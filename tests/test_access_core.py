"""The same policy must cover parsing, environment discovery and old artifacts."""
import json
from pathlib import Path

import pytest

from codesentry.access import AccessPolicy, clear_owned_artifacts
from codesentry.access import AccessDenied
from codesentry.core.policy import Policy
from codesentry.environment import inspect_environment
from codesentry.index.builder import build_index
from codesentry.index.cache import ParseCache, FileCacheEntry, default_cache_dir, default_index_dir
from codesentry.index.store import IndexStore


def guard(monkeypatch, forbidden):
    paths={path.resolve() for path in forbidden}
    original=Path.open
    opened=[]
    def checked(path,*args,**kwargs):
        mode=args[0] if args else kwargs.get('mode','r')
        if path.resolve() in paths and ('r' in mode or '+' in mode):
            opened.append(path)
            raise AssertionError('forbidden content opened')
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',checked)
    return opened


def project(tmp_path):
    root=tmp_path/'project';root.mkdir()
    (root/'main.py').write_text('def main():\n    return 1\n',encoding='utf-8')
    (root/'private.py').write_text('PRIVATE_SENTINEL = 1\n',encoding='utf-8')
    (root/'package.json').write_text('{"dependencies":{"private-sdk":"1.0"}}',encoding='utf-8')
    return root


def test_excluded_sources_and_configs_are_never_opened_by_core(tmp_path,monkeypatch):
    root=project(tmp_path)
    opened=guard(monkeypatch,[root/'private.py',root/'package.json'])
    access=AccessPolicy(root,{'exclude':['private.py','package.json']})
    result=build_index(root,Policy(),use_cache=False,access=access)
    assert [item.path for item in result.files]==['main.py']
    assert not result.is_complete
    assert any(issue['status']=='access_scope_limited' for issue in result.parse_issues)
    assert result.environment['configuration_files']['package.json']=='unread:access-policy'
    assert result.source_permissions=={'main.py':'local_only'}
    assert result.provenance['derived_mode']=='local_only'
    assert not opened


def test_gitignored_source_and_directory_are_scope_limited_without_reading(tmp_path,monkeypatch):
    root=project(tmp_path)
    (root/'.gitignore').write_text('private.py\nprivate/\n',encoding='utf-8')
    folder=root/'private';folder.mkdir();(folder/'hidden.py').write_text('secret = 1\n',encoding='utf-8')
    opened=guard(monkeypatch,[root/'private.py',folder/'hidden.py'])
    result=build_index(root,Policy(),use_cache=False)
    assert not result.is_complete
    assert [item.path for item in result.files]==['main.py']
    assert not opened


def test_new_scope_never_deserializes_old_parse_payload(tmp_path,monkeypatch):
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    build_index(root,Policy())
    cache=ParseCache(root).cache_file
    assert cache.exists()
    opened=guard(monkeypatch,[cache,root/'private.py'])
    result=build_index(root,Policy(),access=AccessPolicy(root,{'exclude':['private.py']}))
    assert not opened
    assert all(item.path!='private.py' for item in result.files)


def test_old_unscoped_cache_is_deleted_before_read_even_when_cache_disabled(tmp_path,monkeypatch):
    root=project(tmp_path)
    directory=tmp_path/'cache';directory.mkdir()
    marker=directory/'parse_cache.json';marker.write_text('OLD_PRIVATE_CONTENT',encoding='utf-8')
    opened=guard(monkeypatch,[marker])
    cache=ParseCache(root,enabled=False,cache_dir=directory,access=AccessPolicy(root))
    cache.load()
    assert not marker.exists() and not opened


def test_index_scope_sidecar_prevents_old_result_payload_read(tmp_path,monkeypatch):
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    access=AccessPolicy(root)
    original=IndexStore(root,access=access)
    assert original.save(build_index(root,Policy(),use_cache=False,access=access))
    opened=guard(monkeypatch,[original.index_file])
    changed=IndexStore(root,access=AccessPolicy(root,{'exclude':['private.py']}))
    assert changed.load() is None
    assert not opened and original.index_file.exists()


def test_project_index_without_scope_is_not_read_or_deleted(tmp_path,monkeypatch):
    root=project(tmp_path)
    old=root/'index.json';old.write_text('USER_OWNED_CONTENT',encoding='utf-8')
    opened=guard(monkeypatch,[old])
    assert IndexStore(root,save_to_project=True).load() is None
    assert old.exists() and not opened


def test_managed_cleanup_unlinks_only_known_artifacts_without_reading(tmp_path,monkeypatch):
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    files=[]
    for directory,names in [(default_cache_dir(root),['parse_cache.json','parse_cache.access.json']),
                            (default_index_dir(root),['index.json','index.json.access.json'])]:
        directory.mkdir(parents=True)
        for name in names:
            path=directory/name;path.write_text('OLD_PRIVATE_CONTENT',encoding='utf-8');files.append(path)
        (directory/'unrelated.txt').write_text('keep',encoding='utf-8')
    opened=guard(monkeypatch,files)
    assert len(clear_owned_artifacts(root))==4
    assert not any(path.exists() for path in files)
    assert all((directory/'unrelated.txt').exists() for directory in [default_cache_dir(root),default_index_dir(root)])
    assert (root/'private.py').exists() and not opened


def test_policy_change_during_index_discards_all_old_derived_information(tmp_path,monkeypatch):
    import codesentry.index.builder as module
    root=project(tmp_path)
    (root/'.gitignore').write_text('',encoding='utf-8')
    original=module.RoleTagger.tag
    changed=False
    def change(tagger,*args,**kwargs):
        nonlocal changed
        if not changed:
            (root/'.gitignore').write_text('private.py\n',encoding='utf-8')
            changed=True
        return original(tagger,*args,**kwargs)
    monkeypatch.setattr(module.RoleTagger,'tag',change)
    result=build_index(root,Policy(),use_cache=False)
    assert not result.is_complete and not result.files and not result.symbols and not result.environment
    assert result.parse_issues[0]['status']=='access_policy_changed'


def test_excluded_project_index_and_sidecar_are_neither_read_nor_written(tmp_path,monkeypatch):
    root=project(tmp_path)
    index=root/'index.json';index.write_text('OLD_PRIVATE_CONTENT',encoding='utf-8')
    sidecar=root/'index.json.access.json';sidecar.write_text('{}',encoding='utf-8')
    opened=guard(monkeypatch,[index,sidecar])
    access=AccessPolicy(root,{'exclude':['*.json']})
    store=IndexStore(root,save_to_project=True,access=access)
    assert store.load() is None
    assert store.save(build_index(root,Policy(),use_cache=False,access=access)) is False
    assert index.exists() and sidecar.exists() and not opened


def test_excluded_repository_cache_is_not_read_or_rewritten(tmp_path,monkeypatch):
    root=project(tmp_path)
    directory=root/'cache';directory.mkdir()
    cache_file=directory/'parse_cache.json';cache_file.write_text('OLD_PRIVATE_CONTENT',encoding='utf-8')
    marker=directory/'parse_cache.access.json';marker.write_text('{}',encoding='utf-8')
    opened=guard(monkeypatch,[cache_file,marker])
    cache=ParseCache(root,cache_dir=directory,access=AccessPolicy(root,{'exclude':['cache/']}))
    cache.load()
    assert not cache.enabled and cache.save() is False and not opened


def test_managed_cleanup_failure_is_explicit_and_never_reads_content(tmp_path,monkeypatch):
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    directory=default_cache_dir(root);directory.mkdir(parents=True)
    cache_file=directory/'parse_cache.json';cache_file.write_text('OLD_PRIVATE_CONTENT',encoding='utf-8')
    original=Path.unlink
    def denied(path,*args,**kwargs):
        if path==cache_file:raise PermissionError('locked file')
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'unlink',denied)
    opened=guard(monkeypatch,[cache_file])
    with pytest.raises(AccessDenied,match='清理未完成'):
        clear_owned_artifacts(root)
    assert cache_file.exists() and not opened


def test_cache_write_revoked_mid_save_removes_new_payload_and_marker(tmp_path,monkeypatch):
    root=project(tmp_path)
    revoked=False
    def live_guard():
        if revoked:raise AccessDenied('revoked')
    access=AccessPolicy(root,read_guard=live_guard)
    cache=ParseCache(root,cache_dir=tmp_path/'cache',access=access)
    cache.put(FileCacheEntry(path='main.py',content_hash='x',mtime=1))
    original=Path.write_text
    def revoke_after_write(path,*args,**kwargs):
        nonlocal revoked
        result=original(path,*args,**kwargs)
        if path==cache.cache_file:revoked=True
        return result
    monkeypatch.setattr(Path,'write_text',revoke_after_write)
    assert cache.save() is False
    assert not cache.cache_file.exists() and not cache.scope_file.exists()
    assert not cache.entries


def test_index_write_revoked_mid_save_removes_new_payload_and_marker(tmp_path,monkeypatch):
    import codesentry.index.store as module
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    result=build_index(root,Policy(),use_cache=False)
    revoked=False
    def live_guard():
        if revoked:raise AccessDenied('revoked')
    access=AccessPolicy(root,read_guard=live_guard)
    store=IndexStore(root,access=access)
    original=module.os.replace
    def revoke_after_replace(source,destination):
        nonlocal revoked
        original(source,destination)
        if destination==store.index_file:revoked=True
    monkeypatch.setattr(module.os,'replace',revoke_after_replace)
    assert store.save(result) is False
    assert not store.index_file.exists() and not store.scope_file.exists()


@pytest.mark.parametrize('custom',[False,True])
def test_interleaved_scope_cache_writes_cannot_substitute_a_wider_payload(tmp_path,monkeypatch,custom):
    from codesentry.core.symbol import FileMeta, Language
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    broad=AccessPolicy(root)
    narrow=AccessPolicy(root,{'exclude':['private.py']})
    directory=tmp_path/'custom-cache' if custom else None
    wider=ParseCache(root,cache_dir=directory,access=broad)
    narrower=ParseCache(root,cache_dir=directory,access=narrow)
    def entry(name):
        return FileCacheEntry(path=name,content_hash='hash',mtime=1,
                              meta=FileMeta(path=name,language=Language.PYTHON).model_dump())
    wider.put(entry('private.py'))
    narrower.put(entry('main.py'))
    original=Path.write_text
    interleaved=False
    def interleave_before_narrow_marker(path,*args,**kwargs):
        nonlocal interleaved
        if path==narrower.scope_file and not interleaved:
            interleaved=True
            assert wider.save()
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'write_text',interleave_before_narrow_marker)
    assert narrower.save() and interleaved
    assert narrower.cache_file!=wider.cache_file
    opened=guard(monkeypatch,[wider.cache_file])
    restored=ParseCache(root,cache_dir=directory,access=narrow)
    restored.load()
    assert set(restored.entries)=={'main.py'} and not opened


@pytest.mark.parametrize('save_to_project',[False,True])
def test_interleaved_scope_index_writes_cannot_substitute_a_wider_payload(tmp_path,monkeypatch,save_to_project):
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    broad=AccessPolicy(root)
    narrow=AccessPolicy(root,{'exclude':['private.py']})
    broad_result=build_index(root,Policy(),use_cache=False,access=broad)
    narrow_result=build_index(root,Policy(),use_cache=False,access=narrow)
    wider=IndexStore(root,access=broad,save_to_project=save_to_project)
    narrower=IndexStore(root,access=narrow,save_to_project=save_to_project)
    original=Path.write_text
    interleaved=False
    def interleave_before_narrow_marker(path,*args,**kwargs):
        nonlocal interleaved
        if path==narrower.scope_file and not interleaved:
            interleaved=True
            assert wider.save(broad_result)
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'write_text',interleave_before_narrow_marker)
    assert narrower.save(narrow_result) and interleaved
    assert narrower.index_file!=wider.index_file
    opened=guard(monkeypatch,[wider.index_file])
    restored=narrower.load()
    assert set(restored['files'])=={'main.py'} and not opened


def test_namespaced_project_index_cannot_be_reused_as_fresh_source(tmp_path,monkeypatch):
    from codesentry.access import prepare_model_input
    root=project(tmp_path)
    broad=AccessPolicy(root,{'model_scope':['**']})
    result=build_index(root,Policy(),use_cache=False,access=broad)
    store=IndexStore(root,save_to_project=True,access=broad)
    assert store.save(result)
    name=store.index_file.name
    temp=root/'temporary.codesentry-index-tmp';temp.write_text('OLD_PRIVATE_DATA',encoding='utf-8')
    opened=guard(monkeypatch,[store.index_file,store.scope_file,temp])
    assert broad.decision(name)['mode']=='exclude'
    with pytest.raises(AccessDenied):broad.read_text(name)
    with pytest.raises(AccessDenied):broad.read_text(temp.name)
    with pytest.raises(AccessDenied):
        prepare_model_input(broad,[name],service='mock',purpose='review',authorized=True)
    narrow=AccessPolicy(root,{'exclude':['private.py'],'model_scope':['**']})
    with pytest.raises(AccessDenied):narrow.read_managed_text(name)
    assert not opened


def test_cleanup_clears_known_files_from_all_hex_scopes_without_touching_unknown_files(tmp_path,monkeypatch):
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    managed=[]
    unrelated=[]
    for base,names in [(default_cache_dir(root),('parse_cache.json','parse_cache.access.json')),
                       (default_index_dir(root),('index.json','index.json.access.json'))]:
        for namespace in ('a'*64,'b'*64,'not-an-owned-namespace'):
            directory=base/'scopes'/namespace;directory.mkdir(parents=True)
            for name in names:
                path=directory/name;path.write_text('PRIVATE_DATA',encoding='utf-8')
                (managed if len(namespace)==64 else unrelated).append(path)
            other=directory/'user-notes.txt';other.write_text('keep',encoding='utf-8');unrelated.append(other)
    opened=guard(monkeypatch,managed+unrelated)
    assert len(clear_owned_artifacts(root))==8
    assert all(not path.exists() for path in managed)
    assert all(path.exists() for path in unrelated)
    assert not opened


def test_cleanup_scope_redirect_fails_closed_without_reading_payload(tmp_path,monkeypatch):
    import codesentry.access.artifacts as module
    root=project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    directory=default_cache_dir(root)/'scopes'/('a'*64);directory.mkdir(parents=True)
    payload=directory/'parse_cache.json';payload.write_text('PRIVATE_DATA',encoding='utf-8')
    original=module.is_link
    monkeypatch.setattr(module,'is_link',lambda path:path==directory or original(path))
    opened=guard(monkeypatch,[payload])
    with pytest.raises(AccessDenied):clear_owned_artifacts(root)
    assert payload.exists() and not opened


def test_source_root_scoped_custom_cache_is_disabled_and_not_fresh_model_source(tmp_path,monkeypatch):
    from codesentry.access import prepare_model_input
    root=project(tmp_path)
    policy=AccessPolicy(root,{'model_scope':['**']})
    cache=ParseCache(root,cache_dir=root/'cache',access=policy)
    assert not cache.enabled
    cache.cache_dir.mkdir(parents=True)
    cache.cache_file.write_text('OLD_PRIVATE_DATA',encoding='utf-8')
    cache.scope_file.write_text('{}',encoding='utf-8')
    opened=guard(monkeypatch,[cache.cache_file,cache.scope_file])
    for path in (cache.cache_file,cache.scope_file):
        relative=path.relative_to(root).as_posix()
        assert policy.decision(relative)['mode']=='exclude'
        with pytest.raises(AccessDenied):policy.read_bytes(relative)
        with pytest.raises(AccessDenied):
            prepare_model_input(policy,[relative],service='mock',purpose='review',authorized=True)
    assert not opened


def test_reused_cache_instance_refreshes_git_rules_before_payload_read(tmp_path,monkeypatch):
    from codesentry.core.symbol import FileMeta,Language
    root=project(tmp_path)
    rules=root/'.gitignore';rules.write_text('',encoding='utf-8')
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    policy=AccessPolicy(root)
    cache=ParseCache(root,access=policy)
    cache.put(FileCacheEntry(path='private.py',content_hash='hash',mtime=1,
                            meta=FileMeta(path='private.py',language=Language.PYTHON).model_dump()))
    assert cache.save()
    rules.write_text('private.py\n',encoding='utf-8')
    opened=guard(monkeypatch,[cache.cache_file])
    with pytest.raises(AccessDenied):cache.load()
    assert not cache.entries and not opened


def test_reused_index_instance_refreshes_git_rules_before_payload_read(tmp_path,monkeypatch):
    root=project(tmp_path)
    rules=root/'.gitignore';rules.write_text('',encoding='utf-8')
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    policy=AccessPolicy(root)
    store=IndexStore(root,access=policy)
    assert store.save(build_index(root,Policy(),use_cache=False,access=policy))
    rules.write_text('private.py\n',encoding='utf-8')
    opened=guard(monkeypatch,[store.index_file])
    assert store.load() is None and not opened
