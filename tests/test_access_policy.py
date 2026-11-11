"""Permission counterexamples exercise actual I/O and the future model boundary."""
import os
from pathlib import Path

import pytest

from codesentry.access import AccessDenied, AccessPolicy, prepare_model_input, validate_settings


def put(root, name, text='content\n'):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def deny_opens(monkeypatch, paths):
    forbidden = {path.resolve() for path in paths}
    opened = []
    original = Path.open
    def guarded(path, *args, **kwargs):
        if path.resolve() in forbidden:
            opened.append(path)
            raise AssertionError(f'excluded content was opened: {path.name}')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', guarded)
    return opened


@pytest.mark.parametrize('settings', [
    {'exclude':['../private.py']}, {'exclude':['/private.py']}, {'exclude':['C:/private.py']},
    {'exclude':['!private.py']}, {'exclude':['a//b.py']}, {'exclude':['a/./b.py']},
    {'model_scope':['%2e%2e/private.py']}, {'exclude':'private.py'},
    {'respect_gitignore':'yes'}, {'unknown':True},
])
def test_settings_reject_escape_and_allow_overrides(settings):
    with pytest.raises(ValueError):
        validate_settings(settings)


def test_modes_are_deny_first_and_models_are_opt_in(tmp_path, monkeypatch):
    private = put(tmp_path, 'private.py', 'TOP_SECRET = 123\n')
    env = put(tmp_path, '.env', 'TOKEN=never-read\n')
    credentials = put(tmp_path, 'credentials/config.py')
    put(tmp_path, 'local.py')
    put(tmp_path, 'public.py')
    opened = deny_opens(monkeypatch, [private, env, credentials])
    policy = AccessPolicy(tmp_path, {'exclude':['private.py'], 'local_only':['local.py'], 'model_scope':['**']})
    assert policy.decision('public.py')['mode'] == 'model_eligible'
    assert policy.decision('local.py')['mode'] == 'local_only'
    for name in ('private.py','.env','credentials/config.py'):
        assert policy.decision(name)['mode'] == 'exclude'
        with pytest.raises(AccessDenied):
            policy.read_bytes(name)
    assert not opened
    assert AccessPolicy(tmp_path).decision('public.py')['mode'] == 'local_only'


def test_gitignore_nested_negation_and_ignored_parent(tmp_path, monkeypatch):
    put(tmp_path, '.gitignore', '*.tmp\nignored/\n')
    put(tmp_path, 'src/.gitignore', '!keep.tmp\n')
    put(tmp_path, 'src/keep.tmp')
    excluded = put(tmp_path, 'src/other.tmp')
    ignored_control = put(tmp_path, 'ignored/.gitignore', '!private.py\n')
    private = put(tmp_path, 'ignored/private.py')
    opened = deny_opens(monkeypatch, [excluded, ignored_control, private])
    policy = AccessPolicy(tmp_path)
    assert policy.decision('src/keep.tmp')['mode'] == 'local_only'
    assert policy.decision('src/other.tmp')['mode'] == 'exclude'
    assert policy.decision('ignored/private.py')['mode'] == 'exclude'
    assert not opened


def test_gitignore_does_not_consult_tracking_state_or_global_git_settings(tmp_path, monkeypatch):
    put(tmp_path, '.gitignore', 'tracked.py\n')
    tracked = put(tmp_path, 'tracked.py')
    git_config = put(tmp_path, '.git/info/exclude', 'public.py\n')
    put(tmp_path, 'public.py')
    opened = deny_opens(monkeypatch, [tracked, git_config])
    policy = AccessPolicy(tmp_path)
    assert policy.decision('tracked.py')['mode'] == 'exclude'
    assert policy.decision('public.py')['mode'] == 'local_only'
    assert not opened


def test_excluded_control_file_is_not_read_and_its_scope_fails_closed(tmp_path, monkeypatch):
    control = put(tmp_path, 'private/.gitignore', '*.py\n')
    private = put(tmp_path, 'private/data.py')
    put(tmp_path, 'public.py')
    opened = deny_opens(monkeypatch, [control, private])
    policy = AccessPolicy(tmp_path, {'exclude':['private/.gitignore']})
    assert policy.decision('private/data.py')['mode'] == 'exclude'
    assert policy.decision('public.py')['mode'] == 'local_only'
    assert policy.to_dict()['issues'][0]['status'] == 'access_rules_blocked'
    with pytest.raises(AccessDenied):
        policy.read_bytes('private/data.py')
    assert not opened


def test_invalid_rule_encoding_is_explicit_and_never_allows_source(tmp_path):
    (tmp_path/'.gitignore').write_bytes(b'\xff')
    put(tmp_path, 'main.py')
    policy = AccessPolicy(tmp_path)
    assert policy.decision('main.py')['mode'] == 'exclude'
    assert policy.to_dict()['issues']


def test_fingerprint_is_stable_for_repeated_metadata_queries(tmp_path):
    put(tmp_path, '.gitignore', '*.log\n')
    put(tmp_path, 'src/a.py')
    policy = AccessPolicy(tmp_path)
    original = policy.fingerprint
    for _ in range(3):
        list(policy.walk())
        assert policy.fingerprint == original
    policy.refresh()
    assert policy.fingerprint == original
    (tmp_path/'empty').mkdir()
    policy.refresh()
    assert policy.fingerprint == original


def test_rule_change_is_observed_before_next_read_even_same_length(tmp_path, monkeypatch):
    rules = put(tmp_path, '.gitignore', 'other.py\n')
    private = put(tmp_path, 'secret.py', 'hidden = 1\n')
    policy = AccessPolicy(tmp_path)
    initial = policy.fingerprint
    rules.write_text('secret.py\n', encoding='utf-8')
    opened = deny_opens(monkeypatch, [private])
    with pytest.raises(AccessDenied):
        policy.read_bytes('secret.py')
    assert policy.fingerprint != initial
    assert not opened


@pytest.mark.skipif(os.name != 'nt', reason='Windows path aliases')
def test_windows_case_alias_cannot_bypass_user_exclusion(tmp_path, monkeypatch):
    private = put(tmp_path, 'Private.py')
    opened = deny_opens(monkeypatch, [private])
    policy = AccessPolicy(tmp_path, {'exclude':['Private.py']})
    assert policy.decision('private.py')['mode'] == 'exclude'
    with pytest.raises(AccessDenied):
        policy.read_bytes('PRIVATE.PY')
    assert not opened
    local = AccessPolicy(tmp_path, {'local_only':['Private.py'], 'model_scope':['**']})
    assert local.decision('PRIVATE.PY')['mode'] == 'local_only'


def test_unconfirmed_policy_does_not_open_even_rule_files(tmp_path, monkeypatch):
    rules = put(tmp_path, '.gitignore', '*.py\n')
    code = put(tmp_path, 'main.py')
    opened = deny_opens(monkeypatch, [rules, code])
    policy = AccessPolicy(tmp_path, confirmed=False)
    assert list(policy.walk()) == []
    with pytest.raises(AccessDenied):
        policy.read_text('main.py')
    assert not opened


def test_model_gateway_rejects_local_and_self_reported_derived_before_read(tmp_path, monkeypatch):
    local = put(tmp_path, 'local.py', 'PRIVATE_ALGORITHM = 1\n')
    put(tmp_path, 'public.py', 'def public():\n    return 1\n')
    policy = AccessPolicy(tmp_path, {'model_scope':['*.py'], 'local_only':['local.py']})
    opened = deny_opens(monkeypatch, [local])
    with pytest.raises(AccessDenied):
        prepare_model_input(policy,['local.py'],service='local-model',purpose='review',authorized=True)
    with pytest.raises(AccessDenied):
        prepare_model_input(policy,['public.py'],service='cloud-model',purpose='review',authorized=True,
                            derived=[{'sources':['public.py'],'access_fingerprint':policy.fingerprint,'content':'PRIVATE_ALGORITHM'}])
    with pytest.raises(AccessDenied):
        prepare_model_input(policy,['public.py'],service='cloud-model',purpose='review')
    assert not opened
    ready = prepare_model_input(policy,['public.py'],service='mock',purpose='review',authorized=True)
    assert ready['sources'][0]['path'] == 'public.py'
    assert ready['transport'] == 'not_implemented'


def test_model_gateway_checks_secret_values_without_opening_excluded_sources(tmp_path):
    put(tmp_path, 'main.py', 'API_KEY = "sk-abcdefghijk1234567890"\n')
    policy = AccessPolicy(tmp_path, {'model_scope':['main.py']})
    with pytest.raises(AccessDenied, match='秘密'):
        prepare_model_input(policy,['main.py'],service='mock',purpose='review',authorized=True)


def test_walk_limit_fails_closed_and_repeated_queries_do_not_change_identity(tmp_path, monkeypatch):
    import codesentry.access.policy as module
    put(tmp_path,'a.py')
    put(tmp_path,'b.py')
    monkeypatch.setattr(module,'MAX_ENTRIES',1)
    policy = AccessPolicy(tmp_path)
    fingerprint = policy.fingerprint
    assert policy.decision('a.py')['mode'] == 'exclude'
    list(policy.walk())
    assert policy.fingerprint == fingerprint


def test_incremental_refresh_does_not_enumerate_ordinary_files_when_unchanged(tmp_path, monkeypatch):
    put(tmp_path,'.gitignore','*.log\n')
    for index in range(50):
        put(tmp_path,f'module_{index}.py')
    policy=AccessPolicy(tmp_path)
    fingerprint=policy.fingerprint
    monkeypatch.setattr(os,'scandir',lambda *_: (_ for _ in ()).throw(AssertionError('unchanged policy walked sources')))
    assert policy.refresh_if_changed() is policy
    assert policy.fingerprint==fingerprint


def test_incremental_refresh_finds_new_nested_ignore_control(tmp_path):
    put(tmp_path,'src/main.py')
    policy=AccessPolicy(tmp_path)
    fingerprint=policy.fingerprint
    assert policy.decision('src/main.py')['mode']=='local_only'
    put(tmp_path,'src/.gitignore','main.py\n')
    policy.refresh_if_changed()
    assert policy.fingerprint!=fingerprint
    assert policy.decision('src/main.py')['mode']=='exclude'


@pytest.mark.parametrize('incremental',[False,True])
def test_rule_digest_detects_restored_size_and_timestamp(tmp_path,monkeypatch,incremental):
    rules=put(tmp_path,'.gitignore','alpha.py\n')
    private=put(tmp_path,'bravo.py')
    policy=AccessPolicy(tmp_path)
    fingerprint=policy.fingerprint
    original_stat=rules.lstat()
    rules.write_text('bravo.py\n',encoding='utf-8')
    original_lstat=Path.lstat
    def unchanged_metadata(path,*args,**kwargs):
        return original_stat if path==rules else original_lstat(path,*args,**kwargs)
    monkeypatch.setattr(Path,'lstat',unchanged_metadata)
    opened=deny_opens(monkeypatch,[private])
    if incremental:
        policy.refresh_if_changed()
    with pytest.raises(AccessDenied):
        policy.read_text('bravo.py')
    assert not opened and policy.fingerprint!=fingerprint


def test_parent_rule_revocation_does_not_read_previously_allowed_child_control(tmp_path,monkeypatch):
    rules=put(tmp_path,'.gitignore','*.tmp\n')
    child=put(tmp_path,'src/.gitignore','!main.py\n')
    private=put(tmp_path,'src/main.py')
    policy=AccessPolicy(tmp_path)
    rules.write_text('src/.gitignore\n',encoding='utf-8')
    opened=deny_opens(monkeypatch,[child,private])
    policy.refresh_if_changed()
    assert policy.decision('src/main.py')['mode']=='exclude'
    assert not opened


def test_external_read_guard_prevents_reads_and_fingerprint_after_revocation(tmp_path,monkeypatch):
    rules=put(tmp_path,'.gitignore','*.log\n')
    code=put(tmp_path,'main.py')
    revoked=False
    def guard():
        if revoked:
            raise AccessDenied('workspace policy changed')
    policy=AccessPolicy(tmp_path,read_guard=guard)
    revoked=True
    opened=deny_opens(monkeypatch,[rules,code])
    for action in (lambda:policy.read_bytes('main.py'),policy.refresh,policy.refresh_if_changed,lambda:policy.fingerprint):
        with pytest.raises(AccessDenied):action()
    assert not opened


def test_hardlink_alias_cannot_bypass_excluded_source(tmp_path,monkeypatch):
    private=put(tmp_path,'private.py','PRIVATE_DATA = 1\n')
    alias=tmp_path/'public.py'
    os.link(private,alias)
    opened=deny_opens(monkeypatch,[private,alias])
    policy=AccessPolicy(tmp_path,{'exclude':['private.py'],'model_scope':['public.py']})
    assert policy.decision('public.py')['mode']=='exclude'
    with pytest.raises(AccessDenied):policy.read_bytes('public.py')
    assert not opened
