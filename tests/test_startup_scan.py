"""Startup discovery keeps its inputs while avoiding irrelevant file decisions.

These fixtures are owned synthetic repositories. The unfiltered adapter is the
previous walk behavior, not a second implementation of the optimized collector.
"""
from pathlib import Path

import pytest

from codesentry.access import AccessPolicy
from codesentry.access import policy as access_module
from codesentry.core.policy import ExcludeConfig
from codesentry.index.startup import collect_startup_inputs


class UnfilteredAccess(AccessPolicy):
    def walk(self, **kwargs):
        return super().walk()


def project(tmp_path, files):
    root = tmp_path / 'project'
    root.mkdir()
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    return root


def test_startup_inputs_match_unfiltered_walk_for_scope_and_name_edges(tmp_path):
    files = {
        '.gitignore': 'ignored.html\nignored-dir/\n',
        'pyproject.toml': '[project]\nname="demo"\n',
        'Dockerfile': 'CMD ["python", "main.py"]\n',
        'ignored.html': '<script src="main.ts"></script>',
        'ignored-dir/package.json': '{}',
        'nested/.gitignore': '*.html\n!launch.HTML\n',
        'nested/launch.HTML': '<script type="module" src="main.ts"></script>',
        'nested/ignored.html': '<script src="ignored.ts"></script>',
        '.custom/package.json': '{}',
        'test_component/package.json': '{}',
        'test_page.html': '<script src="test.ts"></script>',
        'conftest.html': '<script src="test.ts"></script>',
        'uppercase/PACKAGE.JSON': '{}',
        'named-dir/package.json/child.py': 'VALUE = 1',
        'aux/package.json': '{}',
        'vendor-data/package.json': '{}',
        'tests/package.json': '{}',
        'src/ordinary.py': 'VALUE = 1',
    }
    root = project(tmp_path, files)
    settings = {'exclude': ['Dockerfile']}
    cfg = ExcludeConfig(not_parsed=['vendor-data'], not_ranked=['aux'])
    before_access = UnfilteredAccess(root, settings)
    after_access = AccessPolicy(root, settings)
    before = collect_startup_inputs(before_access, exclude=cfg)
    after = collect_startup_inputs(after_access, exclude=cfg)
    assert after == before
    assert set(after.hashes) == {
        'pyproject.toml', 'Dockerfile', 'ignored.html',
        'nested/launch.HTML', 'nested/ignored.html',
        '.custom/package.json', 'test_component/package.json',
    }
    assert after.hashes['Dockerfile'] == 'unread:access-policy'
    assert after.hashes['ignored.html'] == 'unread:access-policy'
    assert after_access.fingerprint == before_access.fingerprint


def test_ignored_control_remains_unread_and_blocks_matching_config(tmp_path, monkeypatch):
    root = project(tmp_path, {'src/.gitignore': '*.html\n',
                              'src/index.html': '<script src="main.ts"></script>',
                              'src/ordinary.py': 'VALUE=1'})
    policy = AccessPolicy(root, {'exclude': ['src/.gitignore']})
    original = Path.open

    def watch(path, *args, **kwargs):
        assert path not in {root / 'src' / '.gitignore', root / 'src' / 'index.html'}
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', watch)
    result = collect_startup_inputs(policy)
    assert result.hashes == {'src/index.html': 'unread:access-policy'}
    assert result.texts == {}


def test_control_fingerprint_still_covers_algorithm_pruned_directories(tmp_path):
    root = project(tmp_path, {'runtime/.gitignore': '*.html\n',
                              'runtime/package.json': '{}', 'package.json': '{}'})
    policy = AccessPolicy(root)
    before = policy.fingerprint
    assert set(collect_startup_inputs(policy).hashes) == {'package.json'}
    (root / 'runtime' / '.gitignore').write_text('*.ts\n', encoding='utf-8')
    policy.refresh()
    assert policy.fingerprint != before
    assert set(collect_startup_inputs(policy).hashes) == {'package.json'}


def test_config_byte_limit_keeps_same_unknown_marker(tmp_path):
    from codesentry.index.startup import MAX_CONFIG_BYTES
    root = project(tmp_path, {'package.json': 'x' * (MAX_CONFIG_BYTES + 1),
                              'ordinary.py': 'VALUE=1'})
    assert collect_startup_inputs(AccessPolicy(root)) == collect_startup_inputs(UnfilteredAccess(root))
    assert collect_startup_inputs(AccessPolicy(root)).hashes == {
        'package.json': 'unread:unsupported-or-limit'}


def test_file_filter_does_not_escape_total_entry_limit(tmp_path, monkeypatch):
    root = project(tmp_path, {f'ordinary{i}.py': 'VALUE=1' for i in range(10)})
    policy = AccessPolicy(root)
    monkeypatch.setattr(access_module, 'MAX_ENTRIES', 5)
    assert list(policy.walk(file_filter=lambda _: False)) == []
    assert any(issue['status'] == 'access_scope_limit' for issue in policy.issues)


def test_file_filter_does_not_escape_directory_limit(tmp_path, monkeypatch):
    root = project(tmp_path, {f'dir{i}/ordinary.py': 'VALUE=1' for i in range(5)})
    policy = AccessPolicy(root)
    monkeypatch.setattr(access_module, 'MAX_DIRECTORIES', 2)
    list(policy.walk(file_filter=lambda _: False))
    assert any(issue['status'] == 'access_scope_limit' for issue in policy.issues)


def test_startup_scan_avoids_deciding_unrelated_files_and_prunes_auxiliary_dirs(tmp_path, monkeypatch):
    files = {f'src/file{i}.py': 'VALUE=1' for i in range(30)}
    files.update({f'runtime/branch{i}/package.json': '{}' for i in range(8)})
    files.update({'package.json': '{}', 'src/index.html': '<script src="main.ts"></script>'})
    root = project(tmp_path, files)
    policy = AccessPolicy(root)
    decisions = []
    original = policy.decision

    def decision(relative, is_dir=False):
        decisions.append((relative, is_dir))
        return original(relative, is_dir=is_dir)

    monkeypatch.setattr(policy, 'decision', decision)
    result = collect_startup_inputs(policy)
    assert set(result.hashes) == {'package.json', 'src/index.html'}
    assert not any(name.endswith('.py') for name, _ in decisions)
    assert not any(name.startswith('runtime/') for name, _ in decisions)
    assert ('runtime', True) in decisions


def test_filtered_walk_still_decides_and_rejects_linked_config(tmp_path):
    root = project(tmp_path, {'package.json': '{}'})
    secret = tmp_path / 'outside.json'
    secret.write_text('{"private":true}', encoding='utf-8')
    try:
        (root / 'linked.html').symlink_to(secret)
    except OSError:
        pytest.skip('This account cannot create ordinary symlinks')
    result = collect_startup_inputs(AccessPolicy(root))
    assert result.hashes['linked.html'] == 'unread:access-policy'
    assert 'linked.html' not in result.texts


def test_directory_predicate_never_overrides_a_denied_parent(tmp_path, monkeypatch):
    root = project(tmp_path, {'blocked/package.json': '{}', 'allowed/package.json': '{}'})
    policy = AccessPolicy(root, {'exclude': ['blocked/']})
    original = access_module.os.scandir
    visited = []

    def scan(path):
        visited.append(Path(path))
        assert Path(path) != root / 'blocked'
        return original(path)

    monkeypatch.setattr(access_module.os, 'scandir', scan)
    rows = list(policy.walk(file_filter=lambda _: True, descend_filter=lambda _: True))
    assert root / 'blocked' not in visited
    assert not any(name == 'blocked/package.json' for name, *_ in rows)


def test_filtered_scan_refuses_hardlinked_config_without_reading_content(tmp_path, monkeypatch):
    import os
    root = project(tmp_path, {'package.json': '{}'})
    outside = tmp_path / 'private.html'
    outside.write_text('<script src="private.ts"></script>', encoding='utf-8')
    linked = root / 'linked.html'
    os.link(outside, linked)
    policy = AccessPolicy(root)
    original = Path.open

    def read(path, *args, **kwargs):
        assert path != linked and path != outside
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', read)
    result = collect_startup_inputs(policy)
    assert result.hashes['linked.html'] == 'unread:access-policy'
    assert 'linked.html' not in result.texts


def test_filtered_scan_does_not_enter_windows_junction(tmp_path, monkeypatch):
    import os
    import subprocess
    if os.name != 'nt':
        pytest.skip('Windows junction fixture')
    root = project(tmp_path, {'package.json': '{}'})
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'package.json').write_text('{"private":true}', encoding='utf-8')
    linked = root / 'linked'
    completed = subprocess.run(['cmd', '/c', 'mklink', '/J', str(linked), str(outside)],
                               capture_output=True, timeout=10)
    assert completed.returncode == 0, completed.returncode
    policy = AccessPolicy(root)
    original = access_module.os.scandir

    def scan(path):
        assert Path(path) != linked and Path(path) != outside
        return original(path)

    monkeypatch.setattr(access_module.os, 'scandir', scan)
    result = collect_startup_inputs(policy)
    assert set(result.hashes) == {'package.json'}
