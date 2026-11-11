"""Snapshot, cache and command failure contracts for static navigation."""
import importlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from codesentry.cli.main import main
from codesentry.core.policy import Policy
from codesentry.core.symbol import FileMeta, Language
from codesentry.index.builder import IndexResult, SourceLimits, build_index
from codesentry.index.cache import FileCacheEntry, ParseCache, hash_content
from codesentry.index.store import IndexStore
from codesentry.parsers import Parser

cli_module = importlib.import_module('codesentry.cli.main')
builder_module = importlib.import_module('codesentry.index.builder')


@pytest.fixture(autouse=True)
def local_cache(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'user-cache'))


def source(tmp_path, text='def run():\n    return 1\n'):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'app.py').write_text(text, encoding='utf-8')
    return project


def test_parse_cache_context_change_discards_old_result(tmp_path):
    directory = tmp_path / 'cache'
    first = ParseCache(tmp_path, cache_dir=directory, context='parser-A')
    first.put(FileCacheEntry(path='app.py', content_hash='same', mtime=0,
                            meta=FileMeta(path='app.py', language=Language.PYTHON).model_dump()))
    assert first.save()
    changed = ParseCache(tmp_path, cache_dir=directory, context='parser-B')
    changed.load()
    assert changed.get('app.py', 'same') is None
    matching = ParseCache(tmp_path, cache_dir=directory, context='parser-A')
    matching.load()
    assert matching.get('app.py', 'same') is not None


def test_disabled_refresh_does_not_remove_existing_cache(tmp_path):
    directory = tmp_path / 'cache'
    directory.mkdir()
    marker = directory / 'parse_cache.json'
    marker.write_text('keep', encoding='utf-8')
    ParseCache(tmp_path, enabled=False, cache_dir=directory).clear()
    assert marker.read_text(encoding='utf-8') == 'keep'


def test_failure_visible_and_not_cached_as_empty_success(tmp_path):
    project = source(tmp_path, 'def broken(:\n')
    (project / 'empty.py').write_text('', encoding='utf-8')
    result = build_index(project, Policy())
    files = {file.path: file for file in result.files}
    assert not result.is_complete and result.parse_failures == 1
    assert not files['app.py'].is_parsed
    assert files['empty.py'].is_parsed
    assert any(issue['file'] == 'app.py' for issue in result.parse_issues)
    cached = ParseCache(project)
    raw = json.loads(cached.cache_file.read_text(encoding='utf-8'))
    assert {item['path'] for item in raw['files']} == {'empty.py'}
    (project / 'app.py').write_text('def fixed():\n    pass\n', encoding='utf-8')
    fixed = build_index(project, Policy())
    assert fixed.is_complete and fixed.parse_failures == 0


def test_python_declared_encoding_is_read_without_replacement(tmp_path):
    project = source(tmp_path)
    (project / 'app.py').write_bytes('# coding: cp1252\nname = "café"\n'.encode('cp1252'))
    result = build_index(project, Policy(), use_cache=False)
    assert result.is_complete
    assert result.files[0].content_hash == hash_content('# coding: cp1252\nname = \"café\"\n')


def test_source_change_during_parse_is_incomplete(tmp_path, monkeypatch):
    project = source(tmp_path)
    original = Parser.parse_with_meta
    def change_after_read(self, path, rel, text, suffix):
        parsed = original(self, path, rel, text, suffix)
        path.write_text('def changed():\n    return 2\n', encoding='utf-8')
        return parsed
    monkeypatch.setattr(Parser, 'parse_with_meta', change_after_read)
    result = build_index(project, Policy(), use_cache=False)
    assert not result.is_complete
    assert any(issue['status'] == 'source_changed' for issue in result.parse_issues)


def test_no_sources_is_not_a_complete_navigation(tmp_path):
    project = tmp_path / 'empty-project'
    project.mkdir()
    result = build_index(project, Policy(), use_cache=False)
    assert not result.is_complete
    assert result.parse_issues[0]['status'] == 'no_sources'


def test_index_creates_parent_and_tracks_environment_and_incomplete(tmp_path):
    project = source(tmp_path)
    store = IndexStore(project)
    first = build_index(project, Policy(), use_cache=False)
    assert store.save(first)
    assert store.index_file.exists()
    assert not store.check_stale(first).stale
    (project / 'package.json').write_text('{"name":"example"}', encoding='utf-8')
    second = build_index(project, Policy(), use_cache=False)
    stale = store.check_stale(second)
    assert stale.stale and stale.environment_changed
    second.is_complete = False
    assert store.save(second)
    assert store.check_stale(second).stale


def test_index_policy_change_is_stale_without_source_change(tmp_path):
    project = source(tmp_path)
    store = IndexStore(project)
    first = build_index(project, Policy(), use_cache=False)
    assert store.save(first)
    altered = Policy()
    altered.index.pagerank_alpha = 0.9
    second = build_index(project, altered, use_cache=False)
    stale = store.check_stale(second)
    assert stale.stale and stale.input_changed
    assert not stale.modified


def test_index_save_failure_does_not_print_success(tmp_path, monkeypatch, capsys):
    project = source(tmp_path)
    monkeypatch.setattr(cli_module, 'build_index',
                        lambda *args, **kwargs: IndexResult(root=str(project)))
    monkeypatch.setattr(IndexStore, 'save', lambda *args: False)
    assert main(['index', str(project), '--json', '--no-cache', '--confirm-access']) == 2
    output = capsys.readouterr()
    assert not json.loads(output.out)['index_saved']
    assert '索引保存失败' in output.err
    assert '索引已保存' not in output.out


def test_status_comparison_disables_cache_writes(tmp_path, monkeypatch):
    project = source(tmp_path)
    result = IndexResult(root=str(project))
    assert IndexStore(project).save(result)
    def current(*args, **kwargs):
        assert kwargs['use_cache'] is False
        return result
    monkeypatch.setattr(cli_module, 'build_index', current)
    assert main(['status', str(project), '--confirm-access']) == 0
    result.environment_fingerprint = 'changed'
    assert main(['status', str(project), '--confirm-access']) == 1


def test_scan_placeholder_does_not_claim_review_success(tmp_path, monkeypatch, capsys):
    project = source(tmp_path)
    def unexpected(*args, **kwargs):
        pytest.fail('scan placeholder must not run the index as if it were a review')
    monkeypatch.setattr(cli_module, 'build_index', unexpected)
    assert main(['scan', str(project), '--json']) == 2
    assert json.loads(capsys.readouterr().out)['review_status'] == 'not_implemented'


@pytest.mark.parametrize('bad', [b'\xff', b'{"version":5,"files":null}', b'[]'])
def test_corrupt_cache_is_discarded(tmp_path, bad):
    directory = tmp_path / 'cache'
    directory.mkdir()
    (directory / 'parse_cache.json').write_bytes(bad)
    cache = ParseCache(tmp_path, cache_dir=directory)
    cache.load()
    assert cache.entries == {}


@pytest.mark.parametrize('key,value', [('built_at_epoch', 'invalid'), ('files', None),
                                      ('is_complete', 'true'), ('built_at_epoch', float('inf'))])
def test_corrupt_index_is_discarded(tmp_path, key, value):
    project = source(tmp_path)
    store = IndexStore(project)
    assert store.save(IndexResult(root=str(project)))
    data = json.loads(store.index_file.read_text(encoding='utf-8'))
    data[key] = value
    store.index_file.write_text(json.dumps(data), encoding='utf-8')
    assert store.load() is None


def test_final_discovery_error_prevents_completeness(tmp_path, monkeypatch):
    project = source(tmp_path)
    original = builder_module.discover
    calls = 0
    def discover(*args, **kwargs):
        nonlocal calls
        calls += 1
        found = original(*args, **kwargs)
        if calls == 2:
            kwargs['issues'].append({'file': '.', 'status': 'discovery_failed', 'message': 'denied'})
        return found
    monkeypatch.setattr(builder_module, 'discover', discover)
    result = build_index(project, Policy(), use_cache=False)
    assert not result.is_complete
    assert any(issue['status'] == 'discovery_failed' for issue in result.parse_issues)


def test_configuration_change_during_parse_is_incomplete(tmp_path, monkeypatch):
    project = source(tmp_path)
    original = Parser.parse_with_meta
    def change_config(self, path, rel, text, suffix):
        parsed = original(self, path, rel, text, suffix)
        (project / 'package.json').write_text('{"name":"changed"}', encoding='utf-8')
        return parsed
    monkeypatch.setattr(Parser, 'parse_with_meta', change_config)
    result = build_index(project, Policy(), use_cache=False)
    assert not result.is_complete
    assert any(issue['status'] == 'configuration_changed' for issue in result.parse_issues)


def test_missing_ts_toolchain_keeps_failed_file_visible(tmp_path, monkeypatch):
    project = source(tmp_path)
    (project / 'entry.ts').write_text('export function run() {}', encoding='utf-8')
    original = builder_module.get_toolchain(project)
    missing = replace(original, typescript_path=None, fingerprint='missing-compiler',
                      diagnostics=['typescript_managed_package_missing'])
    monkeypatch.setattr(builder_module, 'get_toolchain', lambda *args: missing)
    result = build_index(project, Policy(), use_cache=False)
    assert not result.is_complete and result.parse_failures == 1
    metadata = {item.path: item for item in result.files}
    assert metadata['app.py'].is_parsed
    assert not metadata['entry.ts'].is_parsed


def test_source_byte_budget_preserves_failed_metadata(tmp_path):
    project = source(tmp_path)
    result = build_index(project, Policy(), use_cache=False,
                         limits=SourceLimits(file_bytes=4, total_bytes=8, files=1))
    assert not result.is_complete and result.parse_failures == 1
    assert result.files[0].path == 'app.py' and not result.files[0].is_parsed
    assert any('source_byte_limit' in issue['message'] for issue in result.parse_issues)


def test_global_algorithm_update_invalidates_saved_index(tmp_path, monkeypatch):
    project = source(tmp_path)
    package = tmp_path / 'analyzer-copy'
    shutil.copytree(Path(builder_module.__file__).resolve().parents[1], package,
                    ignore=shutil.ignore_patterns('__pycache__'))
    monkeypatch.setattr(builder_module, '__file__', str(package / 'index' / 'builder.py'))
    store = IndexStore(project)
    first = build_index(project, Policy(), use_cache=False)
    assert store.save(first)
    algorithm = package / 'index' / 'entrypoint.py'
    algorithm.write_text(algorithm.read_text(encoding='utf-8') + '\n# updated algorithm version\n', encoding='utf-8')
    second = build_index(project, Policy(), use_cache=False)
    stale = store.check_stale(second)
    assert stale.stale and stale.input_changed
    assert not stale.modified


def test_source_growing_past_validation_budget_is_incomplete(tmp_path, monkeypatch):
    project = source(tmp_path)
    original = Parser.parse_with_meta
    def grow_after_read(self, path, rel, text, suffix):
        parsed = original(self, path, rel, text, suffix)
        path.write_bytes(b'x' * 1024)
        return parsed
    monkeypatch.setattr(Parser, 'parse_with_meta', grow_after_read)
    result = build_index(project, Policy(), use_cache=False,
                         limits=SourceLimits(file_bytes=64, total_bytes=128, files=10))
    assert not result.is_complete
    assert any(issue['status'] == 'source_changed' for issue in result.parse_issues)
