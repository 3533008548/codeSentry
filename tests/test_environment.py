"""Environment declarations and controlled parser execution boundaries."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import time

import pytest

from codesentry.environment import Toolchain, get_toolchain, inspect_environment
from codesentry.environment.inspect import _jsonc
from codesentry.environment import toolchain as tools
from codesentry.parsers import Parser
from codesentry.parsers.ts_parser import TypeScriptParser


def declared_only():
    return Toolchain(fingerprint="fixture-declared-only")


def test_frontend_unit_is_declared_without_evaluating_scripts_or_env(tmp_path):
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nrequires-python = ">=3.11"\ndependencies = ["requests>=2"]\n',
        encoding="utf-8",
    )
    (frontend / "package.json").write_text(json.dumps({
        "engines": {"node": ">=22"},
        "dependencies": {"safe": "^1.0", "private": "https://secret-token@host/pkg"},
        "scripts": {"prepare": "touch SHOULD_NOT_EXIST"},
    }), encoding="utf-8")
    (frontend / "package-lock.json").write_text('{"lockfileVersion": 3}', encoding="utf-8")
    (frontend / "tsconfig.json").write_text('{"compilerOptions": {"target":"ES2022"}}', encoding="utf-8")
    (tmp_path / ".env").write_text("API_KEY=do-not-copy-this-secret", encoding="utf-8")
    profile = inspect_environment(tmp_path, declared_only())
    assert {unit["path"] for unit in profile.project_units} == {".", "frontend"}
    unit = next(unit for unit in profile.project_units if unit["path"] == "frontend")
    assert unit["declarations"]["javascript"]["engines"]["node"] == ">=22"
    assert unit["declarations"]["javascript"]["dependency_specs"]["dependencies"]["private"] == "<non-version-specification>"
    assert unit["declarations"]["javascript"]["script_names"] == ["prepare"]
    rendered = json.dumps(profile.to_dict())
    assert "do-not-copy-this-secret" not in rendered
    assert "secret-token" not in rendered
    assert "touch SHOULD_NOT_EXIST" not in rendered
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()
    assert profile.observed["target_runtime"] == "not_observed"
    assert profile.to_dict()["execution"] == "not_run"


def test_jsonc_comments_and_trailing_commas_preserve_quoted_content():
    value = _jsonc('''{
      // this is a comment
      "url": "https://example.invalid/a,}", /* another */
      "paths": {"@x/*": ["src/a,}",],},
    }''')
    assert value["url"] == "https://example.invalid/a,}"
    assert value["paths"]["@x/*"] == ["src/a,}"]


def test_relative_extends_and_lock_change_fingerprint_without_source_changes(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "tsconfig.json").write_text(
        '{"extends":"./config/base.json", "compilerOptions":{"plugins":[{"name":"unsafe"}]}}',
        encoding="utf-8",
    )
    (tmp_path / "config").mkdir()
    base = tmp_path / "config" / "base.json"
    base.write_text('{"compilerOptions":{"target":"ES2020"}}', encoding="utf-8")
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"version":1}', encoding="utf-8")
    before = inspect_environment(tmp_path, declared_only())
    assert "config/base.json" in before.configuration_files
    assert any("plugins are not loaded" in item for item in before.unknowns)
    assert inspect_environment(tmp_path, declared_only()).fingerprint == before.fingerprint
    base.write_text('{"compilerOptions":{"target":"ES2022"}}', encoding="utf-8")
    config_changed = inspect_environment(tmp_path, declared_only())
    assert config_changed.fingerprint != before.fingerprint
    lock.write_text('{"version":2}', encoding="utf-8")
    assert inspect_environment(tmp_path, declared_only()).fingerprint != config_changed.fingerprint


def test_missing_cycles_and_external_extends_are_explicit(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret":"outside-secret"}', encoding="utf-8")
    (root / "tsconfig.json").write_text(
        '{"extends":["./base.json","../outside.json","third-party/config"]}', encoding="utf-8")
    (root / "base.json").write_text('{"extends":"./tsconfig.json"}', encoding="utf-8")
    profile = inspect_environment(root, declared_only())
    assert any("cyclic" in item for item in profile.unknowns)
    assert any("outside project" in item for item in profile.unknowns)
    assert any("package or absolute extends" in item for item in profile.unknowns)
    assert "outside-secret" not in json.dumps(profile.to_dict())
    (root / "base.json").unlink()
    missing = inspect_environment(root, declared_only())
    assert missing.configuration_files["base.json"].startswith("unread:")


def test_invalid_declaration_is_unknown_not_executed(tmp_path):
    (tmp_path / "package.json").write_text('{"engines":', encoding="utf-8")
    (tmp_path / "setup.py").write_text("raise RuntimeError('must not run')", encoding="utf-8")
    profile = inspect_environment(tmp_path, declared_only())
    assert profile.declared["configuration_records"]["package.json"]["status"] == "invalid"
    assert any("invalid text configuration" in item for item in profile.unknowns)


def test_requirements_only_python_unit_is_not_lost_beside_frontend(tmp_path):
    (tmp_path / "requirements.txt").write_text("private @ https://secret@host/pkg\n", encoding="utf-8")
    (tmp_path / ".python-version").write_text("3.11", encoding="utf-8")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/package.json").write_text("{}", encoding="utf-8")
    profile = inspect_environment(tmp_path, declared_only())
    assert {unit["path"] for unit in profile.project_units} == {".", "frontend"}
    unit = next(unit for unit in profile.project_units if unit["path"] == ".")
    assert unit["declarations"]["python"]["dependency_declaration_files"] == ["requirements.txt"]
    assert unit["declarations"]["python"]["version_files"][".python-version"] == "3.11"
    assert "secret@host" not in json.dumps(profile.to_dict())


def test_target_typescript_and_target_node_are_not_discovered(tmp_path, monkeypatch):
    target_package = tmp_path / "node_modules" / "typescript" / "lib"
    target_package.mkdir(parents=True)
    (target_package / "typescript.js").write_text("throw new Error('must not load');", encoding="utf-8")
    fake_node = tmp_path / ("node.exe" if tools.os.name == "nt" else "node")
    fake_node.write_text("must not execute", encoding="utf-8")
    monkeypatch.setenv("CODESENTRY_NODE", str(fake_node))
    monkeypatch.setattr(tools, "managed_tools_root", lambda: tmp_path / "analyzer-tools")
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: pytest.fail("target node executed"))
    chain = get_toolchain(tmp_path)
    assert chain.node is None and chain.typescript_path is None
    assert "node_executable_inside_target_rejected" in chain.diagnostics
    assert "typescript_managed_package_missing" in chain.diagnostics


def test_modified_managed_compiler_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "managed_tools_root", lambda: tmp_path / "analyzer-tools")
    monkeypatch.setattr(tools, "_find_node", lambda _: (None, None, None, "node_unavailable"))
    package = tools.managed_typescript_dir()
    (package / "lib").mkdir(parents=True)
    (package / "lib/typescript.js").write_text("untrusted change", encoding="utf-8")
    (package / "codesentry-toolchain.json").write_text(json.dumps({
        "version": tools.TYPESCRIPT_VERSION, "integrity": tools.TYPESCRIPT_INTEGRITY,
    }), encoding="utf-8")
    chain = tools.get_toolchain(tmp_path)
    assert chain.typescript_path is None
    assert "typescript_compiler_integrity_mismatch" in chain.diagnostics


@pytest.mark.parametrize("receipt", [
    None, [], ["version"], 42, "not-an-object",
    {"version": [tools.TYPESCRIPT_VERSION], "integrity": tools.TYPESCRIPT_INTEGRITY},
    {"version": tools.TYPESCRIPT_VERSION, "integrity": None},
])
def test_invalid_toolchain_receipt_is_unavailable_before_compiler_read(tmp_path, monkeypatch, receipt):
    monkeypatch.setattr(tools, "managed_tools_root", lambda: tmp_path / "analyzer-tools")
    monkeypatch.setattr(tools, "_find_node", lambda _: (None, None, None, "node_unavailable"))
    package = tools.managed_typescript_dir()
    (package / "lib").mkdir(parents=True)
    (package / "lib/typescript.js").write_text("must not be loaded", encoding="utf-8")
    (package / "codesentry-toolchain.json").write_text(json.dumps(receipt), encoding="utf-8")
    monkeypatch.setattr(tools, "_digest_file", lambda _: pytest.fail("compiler was read after invalid provenance"))
    chain = tools.get_toolchain(tmp_path)
    assert chain.typescript_path is None
    assert "typescript_provenance_invalid" in chain.diagnostics


def test_install_rejects_wrong_integrity_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "managed_tools_root", lambda: tmp_path / "analyzer-tools")
    archive = tmp_path / "bad.tgz"
    archive.write_bytes(b"this is not the official package")
    with pytest.raises(ValueError, match="integrity"):
        tools.install_typescript(archive)
    assert not tools.managed_typescript_dir().exists()


def test_archive_path_traversal_is_rejected_even_with_matching_archive_digest(monkeypatch):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        payload = b"bad"
        entry = tarfile.TarInfo("package/../escape.js")
        entry.size = len(payload)
        archive.addfile(entry, io.BytesIO(payload))
    data = output.getvalue()
    monkeypatch.setattr(tools, "TYPESCRIPT_INTEGRITY",
                        "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode())
    with pytest.raises(ValueError, match="unsafe archive path"):
        tools._verified_archive(data)


@pytest.fixture
def managed_parser(tmp_path):
    chain = get_toolchain(tmp_path)
    if not chain.node or not chain.typescript_path:
        pytest.skip("managed TypeScript unavailable: " + ", ".join(chain.diagnostics))
    parser = TypeScriptParser(tmp_path, toolchain=chain)
    yield parser
    parser.close()


def test_typescript_uses_passed_snapshot_and_classifies_import_kinds(tmp_path, managed_parser):
    source = (
        'import type {T} from "./types"; import { type Q } from "./only"; '
        'import "./side"; export type {T} from "./again"; '
        'const value = import("./dynamic"); export function run() { return 1; }'
    )
    path = tmp_path / "file.ts"
    path.write_text("definitely not this source !!!", encoding="utf-8")
    symbols, _, meta, _ = managed_parser.parse_with_meta(path, "file.ts", source)
    assert meta.is_parsed and not meta.parse_error
    assert "file.ts::run" in {symbol.qname for symbol in symbols}
    assert meta.import_kinds == {
        "./types": "type", "./only": "type", "./side": "runtime",
        "./again": "type", "./dynamic": "conditional",
    }


def test_loader_injection_does_not_run_and_parser_script_is_read_only(tmp_path, managed_parser, monkeypatch):
    marker = tmp_path / "loader-was-executed"
    loader = tmp_path / "loader.js"
    loader.write_text("require('node:fs').writeFileSync(" + json.dumps(str(marker)) + ", 'bad');", encoding="utf-8")
    monkeypatch.setenv("NODE_OPTIONS", "--require " + str(loader))
    monkeypatch.setenv("NODE_PATH", str(tmp_path / "node_modules"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("SECRET_FOR_TEST", "must-not-forward")
    script = Path(__file__).parents[1] / "codesentry/parsers/_ts_extract.js"
    before = script.read_bytes()
    import codesentry.parsers.ts_parser as ts_module
    popen = ts_module.subprocess.Popen
    calls = []

    def capture(*args, **kwargs):
        calls.append(kwargs)
        return popen(*args, **kwargs)

    monkeypatch.setattr(ts_module.subprocess, "Popen", capture)
    path = tmp_path / "file.ts"
    path.write_text("export function run() {}", encoding="utf-8")
    _, _, meta, _ = managed_parser.parse_with_meta(path, "file.ts", path.read_text())
    assert meta.is_parsed and not marker.exists()
    assert script.read_bytes() == before
    assert calls and Path(calls[0]["cwd"]).resolve() != tmp_path.resolve()
    assert not {"NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "SECRET_FOR_TEST"} & set(calls[0]["env"])


def test_syntax_failure_and_unavailable_toolchain_are_visible(tmp_path, managed_parser):
    path = tmp_path / "broken.ts"
    path.write_text("function broken( {", encoding="utf-8")
    _, _, meta, _ = managed_parser.parse_with_meta(path, "broken.ts", path.read_text())
    assert not meta.is_parsed and meta.parse_error == "typescript_syntax_error"
    with Parser(tmp_path, toolchain=Toolchain(diagnostics=["not-installed"])) as parser:
        _, _, unavailable, _ = parser.parse_with_meta(path, "broken.ts", path.read_text(), ".ts")
    assert not unavailable.is_parsed and "managed_typescript_unavailable" in unavailable.parse_error


def test_typescript_timeout_is_bounded_and_worker_is_reaped(tmp_path, managed_parser):
    managed_parser.timeout_seconds = 0.000001
    path = tmp_path / "file.ts"
    path.write_text("export function run() {}", encoding="utf-8")
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="typescript_parse_timeout"):
        managed_parser.parse_with_meta(path, "file.ts", path.read_text())
    assert time.monotonic() - started < 5
    assert managed_parser._proc is None
