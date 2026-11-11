"""The evaluator cannot use an old freeze to restore revoked file access."""
from __future__ import annotations

import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from codesentry.access import AccessPolicy
from codesentry.core.symbol import FileMeta, Language, Symbol, SymbolKind
from codesentry.index.builder import IndexResult
from codesentry.index.entrypoint import EntryPoint
from evals import m0_acceptance as acceptance


@pytest.fixture
def sample(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    names = [f"module{i}.py" for i in range(12)]
    for name in names:
        (root / name).write_text("value = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (root / "README.md").write_text("fixture documentation\n", encoding="utf-8")
    truth = tmp_path / "gold.json"
    truth.write_text(json.dumps(names[:8]), encoding="utf-8")
    def row(name):
        data = (root / name).read_bytes()
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "ranking_scope": True}
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({
        "contract_version": 1, "contract_id": "access-fixture-only",
        "task": {"p_at_10": {"threshold": 0.8}, "latency_seconds": {"l1_less_than": 30, "l2_less_than": 180},
                 "entry_gold": {"status": "independently_adjudicated", "files": [names[0]], "fixture_only": True}},
        "frozen_scope": {"extensions": [".py"], "not_parsed_directory_names": [".git", ".venv"], "not_ranked_directory_names": ["tests"]},
        "formal_acceptance_blockers": [],
        "projects": [{"project_id": "fixture", "root": str(root), "role": "dev-regression", "holdout": False,
                      "source_inventory": [row(name) for name in names],
                      "environment_declarations": [row("pyproject.toml")], "documents": [row("README.md")],
                      "legacy_gt": {"path": str(truth), "sha256": hashlib.sha256(truth.read_bytes()).hexdigest()},
                      "ranking_eligible_canonical_labels": names[:8], "not_ranked_canonical_labels": [],
                      "unmatched_labels": [], "ambiguous_labels": []}],
    }), encoding="utf-8")
    result = IndexResult(root=str(root), files=[FileMeta(path=name, language=Language.PYTHON) for name in names])
    result.entrypoints = [EntryPoint(file=names[0], level="app", reason="fixture")]
    result.file_pr = {name: 1 / (index + 1) for index, name in enumerate(names)}
    monkeypatch.setattr(acceptance, "build_index", lambda *args, **kwargs: result)
    monkeypatch.setattr(acceptance, "reading_order", lambda *args, **kwargs: [(name, "fixture", 0) for name in names])
    monkeypatch.setattr(acceptance, "render_l1", lambda _: "L1 test output")
    monkeypatch.setattr(acceptance, "render_l2", lambda _: "L2 test output")
    return SimpleNamespace(root=root, names=names, truth=truth, contract=contract, result=result, base=tmp_path)


def invoke(sample, *args, confirmed=True):
    flags = ["--confirm-access"] if confirmed else []
    return acceptance.main([str(sample.root), "--contract", str(sample.contract), "--project-id", "fixture", "--no-cache", *flags, *args])


def forbid_open(monkeypatch, paths, *, active=lambda: True):
    original = Path.open
    denied = {path.absolute() for path in paths}
    calls = []
    def checked(path, *args, **kwargs):
        if active() and path.absolute() in denied:
            calls.append(str(path))
            pytest.fail("Evaluator opened forbidden content: " + path.name)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", checked)
    return calls


def test_no_confirmation_does_not_hash_target_or_invoke_builder(sample, monkeypatch, capsys):
    forbid_open(monkeypatch, [sample.root/name for name in sample.names])
    monkeypatch.setattr(acceptance, "build_index", lambda *a, **k: pytest.fail("unconfirmed evaluator reached builder"))
    assert invoke(sample, confirmed=False) == 2
    assert "确认" in capsys.readouterr().out


@pytest.mark.parametrize("name", ["module0.py", "pyproject.toml", "README.md"])
def test_frozen_manifest_does_not_authorize_excluded_content(sample, monkeypatch, capsys, name):
    before = sample.contract.read_bytes()
    forbid_open(monkeypatch, [sample.root/name])
    monkeypatch.setattr(acceptance, "build_index", lambda *a, **k: pytest.fail("conflicting scope reached builder"))
    assert invoke(sample, "--exclude", name) == 1
    output = capsys.readouterr().out
    assert "ACCESS_SCOPE_CONFLICT" in output and "not_evaluable" in output
    assert "P@10=" not in output
    assert sample.contract.read_bytes() == before


def test_git_ignored_frozen_source_is_not_opened_even_for_hash(sample, monkeypatch, capsys):
    (sample.root/".gitignore").write_text("module0.py\n", encoding="utf-8")
    forbid_open(monkeypatch, [sample.root/"module0.py"])
    assert invoke(sample) == 1
    assert "ACCESS_SCOPE_CONFLICT" in capsys.readouterr().out


def test_new_ignored_source_cannot_make_old_scope_look_unchanged(sample, monkeypatch, capsys):
    hidden = sample.root/"new_private.py"
    hidden.write_text("SECRET='fixture-only'\n", encoding="utf-8")
    (sample.root/".gitignore").write_text("new_private.py\n", encoding="utf-8")
    forbid_open(monkeypatch, [hidden])
    monkeypatch.setattr(acceptance, "build_index", lambda *a, **k: pytest.fail("hidden source scope change reached builder"))
    assert invoke(sample) == 1
    assert "ACCESS_SCOPE_CONFLICT" in capsys.readouterr().out


def test_banned_git_control_is_not_read_to_prove_compatibility(sample, monkeypatch, capsys):
    control = sample.root/".gitignore"
    control.write_text("*.tmp\n", encoding="utf-8")
    forbid_open(monkeypatch, [control, *[sample.root/name for name in sample.names]])
    assert invoke(sample, "--exclude", ".gitignore") == 1
    assert "ACCESS_SCOPE_CONFLICT" in capsys.readouterr().out


def test_scope_change_during_build_cannot_publish_old_result(sample, monkeypatch, capsys):
    revoked = [False]
    forbid_open(monkeypatch, [sample.root/"module0.py"], active=lambda: revoked[0])
    def build(*args, **kwargs):
        assert isinstance(kwargs["access"], AccessPolicy)
        (sample.root/".gitignore").write_text("module0.py\n", encoding="utf-8")
        revoked[0] = True
        return sample.result
    monkeypatch.setattr(acceptance, "build_index", build)
    assert invoke(sample) == 1
    output = capsys.readouterr().out
    assert "ACCESS_SCOPE_CONFLICT" in output
    assert "L1 test output" not in output and "P@10=" not in output


def test_output_location_verifier_uses_same_exclusions(sample, monkeypatch):
    name = sample.names[0]
    sample.result.symbols = [Symbol(qname=name+"::run", name="run", kind=SymbolKind.FUNCTION, file=name, line=1)]
    sample.result.symbol_pr = {name+"::run": 1.0}
    access = AccessPolicy(sample.root, {"exclude":[name]})
    forbid_open(monkeypatch, [sample.root/name])
    errors = acceptance.output_location_errors(sample.root, sample.result, [name], access=access)
    assert any("符号文件不可读" in error for error in errors)
    assert any("输出位置不可访问" in error for error in errors)


@pytest.mark.parametrize('legacy_schema', [True, False])
def test_cli_confirmation_cannot_skip_registered_migration(sample, monkeypatch, capsys, legacy_schema):
    state = sample.base/"state"
    if legacy_schema:
        state.mkdir()
        with closing(sqlite3.connect(state/"workspaces.sqlite3")) as connection:
            connection.execute("CREATE TABLE workspaces(canonical_key TEXT,access_policy TEXT)")
            connection.execute("INSERT INTO workspaces VALUES(?,?)", (os.path.normcase(str(sample.root)), json.dumps({"confirmed":False})))
            connection.commit()
    else:
        from codesentry.workspaces.store import WorkspaceStore
        WorkspaceStore(state).create_workspace(str(sample.root))
    forbid_open(monkeypatch, [sample.root/name for name in sample.names])
    assert invoke(sample, "--workspace-data-dir", str(state)) == 2
    assert "工作台" in capsys.readouterr().out


def add_startup_evidence(sample, name="package.json", text='{"main": "module0.py"}\n', *, line=1):
    path = sample.root / name
    path.write_text(text, encoding="utf-8")
    sample.result.startup_inputs[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    sample.result.entrypoints[0].evidence = [{"file": name, "line": line, "type": "fixture_startup_declaration"}]
    return path


def test_entry_evidence_accepts_frozen_startup_config_outside_source_index(sample):
    path = add_startup_evidence(sample)
    assert path.name not in {item.path for item in sample.result.files}
    assert acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root)) == []


@pytest.mark.parametrize("line", [0, -1, 2])
def test_entry_evidence_rejects_out_of_range_config_lines(sample, line):
    add_startup_evidence(sample, line=line)
    errors = acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root))
    assert any("入口证据行号越界" in error for error in errors)


@pytest.mark.parametrize("line", [True, "1", 1.5])
def test_entry_evidence_rejects_non_integer_lines(sample, line):
    add_startup_evidence(sample, line=line)
    errors = acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root))
    assert any("入口证据行号无效" in error for error in errors)


def test_entry_evidence_rejects_outside_root_without_opening(sample, monkeypatch):
    outside = sample.base / "outside.json"
    outside.write_text("private fixture\n", encoding="utf-8")
    name = "../outside.json"
    sample.result.startup_inputs[name] = hashlib.sha256(outside.read_bytes()).hexdigest()
    sample.result.entrypoints[0].evidence = [{"file": name, "line": 1}]
    forbid_open(monkeypatch, [outside])
    errors = acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root))
    assert any("入口证据文件不可读或越界" in error for error in errors)


def test_entry_evidence_obeys_denial_before_config_hash_or_line_read(sample, monkeypatch):
    path = add_startup_evidence(sample)
    access = AccessPolicy(sample.root, {"exclude": [path.name]})
    forbid_open(monkeypatch, [path])
    errors = acceptance.output_location_errors(sample.root, sample.result, [], access=access)
    assert any("入口证据文件不可读或越界" in error for error in errors)


def test_entry_evidence_unfrozen_config_is_not_opened(sample, monkeypatch):
    path = add_startup_evidence(sample)
    sample.result.startup_inputs.clear()
    forbid_open(monkeypatch, [path])
    errors = acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root))
    assert any("入口证据文件未冻结" in error for error in errors)


def test_entry_evidence_unread_startup_input_is_not_opened(sample, monkeypatch):
    path = add_startup_evidence(sample)
    sample.result.startup_inputs[path.name] = "unread:access-policy"
    forbid_open(monkeypatch, [path])
    errors = acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root))
    assert any("入口证据启动输入未成功冻结" in error for error in errors)


def test_entry_evidence_detects_changed_startup_input_hash(sample):
    path = add_startup_evidence(sample)
    path.write_text('{"main": "module1.py"}\n', encoding="utf-8")
    errors = acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root))
    assert any("入口证据启动输入摘要不一致" in error for error in errors)


@pytest.mark.parametrize("include_line", [True, False])
def test_entry_evidence_unknown_line_does_not_invent_first_line(sample, include_line):
    add_startup_evidence(sample, text="", line=None)
    if not include_line:
        sample.result.entrypoints[0].evidence[0].pop("line")
    assert acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root)) == []


def test_entry_evidence_accepts_indexed_source_without_config_freeze(sample):
    sample.result.entrypoints[0].evidence = [{"file": sample.names[1], "line": 1}]
    assert acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root)) == []


def test_entry_evidence_reports_missing_frozen_config(sample):
    path = add_startup_evidence(sample)
    path.unlink()
    errors = acceptance.output_location_errors(sample.root, sample.result, [], access=AccessPolicy(sample.root))
    assert any("入口证据文件不可读或越界" in error for error in errors)
