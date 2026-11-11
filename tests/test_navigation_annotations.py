"""Draft labels remain unknown and cannot bypass current file permissions."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from evals import navigation_annotations as annotations
from evals.navigation_development import _digest


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "tests").mkdir()
    names = ["main.py", "lib.py", "tests/test_lib.py"]
    for name in names + ["private.py"]:
        (root / name).write_text("PRIVATE_SOURCE_TEXT = 'must-stay-local'\n", encoding="utf-8")
    (root / ".gitignore").write_text("generated/\n", encoding="utf-8")
    state = tmp_path / "state"
    state.mkdir()
    settings = {"exclude": ["private.py"]}
    access = AccessPolicy(root, settings)
    saved = access.to_dict() | {"version": 1, "cleanup_pending": False}
    workspace = {"workspace_id": "a" * 32, "policy_version": 1,
                 "policy_fingerprint": access.fingerprint, "settings": access.settings}
    with sqlite3.connect(state / "workspaces.sqlite3") as connection:
        connection.execute("CREATE TABLE workspaces(id TEXT,path TEXT,canonical_key TEXT,access_policy TEXT)")
        connection.execute("INSERT INTO workspaces VALUES(?,?,?,?)", ("a" * 32, str(root),
                           os.path.normcase(str(root)), json.dumps(saved)))
    inputs = {"source_inventory": [
        {"path": name, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
         "ranking_scope": not name.startswith("tests/")}
        for name in names], "startup_input_hashes": {}}
    manifest = {"schema_version": 1, "manifest_kind": "navigation-development-allowed-run",
                "role": "dev-regression", "holdout": False, "root": str(root), "project_id": "synthetic",
                "workspace": workspace, "algorithm_scope": {"extensions": [".py"]},
                "inputs": inputs, "input_snapshot_sha256": _digest(inputs),
                "label_provenance": {"ranking_eligible_canonical_labels": ["main.py"],
                                     "entry_gold": {"files": ["main.py"]}}}
    path = tmp_path / "frozen.manifest.json"
    output = tmp_path / "drafts" / "navigation.json"
    value = {"root": root, "state": state, "manifest": manifest, "path": path, "output": output,
             "names": names}
    write_manifest(value)
    return value


def write_manifest(sample):
    sample["manifest"]["input_snapshot_sha256"] = _digest(sample["manifest"]["inputs"])
    raw = json.dumps(sample["manifest"], ensure_ascii=False).encode("utf-8")
    sample["path"].write_bytes(raw)
    sample["path"].with_name(sample["path"].name + ".sha256").write_text(
        hashlib.sha256(raw).hexdigest(), encoding="ascii")


def generate(sample):
    return annotations.create_annotation_draft(sample["path"], sample["state"], output=sample["output"])


def forbid_source_access(sample, monkeypatch):
    files = {sample["root"] / name for name in sample["names"] + ["private.py"]}
    original_open, original_stat = Path.open, Path.stat
    def guarded_open(path, *args, **kwargs):
        if path in files:
            pytest.fail("Annotation draft opened target source")
        return original_open(path, *args, **kwargs)
    def guarded_stat(path, *args, **kwargs):
        if path in files:
            pytest.fail("Annotation draft statted target source")
        return original_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr(Path, "stat", guarded_stat)


def test_full_inventory_draft_has_no_prefilled_labels_or_target_source_reads(sample, monkeypatch):
    forbid_source_access(sample, monkeypatch)
    result = generate(sample)
    assert result == {"valid_draft_structure": True, "files": 3, "formal_passed": False,
                      "status": "draft_unknown", "source_snapshot_revalidated": False,
                      "human_labels_approved": False}
    raw = sample["output"].read_text(encoding="utf-8")
    draft = json.loads(raw)
    assert {row["file"] for row in draft["files"]} == set(sample["names"])
    assert all(row["reading_key"] is row["entry_roles"] is None and row["evidence"] == []
               for row in draft["files"])
    assert draft["task"]["deployment_context"] is None
    assert draft["source_binding"]["snapshot_kind"] == "frozen_manifest_snapshot"
    assert draft["formal_acceptance"]["passed"] is False
    assert "PRIVATE_SOURCE_TEXT" not in raw and "label_provenance" not in raw
    assert sample["output"].with_name("navigation.instructions.md").read_text(encoding="utf-8").startswith("# 人工导航标注草稿说明")


def test_export_refuses_to_overwrite_any_existing_output(sample):
    generate(sample)
    before = sample["output"].read_bytes()
    with pytest.raises(FileExistsError):
        generate(sample)
    assert sample["output"].read_bytes() == before


def test_export_cannot_write_into_target_source(sample):
    sample["output"] = sample["root"] / "labels.json"
    with pytest.raises(ValueError, match="outside target"):
        generate(sample)
    assert not sample["output"].exists()


def test_existing_instruction_file_is_preserved_before_any_export(sample):
    sample["output"].parent.mkdir()
    instructions = sample["output"].with_name("navigation.instructions.md")
    instructions.write_text("KEEP_EXISTING_NOTE", encoding="utf-8")
    with pytest.raises(FileExistsError):
        generate(sample)
    assert instructions.read_text(encoding="utf-8") == "KEEP_EXISTING_NOTE"
    assert not sample["output"].exists()


def test_manifest_hash_tamper_is_rejected_before_source_access(sample, monkeypatch):
    sample["path"].write_text("{}", encoding="utf-8")
    forbid_source_access(sample, monkeypatch)
    with pytest.raises(ValueError, match="hash changed"):
        generate(sample)
    assert not sample["output"].exists()


@pytest.mark.parametrize("path", ["../secret.py", "/secret.py", "a\\secret.py", "a.py:stream", "alias.py "])
def test_invalid_frozen_paths_cannot_become_annotation_rows(sample, monkeypatch, path):
    sample["manifest"]["inputs"]["source_inventory"][0]["path"] = path
    write_manifest(sample)
    forbid_source_access(sample, monkeypatch)
    with pytest.raises(ValueError):
        generate(sample)
    assert not sample["output"].exists()


def test_alias_rows_are_rejected_instead_of_shrinking_a_denominator(sample):
    row = dict(sample["manifest"]["inputs"]["source_inventory"][0])
    row["path"] = "MAIN.PY"
    sample["manifest"]["inputs"]["source_inventory"].append(row)
    write_manifest(sample)
    with pytest.raises(ValueError, match="aliased"):
        generate(sample)


def test_policy_change_refuses_before_source_read_or_export(sample, monkeypatch):
    with sqlite3.connect(sample["state"] / "workspaces.sqlite3") as connection:
        access = json.loads(connection.execute("SELECT access_policy FROM workspaces").fetchone()[0])
        access["version"] = 2
        connection.execute("UPDATE workspaces SET access_policy=?", (json.dumps(access),))
    forbid_source_access(sample, monkeypatch)
    with pytest.raises(AccessDenied):
        generate(sample)
    assert not sample["output"].exists()


def test_changed_ignore_controls_refuse_without_rehashing_source(sample, monkeypatch):
    (sample["root"] / ".gitignore").write_text("main.py\n", encoding="utf-8")
    forbid_source_access(sample, monkeypatch)
    with pytest.raises(AccessDenied):
        generate(sample)
    assert not sample["output"].exists()


def test_policy_change_during_export_discards_only_created_files(sample, monkeypatch):
    original = annotations._check_scope
    calls = []
    def check(*args):
        calls.append(True)
        if len(calls) == 3:
            raise AccessDenied("Synthetic revocation")
        return original(*args)
    monkeypatch.setattr(annotations, "_check_scope", check)
    with pytest.raises(AccessDenied):
        generate(sample)
    assert not sample["output"].exists()
    assert not sample["output"].with_name("navigation.instructions.md").exists()


@pytest.mark.parametrize("field", ["human_labels_approved", "source_snapshot_revalidated"])
def test_draft_cannot_self_approve_or_claim_source_revalidation(sample, field):
    generate(sample)
    draft = json.loads(sample["output"].read_bytes())
    draft[field] = True
    with pytest.raises(ValueError, match="cannot claim"):
        annotations.validate_draft_structure(draft)


def test_manual_answers_remain_draft_and_never_create_formal_metrics(sample):
    generate(sample)
    draft = json.loads(sample["output"].read_bytes())
    draft["files"][0].update(reading_key=True, entry_roles=["process"], evidence=[])
    assert annotations.validate_draft_structure(draft)["formal_passed"] is False
    altered = copy.deepcopy(draft)
    altered["formal_acceptance"]["passed"] = True
    with pytest.raises(ValueError):
        annotations.validate_draft_structure(altered)


def test_console_contains_only_draft_aggregates(sample, capsys):
    assert annotations.main([str(sample["path"]), "--workspace-data-dir", str(sample["state"]),
                             "--output", str(sample["output"])]) == 0
    output = capsys.readouterr().out
    assert '"files": 3' in output and '"formal_passed": false' in output
    assert "main.py" not in output and str(sample["root"]) not in output
