"""Static fixture provenance/shape checks: never import or execute the target."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals import fingerprint_reproduction as fixture


def read_json(name):
    return json.loads((fixture.FIXTURE / name).read_text(encoding="utf-8"))


def parse_variant(name):
    return ast.parse((fixture.FIXTURE / name / "fingerprint.py").read_text(encoding="utf-8"))


def test_descriptor_freezes_real_source_identity_and_source_only_snapshots():
    descriptor = fixture.load_fixture()
    before = (fixture.FIXTURE / "before" / "fingerprint.py").read_bytes()
    provenance = descriptor["source_provenance"]
    assert provenance["relative_path"] == "codesentry/core/fingerprint.py"
    assert provenance["head_commit"] == "3df1782b23eecec50486f75b761e5814a516ba92"
    assert provenance["normalized_lf_equal_to_head"]
    assert provenance["working_tree_sha256"] == provenance["head_content_sha256"] == hashlib.sha256(before).hexdigest()
    git_blob = hashlib.sha1(b"blob " + str(len(before)).encode("ascii") + b"\0" + before).hexdigest()
    assert git_blob == provenance["head_blob_oid"] == "0c3fe2153a114649fb62ebb48615412d0d7a5f89"
    for variant in descriptor["source_roots"]:
        assert {path.name for path in (fixture.FIXTURE / variant).iterdir()} == {"fingerprint.py", "behavior_driver.py"}
    assert (fixture.FIXTURE / "before" / "behavior_driver.py").read_bytes() == (fixture.FIXTURE / "fix_candidate" / "behavior_driver.py").read_bytes()


def test_candidate_changes_only_normalization_to_full_raw_snippet():
    before, candidate = parse_variant("before"), parse_variant("fix_candidate")
    left = next(node for node in before.body if isinstance(node, ast.FunctionDef) and node.name == "normalize_snippet")
    right = next(node for node in candidate.body if isinstance(node, ast.FunctionDef) and node.name == "normalize_snippet")
    assert ast.dump(left.args) == ast.dump(right.args)
    assert len(right.body) == 2 and isinstance(right.body[0], ast.Expr)
    assert isinstance(right.body[1], ast.Return) and isinstance(right.body[1].value, ast.Name)
    assert right.body[1].value.id == "snippet"
    candidate.body[candidate.body.index(right)] = deepcopy(left)
    assert ast.dump(before) == ast.dump(candidate)


def test_before_static_evidence_contains_cutoff_and_whitespace_regex():
    before = parse_variant("before")
    function = next(node for node in before.body if isinstance(node, ast.FunctionDef) and node.name == "normalize_snippet")
    assert isinstance(function.args.defaults[-1], ast.Constant) and function.args.defaults[-1].value == 12
    assert any(isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)
               and isinstance(node.slice.upper, ast.Name) and node.slice.upper.id == "max_lines"
               for node in ast.walk(function))
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and isinstance(node.func.value, ast.Name) and node.func.value.id == "_WS_RE"
               and node.func.attr == "sub" for node in ast.walk(function))


def test_trusted_plan_expected_stdout_is_independent_and_not_in_snapshot():
    plan = fixture.load_plan()
    expected_ids = {"after_line_12_changes_fingerprint", "string_internal_whitespace_changes_fingerprint", "identical_snippet_is_stable"}
    assert set(plan) == {"schema_version", "plan_id", "cases"}
    assert plan["schema_version"] == 1 and plan["plan_id"] == "fingerprint-reproduction-v1"
    assert {case["case_id"] for case in plan["cases"]} == expected_ids
    for case in plan["cases"]:
        assert set(case) == {"case_id", "argv", "cwd", "expected_output_sha256"}
        assert case["argv"] == ["python3", "-I", "behavior_driver.py", case["case_id"]]
        assert case["cwd"] == "."
        raw = (json.dumps({"actual": True, "case_id": case["case_id"]}, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        assert hashlib.sha256(raw).hexdigest() == case["expected_output_sha256"]
    driver = (fixture.FIXTURE / "before" / "behavior_driver.py").read_text(encoding="utf-8")
    ast.parse(driver)
    assert "expected_output_sha256" not in driver and "expected_actual" not in driver
    assert "spec_from_file_location" in driver
    assert "plan.json" not in driver and "data_card.json" not in driver


def test_card_keeps_dynamic_and_independent_adjudication_unknown():
    card = read_json("data_card.json")
    assert card["split"] == "dev" and card["label"] == "unknown"
    assert card["independent_human_adjudication"] == "pending"
    assert card["dynamic_reproduction"] == {"status": "not_run", "before": None, "fix_candidate": None}
    assert card["rule_basis"]["section"] == "3.3.2"
    assert all(case["expected_actual"] for case in card["cases"])
    assert [case["static_before_hypothesis"] for case in card["cases"]] == [False, False, True]


def test_fixture_loader_cannot_import_or_execute_target(monkeypatch):
    import importlib.util
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("target execution/import must not occur on host")

    monkeypatch.setattr(importlib.util, "spec_from_file_location", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    descriptor = fixture.load_fixture()
    assert descriptor["reproduction_id"] == "fingerprint-reproduction-v1"


def test_fixture_byte_drift_is_rejected(tmp_path, monkeypatch):
    original = fixture.FIXTURE
    for relative in fixture.FROZEN_SHA256:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((original / relative).read_bytes())
    (tmp_path / "fix_candidate" / "fingerprint.py").write_text("changed", encoding="utf-8")
    monkeypatch.setattr(fixture, "FIXTURE", tmp_path)
    with pytest.raises(ValueError, match="changed"):
        fixture.load_fixture()


def test_snapshot_cannot_accidentally_include_expected_answers(tmp_path, monkeypatch):
    for relative in fixture.FROZEN_SHA256:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((fixture.FIXTURE / relative).read_bytes())
    (tmp_path / "before" / "plan.json").write_text("answers", encoding="utf-8")
    monkeypatch.setattr(fixture, "FIXTURE", tmp_path)
    with pytest.raises(ValueError, match="only module and driver"):
        fixture.load_fixture()


def test_loader_returns_fresh_metadata_not_mutable_shared_authority():
    descriptor = fixture.load_fixture()
    descriptor["source_roots"]["before"] = "other"
    assert fixture.load_fixture()["source_roots"]["before"] == "before"


def test_plan_drift_between_fixture_check_and_plan_read_is_rejected(tmp_path, monkeypatch):
    for relative in fixture.FROZEN_SHA256:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((fixture.FIXTURE / relative).read_bytes())
    monkeypatch.setattr(fixture, "FIXTURE", tmp_path)
    original_load = fixture.load_fixture

    def mutate_after_check():
        descriptor = original_load()
        (tmp_path / "plan.json").write_text('{"changed":true}', encoding="utf-8")
        return descriptor

    monkeypatch.setattr(fixture, "load_fixture", mutate_after_check)
    with pytest.raises(ValueError, match="plan changed"):
        fixture.load_plan()


@pytest.mark.parametrize("relative", ["before", ".", ".."])
def test_reparse_in_any_fixture_ancestor_is_rejected_before_content_read(monkeypatch, relative):
    redirected = Path(fixture.os.path.abspath(fixture.FIXTURE / relative))
    original_lstat, original_open = Path.lstat, Path.open
    opened = []

    def fake_lstat(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        if path == redirected:
            return SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=0x400)
        return metadata

    def record_open(path, *args, **kwargs):
        opened.append(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(Path, "open", record_open)
    with pytest.raises(ValueError, match="reparse"):
        fixture.load_fixture()
    assert opened == []


def test_multi_hardlink_file_is_rejected_before_content_read(monkeypatch):
    target = fixture.FIXTURE / "before" / "behavior_driver.py"
    original = Path.lstat

    def fake_lstat(path, *args, **kwargs):
        metadata = original(path, *args, **kwargs)
        if path == target:
            return SimpleNamespace(st_mode=metadata.st_mode, st_nlink=2, st_file_attributes=0)
        return metadata

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: pytest.fail("hardlink content opened"))
    with pytest.raises(ValueError, match="one hard link"):
        fixture.load_fixture()


def test_checked_read_refuses_path_outside_fixed_root(monkeypatch):
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: pytest.fail("external file opened"))
    with pytest.raises(ValueError, match="fixed root"):
        fixture._read_checked(fixture.FIXTURE.parent / "external.json")
