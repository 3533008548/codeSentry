"""Owner-confirmed dev label construction; target source is never executed."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from evals import fingerprint_dataset as dataset
from evals import fingerprint_reproduction as fixture
from evals.review_scoring import score_review
from evals.split_audit import audit_splits


ROOT = Path(__file__).parents[1]
RECEIPT = ROOT / "evals" / "adjudications" / "fingerprint_owner_20261028_v1.json"
REPORT = ROOT / "evals" / "reports" / "p2_fingerprint_reproduction_20261028.json"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sources(tmp_path):
    receipt, report = tmp_path / "receipt.json", tmp_path / "report.json"
    receipt.write_bytes(RECEIPT.read_bytes())
    report.write_bytes(REPORT.read_bytes())
    return receipt, report


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def rebind_report(receipt_path, report_path, mutation):
    report = read(report_path)
    mutation(report)
    write(report_path, report)
    receipt = read(receipt_path)
    receipt["evidence"]["reproduction_report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
    write(receipt_path, receipt)


def test_owner_bundle_has_two_precise_before_issues_and_empty_non_detector_reference(tmp_path):
    destination = tmp_path / "new-dataset"
    manifest = dataset.build_dataset(RECEIPT, REPORT, destination)
    gold, predictions, splits = [read(destination / name) for name in ("gold.json", "predictions.json", "splits.json")]
    assert len(gold["cases"]) == 1
    case = gold["cases"][0]
    assert case["path"] == "fingerprint.py" and case["source_snapshot"] == read(REPORT)["variants"]["before"]["verification"]["snapshot_digest"]
    assert case["label"] == "bugs" and case["adjudication"] == "confirmed"
    assert case["scope"] == {"start_line": 23, "end_line": 36, "complete": False}
    assert [(issue["id"], issue["locations"]) for issue in case["issues"]] == [
        ("after_line_12_changes_fingerprint", [{"start_line": 34, "end_line": 34, "symbol": None}]),
        ("string_internal_whitespace_changes_fingerprint", [{"start_line": 35, "end_line": 35, "symbol": None}]),
    ]
    assert audit_splits(splits)["split_assignment_valid"]
    assert {sample["split"] for sample in splits["samples"]} == {"dev"}
    assert splits["samples"][0]["feedback_used"] is True
    assert predictions["predictions"] == []
    score = score_review(gold, predictions)
    assert (score["bug"]["tp"], score["bug"]["fp"], score["bug"]["fn"]) == (0, 0, 2)
    assert score["bug"]["precision"] is None and score["bug"]["recall"] == 0
    assert score["formal_acceptance"]["passed"] is False
    assert manifest["reference_kind"] == "non_detector_reference"
    assert manifest["independently_adjudicated"] is manifest["identity_authenticated"] is False
    assert read(destination / "manifest.json") == manifest
    for name, digest in manifest["files_sha256"].items():
        assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == digest


def test_new_card_preserves_receipt_origin_and_does_not_promote_candidate_or_control_to_clean(tmp_path):
    destination = tmp_path / "new-dataset"
    old_card_raw = (fixture.FIXTURE / "data_card.json").read_bytes()
    dataset.build_dataset(RECEIPT, REPORT, destination)
    card, adjudication = read(destination / "source_card.json"), read(destination / "adjudication.json")
    assert card["status"] == "confirmed_dev_by_owner" and card["confirmed_issue_count"] == 2
    assert card["independently_adjudicated"] is card["identity_authenticated"] is False
    assert card["reference_predictions"]["kind"] == "non_detector_reference"
    assert "Not a clean negative" in card["stability_control"]
    assert "not labelled clean" in card["fix_candidate"]
    assert adjudication["receipt"] == read(RECEIPT)
    assert adjudication["identity_authenticated"] is False
    assert (fixture.FIXTURE / "data_card.json").read_bytes() == old_card_raw
    assert read(fixture.FIXTURE / "data_card.json")["label"] == "unknown"
    assert not card["formal_acceptance"]["passed"]


def test_unlabelled_locations_remain_unknown_instead_of_fp(tmp_path):
    destination = tmp_path / "new-dataset"
    dataset.build_dataset(RECEIPT, REPORT, destination)
    gold, predictions = read(destination / "gold.json"), read(destination / "predictions.json")
    case = gold["cases"][0]
    predictions["predictions"] = [{"id": "synthetic-unlabelled-test", "case_id": case["id"], "path": case["path"],
        "rule_id": case["rule_id"], "rule_version": case["rule_version"], "line": 30, "symbol": None}]
    score = score_review(gold, predictions)
    assert score["bug"]["unknown_predictions"] == 1 and score["bug"]["fp"] == 0


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(approved=True),
    lambda value: value.update(scope="holdout"),
    lambda value: value.update(independently_adjudicated=True),
    lambda value: value.update(reviewer="candidate-self"),
    lambda value: value.update(case_ids=[*dataset.CONFIRMED_CASES, "identical_snippet_is_stable"]),
    lambda value: value.update(user_statement=""),
    lambda value: value.update(decision="candidate_self_approved"),
    lambda value: value["evidence"].update(descriptor_sha256="a" * 64),
    lambda value: value["evidence"].update(plan_sha256="a" * 64),
    lambda value: value["evidence"].update(reproduction_report_sha256="a" * 64),
])
def test_unrelated_or_widened_owner_record_cannot_create_labels(tmp_path, mutation):
    receipt, report = sources(tmp_path)
    data = read(receipt)
    mutation(data)
    write(receipt, data)
    output = tmp_path / "not-created"
    with pytest.raises(ValueError):
        dataset.build_dataset(receipt, report, output)
    assert not output.exists()


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(comparison_verified=False),
    lambda value: value.update(production_code_and_baseline_modified=True),
    lambda value: value.update(split="holdout"),
    lambda value: value.update(plan_digest="a" * 64),
    lambda value: value["variants"]["before"]["verification"].update(snapshot_digest="a" * 64),
    lambda value: value["variants"]["before"]["verification"].update(evidence_valid=False),
    lambda value: value["variants"]["before"]["verification"]["cases"][0]["execution"].update(exit_code=2),
    lambda value: value["variants"]["before"]["verification"]["cases"][0]["execution"].update(output_sha256="a" * 64),
])
def test_even_rebound_report_must_keep_specific_reproduction_evidence(tmp_path, mutation):
    receipt, report = sources(tmp_path)
    rebind_report(receipt, report, mutation)
    with pytest.raises(ValueError):
        dataset.build_dataset(receipt, report, tmp_path / "not-created")


def test_candidate_self_approval_shape_is_not_an_operator_receipt(tmp_path):
    receipt, report = sources(tmp_path)
    write(receipt, {"candidate_id": "candidate", "approved": True, "passed": True})
    with pytest.raises(ValueError, match="owner receipt"):
        dataset.build_dataset(receipt, report, tmp_path / "not-created")


def test_builder_never_runs_or_imports_target_on_host(tmp_path, monkeypatch):
    import importlib.util
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("target execution forbidden during dataset build")

    monkeypatch.setattr(importlib.util, "spec_from_file_location", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    dataset.build_dataset(RECEIPT, REPORT, tmp_path / "new-dataset")


def test_exclusive_directory_refuses_overwrite_and_frozen_fixture_destination(tmp_path):
    destination = tmp_path / "existing"
    destination.mkdir()
    (destination / "gold.json").write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        dataset.build_dataset(RECEIPT, REPORT, destination)
    assert (destination / "gold.json").read_text(encoding="utf-8") == "keep"
    with pytest.raises(ValueError, match="original frozen fixture"):
        dataset.build_dataset(RECEIPT, REPORT, fixture.FIXTURE / "new-labels")


def test_input_drift_during_implementation_guard_has_no_manifest(tmp_path, monkeypatch):
    receipt, report = sources(tmp_path)
    original = dataset._implementation_hashes
    calls = 0

    def mutate_after_writing():
        nonlocal calls
        calls += 1
        if calls == 3:
            receipt.write_text(receipt.read_text(encoding="utf-8") + " ", encoding="utf-8")
        return original()

    monkeypatch.setattr(dataset, "_implementation_hashes", mutate_after_writing)
    destination = tmp_path / "incomplete"
    with pytest.raises(ValueError, match="changed during build"):
        dataset.build_dataset(receipt, report, destination)
    assert calls == 3
    assert not (destination / "manifest.json").exists()


def test_input_change_during_final_guard_does_not_publish_manifest(tmp_path, monkeypatch):
    receipt, report = sources(tmp_path)
    original = dataset._read_input
    receipt_reads = 0

    def changed_read(path):
        nonlocal receipt_reads
        if path == receipt:
            receipt_reads += 1
            if receipt_reads == 3:
                receipt.write_text(receipt.read_text(encoding="utf-8") + " ", encoding="utf-8")
        return original(path)

    monkeypatch.setattr(dataset, "_read_input", changed_read)
    destination = tmp_path / "incomplete"
    with pytest.raises(ValueError, match="changed during build"):
        dataset.build_dataset(receipt, report, destination)
    assert not (destination / "manifest.json").exists()


def test_cli_rejects_duplicate_json_keys_before_output_creation(tmp_path, capsys):
    receipt, report = sources(tmp_path)
    receipt.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    destination = tmp_path / "invalid"
    assert dataset.main(["--receipt", str(receipt), "--reproduction-report", str(report), "--output-dir", str(destination)]) == 2
    assert not destination.exists()
    assert json.loads(capsys.readouterr().out)["formal_acceptance"] is False
