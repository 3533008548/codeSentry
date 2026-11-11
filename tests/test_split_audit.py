"""Counterexamples for evaluation grouping, using synthetic metadata only."""
from copy import deepcopy
import json

import pytest

from evals.split_audit import audit_splits, main


def sample(identity, split="dev", repository=None, family=None, origins=(), feedback=False):
    return {"id": identity, "split": split, "repository_group": repository or identity,
            "defect_family": family or identity, "derived_from": list(origins),
            "feedback_used": feedback}


def manifest(*rows):
    return {"schema_version": 1, "dataset_id": "synthetic-grouping-v1", "samples": list(rows)}


def kinds(report):
    return {issue["kind"] for issue in report["issues"]}


def test_independent_groups_are_valid_but_do_not_establish_isolation_or_labels():
    report = audit_splits(manifest(sample("a", "train"), sample("b"), sample("c", "holdout")))
    assert report["split_assignment_valid"]
    assert report["split_counts"] == {"train": 1, "dev": 1, "holdout": 1}
    assert report["isolation_verified"] is report["label_truth_verified"] is False
    assert report["formal_acceptance"]["passed"] is False


@pytest.mark.parametrize("shared", ["repository_group", "defect_family"])
def test_shared_group_cannot_cross_splits(shared):
    left, right = sample("a"), sample("b", "holdout")
    left[shared] = right[shared] = "shared"
    assert "cross_split_group" in kinds(audit_splits(manifest(left, right)))


def test_transitive_derivation_and_family_are_one_group():
    report = audit_splits(manifest(
        sample("a", feedback=True), sample("b", origins=["a"], family="copied"),
        sample("c", "holdout", family="copied")))
    assert report["group_count"] == 1
    assert kinds(report) == {"cross_split_group", "feedback_exposed_holdout"}
    assert next(issue for issue in report["issues"]
                if issue["kind"] == "cross_split_group")["sample_ids"] == ["a", "b", "c"]


@pytest.mark.parametrize("project", ["research_agent", "knowledge_loop"])
def test_known_development_projects_cannot_be_assigned_holdout(project):
    report = audit_splits(manifest(sample("a", "holdout", repository=project)))
    assert "development_project_in_holdout" in kinds(report)
    assert not report["split_assignment_valid"]


def test_used_holdout_feedback_is_rejected_until_demoted():
    row = sample("a", "holdout", feedback=True)
    assert "feedback_exposed_holdout" in kinds(audit_splits(manifest(row)))
    row["split"] = "dev"
    assert audit_splits(manifest(row))["split_assignment_valid"]


def test_missing_family_and_derivation_keep_audit_incomplete():
    row = sample("a", origins=["absent"])
    row["defect_family"] = None
    report = audit_splits(manifest(row))
    assert kinds(report) == {"unknown_defect_family", "missing_derivation"}
    assert not report["split_assignment_valid"]


def test_empty_is_not_ready():
    assert kinds(audit_splits(manifest())) == {"empty_dataset"}


def test_same_split_cycle_is_grouped_without_recursion():
    report = audit_splits(manifest(sample("a", origins=["b"]), sample("b", origins=["a"])))
    assert report["split_assignment_valid"] and report["group_count"] == 1


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(schema_version=True),
    lambda value: value.update(accepted=True),
    lambda value: value["samples"].append(deepcopy(value["samples"][0])),
    lambda value: value["samples"][0].update(feedback_used=1),
    lambda value: value["samples"][0].update(split="test"),
    lambda value: value["samples"][0].update(split=[]),
    lambda value: value["samples"][0].update(derived_from=["a"]),
    lambda value: value["samples"][0].update(derived_from=["b", "b"]),
    lambda value: value["samples"][0].update(repository_group=""),
    lambda value: value["samples"][0].update(repository_group="research_agent "),
])
def test_malformed_metadata_is_rejected(mutation):
    value = manifest(sample("a"))
    mutation(value)
    with pytest.raises(ValueError):
        audit_splits(value)


def test_cli_writes_recomputable_new_report_and_refuses_overwrite(tmp_path, capsys):
    source, output = tmp_path / "input.json", tmp_path / "report.json"
    value = manifest(sample("a"))
    source.write_text(json.dumps(value), encoding="utf-8")
    assert main([str(source), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == audit_splits(value)
    before = output.read_bytes()
    assert main([str(source), "--output", str(output)]) == 2
    assert output.read_bytes() == before
    assert "sample_ids" not in capsys.readouterr().out


def test_cli_rejects_duplicate_keys_and_returns_failure_for_leak(tmp_path):
    source, output = tmp_path / "input.json", tmp_path / "report.json"
    source.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    assert main([str(source), "--output", str(output)]) == 2
    assert not output.exists()
    source.write_text(json.dumps(manifest(sample("a", "holdout", feedback=True))), encoding="utf-8")
    assert main([str(source), "--output", str(output)]) == 1
    assert not json.loads(output.read_text(encoding="utf-8"))["split_assignment_valid"]
