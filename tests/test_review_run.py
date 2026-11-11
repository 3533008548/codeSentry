"""Frozen JSON-only dev run and stage-loss counterexamples."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from evals import review_run
from evals.review_run import STAGES, evaluate_run, main, score_stages
from evals.review_scoring import CONTRACT, score_review


FIXTURES = Path(__file__).parents[1] / "evals" / "fixtures"
RUN_FIXTURE = FIXTURES / "review_run_v1.json"


def document(path):
    return json.loads(path.read_text(encoding="utf-8"))


def bundle(tmp_path, fixture=RUN_FIXTURE):
    manifest = document(fixture)
    for name, descriptor in manifest["inputs"].items():
        raw = (FIXTURES / descriptor["path"]).read_bytes()
        target = tmp_path / (name + ".json")
        target.write_bytes(raw)
        descriptor["path"] = target.name
    path = tmp_path / "run.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def change_input(path, name, mutation, *, update_hash=True):
    manifest = document(path)
    source = path.parent / manifest["inputs"][name]["path"]
    data = document(source)
    mutation(data)
    source.write_text(json.dumps(data), encoding="utf-8")
    if update_hash:
        manifest["inputs"][name]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest), encoding="utf-8")


def stage_inputs():
    return (document(FIXTURES / "review_stages_v1.json"),
            document(FIXTURES / "review_gold_v1.json"),
            document(FIXTURES / "review_predictions_v1.json"))


def test_new_synthetic_binding_and_stage_fixtures_are_frozen():
    expected = {
        "review_run_splits_v1.json": "94178ad84b40a54ca5d059b6f7be39582c68cfd1556170d06f2ace1bf7a00ece",
        "review_stages_v1.json": "743e6db651132db6e4dfed220e69959345bfccfd44947aff560e55128adb1f5e",
        "review_run_v1.json": "64f0b2c53c79c2cf3ca71e23ff61a6fadaf703c413a975e8e578dcda8d3af13c",
        "review_run_splits_v2.json": "43b7fa5ab6147d199328b57294683d3989770e2bd91b987a8e6d1162042cde64",
        "review_run_v2.json": "e52357824a3d24d0b605553ee142e07010367455eab4b287549fd80dad1b315c",
    }
    assert {name: hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() for name in expected} == expected


def test_global_plan_audits_other_partitions_without_loading_their_gold():
    report = evaluate_run(FIXTURES / "review_run_v2.json")
    assert report["split_audit"]["sample_count"] == 7
    assert report["split_audit"]["split_counts"] == {"train": 1, "dev": 5, "holdout": 1}
    assert report["split_audit"]["split_assignment_valid"]
    assert len(report["final_score"]["cases"]) == 5
    assert report["final_score"] == evaluate_run(RUN_FIXTURE)["final_score"]
    assert not report["isolation_verified"] and not report["label_truth_verified"]


@pytest.mark.parametrize("relation", ["repository_group", "defect_family", "derived_from"])
def test_current_dev_cannot_leak_into_extra_holdout_metadata(tmp_path, relation):
    path = bundle(tmp_path, FIXTURES / "review_run_v2.json")

    def leak(data):
        dev = next(sample for sample in data["samples"] if sample["split"] == "dev")
        holdout = next(sample for sample in data["samples"] if sample["split"] == "holdout")
        holdout[relation] = [dev["id"]] if relation == "derived_from" else dev[relation]

    change_input(path, "splits", leak)
    with pytest.raises(ValueError, match="split assignments conflict"):
        evaluate_run(path)


def test_gold_cannot_omit_any_sample_in_current_partition(tmp_path):
    path = bundle(tmp_path, FIXTURES / "review_run_v2.json")

    def add_unscored_dev(data):
        row = deepcopy(data["samples"][-1])
        row.update(id="unscored-dev", split="dev", repository_group="new-independent-dev", defect_family="new-dev-family")
        data["samples"].append(row)

    change_input(path, "splits", add_unscored_dev)
    with pytest.raises(ValueError, match="current partition"):
        evaluate_run(path)


def test_bound_run_reproduces_final_score_and_all_declared_losses():
    report = evaluate_run(RUN_FIXTURE)
    assert report["final_score"] == score_review(*stage_inputs()[1:])
    assert report["split_audit"]["sample_count"] == 5
    assert report["split_audit"]["split_assignment_valid"]
    assert report["inputs_revalidated"]
    assert report["stage_flow"]["channel"] == "semantic"
    assert not report["stage_flow"]["execution_verified"]
    stages = report["stage_flow"]["stages"]
    assert [row["stage"] for row in stages] == list(STAGES)
    assert [row["prediction_count"] for row in stages] == [12, 11, 10, 9, 8, 7]
    assert [row["lost_prediction_count"] for row in stages] == [0, 1, 1, 1, 1, 1]
    assert [row["bug"]["matched_issues"] for row in stages] == [3, 3, 3, 3, 3, 2]
    assert [row["bug"]["recall"] for row in stages] == [1, 1, 1, 1, 1, 2 / 3]
    assert all(row["debt"]["matched_issues"] == 1 for row in stages)
    assert report["stage_flow"]["other_channels"] == {"deterministic": "not_included", "explore": "not_included"}
    assert not report["label_truth_verified"] and not report["isolation_verified"]
    assert not report["source_snapshot_revalidated"]
    assert not report["candidate_executed"] and not report["formal_acceptance"]["passed"]
    assert set(report["implementation_sha256"]) == {"review_run", "review_scoring", "split_audit"}
    assert set(report["inputs_sha256"]) == {"run_manifest", *review_run.INPUTS}
    assert report["inputs_sha256"]["run_manifest"] == hashlib.sha256(RUN_FIXTURE.read_bytes()).hexdigest()


def test_each_stage_stratification_recomputes_unique_bug_and_debt_counts():
    for stage in evaluate_run(RUN_FIXTURE)["stage_flow"]["stages"]:
        for dimension in ("project", "language", "rule"):
            for category in ("bug", "debt"):
                rows = [row for row in stage["strata"][dimension] if row["category"] == category]
                assert sum(row["tp"] for row in rows) == stage[category]["matched_issues"]
                assert sum(row["positive_issues"] for row in rows) == stage[category]["applicable_issues"]


def test_raw_and_final_prediction_order_do_not_change_stage_flow():
    stages, gold, predictions = stage_inputs()
    expected = score_stages(stages, gold, predictions, CONTRACT)
    stages["raw_predictions"].reverse()
    predictions["predictions"].reverse()
    for values in stages["stages"].values():
        values.reverse()
    assert score_stages(stages, gold, predictions, CONTRACT) == expected


@pytest.mark.parametrize("name", sorted(review_run.INPUTS))
def test_any_input_change_without_new_binding_is_rejected(tmp_path, name):
    path = bundle(tmp_path)
    change_input(path, name, lambda data: data.update(hidden_change=True), update_hash=False)
    with pytest.raises(ValueError, match="digest"):
        evaluate_run(path)


@pytest.mark.parametrize("mutation", [
    lambda data: data.update(split="holdout"),
    lambda data: data.update(split=[]),
    lambda data: data.update(precision=1),
    lambda data: data.update(dataset_version="2"),
    lambda data: data["inputs"]["gold"].update(sha256="bad"),
    lambda data: data["inputs"].pop("stages"),
])
def test_invalid_or_different_run_identity_cannot_score(tmp_path, mutation):
    path = bundle(tmp_path)
    data = document(path)
    mutation(data)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        evaluate_run(path)


@pytest.mark.parametrize("mutation", [
    lambda data: data.update(dataset_id="other"),
    lambda data: data["samples"].pop(),
    lambda data: data["samples"][0].update(id="different"),
    lambda data: data["samples"][0].update(repository_group="changed-group"),
    lambda data: data["samples"][0].update(defect_family="changed-family"),
    lambda data: data["samples"][0].update(split="train"),
    lambda data: data["samples"][0].update(split="holdout"),
    lambda data: data["samples"][0].update(derived_from=["absent"]),
])
def test_rebinding_mismatched_split_metadata_does_not_change_gold_scope(tmp_path, mutation):
    path = bundle(tmp_path)
    change_input(path, "splits", mutation)
    with pytest.raises(ValueError):
        evaluate_run(path)


def test_stage_ids_cannot_skip_generation_reenter_or_duplicate():
    for stage_name, identity in [("generated", "missing-id"), ("judged", "i-budget-drop"), ("final", "a-flexible")]:
        stages, gold, predictions = stage_inputs()
        stages["stages"][stage_name].append(identity)
        with pytest.raises(ValueError):
            score_stages(stages, gold, predictions, CONTRACT)


def test_raw_candidates_cannot_be_omitted_from_generated_stage():
    stages, gold, predictions = stage_inputs()
    stages["stages"]["generated"].remove("i-budget-drop")
    with pytest.raises(ValueError, match="every raw"):
        score_stages(stages, gold, predictions, CONTRACT)


@pytest.mark.parametrize("channel", ["deterministic", "explore", ["semantic", "deterministic"]])
def test_other_channels_cannot_be_pooled_to_inflate_semantic_recall(channel):
    stages, gold, predictions = stage_inputs()
    stages["channel"] = channel
    with pytest.raises(ValueError, match="channels cannot be pooled"):
        score_stages(stages, gold, predictions, CONTRACT)


@pytest.mark.parametrize("mutation", [
    lambda stages: stages.update(precision=1),
    lambda stages: stages.update(candidate_version="other"),
    lambda stages: stages["stages"].update(recall=1),
    lambda stages: stages["raw_predictions"][0].update(line=11),
    lambda stages: stages["stages"]["final"].pop(),
])
def test_stage_self_scores_or_mutated_final_content_are_rejected(mutation):
    stages, gold, predictions = stage_inputs()
    mutation(stages)
    with pytest.raises(ValueError):
        score_stages(stages, gold, predictions, CONTRACT)


def test_duplicate_raw_predictions_cannot_multiply_stage_gold_hits():
    stages, gold, predictions = stage_inputs()
    duplicate = deepcopy(stages["raw_predictions"][0])
    duplicate["id"] = "new-duplicate"
    stages["raw_predictions"].append(duplicate)
    stages["stages"]["generated"].append(duplicate["id"])
    flow = score_stages(stages, gold, predictions, CONTRACT)
    assert flow["stages"][0]["bug"]["matched_issues"] == 3
    assert flow["stages"][1]["lost_prediction_count"] == 2


def test_empty_applicable_denominator_is_na_at_every_stage():
    stages, gold, predictions = stage_inputs()
    gold["cases"] = [case for case in gold["cases"] if case["label"] == "clean"]
    predictions["predictions"] = []
    stages["raw_predictions"] = []
    stages["stages"] = {name: [] for name in STAGES}
    flow = score_stages(stages, gold, predictions, CONTRACT)
    assert all(row["bug"]["recall"] is row["debt"]["recall"] is None for row in flow["stages"])


@pytest.mark.parametrize("changed", ["manifest", "gold", "implementation"])
def test_post_computation_drift_is_rejected(tmp_path, monkeypatch, changed):
    path = bundle(tmp_path)
    original = review_run.score_stages

    def mutate_after_score(*args, **kwargs):
        result = original(*args, **kwargs)
        if changed == "manifest":
            path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        elif changed == "gold":
            source = path.parent / document(path)["inputs"]["gold"]["path"]
            source.write_text(source.read_text(encoding="utf-8") + " ", encoding="utf-8")
        else:
            monkeypatch.setattr(review_run, "_implementation_hashes", lambda: {"changed": "digest"})
        return result

    monkeypatch.setattr(review_run, "score_stages", mutate_after_score)
    with pytest.raises(ValueError, match="changed during"):
        evaluate_run(path)


def test_cli_uses_bound_input_paths_and_exclusive_output(tmp_path, capsys):
    path = bundle(tmp_path)
    output = tmp_path / "result.json"
    assert main([str(path), "--output", str(output)]) == 0
    report = document(output)
    assert report == evaluate_run(path)
    before = output.read_bytes()
    assert main([str(path), "--output", str(output)]) == 2
    assert output.read_bytes() == before
    messages = capsys.readouterr().out
    assert "formal_acceptance" in messages
    assert "prediction_ids" not in messages


def test_cli_rejects_duplicate_json_key_and_does_not_publish(tmp_path, capsys):
    path, output = tmp_path / "run.json", tmp_path / "result.json"
    path.write_text('{"schema_version":"review-run-v1","schema_version":"review-run-v1"}', encoding="utf-8")
    assert main([str(path), "--output", str(output)]) == 2
    assert not output.exists()
    assert json.loads(capsys.readouterr().out)["status"] == "invalid_run_or_output"


def test_reader_does_not_load_an_unbounded_document(monkeypatch):
    class BoundedFile:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, count):
            assert count == review_run.MAX_BYTES + 1
            return b" " * count

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: BoundedFile())
    with pytest.raises(ValueError, match="16 MiB"):
        review_run._read(Path("synthetic.json"))
