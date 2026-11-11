"""Review scoring checks use fixed synthetic data, never target source."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from evals.review_scoring import CONTRACT, main, score_review, validate_gold


FIXTURES = Path(__file__).parents[1] / "evals" / "fixtures"


def inputs():
    return tuple(json.loads((FIXTURES / name).read_text(encoding="utf-8"))
                 for name in ("review_gold_v1.json", "review_predictions_v1.json"))


def test_synthetic_inputs_and_matching_contract_are_frozen():
    expected = {
        FIXTURES / "review_gold_v1.json": "b43a60c55de0d96eeffffec80b1757cf2272becddc867f940a3a8ae5774c3295",
        FIXTURES / "review_predictions_v1.json": "1faf5078955b703133ca1bb12820f15db08b0dd78528d4a25b32223bf490f50b",
        FIXTURES.parent / "contracts" / "review_matching_v1.json": "2f018bb213d7fb985b75800f3af77f3318b2be50818e6a209e45bbbe406f3e15",
    }
    assert {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in expected} == expected


def test_fixture_maximum_matching_duplicates_unknown_and_categories():
    gold, predictions = inputs()
    report = score_review(gold, predictions)
    assert report["bug"] == {
        "tp": 2, "fp": 2, "fn": 1, "unknown_predictions": 2, "duplicate_predictions": 1,
        "cases": 4, "positive_issues": 3, "unknown_cases": 1,
        "precision": .5, "recall": 2 / 3, "all_predictions_adjudicated": False,
    }
    assert (report["debt"]["tp"], report["debt"]["fp"], report["debt"]["fn"]) == (1, 0, 0)
    assert report["clean"] == {"cases": 1, "false_positive_predictions": 1, "cases_with_false_positives": 1}
    matching = next(case for case in report["cases"] if case["id"] == "matching")
    assert [(item["prediction_id"], item["issue_id"]) for item in matching["predictions"][:2]] == [
        ("a-flexible", "narrow"), ("b-only-wide", "wide")]
    assert report["stage_flow"] == {"status": "not_collected", "counts": None}
    assert report["formal_acceptance"]["passed"] is False
    assert report["uncertainty"]["independent_sampling"] is False


def test_stratified_counts_recompute_aggregate_without_debt_mixing():
    report = score_review(*inputs())
    for dimension in ("project", "language", "rule"):
        for category in ("bug", "debt"):
            rows = [row for row in report["strata"][dimension] if row["category"] == category]
            for key in ("tp", "fp", "fn", "positive_issues", "unknown_predictions", "duplicate_predictions"):
                assert sum(row[key] for row in rows) == report[category][key]


def test_rule_version_strata_do_not_conflate_delimiter_collisions():
    gold, predictions = inputs()
    predictions["predictions"] = []
    gold["cases"][0].update(rule_id="rule@part", rule_version="1")
    gold["cases"][1].update(rule_id="rule", rule_version="part@1")
    strata = score_review(gold, predictions)["strata"]["rule"]
    assert any(row["rule_id"] == "rule@part" and row["rule_version"] == "1" for row in strata)
    assert any(row["rule_id"] == "rule" and row["rule_version"] == "part@1" for row in strata)


def test_prediction_and_gold_order_do_not_change_matching():
    gold, predictions = inputs()
    expected = score_review(gold, predictions)
    gold["cases"].reverse()
    for case in gold["cases"]:
        case["issues"].reverse()
    predictions["predictions"].reverse()
    assert score_review(gold, predictions) == expected


def test_one_prediction_cannot_match_two_issues():
    gold, predictions = inputs()
    predictions["predictions"] = predictions["predictions"][:1]
    report = score_review(gold, predictions)
    assert (report["bug"]["tp"], report["bug"]["fn"]) == (1, 2)


def test_identical_predictions_do_not_cover_distinct_overlapping_issues():
    gold, predictions = inputs()
    predictions["predictions"] = [predictions["predictions"][0], predictions["predictions"][2]]
    report = score_review(gold, predictions)
    assert (report["bug"]["tp"], report["bug"]["fp"], report["bug"]["fn"]) == (1, 1, 2)


def test_missing_predictions_keep_fn_and_precision_na():
    gold, predictions = inputs()
    predictions["predictions"] = []
    report = score_review(gold, predictions)
    assert report["bug"]["precision"] is None
    assert report["bug"]["recall"] == 0
    assert report["bug"]["fn"] == 3


def test_no_positive_gold_keeps_recall_na_even_when_clean_has_fp():
    gold, predictions = inputs()
    gold["cases"] = [case for case in gold["cases"] if case["label"] == "clean"]
    predictions["predictions"] = [item for item in predictions["predictions"] if item["case_id"] == "clean"]
    report = score_review(gold, predictions)
    assert report["bug"]["precision"] == 0
    assert report["bug"]["recall"] is None
    assert report["debt"]["precision"] is None
    assert report["debt"]["recall"] is None


def test_empty_dataset_does_not_claim_perfect_score():
    gold, predictions = inputs()
    gold["cases"], predictions["predictions"] = [], []
    report = score_review(gold, predictions)
    assert report["bug"]["precision"] is report["bug"]["recall"] is None
    assert report["formal_acceptance"]["passed"] is False


@pytest.mark.parametrize("change", [
    {"rule_id": "other.rule"}, {"rule_version": "2"}, {"path": "other.py"}, {"line": 101},
])
def test_wrong_identity_or_outside_reviewed_scope_is_unknown(change):
    gold, predictions = inputs()
    item = next(item for item in predictions["predictions"] if item["case_id"] == "clean")
    item.update(change)
    report = score_review(gold, predictions)
    assert report["clean"]["false_positive_predictions"] == 0
    assert report["bug"]["unknown_predictions"] == 3


def test_unmatched_complete_positive_scope_is_fp_but_partial_is_unknown():
    gold, predictions = inputs()
    item = predictions["predictions"][0]
    predictions["predictions"] = [item]
    item["line"] = 99
    report = score_review(gold, predictions)
    assert report["bug"]["fp"] == 1
    next(case for case in gold["cases"] if case["id"] == "matching")["scope"]["complete"] = False
    report = score_review(gold, predictions)
    assert report["bug"]["fp"] == 0
    assert report["bug"]["unknown_predictions"] == 1


def test_line_and_symbol_are_conjunctive_with_explicit_alternatives():
    gold, predictions = inputs()
    gold["cases"] = gold["cases"][:1]
    case = gold["cases"][0]
    case["issues"] = [{"id": "symbol-issue", "evidence": ["Synthetic"], "locations": [
        {"start_line": 10, "end_line": 12, "symbol": "Module.method"},
        {"start_line": None, "end_line": None, "symbol": "Alternative.method"},
    ]}]
    predictions["predictions"] = predictions["predictions"][:1]
    item = predictions["predictions"][0]
    assert score_review(gold, predictions)["bug"]["tp"] == 0
    item["symbol"] = "Module.method"
    assert score_review(gold, predictions)["bug"]["tp"] == 1
    item["line"] = 50
    assert score_review(gold, predictions)["bug"]["tp"] == 0
    item["symbol"] = "Alternative.method"
    assert score_review(gold, predictions)["bug"]["tp"] == 1


@pytest.mark.parametrize("mutation", [
    lambda gold: gold.update(split="holdout"),
    lambda gold: gold.update(passed=True),
    lambda gold: gold["cases"][0]["scope"].update(start_line=True),
    lambda gold: gold["cases"][0]["scope"].update(complete=1),
    lambda gold: gold["cases"][0].update(path="../private.py"),
    lambda gold: gold["cases"][0].update(evidence=[]),
    lambda gold: gold["cases"][0].update(adjudication="pending"),
    lambda gold: gold["cases"][0].update(source_snapshot="mutable-branch"),
    lambda gold: gold["cases"][0].update(category="debt"),
    lambda gold: gold["cases"][1]["scope"].update(complete=False),
    lambda gold: gold["cases"][-1]["scope"].update(complete=True),
    lambda gold: gold["cases"][0]["issues"][0]["locations"][0].update(end_line=101),
    lambda gold: gold["cases"][0]["issues"][0]["locations"][0].update(start_line=None),
])
def test_invalid_gold_fails_closed(mutation):
    gold, _ = inputs()
    mutation(gold)
    with pytest.raises(ValueError):
        validate_gold(gold)


def test_overlapping_duplicate_case_scope_is_rejected():
    gold, _ = inputs()
    extra = deepcopy(gold["cases"][0])
    extra["id"] = "duplicate-scope"
    gold["cases"].append(extra)
    with pytest.raises(ValueError, match="overlapping"):
        validate_gold(gold)


def test_issues_with_identical_allowed_locations_are_rejected():
    gold, _ = inputs()
    issues = gold["cases"][0]["issues"]
    issues[1]["locations"] = deepcopy(issues[0]["locations"])
    with pytest.raises(ValueError, match="indistinguishable"):
        validate_gold(gold)


@pytest.mark.parametrize("mutation", [
    lambda predictions: predictions.update(passed=True),
    lambda predictions: predictions.update(precision=1),
    lambda predictions: predictions.update(dataset_version="different"),
    lambda predictions: predictions["predictions"][0].update(case_id="unregistered"),
    lambda predictions: predictions["predictions"][0].update(line=True),
    lambda predictions: predictions["predictions"][0].update(path="C:/secret"),
    lambda predictions: predictions["predictions"][0].update(tp=True),
    lambda predictions: predictions["predictions"].append(deepcopy(predictions["predictions"][0])),
])
def test_candidate_cannot_self_score_or_change_task_identity(mutation):
    gold, predictions = inputs()
    mutation(predictions)
    with pytest.raises(ValueError):
        score_review(gold, predictions)


def test_changed_matching_contract_is_not_accepted():
    gold, predictions = inputs()
    contract = dict(CONTRACT, matching="greedy")
    with pytest.raises(ValueError):
        score_review(gold, predictions, contract)


def test_cli_writes_recomputable_report_and_refuses_overwrite(tmp_path, capsys):
    output = tmp_path / "score.json"
    gold_path, prediction_path = [FIXTURES / name for name in ("review_gold_v1.json", "review_predictions_v1.json")]
    args = ["--gold", str(gold_path), "--predictions", str(prediction_path), "--output", str(output)]
    assert main(args) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["inputs_sha256"]["gold"] == hashlib.sha256(gold_path.read_bytes()).hexdigest()
    assert report["inputs_sha256"]["predictions"] == hashlib.sha256(prediction_path.read_bytes()).hexdigest()
    assert len(report["inputs_sha256"]["scorer"]) == 64
    before = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == before
    output.unlink()
    # Inputs include only JSON; target source access and candidate execution are absent.
    text = capsys.readouterr().out
    assert "formal_acceptance" in text
    assert "Synthetic manually" not in text


def test_cli_rejects_duplicate_json_keys_without_writing_output(tmp_path, capsys):
    gold_path = tmp_path / "gold.json"
    gold_path.write_text('{"schema_version":"review-gold-v1","schema_version":"review-gold-v1"}', encoding="utf-8")
    output = tmp_path / "score.json"
    assert main(["--gold", str(gold_path), "--predictions", str(FIXTURES / "review_predictions_v1.json"), "--output", str(output)]) == 2
    assert not output.exists()
    assert json.loads(capsys.readouterr().out)["status"] == "invalid_input_or_output"


def test_json_reader_enforces_bound_before_loading_entire_input(monkeypatch):
    from evals.review_scoring import _read_json
    limit = 16 * 1024 * 1024

    class LimitedFile:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, count):
            assert count == limit + 1
            return b" " * count

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: LimitedFile())
    with pytest.raises(ValueError, match="16 MiB"):
        _read_json(Path("synthetic.json"))
