"""验收指标：不同分母、无证据边界和漏目录反例。"""
import pytest

from evals.metrics import (
    application_entry_predictions,
    directory_coverage,
    entrypoint_metrics,
    precision,
    ranking_metrics,
    resolution_summary,
)


def test_p10_and_recall_have_different_denominators():
    truth = [f"key{i}.py" for i in range(40)]
    recommendations = truth[:8] + ["unknown.py", "other.py"]
    score = ranking_metrics(recommendations, truth, 10)
    assert score.precision == 0.8
    assert score.recall == 0.2
    assert score.unlabelled == ("unknown.py", "other.py")


def test_short_output_reports_actual_denominator():
    score = ranking_metrics(["a.py", "unknown.py"], ["a.py", "b.py"], 10)
    assert (score.hits, score.recommended) == (1, 2)
    assert score.precision == score.recall == 0.5


def test_no_output_or_no_truth_cannot_fabricate_precision():
    no_output = ranking_metrics([], ["a.py"], 10)
    assert no_output.precision is None
    assert no_output.recall == 0.0
    no_truth = ranking_metrics(["a.py"], [], 10)
    assert no_truth.precision is None
    assert no_truth.recall is None
    assert precision(0, 0) is None
    assert precision(8, 2) == 0.8
    assert precision(0, 3) == 0.0


def test_duplicate_recommendations_do_not_multiply_hits():
    score = ranking_metrics(["a.py", "a.py"], ["a.py", "a.py"], 10)
    assert (score.hits, score.recommended, score.truth_count) == (1, 2, 1)
    assert score.precision == 0.5


def test_unrecommended_directory_stays_in_denominator():
    coverage = directory_coverage(["api/a.py", "core/b.py"], ["api/a.py"])
    assert len(coverage) == 2
    assert sum(item.complete for item in coverage) == 1
    assert coverage[1].directory == "core/"
    assert coverage[1].covered == 0


def test_resolution_excludes_external_but_counts_ambiguity_and_guesses():
    score = resolution_summary({
        "local": 6, "cross_file": 2, "unresolved": 1, "ambiguous": 1,
        "heuristic": 2, "builtin": 50, "external": 30, "test_helper": 3,
    })
    assert (score.resolved, score.denominator, score.heuristic) == (8, 12, 2)
    assert score.rate == pytest.approx(2 / 3)
    assert resolution_summary({"builtin": 1}).rate is None


def test_invalid_metric_arguments_rejected():
    with pytest.raises(ValueError):
        ranking_metrics([], [], 0)
    with pytest.raises(ValueError):
        precision(-1, 0)


def test_entry_metrics_require_independent_labels():
    score = entrypoint_metrics(["main.py"], ["main.py"])
    assert score.predicted == 1
    assert score.precision is None and score.recall is None and score.truth_count is None


def test_entry_metrics_use_unique_file_hits_and_keep_empty_denominators_na():
    score = entrypoint_metrics(["a.py", "a.py", "wrong.py"], ["a.py", "b.py"], independently_annotated=True)
    assert (score.hits, score.predicted, score.truth_count) == (1, 2, 2)
    assert score.precision == score.recall == 0.5
    empty_predictions = entrypoint_metrics([], ["main.py"], independently_annotated=True)
    assert empty_predictions.precision is None and empty_predictions.recall == 0.0
    empty_truth = entrypoint_metrics(["main.py"], [], independently_annotated=True)
    assert empty_truth.precision == 0.0 and empty_truth.recall is None


def test_application_prediction_union_excludes_hints_and_deduplicates_roles():
    from types import SimpleNamespace
    def entry(file, kind, confidence="static", level="app"):
        return SimpleNamespace(file=file, kind=kind, confidence=confidence, level=level)
    predictions = application_entry_predictions([
        entry("shared.py", "process"), entry("shared.py", "mount", "declared"),
        entry("ui.tsx", "mount"), entry("factory.py", "assembly"),
        entry("preload.ts", "bridge", "declared"), entry("app.py", "candidate"),
        entry("guessed.py", "process", "heuristic"),
        entry("script.py", "process", "declared", "script"),
        entry("unknown.py", "process", "unknown"),
    ])
    assert predictions == ("shared.py", "ui.tsx")
    metrics = entrypoint_metrics(predictions, ["shared.py", "ui.tsx"])
    assert metrics.precision is metrics.recall is None
