"""Bind and score one trusted train/dev evaluation run from local JSON data.

No candidate or target project code is executed or imported. These are explicit,
operator-owned evaluation documents, not a project/source importer. Declared
stage IDs are checked and counted, not evidence that an actual model ran.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from evals import review_scoring, split_audit


MAX_BYTES = 16 * 1024 * 1024
STAGES = ("generated", "budget_admitted", "judged", "accepted", "verified", "final")
INPUTS = frozenset({"gold", "predictions", "matching_contract", "splits", "stages"})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _keys(value, keys: set[str], where: str) -> None:
    _require(isinstance(value, dict) and set(value) == keys, where + ": missing or unknown fields")


def _text(value) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _read(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    _require(len(raw) <= MAX_BYTES, "evaluation document exceeds 16 MiB")
    return raw


def _document(raw: bytes) -> dict:
    def reject_constant(_):
        raise ValueError("non-finite JSON")
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=reject_constant)


def _implementation_paths() -> dict[str, Path]:
    return {"review_run": Path(__file__), "review_scoring": Path(review_scoring.__file__),
            "split_audit": Path(split_audit.__file__)}


def _implementation_hashes() -> dict[str, str]:
    return {name: _sha256(_read(path)) for name, path in _implementation_paths().items()}


def validate_manifest(manifest: dict) -> None:
    _keys(manifest, {"schema_version", "run_id", "dataset_id", "dataset_version", "split", "inputs"}, "run")
    _require(manifest["schema_version"] == "review-run-v1", "unsupported run schema")
    _require(all(_text(manifest[key]) for key in ("run_id", "dataset_id", "dataset_version")), "invalid run identity")
    _require(isinstance(manifest["split"], str) and manifest["split"] in {"train", "dev"},
             "holdout is unavailable in this trusted dev tool")
    _keys(manifest["inputs"], INPUTS, "inputs")
    for descriptor in manifest["inputs"].values():
        _keys(descriptor, {"path", "sha256"}, "input")
        _require(_text(descriptor["path"]) and _digest(descriptor["sha256"]), "invalid input descriptor")


def _check_group_binding(manifest: dict, gold: dict, splits: dict) -> dict:
    # Audit the full supplied plan, including other partitions' metadata; only
    # this run's partition has labels. Undeclared samples remain undiscoverable.
    audit = split_audit.audit_splits(splits)
    _require(audit["split_assignment_valid"], "declared split assignments conflict or are incomplete")
    _require(splits["dataset_id"] == gold["dataset_id"] == manifest["dataset_id"], "split dataset mismatch")
    samples = {sample["id"]: sample for sample in splits["samples"]}
    partition = {identity for identity, sample in samples.items() if sample["split"] == manifest["split"]}
    cases = {case["id"]: case for case in gold["cases"]}
    _require(partition == cases.keys(), "gold IDs must cover exactly the current partition of the complete split plan")
    for identity, case in cases.items():
        sample = samples[identity]
        _require(sample["split"] == manifest["split"] == gold["split"], "case split mismatch")
        _require(all(sample[key] == case[key] for key in ("repository_group", "defect_family")),
                 "case repository or family mismatch")
    return audit


def score_stages(stages: dict, gold: dict, final_predictions: dict, contract: dict) -> dict:
    """Count a single semantic channel using frozen raw predictions and ID subsets."""
    review_scoring.validate_predictions(final_predictions, gold)
    _keys(stages, {"schema_version", "dataset_id", "dataset_version", "candidate_id", "candidate_version",
                   "channel", "raw_predictions", "stages"}, "stage telemetry")
    _require(stages["schema_version"] == "review-stages-v1", "unsupported stages schema")
    _require(stages["channel"] == "semantic", "this pipeline supports semantic telemetry only; channels cannot be pooled")
    _require(all(stages[key] == final_predictions[key] for key in (
        "dataset_id", "dataset_version", "candidate_id", "candidate_version")), "stage task/candidate mismatch")
    raw_document = {key: final_predictions[key] for key in (
        "schema_version", "dataset_id", "dataset_version", "candidate_id", "candidate_version")}
    raw_document["predictions"] = stages["raw_predictions"]
    review_scoring.validate_predictions(raw_document, gold)
    _keys(stages["stages"], set(STAGES), "stage IDs")
    raw = {item["id"]: item for item in raw_document["predictions"]}
    previous, rows = set(raw), []
    for name in STAGES:
        values = stages["stages"][name]
        _require(isinstance(values, list) and all(_text(value) for value in values), "invalid stage IDs")
        ids = set(values)
        _require(len(ids) == len(values) and ids <= previous, "stage IDs duplicate, appear late or re-enter")
        if name == "generated":
            _require(ids == set(raw), "generated IDs must cover every raw candidate")
        subset = dict(raw_document, predictions=[raw[identity] for identity in sorted(ids)])
        score = review_scoring.score_review(gold, subset, contract)
        metrics = {}
        for category in ("bug", "debt"):
            metric = score[category]
            metrics[category] = {"matched_issues": metric["tp"], "applicable_issues": metric["positive_issues"],
                                 "recall": metric["recall"], "unknown_predictions": metric["unknown_predictions"]}
        rows.append({"stage": name, "prediction_ids": sorted(ids), "prediction_count": len(ids),
                     "lost_prediction_ids": sorted(previous - ids), "lost_prediction_count": len(previous - ids),
                     "strata": score["strata"],
                     **metrics})
        previous = ids
    final = {item["id"]: item for item in final_predictions["predictions"]}
    _require(set(final) == previous and all(final[identity] == raw[identity] for identity in final),
             "final predictions must exactly equal the retained raw candidates")
    return {"status": "computed_from_declared_ids", "channel": "semantic", "execution_verified": False,
            "counting": "maximum one-to-one matching of unique applicable gold issues at each stage",
            "other_channels": {"deterministic": "not_included", "explore": "not_included"}, "stages": rows}


def evaluate_run(manifest_path: Path) -> dict:
    """Evaluate captured JSON snapshots and recheck their hashes before returning."""
    implementation = _implementation_hashes()
    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest_raw = _read(manifest_path)
    manifest = _document(manifest_raw)
    validate_manifest(manifest)
    documents, input_paths, input_hashes = {}, {}, {}
    for name in sorted(INPUTS):
        descriptor = manifest["inputs"][name]
        path = (manifest_path.parent / descriptor["path"]).resolve(strict=True)
        raw = _read(path)
        _require(_sha256(raw) == descriptor["sha256"], "input digest differs from frozen run")
        documents[name], input_paths[name], input_hashes[name] = _document(raw), path, _sha256(raw)
    gold, predictions, contract = (documents[name] for name in ("gold", "predictions", "matching_contract"))
    review_scoring.validate_gold(gold)
    _require(all(gold[key] == manifest[key] for key in ("dataset_id", "dataset_version", "split")), "gold run identity mismatch")
    final_score = review_scoring.score_review(gold, predictions, contract)
    audit = _check_group_binding(manifest, gold, documents["splits"])
    stage_flow = score_stages(documents["stages"], gold, predictions, contract)
    _require(_sha256(_read(manifest_path)) == _sha256(manifest_raw), "run manifest changed during evaluation")
    _require(all(_sha256(_read(input_paths[name])) == digest for name, digest in input_hashes.items()),
             "evaluation input changed during evaluation")
    _require(_implementation_hashes() == implementation, "evaluation implementation changed during evaluation")
    return {"schema_version": "review-run-report-v1", "status": "scored_trusted_dev_data",
            "run_id": manifest["run_id"], "dataset_id": manifest["dataset_id"],
            "dataset_version": manifest["dataset_version"], "split": manifest["split"],
            "inputs_sha256": {"run_manifest": _sha256(manifest_raw), **input_hashes},
            "implementation_sha256": implementation, "inputs_revalidated": True,
            "split_audit": audit, "final_score": final_score, "stage_flow": stage_flow,
            "source_snapshot_revalidated": False,
            "label_truth_verified": False, "isolation_verified": False, "candidate_executed": False,
            "formal_acceptance": {"passed": False, "reason": "trusted dev metadata only; no independent labels, sealed execution or detector acceptance"}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = evaluate_run(args.manifest)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
        print(json.dumps({"status": report["status"], "run_id": report["run_id"],
                          "cases": len(report["final_score"]["cases"]),
                          "split_plan_samples": report["split_audit"]["sample_count"],
                          "bug": report["final_score"]["bug"], "debt": report["final_score"]["debt"],
                          "formal_acceptance": False}, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({"status": "invalid_run_or_output", "formal_acceptance": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
