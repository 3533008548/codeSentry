"""Trusted, offline dev scoring of data-only review predictions.

This command never executes a candidate, reads target source, or establishes an
OS boundary around labels. Holdout scoring is deliberately unavailable here.
JSON input is operator-managed local data, not an automatic project importer.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path, PurePosixPath


CONTRACT = {
    "schema_version": "review-matching-v1",
    "identity": ["case_id", "rule_id", "rule_version", "path"],
    "locations": "any selector; inclusive line range AND exact symbol when specified",
    "matching": "maximum-cardinality one-to-one; identical predictions share one opportunity",
    "unmatched": "FP only in adjudicated complete scope or duplicate of a known issue; otherwise unknown",
    "categories": "bug and debt separate; clean is a rule-specific reviewed negative",
    "empty_denominators": "null",
}
DEFAULT_CONTRACT = Path(__file__).parent / "contracts" / "review_matching_v1.json"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _keys(value, keys: set[str], where: str) -> None:
    _require(isinstance(value, dict) and set(value) == keys, where + ": missing or unknown fields")


def _text(value) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _line(value) -> bool:
    return type(value) is int and value >= 1


def _path(value) -> bool:
    return (_text(value) and "\\" not in value and ":" not in value
            and not value.startswith("/") and all(p not in {"", ".", ".."} for p in value.split("/"))
            and PurePosixPath(value).as_posix() == value)


def _evidence(value) -> bool:
    return isinstance(value, list) and bool(value) and all(_text(item) for item in value)


def validate_gold(gold: dict) -> None:
    _keys(gold, {"schema_version", "dataset_id", "dataset_version", "split", "cases"}, "gold")
    _require(gold["schema_version"] == "review-gold-v1", "unsupported gold schema")
    _require(_text(gold["dataset_id"]) and _text(gold["dataset_version"]), "invalid dataset identity")
    _require(gold["split"] in {"train", "dev"}, "holdout requires a separate independent execution identity")
    _require(isinstance(gold["cases"], list) and len(gold["cases"]) <= 10000, "invalid cases")
    case_ids, ranges, rule_categories = set(), {}, {}
    for case in gold["cases"]:
        _keys(case, {"id", "project", "language", "repository_group", "defect_family", "source_snapshot",
                     "path", "rule_id", "rule_version", "category", "label", "adjudication", "evidence",
                     "scope", "issues"}, "case")
        _require(all(_text(case[key]) for key in ("id", "project", "language", "repository_group",
                 "defect_family", "rule_id", "rule_version")), "invalid case identity")
        _require(case["id"] not in case_ids, "duplicate case id")
        case_ids.add(case["id"])
        digest = case["source_snapshot"]
        _require(isinstance(digest, str) and len(digest) == 64
                 and all(char in "0123456789abcdef" for char in digest), "invalid source snapshot digest")
        _require(_path(case["path"]), "invalid relative path")
        _require(case["category"] in {"bug", "debt"} and case["label"] in {"bugs", "clean", "debt", "unknown"},
                 "invalid category or label")
        _require(case["label"] not in {"bugs", "debt"}
                 or case["category"] == {"bugs": "bug", "debt": "debt"}[case["label"]], "category conflicts with label")
        rule_key = (case["rule_id"], case["rule_version"])
        _require(rule_categories.setdefault(rule_key, case["category"]) == case["category"], "rule category changed")
        _keys(case["scope"], {"start_line", "end_line", "complete"}, "scope")
        scope = case["scope"]
        _require(_line(scope["start_line"]) and _line(scope["end_line"])
                 and scope["start_line"] <= scope["end_line"] and type(scope["complete"]) is bool, "invalid scope")
        scope_key = (case["project"], digest, case["path"], *rule_key)
        previous_ranges = ranges.setdefault(scope_key, [])
        _require(not any(scope["start_line"] <= end and start <= scope["end_line"]
                         for start, end in previous_ranges), "overlapping cases duplicate a rule scope")
        previous_ranges.append((scope["start_line"], scope["end_line"]))
        if case["label"] == "unknown":
            _require(case["adjudication"] == "pending" and not scope["complete"], "unknown cannot be adjudicated complete")
            _require(isinstance(case["evidence"], list) and all(_text(x) for x in case["evidence"]), "invalid unknown evidence")
        else:
            _require(case["adjudication"] == "confirmed" and _evidence(case["evidence"]), "known labels require adjudication evidence")
        _require(case["label"] != "clean" or scope["complete"], "clean scope must be reviewed completely")
        _require(isinstance(case["issues"], list) and len(case["issues"]) <= 500, "invalid issue list")
        _require(bool(case["issues"]) == (case["label"] in {"bugs", "debt"}), "issues conflict with label")
        issue_ids, selectors = set(), set()
        for issue in case["issues"]:
            _keys(issue, {"id", "locations", "evidence"}, "issue")
            _require(_text(issue["id"]) and issue["id"] not in issue_ids and _evidence(issue["evidence"]), "invalid or duplicate issue")
            issue_ids.add(issue["id"])
            _require(isinstance(issue["locations"], list) and bool(issue["locations"]), "missing allowed locations")
            local_selectors = set()
            for location in issue["locations"]:
                _keys(location, {"start_line", "end_line", "symbol"}, "location")
                start, end, symbol = (location[key] for key in ("start_line", "end_line", "symbol"))
                _require(symbol is None or _text(symbol), "invalid location symbol")
                if start is None or end is None:
                    _require(start is None and end is None and symbol is not None, "invalid symbol-only location")
                else:
                    _require(_line(start) and _line(end) and scope["start_line"] <= start <= end <= scope["end_line"], "location outside scope")
                selector = (start, end, symbol)
                _require(selector not in local_selectors, "duplicate selector")
                local_selectors.add(selector)
            identity = frozenset(local_selectors)
            _require(identity not in selectors, "indistinguishable issue locations")
            selectors.add(identity)


def validate_predictions(predictions: dict, gold: dict) -> None:
    _keys(predictions, {"schema_version", "dataset_id", "dataset_version", "candidate_id", "candidate_version", "predictions"}, "predictions")
    _require(predictions["schema_version"] == "review-predictions-v1", "unsupported prediction schema")
    _require(all(_text(predictions[key]) for key in ("candidate_id", "candidate_version")), "invalid candidate identity")
    _require(all(predictions[key] == gold[key] for key in ("dataset_id", "dataset_version")), "dataset identity mismatch")
    items = predictions["predictions"]
    _require(isinstance(items, list) and len(items) <= 10000, "invalid predictions")
    ids = set()
    cases = {case["id"] for case in gold["cases"]}
    for item in items:
        _keys(item, {"id", "case_id", "path", "rule_id", "rule_version", "line", "symbol"}, "prediction")
        _require(all(_text(item[key]) for key in ("id", "case_id", "rule_id", "rule_version"))
                 and item["id"] not in ids and item["case_id"] in cases, "invalid or duplicate prediction identity")
        _require(_path(item["path"]) and _line(item["line"])
                 and (item["symbol"] is None or _text(item["symbol"])), "invalid prediction location")
        ids.add(item["id"])


def _matches(prediction: dict, issue: dict) -> bool:
    return any((place["start_line"] is None or place["start_line"] <= prediction["line"] <= place["end_line"])
               and (place["symbol"] is None or place["symbol"] == prediction["symbol"])
               for place in issue["locations"])


def _maximum_matching(adjacency: dict[str, list[str]]) -> dict[str, str]:
    """Alternating-path augmentation; broad first predictions cannot steal a hit."""
    by_prediction, by_issue = {}, {}
    for initial in sorted(adjacency):
        pending, seen_predictions, parents = deque([initial]), {initial}, {}
        found = None
        while pending and found is None:
            prediction_id = pending.popleft()
            for issue_id in adjacency[prediction_id]:
                if issue_id in parents:
                    continue
                parents[issue_id] = prediction_id
                if issue_id not in by_issue:
                    found = issue_id
                    break
                owner = by_issue[issue_id]
                if owner not in seen_predictions:
                    seen_predictions.add(owner)
                    pending.append(owner)
        while found is not None:
            prediction_id = parents[found]
            previous = by_prediction.get(prediction_id)
            by_prediction[prediction_id] = found
            by_issue[found] = prediction_id
            found = previous
    return by_prediction


def _metrics(rows: list[dict]) -> dict:
    counts = {key: sum(row[key] for row in rows) for key in ("tp", "fp", "fn", "unknown_predictions", "duplicate_predictions")}
    counts.update(cases=len(rows), positive_issues=sum(row["positive_issues"] for row in rows),
                  unknown_cases=sum(row["label"] == "unknown" for row in rows))
    counts["precision"] = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else None
    counts["recall"] = counts["tp"] / counts["positive_issues"] if counts["positive_issues"] else None
    counts["all_predictions_adjudicated"] = counts["unknown_predictions"] == 0
    return counts


def score_review(gold: dict, predictions: dict, contract: dict = CONTRACT) -> dict:
    _require(contract == CONTRACT, "unsupported or modified matching contract")
    validate_gold(gold)
    validate_predictions(predictions, gold)
    rows = []
    for case in sorted(gold["cases"], key=lambda item: item["id"]):
        items = sorted((item for item in predictions["predictions"] if item["case_id"] == case["id"]), key=lambda item: item["id"])
        eligible, duplicates, seen = [], set(), set()
        for item in items:
            key = tuple(item[name] for name in ("path", "rule_id", "rule_version", "line", "symbol"))
            if key in seen:
                duplicates.add(item["id"])
            else:
                seen.add(key)
                eligible.append(item)
        def same_scope(item):
            return (all(item[key] == case[key] for key in ("path", "rule_id", "rule_version"))
                    and case["scope"]["start_line"] <= item["line"] <= case["scope"]["end_line"])
        adjacency = {item["id"]: sorted(issue["id"] for issue in case["issues"] if _matches(item, issue))
                     for item in eligible if same_scope(item)}
        matches = _maximum_matching(adjacency)
        decisions = []
        for item in items:
            known_issue = same_scope(item) and any(_matches(item, issue) for issue in case["issues"])
            if item["id"] in matches:
                outcome, reason = "tp", "one_to_one_match"
            elif known_issue:
                outcome, reason = "fp", "additional_prediction_for_known_issue"
            elif same_scope(item) and case["scope"]["complete"] and case["label"] != "unknown":
                outcome, reason = "fp", "adjudicated_negative_location"
            else:
                outcome, reason = "unknown", "outside_adjudicated_scope"
            decisions.append({"prediction_id": item["id"], "outcome": outcome, "reason": reason,
                              "issue_id": matches.get(item["id"]), "duplicate": item["id"] in duplicates})
        unmatched = sorted(issue["id"] for issue in case["issues"] if issue["id"] not in matches.values())
        rows.append({key: case[key] for key in ("id", "project", "language", "rule_id", "rule_version", "category", "label")} | {
            "tp": len(matches), "fp": sum(item["outcome"] == "fp" for item in decisions), "fn": len(unmatched),
            "unknown_predictions": sum(item["outcome"] == "unknown" for item in decisions),
            "duplicate_predictions": len(duplicates), "positive_issues": len(case["issues"]),
            "unmatched_issue_ids": unmatched, "predictions": decisions})
    strata = {}
    for dimension in ("project", "language"):
        strata[dimension] = [{"value": value, "category": category,
                              **_metrics([row for row in rows if row[dimension] == value and row["category"] == category])}
                             for value, category in sorted({(row[dimension], row["category"]) for row in rows})]
    strata["rule"] = [{"rule_id": rule_id, "rule_version": version, "category": category,
                       **_metrics([row for row in rows if (row["rule_id"], row["rule_version"], row["category"])
                                   == (rule_id, version, category)])}
                      for rule_id, version, category in sorted({
                          (row["rule_id"], row["rule_version"], row["category"]) for row in rows})]
    return {"schema_version": "review-score-v1", "status": "scored_dev_data", "dataset_id": gold["dataset_id"],
            "dataset_version": gold["dataset_version"], "split": gold["split"],
            "candidate_id": predictions["candidate_id"], "candidate_version": predictions["candidate_version"],
            "matching_contract": CONTRACT["schema_version"], "cases": rows,
            "metric_scope": {"precision": "adjudicated_predictions_only", "recall": "confirmed_issues_in_declared_cases"},
            "bug": _metrics([row for row in rows if row["category"] == "bug"]),
            "debt": _metrics([row for row in rows if row["category"] == "debt"]),
            "clean": {"cases": sum(row["label"] == "clean" for row in rows),
                      "false_positive_predictions": sum(row["fp"] for row in rows if row["label"] == "clean"),
                      "cases_with_false_positives": sum(row["label"] == "clean" and row["fp"] > 0 for row in rows)},
            "strata": strata, "stage_flow": {"status": "not_collected", "counts": None},
            "uncertainty": {"status": "not_estimated", "independent_sampling": False},
            "formal_acceptance": {"passed": False, "reason": "dev scoring only; no independent labels, execution isolation or detector acceptance established"}}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict, str]:
    with path.open("rb") as handle:
        raw = handle.read(16 * 1024 * 1024 + 1)
    _require(len(raw) <= 16 * 1024 * 1024, "input exceeds 16 MiB")
    return json.loads(raw, object_pairs_hook=_unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON"))), hashlib.sha256(raw).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        gold, gold_hash = _read_json(args.gold)
        predictions, predictions_hash = _read_json(args.predictions)
        contract, contract_hash = _read_json(args.contract)
        report = score_review(gold, predictions, contract)
        report["inputs_sha256"] = {"gold": gold_hash, "predictions": predictions_hash, "matching_contract": contract_hash,
                                   "scorer": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
        print(json.dumps({"status": report["status"], "bug": report["bug"], "debt": report["debt"],
                          "formal_acceptance": False}, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({"status": "invalid_input_or_output", "formal_acceptance": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
