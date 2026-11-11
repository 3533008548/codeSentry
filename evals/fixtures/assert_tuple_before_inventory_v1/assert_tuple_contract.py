"""Trusted developer syntax-contract check, without executing candidate source.

Register fixed expected positions/facts and implementation hashes first, then
run predictions against that exact registration. This is not behavioral bug
gold, human-identity authentication, holdout isolation or quality acceptance.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile

from codesentry.access import AccessPolicy
from codesentry.review.defects import RULE_ID, RULE_VERSION, scan_defect_preview
from codesentry.review.scan import PreviewLimits


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "evals/contracts/assert_tuple_v1"
CONTRACT_ID = "python-assert-tuple-synthetic-v1"
FIELDS = ("file", "line", "end_line", "symbol", "occurrence", "tuple_arity")
IMPLEMENTATIONS = (
    "codesentry/review/defects.py", "codesentry/review/verification.py", "codesentry/review/scan.py",
    "codesentry/core/finding.py", "codesentry/core/fingerprint.py", "codesentry/access/policy.py",
    "evals/assert_tuple_contract.py",
)
FACTS = {"classification": "behavior_bug_candidate", "no_starred": True,
    "always_truthy_after_successful_construction": True, "assertions_enabled_requirement": True,
    "unreachable_or_side_effects_not_assessed": True, "intent_not_confirmed": True,
    "confirmed_behavior_bug": False}


def _json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("contract material exceeds the developer-tool input bound")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    return value, hashlib.sha256(raw).hexdigest()


def _name(value):
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value or "\0" in value
            or PurePosixPath(value).is_absolute() or any(p in {"", ".", ".."} for p in value.split("/"))):
        raise ValueError("invalid synthetic source name")
    return value


def _inputs():
    spec, spec_hash = _json(ASSETS / "spec.json")
    dataset, case_hash = _json(ASSETS / "cases.json")
    card, card_hash = _json(ASSETS / "rule_card.json")
    if (spec["contract_id"] != CONTRACT_ID or dataset["contract_id"] != CONTRACT_ID
            or spec["split"] != "dev" or card["rule_id"] != RULE_ID or card["rule_version"] != RULE_VERSION
            or card["approved_for_blocking"] is not False or spec["confirmed_behavior_bug"] is not False):
        raise ValueError("unsupported syntax contract or rule approval claim")
    cases = dataset["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 100:
        raise ValueError("bounded synthetic cases required")
    ids, denominator = set(), 0
    for case in cases:
        if set(case) - {"id", "files", "exclude", "limits", "expected"} or not {"id", "files", "expected"} <= set(case):
            raise ValueError("unsupported synthetic case fields")
        if not isinstance(case["id"], str) or not case["id"] or case["id"] in ids:
            raise ValueError("unique case ids required")
        ids.add(case["id"])
        if not isinstance(case["files"], dict) or len(case["files"]) > 10:
            raise ValueError("bounded source mapping required")
        for name, text in case["files"].items():
            _name(name)
            if not isinstance(text, str) or len(text.encode()) > 64 * 1024:
                raise ValueError("bounded synthetic text required")
        PreviewLimits(**case.get("limits", {}))
        expected = case["expected"]
        if set(expected) != {"review_status", "findings", "issue_statuses"}:
            raise ValueError("expected contract fields differ")
        for row in expected["findings"]:
            if (set(row) != set(FIELDS) or row["file"] not in case["files"]
                    or any(type(row[key]) is not int or row[key] < 1
                           for key in ("line", "end_line", "occurrence", "tuple_arity"))
                    or row["end_line"] < row["line"] or type(row["symbol"]) is not str):
                raise ValueError("invalid expected syntax location/facts")
        denominator += len(expected["findings"])
    implementation_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                             for name in IMPLEMENTATIONS}
    if card["implementation_sha256"] != implementation_hashes["codesentry/review/defects.py"]:
        raise ValueError("frozen rule card does not match implementation")
    binding = {"schema_version": 1, "contract_id": CONTRACT_ID, "split": "dev",
        "material_sha256": {"spec.json": spec_hash, "cases.json": case_hash, "rule_card.json": card_hash},
        "implementation_sha256": implementation_hashes, "case_ids": [case["id"] for case in cases],
        "expected_syntax_candidates": denominator, "bug_gold": False,
        "independently_adjudicated": False, "target_execution": False}
    return binding, cases


def _write_new(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def register_contract(output: str | Path) -> dict:
    binding, _ = _inputs()
    _write_new(output, binding)
    return binding


def run_contract(registration: str | Path, output: str | Path) -> dict:
    if Path(output).exists():
        raise FileExistsError("contract report already exists")
    recorded, registration_sha = _json(registration)
    binding, cases = _inputs()
    if recorded != binding:
        raise ValueError("registered contract, expected denominator or implementation changed")
    results = []
    totals = Counter()
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="codesentry-assert-contract-") as temporary:
            project = Path(temporary)
            for name, text in case["files"].items():
                path = project / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(text.encode())
            result = scan_defect_preview(AccessPolicy(project, {"exclude": case.get("exclude", [])}),
                                         limits=PreviewLimits(**case.get("limits", {})))
        expected = Counter(tuple(row[key] for key in FIELDS) for row in case["expected"]["findings"])
        observed, invalid = Counter(), 0
        for row in result["findings"]:
            finding = row["finding"]
            facts = finding["facts"]
            if (any(facts.get(key) != value for key, value in FACTS.items())
                    or finding["rule_id"] != RULE_ID or finding["rule_version"] != RULE_VERSION
                    or finding["source"] != "deterministic" or finding["verified"] is not True
                    or row["classification"] != "behavior_bug_candidate" or row["can_block"] is not False
                    or row["confirmed_behavior_bug"] is not False):
                invalid += 1
                continue
            selected = {**finding, "tuple_arity": facts["tuple_arity"]}
            observed[tuple(selected[key] for key in FIELDS)] += 1
        hits = sum((expected & observed).values())
        missing = sum(expected.values()) - hits
        extra = sum(observed.values()) - hits + invalid
        status_match = result["review_status"] == case["expected"]["review_status"]
        issues_match = sorted({row["status"] for row in result["issues"]}) == sorted(case["expected"]["issue_statuses"])
        consistent = (not missing and not extra and status_match and issues_match
                      and result["gate_status"] == "not_evaluated" and not result["formal_acceptance"]["passed"])
        totals.update(contract_hits=hits, contract_missing=missing, contract_extra=extra,
                      consistent_cases=int(consistent))
        results.append({"case_id": case["id"], "contract_hits": hits, "contract_missing": missing,
            "contract_extra": extra, "status_matches": status_match, "issues_match": issues_match,
            "contract_consistent": consistent, "prediction": result})
    final_binding, _ = _inputs()
    if final_binding != binding or _json(registration)[1] != registration_sha:
        raise ValueError("registered implementation or contract drifted during prediction")
    report = {"schema_version": 1, "mode": "synthetic_syntax_contract", "split": "dev",
        "contract_id": CONTRACT_ID, "binding": binding, "registration_sha256": registration_sha,
        "summary": {**dict(totals), "case_count": len(cases),
                    "expected_syntax_candidates": binding["expected_syntax_candidates"]},
        "cases": results, "target_execution": False, "bug_gold": False,
        "formal_acceptance": {"passed": False,
            "reason": "developer-authored synthetic syntax contract; no bug precision, independent adjudication or gate acceptance"}}
    _write_new(output, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    register = subparsers.add_parser("register")
    register.add_argument("--output", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--registration", required=True)
    run.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = register_contract(args.output) if args.action == "register" else run_contract(args.registration, args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"contract tool refused: {error}\n")
    print(json.dumps(result.get("summary", {"registered": result["contract_id"]}), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
