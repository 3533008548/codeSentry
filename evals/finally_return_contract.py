"""Freeze and evaluate the developer-authored finally-return syntax contract."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform

from evals import finally_return_candidate as candidate


ROOT = Path(__file__).resolve().parents[1]
PROPOSAL = "rules/proposals/python.finally_return.v1.json"
DATASET = "evals/datasets/p6_finally_return_dev_v1.json"
IMPLEMENTATION = "evals/finally_return_candidate.py"
SCORER = "evals/finally_return_contract.py"


def _inputs():
    materials = {name: (ROOT / name).read_bytes() for name in (PROPOSAL, DATASET, IMPLEMENTATION, SCORER)}
    proposal, dataset = (json.loads(materials[name]) for name in (PROPOSAL, DATASET))
    if (proposal["rule_id"] != candidate.RULE_ID or proposal["version"] != candidate.RULE_VERSION
            or proposal["status"] != "proposal" or proposal["mode"] != "report_only"
            or proposal["production_admission"] is not False
            or proposal["implementation"] != IMPLEMENTATION or proposal["development_contract"] != DATASET):
        raise ValueError("invalid proposal status or candidate identity")
    if dataset["partition"] != "dev" or dataset["label_kind"] != "synthetic_syntax_contract":
        raise ValueError("only the registered synthetic development contract is supported")
    cases = dataset["cases"]
    ids = [case["id"] for case in cases]
    if not 1 <= len(ids) <= 100 or len(ids) != len(set(ids)):
        raise ValueError("unique and bounded case ids are required")
    binding = {
        "schema_version": 1, "rule_id": candidate.RULE_ID, "rule_version": candidate.RULE_VERSION,
        "dataset_id": dataset["dataset_id"], "partition": "dev", "case_ids": ids,
        "sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in materials.items()},
        "runtime": {"implementation": platform.python_implementation(), "version": platform.python_version()},
        "matching": "exact multiset of (return_start_line, return_end_line, owner_try_line), and exact case status",
    }
    return binding, cases


def _write_new(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def register(output):
    binding, _ = _inputs()
    _write_new(output, binding)
    return binding


def evaluate(registration, output):
    recorded = Path(registration).read_bytes()
    binding, cases = _inputs()
    if json.loads(recorded) != binding:
        raise ValueError("registration differs from current proposal, implementation, labels or runtime")

    results = []
    totals = Counter(matched=0, missed=0, unexpected=0, status_mismatches=0)
    for case in cases:
        observed = candidate.detect(case["source"])
        expected_hits = Counter(tuple(hit) for hit in case["expected_hits"])
        actual_hits = Counter(tuple(hit) for hit in observed["hits"])
        matched = sum((expected_hits & actual_hits).values())
        totals.update(matched=matched, missed=sum(expected_hits.values()) - matched,
                      unexpected=sum(actual_hits.values()) - matched,
                      status_mismatches=int(observed["status"] != case["expected_status"]))
        results.append({"case_id": case["id"], "expected_status": case["expected_status"],
                        "expected_hits": case["expected_hits"], "observed": observed})

    if _inputs()[0] != binding or Path(registration).read_bytes() != recorded:
        raise ValueError("evaluation inputs changed during the run")
    report = {
        "schema_version": 1, "mode": "report_only", "binding": binding,
        "registration_sha256": hashlib.sha256(recorded).hexdigest(),
        "summary": {"cases": len(cases), **dict(totals)},
        "contract_consistent": not any(totals[key] for key in ("missed", "unexpected", "status_mismatches")),
        "formal_acceptance": False, "independent_labels": False, "target_execution": False,
        "cases": results,
    }
    _write_new(output, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("register").add_argument("--output", type=Path, required=True)
    run = actions.add_parser("run")
    run.add_argument("--registration", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "register":
            print(register(args.output)["dataset_id"])
            return 0
        result = evaluate(args.registration, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        parser.exit(2, f"development contract refused: {error}\n")
    print(json.dumps(result["summary"], sort_keys=True))
    return 0 if result["contract_consistent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
