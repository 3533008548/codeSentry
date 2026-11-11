"""Build one owner-confirmed dev dataset from explicit local evidence inputs.

The receipt is an operator-selected record, not authenticated human identity.
This module neither executes target code nor promotes candidate self-reports to
approval. Original reproduction fixtures and historical reports remain intact.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat

from codesentry.access.policy import is_link
from evals import fingerprint_reproduction as fixture
from evals import fingerprint_verification as reproduction
from evals import review_scoring


DATASET_ID = "codesentry-fingerprint-dev-v1"
CASE_ID = "codesentry-legacy-fingerprint-before"
CONFIRMED_CASES = ("after_line_12_changes_fingerprint", "string_internal_whitespace_changes_fingerprint")
MAX_BYTES = 4 * 1024 * 1024


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _keys(value, expected: set[str], where: str) -> None:
    _require(isinstance(value, dict) and set(value) == expected, where + ": missing or unknown fields")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(document: dict) -> bytes:
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _safe_metadata(path: Path):
    for component in reversed((path, *path.parents)):
        _require(not is_link(component), "evaluation input path is redirected")
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "evaluation input must be a regular file without aliases")
    return metadata


def _read_input(path: Path) -> bytes:
    metadata = _safe_metadata(path)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink", "st_mode")
        _require(all(getattr(opened, key) == getattr(metadata, key) for key in fields), "evaluation input changed at open")
        raw = stream.read(MAX_BYTES + 1)
    current = _safe_metadata(path)
    _require(len(raw) <= MAX_BYTES and all(getattr(current, key) == getattr(metadata, key)
             for key in (*fields, "st_ctime_ns")), "evaluation input changed or exceeds limit")
    return raw


def _parse(raw: bytes) -> dict:
    def reject(_):
        raise ValueError("non-finite JSON")
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=reject)


def _implementation_hashes() -> dict[str, str]:
    return {module.__name__: _hash(_read_input(Path(module.__file__)))
            for module in (fixture, reproduction, review_scoring)} | {
                "evals.fingerprint_dataset": _hash(_read_input(Path(__file__)))}


def _locations(raw: bytes) -> tuple[int, int, int, int]:
    """Locate both known normalization operations using syntax only."""
    tree = ast.parse(raw.decode("utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "normalize_snippet")
    truncations, collapses = [], []
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if isinstance(call.func, ast.Attribute) and call.func.attr == "join" and any(
                isinstance(child, ast.Subscript) and isinstance(child.slice, ast.Slice)
                and isinstance(child.slice.upper, ast.Name) and child.slice.upper.id == "max_lines"
                for child in ast.walk(call)):
            truncations.append(node.lineno)
        if (isinstance(call.func, ast.Attribute) and call.func.attr == "sub"
                and isinstance(call.func.value, ast.Name) and call.func.value.id == "_WS_RE"):
            collapses.append(node.lineno)
    _require(len(truncations) == len(collapses) == 1 and truncations != collapses, "known issue locations are ambiguous")
    return function.lineno, function.end_lineno, truncations[0], collapses[0]


def _snapshot_digest(descriptor: dict, variant: str) -> str:
    root = fixture.FIXTURE / descriptor["source_roots"][variant]
    rows = []
    for entry in descriptor["variant_files"][variant]:
        raw = fixture._read_checked(root / entry["path"])
        _require(_hash(raw) == entry["sha256"], "source fixture changed")
        rows.append({"path": entry["path"], "sha256": entry["sha256"], "size": len(raw)})
    return _hash(_canonical(sorted(rows, key=lambda row: row["path"])))


def _check_evidence(receipt: dict, report: dict, report_hash: str, descriptor: dict) -> None:
    _keys(receipt, {"schema_version", "kind", "decision", "case_ids", "reviewer", "independently_adjudicated",
                    "scope", "evidence", "user_statement"}, "owner receipt")
    _require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
             and receipt["kind"] == "fingerprint-owner-adjudication"
             and receipt["decision"] == "confirm_two_dev_defects", "receipt is not this owner decision")
    _require(receipt["case_ids"] == list(CONFIRMED_CASES) and receipt["reviewer"] == "conversation_user/project_owner"
             and receipt["independently_adjudicated"] is False and receipt["scope"] == "dev_only",
             "owner receipt cannot widen the adjudication scope")
    _require(isinstance(receipt["user_statement"], str) and bool(receipt["user_statement"].strip()), "missing user statement")
    expected = {"reproduction_report_sha256": report_hash,
                "descriptor_sha256": fixture.FROZEN_SHA256["descriptor.json"],
                "plan_sha256": fixture.FROZEN_SHA256["plan.json"]}
    _require(receipt["evidence"] == expected, "owner receipt evidence differs from selected inputs")
    _require(type(report.get("schema_version")) is int and report["schema_version"] == 1
             and report.get("kind") == "codesentry-legacy-fingerprint-contract-reproduction"
             and report.get("status") == "reproduced" and report.get("comparison_verified") is True
             and report.get("split") == "dev" and report.get("production_code_and_baseline_modified") is False,
             "selected report is not a valid dev reproduction")
    _require(report.get("fixture_descriptor_sha256") == fixture.FROZEN_SHA256["descriptor.json"]
             and report.get("fixture_files_sha256") == fixture.FROZEN_SHA256
             and report.get("source_provenance") == descriptor["source_provenance"], "reproduction source binding mismatch")
    _require(reproduction._comparison_valid(report["variants"]), "actual before/after observations are incomplete or invalid")
    plan = fixture.load_plan()
    _require(report["plan_digest"] == _hash(_canonical(plan)), "reproduction plan mismatch")
    for variant in ("before", "fix_candidate"):
        verification = report["variants"][variant]["verification"]
        _require(verification["snapshot_digest"] == _snapshot_digest(descriptor, variant)
                 and verification["plan_digest"] == report["plan_digest"], "reproduction snapshot/plan mismatch")


def build_dataset(receipt_path: Path, reproduction_report_path: Path, output_dir: Path) -> dict:
    """Build a new bundle; receipt selection is an explicit trusted-operator act."""
    implementation = _implementation_hashes()
    receipt_path, reproduction_report_path, output_dir = [Path(os.path.abspath(path))
        for path in (receipt_path, reproduction_report_path, output_dir)]
    _require(not output_dir.is_relative_to(Path(os.path.abspath(fixture.FIXTURE))), "cannot write into the original frozen fixture")
    receipt_raw, report_raw = _read_input(receipt_path), _read_input(reproduction_report_path)
    receipt, report = _parse(receipt_raw), _parse(report_raw)
    descriptor = fixture.load_fixture()
    _check_evidence(receipt, report, _hash(report_raw), descriptor)
    before_raw = fixture._read_checked(fixture.FIXTURE / "before" / "fingerprint.py")
    _require(_hash(before_raw) == fixture.FROZEN_SHA256["before/fingerprint.py"], "before source changed")
    start, end, truncation, whitespace = _locations(before_raw)
    binding = {"receipt": _hash(receipt_raw), "reproduction_report": _hash(report_raw),
               "fixture_descriptor": fixture.FROZEN_SHA256["descriptor.json"], "plan_file": fixture.FROZEN_SHA256["plan.json"]}
    case = {"id": CASE_ID, "project": "CodeSentry", "language": "python", "repository_group": "codesentry",
            "defect_family": "codesentry-legacy-fingerprint-normalization", "source_snapshot": report["variants"]["before"]["verification"]["snapshot_digest"],
            "path": "fingerprint.py", "rule_id": "fingerprint.complete_source_preservation", "rule_version": "owner-dev-v1",
            "category": "bug", "label": "bugs", "adjudication": "confirmed",
            "evidence": ["Owner-confirmed development defects; not independent holdout adjudication.",
                         "Receipt SHA256: " + binding["receipt"], "Reproduction report SHA256: " + binding["reproduction_report"]],
            "scope": {"start_line": start, "end_line": end, "complete": False}, "issues": []}
    for identity, line in zip(CONFIRMED_CASES, (truncation, whitespace)):
        case["issues"].append({"id": identity, "locations": [{"start_line": line, "end_line": line, "symbol": None}],
                               "evidence": ["Owner decision applies to this unique issue only.",
                                            "Frozen AST location in normalize_snippet; before observation false, candidate observation true.",
                                            "Trusted behavior case: " + identity, "Technical decision section 3.3.2."]})
    gold = {"schema_version": "review-gold-v1", "dataset_id": DATASET_ID, "dataset_version": "1", "split": "dev", "cases": [case]}
    predictions = {"schema_version": "review-predictions-v1", "dataset_id": DATASET_ID, "dataset_version": "1",
                   "candidate_id": "empty-non-detector-reference", "candidate_version": "1", "predictions": []}
    splits = {"schema_version": 1, "dataset_id": DATASET_ID, "samples": [{"id": CASE_ID, "split": "dev",
              "repository_group": case["repository_group"], "defect_family": case["defect_family"], "derived_from": [], "feedback_used": True}]}
    review_scoring.validate_gold(gold)
    review_scoring.validate_predictions(predictions, gold)
    adjudication = {"schema_version": 1, "status": "confirmed_dev_by_owner", "receipt": receipt,
                    "receipt_sha256": binding["receipt"], "identity_authenticated": False,
                    "independently_adjudicated": False, "interpretation": "Explicit operator-selected record; JSON fields do not authenticate a human reviewer."}
    source_card = {"schema_version": 1, "dataset_id": DATASET_ID, "status": "confirmed_dev_by_owner", "split": "dev",
                   "label": "bugs", "confirmed_issue_count": 2, "source_snapshot": case["source_snapshot"],
                   "source_provenance": descriptor["source_provenance"], "inputs_sha256": binding,
                   "original_unknown_data_card_sha256": fixture.FROZEN_SHA256["data_card.json"],
                   "independently_adjudicated": False, "identity_authenticated": False,
                   "reference_predictions": {"kind": "non_detector_reference", "candidate_id": predictions["candidate_id"],
                       "meaning": "No detector executed; empty predictions demonstrate FN accounting, not detector quality."},
                   "stability_control": "Not a clean negative label; it only checks repeated identical inputs.",
                   "fix_candidate": "Behavioral candidate only; not labelled clean and not merged into production.",
                   "scope": "Only the two adjudicated before issues are positive; all other locations remain unknown.",
                   "formal_acceptance": {"passed": False}}
    documents = {"gold.json": gold, "predictions.json": predictions, "splits.json": splits,
                 "adjudication.json": adjudication, "source_card.json": source_card}
    files = {name: (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8") for name, data in documents.items()}
    manifest = {"schema_version": 1, "kind": "fingerprint-owner-confirmed-dev-dataset", "dataset_id": DATASET_ID,
                "dataset_version": "1", "split": "dev", "inputs_sha256": binding, "implementation_sha256": implementation,
                "files_sha256": {name: _hash(raw) for name, raw in files.items()}, "reference_kind": "non_detector_reference",
                "independently_adjudicated": False, "identity_authenticated": False, "formal_acceptance": {"passed": False}}

    def check_inputs():
        fixture.load_fixture()
        _require(_implementation_hashes() == implementation, "dataset implementation changed during build")
        _require(_hash(_read_input(receipt_path)) == binding["receipt"]
                 and _hash(_read_input(reproduction_report_path)) == binding["reproduction_report"], "selected evidence changed during build")

    check_inputs()
    for ancestor in reversed(output_dir.parents):
        _require(not is_link(ancestor), "output ancestor is redirected")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(exist_ok=False)
    for name, raw in files.items():
        with (output_dir / name).open("xb") as stream:
            stream.write(raw)
    _require(all(_hash(_read_input(output_dir / name)) == digest for name, digest in manifest["files_sha256"].items()),
             "generated dataset file changed before publication")
    check_inputs()
    with (output_dir / "manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--reproduction-report", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest = build_dataset(args.receipt, args.reproduction_report, args.output_dir)
        print(json.dumps({"dataset_id": manifest["dataset_id"], "status": "confirmed_dev_by_owner", "issues": 2,
                          "reference_kind": manifest["reference_kind"], "formal_acceptance": False}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, StopIteration, RecursionError):
        print(json.dumps({"status": "invalid_input_or_output", "published": False, "formal_acceptance": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
