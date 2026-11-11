"""Run one fixed CodeSentry legacy-contract reproduction in isolated copies.

This development entry cannot select a project, command, plan or expected result.
The local production fingerprint, approved baselines and gates are never changed.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tempfile
import time

from codesentry.access import AccessPolicy
from codesentry.execution.admission import BuiltinTaskPolicy, admit_execution
from codesentry.execution.commands import default_endpoint, default_executable
from codesentry.execution.runner import DockerRunner, ResourceLimits
from codesentry.execution.snapshot import prepare_snapshot
from codesentry.execution.verification import load_trusted_plan, verify_plan
from evals.fingerprint_reproduction import FIXTURE, FROZEN_SHA256, load_fixture


IMAGE_REFERENCE = "docker.io/library/python@sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c"
IMAGE_ID = "sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c"
LIMITS = ResourceLimits(256*1024*1024, 1, 32, 10, 4096, 8*1024*1024)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _implementation_hashes():
    from codesentry.execution import admission, runner, snapshot, verification
    from evals import fingerprint_reproduction
    return {module.__name__: _hash(Path(module.__file__).read_bytes())
            for module in (admission, runner, snapshot, verification, fingerprint_reproduction)} | {
        "evals.fingerprint_verification": _hash(Path(__file__).read_bytes())}


def _snapshot_digest(descriptor, variant):
    root = FIXTURE / descriptor["source_roots"][variant]
    rows = []
    for entry in descriptor["variant_files"][variant]:
        raw = (root / entry["path"]).read_bytes()
        if _hash(raw) != entry["sha256"]:
            raise ValueError("Fixed input changed during task admission")
        rows.append({"path": entry["path"], "sha256": entry["sha256"], "size": len(raw)})
    return _hash(json.dumps(sorted(rows, key=lambda row: row["path"]), ensure_ascii=False,
                           sort_keys=True, separators=(",", ":")).encode())


def _comparison_valid(variants):
    if set(variants) != {"before", "fix_candidate"}:
        return False
    before, after = (variants[name]["verification"] for name in ("before", "fix_candidate"))
    if before["status"] != "failed" or after["status"] != "passed":
        return False
    if any(before[key] != after[key] for key in ("plan_digest", "image_reference", "image_id", "limits")):
        return False
    for result in (before, after):
        if (not result["evidence_valid"] or result["cleanup_pending"] or result["planned_cases"] != 3
                or result["executed_cases"] != 3 or result["completed_cases"] != 3
                or result["host_behavior_checks_evaluated"] != 6
                or any(case["execution"] is None or case["execution"]["exit_code"] != 0
                    or case["execution"]["status"] != "not_verified" for case in result["cases"])):
            return False
    # A mismatched success digest alone could be a warning or formatting error.
    # Require the exact preregistered legacy observations, not just any failure.
    legacy_values = {"after_line_12_changes_fingerprint": False,
        "string_internal_whitespace_changes_fingerprint": False, "identical_snippet_is_stable": True}
    if {case["case_id"] for case in before["cases"]} != set(legacy_values):
        return False
    for case in before["cases"]:
        expected_raw = (json.dumps({"case_id": case["case_id"], "actual": legacy_values[case["case_id"]]},
            sort_keys=True, separators=(",", ":")) + "\n").encode()
        if case["execution"]["output_sha256"] != _hash(expected_raw):
            return False
    return ([case["status"] for case in before["cases"]] == ["failed", "failed", "passed"]
        and all(case["status"] == "passed" for case in after["cases"])
        and {case["execution"]["architecture"] for result in (before, after) for case in result["cases"]} == {"amd64"})


def reproduce(*, executable: Path, endpoint: str,
              image_reference=IMAGE_REFERENCE, image_id=IMAGE_ID) -> dict:
    if image_reference != IMAGE_REFERENCE or image_id != IMAGE_ID:
        raise ValueError("This fixed reproduction only admits its preregistered runtime image")
    started = time.perf_counter()
    implementation = _implementation_hashes()
    descriptor = load_fixture()
    initial_plan = load_trusted_plan(FIXTURE / descriptor["plan"]["path"],
        source_root=FIXTURE / descriptor["source_roots"]["before"])
    digests = tuple(_snapshot_digest(descriptor, name) for name in ("before", "fix_candidate"))
    policy = BuiltinTaskPolicy("codesentry-fingerprint-dev-v1", initial_plan.digest,
        digests, IMAGE_REFERENCE, IMAGE_ID, LIMITS)
    variants = {}
    with tempfile.TemporaryDirectory(prefix="codesentry-fingerprint-reproduction-") as temporary:
        base = Path(temporary)
        for variant in ("before", "fix_candidate"):
            load_fixture()
            root = FIXTURE / descriptor["source_roots"][variant]
            plan = load_trusted_plan(FIXTURE / descriptor["plan"]["path"], source_root=root)
            prepare_start = time.perf_counter()
            with prepare_snapshot(AccessPolicy(root), base / variant,
                    paths=[entry["path"] for entry in descriptor["variant_files"][variant]],
                    max_files=2, max_bytes=32768, max_file_bytes=16384) as source:
                preparation_seconds = time.perf_counter() - prepare_start
                runner = DockerRunner(executable, image_ref=IMAGE_REFERENCE, expected_image_id=IMAGE_ID,
                                      limits=LIMITS, endpoint=endpoint)
                admission = admit_execution(policy, runner, source, plan)
                verify_start = time.perf_counter()
                result = verify_plan(runner, source, plan, admission_check=admission.check)
                variants[variant] = {"admission": admission.to_dict(), "verification": result.to_dict(),
                    "preparation_seconds": round(preparation_seconds, 4),
                    "verification_seconds": round(time.perf_counter() - verify_start, 4)}
            load_fixture()
    if _implementation_hashes() != implementation:
        raise ValueError("Trusted verification implementation changed during reproduction")
    reproduced = _comparison_valid(variants)
    return {"schema_version": 1, "kind": "codesentry-legacy-fingerprint-contract-reproduction",
        "status": "reproduced" if reproduced else "not_reproduced",
        "reproduction_id": descriptor["reproduction_id"], "split": "dev",
        "fixture_descriptor_sha256": FROZEN_SHA256["descriptor.json"],
        "fixture_files_sha256": FROZEN_SHA256, "source_provenance": descriptor["source_provenance"],
        "fixed_policy_digest": policy.digest, "plan_digest": initial_plan.digest,
        "image_reference": IMAGE_REFERENCE, "image_id": IMAGE_ID, "limits": asdict(LIMITS),
        "variants": variants, "comparison_verified": reproduced,
        "total_seconds": round(time.perf_counter() - started, 4),
        "implementation_sha256": implementation,
        "production_code_and_baseline_modified": False, "source_fixture_hashes_revalidated": True,
        "target_user_projects_executed": False, "arbitrary_project_execution_enabled": False,
        "independent_human_adjudication": "pending", "dataset_label": "unknown",
        "formal_acceptance": {"passed": False,
            "reason": "one dev contract reproduction; no detector-quality or full P3 fingerprint migration acceptance"}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-executable", type=Path, default=default_executable())
    parser.add_argument("--endpoint", default=default_endpoint())
    parser.add_argument("--image-ref", default=IMAGE_REFERENCE)
    parser.add_argument("--image-id", default=IMAGE_ID)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            report = reproduce(executable=args.docker_executable, endpoint=args.endpoint,
                               image_reference=args.image_ref, image_id=args.image_id)
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print(json.dumps({"status": report["status"], "comparison_verified": report["comparison_verified"],
            "before": report["variants"]["before"]["verification"]["status"],
            "fix_candidate": report["variants"]["fix_candidate"]["verification"]["status"],
            "production_modified": False, "formal_acceptance": False}))
        return 0 if report["comparison_verified"] else 1
    except (OSError, ValueError, TypeError):
        print(json.dumps({"status": "unavailable", "comparison_verified": False,
                          "formal_acceptance": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
