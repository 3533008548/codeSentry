"""Measure permission-bound navigation latency through actual local output.

The clock starts before preparation and full manifest validation. Plaintext
reports remain in the analyzer's ignored .venv directory; console/JSON contain
only aggregate measurements and hashes, never target source or file lists.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import time

from codesentry.access import AccessDenied
from codesentry.index.builder import build_index
from codesentry.output.report import render_l1, render_l2
from evals.m0_acceptance import load_contract
from evals.navigation_comparison import implementation_hashes
from evals.navigation_development import _confirmed_access, validate_run_manifest

LOCAL_ARTIFACT_ROOT = Path(__file__).resolve().parents[1] / ".venv"
MAX_MANIFEST_BYTES = 32 * 1024 * 1024


class ArtifactCleanupIncomplete(RuntimeError):
    """No result is valid; some local artifacts need operator cleanup."""

    def __init__(self, original_error_type, pending_count):
        super().__init__("Measurement discarded; invalid local artifacts require cleanup")
        self.original_error_type = original_error_type
        self.cleanup_pending = True
        self.pending_artifact_count = pending_count


def _implementation():
    hashes = implementation_hashes()
    hashes["evals/navigation_latency.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return hashes


def _manifest(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest exceeds local measurement limit")
    value = json.loads(raw)
    if (type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or value.get("manifest_kind") != "navigation-development-allowed-run"
            or value.get("role") != "dev-regression" or value.get("holdout") is not False):
        raise ValueError("Latency measurements require a frozen development manifest")
    return value, hashlib.sha256(raw).hexdigest()


def _destination(path, root, *, plaintext=False):
    path = Path(path).absolute()
    if path.is_relative_to(root):
        raise ValueError("Measurement outputs must stay outside target source")
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink() or getattr(ancestor, "is_junction", lambda: False)():
            raise ValueError("Measurement outputs cannot follow links or junctions")
    resolved = path.resolve()
    if resolved != path or resolved.is_relative_to(root):
        raise ValueError("Measurement destination is redirected or noncanonical")
    if plaintext:
        private = LOCAL_ARTIFACT_ROOT.absolute()
        for ancestor in (private, *private.parents):
            if ancestor.is_symlink() or getattr(ancestor, "is_junction", lambda: False)():
                raise ValueError("Local artifact root cannot be redirected")
        if not resolved.is_relative_to(private.resolve()):
            raise ValueError("Plaintext reports must remain in the analyzer .venv")
    return resolved


def _close(access):
    close = getattr(access, "close", None)
    if callable(close):
        close()


def _check_access(access, identity):
    access.check_current()
    access.refresh_if_changed()
    if access.fingerprint != identity["policy_fingerprint"]:
        raise AccessDenied("Workspace ignore rules changed during measurement")


def _write_utf8(path, content, created):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stat = os.fstat(stream.fileno())
        created.append((path, stat.st_dev, stat.st_ino))
        stream.write(content)
        stream.flush()


def _cleanup(created, root):
    pending = 0
    for path, device, inode in reversed(created):
        try:
            # Never delete an unrelated file if an output directory or file
            # was replaced after this run created its exclusive artifacts.
            _destination(path, root)
            stat = path.lstat()
            if (stat.st_dev, stat.st_ino) == (device, inode):
                path.unlink()
            else:
                pending += 1
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            pending += 1
    return pending


def measure_navigation_latency(manifest_path: Path, workspace_data_dir: Path,
                               *, output_dir: Path, report_path: Path | None = None):
    started = time.perf_counter()
    implementation = _implementation()
    manifest_path = Path(manifest_path).resolve(strict=True)
    initial, initial_digest = _manifest(manifest_path)
    root = Path(initial["root"]).resolve(strict=True)
    if manifest_path.is_relative_to(root):
        raise ValueError("Trusted manifest must be outside target source")
    output_dir = _destination(output_dir, root, plaintext=True)
    l1_path = _destination(output_dir / "l1.txt", root, plaintext=True)
    l2_path = _destination(output_dir / "l2.txt", root, plaintext=True)
    report_path = _destination(report_path or output_dir / "measurement.json", root)
    if len({l1_path, l2_path, report_path}) != 3:
        raise ValueError("Measurement artifacts need distinct destinations")
    if any(path.exists() for path in (l1_path, l2_path, report_path)):
        raise FileExistsError("Measurement artifacts already exist")
    access = None
    created = []
    try:
        precheck = validate_run_manifest(manifest_path, workspace_data_dir)
        if not precheck.get("valid"):
            raise ValueError("Frozen inputs or permissions are not valid before measurement")
        manifest, manifest_digest = _manifest(manifest_path)
        if manifest_digest != initial_digest or manifest_digest != precheck.get("manifest_sha256"):
            raise ValueError("Manifest changed during preparation")
        access, identity = _confirmed_access(root, workspace_data_dir)
        if identity != manifest["workspace"]:
            raise AccessDenied("Workspace policy differs from the frozen manifest")
        frozen = load_contract(Path(manifest["parent_contract_path"]), manifest["project_id"],
                               root, None, access=access)
        if frozen.sha256 != manifest["parent_contract_sha256"]:
            raise ValueError("Parent contract changed during preparation")
        prepared_at = time.perf_counter()
        result = build_index(root, frozen.policy, use_cache=False, access=access)
        built_at = time.perf_counter()
        _check_access(access, identity)
        l1 = render_l1(result)
        output_dir.mkdir(parents=True, exist_ok=True)
        _destination(l1_path, root, plaintext=True)
        _write_utf8(l1_path, l1, created)
        l1_completed = time.perf_counter()
        del l1
        _check_access(access, identity)
        l2 = render_l2(result)
        _destination(l2_path, root, plaintext=True)
        _write_utf8(l2_path, l2, created)
        l2_completed = time.perf_counter()
        del l2

        # This audit does not move the already observed L1/L2 boundaries. Its
        # cost is visible separately; any drift discards both local outputs.
        postcheck = validate_run_manifest(manifest_path, workspace_data_dir)
        if not postcheck.get("valid") or postcheck.get("manifest_sha256") != manifest_digest:
            raise ValueError("Frozen inputs changed during measurement; outputs discarded")
        if _implementation() != implementation:
            raise ValueError("Analyzer implementation changed during measurement")
        _check_access(access, identity)
        outputs = {}
        for name, path in (("l1", l1_path), ("l2", l2_path)):
            _destination(path, root, plaintext=True)
            raw = path.read_bytes()
            outputs[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        audit_completed = time.perf_counter()
        l1_seconds, l2_seconds = l1_completed - started, l2_completed - started
        report = {
            "schema_version": 1, "evaluation": "permission-bound navigation end-to-end latency",
            "status": "measured", "project_id": manifest["project_id"],
            "manifest_sha256": manifest_digest,
            "input_snapshot_sha256": precheck["input_snapshot_sha256"],
            "parent_contract_sha256": frozen.sha256,
            "analysis_implementation_sha256": implementation,
            "scope_identity": {"workspace_id": identity["workspace_id"],
                               "policy_version": identity["policy_version"],
                               "policy_fingerprint": identity["policy_fingerprint"]},
            "conditions": {"cache_used": False, "full_manifest_valid_before_and_after": True,
                           "source_complete": bool(result.is_complete), "target_code_executed": False,
                           "target_dependencies_installed": False, "target_tests_collected": False,
                           "model_calls": False, "local_plaintext_report_written": True,
                           "plaintext_console_output": False,
                           "source_or_derived_content_sent_to_model": False,
                           "plaintext_local_ignored_directory_only": True,
                           "operator_managed_export": True,
                           "auto_removed_on_workspace_revoke": False,
                           "measurement_requires_successful_command_receipt": True},
            "counts": {"indexed": len(result.files),
                       "parsed": sum(meta.is_parsed for meta in result.files),
                       "parse_failures": result.parse_failures},
            "latency": {"l1_end_to_end_seconds": round(l1_seconds, 4),
                        "l2_end_to_end_seconds": round(l2_seconds, 4),
                        "preparation_seconds": round(prepared_at - started, 4),
                        "uncached_build_seconds": round(built_at - prepared_at, 4),
                        "l1_delivery_seconds": round(l1_completed - built_at, 4),
                        "post_output_validation_seconds": round(audit_completed - l2_completed, 4),
                        "validated_outputs_ready_seconds": round(audit_completed - started, 4),
                        "l1_limit_seconds": 30, "l1_below_limit": l1_seconds < 30,
                        "l2_limit_seconds": 180, "l2_below_limit": l2_seconds < 180,
                        "timing_scope": "preparation + full precheck + uncached build + rendered UTF-8 file write and flush",
                        "timing_definition_reference": "evals/m0_acceptance.py:main; cumulative L1/L2 output-flush boundaries, not post-audit validated-ready boundaries",
                        "post_audit_excluded_from_l1_l2": True,
                        "validated_ready_excludes_measurement_record_persistence_and_final_publication_check": True,
                        "json_record_persistence_excluded_from_timing": True},
            "build_stage_seconds": {key: round(value, 4) for key, value in getattr(result, "timings", {}).items()},
            "local_outputs": outputs,
            "formal_acceptance": {"passed": False, "human_entry_gold": "not_adjudicated",
                                  "reason": "Latency observations do not approve incomplete document labels or human entry gold"},
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        _destination(report_path, root)
        _write_utf8(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n", created)
        # Keep the original guard alive through record persistence. A command
        # receipt is successful only after another live identity/rule check;
        # leftover files from any failed command are never a valid measurement.
        _check_access(access, identity)
        current_access, current_identity = _confirmed_access(root, workspace_data_dir)
        try:
            if current_identity != identity:
                raise AccessDenied("Workspace identity changed during publication")
            _check_access(current_access, identity)
        finally:
            _close(current_access)
        owned, access = access, None
        _close(owned)
        return report
    except BaseException as error:
        pending = _cleanup(created, root)
        if pending:
            raise ArtifactCleanupIncomplete(type(error).__name__, pending) from None
        raise
    finally:
        _close(access)


def main(argv=None):
    command_started = time.perf_counter()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--workspace-data-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = measure_navigation_latency(args.manifest, args.workspace_data_dir,
                                            output_dir=args.output_dir, report_path=args.report)
    except Exception as error:
        print(json.dumps({"status": "not_evaluable", "error_type": type(error).__name__,
                          "original_error_type": getattr(error, "original_error_type", type(error).__name__),
                          "cleanup_pending": bool(getattr(error, "cleanup_pending", False)),
                          "pending_artifact_count": getattr(error, "pending_artifact_count", 0),
                          "artifacts_valid": False, "formal_passed": False,
                          "measured_command_seconds": round(time.perf_counter() - command_started, 4)}))
        return 1
    print(json.dumps({"status": report["status"], "project_id": report["project_id"],
                      "counts": report["counts"], "latency": report["latency"],
                      "source_complete": report["conditions"]["source_complete"],
                      "measured_command_seconds": round(time.perf_counter() - command_started, 4),
                      "artifacts_valid": True, "cleanup_pending": False,
                      "formal_passed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
