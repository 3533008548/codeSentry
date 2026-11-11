"""Freeze permission-bound development inputs before navigation ablations.

This records local hashes and metadata, never source text, executes no target
code, and does not create human gold or a new formal navigation contract.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.cli.access import resolve_access
from codesentry.environment import inspect_environment
from codesentry.environment.toolchain import Toolchain
from codesentry.index.discovery import classify, discover
from codesentry.index.startup import collect_startup_inputs
from evals.m0_acceptance import DOCUMENT_NAMES, FrozenInputs, contract_input_drift, load_contract

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT = REPOSITORY_ROOT / "evals/contracts/navigation_v1.json"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 10000
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}")


def _json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _digest(value) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _workspace_identity(root: Path, data_dir: Path) -> dict:
    """Read only trusted registry metadata; never create or migrate a store."""
    database = data_dir.resolve() / "workspaces.sqlite3"
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        row = connection.execute(
            "SELECT id,access_policy FROM workspaces WHERE canonical_key=?",
            (os.path.normcase(str(root.resolve())),),
        ).fetchone()
    if row is None:
        raise AccessDenied("Development preflight requires an existing confirmed workspace")
    policy = json.loads(row[1])
    if policy.get("confirmed") is not True or policy.get("cleanup_pending"):
        raise AccessDenied("Workspace scope confirmation or cleanup is pending")
    return {"workspace_id": row[0], "policy_version": policy["version"],
            "policy_fingerprint": policy["fingerprint"], "settings": policy["settings"]}


def _confirmed_access(root: Path, data_dir: Path) -> tuple[AccessPolicy, dict]:
    args = SimpleNamespace(workspace_data_dir=str(data_dir), access_policy=None,
                           confirm_access=False, exclude=[], local_only=[])
    access = resolve_access(args, root)
    identity = _workspace_identity(root, data_dir)
    if access.fingerprint != identity["policy_fingerprint"]:
        raise AccessDenied("Saved workspace policy and current ignore rules differ")
    access.check_current()
    return access, identity


def _hash_source(access: AccessPolicy, relative: str, *, limit: int) -> dict:
    data = access.read_bytes(relative, limit=limit)
    return {"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "access_mode": access.decision(relative)["mode"]}


def _safe_issues(issues) -> list[dict]:
    # No parser messages, declaration values, or command text enter artifacts.
    return [{"path": row.get("file", "."), "status": row.get("status", "unknown")}
            for row in issues]


def collect_current_inputs(access: AccessPolicy, frozen: FrozenInputs) -> dict:
    """Collect the same target-input boundaries used by the current builder."""
    access.refresh_if_changed()
    initial = access.fingerprint
    cfg = frozen.policy.index.exclude
    source_issues = []
    found = discover(access.root, cfg, issues=source_issues, access=access)
    sources = []
    unread_sources = []
    remaining = MAX_TOTAL_SOURCE_BYTES
    for index, (_absolute, relative, _suffix) in enumerate(sorted(found, key=lambda item: item[1])):
        if index >= MAX_SOURCE_FILES or remaining <= 0:
            unread_sources.append({"path":relative, "status":"unread:source-budget-limit"})
            continue
        try:
            allowance = min(MAX_SOURCE_BYTES, remaining)
            if access.resolve(relative).stat().st_size > allowance:
                unread_sources.append({"path":relative, "status":"unread:source-budget-limit"})
                continue
            row = _hash_source(access, relative, limit=allowance)
            remaining -= row["bytes"]
            row["ranking_scope"] = not any(classify(relative, cfg)[1:])
            sources.append(row)
        except AccessDenied:
            raise
        except (OSError, ValueError, UnicodeError):
            # A read may race a growing file. Its exact partial byte count is
            # unavailable after a bounded-reader exception, so reserve the
            # maximum allowance rather than accidentally exceed the run budget.
            remaining = max(0, remaining - allowance - 1)
            unread_sources.append({"path": relative, "status": "unread:source-limit-or-error"})
    # Environment declaration inspection is local and supplied with a non-probing
    # analyzer profile. No Node command, target import, dependency or test runs.
    profile = inspect_environment(access.root,
                                  toolchain=Toolchain(fingerprint="development-preflight-declarations-only"),
                                  access=access)
    configurations = dict(sorted(profile.configuration_files.items()))
    startup = collect_startup_inputs(access, exclude=cfg)
    startup_hashes = dict(sorted(startup.hashes.items()))
    del startup.texts
    documents = []
    document_states = []
    candidates = {row["path"] for row in frozen.project.get("documents", [])}
    candidates.update(name for name in DOCUMENT_NAMES if (access.root/name).is_file())
    for relative in sorted(candidates):
        decision = access.decision(relative)
        if decision["mode"] == "exclude":
            document_states.append({"path": relative, "status": "unread:access-policy"})
            continue
        if not (access.root/relative).is_file():
            document_states.append({"path": relative, "status": "missing"})
            continue
        try:
            documents.append(_hash_source(access, relative, limit=MAX_DOCUMENT_BYTES))
        except AccessDenied:
            raise
        except (OSError, ValueError, UnicodeError):
            document_states.append({"path": relative, "status": "unread:document-limit-or-error"})
    access.refresh_if_changed()
    access.check_current()
    if initial != access.fingerprint:
        raise AccessDenied("File permissions changed while collecting the manifest")
    return {
        "source_inventory": sources, "unread_source_inventory": unread_sources,
        "environment_configuration_hashes": configurations,
        "startup_input_hashes": startup_hashes,
        "document_inventory": documents, "document_states": document_states,
        "source_discovery_issues": _safe_issues(source_issues),
        "startup_issues": _safe_issues(startup.issues),
        "access_issues": _safe_issues(access.to_dict().get("issues", [])),
        "environment_unknown_count": len(profile.unknowns),
    }


def _summary(inputs: dict) -> dict:
    return {
        "source_files": len(inputs["source_inventory"]),
        "ranking_eligible_files": sum(row["ranking_scope"] for row in inputs["source_inventory"]),
        "source_bytes": sum(row["bytes"] for row in inputs["source_inventory"]),
        "unread_sources": len(inputs["unread_source_inventory"]),
        "configuration_files": len(inputs["environment_configuration_hashes"]),
        "configuration_unread": sum(not HEX.fullmatch(value) for value in inputs["environment_configuration_hashes"].values()),
        "startup_inputs": len(inputs["startup_input_hashes"]),
        "startup_unread": sum(not HEX.fullmatch(value) for value in inputs["startup_input_hashes"].values()),
        "documents": len(inputs["document_inventory"]), "document_unavailable": len(inputs["document_states"]),
        "source_scope_issues": len(inputs["source_discovery_issues"]),
        "startup_issues": len(inputs["startup_issues"]), "access_issues": len(inputs["access_issues"]),
    }


def _same_inputs(first: dict, second: dict) -> bool:
    return first == second


def _write_exclusive(path: Path, value: dict) -> str:
    raw = _json_bytes(value)
    with path.open("xb") as output:
        output.write(raw)
    digest = hashlib.sha256(raw).hexdigest()
    with path.with_name(path.name + ".sha256").open("x", encoding="ascii") as output:
        output.write(digest + "\n")
    return digest


def freeze_development_manifest(contract_path: Path, project_id: str, workspace_data_dir: Path,
                                output_dir: Path, run_id: str) -> dict:
    """Preflight then freeze current allowed inputs, with no scoring or relabeling."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", run_id):
        raise ValueError("Invalid run ID")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", project_id):
        raise ValueError("Invalid project ID")
    control = json.loads(contract_path.read_text(encoding="utf-8"))
    selected = [project for project in control.get("projects", []) if project.get("project_id") == project_id]
    if len(selected) != 1:
        raise ValueError("Unknown or ambiguous development project")
    root = Path(selected[0]["root"]).resolve()
    if contract_path.resolve().is_relative_to(root):
        raise ValueError("Trusted development contract must be outside target source")
    output_dir = output_dir.resolve()
    if output_dir.is_relative_to(root):
        raise ValueError("Development records must stay outside target source")
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{run_id}.{project_id}"
    manifest_path = output_dir/(stem + ".manifest.json")
    preflight_path = output_dir/(stem + ".preflight.json")
    if any(path.exists() for path in (manifest_path, preflight_path,
                                     manifest_path.with_name(manifest_path.name+".sha256"),
                                     preflight_path.with_name(preflight_path.name+".sha256"))):
        raise FileExistsError("Run ID already has frozen records; use a new ID")
    access, identity = _confirmed_access(root, workspace_data_dir)
    frozen = load_contract(contract_path.absolute(), project_id, root, None, access=access)
    drift = contract_input_drift(frozen, root, access=access)
    initial = access.fingerprint
    current = collect_current_inputs(access, frozen)
    second = collect_current_inputs(access, frozen)
    if not _same_inputs(current, second):
        raise ValueError("Target inputs changed while freezing; no manifest was published")
    access.check_current()
    if access.fingerprint != initial or _workspace_identity(root, workspace_data_dir) != identity:
        raise AccessDenied("Workspace permission identity changed while freezing")
    if hashlib.sha256(contract_path.read_bytes()).hexdigest() != frozen.sha256:
        raise ValueError("Parent contract changed during capture")
    covered = {row["path"] for group in (frozen.project["source_inventory"],
               frozen.project.get("environment_declarations", []), frozen.project.get("documents", [])) for row in group}
    startup_not_in_v1 = sorted(path for path in current["startup_input_hashes"] if path not in covered)
    change_counts = dict(sorted(Counter(row.get("change", "unknown") for row in drift).items()))
    if startup_not_in_v1:
        change_counts["startup_input_not_frozen_in_v1"] = len(startup_not_in_v1)
    summary = _summary(current)
    compatibility = {"comparable_to_v1": not drift and not startup_not_in_v1,
                     "change_counts": change_counts,
                     "kind_counts": dict(sorted(Counter(row.get("kind", "unknown") for row in drift).items()))}
    now = datetime.now(timezone.utc).isoformat()
    preflight = {"schema_version":1, "captured_at":now, "project_id":project_id,
                 "parent_contract_sha256":frozen.sha256, "changes":drift,
                 "additional_startup_inputs_not_frozen_in_v1":startup_not_in_v1,
                 "compatibility":compatibility, "summary":summary}
    manifest = {
        "schema_version":1, "manifest_kind":"navigation-development-allowed-run",
        "run_id":run_id, "captured_at":now, "project_id":project_id,
        "role":"dev-regression", "holdout":False, "root":str(root),
        "parent_contract_path":str(contract_path.absolute()), "parent_contract_sha256":frozen.sha256,
        "parent_contract_id":frozen.contract.get("contract_id"),
        "workspace":identity, "algorithm_scope":frozen.contract["frozen_scope"],
        "inputs":current, "input_snapshot_sha256":_digest(current),
        "summary":summary, "legacy_compatibility":compatibility,
        "label_provenance":{
            "source":"unchanged parent legacy document proxy; not human gold",
            "legacy_gt":frozen.project["legacy_gt"], "policy":frozen.contract.get("label_policy", {}),
            "ranking_eligible_canonical_labels":frozen.project["ranking_eligible_canonical_labels"],
            "not_ranked_canonical_labels":frozen.project.get("not_ranked_canonical_labels", []),
            "unmatched_labels":frozen.project.get("unmatched_labels", []),
            "ambiguous_labels":frozen.project.get("ambiguous_labels", []),
            "entry_gold":frozen.project.get("entry_gold", frozen.contract.get("task", {}).get("entry_gold", {})),
            "formal_acceptance_blockers":frozen.contract.get("formal_acceptance_blockers", []),
        },
        "constraints":{"scoring_started":False, "human_labels_approved":False,
                       "formal_contract_v2":False, "target_code_executed":False,
                       "target_dependencies_installed":False, "target_tests_collected":False,
                       "model_calls":False, "git_head":"not_read_under_access_policy",
                       "comparison":"current parser/graph with detector and reader ablations; not old binary replay"},
    }
    _write_exclusive(preflight_path, preflight)
    manifest_digest = _write_exclusive(manifest_path, manifest)
    return {"project_id":project_id, "compatibility":compatibility,
            "summary":summary, "manifest_sha256":manifest_digest,
            "input_snapshot_sha256":manifest["input_snapshot_sha256"],
            "manifest_path":str(manifest_path), "preflight_path":str(preflight_path)}


def _validate_run_manifest(manifest_path: Path, workspace_data_dir: Path) -> dict:
    """Recheck a frozen allowed run without modifying it or printing source data."""
    raw = manifest_path.read_bytes()
    expected = manifest_path.with_name(manifest_path.name+".sha256").read_text(encoding="ascii").strip()
    if hashlib.sha256(raw).hexdigest() != expected:
        return {"valid":False, "reason":"manifest_hash_changed"}
    manifest = json.loads(raw)
    if manifest.get("manifest_kind") != "navigation-development-allowed-run":
        return {"valid":False, "reason":"unsupported_manifest"}
    root = Path(manifest["root"]).resolve()
    access, identity = _confirmed_access(root, workspace_data_dir)
    if identity != manifest["workspace"]:
        return {"valid":False, "reason":"workspace_policy_changed"}
    parent = Path(manifest["parent_contract_path"])
    frozen = load_contract(parent, manifest["project_id"], root, None, access=access)
    if frozen.sha256 != manifest["parent_contract_sha256"]:
        return {"valid":False, "reason":"parent_contract_changed"}
    current = collect_current_inputs(access, frozen)
    if not _same_inputs(manifest["inputs"], current):
        return {"valid":False, "reason":"input_snapshot_changed", "summary":_summary(current)}
    access.check_current()
    return {"valid":True, "manifest_sha256":expected,
            "input_snapshot_sha256":_digest(current), "summary":_summary(current)}


def validate_run_manifest(manifest_path: Path, workspace_data_dir: Path) -> dict:
    """Return an explicit invalid status, including when permissions close."""
    try:
        return _validate_run_manifest(manifest_path, workspace_data_dir)
    except AccessDenied:
        return {"valid":False, "reason":"workspace_scope_unavailable"}
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        return {"valid":False, "reason":"validation_unavailable", "error_type":type(error).__name__}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--project-id", action="append", required=True)
    parser.add_argument("--workspace-data-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=REPOSITORY_ROOT/".venv/navigation-development")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    for project_id in args.project_id:
        try:
            report = freeze_development_manifest(args.contract, project_id, args.workspace_data_dir,
                                                 args.output_dir, args.run_id)
            # Paths, per-file changes and digests remain local. Only aggregate
            # counters and compatibility are exposed to the chat caller.
            print(json.dumps({key:report[key] for key in ("project_id","compatibility","summary")}, ensure_ascii=False))
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
            print(json.dumps({"project_id":project_id, "status":"preflight_failed",
                              "error_type":type(error).__name__}, ensure_ascii=False))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
