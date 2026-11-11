"""Bounded, permission-checked preview of report-only static observations."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.review.rules import RULE_ID, RULE_VERSION, function_length_rule
from codesentry.review.verification import VerificationContext


PYTHON_SUFFIXES = {".py", ".pyi"}
OTHER_SOURCE_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}


@dataclass(frozen=True)
class PreviewLimits:
    max_files: int = 2000
    max_total_bytes: int = 32 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in asdict(self).values()):
            raise ValueError("Preview limits must be positive integers")
        if self.max_files > 10_000 or self.max_total_bytes > 256*1024*1024 or self.max_file_bytes > 8*1024*1024:
            raise ValueError("Preview limits exceed the supported first-rule scope")


def preview_policy(*, max_function_lines: int = 80, limits: PreviewLimits | None = None) -> dict:
    """Describe trusted rule settings without enumerating or reading a project."""
    limits = limits or PreviewLimits()
    function_length_rule(max_function_lines)
    return {"schema_version": 1, "rule_id": RULE_ID, "rule_version": RULE_VERSION,
        "max_function_lines": max_function_lines, "classification": "policy_debt",
        "mode": "report_only", "limits": asdict(limits)}


def scan_preview(access: AccessPolicy, *, max_function_lines: int = 80,
                 limits: PreviewLimits | None = None) -> dict:
    limits = limits or PreviewLimits()
    rule = function_length_rule(max_function_lines)
    access.refresh_if_changed()
    if not access.confirmed:
        raise AccessDenied("请先确认文件访问范围")
    initial_access = access.fingerprint
    policy = preview_policy(max_function_lines=max_function_lines, limits=limits)
    policy_hash = hashlib.sha256(json.dumps(policy, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    contexts, rows, issues, source_hashes = [], [], [], {}
    discovered = excluded = unsupported = total_bytes = attempted = 0

    def check_scope():
        access.refresh_if_changed()
        if access.fingerprint != initial_access:
            raise AccessDenied("扫描期间文件访问范围变化，预览输出已丢弃")

    def candidate(relative):
        return Path(relative).suffix.casefold() in PYTHON_SUFFIXES | OTHER_SOURCE_SUFFIXES

    def inventory():
        return sorted((relative, decision["mode"]) for relative, _, directory, decision
                      in access.walk(file_filter=candidate) if not directory)

    initial_inventory = inventory()
    check_scope()
    discovered = sum(Path(relative).suffix.casefold() in PYTHON_SUFFIXES
                     and mode != "exclude" for relative, mode in initial_inventory)
    for relative, mode in initial_inventory:
        suffix = Path(relative).suffix.casefold()
        if mode == "exclude":
            if suffix in PYTHON_SUFFIXES:
                excluded += 1
            continue
        if suffix in OTHER_SOURCE_SUFFIXES:
            unsupported += 1
            continue
        if attempted >= limits.max_files or total_bytes >= limits.max_total_bytes:
            issues.append({"file": relative, "status": "budget_exhausted"})
            break
        attempted += 1
        reservation = min(limits.max_file_bytes, limits.max_total_bytes - total_bytes)
        # On failed loads the exact amount may be unavailable. Keep the whole
        # reservation charged; only a successful bounded read can refund it.
        total_bytes += reservation
        try:
            context = VerificationContext(access, rule, file=relative, policy_identity=policy,
                max_file_bytes=reservation,
                max_total_bytes=reservation)
            total_bytes -= reservation - context.input.raw_size
            source_hashes[relative] = context.input.raw_sha256
            findings = context.evaluate()
            contexts.append((relative, context, findings))
        except SyntaxError as error:
            issues.append({"file": relative, "status": "syntax_error", "line": error.lineno})
        except (OSError, ValueError, UnicodeError, RecursionError):
            check_scope()
            issues.append({"file": relative, "status": "input_or_rule_incomplete"})
    check_scope()
    if inventory() != initial_inventory:
        issues.append({"file": ".", "status": "source_inventory_changed"})
    check_scope()
    for relative, context, findings in contexts:
        try:
            context.check_current()
            file_rows = []
            for finding in findings:
                file_rows.append({"finding": finding.model_dump(mode="json"),
                    "classification": "policy_debt", "mode": "report_only",
                    "can_block": finding.can_block(context), "file": finding.file})
            # can_block deliberately converts expired credentials to False.
            # Do not confuse observed source drift with ordinary report-only
            # ineligibility when publishing the file's serialized observations.
            context.check_current()
        except (OSError, ValueError):
            check_scope()
            issues.append({"file": relative, "status": "source_or_rule_changed"})
            source_hashes.pop(relative, None)
            continue
        rows.extend(file_rows)
    check_scope()
    if access.issues:
        issues.append({"file": ".", "status": "access_scope_incomplete"})
    coverage = access.to_dict()
    permissions_limited = bool(coverage["restricted"] or excluded)
    status = "incomplete" if issues else "report_only" if contexts else "not_applicable"
    # A preview never reports pass/block and deliberately returns no gate
    # success. Its Findings' serialized hints cannot restore process credentials.
    return {"schema_version": 1, "review_status": status, "gate_status": "not_evaluated",
        "mode": "preview", "language_scope": "permitted_python_files_only",
        "policy": policy, "policy_sha256": policy_hash,
        "rules": [{"rule_id": RULE_ID, "rule_version": RULE_VERSION,
                   "classification": "policy_debt", "approved_for_blocking": False}],
        "coverage": {"discovered_python": discovered, "analyzed_python": len(contexts),
            "attempted_python": attempted,
            "excluded_python": excluded, "other_language_files_not_evaluated": unsupported,
            "bytes_accounted_for_budget": total_bytes,
            "byte_accounting": "actual bytes on successful load; full per-file reservation on load failure",
            "permissions_limited": permissions_limited,
            "within_scope_complete": status == "report_only",
            "whole_repository_evaluated": False},
        "access_fingerprint": initial_access, "source_sha256": source_hashes,
        "findings": rows, "issues": issues,
        "summary": {"policy_debt_findings": len(rows), "behavior_bug_findings": 0,
                    "blocking_findings": 0},
        "formal_acceptance": {"passed": False, "reason": "report-only preview; no CI gate or detector-quality acceptance"}}
