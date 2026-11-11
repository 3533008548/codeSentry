"""Report-only syntax candidates; no target execution or confirmed bug claims.

The first rule observes a literal, nonempty tuple used as an assert test. Its
truth check is true *after successful construction*, if assertions are enabled.
Reachability, element effects/exceptions and the author's intent are unknown.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.core.finding import Extraction, Severity
from codesentry.review.scan import OTHER_SOURCE_SUFFIXES, PYTHON_SUFFIXES, PreviewLimits
from codesentry.review.verification import RuleObservation, SourceInput, TrustedRuleSpec, VerificationContext


RULE_ID = "python.assert_tuple"
RULE_VERSION = "1"
LIMITATIONS = (
    "Only the assert-test syntax is established; a behavioral bug has not been confirmed by a person.",
    "The tuple truth check is true only after successful construction and when assertions are enabled.",
    "Reachability, side effects, exceptions, author intent and actual runtime consequences are not assessed.",
    "Only permitted Python files are checked; zero candidates is not a gate pass or detector-quality acceptance.",
)


def _evaluate_assert_tuples(source: SourceInput):
    tree = ast.parse(source.text, filename=source.file, type_comments=True)
    observations, occurrences = [], defaultdict(int)

    def visit(node, scope=()):
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                visit(child, (*scope, node.name))
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in node.body:
                visit(child, (*scope, node.name, "<locals>"))
            return
        if (isinstance(node, ast.Assert) and isinstance(node.test, ast.Tuple)
                and node.test.elts and not any(isinstance(child, ast.Starred) for child in ast.walk(node.test))):
            # Drop only the trailing locals marker; retain full enclosing scopes.
            names = scope[:-1] if scope and scope[-1] == "<locals>" else scope
            symbol = source.file + "::" + (".".join(names) if names else "<module>")
            anchor = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
            occurrences[(symbol, anchor)] += 1
            facts = {
                "classification": "behavior_bug_candidate", "tuple_arity": len(node.test.elts),
                "no_starred": True, "always_truthy_after_successful_construction": True,
                "assertions_enabled_requirement": True, "unreachable_or_side_effects_not_assessed": True,
                "intent_not_confirmed": True, "confirmed_behavior_bug": False,
            }
            observations.append(RuleObservation(
                file=source.file, line=node.lineno, end_line=node.end_lineno,
                symbol=symbol, anchor=anchor, occurrence=occurrences[(symbol, anchor)],
                reason="assert 检查非空元组；构造成功后真值恒真。可能误写断言，尚未人工确认",
                severity=Severity.MEDIUM, extraction=Extraction(extra=facts), facts=facts))
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree)
    return tuple(observations)


def assert_tuple_rule() -> TrustedRuleSpec:
    return TrustedRuleSpec(RULE_ID, RULE_VERSION, hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                           _evaluate_assert_tuples, approved_for_blocking=False)


def defect_preview_policy(*, limits: PreviewLimits | None = None) -> dict:
    limits = PreviewLimits() if limits is None else limits
    if type(limits) is not PreviewLimits:
        raise TypeError("defect preview requires trusted PreviewLimits")
    return {"schema_version": 1, "rule_id": RULE_ID, "rule_version": RULE_VERSION,
            "classification": "behavior_bug_candidate", "mode": "report_only", "limits": asdict(limits)}


def scan_defect_preview(access: AccessPolicy, *, limits: PreviewLimits | None = None) -> dict:
    if not isinstance(access, AccessPolicy):
        raise TypeError("defect preview requires trusted AccessPolicy")
    limits = PreviewLimits() if limits is None else limits
    policy = defect_preview_policy(limits=limits)
    policy_hash = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=False).encode()).hexdigest()
    rule = assert_tuple_rule()
    access.refresh_if_changed()
    access.check_current()
    if not access.confirmed:
        raise AccessDenied("请先确认文件访问范围")
    initial_access = access.fingerprint
    contexts, rows, issues, source_hashes = [], [], [], {}
    excluded = unsupported = total_bytes = attempted = 0

    def check_scope():
        access.refresh_if_changed()
        access.check_current()
        if not access.confirmed or access.fingerprint != initial_access:
            raise AccessDenied("扫描期间文件访问范围变化，缺陷候选输出已丢弃")

    def inventory():
        # Check the whole permitted inventory, not only files with findings.
        return sorted((relative, directory, decision["mode"])
                      for relative, _, directory, decision in access.walk())

    try:
        initial_inventory = inventory()
        check_scope()
        discovered = sum(not directory and Path(relative).suffix.casefold() in PYTHON_SUFFIXES
                         and mode != "exclude" for relative, directory, mode in initial_inventory)
        for relative, directory, mode in initial_inventory:
            if directory:
                continue
            suffix = Path(relative).suffix.casefold()
            if mode == "exclude":
                excluded += suffix in PYTHON_SUFFIXES
                continue
            if suffix not in PYTHON_SUFFIXES:
                unsupported += suffix in OTHER_SOURCE_SUFFIXES
                continue
            if attempted >= limits.max_files or total_bytes >= limits.max_total_bytes:
                issues.append({"file": relative, "status": "budget_exhausted"})
                break
            attempted += 1
            reservation = min(limits.max_file_bytes, limits.max_total_bytes - total_bytes)
            total_bytes += reservation
            context = None
            try:
                context = VerificationContext(access, rule, file=relative, policy_identity=policy,
                    max_file_bytes=reservation, max_total_bytes=reservation)
                total_bytes -= reservation - context.input.raw_size
                findings = context.evaluate()
                source_hashes[relative] = context.input.raw_sha256
                contexts.append((relative, context, findings))
            except AccessDenied:
                if context is not None:
                    context.close()
                raise
            except SyntaxError as error:
                if context is not None:
                    context.close()
                issues.append({"file": relative, "status": "syntax_error", "line": error.lineno})
            except (OSError, ValueError, UnicodeError, RecursionError):
                if context is not None:
                    context.close()
                check_scope()
                issues.append({"file": relative, "status": "input_or_rule_incomplete"})
        check_scope()
        if inventory() != initial_inventory:
            issues.append({"file": ".", "status": "source_inventory_changed"})
        check_scope()
        analyzed = 0
        for relative, context, findings in contexts:
            try:
                context.check_current()
                file_rows = [{"finding": finding.model_dump(mode="json"),
                    "classification": "behavior_bug_candidate", "mode": "report_only",
                    "can_block": finding.can_block(context), "confirmed_behavior_bug": False,
                    "file": finding.file} for finding in findings]
                context.check_current()
            except AccessDenied:
                raise
            except (OSError, ValueError):
                check_scope()
                issues.append({"file": relative, "status": "source_or_rule_changed"})
                source_hashes.pop(relative, None)
                continue
            rows.extend(file_rows)
            analyzed += 1
        check_scope()
        if access.issues:
            issues.append({"file": ".", "status": "access_scope_incomplete"})
        coverage = access.to_dict()
        status = "incomplete" if issues else "report_only" if analyzed else "not_applicable"
        return {"schema_version": 1, "review_status": status, "gate_status": "not_evaluated",
            "mode": "defect_preview", "language_scope": "permitted_python_files_only",
            "policy": policy, "policy_sha256": policy_hash,
            "rules": [{"rule_id": RULE_ID, "rule_version": RULE_VERSION,
                "classification": "behavior_bug_candidate", "approved_for_blocking": False}],
            "coverage": {"discovered_python": discovered, "analyzed_python": analyzed,
                "attempted_python": attempted, "excluded_python": excluded,
                "other_language_files_not_evaluated": unsupported, "bytes_accounted_for_budget": total_bytes,
                "byte_accounting": "actual bytes on successful load; full per-file reservation on load failure",
                "permissions_limited": bool(coverage["restricted"] or excluded),
                "within_scope_complete": status == "report_only", "whole_repository_evaluated": False},
            "access_fingerprint": initial_access, "source_sha256": source_hashes,
            "findings": rows, "issues": issues, "limitations": list(LIMITATIONS),
            "summary": {"candidate_findings": len(rows), "confirmed_behavior_bug_findings": 0,
                "blocking_findings": 0},
            "formal_acceptance": {"passed": False,
                "reason": "syntax candidates only; no human bug adjudication, CI gate or detector-quality acceptance"}}
    finally:
        for _, context, _ in contexts:
            context.close()
