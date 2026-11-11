"""First trusted static rule: a report-only Python physical-length policy.

This is a policy-debt observation, never a demonstrated behavioral bug. The
threshold is selected by trusted caller arguments, not target repository config.
"""
from __future__ import annotations

import ast
from collections import defaultdict
import hashlib
from pathlib import Path

from codesentry.core.finding import Extraction, Severity
from codesentry.review.verification import RuleObservation, SourceInput, TrustedRuleSpec


RULE_ID = "python.function_length"
RULE_VERSION = "1"
DEFAULT_MAX_FUNCTION_LINES = 80


def function_length_rule(max_lines: int = DEFAULT_MAX_FUNCTION_LINES) -> TrustedRuleSpec:
    if type(max_lines) is not int or not 1 <= max_lines <= 100_000:
        raise ValueError("Function-line threshold must be an integer between 1 and 100000")

    def evaluate(source: SourceInput):
        tree = ast.parse(source.text, filename=source.file, type_comments=True)
        observations = []
        occurrences = defaultdict(int)

        def visit(node, scope=()):
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    visit(child, (*scope, node.name))
                return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbol = source.file + "::" + ".".join((*scope, node.name))
                anchor = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                occurrences[(symbol, anchor)] += 1
                length = node.end_lineno - node.lineno + 1
                if length > max_lines:
                    facts = {"classification": "policy_debt", "function_lines": length,
                        "max_function_lines": max_lines, "function_kind": type(node).__name__,
                        "measurement": "def_through_ast_end_inclusive", "decorators_counted": False}
                    observations.append(RuleObservation(
                        file=source.file, line=node.lineno, end_line=node.end_lineno,
                        symbol=symbol, anchor=anchor, occurrence=occurrences[(symbol, anchor)],
                        reason=f"函数定义跨{length}行，超过本次策略阈值{max_lines}行",
                        severity=Severity.LOW,
                        extraction=Extraction(function_lines=length, extra=facts), facts=facts))
                for child in node.body:
                    visit(child, (*scope, node.name, "<locals>"))
                return
            for child in ast.iter_child_nodes(node):
                visit(child, scope)

        visit(tree)
        return tuple(observations)

    return TrustedRuleSpec(RULE_ID, RULE_VERSION,
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), evaluate,
        approved_for_blocking=False)
