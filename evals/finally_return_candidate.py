"""Fixed development-only syntax detector. Takes source text and produces positions."""
from __future__ import annotations

import ast
import warnings


RULE_ID = "python.finally_return"
RULE_VERSION = "1"
MAX_SOURCE_BYTES = 64 * 1024


def detect(source: str) -> dict:
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        return {"status": "source_limit", "hits": []}
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=r"^'return' in a 'finally' block$", category=SyntaxWarning)
            tree = ast.parse(source, filename="<synthetic>")
            # AST parsing alone accepts constructs such as a module-level return.
            compile(tree, "<synthetic>", "exec", dont_inherit=True)
    except SyntaxError:
        return {"status": "invalid_source", "hits": []}
    except RecursionError:
        return {"status": "source_limit", "hits": []}

    hits = []

    def visit(node, cleanup_try=None):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            cleanup_try = None
        if isinstance(node, ast.Return) and cleanup_try is not None:
            hits.append([node.lineno, node.end_lineno, cleanup_try])
        if isinstance(node, (ast.Try, ast.TryStar)):
            for child in (*node.body, *node.handlers, *node.orelse):
                visit(child, cleanup_try)
            for child in node.finalbody:
                visit(child, node.lineno)
        else:
            for child in ast.iter_child_nodes(node):
                visit(child, cleanup_try)

    try:
        visit(tree)
    except RecursionError:
        return {"status": "source_limit", "hits": []}
    return {"status": "checked", "hits": sorted(hits)}
