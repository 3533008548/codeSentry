"""Bounded Python call bindings derived from source already cited for review."""
from __future__ import annotations

from codesentry.core.symbol import SymbolKind
from codesentry.index.resolver import SymbolResolver
from codesentry.parsers.python_parser import PythonParser


MAX_FILES = 64
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 256 * 1024
MAX_LINKS = 24


def _range_at(rows, line):
    return next(row for row in rows if row["start_line"] <= line <= row["end_line"])


def collect_call_links(root, files, cited, sources):
    """Parse fully cited files, preserving both ends of exact cross-file imports."""
    parser = PythonParser(max_ast_nodes=30_000, max_ast_depth=120)
    symbols, calls, imports, covered = {}, [], {}, {}
    used_bytes = 0
    for file in files:
        path = file["path"]
        rows = cited.get(path, ())
        if not path.endswith(".py") or not rows or file["raw_bytes"] > MAX_FILE_BYTES:
            continue
        if sum(row["end_line"] - row["start_line"] + 1 for row in rows) != file["lines"]:
            continue
        if len(covered) >= MAX_FILES:
            break
        text = "".join(sources[row["id"]]["source"] for row in rows)
        size = len(text.encode())
        if size > MAX_FILE_BYTES or used_bytes + size > MAX_TOTAL_BYTES:
            continue
        used_bytes += size
        definitions, sites, _, modules = parser.parse_with_meta(root / path, path, text)
        covered[path] = rows
        imports[path] = modules
        calls.extend(sites)
        symbols.update((symbol.qname, symbol) for symbol in definitions)

    resolver = SymbolResolver()
    # Known alternative module paths still count for ambiguity if their text is out of scope.
    resolver.build(list(symbols.values()), imports, set(), all_files=[file["path"] for file in files])
    links = set()
    for call in resolver.resolve_all(calls, set(), set()):
        if not call.is_certain or call.method != "exact_import":
            continue
        target = symbols[call.target]
        if target.file == call.file or target.kind != SymbolKind.FUNCTION:
            continue
        origin = _range_at(covered[call.file], call.line)
        destination = _range_at(covered[target.file], target.line)
        links.add((origin["batch"] == destination["batch"], origin["id"], call.line, destination["id"], target.line))
    return [{"source_id": origin, "line": line, "target_id": target, "target_line": target_line}
            for _, origin, line, target, target_line in sorted(links)[:MAX_LINKS]]
