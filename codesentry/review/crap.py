"""Report Python function complexity and CRAP using an existing coverage report."""
from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Callable
import hashlib
import json
import math
from pathlib import PurePosixPath, PureWindowsPath

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.review.scan import PreviewLimits


FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
DECISIONS = (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler)


def _complexity(body: list[ast.stmt]) -> int:
    score = 1
    pending: list[ast.AST] = list(body)
    while pending:
        node = pending.pop()
        if isinstance(node, (*FUNCTIONS, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, DECISIONS):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            score += 1 + len(node.ifs)
        elif isinstance(node, ast.match_case):
            catch_all = isinstance(node.pattern, ast.MatchAs) and node.pattern.pattern is None
            score += int(not catch_all) + int(node.guard is not None)
        pending.extend(ast.iter_child_nodes(node))
    return score


def _functions(tree: ast.AST):
    pending = [(tree, ())]
    while pending:
        node, scope = pending.pop()
        if isinstance(node, (*FUNCTIONS, ast.ClassDef)):
            scope = (*scope, node.name)
            if isinstance(node, FUNCTIONS):
                yield ".".join(scope), node
            pending.extend((child, scope) for child in node.body)
        else:
            pending.extend((child, scope) for child in ast.iter_child_nodes(node))


def _read_coverage(access: AccessPolicy, path: str) -> tuple[dict, bool, str]:
    raw = access.read_bytes(path)
    try:
        report = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        raise ValueError("覆盖率文件须为有效的 coverage.py JSON 报告") from None
    meta = report.get("meta") if isinstance(report, dict) else None
    if (not isinstance(meta, dict) or meta.get("format") != 3
            or type(meta.get("branch_coverage")) is not bool or not isinstance(report.get("files"), dict)):
        raise ValueError("需要包含函数信息的 coverage.py JSON（格式 3，建议使用 7.13.1 或更新版本）")
    files = {}
    for name, data in report["files"].items():
        relative = PurePosixPath(name.replace("\\", "/"))
        if relative.is_absolute() or PureWindowsPath(name).drive or ".." in relative.parts:
            continue
        key = relative.as_posix()
        if key in files:
            raise ValueError("覆盖率报告中存在重复的项目相对路径")
        files[key] = data
    return files, meta["branch_coverage"], hashlib.sha256(raw).hexdigest()


def _count(summary: dict, covered_key: str, total_key: str) -> tuple[int, int] | None:
    covered, total = summary.get(covered_key), summary.get(total_key)
    if type(covered) is not int or type(total) is not int or not 0 <= covered <= total <= 2**31 - 1:
        return None
    return covered, total


def _coverage(region, start: int, end: int, branch_coverage: bool) -> tuple[str, dict | None]:
    if not isinstance(region, dict):
        return "missing_function_coverage", None
    if type(region.get("start_line")) is not int:
        return "missing_start_line", None
    if region["start_line"] != start:
        return "location_mismatch", None
    for field in ("executed_lines", "missing_lines"):
        lines = region.get(field)
        if not isinstance(lines, list) or any(type(line) is not int or not start <= line <= end for line in lines):
            return "invalid_region_lines", None
    summary = region.get("summary")
    if not isinstance(summary, dict):
        return "invalid_coverage_counts", None
    statements = _count(summary, "covered_lines", "num_statements")
    branches = _count(summary, "covered_branches", "num_branches") if branch_coverage else (0, 0)
    if statements is None or branches is None:
        return "invalid_coverage_counts", None
    if not branches[1] and not statements[1]:
        return "no_measurable_coverage", None

    measured = {}
    for basis, (covered, total) in (("branches", branches), ("statements", statements)):
        if total:
            measured[basis] = {"basis": basis, "covered": covered, "total": total, "ratio": covered / total}

    missing_branches = []
    arcs = region.get("missing_branches")
    if branches[1] and isinstance(arcs, list):
        for arc in arcs:
            if len(missing_branches) == 5:
                break
            if (isinstance(arc, list) and len(arc) == 2 and all(type(line) is int for line in arc)
                    and start <= arc[0] <= end and (-end <= arc[1] <= 0 or start <= arc[1] <= end)
                    and arc not in missing_branches):
                missing_branches.append(arc)
    return "available", {"branches": measured.get("branches"), "statements": measured.get("statements"),
                         "missing_branches": missing_branches, "missing_lines": sorted(set(region["missing_lines"]))[:5]}


def _suggestion(complexity: int, score: float | None, reference: float, measurement: dict | None) -> str:
    if score is None:
        if complexity >= reference:
            return "先收集同版本的覆盖率并锁定关键行为。即使完全覆盖，分数也至少等于当前圈复杂度，可检查是否能按独立职责拆分。"
        return "先取得同版本的函数级覆盖率，再根据未覆盖路径决定是否补测。"
    if complexity >= reference:
        return "圈复杂度本身已达到参考线。先用测试锁定输入、输出和异常，再检查能否按独立职责拆分决策，并比较改前改后结果。"
    if score >= reference:
        if measurement and measurement["branches"]:
            return "优先为未覆盖的分支增加行为测试，断言返回值、状态变化或异常，再重算评分。"
        return "优先补测未覆盖语句对应的行为。开启分支测量后核对条件两侧，再决定是否重构。"
    if measurement and measurement["branches"] and measurement["branches"]["ratio"] < 1:
        return "评分低于参考线。如果本次会修改这些分支，优先为未覆盖的路径补充行为断言。"
    if measurement and measurement["statements"] and measurement["statements"]["ratio"] < 1:
        return "评分低于参考线。如果本次会修改该函数，先为改动涉及的未覆盖行为补充断言。"
    return "当前评分低于参考线。修改前保留关键行为的测试，改动后复测并对比分数。"


def _file_scores(raw: bytes, relative: str, coverage, branch_coverage: bool,
                 report_provided: bool, reference: float) -> list[dict]:
    functions = list(_functions(ast.parse(raw, filename=relative)))
    counts = Counter(name for name, _ in functions)
    regions = coverage.get("functions") if isinstance(coverage, dict) else None
    rows = []
    for name, node in functions:
        complexity = _complexity(node.body)
        measurement = None
        if not report_provided:
            status = "coverage_not_provided"
        elif counts[name] > 1:
            status = "ambiguous_function_name"
        else:
            region = regions.get(name) if isinstance(regions, dict) else None
            status, measurement = _coverage(region, node.lineno, node.end_lineno, branch_coverage)
        coverage_used, score = None, None
        if measurement is not None:
            coverage_used = measurement["branches"] or measurement["statements"]
            score = complexity ** 2 * (1 - coverage_used["ratio"]) ** 3 + complexity
        rows.append({"file": relative, "function": name, "line": node.lineno, "end_line": node.end_lineno,
                     "complexity": complexity, "coverage_status": status, "coverage": coverage_used,
                     "branch_coverage": measurement["branches"] if measurement else None,
                     "statement_coverage": measurement["statements"] if measurement else None,
                     "missing_branches": measurement["missing_branches"] if measurement else [],
                     "missing_lines": measurement["missing_lines"] if measurement else [],
                     "crap": score, "at_or_above_reference": None if score is None else score >= reference,
                     "suggestion": _suggestion(complexity, score, reference, measurement)})
    return rows


def scan_crap(access: AccessPolicy, *, coverage_path: str | None = None, reference: float = 10,
              checkpoint: Callable[[], None] | None = None) -> dict:
    """Compute report-only scores for the permitted Python source snapshot."""
    if not math.isfinite(reference) or reference <= 0:
        raise ValueError("CRAP 参考线必须为有限正数")
    if not access.confirmed:
        raise AccessDenied("请先确认文件访问范围")
    access.refresh_if_changed()

    def inventory():
        paths = []
        for relative, _, is_dir, decision in access.walk(file_filter=lambda name: name.lower().endswith(".py")):
            if checkpoint:
                checkpoint()
            if not is_dir and decision["mode"] != "exclude":
                paths.append(relative)
        return sorted(paths)

    sources = inventory()
    access_fingerprint = access.fingerprint
    coverage, branch_coverage, coverage_hash = {}, False, None
    if coverage_path is not None:
        coverage, branch_coverage, coverage_hash = _read_coverage(access, coverage_path)

    limits = PreviewLimits()
    remaining = limits.max_total_bytes
    rows_by_file, snapshots, issues = {}, {}, []
    for index, relative in enumerate(sources):
        if checkpoint:
            checkpoint()
        if index >= limits.max_files or remaining <= 0:
            issues.append({"file": relative, "status": "budget_exhausted"})
            break
        reservation = min(remaining, limits.max_file_bytes)
        remaining -= reservation
        try:
            raw = access.read_bytes(relative, reservation)
            remaining += reservation - len(raw)
            rows_by_file[relative] = _file_scores(raw, relative, coverage.get(relative), branch_coverage,
                                                 coverage_path is not None, reference)
            snapshots[relative] = (len(raw), hashlib.sha256(raw).hexdigest())
        except SyntaxError as error:
            issues.append({"file": relative, "status": "syntax_error", "line": error.lineno})
        except (OSError, ValueError, RecursionError):
            issues.append({"file": relative, "status": "source_unavailable"})

    access.refresh_if_changed()
    if inventory() != sources:
        issues.append({"file": ".", "status": "source_inventory_changed"})
    for relative, (size, digest) in snapshots.items():
        if checkpoint:
            checkpoint()
        try:
            current = hashlib.sha256(access.read_bytes(relative, max(1, size))).hexdigest()
        except (OSError, ValueError):
            current = None
        if current != digest:
            del rows_by_file[relative]
            issues.append({"file": relative, "status": "source_changed"})
    if coverage_path is not None and hashlib.sha256(access.read_bytes(coverage_path)).hexdigest() != coverage_hash:
        raise ValueError("覆盖率报告在计算期间变化，请重新运行")
    access.refresh_if_changed()
    if access.fingerprint != access_fingerprint:
        raise AccessDenied("计算期间文件访问范围变化，本次报告已丢弃")
    issues.extend(access.to_dict()["issues"])

    rows = [row for file_rows in rows_by_file.values() for row in file_rows]
    rows.sort(key=lambda row: (row["crap"] is None, -(row["crap"] or 0), -row["complexity"],
                               row["file"], row["line"]))
    scored = sum(row["crap"] is not None for row in rows)
    branches = [row["branch_coverage"] for row in rows if row["branch_coverage"] is not None]
    return {"schema_version": 1, "mode": "report_only", "gate_status": "not_evaluated",
            "scan_status": "incomplete" if issues else "complete", "complexity_method": "python_ast_v1",
            "coverage_origin": "imported_unverified" if coverage_path is not None else "not_provided",
            "coverage_report_sha256": coverage_hash, "reference": reference,
            "branch_totals": {"covered": sum(item["covered"] for item in branches),
                              "total": sum(item["total"] for item in branches), "functions": len(branches)},
            "summary": {"python_files": len(rows_by_file), "functions": len(rows), "scored": scored,
                        "unscored": len(rows) - scored,
                        "at_or_above_reference": sum(row["at_or_above_reference"] is True for row in rows)},
            "source_sha256": {name: snapshots[name][1] for name in rows_by_file},
            "functions": rows, "issues": issues}
