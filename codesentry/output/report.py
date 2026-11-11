"""L1 / L2 输出。

L1 · 定位（<30s）  —— "这是什么项目？"
    技术栈 + 入口点列表 + 规模统计
L2 · 骨架（<3min） —— "它怎么组织的？"
    核心模块（按 PageRank 排序）+ 推荐阅读顺序

**L1/L2 全确定性，不调 LLM**（v0.2 决策 10）。
"""
from __future__ import annotations

import json
from collections import defaultdict

from codesentry.core.symbol import FileMeta, Language, Symbol
from codesentry.index.builder import IndexResult

# 已知技术栈识别（基于依赖名，不联网）
TECH_SIGNALS = {
    "langgraph": "LangGraph", "langchain": "LangChain",
    "fastapi": "FastAPI", "flask": "Flask", "django": "Django",
    "sqlalchemy": "SQLAlchemy", "alembic": "Alembic",
    "chromadb": "ChromaDB", "faiss": "FAISS", "sentence_transformers": "SentenceTransformers",
    "transformers": "Transformers", "torch": "PyTorch", "onnxruntime": "ONNX Runtime",
    "playwright": "Playwright", "pytest": "pytest", "pydantic": "Pydantic",
    "react": "React", "vue": "Vue", "svelte": "Svelte",
    "electron": "Electron", "vite": "Vite", "esbuild": "esbuild",
    "vitest": "Vitest", "tailwindcss": "Tailwind CSS",
    "zod": "Zod", "redux": "Redux", "zustand": "Zustand",
    "mermaid": "Mermaid", "express": "Express",
}


def detect_stack(files: list[FileMeta]) -> list[str]:
    """从 import / 文件名识别技术栈。"""
    found: set[str] = set()
    for f in files:
        haystack = " ".join(f.imports).lower() + " " + f.path.lower()
        for key, label in TECH_SIGNALS.items():
            if key in haystack:
                found.add(label)
    return sorted(found)


def _lang_line(files: list[FileMeta]) -> str:
    by_lang: dict[Language, list[FileMeta]] = defaultdict(list)
    for f in files:
        by_lang[f.language].append(f)
    parts = []
    for lang, group in sorted(by_lang.items(), key=lambda kv: -len(kv[1])):
        if lang is Language.UNKNOWN:
            continue
        lines = sum(g.lines for g in group)
        name = {Language.PYTHON: "Python", Language.TYPESCRIPT: "TypeScript"}.get(
            lang, lang.value)
        parts.append(f"{name} {lines:,} 行 / {len(group)} 文件")
    return " · ".join(parts)



def _analysis_context(result: IndexResult) -> list[str]:
    """公开证据边界，环境声明不被描述成目标已运行。"""
    files = result.files
    parsed = sum(f.is_parsed and f.language is not Language.UNKNOWN for f in files)
    issues = getattr(result, "parse_issues", []) or []
    complete = (bool(files) and parsed == len(files) and not result.parse_failures
                and not issues and getattr(result, "is_complete", None) is not False)
    lines = ["证据    static（静态分析）；目标运行验证未执行",
             f"解析    成功{parsed}/{len(files)}个已记录文件 · 失败/未解析{len(files) - parsed} · {'完整' if complete else '不完整'}"]
    environment = getattr(result, "environment", {}) or {}
    if isinstance(environment, dict) and environment:
        units = environment.get("project_units", [])
        unknowns = environment.get("unknowns", [])
        observed = environment.get("observed", {})
        names = ", ".join(sorted(observed)) if isinstance(observed, dict) else "未提供"
        lines.append(f"环境    声明项目单元{len(units) if isinstance(units, list) else '未知'}；已观测工具字段：{names or '无'}；未知项{len(unknowns) if isinstance(unknowns, (list, dict)) else '未知'}")
        lines.append("        声明/工具观测不代表目标依赖已安装或业务可运行")
    else:
        lines.append("环境    画像未提供；不推定目标环境已就绪")
    fingerprint = getattr(result, "environment_fingerprint", "")
    if fingerprint:
        lines.append(f"环境身份 {fingerprint[:16]}（完整身份见JSON）")
    for issue in issues[:8]:
        if isinstance(issue, dict):
            path = issue.get("path", issue.get("file", "未知文件"))
            reason = issue.get("reason", issue.get("message", issue.get("kind", "解析未完成")))
            lines.append(f"未完成  {path}: {reason}")
        else:
            lines.append(f"未完成  {issue}")
    if len(issues) > 8:
        lines.append(f"未完成  另有{len(issues) - 8}项，详见JSON")
    return lines


def render_l1(result: IndexResult) -> str:
    """L1 · 定位输出。"""
    lines: list[str] = []
    files = result.files
    prod = [f for f in files if f.is_production]
    test_files = [f for f in files if f.is_test]

    lines.append("=" * 68)
    lines.append("L1 · 定位（静态证据）")
    lines.append("=" * 68)

    lines.extend(_analysis_context(result))
    lines.append("")

    stack = detect_stack(files)
    if stack:
        lines.append(f"技术栈  {', '.join(stack)}")
    lines.append(f"规模    {_lang_line(files)}")

    prod_syms = [s for s in result.symbols if s.is_production]
    test_syms = [s for s in result.symbols if s.is_test]
    n_func = sum(1 for s in prod_syms if s.kind.value in ("function", "method"))
    n_class = sum(1 for s in prod_syms if s.kind.value == "class")
    lines.append(
        f"符号    生产 {len(prod_syms):,}（{n_func:,} 函数 · {n_class:,} 类）"
        f" · 测试 {len(test_syms):,}（{len(test_files)} 文件）"
    )

    # 最长符号
    longest = max(
        (s for s in result.symbols if s.is_production),
        key=lambda s: s.length, default=None,
    )
    if longest:
        lines.append(
            f"最长    {longest.name}  {longest.length} 行  ({longest.file})")

    # 入口点
    lines.append("")
    lines.append("启动与装配线索（不等于已运行或人工标签）:")
    kinds = {"process": "进程入口", "mount": "界面挂载", "bridge": "桥接上下文",
             "assembly": "应用装配", "candidate": "待确认候选"}
    confidence = {"declared": "启动声明", "static": "静态证据", "heuristic": "名称线索"}
    for e in result.entrypoints:
        position = f"{e.file}:{e.line}" if getattr(e, "line", None) else f"{e.file}（入口行号未知）"
        kind = kinds.get(getattr(e, "kind", "candidate"), "待确认候选")
        basis = confidence.get(getattr(e, "confidence", "heuristic"), "待核对证据")
        lines.append(f"  {position:<44} [{kind} · {basis}] {e.reason}")
        for evidence in getattr(e, 'evidence', [])[:3]:
            source = evidence.get('file', '')
            if source:
                number = evidence.get('line')
                location = f'{source}:{number}' if number else source
                lines.append(f'      依据 {location}')
    entry_issues = getattr(result, 'entry_evidence_issues', [])
    if entry_issues:
        lines.append(f'启动证据有{len(entry_issues)}项未知/限制，不能据此声称入口已找齐。')
        for issue in entry_issues[:5]:
            lines.append(f"  {issue.get('file', '.')}：{issue.get('message', issue.get('status', '未知'))}")
    if result.script_entrypoints:
        lines.append(f"脚本入口: {len(result.script_entrypoints)} 个（折叠不列）")

    # 调用解析统计
    if result.call_stats:
        resolved = result.call_stats.get("local", 0) + \
            result.call_stats.get("cross_file", 0)
        heuristic = result.call_stats.get("heuristic", 0)
        total = resolved + sum(result.call_stats.get(kind, 0)
                               for kind in ("unresolved", "ambiguous", "heuristic"))
        rate = f"{resolved / total * 100:.1f}%" if total else "N/A"
        lines.append("")
        lines.append(
            f"绑定    项目内候选确定绑定 {resolved:,}/{total:,} "
            f"({rate}) · 启发式猜测 {heuristic:,}")

    return "\n".join(lines)


def _reading_order(
    result: IndexResult, top: int = 10
) -> list[tuple[str, str]]:
    """兼容旧调用：返回 [(文件, 标签)]。"""
    from codesentry.output.reading_order import reading_order
    return [(f, label) for f, label, _ in reading_order(result, max_items=top)]


def render_l2(result: IndexResult, top: int = 12) -> str:
    """L2 · 骨架输出。"""
    lines: list[str] = []
    lines.append("=" * 68)
    lines.append("L2 · 骨架（PageRank 重要度）")
    lines.append("=" * 68)

    lines.extend(_analysis_context(result))
    lines.append("")

    line_count = {f.path: f.lines for f in result.files}
    sym_count: dict[str, int] = defaultdict(int)
    for s in result.symbols:
        sym_count[s.file] += 1

    lines.append(
        f"{'#':<3}{'文件':<40}{'PR':>10}{'行数':>8}{'符号':>7}{'被引':>7}  角色")
    for i, (f, score) in enumerate(result.top_files(top), 1):
        role = result.roles.get(f)
        role_label = role.role if role and role.role != "-" else ""
        lines.append(
            f"{i:<3}{f:<40}{score:>10.5f}{line_count.get(f, 0):>8}"
            f"{sym_count.get(f, 0):>7}{len(result.reverse_refs.get(f, ())):>7}"
            f"  {role_label}")

    lines.append("")
    from codesentry.output.reading_order import render_reading_order
    lines.append(render_reading_order(result))

    # 核心符号
    sym_ranked = sorted(
        result.symbol_pr.items(), key=lambda kv: -kv[1]
    )[:10]
    if sym_ranked:
        lines.append("")
        lines.append("核心符号 Top10:")
        qmap = {s.qname: s for s in result.symbols}
        for i, (q, score) in enumerate(sym_ranked, 1):
            s = qmap.get(q)
            if not s:
                continue
            lines.append(
                f"  {i:<3}{s.name:<30}{s.file}:{s.line:<7}{score:>10.5f}")

    return "\n".join(lines)


def to_dict(result: IndexResult) -> dict:
    """导出为 JSON 友好的结构。"""
    return {
        "root": result.root,
        "analysis_mode": "static",
        "dynamic_verification": "not_run",
        "environment": getattr(result, "environment", {}),
        "environment_fingerprint": getattr(result, "environment_fingerprint", ""),
        "input_fingerprint": getattr(result, "input_fingerprint", ""),
        "access_fingerprint": getattr(result, "access_fingerprint", ""),
        "access_policy": getattr(result, "access_policy", {}),
        "source_permissions": getattr(result, "source_permissions", {}),
        "provenance": getattr(result, "provenance", {}),
        "startup_inputs": getattr(result, "startup_inputs", {}),
        "entry_evidence_complete": not bool(getattr(result, "entry_evidence_issues", [])),
        "entry_evidence_issues": getattr(result, "entry_evidence_issues", []),
        "access_scope_limited": any(issue.get("status") == "access_scope_limited"
                                    for issue in getattr(result, "parse_issues", [])),
        "is_complete": getattr(result, "is_complete", None),
        "parse_failures": result.parse_failures,
        "parse_issues": getattr(result, "parse_issues", []),
        "parsing": {
            "recorded_files": len(result.files),
            "parsed_files": sum(f.is_parsed and f.language is not Language.UNKNOWN for f in result.files),
            "unparsed_files": [f.path for f in result.files if not f.is_parsed or f.language is Language.UNKNOWN],
        },
        "files": len(result.files),
        "symbols": len(result.symbols),
        "edges": len(result.edges),
        "timings": {k: round(v, 4) for k, v in result.timings.items()},
        "call_stats": result.call_stats,
        "entrypoints": [
            {"file": e.file, "line": getattr(e, "line", None), "reason": e.reason, "out_degree": e.out_degree,
             "in_degree": e.in_degree, "kind": getattr(e, "kind", "candidate"),
             "confidence": getattr(e, "confidence", "heuristic"), "evidence": getattr(e, "evidence", [])}
            for e in result.entrypoints
        ],
        "script_entrypoint_count": len(result.script_entrypoints),
        "top_files": [
            {"file": f, "score": round(s, 6),
             "role": (result.roles.get(f).role if result.roles.get(f) else "-"),
             "lines": next((m.lines for m in result.files if m.path == f), 0)}
            for f, s in result.top_files(20)
        ],
        "top_symbols": [
            {"qname": q, "score": round(s, 6)}
            for q, s in sorted(result.symbol_pr.items(), key=lambda kv: -kv[1])[:20]
        ],
    }


def render_json(result: IndexResult) -> str:
    return json.dumps(to_dict(result), ensure_ascii=False, indent=2)
