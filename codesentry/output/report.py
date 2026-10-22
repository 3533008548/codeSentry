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


def render_l1(result: IndexResult) -> str:
    """L1 · 定位输出。"""
    lines: list[str] = []
    files = result.files
    prod = [f for f in files if f.is_production]
    test_files = [f for f in files if f.is_test]

    lines.append("=" * 68)
    lines.append("L1 · 定位")
    lines.append("=" * 68)

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
    lines.append("应用入口:")
    for e in result.entrypoints:
        lines.append(f"  {e.file:<44} {e.reason}")
    if result.script_entrypoints:
        lines.append(f"脚本入口: {len(result.script_entrypoints)} 个（折叠不列）")

    # 调用解析统计
    if result.call_stats:
        total = sum(result.call_stats.values())
        resolved = result.call_stats.get("local", 0) + \
            result.call_stats.get("cross_file", 0)
        lines.append("")
        lines.append(
            f"解析    项目内 {resolved:,}/{total:,} "
            f"({resolved / total * 100:.1f}%)")

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
        "files": len(result.files),
        "symbols": len(result.symbols),
        "edges": len(result.edges),
        "timings": {k: round(v, 4) for k, v in result.timings.items()},
        "call_stats": result.call_stats,
        "entrypoints": [
            {"file": e.file, "reason": e.reason, "out_degree": e.out_degree,
             "in_degree": e.in_degree}
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
