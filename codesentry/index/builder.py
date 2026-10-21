"""索引层编排：扫描 → 解析 → 符号解析 → PageRank → 入口点。

这是两个场景共用的地基（v0.2 M0）：
  - 场景 A（理解）用它决定"我要读什么"
  - 场景 B（审查）用它决定"改这里会波及什么"
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from codesentry.core.policy import Policy
from codesentry.core.symbol import CallSite, FileMeta, Symbol
from codesentry.index.discovery import classify, discover
from codesentry.index.entrypoint import EntryPoint, detect as detect_entrypoints
from codesentry.index.pagerank import pagerank
from codesentry.index.resolver import ResolvedCall, SymbolResolver
from codesentry.index.roles import RoleLabel, RoleTagger
from codesentry.parsers import BUILTIN_NAMES, TEST_HELPERS, Parser

BUILTIN_SET = set(BUILTIN_NAMES)
TEST_HELPER_SET = set(TEST_HELPERS)


@dataclass
class IndexResult:
    """一次索引的完整结果。"""

    root: str
    files: list[FileMeta] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    edges: list[ResolvedCall] = field(default_factory=list)
    file_pr: dict[str, float] = field(default_factory=dict)
    symbol_pr: dict[str, float] = field(default_factory=dict)
    out_degree: dict[str, int] = field(default_factory=dict)
    in_degree: dict[str, int] = field(default_factory=dict)
    reverse_refs: dict[str, set[str]] = field(default_factory=dict)
    entrypoints: list[EntryPoint] = field(default_factory=list)
    script_entrypoints: list[EntryPoint] = field(default_factory=list)
    roles: dict[str, RoleLabel] = field(default_factory=dict)
    call_stats: dict[str, int] = field(default_factory=dict)
    timings: dict[str, float] = field(default_factory=dict)
    parse_failures: int = 0

    @property
    def production_files(self) -> set[str]:
        return {f.path for f in self.files if f.is_production}

    def symbols_of(self, rel_path: str) -> list[Symbol]:
        return [s for s in self.symbols if s.file == rel_path]

    def top_files(self, n: int = 20) -> list[tuple[str, float]]:
        return sorted(self.file_pr.items(), key=lambda kv: -kv[1])[:n]


class IndexBuilder:
    """构建索引。"""

    def __init__(self, root: Path, policy: Policy):
        self.root = root.resolve()
        self.policy = policy
        self.tagger = RoleTagger(policy.index.roles)

    def build(self, verbose: bool = False) -> IndexResult:
        cfg = self.policy.index.exclude
        result = IndexResult(root=str(self.root))

        # ---- 1. 发现 ----
        t0 = time.perf_counter()
        found = discover(self.root, cfg)
        result.timings["discover"] = time.perf_counter() - t0

        # ---- 2. 解析 ----
        t0 = time.perf_counter()
        symbols: list[Symbol] = []
        calls: list[CallSite] = []
        metas: dict[str, FileMeta] = {}
        contents: dict[str, str] = {}
        imports_by_file: dict[str, dict[str, set[str]]] = {}
        imported_names: set[str] = set()

        with Parser(self.root) as parser:
            for abs_path, rel, suffix in found:
                is_data, not_parsed, is_script, is_test = classify(rel, cfg)
                if not_parsed:
                    continue
                try:
                    text = abs_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                contents[rel] = text

                try:
                    syms, cs, meta, imps = parser.parse_with_meta(
                        abs_path, rel, text, suffix)
                except Exception:
                    result.parse_failures += 1
                    continue

                meta.is_test = is_test
                meta.is_script = is_script
                meta.is_data = is_data
                metas[rel] = meta
                result.files.append(meta)

                # 符号继承所属文件的测试/脚本标记
                for s in syms:
                    s.is_test = is_test
                    s.is_script = is_script
                symbols.extend(syms)
                calls.extend(cs)
                imports_by_file[rel] = imps
                for names in imps.values():
                    imported_names |= names

        result.timings["parse"] = time.perf_counter() - t0
        result.symbols = symbols

        result.timings["imports"] = time.perf_counter() - t0

        # ---- 3. 符号解析 ----
        t0 = time.perf_counter()
        resolver = SymbolResolver()
        resolver.build(symbols, imports_by_file, imported_names)
        edges = resolver.resolve_all(calls, BUILTIN_SET, TEST_HELPER_SET)
        result.edges = edges
        result.timings["resolve"] = time.perf_counter() - t0

        stats: dict[str, int] = {}
        for e in edges:
            stats[e.resolution] = stats.get(e.resolution, 0) + 1
        result.call_stats = stats

        # ---- 4. 文件级依赖图与 PageRank ----
        t0 = time.perf_counter()
        prod = result.production_files
        file_edges: list[tuple[str, str]] = []
        out_degree: dict[str, int] = {}
        in_degree: dict[str, int] = {}
        reverse_refs: dict[str, set[str]] = {}

        for e in edges:
            if e.resolution not in ("local", "cross_file") or not e.target:
                continue
            src_file = resolver.qname_to_file.get(e.source or "", e.file)
            dst_file = resolver.qname_to_file.get(e.target, "")
            if not dst_file or src_file == dst_file:
                continue
            if src_file not in prod or dst_file not in prod:
                continue
            file_edges.append((src_file, dst_file))
            out_degree[src_file] = out_degree.get(src_file, 0) + 1
            in_degree[dst_file] = in_degree.get(dst_file, 0) + 1
            reverse_refs.setdefault(dst_file, set()).add(src_file)

        result.out_degree = out_degree
        result.in_degree = in_degree
        result.reverse_refs = reverse_refs

        pr = pagerank(
            sorted(prod), file_edges,
            alpha=self.policy.index.pagerank_alpha,
            max_iter=self.policy.index.pagerank_max_iter,
            tol=self.policy.index.pagerank_tol,
        )
        result.file_pr = pr
        result.timings["pagerank"] = time.perf_counter() - t0

        # ---- 5. 符号级 PageRank ----
        # 只在生产文件之间计算：测试文件之间的调用不应抬高测试符号的
        # 架构地位（实测否则 Top10 会被 tests/ 里的 cand/tokenize 霸占）。
        t0 = time.perf_counter()
        prod_qnames = {
            s.qname for s in symbols
            if resolver.qname_to_file.get(s.qname) in prod
        }
        sym_nodes = [s.qname for s in symbols if s.qname in prod_qnames]
        sym_edges = [
            (e.source, e.target)
            for e in edges
            if e.resolution in ("local", "cross_file")
            and e.source and e.target
            and e.source in prod_qnames and e.target in prod_qnames
        ]
        result.symbol_pr = pagerank(
            sym_nodes, sym_edges,
            alpha=self.policy.index.pagerank_alpha,
            max_iter=self.policy.index.pagerank_max_iter,
            tol=self.policy.index.pagerank_tol,
        )
        result.timings["symbol_pagerank"] = time.perf_counter() - t0

        # ---- 6. 入口点 ----
        t0 = time.perf_counter()
        apps, scripts = detect_entrypoints(
            metas, contents, out_degree, in_degree, prod)
        result.entrypoints = apps
        result.script_entrypoints = scripts
        result.timings["entrypoints"] = time.perf_counter() - t0

        # ---- 7. 角色标签 ----
        t0 = time.perf_counter()
        for rel, meta in metas.items():
            if not meta.is_production:
                continue
            result.roles[rel] = self.tagger.tag(rel, contents.get(rel, ""))
        result.timings["roles"] = time.perf_counter() - t0

        if verbose:
            self._print_summary(result)
        return result

    # ---------- 辅助 ----------

    @staticmethod
    def _print_summary(r: IndexResult) -> None:
        print(f"文件 {len(r.files)} · 符号 {len(r.symbols)} · 边 {len(r.edges)}")
        print("调用分类:", r.call_stats)
        print("耗时:", {k: round(v, 3) for k, v in r.timings.items()})


def build_index(root: Path, policy: Policy, verbose: bool = False) -> IndexResult:
    """便捷入口。"""
    return IndexBuilder(root, policy).build(verbose=verbose)
