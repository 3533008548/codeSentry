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
from codesentry.index.cache import (
    FileCacheEntry,
    ParseCache,
    hash_content,
)
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
    # 正向依赖：这个文件依赖了哪些文件（阅读顺序沿此边 BFS）
    dependencies: dict[str, set[str]] = field(default_factory=dict)
    # 反向依赖：哪些文件依赖了它（影响面分析沿此边）
    dependents: dict[str, set[str]] = field(default_factory=dict)
    # import 边数量（只用于阅读顺序/影响面，不进 PageRank）
    import_edge_count: int = 0
    entrypoints: list[EntryPoint] = field(default_factory=list)
    script_entrypoints: list[EntryPoint] = field(default_factory=list)
    roles: dict[str, RoleLabel] = field(default_factory=dict)
    call_stats: dict[str, int] = field(default_factory=dict)
    cache_stats: dict[str, float] = field(default_factory=dict)
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

    def build(
        self,
        verbose: bool = False,
        use_cache: bool | None = None,
        refresh: bool = False,
    ) -> IndexResult:
        cfg = self.policy.index.exclude
        result = IndexResult(root=str(self.root))

        # ---- 1. 发现 ----
        t0 = time.perf_counter()
        found = discover(self.root, cfg)
        result.timings["discover"] = time.perf_counter() - t0

        # ---- 缓存准备 ----
        cache_enabled = (
            self.policy.index.cache_enabled
            if use_cache is None else use_cache
        )
        cache = ParseCache(self.root, enabled=cache_enabled)
        if refresh:
            cache.clear()
        cache.load()

        # ---- 2. 解析（唯一走缓存的阶段）----
        # 增量失效（v0.2 §4.5）：内容哈希未变的文件跳过解析。
        # **只有 parse 走缓存**，符号解析 / PageRank / 入口点每次全量重算
        # ——实测这些加起来不到 0.1 s，而局部近似的排序质量代价很大。
        t0 = time.perf_counter()
        symbols: list[Symbol] = []
        calls: list[CallSite] = []
        metas: dict[str, FileMeta] = {}
        contents: dict[str, str] = {}
        imports_by_file: dict[str, dict[str, set[str]]] = {}
        imported_names: set[str] = set()
        alive_paths: set[str] = set()

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
                alive_paths.add(rel)

                content_hash = hash_content(text)
                entry = cache.get(rel, content_hash)

                if entry is not None:
                    # 缓存命中：复用解析结果
                    syms = list(entry.symbols)
                    cs = list(entry.calls)
                    imps = {k: set(v) for k, v in entry.imports.items()}
                    meta = FileMeta.model_validate(entry.meta)
                else:
                    try:
                        syms, cs, meta, imps = parser.parse_with_meta(
                            abs_path, rel, text, suffix)
                    except Exception:
                        result.parse_failures += 1
                        continue
                    cache.put(FileCacheEntry(
                        path=rel,
                        content_hash=content_hash,
                        mtime=abs_path.stat().st_mtime
                        if abs_path.exists() else 0.0,
                        symbols=syms,
                        calls=cs,
                        imports={k: sorted(v) for k, v in imps.items()},
                        meta=meta.model_dump(),
                    ))

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
        result.cache_stats = cache.stats

        # 清理已删除文件的缓存条目
        cache.prune(alive_paths)
        cache.save()
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
        # 正向依赖：这个文件依赖了哪些文件（阅读顺序 BFS 沿此边展开）
        dependencies: dict[str, set[str]] = {}
        # 依赖者：哪些文件依赖了它
        dependents: dict[str, set[str]] = {}

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
            dependencies.setdefault(src_file, set()).add(dst_file)
            dependents.setdefault(dst_file, set()).add(src_file)

        result.out_degree = out_degree
        result.in_degree = in_degree
        result.reverse_refs = reverse_refs

        # ---- 4b. import 边（补充调用图覆盖不到的文件）----
        # 调用图和依赖图是两回事：接口文件、类型契约、常量模块只有
        # import 关系没有函数调用，在调用图里是孤立点。
        # 实测 Knowledge Loop 有 5 个核心文件在调用图里入度出度全为 0。
        #
        # **import 边只用于阅读顺序与影响面，不进 PageRank** ——
        # 保持"重要度 = 调用结构中心性"这个语义不变。
        import_edges = resolver.resolve_import_edges()
        for src, dst in import_edges:
            if src not in prod or dst not in prod:
                continue
            dependencies.setdefault(src, set()).add(dst)
            dependents.setdefault(dst, set()).add(src)
        result.import_edge_count = len(import_edges)

        result.dependencies = dependencies
        result.dependents = dependents

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


def build_index(
    root: Path,
    policy: Policy,
    verbose: bool = False,
    use_cache: bool | None = None,
    refresh: bool = False,
) -> IndexResult:
    """便捷入口。"""
    return IndexBuilder(root, policy).build(
        verbose=verbose, use_cache=use_cache, refresh=refresh)
