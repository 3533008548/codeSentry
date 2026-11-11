"""索引层编排：扫描 → 解析 → 符号解析 → PageRank → 入口点。

这是两个场景共用的地基（v0.2 M0）：
  - 场景 A（理解）用它决定"我要读什么"
  - 场景 B（审查）用它决定"改这里会波及什么"
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tokenize
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from codesentry.core.policy import Policy
from codesentry.access import AccessPolicy
from codesentry.environment import get_toolchain, inspect_environment
from codesentry.core.symbol import CallSite, FileMeta, Language, Symbol
from codesentry.index.cache import (
    FileCacheEntry,
    ParseCache,
    hash_content,
)
from codesentry.index.discovery import classify, discover
from codesentry.index.entrypoint import EntryPoint, detect as detect_entrypoints
from codesentry.index.startup import collect_startup_inputs
from codesentry.index.pagerank import pagerank
from codesentry.index.resolver import ResolvedCall, SymbolResolver
from codesentry.index.roles import RoleLabel, RoleTagger
from codesentry.parsers import BUILTIN_NAMES, TEST_HELPERS, Parser

BUILTIN_SET = set(BUILTIN_NAMES)
TEST_HELPER_SET = set(TEST_HELPERS)


@dataclass(frozen=True)
class SourceLimits:
    file_bytes: int = 8 * 1024 * 1024
    total_bytes: int = 64 * 1024 * 1024
    files: int = 10000

    def __post_init__(self):
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in asdict(self).values()):
            raise ValueError('源码读取限额必须为正整数')


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
    environment: dict = field(default_factory=dict)
    environment_fingerprint: str = ''
    parse_issues: list[dict] = field(default_factory=list)
    is_complete: bool = True
    input_fingerprint: str = ''
    import_records: list[dict] = field(default_factory=list)
    access_fingerprint: str = ''
    access_policy: dict = field(default_factory=dict)
    source_permissions: dict[str, str] = field(default_factory=dict)
    provenance: dict = field(default_factory=dict)
    startup_inputs: dict[str, str] = field(default_factory=dict)
    entry_evidence_issues: list[dict] = field(default_factory=list)

    @property
    def production_files(self) -> set[str]:
        return {f.path for f in self.files if f.is_production}

    def symbols_of(self, rel_path: str) -> list[Symbol]:
        return [s for s in self.symbols if s.file == rel_path]

    def top_files(self, n: int = 20) -> list[tuple[str, float]]:
        return sorted(self.file_pr.items(), key=lambda kv: -kv[1])[:n]


class IndexBuilder:
    """构建索引。"""

    def __init__(self, root: Path, policy: Policy, limits: SourceLimits | None = None, *, access: AccessPolicy | None = None):
        self.root = root.resolve()
        self.policy = policy
        self.tagger = RoleTagger(policy.index.roles)
        self.limits = limits or SourceLimits()
        self.access = access or AccessPolicy(self.root)
        if self.access.root != self.root or not self.access.confirmed:
            raise ValueError('当前项目文件访问范围尚未确认或不匹配')

    def build(
        self,
        verbose: bool = False,
        use_cache: bool | None = None,
        refresh: bool = False,
    ) -> IndexResult:
        if not self.root.is_dir():
            raise ValueError(f'项目目录不存在或不是目录: {self.root}')
        cfg = self.policy.index.exclude
        result = IndexResult(root=str(self.root))
        self.access.refresh()
        initial_access = self.access.fingerprint
        result.access_fingerprint = initial_access
        result.access_policy = self.access.to_dict()
        result.parse_issues.extend(result.access_policy['issues'])
        startup_snapshot = collect_startup_inputs(self.access, exclude=cfg)
        result.startup_inputs = dict(startup_snapshot.hashes)
        t0 = time.perf_counter()
        toolchain = get_toolchain(self.root)
        profile = inspect_environment(self.root, toolchain=toolchain, access=self.access)
        result.environment = profile.to_dict()
        result.environment['analysis_limits'] = asdict(self.limits)
        result.environment_fingerprint = profile.fingerprint
        result.timings['environment'] = time.perf_counter() - t0

        t0 = time.perf_counter()
        found = discover(self.root, cfg, issues=result.parse_issues, access=self.access)
        if self.access.settings['exclude'] or any(value == 'unread:access-policy' for value in profile.configuration_files.values()):
            result.parse_issues.append({'file': '.', 'status': 'access_scope_limited', 'message': '部分源码或环境声明受文件访问范围限制'})
        result.timings['discover'] = time.perf_counter() - t0
        if not found:
            result.parse_issues.append({'file': '.', 'status': 'no_sources',
                                       'message': '声明范围内没有支持的源文件'})

        cache_enabled = self.policy.index.cache_enabled if use_cache is None else use_cache
        implementation = {}
        package_root = Path(__file__).resolve().parents[1]
        for name in ['parsers/python_parser.py', 'parsers/ts_parser.py',
                     'parsers/_ts_extract.js', 'parsers/__init__.py', 'core/symbol.py']:
            implementation[name] = hashlib.sha256((package_root / name).read_bytes()).hexdigest()
        parse_context = hashlib.sha256(json.dumps({
            'python': list(sys.version_info[:3]), 'toolchain': toolchain.fingerprint,
            'implementation': implementation,
            'access_fingerprint': initial_access,
        }, sort_keys=True).encode()).hexdigest()
        cache = ParseCache(self.root, enabled=cache_enabled, context=parse_context, access=self.access)
        if refresh and cache_enabled:
            cache.clear()
        cache.load()

        t0 = time.perf_counter()
        symbols: list[Symbol] = []
        calls: list[CallSite] = []
        metas: dict[str, FileMeta] = {}
        contents: dict[str, str] = {}
        source_hashes: dict[str, str] = {}
        imports_by_file: dict[str, dict[str, set[str]]] = {}
        import_kinds_by_file: dict[str, dict[str, str]] = {}
        imported_names: set[str] = set()
        alive_paths: set[str] = set()

        total_read = 0
        with Parser(self.root, toolchain=toolchain) as parser:
            for file_number, (abs_path, rel, suffix) in enumerate(found):
                is_data, not_parsed, is_script, is_test = classify(rel, cfg)
                if not_parsed:
                    continue
                alive_paths.add(rel)
                language = Language.PYTHON if suffix == '.py' else Language.TYPESCRIPT
                syms, cs, imps = [], [], {}
                meta = FileMeta(path=rel, language=language, is_parsed=False)
                text = ''
                try:
                    if file_number >= self.limits.files:
                        raise ValueError('source_file_count_limit')
                    allowance = min(self.limits.file_bytes, self.limits.total_bytes - total_read)
                    if allowance <= 0:
                        raise ValueError('source_total_byte_limit')
                    if abs_path.stat().st_size > allowance:
                        raise ValueError('source_byte_limit')
                    raw = self.access.read_bytes(rel, limit=allowance)
                    total_read += len(raw)
                    if len(raw) > allowance:
                        raise ValueError('source_byte_limit')
                    source_hashes[rel] = hashlib.sha256(raw).hexdigest()
                    if suffix == '.py':
                        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                    else:
                        encoding = 'utf-8-sig'
                    text = raw.decode(encoding)
                    contents[rel] = text
                    content_hash = hash_content(text)
                    entry = cache.get(rel, content_hash)
                    if entry is not None and entry.meta.get('is_parsed', True):
                        syms = [item.model_copy(deep=True) for item in entry.symbols]
                        cs = [item.model_copy(deep=True) for item in entry.calls]
                        imps = {k: set(v) for k, v in entry.imports.items()}
                        meta = FileMeta.model_validate(entry.meta)
                    else:
                        warning_count = len(parser.warnings)
                        syms, cs, meta, imps = parser.parse_with_meta(abs_path, rel, text, suffix)
                        if meta.language == Language.UNKNOWN:
                            meta.is_parsed = False
                        if meta.is_parsed:
                            cache.put(FileCacheEntry(
                                path=rel, content_hash=content_hash,
                                mtime=abs_path.stat().st_mtime,
                                symbols=syms, calls=cs,
                                imports={k: sorted(v) for k, v in imps.items()},
                                meta=meta.model_dump(),
                            ))
                        else:
                            reason = meta.parse_error or '; '.join(parser.warnings[warning_count:]) or '解析器拒绝该语法或工具链不可用'
                            result.parse_issues.append({'file': rel, 'status': 'parse_failed', 'message': reason})
                    meta.content_hash = content_hash
                    meta.lines = len(text.splitlines())
                except (OSError, UnicodeError, SyntaxError, LookupError, RuntimeError, ValueError) as exc:
                    meta.is_parsed = False
                    result.parse_issues.append({'file': rel, 'status': 'read_or_parse_failed',
                                               'message': str(exc)[:500]})
                if not meta.is_parsed:
                    result.parse_failures += 1
                    syms, cs, imps = [], [], {}
                meta.is_test, meta.is_script, meta.is_data = is_test, is_script, is_data
                meta.participates_in_ranking = not is_script
                metas[rel] = meta
                result.files.append(meta)
                result.source_permissions[rel] = self.access.decision(rel)['mode']
                for symbol in syms:
                    symbol.is_test, symbol.is_script = is_test, is_script
                symbols.extend(syms)
                calls.extend(cs)
                imports_by_file[rel] = imps
                import_kinds_by_file[rel] = meta.import_kinds
                for names in imps.values():
                    imported_names |= names

        result.timings['parse'] = time.perf_counter() - t0
        result.symbols = symbols
        cache.prune(alive_paths)
        result.cache_stats = cache.stats
        cache.save()
        result.timings['imports'] = 0.0

        # ---- 3. 符号解析 ----
        t0 = time.perf_counter()
        resolver = SymbolResolver()
        resolver.build(symbols, imports_by_file, imported_names, list(metas),
                       import_kinds_by_file=import_kinds_by_file)
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
            if not e.is_certain:
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
        result.import_records = resolver.import_records
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
            if e.is_certain
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
            metas, contents, out_degree, in_degree, prod,
            root=self.root, access=self.access, calls=calls,
            startup_snapshot=startup_snapshot, issues=result.entry_evidence_issues,
            exclude_config=cfg)
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

        # Never certify a mixed snapshot. Re-read hashes and discovery after analysis.
        t0 = time.perf_counter()
        self.access.refresh()
        current = {rel: path for path, rel, _ in discover(self.root, cfg, issues=result.parse_issues, access=self.access)}
        if set(current) != set(alive_paths):
            result.parse_issues.append({'file': '.', 'status': 'source_set_changed',
                                       'message': '扫描期间源文件集合发生变化'})
        verify_remaining = self.limits.total_bytes
        for rel, expected in source_hashes.items():
            if verify_remaining <= 0:
                result.parse_issues.append({'file': rel, 'status': 'snapshot_validation_limit',
                                           'message': '源码复查预算耗尽，需要重试'})
                break
            allowance = min(self.limits.file_bytes, verify_remaining)
            try:
                verification = self.access.read_bytes(rel, limit=allowance)
                verify_remaining -= len(verification)
                actual = hashlib.sha256(verification).hexdigest() if len(verification) <= allowance else ''
            except (OSError, ValueError):
                actual = ''
            if actual != expected:
                result.parse_issues.append({'file': rel, 'status': 'source_changed',
                                           'message': '扫描期间源码发生变化，需要重试'})
        final_profile = inspect_environment(self.root, toolchain=toolchain, access=self.access)
        if final_profile.fingerprint != profile.fingerprint:
            result.parse_issues.append({'file': '.', 'status': 'configuration_changed',
                                       'message': '扫描期间环境声明或配置发生变化'})
        final_startup = collect_startup_inputs(self.access, exclude=cfg)
        if final_startup.hashes != startup_snapshot.hashes:
            result.entrypoints = []
            result.script_entrypoints = []
            result.parse_issues.append({'file': '.', 'status': 'startup_configuration_changed',
                                       'message': '分析期间启动声明变化，旧入口证据已丢弃，请重新分析'})
        result.is_complete = not result.parse_issues and result.parse_failures == 0
        if self.access.fingerprint != initial_access:
            # A result built before a revocation cannot retain even its old
            # paths, symbols or environment-derived declarations.
            cache.entries.clear()
            if cache.cache_file.exists():
                cache.cache_file.unlink()
            result = IndexResult(root=str(self.root), is_complete=False,
                                 access_fingerprint=self.access.fingerprint,
                                 access_policy=self.access.to_dict(),
                                 parse_issues=[{'file': '.', 'status': 'access_policy_changed',
                                                'message': '分析期间访问权限变化，旧结果已丢弃，请重新分析'}])
            return result
        result.provenance = {'access_fingerprint': initial_access,
                             'sources': dict(result.source_permissions),
                             # The whole index includes local environment and
                             # structure facts. Eligible model views must be
                             # rebuilt from their own sources, not this object.
                             'derived_mode': 'local_only',
                             'model_authorized': False}
        index_implementation = dict(implementation)
        for name in ['core/policy.py', 'index/builder.py', 'index/cache.py',
                     'index/discovery.py', 'index/entrypoint.py', 'index/resolver.py',
                     'index/startup.py',
                     'index/roles.py', 'index/pagerank.py', 'output/reading_order.py',
                     'environment/inspect.py', 'environment/toolchain.py']:
            index_implementation[name] = hashlib.sha256((package_root / name).read_bytes()).hexdigest()
        result.input_fingerprint = hashlib.sha256(json.dumps({
            'sources': source_hashes, 'environment': profile.fingerprint,
            'startup_inputs': startup_snapshot.hashes,
            'implementation': index_implementation, 'limits': asdict(self.limits),
            'policy': self.policy.model_dump(mode='json'),
            'access_fingerprint': initial_access,
        }, sort_keys=True).encode()).hexdigest()
        result.timings['validate_snapshot'] = time.perf_counter() - t0

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
    limits: SourceLimits | None = None,
    access: AccessPolicy | None = None,
) -> IndexResult:
    """便捷入口。"""
    return IndexBuilder(root, policy, limits=limits, access=access).build(
        verbose=verbose, use_cache=use_cache, refresh=refresh)
