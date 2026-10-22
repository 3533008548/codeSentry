"""符号解析：把被调用的裸名定位到具体定义。

这是索引层的核心难点。v0.2 实测记录的纯 AST 天花板：

  Python 侧 unresolved 12.8%
    - 约 1,084 条是标准库的**类方法**（datetime.now() 的 now、
      sqlite3.commit() 的 commit）—— ast 看不到类的方法
    - 约 256 条是**同名多定义歧义**（create 29 次、start 21 次）
  TypeScript 侧 unresolved 6.9%（import 语法更规整）

解析策略（按优先级）：
  1. 本文件定义           → local
  2. import 路径精确匹配  → cross_file（最可靠）
  3. import 路径模糊匹配  → cross_file
  4. 全项目唯一定义       → cross_file
  5. 多候选 / 无候选      → ambiguous / unresolved
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from codesentry.core.symbol import CallSite, Symbol


@dataclass
class ResolvedCall:
    """一条解析后的调用。"""

    source: str | None          # 调用方限定名
    target_name: str            # 被调名
    target: str | None          # 被调方限定名（解析成功时）
    file: str
    line: int
    resolution: str             # local/cross_file/external/builtin/...

    @property
    def is_internal(self) -> bool:
        return self.target is not None


@dataclass
class SymbolResolver:
    """跨文件符号解析器。

    依赖全局信息（本文件所有定义 + import 表），所以只能在索引层做。
    """

    defs_by_file: dict[str, set[str]] = field(default_factory=dict)
    imports_by_file: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    imported_names: set[str] = field(default_factory=set)
    name_to_files: dict[str, list[str]] = field(default_factory=dict)
    qname_to_file: dict[str, str] = field(default_factory=dict)
    external_names: set[str] = field(default_factory=set)
    builtin_names: set[str] = field(default_factory=set)
    test_helper_names: set[str] = field(default_factory=set)

    def build(
        self,
        symbols: list[Symbol],
        imports_by_file: dict[str, dict[str, set[str]]],
        imported_names: set[str],
    ) -> None:
        """用解析结果初始化索引。"""
        self.defs_by_file = defaultdict(set)
        self.imports_by_file = imports_by_file
        self.imported_names = imported_names
        self.name_to_files = defaultdict(list)
        self.qname_to_file = {}
        self._all_files: list[str] = []

        for s in symbols:
            self.defs_by_file[s.file].add(s.name)
            self.qname_to_file[s.qname] = s.file
            self.name_to_files[s.name].append(s.file)
            if s.file not in self._all_files:
                self._all_files.append(s.file)

    # ---------- 解析 ----------

    def resolve(self, callee: str, caller_file: str) -> tuple[str | None, str]:
        """解析一个被调名。

        Returns:
            (目标限定名或 None, 解析方式)
        """
        # 1. 本文件定义
        if callee in self.defs_by_file.get(caller_file, ()):
            return self._qname_in(caller_file, callee), "local"

        # 2. import 精确匹配
        target = self._match_import(caller_file, callee)
        if target:
            return target, "cross_file"

        # 3. 全项目唯一定义
        cands = self.name_to_files.get(callee, [])
        if len(cands) == 1:
            return self._qname_in(cands[0], callee), "cross_file"

        if len(cands) > 1:
            # 歧义：尝试用调用者所在目录消歧
            guess = self._disambiguate(callee, caller_file, cands)
            if guess:
                return guess, "cross_file"
            return None, "ambiguous"

        return None, "unresolved"

    def _qname_in(self, file: str, name: str) -> str:
        """在给定文件里找符号的限定名。

        同名多定义时取第一个（限定名不唯一的情况已由 resolve 处理）。
        """
        return f"{file}::{name}"

    def _match_import(self, caller_file: str, callee: str) -> str | None:
        """用 import 表定位目标文件。"""
        imports = self.imports_by_file.get(caller_file)
        if not imports:
            return None
        for module, names in imports.items():
            if callee not in names:
                continue
            mod_path = module.replace(".", "/").replace("\\", "/")
            cands = self.name_to_files.get(callee, [])
            if not cands:
                continue
            # 精确：路径包含模块路径
            hit = next(
                (f for f in cands if mod_path in f.replace("\\", "/")), None
            )
            if hit:
                return self._qname_in(hit, callee)
            # 模糊：文件名匹配模块 basename
            base = mod_path.split("/")[-1]
            hit = next(
                (f for f in cands
                 if f.replace("\\", "/").split("/")[-1] == f"{base}.py"
                 or f.replace("\\", "/").split("/")[-1] == f"{base}.ts"
                 or f.replace("\\", "/").split("/")[-1] == f"{base}.tsx"),
                None,
            )
            if hit:
                return self._qname_in(hit, callee)
        return None

    def _disambiguate(
        self, callee: str, caller_file: str, cands: list[str]
    ) -> str | None:
        """同名多定义时的启发式消歧。

        规则：同目录优先 > 同顶层目录优先。
        """
        caller_parts = caller_file.replace("\\", "/").split("/")
        caller_dir = "/".join(caller_parts[:-1])

        # 同目录
        for f in cands:
            if f.replace("\\", "/").rsplit("/", 1)[0] == caller_dir:
                return self._qname_in(f, callee)

        # 同顶层目录
        if len(caller_parts) > 1:
            top = caller_parts[0]
            for f in cands:
                if f.replace("\\", "/").split("/")[0] == top:
                    return self._qname_in(f, callee)
        return None

    # ---------- import 边（文件级）----------

    def resolve_import_edges(self) -> list[tuple[str, str]]:
        """从 import 表建立文件级依赖边。

        **为什么必须单独建 import 边**：调用图和依赖图是两回事。
        接口文件、类型契约、常量模块只有 import 关系、没有任何函数调用，
        在调用图里是孤立点。实测 Knowledge Loop 的 5 个核心文件
        （knowledge-repository.ts / desktop-api.ts / json-post.ts /
        fetch-api-request.ts / preload.ts）在调用图里入度出度全为 0，
        全部漏出阅读顺序。

        解析规则：
          1. 相对路径（../core/x）→ 按调用方目录求绝对项目路径
          2. 绝对模块路径（core.x）→ 点号转斜杠
          3. 从导入符号名反推定义所在文件
        """
        import posixpath

        edges: list[tuple[str, str]] = []
        for caller_file, imports in self.imports_by_file.items():
            caller_dir = posixpath.dirname(caller_file)
            for module, names in imports.items():
                if module.startswith("node:") or module.startswith("electron"):
                    continue
                if not names:
                    continue

                # 1. 相对路径 → 绝对项目路径
                if module.startswith("."):
                    target_path = posixpath.normpath(
                        posixpath.join(caller_dir, module))
                else:
                    target_path = module.replace(".", "/")

                cands = self.name_to_files.get(module) or []
                # 先按路径匹配
                hit = next(
                    (f for f in self._all_files
                     if f.replace("\\", "/") == target_path
                     or f.replace("\\", "/").startswith(target_path + "/")),
                    None)
                if hit is None:
                    # 再按符号名反推：找到定义了这些名字的文件
                    by_name = set()
                    for n in names:
                        by_name.update(self.name_to_files.get(n, []))
                    cands = list(by_name)
                    if not cands:
                        continue
                    # 优先选路径能对上的
                    hit = next(
                        (f for f in cands
                         if f.replace("\\", "/").startswith(target_path)), None)
                    if hit is None:
                        # 其次选同目录
                        hit = next(
                            (f for f in cands
                             if posixpath.dirname(f.replace("\\", "/")) == caller_dir),
                            None)
                    if hit is None and len(cands) == 1:
                        hit = cands[0]
                    if hit is None:
                        continue
                if hit != caller_file:
                    edges.append((caller_file, hit))
        return edges

    # ---------- 批量解析 ----------

    def resolve_all(
        self,
        calls: list[CallSite],
        builtin_names: set[str],
        test_helper_names: set[str],
    ) -> list[ResolvedCall]:
        """批量解析调用点并分类。"""
        self.builtin_names = builtin_names
        self.test_helper_names = test_helper_names

        out: list[ResolvedCall] = []
        for c in calls:
            callee = c.callee_name
            caller_file = c.file

            if callee in test_helper_names:
                res, kind = None, "test_helper"
            elif callee in builtin_names:
                res, kind = None, "builtin"
            elif c.caller_qname is None:
                res, kind = None, "module_level"
            else:
                res, kind = self.resolve(callee, caller_file)

            out.append(ResolvedCall(
                source=c.caller_qname,
                target_name=callee,
                target=res,
                file=c.file,
                line=c.line,
                resolution=kind,
            ))
        return out
