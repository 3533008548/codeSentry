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

        for s in symbols:
            self.defs_by_file[s.file].add(s.name)
            self.qname_to_file[s.qname] = s.file
            self.name_to_files[s.name].append(s.file)

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
