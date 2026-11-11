"""Python 解析器。

用标准库 `ast`（零依赖，官方精确）。v0.1 决策 1：
各语言用各自最优工具，Python 侧就是 `ast`。

关键设计：
  - 符号主键用限定名 `file::symbol`
  - 调用归属到 AST 词法作用域，装饰器/default 使用外层作用域
  - 产出 CallSite 原始记录，符号解析交给索引层（因为需要全局信息）
"""
from __future__ import annotations

import ast
import builtins
import hashlib
from types import BuiltinFunctionType
from pathlib import Path

from codesentry.core.symbol import (
    CallSite,
    FileMeta,
    Language,
    Symbol,
    SymbolKind,
)

# Only real language builtins, not a global bag of common method names. Site's
# optional help/exit objects are deliberately excluded. Lexical shadowing is
# checked before this list is used; it never proves an arbitrary obj.get().
BUILTIN_NAMES: frozenset[str] = frozenset(
    name for name, value in vars(builtins).items()
    if isinstance(value, (BuiltinFunctionType, type))
)


TEST_HELPERS: frozenset[str] = frozenset({
    "assertEqual", "assertIn", "assertTrue", "assertFalse", "assertRaises",
    "assertIsNone", "assertIsNotNone", "assertAlmostEqual", "assertRegex",
    "assertNotIn", "assertGreater", "assertLess", "assertGreaterEqual",
    "assertLessEqual", "assertCountEqual", "assertDictEqual",
    "assertListEqual", "assertSetEqual", "assertTupleEqual",
    "assertMultiLineEqual", "assertSequenceEqual", "assertNotEqual",
    "fail", "skip", "skipTest", "subTest", "setUp", "tearDown",
    "setUpClass", "tearDownClass", "expectedFailure",
})


class PythonParser:
    """把一个 .py 文件解析成符号 + 调用点。"""

    language = Language.PYTHON
    DEFAULT_MAX_AST_NODES = 200_000
    DEFAULT_MAX_AST_DEPTH = 200

    def __init__(
        self, *, max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
        max_ast_depth: int = DEFAULT_MAX_AST_DEPTH,
    ):
        # These are soft analysis limits, not an OS CPU/memory/time sandbox.
        # ast.parse still constructs a tree before the iterative check can run.
        for name, value in (("max_ast_nodes", max_ast_nodes), ("max_ast_depth", max_ast_depth)):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.max_ast_nodes = max_ast_nodes
        self.max_ast_depth = max_ast_depth

    def _ast_limit_error(self, tree: ast.AST) -> str | None:
        """Bound recursive analysis with an iterative, depth-bounded walk."""
        count = 1
        stack = [(iter(ast.iter_child_nodes(tree)), 1)]
        while stack:
            children, parent_depth = stack[-1]
            try:
                child = next(children)
            except StopIteration:
                stack.pop()
                continue
            count += 1
            depth = parent_depth + 1
            if count > self.max_ast_nodes:
                return f"python_ast_resource_limit: nodes>{self.max_ast_nodes}"
            if depth > self.max_ast_depth:
                return f"python_ast_resource_limit: depth>{self.max_ast_depth}"
            stack.append((iter(ast.iter_child_nodes(child)), depth))
        return None

    def parse(self, path: Path, rel_path: str) -> tuple[list[Symbol], list[CallSite]]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], []
        symbols, calls, _, _ = self.parse_with_meta(path, rel_path, source)
        return symbols, calls

    def _analyze(
        self, tree: ast.AST, rel_path: str
    ) -> tuple[list[Symbol], list[CallSite], dict[str, set[str]], dict[str, str]]:
        """Extract static bindings without claiming that their calls execute."""
        definitions = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        symbols: list[Symbol] = []
        node_symbols: dict[ast.AST, Symbol] = {}
        scope_parent: dict[ast.AST, ast.AST | None] = {tree: None}
        bindings: dict[ast.AST, dict[str, list[tuple[str, str, str]]]] = {}
        declaration_lines: dict[ast.AST, dict[str, int]] = {}
        imports: dict[str, set[str]] = {}
        import_kinds: dict[str, str] = {}
        node_kinds: dict[ast.AST, str] = {}
        star_scopes: set[ast.AST] = set()

        def direct_nodes(scope: ast.AST):
            def walk(node: ast.AST):
                yield node
                if isinstance(node, definitions):
                    # Defaults/decorators are evaluated in the enclosing scope,
                    # including any assignment expressions in their inputs.
                    for key, value in ast.iter_fields(node):
                        if key == "body":
                            continue
                        values = value if isinstance(value, list) else [value]
                        for child in values:
                            if isinstance(child, ast.AST):
                                yield from walk(child)
                    return
                if isinstance(node, ast.Lambda):
                    for value in [*node.args.defaults, *[v for v in node.args.kw_defaults if v]]:
                        yield from walk(value)
                    return
                for child in ast.iter_child_nodes(node):
                    yield from walk(child)
            body = getattr(scope, "body", [])
            for child in body if isinstance(body, list) else [body]:
                if isinstance(child, ast.AST):
                    yield from walk(child)

        def collect(scope: ast.AST, parent: Symbol | None = None):
            nodes = list(direct_nodes(scope))
            defs = [n for n in nodes if isinstance(n, definitions)]
            counts: dict[str, int] = {}
            for node in defs:
                counts[node.name] = counts.get(node.name, 0) + 1
            seen: dict[str, int] = {}
            table: dict[str, list[tuple[str, str, str]]] = {}
            bindings[scope] = table
            last_declarations: dict[str, int] = {}
            declaration_lines[scope] = last_declarations

            def bind(name: str, kind: str, module: str = "", original: str = ""):
                table.setdefault(name, []).append((kind, module, original))

            def declare(name: str, line: int):
                last_declarations[name] = max(last_declarations.get(name, -1), line)

            for node in defs:
                declare(node.name, node.lineno)
                part = node.name
                if counts[part] > 1:
                    digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()[:12]
                    key = part + "~" + digest
                    seen[key] = seen.get(key, 0) + 1
                    part = key + (f"~{seen[key]}" if seen[key] > 1 else "")
                qname = (parent.qname + "." + part) if parent else f"{rel_path}::{part}"
                is_class = isinstance(node, ast.ClassDef)
                symbol = Symbol(
                    qname=qname, name=node.name,
                    kind=(SymbolKind.CLASS if is_class else
                          SymbolKind.METHOD if parent and parent.kind == SymbolKind.CLASS else SymbolKind.FUNCTION),
                    file=rel_path, line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    signature=self._class_signature(node) if is_class else self._func_signature(node),
                    docstring=ast.get_docstring(node), parent=parent.qname if parent else None,
                )
                symbols.append(symbol)
                node_symbols[node] = symbol
                scope_parent[node] = scope
                bind(node.name, "local")

            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                args = scope.args
                for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
                    bind(arg.arg, "shadowed")
                for arg in (args.vararg, args.kwarg):
                    if arg:
                        bind(arg.arg, "shadowed")
            for node in nodes:
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.asname or alias.name.split(".")[0]
                        module = alias.name if alias.asname else alias.name.split(".")[0]
                        declare(name, node.lineno)
                        bind(name, "namespace", module)
                        imports.setdefault(alias.name, set()).add(name)
                elif isinstance(node, ast.ImportFrom):
                    module = "." * node.level + (node.module or "")
                    for alias in node.names:
                        name = alias.asname or alias.name
                        declare(name, node.lineno)
                        bind(name, "symbol", module, alias.name)
                        imports.setdefault(module, set()).add(alias.name)
                        if alias.name == "*":
                            star_scopes.add(scope)
                elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    bind(node.id, "shadowed")
                elif isinstance(node, ast.ExceptHandler) and node.name:
                    bind(node.name, "shadowed")
                elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                    bind(node.name, "shadowed")
                elif isinstance(node, ast.MatchMapping) and node.rest:
                    bind(node.rest, "shadowed")
                elif isinstance(node, (ast.Global, ast.Nonlocal)):
                    for name in node.names:
                        bind(name, "shadowed")

            def typing_guard(test: ast.AST):
                if isinstance(test, ast.Name):
                    root, expected = test.id, ("symbol", "typing", "TYPE_CHECKING")
                elif (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
                      and isinstance(test.value, ast.Name)):
                    root, expected = test.value.id, ("namespace", "typing", "")
                else:
                    return False
                current: ast.AST | None = scope
                while current is not None:
                    candidates = bindings.get(current, {}).get(root, [])
                    if candidates:
                        # The alias must be an unconditional direct import, not a
                        # parameter, reassignment or import inside another branch.
                        direct_import = any(
                            isinstance(stmt, (ast.Import, ast.ImportFrom))
                            and stmt.lineno < test.lineno
                            and any((alias.asname or (alias.name.split(".")[0] if isinstance(stmt, ast.Import) else alias.name)) == root
                                    for alias in stmt.names)
                            for stmt in getattr(current, "body", [])
                        )
                        return candidates == [expected] and direct_import
                    current = scope_parent.get(current)
                    while isinstance(current, ast.ClassDef):
                        current = scope_parent.get(current)
                return False

            def contexts(node: ast.AST, kind: str = "runtime"):
                node_kinds[node] = kind
                if isinstance(node, definitions):
                    for key, value in ast.iter_fields(node):
                        if key == "body":
                            continue
                        values = value if isinstance(value, list) else [value]
                        for child in values:
                            if isinstance(child, ast.AST):
                                contexts(child, kind)
                    return
                if isinstance(node, ast.If):
                    contexts(node.test, kind)
                    branch = "type" if kind == "runtime" and typing_guard(node.test) else (
                        "type" if kind == "type" else "conditional")
                    for child in node.body:
                        contexts(child, branch)
                    for child in node.orelse:
                        contexts(child, "type" if kind == "type" else "conditional")
                    return
                if isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar,
                                     ast.Match, ast.With, ast.AsyncWith)):
                    for child in ast.iter_child_nodes(node):
                        contexts(child, "type" if kind == "type" else "conditional")
                    return
                for child in ast.iter_child_nodes(node):
                    contexts(child, kind)

            for node in getattr(scope, "body", []):
                contexts(node)
            for node in nodes:
                kind = node_kinds.get(node, "unknown")
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else ["." * node.level + (node.module or "")]
                    for module in modules:
                        old = import_kinds.get(module)
                        priority = {"unknown": 0, "type": 1, "conditional": 2, "runtime": 3}
                        if old is None or priority[kind] > priority[old]:
                            import_kinds[module] = kind
                    if kind != "runtime":
                        for alias in node.names:
                            name = alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
                            bind(name, "shadowed")
                if isinstance(node, definitions) and (
                    kind != "runtime" or node.decorator_list
                    or (isinstance(node, ast.ClassDef) and any(k.arg == "metaclass" for k in node.keywords))
                ):
                    bind(node.name, "shadowed")
            for node in defs:
                collect(node, node_symbols[node])

        collect(tree)
        # Explicit global/nonlocal declarations can rebind outer definitions.
        # Conservatively invalidate those outer bindings rather than retaining a
        # false edge merely because the assignment is inside a nested function.
        for scope in list(bindings):
            for node in direct_nodes(scope):
                if not isinstance(node, (ast.Global, ast.Nonlocal)):
                    continue
                for name in node.names:
                    target: ast.AST | None = tree if isinstance(node, ast.Global) else scope_parent.get(scope)
                    if isinstance(node, ast.Nonlocal):
                        while target is not None and (isinstance(target, ast.ClassDef) or name not in bindings.get(target, {})):
                            target = scope_parent.get(target)
                    if target is not None:
                        bindings[target].setdefault(name, []).append(("shadowed", "", ""))
        for node, symbol in node_symbols.items():
            table = bindings[scope_parent[node]]
            symbol.binding_is_static = all(candidate[0] == "local" for candidate in table[node.name])

        calls: list[CallSite] = []

        def binding(root: str, scope: ast.AST, line: int):
            current: ast.AST | None = scope
            while current is not None:
                if isinstance(current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                    return "shadowed", "", "", None
                candidates = bindings.get(current, {}).get(root, [])
                if candidates:
                    # The current execution scope cannot use a later local
                    # definition/import. Outer closures may run after their
                    # declarations, so physical line order does not prove that
                    # those outer bindings are unavailable.
                    check_order = current is scope or (
                        (scope is tree or isinstance(scope, ast.ClassDef))
                        and (current is tree or isinstance(current, ast.ClassDef))
                    )
                    # Existence of a declaration at/after this call is equivalent
                    # to comparing the latest declaration, collected once per
                    # scope. Lambda scopes are created later and have no such
                    # declarations, so their lookup intentionally stays empty.
                    if check_order and declaration_lines.get(current, {}).get(root, -1) >= line:
                        return "shadowed", "", "", None
                    kinds = {candidate[0] for candidate in candidates}
                    if kinds == {"local"}:
                        return "local", "", "", node_symbols[current].qname if current in node_symbols else None
                    if len(candidates) == 1:
                        kind, module, original = candidates[0]
                        return kind, module, original, None
                    return "shadowed", "", "", None
                if current in star_scopes:
                    return "shadowed", "", "", None
                current = scope_parent.get(current)
                while isinstance(current, ast.ClassDef):
                    current = scope_parent.get(current)
            return ("builtin" if root in BUILTIN_NAMES else "unbound"), "", "", None

        def visit(node: ast.AST, scope: ast.AST, type_context: bool = False):
            type_context = type_context or node_kinds.get(node) == "type"
            if isinstance(node, definitions):
                for key, value in ast.iter_fields(node):
                    if key == "body":
                        for child in value:
                            visit(child, node, type_context)
                    elif key == "args":
                        for default in [*value.defaults, *[v for v in value.kw_defaults if v]]:
                            visit(default, scope, type_context)
                        args = [*value.posonlyargs, *value.args, *value.kwonlyargs]
                        args += [arg for arg in (value.vararg, value.kwarg) if arg]
                        for arg in args:
                            if arg.annotation:
                                visit(arg.annotation, scope, True)
                    elif key in {"returns", "type_params"}:
                        for child in value if isinstance(value, list) else [value]:
                            if isinstance(child, ast.AST):
                                visit(child, scope, True)
                    elif isinstance(value, ast.AST):
                        visit(value, scope, type_context)
                    elif isinstance(value, list):
                        for child in value:
                            if isinstance(child, ast.AST):
                                visit(child, scope, type_context)
                return
            if isinstance(node, ast.Lambda):
                scope_parent[node] = scope
                table: dict[str, list[tuple[str, str, str]]] = {}
                bindings[node] = table
                for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                    table[arg.arg] = [("shadowed", "", "")]
                for arg in (node.args.vararg, node.args.kwarg):
                    if arg:
                        table[arg.arg] = [("shadowed", "", "")]
                def lambda_stores(child):
                    if isinstance(child, ast.Lambda):
                        return
                    if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                        table[child.id] = [("shadowed", "", "")]
                    for descendant in ast.iter_child_nodes(child):
                        lambda_stores(descendant)
                lambda_stores(node.body)
                for default in [*node.args.defaults, *[value for value in node.args.kw_defaults if value]]:
                    visit(default, scope, type_context)
                visit(node.body, node, type_context)
                return
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                scope_parent[node] = scope
                bindings[node] = {}
                for child in ast.iter_child_nodes(node):
                    visit(child, node, type_context)
                return
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, (ast.Name, ast.Attribute)):
                    expression = ast.unparse(fn)
                    receiver = ast.unparse(fn.value) if isinstance(fn, ast.Attribute) else None
                    callee = fn.id if isinstance(fn, ast.Name) else fn.attr
                    root = fn
                    while isinstance(root, ast.Attribute):
                        root = root.value
                    if type_context:
                        kind, module, original, bound_scope = "type_only", "", "", None
                    elif isinstance(root, ast.Name):
                        kind, module, original, bound_scope = binding(root.id, scope, node.lineno)
                    else:
                        kind, module, original, bound_scope = "shadowed", "", "", None
                    # Class bodies/defaults/decorators execute in their enclosing
                    # function/module context, not when a class method is called.
                    owner: ast.AST | None = scope
                    while owner is not None and (owner not in node_symbols or isinstance(owner, ast.ClassDef)):
                        owner = scope_parent.get(owner)
                    calls.append(CallSite(
                        caller_qname=node_symbols[owner].qname if owner else None,
                        callee_name=callee, file=rel_path, line=node.lineno,
                        receiver=receiver, expression=expression, binding_kind=kind,
                        module=module, imported_name=original, binding_scope=bound_scope,
                        is_module_level=scope is tree,
                    ))
            for child in ast.iter_child_nodes(node):
                visit(child, scope, type_context)

        visit(tree, tree)
        symbols.sort(key=lambda symbol: (symbol.line, symbol.qname))
        return symbols, calls, imports, import_kinds

    @staticmethod
    def _class_signature(node: ast.ClassDef) -> str:
        bases = []
        for b in node.bases:
            try:
                bases.append(ast.unparse(b))
            except Exception:
                pass
        suffix = f"({', '.join(bases)})" if bases else ""
        return f"class {node.name}{suffix}"

    @staticmethod
    def _func_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
        a = node.args
        pos = list(a.posonlyargs) + list(a.args)
        defaults = list(a.defaults)
        pad = len(pos) - len(defaults)
        args: list[str] = []
        for i, arg in enumerate(pos):
            s = arg.arg
            if arg.annotation is not None:
                try:
                    s += f": {ast.unparse(arg.annotation)}"
                except Exception:
                    pass
            if i >= pad:
                try:
                    s += f"={ast.unparse(defaults[i - pad])}"
                except Exception:
                    pass
            args.append(s)
        if a.vararg:
            args.append(f"*{a.vararg.arg}")
        for arg in a.kwonlyargs:
            args.append(arg.arg)
        if a.kwarg:
            args.append(f"**{a.kwarg.arg}")
        ret = ""
        if node.returns is not None:
            try:
                ret = f" -> {ast.unparse(node.returns)}"
            except Exception:
                pass
        return f"{prefix} {node.name}({', '.join(args)}){ret}"

    def parse_with_meta(
        self, path: Path, rel_path: str, text: str
    ) -> tuple[list[Symbol], list[CallSite], FileMeta, dict[str, set[str]]]:
        """一次读取 + 一次 AST 解析，产出符号、调用点、元数据与 import 表。

        实测：分开做 file_meta() + parse() 会把文件读两遍、AST 解析两遍，
        在 42k 行项目上多花约 1.3 秒。合并后单遍即可。
        """
        parse_error = None
        try:
            tree = ast.parse(text)
        except RecursionError:
            tree = None
            parse_error = "python_ast_recursion_limit: ast_parse"
        except (SyntaxError, ValueError) as error:
            tree = None
            parse_error = f"{getattr(error, 'msg', str(error))} (line {getattr(error, 'lineno', '?')})"
        if tree is not None:
            parse_error = self._ast_limit_error(tree)
            if parse_error:
                tree = None

        symbols: list[Symbol] = []
        calls: list[CallSite] = []
        imports: dict[str, set[str]] = {}
        exports: list[str] = []
        import_kinds: dict[str, str] = {}

        if tree is not None:
            try:
                symbols, calls, imports, import_kinds = self._analyze(tree, rel_path)
            except RecursionError:
                tree = None
                parse_error = "python_ast_recursion_limit: analysis"
                symbols, calls, imports, import_kinds = [], [], {}, {}

        if tree is not None:
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.isupper():
                            exports.append(target.id)

        stat = path.stat() if path.exists() else None
        meta = FileMeta(
            path=rel_path,
            language=Language.PYTHON,
            lines=len(text.splitlines()),
            content_hash=hashlib.sha1(
                text.encode("utf-8", errors="replace")).hexdigest(),
            mtime=stat.st_mtime if stat else 0.0,
            imports=sorted(imports.keys()),
            exports=sorted(set(exports)),
            is_parsed=tree is not None,
            parse_error=parse_error,
            import_kinds=import_kinds,
        )
        return symbols, calls, meta, imports

    # ---------- 文件元数据 ----------

    def file_meta(
        self, path: Path, rel_path: str, is_test: bool, is_script: bool,
        is_data: bool,
    ) -> FileMeta:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            return FileMeta(
                path=rel_path, language=Language.PYTHON, is_test=is_test,
                is_script=is_script, is_data=is_data, is_parsed=False,
                parse_error=f"source_read_failed: {type(error).__name__}",
            )
        _, _, meta, _ = self.parse_with_meta(path, rel_path, text)
        meta.is_test = is_test
        meta.is_script = is_script
        meta.is_data = is_data
        return meta
