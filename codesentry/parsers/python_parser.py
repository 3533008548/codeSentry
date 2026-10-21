"""Python 解析器。

用标准库 `ast`（零依赖，官方精确）。v0.1 决策 1：
各语言用各自最优工具，Python 侧就是 `ast`。

关键设计：
  - 符号主键用限定名 `file::symbol`
  - 调用归属到「最内层符号」（按行号区间匹配）
  - 产出 CallSite 原始记录，符号解析交给索引层（因为需要全局信息）
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from codesentry.core.symbol import (
    CallSite,
    FileMeta,
    Language,
    Symbol,
    SymbolKind,
)

# 会被误判为项目内符号的内置名（方法调用形式）
BUILTIN_NAMES: frozenset[str] = frozenset({
    # 构造/类型
    "str", "int", "float", "bool", "bytes", "bytearray", "frozenset",
    "complex", "list", "dict", "set", "tuple", "range", "slice",
    "object", "type", "super", "property", "staticmethod", "classmethod",
    # 函数
    "print", "len", "range", "enumerate", "zip", "map", "filter", "reversed",
    "sorted", "sum", "min", "max", "any", "all", "abs", "round", "pow",
    "divmod", "hash", "iter", "next", "id", "callable", "vars", "dir",
    "globals", "locals", "input", "open", "compile", "exec", "eval",
    "getattr", "setattr", "hasattr", "delattr", "format", "repr",
    "isinstance", "issubclass", "aiter", "anext",
    # 方法名（属性访问形式）
    "get", "keys", "values", "items", "update", "pop", "popitem", "clear",
    "copy", "setdefault", "append", "extend", "insert", "remove", "discard",
    "add", "union", "intersection", "difference", "symmetric_difference",
    "issubset", "issuperset", "isdisjoint",
    "join", "split", "rsplit", "splitlines", "strip", "lstrip", "rstrip",
    "replace", "startswith", "endswith", "find", "rfind", "index", "rindex",
    "count", "upper", "lower", "title", "capitalize", "casefold", "swapcase",
    "center", "ljust", "rjust", "zfill", "expandtabs", "translate",
    "encode", "decode", "format_map", "isalnum", "isalpha", "isdecimal",
    "isdigit", "isidentifier", "islower", "isnumeric", "isprintable",
    "isspace", "istitle", "isupper",
    "read", "readline", "readlines", "write", "writelines", "flush",
    "seek", "tell", "truncate", "close", "detach", "fileno", "isatty",
    "readable", "writable", "seekable", "readinto", "read1",
    "group", "groups", "groupdict", "span", "start", "end", "search",
    "findall", "finditer", "sub", "subn", "match", "fullmatch", "escape",
    "now", "utcnow", "today", "fromtimestamp", "utcfromtimestamp",
    "strftime", "strptime", "isoformat", "fromisoformat", "timestamp",
    "astimezone", "utcoffset", "dst", "tzname", "combine", "combine",
    "fetchone", "fetchmany", "fetchall", "commit", "rollback",
    "cursor", "execute", "executemany", "executescript", "lastrowid",
    "description", "rowcount", "close", "connect", "autocommit",
    "json", "dumps", "loads", "dump", "load", "text", "binary",
    "hexdigest", "digest", "update", "copy", "digest_size",
    "urlencode", "urlparse", "urlsplit", "urljoin", "quote", "unquote",
    "urlopen", "request", "getcode", "geturl", "info", "headers",
    "get", "getheaders", "read", "readline", "status", "reason",
    "add_argument", "parse_args", "parse_known_args", "add_subparsers",
    "set_defaults", "add_argument_group", "add_mutually_exclusive_group",
    "format_help", "print_help", "exit", "error",
    "acquire", "release", "wait", "notify", "notify_all", "set", "clear",
    "is_set", "is_alive", "join", "run", "start", "daemon", "name",
    "getpid", "put", "get_nowait", "put_nowait", "task_done",
    "sleep", "perf_counter", "monotonic", "process_time", "time",
    "uuid4", "uuid1", "hex", "getnode",
    "loads", "dumps", "make_signed", "verify", "encode", "decode",
    "urlsafe_b64encode", "urlsafe_b64decode", "b64encode", "b64decode",
    "urlsafe_b64decode", "standard_b64encode", "standard_b64decode",
    "Poster", "getstate", "setstate", "copyreg", "pickle", "dumps",
    "loads", "dump", "load", "Pack", "Unpack", "pack", "unpack",
    "wrap", "unwrap", "update_wrapper", "wraps",
    "subprocess", "run", "Popen", "check_output", "check_call", "call",
    "communicate", "wait", "poll", "kill", "terminate", "send_signal",
    "wait_for", "gather", "create_task", "sleep", "shield", "wait",
    "as_completed", "to_thread", "run_in_executor", "get_event_loop",
    "new_event_loop", "set_event_loop", "run_until_complete",
    "asyncio", "CancelledError", "TimeoutError",
    "isdir", "isfile", "exists", "lexists", "islink", "isabs", "getsize",
    "getmtime", "getctime", "getatime", "samefile", "dirname", "basename",
    "splitext", "splitdrive", "normpath", "abspath", "realpath", "relpath",
    "expanduser", "expandvars", "normcase", "join", "commonprefix",
    "commonpath", "supports_unicode_filenames",
    "walk", "listdir", "mkdir", "makedirs", "rmdir", "removedirs", "unlink",
    "rename", "replace", "copy", "copy2", "copymode", "copystat", "copyfile",
    "copytree", "rmtree", "stat", "chmod", "chown", "lchmod", "utime",
    "mkstemp", "mkdtemp", "NamedTemporaryFile", "TemporaryDirectory",
    "gettempdir", "gettempprefix", "is_mount",
    "urlsplit", "urlparse", "urljoin", "urlencode", "quote_plus",
    "unquote_plus", "urlunsplit", "urlunparse", "parse_qs", "parse_qsl",
    "getusername", "getuser", "expanduser", "getlogin",
    "getdefaultencoding", "getfilesystemencoding", "getpreferredencoding",
    "setdefaultencoding",
    "compile", "exec", "eval", "globals", "locals", "vars", "dir",
    "exit", "quit", "help", "copyright", "credits", "license",
    "BrokenPipeError", "ConnectionResetError", "TimeoutError",
})

# 测试断言与辅助
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

    def parse(self, path: Path, rel_path: str) -> tuple[list[Symbol], list[CallSite]]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], []
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            return [], []

        symbols = self._extract_symbols(tree, rel_path, source)
        calls = self._extract_calls(tree, symbols, rel_path)
        return symbols, calls

    # ---------- 符号 ----------

    def _extract_symbols(
        self, tree: ast.AST, rel_path: str, source: str
    ) -> list[Symbol]:
        symbols: list[Symbol] = []
        # 先收集类，用于方法的 parent 归属
        class_spans: list[tuple[int, int, str]] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_spans.append(
                    (node.lineno, getattr(node, "end_lineno", node.lineno),
                     node.name)
                )

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                symbols.append(Symbol(
                    qname=f"{rel_path}::{node.name}",
                    name=node.name,
                    kind=SymbolKind.CLASS,
                    file=rel_path,
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    signature=self._class_signature(node),
                    docstring=ast.get_docstring(node),
                ))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parent = self._find_parent(class_spans, node.lineno)
                kind = SymbolKind.METHOD if parent else SymbolKind.FUNCTION
                symbols.append(Symbol(
                    qname=f"{rel_path}::{node.name}",
                    name=node.name,
                    kind=kind,
                    file=rel_path,
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    signature=self._func_signature(node),
                    docstring=ast.get_docstring(node),
                    parent=f"{rel_path}::{parent}" if parent else None,
                ))

        symbols.sort(key=lambda s: (s.line, s.name))
        return symbols

    @staticmethod
    def _find_parent(
        class_spans: list[tuple[int, int, str]], line: int
    ) -> str | None:
        """找包含该行的最内层类。"""
        best: str | None = None
        best_span: int | None = None
        for start, end, name in class_spans:
            if start <= line <= end:
                width = end - start
                if best_span is None or width < best_span:
                    best_span = width
                    best = name
        return best

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

    # ---------- 调用 ----------

    def _extract_calls(
        self, tree: ast.AST, symbols: list[Symbol], rel_path: str
    ) -> list[CallSite]:
        spans = sorted(
            ((s.line, s.end_line or s.line, s.qname) for s in symbols),
            key=lambda x: x[0],
        )
        calls: list[CallSite] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Name):
                callee = fn.id
            elif isinstance(fn, ast.Attribute):
                callee = fn.attr
            else:
                continue
            calls.append(CallSite(
                caller_qname=self._owner(spans, node.lineno),
                callee_name=callee,
                file=rel_path,
                line=node.lineno,
            ))
        return calls

    @staticmethod
    def _owner(
        spans: list[tuple[int, int, str]], line: int
    ) -> str | None:
        """找包含该调用行的最内层符号。"""
        owner: str | None = None
        best: int | None = None
        for start, end, qname in spans:
            if start <= line <= end:
                width = end - start
                if best is None or width < best:
                    best = width
                    owner = qname
        return owner

    def parse_with_meta(
        self, path: Path, rel_path: str, text: str
    ) -> tuple[list[Symbol], list[CallSite], FileMeta, dict[str, set[str]]]:
        """一次读取 + 一次 AST 解析，产出符号、调用点、元数据与 import 表。

        实测：分开做 file_meta() + parse() 会把文件读两遍、AST 解析两遍，
        在 42k 行项目上多花约 1.3 秒。合并后单遍即可。
        """
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            tree = None

        symbols: list[Symbol] = []
        calls: list[CallSite] = []
        imports: dict[str, set[str]] = {}
        exports: list[str] = []

        if tree is not None:
            symbols = self._extract_symbols(tree, rel_path, text)
            calls = self._extract_calls(tree, symbols, rel_path)

            for node in tree.body:
                if isinstance(node, ast.Import):
                    for a in node.names:
                        imports.setdefault(a.name, set()).add(
                            a.asname or a.name.split(".")[-1])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = imports.setdefault(node.module, set())
                    for a in node.names:
                        names.add(a.asname or a.name)
                elif isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name) and t.id.isupper():
                            exports.append(t.id)

        stat = path.stat() if path.exists() else None
        meta = FileMeta(
            path=rel_path,
            language=Language.PYTHON,
            lines=text.count("\n"),
            content_hash=hashlib.sha1(
                text.encode("utf-8", errors="replace")).hexdigest(),
            mtime=stat.st_mtime if stat else 0.0,
            imports=sorted(imports.keys()),
            exports=sorted(set(exports)),
        )
        return symbols, calls, meta, imports

    # ---------- 文件元数据 ----------

    def file_meta(
        self, path: Path, rel_path: str, is_test: bool, is_script: bool,
        is_data: bool,
    ) -> FileMeta:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        imports: list[str] = []
        exports: list[str] = []
        try:
            tree = ast.parse(text)
            for node in tree.body:
                if isinstance(node, ast.Import):
                    imports.extend(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)
                elif isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name) and t.id.isupper():
                            exports.append(t.id)
        except (SyntaxError, ValueError):
            pass
        stat = path.stat() if path.exists() else None
        return FileMeta(
            path=rel_path,
            language=Language.PYTHON,
            lines=text.count("\n"),
            is_test=is_test,
            is_script=is_script,
            is_data=is_data,
            content_hash=__import__("hashlib").sha1(
                text.encode("utf-8", errors="replace")
            ).hexdigest(),
            mtime=stat.st_mtime if stat else 0.0,
            imports=sorted(set(imports)),
            exports=sorted(set(exports)),
        )
