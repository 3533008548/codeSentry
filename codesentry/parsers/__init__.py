"""解析层：把源码变成符号表与调用点。

统一入口，按扩展名分派到对应语言的解析器。
"""
from codesentry.core.symbol import CallSite, FileMeta, Symbol
from codesentry.parsers.python_parser import (
    BUILTIN_NAMES,
    TEST_HELPERS,
    PythonParser,
)
from codesentry.parsers.ts_parser import TypeScriptParser

__all__ = [
    "BUILTIN_NAMES",
    "TEST_HELPERS",
    "CallSite",
    "FileMeta",
    "Parser",
    "PythonParser",
    "Symbol",
    "TypeScriptParser",
]


class Parser:
    """多语言解析器的统一入口。

    持有各语言解析器实例（TS 解析器需要常驻 Node 进程）。
    """

    def __init__(self, project_root, use_typescript: bool = True):
        self.project_root = project_root
        self.python = PythonParser()
        self.typescript: TypeScriptParser | None = None
        self.warnings: list[str] = []
        if use_typescript:
            self.typescript = TypeScriptParser(project_root)

    def parse_with_meta(
        self, path, rel_path: str, text: str, suffix: str
    ) -> tuple[list[Symbol], list[CallSite], FileMeta, dict[str, set[str]]]:
        """一次读取 + 一次解析，产出符号、调用点、元数据与 import 映射。

        合并 file_meta() 与 parse() 是为了避免把文件读两遍、AST 解析两遍
        （实测在 42k 行项目上多花约 1.3 秒）。
        """
        if suffix == ".py":
            return self.python.parse_with_meta(path, rel_path, text)
        if suffix in (".ts", ".tsx"):
            if self.typescript is None:
                return [], [], FileMeta(path=rel_path, language="unknown"), {}
            try:
                return self.typescript.parse_with_meta(path, rel_path, text)
            except RuntimeError as e:
                self.warnings.append(f"{rel_path}: {e}")
                return [], [], FileMeta(path=rel_path, language="unknown"), {}
        return [], [], FileMeta(path=rel_path, language="unknown"), {}

    def parse(
        self, path, rel_path: str, suffix: str
    ) -> tuple[list[Symbol], list[CallSite]]:
        if suffix == ".py":
            return self.python.parse(path, rel_path)
        if suffix in (".ts", ".tsx"):
            if self.typescript is None:
                return [], []
            try:
                return self.typescript.parse(path, rel_path)
            except RuntimeError as e:
                # 不静默失败：TypeScript 解析不可用时必须让人知道
                self.warnings.append(f"{rel_path}: {e}")
                return [], []
        return [], []

    def file_meta(
        self, path, rel_path: str, suffix: str, is_test: bool,
        is_script: bool, is_data: bool,
    ) -> FileMeta:
        if suffix == ".py":
            return self.python.file_meta(
                path, rel_path, is_test, is_script, is_data)
        if suffix in (".ts", ".tsx"):
            if self.typescript is None:
                return FileMeta(path=rel_path, language="unknown")
            return self.typescript.file_meta(
                path, rel_path, is_test, is_script, is_data)
        return FileMeta(path=rel_path, language="unknown")

    def close(self) -> None:
        if self.typescript:
            self.typescript.close()

    def __enter__(self) -> "Parser":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
