"""Symbol 与 SymbolEdge 数据契约。

设计要点（依据 docs/CodeSentry_技术选型定稿_v0.2.md §4.2）：

1. **符号主键必须是限定名 `file::symbol`**，不得用裸符号名。
   实测 research_agent 重名率 18%，裸名做主键会让 PageRank 变成
   "给最常见的词打分"（get/append/list 霸榜）。

2. **符号种类区分「定义」与「接口」**。纯定义文件（如 tool_schemas.py
   只有常量与类型声明）是第四种架构形态，不能与实现型文件混为一谈。

3. **文件元数据单列**，因为排除规则分两类（不解析 / 不参与重要度排序），
   都需要文件级属性支撑。
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class SymbolKind(str, Enum):
    """符号种类。"""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    INTERFACE = "interface"
    TYPE_ALIAS = "type_alias"
    ENUM = "enum"
    CONSTANT = "constant"
    PROPERTY = "property"
    MODULE = "module"


class Language(str, Enum):
    """支持的语言。"""

    PYTHON = "python"
    TYPESCRIPT = "typescript"
    UNKNOWN = "unknown"


class Symbol(BaseModel):
    """一个符号定义。

    `qname` 是限定名（`file::symbol`），是全系统的唯一标识。
    """

    qname: str = Field(
        description="限定名 file::symbol，全系统唯一标识"
    )
    name: str
    kind: SymbolKind
    file: str = Field(description="相对项目根的路径，统一用 / 分隔")
    line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    signature: str = ""
    parent: str | None = Field(
        default=None, description="父符号的限定名（方法归属的类）"
    )
    docstring: str | None = None
    is_test: bool = False
    is_script: bool = Field(
        default=False, description="位于 scripts/ evals/ tools/ 等脚本目录"
    )
    is_definition_only: bool = Field(
        default=False,
        description="文件内只有定义/常量，无实现逻辑（契约层形态）",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def length(self) -> int:
        """符号的物理行数。"""
        return max(1, (self.end_line or self.line) - self.line + 1)

    @property
    def is_production(self) -> bool:
        """是否属于生产代码（排除测试与脚本目录）。"""
        return not self.is_test and not self.is_script


class SymbolEdge(BaseModel):
    """一条引用边：from 引用了 to。

    两端都用限定名。`resolved` 标记该边是否定位到了具体定义。
    """

    source: str = Field(description="调用方限定名；模块级调用为 None")
    target_name: str = Field(description="被调用名（可能未解析到唯一定义）")
    target: str | None = Field(
        default=None, description="被调用方的限定名（解析成功时）"
    )
    file: str
    line: int = Field(ge=1)
    resolution: str = Field(
        default="unresolved",
        description="local | cross_file | external | builtin | "
        "test_helper | module_level | ambiguous | unresolved",
    )

    @property
    def is_internal(self) -> bool:
        """是否项目内可定位的引用。"""
        return self.target is not None


class FileMeta(BaseModel):
    """文件级元数据。

    排除规则分两类，都需要这里的字段支撑：
      ① 不解析           → is_parsed=False
      ② 不参与重要度排序 → participates_in_ranking=False
    """

    path: str
    language: Language
    lines: int = 0
    is_test: bool = False
    is_script: bool = False
    is_data: bool = Field(
        default=False, description="数据目录（论文库、实验产物等），非源码"
    )
    is_parsed: bool = True
    participates_in_ranking: bool = True
    content_hash: str = ""
    mtime: float = 0.0
    doc_summary: str | None = None
    imports: list[str] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)

    @property
    def is_production(self) -> bool:
        return (
            self.is_parsed
            and self.participates_in_ranking
            and not self.is_test
            and not self.is_script
        )


class CallSite(BaseModel):
    """一次调用点的原始记录（解析层产出，索引层消费）。"""

    caller_qname: str | None
    callee_name: str
    file: str
    line: int
    module: str = Field(default="", description="import 到的模块路径")
