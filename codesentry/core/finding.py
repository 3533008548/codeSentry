"""Finding 数据契约。

一份模型同时满足三件事（v0.1 决策 2）：
  1. 向 LLM 提供 JSON Schema 做结构化输出约束
  2. 在 Web 报告里序列化
  3. 在 policy.yaml 中做配置校验

`source` 字段决定它能否进阻断路径（v0.1 决策 7）：
  只有 deterministic + 回验通过才可阻断。
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Source(str, Enum):
    """结论来源，决定门禁行为。"""

    DETERMINISTIC = "deterministic"
    LLM = "llm"
    EXPLORE = "explore"


class SuggestionType(str, Enum):
    """修复建议的可信等级（v0.1 决策 6）。"""

    STRUCTURAL = "structural"  # 仅参考，需人工设计
    PATCH = "patch"            # 过门禁后可用
    ADVISORY = "advisory"      # 主力形态：定位 + 依据


class Extraction(BaseModel):
    """确定性层给出的机器可读依据。

    这是「修复建议有据可依」的关键：LLM 说职责过载，但子结构计数
    是我们自己数出来的。回答"你怎么知道"时不依赖模型的自我声明。
    """

    sub_symbols: list[str] = Field(default_factory=list)
    sub_symbol_counts: list[int] = Field(default_factory=list)
    function_lines: int | None = None
    call_depth_max: int | None = None
    branches: int | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """可验证的证据锚点。

    每个证据都必须能被用户 5 秒内自行核对。
    """

    file: str
    line: int = Field(ge=1)
    snippet: str = ""
    symbol: str | None = None


class Finding(BaseModel):
    """一条审查结论。"""

    file: str
    line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = None

    rule_id: str = Field(description="如 complexity.function_length")
    severity: Severity = Severity.MEDIUM
    source: Source = Source.DETERMINISTIC

    reason: str = Field(description="为什么这是问题")
    evidence: str = Field(default="", description="人类可读的证据描述")
    evidence_refs: list[Evidence] = Field(default_factory=list)

    extraction: Extraction | None = None
    suggestion: str | None = None
    suggestion_type: SuggestionType | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    fingerprint: str = Field(
        default="", description="内容指纹，用于基线匹配（禁用行号）"
    )
    verified: bool = Field(
        default=True, description="是否通过回验（行号存在 + 符号命中）"
    )
    created_at: datetime = Field(default_factory=datetime.now)

    def can_block(self) -> bool:
        """能否进入阻断路径。

        规则（v0.1 决策 7 + v0.2 三条护栏）：
          - 必须来自确定性层
          - 必须通过回验
          - 置信度必须足够高
        LLM 结论与 explore 模式一律不可阻断。
        """
        if self.source is not Source.DETERMINISTIC:
            return False
        if not self.verified:
            return False
        return self.confidence >= 0.9
