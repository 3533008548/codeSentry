"""Untrusted drafts and report data never carry blocking authority.

Only a current trusted verification context can recognise its original finding
objects. Serialized source/verified/fingerprint fields remain report data.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from codesentry.review.verification import VerificationContext


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Source(str, Enum):
    """结论来源，决定门禁行为。"""

    UNKNOWN = "unknown"
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

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

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

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    file: str
    line: int = Field(ge=1)
    snippet: str = ""
    symbol: str | None = None


class Finding(BaseModel):
    """一条审查结论。"""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    file: str
    line: int = Field(ge=1, strict=True)
    end_line: int | None = Field(default=None, ge=1, strict=True)
    symbol: str | None = None

    rule_id: str = Field(description="如 complexity.function_length")
    severity: Severity = Severity.MEDIUM
    source: Source = Source.UNKNOWN

    reason: str = Field(description="为什么这是问题")
    evidence: str = Field(default="", description="人类可读的证据描述")
    evidence_refs: list[Evidence] = Field(default_factory=list)

    extraction: Extraction | None = None
    suggestion: str | None = None
    suggestion_type: SuggestionType | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    rule_version: str = ""
    anchor: str = ""
    occurrence: int = Field(default=1, ge=1, strict=True)
    facts: dict[str, Any] = Field(default_factory=dict)
    identity_digest: str = ""
    evidence_digest: str = ""
    combined_digest: str = ""

    fingerprint: str = Field(
        default="", description="内容指纹，用于基线匹配（禁用行号）"
    )
    verified: bool = Field(
        default=False, description="创建报告时是否经可信规则重算；此字段不授予阻断资格"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def _location(self):
        if self.end_line is not None and self.end_line < self.line:
            raise ValueError("end_line cannot precede line")
        return self

    def can_block(self, context: VerificationContext | None = None) -> bool:
        """Minimum eligibility only; a final gate and approved baseline are separate."""
        if context is None:
            return False
        from codesentry.review.verification import VerificationContext
        return type(context) is VerificationContext and context.can_block(self)


class LLMFindingDraft(BaseModel):
    """Model-shaped suggestions; provenance and verification fields are forbidden."""

    model_config = ConfigDict(extra="forbid")
    file: str
    line: int = Field(ge=1, strict=True)
    end_line: int | None = Field(default=None, ge=1, strict=True)
    symbol: str | None = None
    rule_id: str
    severity: Severity = Severity.MEDIUM
    reason: str
    evidence: str = ""
    evidence_refs: list[Evidence] = Field(default_factory=list)
    suggestion: str | None = None
    suggestion_type: SuggestionType | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    def to_finding(self, *, source: Source = Source.LLM) -> Finding:
        if source not in {Source.LLM, Source.EXPLORE}:
            raise ValueError("a model draft cannot become a deterministic finding")
        return Finding(**self.model_dump(), source=source, verified=False)
