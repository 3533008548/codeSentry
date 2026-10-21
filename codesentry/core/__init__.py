"""CodeSentry 核心契约。

一份模型覆盖两个场景（理解 / 审查）共用的数据结构。
"""
from codesentry.core.finding import (
    Evidence,
    Extraction,
    Finding,
    Severity,
    Source,
    SuggestionType,
)
from codesentry.core.fingerprint import (
    compute_fingerprint,
    content_hash,
    normalize_snippet,
)
from codesentry.core.policy import (
    ExcludeConfig,
    GateConfig,
    IndexConfig,
    Policy,
    RoleRule,
    RolesConfig,
    default_policy_text,
    load_policy,
)
from codesentry.core.symbol import (
    CallSite,
    FileMeta,
    Language,
    Symbol,
    SymbolEdge,
    SymbolKind,
)

__all__ = [
    "Evidence",
    "ExcludeConfig",
    "Extraction",
    "Finding",
    "FileMeta",
    "GateConfig",
    "IndexConfig",
    "Language",
    "Policy",
    "RoleRule",
    "RolesConfig",
    "Severity",
    "Source",
    "SuggestionType",
    "Symbol",
    "SymbolEdge",
    "SymbolKind",
    "CallSite",
    "compute_fingerprint",
    "content_hash",
    "default_policy_text",
    "load_policy",
    "normalize_snippet",
]
