"""Versioned issue identity and complete evidence digests.

Hashes describe inputs; they confer no verification, baseline approval or gate
authority. Evidence is conservatively raw: comments, whitespace, suppression
directives and every line are preserved. Cache content_hash remains SHA-1.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from types import MappingProxyType


_IDENTITY_PREFIX = "v2:sha256:identity:"
_EVIDENCE_PREFIX = "v2:sha256:evidence:"
_COMBINED_PREFIX = "v2:sha256:"


def _text(value, field_name: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a nonempty, unpadded string")


def _freeze(value):
    """Capture JSON data without retaining a caller's mutable dict/list aliases."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("evidence JSON object keys must be strings")
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    raise ValueError("evidence must contain finite JSON data only")


def _plain(value):
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _hash(domain: str, data: dict) -> str:
    raw = json.dumps({"version": 2, "domain": domain, "input": data},
                     sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _combined(identity_digest: str, evidence_digest: str) -> str:
    return _COMBINED_PREFIX + _hash("combined", {"identity": identity_digest, "evidence": evidence_digest})


@dataclass(frozen=True)
class FingerprintIdentity:
    """Caller supplies repository/path scope, a full symbol, anchor and count."""

    rule_id: str
    rule_version: str
    file_scope: str
    symbol: str
    structural_anchor: str
    occurrence: int = 1

    def __post_init__(self):
        for name in ("rule_id", "rule_version", "file_scope", "symbol", "structural_anchor"):
            _text(getattr(self, name), name)
        if type(self.occurrence) is not int or self.occurrence < 1:
            raise ValueError("occurrence must be a positive integer")

    def to_dict(self) -> dict:
        return {name: getattr(self, name) for name in (
            "rule_id", "rule_version", "file_scope", "symbol", "structural_anchor", "occurrence")}


@dataclass(frozen=True)
class FingerprintEvidence:
    """Complete input, including explicit missing/unknown dependencies.

    Callers declare coverage; this API cannot discover dependencies or prove
    equivalence. normalization is an extraction version label. Source always
    enters the digest unchanged, regardless of that label.
    """

    source: str
    facts: Mapping[str, object]
    dependencies: Mapping[str, object]
    rule_implementation: str
    policy: str
    analyzer: str
    language: str
    normalization: str = "raw-v1"
    config: Mapping[str, object] = field(default_factory=dict)
    environment: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.source, str):
            raise ValueError("source must be the complete original text")
        for name in ("rule_implementation", "policy", "analyzer", "language", "normalization"):
            _text(getattr(self, name), name)
        for name in ("facts", "dependencies", "config", "environment"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise ValueError(f"{name} must be a JSON object")
            object.__setattr__(self, name, _freeze(value))

    def to_dict(self) -> dict:
        return {name: _plain(getattr(self, name)) for name in (
            "source", "facts", "dependencies", "rule_implementation", "policy", "analyzer",
            "language", "normalization", "config", "environment")}


@dataclass(frozen=True)
class FingerprintV2:
    identity_digest: str
    evidence_digest: str
    combined_digest: str
    version: int = field(default=2, init=False)

    def __post_init__(self):
        for value, prefix in ((self.identity_digest, _IDENTITY_PREFIX), (self.evidence_digest, _EVIDENCE_PREFIX)):
            if not isinstance(value, str) or re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", value) is None:
                raise ValueError("invalid v2 fingerprint digest")
        if self.combined_digest != _combined(self.identity_digest, self.evidence_digest):
            raise ValueError("inconsistent combined fingerprint")

    def to_dict(self) -> dict:
        return {"version": self.version, "identity_digest": self.identity_digest,
                "evidence_digest": self.evidence_digest, "combined_digest": self.combined_digest}

    @classmethod
    def from_dict(cls, document: dict) -> "FingerprintV2":
        if (not isinstance(document, dict) or set(document) != {
                "version", "identity_digest", "evidence_digest", "combined_digest"}
                or type(document["version"]) is not int or document["version"] != 2):
            raise ValueError("unknown fingerprint version or fields")
        return cls(document["identity_digest"], document["evidence_digest"], document["combined_digest"])


def fingerprint_v2(identity: FingerprintIdentity, evidence: FingerprintEvidence) -> FingerprintV2:
    if type(identity) is not FingerprintIdentity or type(evidence) is not FingerprintEvidence:
        raise TypeError("typed fingerprint identity and evidence are required")
    identity_digest = _IDENTITY_PREFIX + _hash("identity", identity.to_dict())
    evidence_digest = _EVIDENCE_PREFIX + _hash("evidence", evidence.to_dict())
    return FingerprintV2(identity_digest, evidence_digest, _combined(identity_digest, evidence_digest))


def normalize_snippet(snippet: str, max_lines: int = 12) -> str:
    """Preserve complete raw text; legacy max_lines is accepted but ignored."""
    if not isinstance(snippet, str) or type(max_lines) is not int:
        raise ValueError("snippet must be text and legacy max_lines must be an integer")
    return snippet


def compute_fingerprint(rule_id: str, symbol_name: str | None, snippet: str, max_lines: int = 12) -> str:
    """Compatibility report digest, using unscoped/unversioned context markers.

    New trusted rules use fingerprint_v2 with actual context. Old sha1: digests
    cannot inherit baseline approval from this version change.
    """
    if symbol_name is not None and not isinstance(symbol_name, str):
        raise ValueError("symbol_name must be text or None")
    identity = FingerprintIdentity(rule_id, "legacy-unversioned", "legacy-unscoped",
                                   (symbol_name or "").strip() or "<unknown-symbol>", "legacy-symbol")
    evidence = FingerprintEvidence(normalize_snippet(snippet, max_lines), {}, {},
        "legacy-unversioned", "legacy-unconfigured", "legacy-unversioned", "unknown")
    return fingerprint_v2(identity, evidence).combined_digest


def content_hash(text: str) -> str:
    """Preserve the existing index/cache SHA-1 contract."""
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()
