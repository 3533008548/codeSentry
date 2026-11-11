"""Recompute a single-file rule from explicitly authorised, fixed inputs.

Original finding objects are recognised by an in-memory context registry. Report
fields and hashes are never credentials. This is not an OS boundary against
malicious Python already executing inside the trusted host process.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import inspect
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys
import tokenize
from types import CodeType, FunctionType, MappingProxyType
from typing import Callable
import weakref

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.core.finding import Evidence, Extraction, Finding, LLMFindingDraft, Severity, Source
from codesentry.core.fingerprint import FingerprintEvidence, FingerprintIdentity, fingerprint_v2


MAX_OBSERVATIONS = 10_000


def _json(value, depth=0):
    if depth > 24:
        raise ValueError("trusted facts/configuration are too deep")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, Mapping) and all(type(key) is str for key in value):
        return {key: _json(item, depth + 1) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [_json(item, depth + 1) for item in value]
    raise ValueError("only finite JSON-native trusted facts/configuration are supported")


def _encoded(value):
    result = json.dumps(_json(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if len(result) > 512 * 1024:
        raise ValueError("trusted facts/configuration exceed the supported bound")
    return result


def _digest(value):
    return hashlib.sha256(_encoded(value)).hexdigest()


def _name(value):
    if (not isinstance(value, str) or not value or len(value) > 4096 or "\\" in value or ":" in value
            or "\0" in value or PurePosixPath(value).is_absolute()
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ValueError("verification input needs a strict workspace-relative name")
    return value


def _label(value, name):
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True)
class SourceInput:
    file: str
    text: str
    raw_sha256: str
    dependencies: Mapping[str, bytes] = field(default_factory=dict)
    dependency_hashes: Mapping[str, str] = field(default_factory=dict)
    raw_size: int = 0


@dataclass(frozen=True)
class RuleObservation:
    file: str
    line: int
    end_line: int
    symbol: str
    anchor: str
    occurrence: int
    reason: str
    severity: Severity = Severity.MEDIUM
    extraction: Extraction | None = None
    facts: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        _name(self.file)
        for name in ("symbol", "anchor", "reason"):
            _label(getattr(self, name), name)
        if (type(self.line) is not int or type(self.end_line) is not int or not 1 <= self.line <= self.end_line
                or type(self.occurrence) is not int or self.occurrence < 1 or not isinstance(self.severity, Severity)
                or self.extraction is not None and type(self.extraction) is not Extraction
                or not isinstance(self.facts, Mapping)):
            raise ValueError("invalid trusted rule observation")
        _encoded(self.facts)


@dataclass(frozen=True)
class TrustedRuleSpec:
    rule_id: str
    version: str
    implementation_hash: str
    evaluator: Callable[[SourceInput], Sequence[RuleObservation]]
    approved_for_blocking: bool = False

    def __post_init__(self):
        _label(self.rule_id, "rule identity")
        _label(self.version, "rule version")
        if (not isinstance(self.implementation_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", self.implementation_hash) is None
                or type(self.evaluator) is not FunctionType or type(self.approved_for_blocking) is not bool):
            raise ValueError("a trusted host function and fixed rule implementation are required")


def _callable_hash(evaluator):
    values = {"defaults": evaluator.__defaults__ or (), "kwdefaults": evaluator.__kwdefaults__ or {},
              "closure": [cell.cell_contents for cell in evaluator.__closure__ or ()]}
    return _digest({"code": _code_shape(evaluator.__code__), "configuration": values})


def _constant_shape(value):
    if type(value) is CodeType:
        return {"type": "code", "value": _code_shape(value)}
    if value is None or type(value) in (bool, int, str):
        return {"type": type(value).__name__, "value": value}
    if type(value) in (float, complex):
        return {"type": type(value).__name__, "value": repr(value)}
    if type(value) is bytes:
        return {"type": "bytes", "value": value.hex()}
    if type(value) is tuple:
        return {"type": "tuple", "value": [_constant_shape(item) for item in value]}
    if type(value) is frozenset:
        return {"type": "frozenset", "value": sorted((_constant_shape(item) for item in value), key=_encoded)}
    if value is Ellipsis:
        return {"type": "ellipsis"}
    raise ValueError("unsupported trusted code constant")


def _code_shape(code):
    # marshal can encode runtime interning/reference state differently after a
    # first execution. These public structural fields exclude adaptive caches.
    return {"bytecode": code.co_code.hex(), "constants": [_constant_shape(value) for value in code.co_consts],
            "names": code.co_names, "variables": code.co_varnames, "freevars": code.co_freevars,
            "cellvars": code.co_cellvars, "argcount": code.co_argcount, "posonly": code.co_posonlyargcount,
            "kwonly": code.co_kwonlyargcount, "nlocals": code.co_nlocals, "stacksize": code.co_stacksize,
            "flags": code.co_flags, "name": code.co_name, "qualname": code.co_qualname,
            "firstlineno": code.co_firstlineno, "linetable": code.co_linetable.hex(),
            "exceptiontable": code.co_exceptiontable.hex()}


def _analyzer_hash():
    package = Path(__file__).resolve().parents[1]
    content = {name: hashlib.sha256((package / name).read_bytes()).hexdigest()
               for name in ("review/verification.py", "core/finding.py", "core/fingerprint.py")}
    return _digest({"implementation": content, "python": sys.version, "schema": "trusted-finding-v1"})


@dataclass(frozen=True)
class _Receipt:
    finding: weakref.ReferenceType
    fields_hash: str


class VerificationContext:
    def __init__(self, access: AccessPolicy, rule: TrustedRuleSpec, *, file: str,
                 dependencies: tuple[str, ...] = (), policy_identity=None,
                 max_file_bytes: int = 2 * 1024 * 1024, max_total_bytes: int = 32 * 1024 * 1024):
        if not isinstance(access, AccessPolicy) or type(rule) is not TrustedRuleSpec:
            raise TypeError("trusted host access and rule objects are required")
        self.access, self.rule, self.file = access, rule, _name(file)
        if (not isinstance(dependencies, tuple) or len(dependencies) > 128
                or len({self.file, *dependencies}) != len(dependencies) + 1):
            raise ValueError("dependencies must be explicit, unique input names")
        self.dependencies = tuple(sorted(_name(name) for name in dependencies))
        if any(type(value) is not int or value <= 0 for value in (max_file_bytes, max_total_bytes)):
            raise ValueError("verification input budgets must be explicit positive integers")
        self.max_file_bytes, self.max_total_bytes = max_file_bytes, max_total_bytes
        self.policy_identity = {} if policy_identity is None else policy_identity
        self._policy_hash = _digest(self.policy_identity)
        self._self_id, self._closed, self._invalidated = id(self), False, False
        self._receipts = {}
        self._root = self.access.root
        self._access_identity = (id(access), id(access.read_guard))
        self._access_hash = self.access.fingerprint
        self._analyzer = _analyzer_hash()
        self._rule_signature = self._current_rule_signature()
        inputs = self._read_inputs()
        raw = inputs[self.file]
        encoding = tokenize.detect_encoding(io.BytesIO(raw).readline)[0] if self.file.endswith((".py", ".pyi")) else "utf-8-sig"
        self._hashes = {name: hashlib.sha256(content).hexdigest() for name, content in inputs.items()}
        self._input = SourceInput(self.file, raw.decode(encoding), self._hashes[self.file],
                                  MappingProxyType({name: inputs[name] for name in self.dependencies}),
                                  MappingProxyType({name: self._hashes[name] for name in self.dependencies}), len(raw))
        self.input_bytes = sum(map(len, inputs.values()))
        self.check_current()

    @property
    def input(self):
        return self._input

    def _current_rule_signature(self):
        module = inspect.getsourcefile(self.rule.evaluator)
        if module is None:
            raise ValueError("rule implementation source is unavailable")
        observed = hashlib.sha256(Path(module).read_bytes()).hexdigest()
        if observed != self.rule.implementation_hash:
            raise ValueError("trusted rule source does not match its selected implementation")
        return (self.rule.rule_id, self.rule.version, observed, _callable_hash(self.rule.evaluator),
                self.rule.approved_for_blocking, id(self.rule.evaluator))

    def _read_inputs(self):
        self.access.refresh_if_changed()
        self.access.check_current()
        if not self.access.confirmed or self.access.root != self._root or self.access.fingerprint != self._access_hash:
            raise AccessDenied("verification source scope changed or was never confirmed")
        inputs, total = {}, 0
        for name in (self.file, *self.dependencies):
            raw = self.access.read_bytes(name, limit=self.max_file_bytes)
            total += len(raw)
            if total > self.max_total_bytes:
                raise ValueError("verification total input byte budget exceeded")
            inputs[name] = raw
        self.access.check_current()
        if self.access.fingerprint != self._access_hash:
            raise AccessDenied("verification source scope changed during the read")
        return inputs

    def check_current(self):
        """Recheck full explicit inputs, permission, policy and rule; latch drift."""
        try:
            if self._self_id != id(self) or self._closed or self._invalidated:
                raise ValueError("verification context is closed, copied, or invalidated")
            if (id(self.access), id(self.access.read_guard)) != self._access_identity:
                raise ValueError("verification access object or its live guard changed")
            if (_digest(self.policy_identity) != self._policy_hash or self._current_rule_signature() != self._rule_signature
                    or _analyzer_hash() != self._analyzer):
                raise ValueError("trusted policy, rule, or analyzer identity changed")
            inputs = self._read_inputs()
            if {name: hashlib.sha256(raw).hexdigest() for name, raw in inputs.items()} != self._hashes:
                raise ValueError("verification source or dependency snapshot changed")
        except Exception:
            self._invalidated = True
            raise

    def evaluate(self) -> tuple[Finding, ...]:
        self.check_current()
        observations = self.rule.evaluator(self._input)
        if (not isinstance(observations, (tuple, list)) or len(observations) > MAX_OBSERVATIONS
                or any(type(item) is not RuleObservation for item in observations)):
            raise ValueError("trusted evaluator returned an unsupported observation collection")
        line_count = len(self._input.text.splitlines())
        seen = set()
        for item in observations:
            key = (item.file, item.symbol, item.anchor, item.occurrence)
            if item.file != self.file or item.end_line > line_count or key in seen:
                raise ValueError("rule observations have invalid locations or duplicate identities")
            seen.add(key)
        self.check_current()
        findings = tuple(self._mint(item) for item in observations)
        self.check_current()
        return findings

    def _mint(self, observation):
        facts = json.loads(_encoded(observation.facts))
        extraction = observation.extraction.model_copy(deep=True) if observation.extraction is not None else None
        extracted = extraction.model_dump(mode="json") if extraction is not None else None
        # Extraction and measured positions are part of this rule's facts, not
        # substituted from any model draft or report JSON.
        fingerprint = fingerprint_v2(
            FingerprintIdentity(self.rule.rule_id, self.rule.version, str(self._root / self.file),
                                observation.symbol, observation.anchor, observation.occurrence),
            FingerprintEvidence(self._input.text,
                                {"rule_facts": facts, "extraction": extracted,
                                 "line": observation.line, "end_line": observation.end_line},
                                {name: {"state": "present", "sha256": self._hashes[name]} for name in self.dependencies},
                                self.rule.implementation_hash, "sha256:" + self._policy_hash, "sha256:" + self._analyzer,
                                "python" if self.file.endswith((".py", ".pyi")) else "text", "raw-v1",
                                {"trusted_callable_hash": self._rule_signature[3], "access_fingerprint": self._access_hash,
                                 "source_sha256": self._input.raw_sha256},
                                {"python": sys.version}),
        )
        snippet = "\n".join(self._input.text.splitlines()[observation.line - 1:observation.end_line])
        finding = Finding(file=self.file, line=observation.line, end_line=observation.end_line,
                          symbol=observation.symbol, rule_id=self.rule.rule_id, rule_version=self.rule.version,
                          anchor=observation.anchor, occurrence=observation.occurrence, severity=observation.severity,
                          source=Source.DETERMINISTIC, reason=observation.reason, evidence=snippet,
                          evidence_refs=[Evidence(file=self.file, line=observation.line, snippet=snippet, symbol=observation.symbol)],
                          extraction=extraction, facts=facts, confidence=1.0, verified=True,
                          fingerprint=fingerprint.combined_digest, identity_digest=fingerprint.identity_digest,
                          evidence_digest=fingerprint.evidence_digest, combined_digest=fingerprint.combined_digest)
        self._receipts[id(finding)] = _Receipt(weakref.ref(finding), _digest(finding.model_dump(mode="json")))
        return finding

    def verify(self, draft: LLMFindingDraft | Finding) -> Finding | None:
        """Recompute facts for an external draft/report as a nonblocking warning.

        Independent evaluate() findings are a separate deterministic route.
        External source fields never select a credential-issuing pathway.
        """
        if type(draft) not in {LLMFindingDraft, Finding}:
            raise TypeError("verify accepts a typed untrusted draft or report")
        self.check_current()
        if draft.rule_id != self.rule.rule_id or draft.file != self.file:
            return None
        matches = [finding for finding in self.evaluate()
                   if finding.line == draft.line and (draft.symbol is None or finding.symbol == draft.symbol)]
        if len(matches) != 1:
            return None
        recomputed = matches[0]
        origin = Source.LLM if type(draft) is LLMFindingDraft else draft.source
        source = Source(origin) if origin in {Source.LLM, Source.EXPLORE} else Source.UNKNOWN
        self._receipts.pop(id(recomputed), None)
        return recomputed.model_copy(update={"source": source})

    def can_block(self, finding: Finding) -> bool:
        """A current original object and approved rule are minimum eligibility."""
        receipt = self._receipts.get(id(finding))
        if receipt is None or receipt.finding() is not finding:
            return False
        try:
            if (finding.source is not Source.DETERMINISTIC or finding.verified is not True
                    or _digest(finding.model_dump(mode="json")) != receipt.fields_hash):
                self._receipts.pop(id(finding), None)
                return False
            self.check_current()
            return self.rule.approved_for_blocking is True
        except Exception:
            self._receipts.pop(id(finding), None)
            return False

    def close(self):
        self._closed = True
        self._receipts.clear()

    def __enter__(self):
        self.check_current()
        return self

    def __exit__(self, *_):
        self.close()

    def __getstate__(self):
        raise TypeError("verification contexts and their credentials cannot be serialized")
