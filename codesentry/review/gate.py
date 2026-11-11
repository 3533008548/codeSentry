"""Host-owned required checks and a gate over live, original Finding receipts.

The production catalogue deliberately has no admitted blocking detector yet.
Reports, repository configuration, and preview baseline approvals cannot admit
rules or exempt blockers. This is a trusted-process contract, not OS isolation.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import weakref

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.core.finding import Finding, Severity
from codesentry.review.rules import function_length_rule
from codesentry.review.scan import OTHER_SOURCE_SUFFIXES, PYTHON_SUFFIXES, PreviewLimits
from codesentry.review.verification import TrustedRuleSpec, VerificationContext, _callable_hash


EXIT_CODES = {"pass": 0, "block": 1, "incomplete": 3, "error": 2}
SCOPE = "permitted_python_files_only"
_EVIDENCE_FIELDS = ("preregistration_sha256", "validation_dataset_sha256", "validation_report_sha256")
_POLICIES: dict[int, tuple] = {}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _implementation():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _occurrence_key(finding):
    return (finding.rule_id, finding.rule_version, finding.file, finding.symbol, finding.anchor, finding.occurrence)


@dataclass(frozen=True)
class BlockingPolicy:
    """Host-selected severity/count settings; data alone never admits a rule."""
    block_severities: tuple[str, ...] = ("critical", "high")
    max_new_findings: int = 0
    count_unit: str = "unique_issue_occurrences"

    def __post_init__(self):
        if (type(self.block_severities) is not tuple or not self.block_severities
                or any(type(value) is not str or value not in {severity.value for severity in Severity}
                       for value in self.block_severities)
                or len(set(self.block_severities)) != len(self.block_severities)
                or type(self.max_new_findings) is not int or not 0 <= self.max_new_findings <= 10_000
                or type(self.count_unit) is not str or self.count_unit != "unique_issue_occurrences"):
            raise ValueError("invalid host blocking severity/count policy")

    def to_dict(self):
        self.__post_init__()
        return {"block_severities": list(self.block_severities), "max_new_findings": self.max_new_findings,
                "count_unit": self.count_unit}


@dataclass(frozen=True)
class _RequiredRule:
    rule: TrustedRuleSpec
    classification: str
    config_json: str = "{}"
    dependencies: tuple[str, ...] = ()
    admission: str = "report_only"
    evidence: tuple[tuple[str, str], ...] = ()
    callable_hash: str = ""

    def __post_init__(self):
        if type(self.rule) is not TrustedRuleSpec or self.classification not in {"policy_debt", "behavior_bug"}:
            raise ValueError("a typed trusted rule and explicit classification are required")
        if (self.admission not in {"report_only", "admitted"} or type(self.dependencies) is not tuple
                or any(type(name) is not str for name in self.dependencies)
                or len(set(self.dependencies)) != len(self.dependencies)):
            raise ValueError("invalid required rule configuration")
        config = json.loads(self.config_json)
        if type(config) is not dict or _canonical(config) != self.config_json:
            raise ValueError("rule configuration must be canonical host-owned JSON")
        if self.callable_hash != _callable_hash(self.rule.evaluator):
            raise ValueError("rule callable identity was not frozen")
        if self.admission == "admitted":
            evidence = dict(self.evidence)
            if (self.rule.approved_for_blocking is not True or set(evidence) != set(_EVIDENCE_FIELDS)
                    or len(evidence) != len(self.evidence)
                    or any(type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value)
                           for value in evidence.values())
                    or self.rule.rule_id == "python.function_length"):
                raise ValueError("required blocking admission evidence is absent or production rule is report-only")
        elif self.evidence or self.rule.approved_for_blocking:
            raise ValueError("report-only catalogue entries cannot claim blocking approval")


@dataclass(frozen=True, eq=False)
class GatePolicy:
    """Opaque host-issued policy; constructing/copying report data grants nothing.

    Only production_policy is public issuance. Private synthetic test fixtures
    exercise admitted checks without creating a production registration API.
    """
    policy_id: str
    version: str
    _required: tuple[_RequiredRule, ...]
    _limits: PreviewLimits
    _blocking_policy: BlockingPolicy = BlockingPolicy()

    def __getstate__(self):
        raise TypeError("gate policies cannot be serialized as authority")


def _rule_metadata(entry):
    return {"rule_id": entry.rule.rule_id, "rule_version": entry.rule.version,
        "implementation_hash": entry.rule.implementation_hash, "trusted_callable_sha256": entry.callable_hash,
        "classification": entry.classification, "required": True, "admission": entry.admission,
        "approved_for_blocking": entry.rule.approved_for_blocking,
        "admission_evidence": {"status": "present" if entry.admission == "admitted" else "absent",
            "missing": [] if entry.admission == "admitted" else list(_EVIDENCE_FIELDS),
            "hashes": dict(entry.evidence)},
        "config": json.loads(entry.config_json), "dependencies": list(entry.dependencies)}


def _policy_body(policy):
    if type(policy._blocking_policy) is not BlockingPolicy:
        raise TypeError("a typed host blocking policy is required")
    return {"schema_version": 1, "policy_id": policy.policy_id, "policy_version": policy.version,
        "required_rules": [_rule_metadata(entry) for entry in policy._required],
        "blocking_policy": policy._blocking_policy.to_dict(),
        "limits": asdict(policy._limits), "scope": SCOPE, "exit_codes": dict(EXIT_CODES),
        "admission_ready": bool(policy._required) and all(entry.admission == "admitted" for entry in policy._required),
        "gate_implementation_sha256": _implementation()}


def _policy_identity(policy):
    return tuple((id(entry), id(entry.rule), id(entry.rule.evaluator)) for entry in policy._required)


def _build_policy(policy_id, version, required, *, limits=None, blocking_policy=None):
    """Internal trusted-tool construction, used by tool-owned synthetic tests."""
    if (type(policy_id) is not str or not policy_id or type(version) is not str or not version
            or type(required) is not tuple or any(type(entry) is not _RequiredRule for entry in required)
            or len(required) > 32 or len({entry.rule.rule_id for entry in required}) != len(required)):
        raise ValueError("invalid host-owned required catalogue")
    limits = PreviewLimits() if limits is None else limits
    if type(limits) is not PreviewLimits:
        raise TypeError("trusted fixed limits are required")
    blocking_policy = BlockingPolicy() if blocking_policy is None else blocking_policy
    if type(blocking_policy) is not BlockingPolicy:
        raise TypeError("trusted typed blocking settings are required")
    blocking_policy.__post_init__()
    policy = GatePolicy(policy_id, version, required, limits, blocking_policy)
    key = id(policy)
    reference = weakref.ref(policy, lambda _: _POLICIES.pop(key, None))
    _POLICIES[key] = (reference, _sha(_policy_body(policy)), _policy_identity(policy))
    return policy


def production_policy() -> GatePolicy:
    rule = function_length_rule(80)
    entry = _RequiredRule(rule, "policy_debt", _canonical({"max_function_lines": 80}),
                          callable_hash=_callable_hash(rule.evaluator))
    return _build_policy("codesentry.production.python", "2", (entry,))


def gate_manifest(policy: GatePolicy | None = None) -> dict:
    policy = production_policy() if policy is None else policy
    if type(policy) is not GatePolicy:
        raise TypeError("a live host-issued gate policy is required")
    receipt = _POLICIES.get(id(policy))
    body = _policy_body(policy)
    if (receipt is None or receipt[0]() is not policy or receipt[1] != _sha(body)
            or receipt[2] != _policy_identity(policy)):
        raise ValueError("gate policy identity changed or was not issued by the host")
    return {**body, "policy_sha256": receipt[1]}


def _report(manifest):
    return {"schema_version": 1, "mode": "gate", "language_scope": SCOPE,
        "gate_status": "incomplete", "exit_code": 3,
        "policy": manifest, "policy_sha256": manifest.get("policy_sha256"),
        "blocking_policy": manifest.get("blocking_policy"),
        "required_rules": [{**entry, "checks_attempted": 0, "checks_completed": 0,
                            "completed": False, "completion": "not_applicable"}
                           for entry in manifest.get("required_rules", [])],
        "coverage": {"discovered_python": 0, "attempted_python": 0, "analyzed_python": 0,
            "excluded_python": 0, "other_language_files_not_evaluated": 0,
            "permissions_limited": False, "within_scope_complete": False,
            "whole_repository_evaluated": False, "bytes_accounted_for_budget": 0},
        "access_fingerprint": None, "source_sha256": {}, "findings": [], "issues": [],
        "summary": {"total_findings": 0, "report_only_findings": 0, "blocking_findings": 0,
            "eligible_blocking_findings": 0, "counted_new_findings": 0,
            "allowed_new_findings": manifest.get("blocking_policy", {}).get("max_new_findings", 0),
            "required_rules": len(manifest.get("required_rules", [])), "completed_required_rules": 0,
            "admitted_required_rules": sum(entry["admission"] == "admitted" for entry in manifest.get("required_rules", []))},
        "baseline_summary": {"mode": "annotation_only", "gate_exemptions_applied": 0,
            "preview_approvals_authorize_gate_exemptions": False},
        "formal_acceptance": {"passed": False, "detector_quality_accepted": False,
            "whole_repository_gate": False, "independent_identity_verified": False}}


def gate_error(message, *, status="input_or_permission_error", policy=None) -> dict:
    try:
        manifest = gate_manifest(policy)
    except Exception:
        manifest = {"required_rules": []}
    report = _report(manifest)
    report.update(gate_status="error", exit_code=2)
    # Errors are trusted caller text, never exception repr containing source.
    report["issues"] = [{"status": status, "message": str(message)[:2000]}]
    return report


def evaluate_gate(access: AccessPolicy, *, policy: GatePolicy | None = None,
                  baseline_store=None, baseline_context=None) -> dict:
    """Evaluate required checks using original current Finding credentials.

    Baseline parameters are deliberately annotation-only compatibility inputs;
    neither local preview records nor serialized approvals can exempt a block.
    """
    try:
        policy = production_policy() if policy is None else policy
        manifest = gate_manifest(policy)
    except Exception:
        return gate_error("A current host-issued policy is required", status="invalid_gate_policy", policy=policy)
    report = _report(manifest)
    issues, coverage = report["issues"], report["coverage"]
    contexts, initial_inventory, initial_access = [], None, None
    limits, total_bytes = policy._limits, 0
    completed_files = set()

    def check_scope():
        access.check_current()
        access.refresh_if_changed()
        access.check_current()
        if not access.confirmed or access.root != initial_root or access.fingerprint != initial_access:
            raise AccessDenied("gate file permissions changed")

    def inventory():
        return sorted((relative, decision["mode"]) for relative, _, directory, decision in access.walk(
            file_filter=lambda name: Path(name).suffix.casefold() in PYTHON_SUFFIXES | OTHER_SOURCE_SUFFIXES)
            if not directory)

    try:
        if not isinstance(access, AccessPolicy) or not access.confirmed:
            return gate_error("Confirm a valid source access policy first", policy=policy)
        access.check_current()
        access.refresh_if_changed()
        initial_root, initial_access = access.root, access.fingerprint
        check_scope()
        report["access_fingerprint"] = initial_access
        initial_inventory = inventory()
        check_scope()
        python_files = [name for name, mode in initial_inventory
                        if Path(name).suffix.casefold() in PYTHON_SUFFIXES and mode != "exclude"]
        coverage["discovered_python"] = len(python_files)
        coverage["excluded_python"] = sum(mode == "exclude" and Path(name).suffix.casefold() in PYTHON_SUFFIXES
                                          for name, mode in initial_inventory)
        coverage["other_language_files_not_evaluated"] = sum(mode != "exclude" and Path(name).suffix.casefold() in OTHER_SOURCE_SUFFIXES
                                                            for name, mode in initial_inventory)
        coverage["permissions_limited"] = bool(access.to_dict()["restricted"] or coverage["excluded_python"])
        if not policy._required:
            issues.append({"status": "required_rules_empty"})
        if not python_files:
            issues.append({"status": "no_applicable_python"})
        for entry in policy._required:
            if entry.admission != "admitted":
                issues.append({"status": "required_rule_not_admitted", "rule_id": entry.rule.rule_id})
        for relative in python_files:
            if coverage["attempted_python"] >= limits.max_files or total_bytes >= limits.max_total_bytes:
                issues.append({"status": "budget_exhausted", "file": relative})
                break
            coverage["attempted_python"] += 1
            file_complete = True
            for index, entry in enumerate(policy._required):
                row = report["required_rules"][index]
                row["checks_attempted"] += 1
                if total_bytes >= limits.max_total_bytes:
                    issues.append({"status": "budget_exhausted", "file": relative, "rule_id": entry.rule.rule_id})
                    file_complete = False
                    continue
                reservation = min(limits.max_file_bytes, limits.max_total_bytes - total_bytes)
                # Reserve the entire failed read; successful reads refund only known bytes.
                total_bytes += reservation
                context = None
                try:
                    if _callable_hash(entry.rule.evaluator) != entry.callable_hash:
                        raise ValueError("required callable differs from the frozen catalogue")
                    context = VerificationContext(access, entry.rule, file=relative, dependencies=entry.dependencies,
                        policy_identity={"gate_policy_sha256": manifest["policy_sha256"], "required_rule": _rule_metadata(entry)},
                        max_file_bytes=reservation, max_total_bytes=reservation)
                    total_bytes -= reservation - context.input_bytes
                    observed = context.evaluate()
                    contexts.append((index, relative, context, observed))
                except SyntaxError:
                    issues.append({"status": "syntax_error", "file": relative, "rule_id": entry.rule.rule_id})
                    file_complete = False
                except AccessDenied:
                    raise
                except Exception:
                    issues.append({"status": "input_or_rule_incomplete", "file": relative, "rule_id": entry.rule.rule_id})
                    file_complete = False
                finally:
                    if context is not None and not any(item[2] is context for item in contexts):
                        context.close()
            if file_complete and policy._required:
                completed_files.add(relative)
        check_scope()
        if inventory() != initial_inventory:
            issues.append({"status": "source_inventory_changed"})
        check_scope()
        if access.issues:
            issues.append({"status": "access_scope_incomplete"})
        gate_manifest(policy)
        # First validate every context, including negative-result files. Recheck
        # original Finding receipts immediately before building report rows.
        valid = []
        counts = Counter()
        for index, relative, context, observed in contexts:
            entry = policy._required[index]
            try:
                context.check_current()
                if type(observed) not in {tuple, list}:
                    raise ValueError("invalid observation output")
                for finding in observed:
                    if (type(finding) is not Finding or finding.file != relative
                            or finding.rule_id != entry.rule.rule_id or finding.rule_version != entry.rule.version):
                        raise ValueError("unknown finding receipt")
                    counts[_occurrence_key(finding)] += 1
                valid.append((index, relative, context, observed))
            except Exception:
                completed_files.discard(relative)
                issues.append({"status": "source_or_rule_changed", "file": relative, "rule_id": entry.rule.rule_id})
        staged = []
        for index, relative, context, observed in valid:
            entry, rows = policy._required[index], []
            ambiguous = False
            try:
                for finding in observed:
                    duplicate = counts[_occurrence_key(finding)] != 1
                    ambiguous = ambiguous or duplicate
                    current_receipt = finding.can_block(context)
                    if entry.admission == "admitted" and not current_receipt:
                        raise ValueError("invalid_finding_receipt")
                    eligible = (entry.admission == "admitted" and current_receipt
                                and not duplicate
                                and finding.severity.value in manifest["blocking_policy"]["block_severities"])
                    rows.append({"finding": finding.model_dump(mode="json"), "classification": entry.classification,
                        "mode": "report_only", "can_block": current_receipt,
                        "eligible_for_blocking": eligible, "blocking": False, "file": finding.file,
                        "count_status": "ambiguous" if duplicate else "counted" if eligible else "ineligible"})
                context.check_current()
                previous = report["source_sha256"].get(relative)
                if previous is not None and previous != context.input.raw_sha256:
                    raise ValueError("source_or_rule_changed")
                report["source_sha256"][relative] = context.input.raw_sha256
                staged.append((index, relative, context, observed, rows, ambiguous))
                if ambiguous:
                    completed_files.discard(relative)
                    issues.append({"status": "duplicate_finding", "file": relative, "rule_id": entry.rule.rule_id})
            except Exception as error:
                completed_files.discard(relative)
                status = str(error) if str(error) in {"duplicate_finding", "invalid_finding_receipt"} else "source_or_rule_changed"
                issues.append({"status": status, "file": relative, "rule_id": entry.rule.rule_id})
        # Revisit negative checks as well as positives after all receipt reads.
        # A different rule's callback cannot leave an earlier stale result current.
        for index, relative, context, observed, rows, ambiguous in staged:
            try:
                context.check_current()
                if policy._required[index].admission == "admitted" and any(not finding.can_block(context) for finding in observed):
                    raise ValueError("expired receipt")
                context.check_current()
                report["findings"].extend(rows)
                if not ambiguous:
                    report["required_rules"][index]["checks_completed"] += 1
            except Exception:
                completed_files.discard(relative)
                report["source_sha256"].pop(relative, None)
                issues.append({"status": "source_or_rule_changed", "file": relative,
                               "rule_id": policy._required[index].rule.rule_id})
        check_scope()
        if inventory() != initial_inventory and not any(item["status"] == "source_inventory_changed" for item in issues):
            issues.append({"status": "source_inventory_changed"})
        check_scope()
        gate_manifest(policy)
    except AccessDenied:
        # Revocation discards all old content, including confirmed old blockers.
        report["findings"].clear()
        report["source_sha256"].clear()
        completed_files.clear()
        issues.clear()
        for row in report["required_rules"]:
            row["checks_completed"] = 0
        issues.append({"status": "access_scope_changed" if initial_inventory is not None else "input_or_permission_error"})
        if initial_inventory is None:
            report.update(gate_status="error", exit_code=2)
    except Exception:
        report["findings"].clear()
        report["source_sha256"].clear()
        completed_files.clear()
        for row in report["required_rules"]:
            row["checks_completed"] = 0
        issues.append({"status": "policy_identity_changed" if initial_inventory is not None else "input_or_permission_error"})
        report.update(gate_status="error", exit_code=2)
    finally:
        for _, _, context, _ in contexts:
            context.close()
    coverage["analyzed_python"] = len(completed_files)
    coverage["bytes_accounted_for_budget"] = total_bytes
    for row in report["required_rules"]:
        row["completed"] = bool(coverage["discovered_python"]) and row["checks_completed"] == coverage["discovered_python"]
        row["completion"] = "complete" if row["completed"] else "incomplete" if coverage["discovered_python"] else "not_applicable"
    complete = bool(report["required_rules"]) and bool(coverage["discovered_python"]) and all(row["completed"] for row in report["required_rules"])
    coverage["within_scope_complete"] = complete and not any(issue["status"] != "required_rule_not_admitted" for issue in issues)
    # With no gate-exemption flow, each unique eligible occurrence is new.
    # Keep every observation; a count allowance affects only the gate decision.
    eligible_rows = sorted((row for row in report["findings"] if row["eligible_for_blocking"]),
                           key=lambda row: tuple(row["finding"][name] for name in
                               ("rule_id", "rule_version", "file", "symbol", "anchor", "occurrence")))
    allowed = manifest["blocking_policy"]["max_new_findings"]
    for ordinal, row in enumerate(eligible_rows):
        row["blocking"] = ordinal >= allowed
        row["mode"] = "blocking" if row["blocking"] else "report_only"
    blocking = sum(row["blocking"] for row in report["findings"])
    report["summary"].update(total_findings=len(report["findings"]), blocking_findings=blocking,
        eligible_blocking_findings=len(eligible_rows), counted_new_findings=len(eligible_rows),
        report_only_findings=len(report["findings"]) - blocking,
        completed_required_rules=sum(row["completed"] for row in report["required_rules"]))
    if report["gate_status"] != "error":
        status = "block" if blocking else "incomplete" if issues or not complete or not manifest["admission_ready"] else "pass"
        report.update(gate_status=status, exit_code=EXIT_CODES[status])
    return report
