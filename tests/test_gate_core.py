"""Tool-owned synthetic admitted rules; no production admission API or targets."""
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import pickle
import subprocess
import sys

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.core.finding import Finding, Severity
from codesentry.review import gate
from codesentry.review.scan import PreviewLimits
from codesentry.review.verification import RuleObservation, TrustedRuleSpec, VerificationContext, _callable_hash


def synthetic_rule(name="synthetic.required", *, mode="finding", mutation_path=None, threshold=None, approved=True,
                   severity="high", occurrences=1):
    def evaluate(source):
        if threshold is not None and len(source.text.splitlines()) <= threshold[0]:
            return ()
        if mode == "error":
            raise RuntimeError("synthetic rule failed")
        if mode == "syntax":
            raise SyntaxError("synthetic parse failure")
        if mode in {"mutate", "add"}:
            Path(mutation_path).write_text("changed = True\n", encoding="utf-8")
        if mode in {"clean", "mutate", "add"}:
            return ()
        findings = tuple(RuleObservation(source.file, 1, 1, source.file + "::subject", "synthetic-anchor", occurrence,
                                  "trusted synthetic check", Severity(severity), facts={"classification": "behavior_bug"})
                         for occurrence in range(1, occurrences + 1))
        return (findings[0], findings[0]) if mode == "duplicate" else tuple(reversed(findings)) if mode == "reverse" else findings
    return TrustedRuleSpec(name, "1", hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), evaluate,
                           approved_for_blocking=approved)


def required(rule=None, *, admitted=True):
    rule = synthetic_rule(approved=admitted) if rule is None else rule
    return gate._RequiredRule(rule, "behavior_bug", admission="admitted" if admitted else "report_only",
        evidence=tuple((name, hashlib.sha256(("synthetic-only:" + name).encode()).hexdigest())
                       for name in gate._EVIDENCE_FIELDS) if admitted else (),
        callable_hash=_callable_hash(rule.evaluator))


def policy(*entries, limits=None, blocking_policy=None):
    return gate._build_policy("tool-owned.synthetic-fixture", "1", tuple(entries), limits=limits,
                              blocking_policy=blocking_policy)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "synthetic-project"
    root.mkdir()
    (root / "a.py").write_text("value = 1\n", encoding="utf-8")
    return root, AccessPolicy(root, confirmed=True)


def statuses(report):
    return {issue["status"] for issue in report["issues"]}


def test_production_manifest_is_fixed_report_only_with_absent_effect_evidence():
    manifest = gate.gate_manifest()
    assert manifest["policy_id"] == "codesentry.production.python"
    assert manifest["policy_version"] == "2"
    assert manifest["blocking_policy"] == {"block_severities": ["critical", "high"], "max_new_findings": 0,
                                          "count_unit": "unique_issue_occurrences"}
    assert manifest["scope"] == "permitted_python_files_only"
    assert manifest["exit_codes"] == {"pass": 0, "block": 1, "incomplete": 3, "error": 2}
    assert not manifest["admission_ready"]
    entry, = manifest["required_rules"]
    assert entry["rule_id"] == "python.function_length" and entry["rule_version"] == "1"
    assert entry["config"] == {"max_function_lines": 80}
    assert entry["classification"] == "policy_debt" and entry["admission"] == "report_only"
    assert not entry["approved_for_blocking"]
    assert entry["admission_evidence"]["status"] == "absent"
    assert set(entry["admission_evidence"]["missing"]) == set(gate._EVIDENCE_FIELDS)
    assert len(manifest["policy_sha256"]) == 64
    assert gate.gate_manifest() == manifest


def test_production_zero_findings_complete_check_still_incomplete(project):
    _, access = project
    report = gate.evaluate_gate(access)
    assert report["gate_status"] == "incomplete" and report["exit_code"] == 3
    assert report["findings"] == []
    assert report["coverage"]["within_scope_complete"]
    assert report["required_rules"][0]["completion"] == "complete"
    assert report["required_rules"][0]["checks_completed"] == 1
    assert statuses(report) == {"required_rule_not_admitted"}


def test_production_policy_debt_is_report_only_and_never_a_block(project):
    root, access = project
    (root / "a.py").write_text("def long_function():\n" + "    value = 1\n" * 81)
    report = gate.evaluate_gate(access)
    assert report["gate_status"] == "incomplete" and report["summary"]["blocking_findings"] == 0
    row, = report["findings"]
    assert row["classification"] == "policy_debt" and row["mode"] == "report_only"
    assert row["finding"]["extraction"]["function_lines"] == 82
    assert not row["can_block"] and not row["blocking"]


@pytest.mark.parametrize("shape", ["empty", "excluded", "javascript"])
def test_no_applicable_check_never_passes_even_with_admitted_policy(project, shape):
    root, _ = project
    if shape in {"empty", "javascript"}:
        (root / "a.py").unlink()
    if shape == "javascript":
        (root / "main.js").write_text("export const value = 1;")
    access = AccessPolicy(root, {"exclude": ["a.py"]} if shape == "excluded" else {}, confirmed=True)
    report = gate.evaluate_gate(access, policy=policy(required(synthetic_rule(mode="clean"))))
    assert report["gate_status"] == "incomplete" and "no_applicable_python" in statuses(report)
    assert report["required_rules"][0]["completion"] == "not_applicable"
    assert not report["coverage"]["within_scope_complete"]
    assert not report["coverage"]["whole_repository_evaluated"]
    if shape == "excluded":
        assert report["coverage"]["excluded_python"] == 1
    if shape == "javascript":
        assert report["coverage"]["other_language_files_not_evaluated"] == 1


def test_empty_required_catalogue_cannot_vacuously_pass(project):
    _, access = project
    report = gate.evaluate_gate(access, policy=policy())
    assert report["gate_status"] == "incomplete" and "required_rules_empty" in statuses(report)
    assert not report["policy"]["admission_ready"]


def test_admitted_check_completes_without_findings_and_passes_only_python_scope(project):
    root, access = project
    (root / "main.ts").write_text("export const value = 1;")
    report = gate.evaluate_gate(access, policy=policy(required(synthetic_rule(mode="clean"))))
    assert report["gate_status"] == "pass" and report["exit_code"] == 0
    assert report["issues"] == [] and report["findings"] == []
    assert report["coverage"]["discovered_python"] == report["coverage"]["analyzed_python"] == 1
    assert report["coverage"]["within_scope_complete"]
    assert not report["coverage"]["whole_repository_evaluated"]
    assert report["source_sha256"] == {"a.py": hashlib.sha256((root / "a.py").read_bytes()).hexdigest()}
    assert report["summary"]["completed_required_rules"] == report["summary"]["admitted_required_rules"] == 1


def test_current_original_admitted_finding_blocks(project):
    _, access = project
    report = gate.evaluate_gate(access, policy=policy(required()))
    assert report["gate_status"] == "block" and report["exit_code"] == 1
    row, = report["findings"]
    assert row["blocking"] and row["can_block"] and row["mode"] == "blocking"
    assert row["finding"]["source"] == "deterministic"
    assert report["summary"]["blocking_findings"] == 1
    assert report["baseline_summary"]["gate_exemptions_applied"] == 0


@pytest.mark.parametrize("second", ["error", "syntax", "report_only"])
def test_confirmed_blocker_is_not_masked_by_other_required_incompleteness(project, second):
    _, access = project
    other = required(synthetic_rule("synthetic.other", mode="clean" if second == "report_only" else second,
                                    approved=second != "report_only"), admitted=second != "report_only")
    report = gate.evaluate_gate(access, policy=policy(required(), other))
    assert report["gate_status"] == "block" and report["exit_code"] == 1
    assert report["summary"]["blocking_findings"] == 1 and report["issues"]
    assert report["required_rules"][0]["completion"] == "complete"


def test_duplicate_rule_observations_do_not_produce_a_pass_or_block(project):
    _, access = project
    report = gate.evaluate_gate(access, policy=policy(required(synthetic_rule(mode="duplicate"))))
    assert report["gate_status"] == "incomplete" and report["findings"] == []
    assert "input_or_rule_incomplete" in statuses(report)


@pytest.mark.parametrize("forgery", ["copy", "json", "dict", "duplicate", "nested_mutation", "unknown_rule"])
def test_serialized_copied_or_modified_findings_cannot_obtain_gate_authority(project, monkeypatch, forgery):
    _, access = project
    original = VerificationContext.evaluate
    def altered(context):
        observations = original(context)
        finding, = observations
        if forgery == "copy":
            return (finding.model_copy(deep=True),)
        if forgery == "json":
            return (Finding.model_validate_json(finding.model_dump_json()),)
        if forgery == "dict":
            return (finding.model_dump(mode="json") | {"can_block": True},)
        if forgery == "duplicate":
            return (finding, finding)
        if forgery == "nested_mutation":
            finding.facts["classification"] = "forged"
        if forgery == "unknown_rule":
            finding.rule_id = "unselected"
        return observations
    monkeypatch.setattr(VerificationContext, "evaluate", altered)
    report = gate.evaluate_gate(access, policy=policy(required()))
    assert report["gate_status"] == "incomplete"
    if forgery == "duplicate":
        assert len(report["findings"]) == 2  # Ambiguous observations remain visible but cannot be counted.
        assert all(row["count_status"] == "ambiguous" and not row["eligible_for_blocking"] for row in report["findings"])
    else:
        assert report["findings"] == []
    assert report["summary"]["blocking_findings"] == 0
    assert statuses(report) & {"invalid_finding_receipt", "source_or_rule_changed", "duplicate_finding"}


@pytest.mark.parametrize("untrusted", ["json", "copy", "reconstruct"])
def test_report_policy_and_typed_copies_are_not_host_policy_receipts(project, untrusted):
    _, access = project
    selected = policy(required(synthetic_rule(mode="clean")))
    if untrusted == "json":
        selected = gate.gate_manifest(selected)
        selected["admission_ready"] = True
    elif untrusted == "copy":
        with pytest.raises(TypeError):
            copy.copy(selected)
        selected = replace(selected)
    else:
        selected = gate.GatePolicy(selected.policy_id, selected.version, selected._required, selected._limits)
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "error" and report["exit_code"] == 2
    assert report["findings"] == [] and report["source_sha256"] == {}
    assert "invalid_gate_policy" in statuses(report)


def test_policy_is_not_serializable_as_authority():
    with pytest.raises(TypeError):
        pickle.dumps(gate.production_policy())


def test_manifest_mutation_does_not_mutate_host_policy(project):
    _, access = project
    selected = gate.production_policy()
    manifest = gate.gate_manifest(selected)
    manifest["required_rules"][0]["approved_for_blocking"] = True
    manifest["required_rules"][0]["admission"] = "admitted"
    manifest["required_rules"][0]["config"]["max_function_lines"] = 1
    assert gate.evaluate_gate(access, policy=selected)["gate_status"] == "incomplete"
    assert gate.gate_manifest(selected)["required_rules"][0]["config"] == {"max_function_lines": 80}


def test_production_rule_cannot_be_admitted_by_private_synthetic_constructor():
    selected = replace(gate.function_length_rule(80), approved_for_blocking=True)
    with pytest.raises(ValueError, match="production rule"):
        required(selected)


def test_admission_requires_all_evidence_and_approved_rule():
    selected = synthetic_rule()
    with pytest.raises(ValueError, match="admission evidence"):
        gate._RequiredRule(selected, "behavior_bug", admission="admitted", callable_hash=_callable_hash(selected.evaluator))
    with pytest.raises(ValueError):
        required(synthetic_rule(approved=False))


def test_synthetic_rollback_requires_host_issuance_and_rechecks_the_project(project):
    root, access = project
    production_before = gate.gate_manifest()
    policy_id = "tool-owned.synthetic-rollback"
    known_good = (required(synthetic_rule(mode="clean")),)
    failing_release = (required(synthetic_rule()),)

    before = gate.evaluate_gate(access, policy=gate._build_policy(policy_id, "1", known_good))
    release = gate.evaluate_gate(access, policy=gate._build_policy(policy_id, "2", failing_release))
    assert before["gate_status"] == "pass"
    assert release["gate_status"] == "block" and release["summary"]["blocking_findings"] == 1
    assert before["policy_sha256"] != release["policy_sha256"]
    assert before["source_sha256"] == release["source_sha256"]

    replay = gate.evaluate_gate(access, policy=before["policy"])
    assert replay["gate_status"] == "error" and "invalid_gate_policy" in statuses(replay)

    changed = b"value = 2\n"
    (root / "a.py").write_bytes(changed)
    restored = gate.evaluate_gate(access, policy=gate._build_policy(policy_id, "1", known_good))
    assert restored["gate_status"] == "pass"
    assert restored["policy_sha256"] == before["policy_sha256"]
    assert restored["source_sha256"] == {"a.py": hashlib.sha256(changed).hexdigest()}
    assert restored["coverage"]["within_scope_complete"] and restored["summary"]["blocking_findings"] == 0
    assert gate.gate_manifest() == production_before


def test_rule_closure_drift_after_catalogue_freeze_cannot_pass(project):
    _, access = project
    threshold = [0]
    selected = policy(required(synthetic_rule(threshold=threshold)))
    threshold[0] = 10000
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "incomplete"
    assert "input_or_rule_incomplete" in statuses(report)


def test_rule_source_implementation_mismatch_cannot_pass(project):
    _, access = project
    selected = replace(synthetic_rule(mode="clean"), implementation_hash="0" * 64)
    report = gate.evaluate_gate(access, policy=policy(required(selected)))
    assert report["gate_status"] == "incomplete" and not report["coverage"]["within_scope_complete"]


def test_budget_file_limit_and_failed_read_reservations_are_not_success(project):
    root, access = project
    (root / "b.py").write_text("value = 2\n")
    selected = policy(required(synthetic_rule(mode="clean")), limits=PreviewLimits(max_files=1))
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "incomplete" and "budget_exhausted" in statuses(report)
    assert report["coverage"]["attempted_python"] == 1
    selected = policy(required(synthetic_rule(mode="clean")), limits=PreviewLimits(max_file_bytes=1, max_total_bytes=2))
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "incomplete"
    assert report["coverage"]["bytes_accounted_for_budget"] == 2


def test_byte_budget_uses_raw_bytes_and_explicit_dependencies(project):
    root, access = project
    raw = "label = '中文'\n".encode("utf-8-sig")
    (root / "a.py").write_bytes(raw)
    (root / "config.json").write_bytes(b'{"enabled":true}')
    entry = replace(required(synthetic_rule(mode="clean")), dependencies=("config.json",))
    report = gate.evaluate_gate(access, policy=policy(entry))
    assert report["gate_status"] == "pass"
    assert report["coverage"]["bytes_accounted_for_budget"] == len(raw) + len(b'{"enabled":true}')
    assert report["source_sha256"]["a.py"] == hashlib.sha256(raw).hexdigest()


def test_python_syntax_failure_is_required_incomplete(project):
    root, access = project
    (root / "a.py").write_text("def broken(:\n")
    report = gate.evaluate_gate(access)
    assert report["gate_status"] == "incomplete" and "syntax_error" in statuses(report)
    assert report["required_rules"][0]["completion"] == "incomplete"


def test_new_python_file_during_negative_check_is_not_vacuous_pass(project):
    root, access = project
    selected = policy(required(synthetic_rule(mode="add", mutation_path=str(root / "new.py"))))
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "incomplete" and "source_inventory_changed" in statuses(report)


def test_source_drift_in_negative_check_invalidates_completion(project):
    root, access = project
    selected = policy(required(synthetic_rule(mode="mutate", mutation_path=str(root / "a.py"))))
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "incomplete" and report["source_sha256"] == {}
    assert not report["coverage"]["within_scope_complete"]


def test_later_rule_source_change_revokes_an_earlier_blocker(project):
    root, access = project
    other = required(synthetic_rule("synthetic.mutate", mode="mutate", mutation_path=str(root / "a.py")))
    report = gate.evaluate_gate(access, policy=policy(required(), other))
    assert report["gate_status"] == "incomplete" and report["findings"] == []
    assert "source_or_rule_changed" in statuses(report)


def test_permission_revocation_discards_all_old_content(project, monkeypatch):
    _, access = project
    original = VerificationContext.evaluate
    def revoke_after_evaluation(context):
        observations = original(context)
        access.confirmed = False
        return observations
    monkeypatch.setattr(VerificationContext, "evaluate", revoke_after_evaluation)
    report = gate.evaluate_gate(access, policy=policy(required()))
    assert report["gate_status"] == "incomplete" and "access_scope_changed" in statuses(report)
    assert report["findings"] == [] and report["source_sha256"] == {}


@pytest.mark.parametrize("bad", [None, {}, "path", False])
def test_invalid_initial_access_is_structured_error(bad):
    report = gate.evaluate_gate(bad)
    assert report["gate_status"] == "error" and report["exit_code"] == 2
    assert report["coverage"]["discovered_python"] == 0


def test_unconfirmed_access_does_not_read_source(project, monkeypatch):
    root, _ = project
    access = AccessPolicy(root, confirmed=False)
    monkeypatch.setattr(access, "read_bytes", lambda *_args, **_kwargs: pytest.fail("must not read"))
    assert gate.evaluate_gate(access)["gate_status"] == "error"


def test_gate_error_preserves_complete_schema_and_freezes_manifest():
    report = gate.gate_error("missing input")
    assert report["gate_status"] == "error" and report["exit_code"] == 2
    assert report["policy_sha256"] == report["policy"]["policy_sha256"]
    assert report["issues"] == [{"status": "input_or_permission_error", "message": "missing input"}]
    assert report["required_rules"][0]["completion"] == "not_applicable"
    assert report["baseline_summary"]["mode"] == "annotation_only"


@pytest.mark.parametrize("approval", [{"approved": True, "can_block": False}, {"status": "approved", "gate_exemption": True}])
def test_preview_approval_json_cannot_exempt_admitted_blocker(project, approval):
    _, access = project
    report = gate.evaluate_gate(access, policy=policy(required()), baseline_store=approval, baseline_context=approval)
    assert report["gate_status"] == "block"
    assert report["summary"]["blocking_findings"] == 1
    assert report["baseline_summary"]["gate_exemptions_applied"] == 0


def test_existing_trusted_preview_store_is_not_a_gate_exemption(project, tmp_path):
    from codesentry.review.approvals import BaselineContext, BaselineStore
    from codesentry.review.scan import scan_preview
    root, access = project
    (root / "a.py").write_text("def subject():\n    return 1\n")
    current = scan_preview(access, max_function_lines=1)
    current["analysis_id"] = "synthetic-preview"
    context = BaselineContext(root, access.fingerprint, 1, "tool-owned-synthetic", current["policy_sha256"])
    store = BaselineStore(tmp_path / "external-state")
    proposal = store.create_proposal("workspace-a", context, current)
    store.approve("workspace-a", proposal["id"], context, current,
                  [issue["id"] for issue in proposal["issues"]], "reviewed local policy debt", proposal["revision"])
    assert store.annotate("workspace-a", context, current)["baseline"]["approved_exact_matches"] == 1
    report = gate.evaluate_gate(access, policy=policy(required()), baseline_store=store, baseline_context=context)
    assert report["gate_status"] == "block" and report["summary"]["blocking_findings"] == 1
    assert report["baseline_summary"]["gate_exemptions_applied"] == 0


def test_blocking_policy_is_frozen_typed_and_returns_fresh_report_data():
    selected = gate.BlockingPolicy()
    with pytest.raises(FrozenInstanceError):
        selected.max_new_findings = 100
    report = selected.to_dict()
    report["block_severities"].append("low")
    assert selected.to_dict() == {"block_severities": ["critical", "high"], "max_new_findings": 0,
                                  "count_unit": "unique_issue_occurrences"}
    with pytest.raises(TypeError, match="typed blocking"):
        policy(required(), blocking_policy=report)


@pytest.mark.parametrize("fields", [
    {"block_severities": ["critical", "high"]}, {"block_severities": ()},
    {"block_severities": ("high", "high")}, {"block_severities": ("unknown",)},
    {"block_severities": (True,)}, {"block_severities": (Severity.HIGH,)},
    {"max_new_findings": True}, {"max_new_findings": -1}, {"max_new_findings": 0.0},
    {"max_new_findings": "0"}, {"max_new_findings": 10_001},
    {"count_unit": "rows"}, {"count_unit": False},
])
def test_invalid_blocking_configuration_is_rejected(fields):
    with pytest.raises(ValueError, match="severity/count"):
        gate.BlockingPolicy(**fields)


@pytest.mark.parametrize("severity,eligible", [("critical", True), ("high", True), ("medium", False),
                                               ("low", False), ("info", False)])
def test_severity_policy_is_applied_after_live_receipt_validation(project, severity, eligible):
    _, access = project
    report = gate.evaluate_gate(access, policy=policy(required(synthetic_rule(severity=severity))))
    row, = report["findings"]
    assert row["can_block"]  # Minimum original receipt/rule eligibility is separate from severity/count policy.
    assert row["eligible_for_blocking"] is eligible and row["blocking"] is eligible
    assert report["gate_status"] == ("block" if eligible else "pass")
    assert report["summary"]["eligible_blocking_findings"] == int(eligible)
    assert report["summary"]["counted_new_findings"] == int(eligible)
    assert report["summary"]["allowed_new_findings"] == 0
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["report_only_findings"] == int(not eligible)


@pytest.mark.parametrize("occurrences,allowed,status,blocking", [(1, 0, "block", 1), (1, 1, "pass", 0),
                                                               (2, 1, "block", 1), (2, 2, "pass", 0)])
def test_unique_occurrence_count_budget_boundaries_preserve_every_observation(project, occurrences, allowed, status, blocking):
    _, access = project
    selected = policy(required(synthetic_rule(occurrences=occurrences)),
                      blocking_policy=gate.BlockingPolicy(max_new_findings=allowed))
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == status
    assert len(report["findings"]) == occurrences
    assert all(row["eligible_for_blocking"] for row in report["findings"])
    assert sum(row["blocking"] for row in report["findings"]) == blocking
    assert report["summary"]["blocking_findings"] == blocking
    assert report["summary"]["eligible_blocking_findings"] == report["summary"]["counted_new_findings"] == occurrences
    assert report["summary"]["allowed_new_findings"] == allowed
    assert report["blocking_policy"] == report["policy"]["blocking_policy"] == selected._blocking_policy.to_dict()
    assert report["baseline_summary"]["gate_exemptions_applied"] == 0


def test_allowance_uses_stable_identity_order_instead_of_evaluator_row_order(project):
    _, access = project
    selected = policy(required(synthetic_rule(mode="reverse", occurrences=3)),
                      blocking_policy=gate.BlockingPolicy(max_new_findings=1))
    report = gate.evaluate_gate(access, policy=selected)
    assert [row["finding"]["occurrence"] for row in report["findings"]] == [3, 2, 1]
    assert {row["finding"]["occurrence"] for row in report["findings"] if row["blocking"]} == {2, 3}
    assert report["summary"]["counted_new_findings"] == 3


def test_identical_occurrence_numbers_in_distinct_files_are_distinct_issues(project):
    root, access = project
    (root / "b.py").write_text("value = 2\n")
    report = gate.evaluate_gate(access, policy=policy(required(), blocking_policy=gate.BlockingPolicy(max_new_findings=1)))
    assert report["gate_status"] == "block" and report["summary"]["counted_new_findings"] == 2
    assert {row["file"] for row in report["findings"] if row["blocking"]} == {"b.py"}


def test_distinct_rule_identities_do_not_share_counted_occurrences(project):
    _, access = project
    report = gate.evaluate_gate(access, policy=policy(required(), required(synthetic_rule("synthetic.other")),
                                                     blocking_policy=gate.BlockingPolicy(max_new_findings=1)))
    assert report["gate_status"] == "block" and report["summary"]["counted_new_findings"] == 2
    assert report["summary"]["blocking_findings"] == 1


def test_not_over_budget_does_not_mask_other_required_failure(project):
    _, access = project
    selected = policy(required(), required(synthetic_rule("synthetic.broken", mode="error")),
                      blocking_policy=gate.BlockingPolicy(max_new_findings=1))
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "incomplete" and report["summary"]["counted_new_findings"] == 1
    assert report["summary"]["blocking_findings"] == 0
    assert "input_or_rule_incomplete" in statuses(report)


@pytest.mark.parametrize("allowed,status", [(0, "block"), (1, "incomplete")])
def test_ambiguous_rows_stay_visible_but_never_expand_allowance_or_hide_unique_blocker(project, monkeypatch, allowed, status):
    _, access = project
    original = VerificationContext.evaluate
    def duplicate_one(context):
        first, second = original(context)
        return first, first, second
    monkeypatch.setattr(VerificationContext, "evaluate", duplicate_one)
    selected = policy(required(synthetic_rule(occurrences=2)), blocking_policy=gate.BlockingPolicy(max_new_findings=allowed))
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == status and "duplicate_finding" in statuses(report)
    assert report["summary"]["total_findings"] == len(report["findings"]) == 3
    assert report["summary"]["eligible_blocking_findings"] == report["summary"]["counted_new_findings"] == 1
    assert report["summary"]["blocking_findings"] == (1 if allowed == 0 else 0)
    assert sum(row["count_status"] == "ambiguous" for row in report["findings"]) == 2
    assert all(not row["eligible_for_blocking"] for row in report["findings"] if row["finding"]["occurrence"] == 1)


@pytest.mark.parametrize("original_severity,forged", [("low", Severity.HIGH), ("high", Severity.LOW)])
def test_severity_mutation_cannot_select_or_bypass_blocking_policy(project, monkeypatch, original_severity, forged):
    _, access = project
    original = VerificationContext.evaluate
    def forge(context):
        finding, = original(context)
        finding.severity = forged
        finding.confidence = 1  # Claimed certainty cannot repair the expired original receipt.
        return (finding,)
    monkeypatch.setattr(VerificationContext, "evaluate", forge)
    report = gate.evaluate_gate(access, policy=policy(required(synthetic_rule(severity=original_severity))))
    assert report["gate_status"] == "incomplete"
    assert report["summary"]["counted_new_findings"] == report["summary"]["blocking_findings"] == 0
    assert "invalid_finding_receipt" in statuses(report)


def test_blocking_configuration_changes_are_bound_into_host_policy_hash(project):
    _, access = project
    entry = required(synthetic_rule(severity="low"))
    standard = policy(entry)
    count_changed = policy(entry, blocking_policy=gate.BlockingPolicy(max_new_findings=1))
    severity_changed = policy(entry, blocking_policy=gate.BlockingPolicy(block_severities=("low",)))
    assert len({gate.gate_manifest(selected)["policy_sha256"] for selected in (standard, count_changed, severity_changed)}) == 3
    assert gate.evaluate_gate(access, policy=standard)["gate_status"] == "pass"
    assert gate.evaluate_gate(access, policy=severity_changed)["gate_status"] == "block"


def test_in_process_blocking_policy_drift_is_global_error_and_drops_old_evidence(project, monkeypatch):
    _, access = project
    selected = policy(required())
    original = VerificationContext.evaluate
    def change_host_policy(context):
        findings = original(context)
        object.__setattr__(selected._blocking_policy, "max_new_findings", 100)
        return findings
    monkeypatch.setattr(VerificationContext, "evaluate", change_host_policy)
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "error" and report["exit_code"] == 2
    assert report["findings"] == [] and report["source_sha256"] == {}
    assert report["blocking_policy"]["max_new_findings"] == report["summary"]["allowed_new_findings"] == 0
    assert "policy_identity_changed" in statuses(report)


def test_corrupt_typed_blocking_policy_cannot_be_accepted_as_valid_input(project):
    _, access = project
    selected = policy(required())
    object.__setattr__(selected._blocking_policy, "max_new_findings", True)
    report = gate.evaluate_gate(access, policy=selected)
    assert report["gate_status"] == "error" and report["exit_code"] == 2
    assert "invalid_gate_policy" in statuses(report)


def test_production_manifest_hash_is_stable_across_fresh_host_processes():
    # Only imports the tool; no target code or real workspace is opened.
    command = [sys.executable, "-c", "import json; from codesentry.review.gate import gate_manifest; print(json.dumps(gate_manifest(), sort_keys=True))"]
    outputs = [subprocess.run(command, cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
                              timeout=20, check=True).stdout for _ in range(2)]
    first, second = map(json.loads, outputs)
    assert first == second == gate.gate_manifest()
    assert first["policy_version"] == "2" and not first["admission_ready"]
