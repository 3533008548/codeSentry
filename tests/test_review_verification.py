"""Positive trusted verification and fixed forgery/drift counterexamples."""
import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import pickle

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.core.finding import Extraction, Finding, LLMFindingDraft, Severity, Source
from codesentry.review.verification import RuleObservation, SourceInput, TrustedRuleSpec, VerificationContext, _callable_hash


def rule(*, approved=True, threshold=1, mode="normal", mutation_path=None):
    def evaluate(source):
        length = len(source.text.splitlines())
        if mode == "syntax-error":
            raise SyntaxError("synthetic parse failure")
        if length <= threshold:
            return ()
        result = RuleObservation(source.file, 1, length, source.file + "::subject", "body-policy", 1,
                                 "trusted measured policy observation", Severity.LOW,
                                 Extraction(function_lines=length, extra={"threshold": threshold}),
                                 {"physical_lines": length, "threshold": threshold, "classification": "policy_debt"})
        if mode == "wrong-file":
            result = replace(result, file="other.py")
        if mode == "wrong-line":
            result = replace(result, end_line=length + 1)
        if mode == "change-during-rule":
            Path(mutation_path).write_text("changed by a synthetic host race\n", encoding="utf-8")
        return (result, result) if mode == "duplicate" else (result,)
    return TrustedRuleSpec("policy.synthetic_length", "1", hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                           evaluate, approved_for_blocking=approved)


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "a.py").write_text("def subject():\n    return 'value'\n", encoding="utf-8")
    (source / "config.json").write_text('{"limit":1}', encoding="utf-8")
    access = AccessPolicy(source, {}, confirmed=True)
    selected, policy = rule(), {"scope": "synthetic", "threshold": 1}
    ctx = VerificationContext(access, selected, file="a.py", dependencies=("config.json",), policy_identity=policy)
    yield source, access, selected, policy, ctx
    ctx.close()


def test_trusted_rule_recomputes_complete_finding_and_minimum_eligibility(context):
    _, _, _, _, ctx = context
    finding, = ctx.evaluate()
    assert finding.verified and finding.source is Source.DETERMINISTIC
    assert finding.reason == "trusted measured policy observation" and finding.severity is Severity.LOW
    assert finding.extraction.function_lines == 2 and finding.facts["classification"] == "policy_debt"
    assert finding.identity_digest.startswith("v2:sha256:identity:")
    assert finding.evidence_digest.startswith("v2:sha256:evidence:")
    assert finding.fingerprint == finding.combined_digest and finding.can_block(ctx)
    assert not finding.can_block()
    assert ctx.input.raw_size == len((ctx.access.root / "a.py").read_bytes())
    assert ctx.input_bytes == ctx.input.raw_size + len(ctx.input.dependencies["config.json"])


def test_report_only_rule_verifies_without_blocking_qualification(context):
    _, access, selected, policy, _ = context
    with VerificationContext(access, replace(selected, approved_for_blocking=False), file="a.py", policy_identity=policy) as ctx:
        finding, = ctx.evaluate()
        assert finding.verified and not finding.can_block(ctx)


def test_model_claims_are_replaced_by_rule_recomputation(context):
    _, _, _, _, ctx = context
    draft = LLMFindingDraft(file="a.py", line=1, rule_id=ctx.rule.rule_id, reason="invented critical bug",
                            severity=Severity.CRITICAL, confidence=1, evidence="fabricated snippet")
    finding = ctx.verify(draft)
    assert finding is not None and finding.reason == "trusted measured policy observation"
    assert finding.severity is Severity.LOW and "fabricated" not in finding.evidence
    assert finding.source is Source.LLM and not finding.can_block(ctx)
    assert not draft.to_finding().can_block(ctx)
    independent, = ctx.evaluate()
    assert independent.source is Source.DETERMINISTIC and independent.can_block(ctx)


@pytest.mark.parametrize("origin", [Source.LLM, Source.EXPLORE, Source.DETERMINISTIC, Source.UNKNOWN])
def test_external_report_source_never_selects_a_credential_issuing_route(context, origin):
    _, _, _, _, ctx = context
    report = Finding(file="a.py", line=1, rule_id=ctx.rule.rule_id, source=origin,
                     reason="untrusted model claim", severity=Severity.CRITICAL, verified=True, confidence=1)
    warning = ctx.verify(report)
    expected = origin if origin in {Source.LLM, Source.EXPLORE} else Source.UNKNOWN
    assert warning is not None and warning.source is expected and warning.verified
    assert warning.reason == "trusted measured policy observation" and warning.severity is Severity.LOW
    assert not warning.can_block(ctx)
    warning.source = Source.DETERMINISTIC
    assert not warning.can_block(ctx)  # Recomputed warning objects were never granted receipts.


def test_report_reverification_rebuilds_instead_of_stamping_report_fields(context):
    _, _, _, _, ctx = context
    report = Finding(file="a.py", line=1, rule_id=ctx.rule.rule_id, reason="untrusted", verified=True,
                     source=Source.DETERMINISTIC, extraction=Extraction(function_lines=999))
    assert not report.can_block(ctx)
    verified = ctx.verify(report)
    assert verified is not report and verified.extraction.function_lines == 2
    assert verified.source is Source.UNKNOWN and not verified.can_block(ctx)
    independent, = ctx.evaluate()
    assert independent.source is Source.DETERMINISTIC and independent.can_block(ctx)


@pytest.mark.parametrize("change", [{"file": "other.py"}, {"rule_id": "unselected"}, {"line": 2}, {"symbol": "other.symbol"}])
def test_unmatched_model_locations_do_not_gain_a_credential(context, change):
    _, _, _, _, ctx = context
    fields = dict(file="a.py", line=1, rule_id=ctx.rule.rule_id, reason="untrusted") | change
    assert ctx.verify(LLMFindingDraft(**fields)) is None


@pytest.mark.parametrize("copying", [lambda value: value.model_copy(), lambda value: value.model_copy(deep=True),
                                     copy.copy, copy.deepcopy, lambda value: Finding.model_validate_json(value.model_dump_json()),
                                     lambda value: Finding(**value.model_dump()), lambda value: pickle.loads(pickle.dumps(value))])
def test_serialisation_and_copy_never_transfer_object_receipts(context, copying):
    _, _, _, _, ctx = context
    original, = ctx.evaluate()
    duplicate = copying(original)
    assert duplicate is not original and not duplicate.can_block(ctx) and original.can_block(ctx)


@pytest.mark.parametrize("field,value", [("reason", "changed"), ("severity", Severity.CRITICAL), ("source", Source.LLM),
                                        ("confidence", 0.1), ("verified", False), ("fingerprint", "sha1:forged"),
                                        ("rule_version", "2"), ("anchor", "changed"), ("occurrence", 2), ("symbol", "different")])
def test_observed_field_drift_revokes_receipts_even_after_restoration(context, field, value):
    _, _, _, _, ctx = context
    finding, = ctx.evaluate()
    original = getattr(finding, field)
    setattr(finding, field, value)
    assert not finding.can_block(ctx)
    setattr(finding, field, original)
    assert not finding.can_block(ctx)


@pytest.mark.parametrize("mutate", [lambda value: value.facts.update(physical_lines=999),
                                    lambda value: value.extraction.extra.update(threshold=999),
                                    lambda value: setattr(value.evidence_refs[0], "snippet", "forged"),
                                    lambda value: setattr(value.extraction, "function_lines", 999)])
def test_nested_mutation_revokes_evidence(context, mutate):
    _, _, _, _, ctx = context
    finding, = ctx.evaluate()
    mutate(finding)
    assert not finding.can_block(ctx)


@pytest.mark.parametrize("replacement", ["access", "guard"])
def test_access_object_and_live_guard_are_fixed(context, replacement):
    source, access, _, _, ctx = context
    finding, = ctx.evaluate()
    if replacement == "access":
        ctx.access = AccessPolicy(source, {}, confirmed=True)
    else:
        access.read_guard = lambda: None
    assert not finding.can_block(ctx)


def test_other_context_and_serialisation_cannot_reuse_credentials(context):
    _, access, selected, policy, ctx = context
    finding, = ctx.evaluate()
    with VerificationContext(access, selected, file="a.py", dependencies=("config.json",), policy_identity=policy) as other:
        assert not finding.can_block(other)
    assert finding.can_block(ctx)
    with pytest.raises(TypeError):
        pickle.dumps(ctx)
    with pytest.raises(TypeError):
        copy.copy(ctx)


@pytest.mark.parametrize("path", ["a.py", "config.json"])
def test_input_drift_latches_invalid_even_if_bytes_are_restored(context, path):
    source, _, _, _, ctx = context
    finding, = ctx.evaluate()
    original = (source / path).read_bytes()
    (source / path).write_bytes(original + b"\n# changed input\n")
    assert not finding.can_block(ctx)
    (source / path).write_bytes(original)
    assert not finding.can_block(ctx)
    with pytest.raises(ValueError):
        ctx.check_current()


def test_git_controls_and_policy_changes_revoke_receipts(context):
    source, _, _, policy, ctx = context
    finding, = ctx.evaluate()
    (source / ".gitignore").write_text("a.py\n", encoding="utf-8")
    assert not finding.can_block(ctx)


def test_rule_policy_identity_changes_revoke_receipts(context):
    _, _, _, policy, ctx = context
    finding, = ctx.evaluate()
    policy["threshold"] = 100
    assert not finding.can_block(ctx)


def test_rule_approval_cannot_be_changed_to_promote_old_findings(context):
    _, access, selected, _, _ = context
    with VerificationContext(access, replace(selected, approved_for_blocking=False), file="a.py") as ctx:
        finding, = ctx.evaluate()
        ctx.rule = replace(selected, approved_for_blocking=True)
        assert not finding.can_block(ctx)


@pytest.mark.parametrize("change", ["closure", "code"])
def test_actual_callable_configuration_and_code_changes_are_detected(context, change):
    _, _, _, _, ctx = context
    finding, = ctx.evaluate()
    if change == "closure":
        for name, cell in zip(ctx.rule.evaluator.__code__.co_freevars, ctx.rule.evaluator.__closure__):
            if name == "threshold":
                cell.cell_contents = 100
    else:
        current = ctx.rule.evaluator.__code__
        ctx.rule.evaluator.__code__ = current.replace(co_name=current.co_name + "_changed")
    assert not finding.can_block(ctx)


def test_real_nested_function_rule_first_execution_has_stable_code_identity(context):
    from codesentry.review.rules import function_length_rule
    _, access, _, _, _ = context
    selected = function_length_rule(1)
    source = SourceInput("a.py", "def subject():\n    return 1\n", "a" * 64)
    before = _callable_hash(selected.evaluator)
    selected.evaluator(source)
    assert _callable_hash(selected.evaluator) == before
    with VerificationContext(access, selected, file="a.py", policy_identity={"threshold": 1}) as ctx:
        finding, = ctx.evaluate()
        assert finding.verified and not finding.can_block(ctx)
        ctx.check_current()


def test_negative_results_still_require_current_source(context):
    source, access, _, _, _ = context
    with VerificationContext(access, rule(threshold=100), file="a.py") as ctx:
        assert ctx.evaluate() == ()
        (source / "a.py").write_text("new_generation = True\n", encoding="utf-8")
        with pytest.raises(ValueError):
            ctx.check_current()


@pytest.mark.parametrize("mode", ["wrong-file", "wrong-line", "duplicate", "syntax-error"])
def test_invalid_observations_and_parse_failure_cannot_succeed(context, mode):
    _, access, _, _, _ = context
    with VerificationContext(access, rule(mode=mode), file="a.py") as ctx:
        with pytest.raises((ValueError, SyntaxError)):
            ctx.evaluate()


def test_source_drift_during_evaluation_cannot_mint_evidence(context):
    source, access, _, _, _ = context
    with VerificationContext(access, rule(mode="change-during-rule", mutation_path=str(source / "a.py")), file="a.py") as ctx:
        with pytest.raises(ValueError, match="snapshot changed"):
            ctx.evaluate()


def test_python_encoding_and_raw_byte_size_are_preserved(context):
    source, access, selected, _, _ = context
    raw = b"# coding: cp1252\nvalue = 'caf\xe9'\n"
    (source / "encoded.py").write_bytes(raw)
    with VerificationContext(access, selected, file="encoded.py") as ctx:
        assert "caf\u00e9" in ctx.input.text and ctx.input.raw_size == len(raw)
        assert ctx.input.raw_sha256 == hashlib.sha256(raw).hexdigest()


def test_evidence_digest_covers_raw_bytes_even_when_bom_decodes_to_identical_text(context):
    source, access, selected, _, _ = context
    raw = b"def subject():\n    return 'value'\n"
    (source / "a.py").write_bytes(b"\xef\xbb\xbf" + raw)
    with VerificationContext(access, selected, file="a.py") as first:
        before, = first.evaluate()
        text = first.input.text
    (source / "a.py").write_bytes(raw)
    with VerificationContext(access, selected, file="a.py") as second:
        after, = second.evaluate()
        assert second.input.text == text and before.identity_digest == after.identity_digest
        assert before.evidence_digest != after.evidence_digest


def test_excluded_source_is_denied_before_open(context, monkeypatch):
    source, _, selected, _, _ = context
    access = AccessPolicy(source, {"exclude": ["a.py"]}, confirmed=True)
    original = Path.open
    def forbidden(path, *args, **kwargs):
        if path == source / "a.py":
            pytest.fail("excluded source was opened")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(AccessDenied):
        VerificationContext(access, selected, file="a.py")


def test_bad_rule_identity_does_not_read_target_input(context, monkeypatch):
    _, access, selected, _, _ = context
    monkeypatch.setattr(access, "read_bytes", lambda *args, **kwargs: pytest.fail("unselected rule read source"))
    with pytest.raises(ValueError, match="selected implementation"):
        VerificationContext(access, replace(selected, implementation_hash="0" * 64), file="a.py")


def test_missing_dependencies_and_byte_limits_do_not_become_empty_success(context):
    _, access, selected, _, _ = context
    with pytest.raises(FileNotFoundError):
        VerificationContext(access, selected, file="a.py", dependencies=("missing.json",))
    with pytest.raises(ValueError):
        VerificationContext(access, selected, file="a.py", max_file_bytes=1)
    with pytest.raises(ValueError):
        VerificationContext(access, selected, file="a.py", max_total_bytes=1)


def test_close_revokes_original_findings(context):
    _, _, _, _, ctx = context
    finding, = ctx.evaluate()
    ctx.close()
    assert not finding.can_block(ctx)
