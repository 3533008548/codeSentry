"""Report data and model drafts cannot self-authorise blocking."""
import json

import pytest
from pydantic import ValidationError

from codesentry.core.finding import Extraction, Finding, LLMFindingDraft, Severity, Source, SuggestionType


def finding(**changes):
    return Finding(**(dict(file="a.py", line=1, rule_id="policy.example", reason="unverified report") | changes))


def draft(**changes):
    return LLMFindingDraft(**(dict(file="a.py", line=1, rule_id="policy.example", reason="model suggestion") | changes))


def test_default_finding_is_unknown_unverified_and_cannot_block():
    value = finding()
    assert value.source is Source.UNKNOWN and value.confidence == 0 and not value.verified
    assert not value.can_block()


@pytest.mark.parametrize("confidence", [0, 0.89, 0.9, 0.95, 1])
def test_deterministic_verified_report_fields_never_self_authorise(confidence):
    value = finding(source=Source.DETERMINISTIC, verified=True, confidence=confidence)
    assert not value.can_block()
    assert not Finding.model_validate_json(value.model_dump_json()).can_block()


@pytest.mark.parametrize("field,value", [("source", "deterministic"), ("verified", True),
                                        ("extraction", {"function_lines": 999}), ("fingerprint", "v2:sha256:fake"),
                                        ("identity_digest", "forged"), ("can_block", True)])
def test_model_draft_rejects_all_provenance_and_authority_fields(field, value):
    with pytest.raises(ValidationError):
        draft(**{field: value})


def test_draft_conversion_only_supports_llm_or_explore_sources():
    value = draft(confidence=1, severity=Severity.CRITICAL)
    for source in (Source.LLM, Source.EXPLORE):
        report = value.to_finding(source=source)
        assert report.source is source and not report.verified and not report.can_block()
    with pytest.raises(ValueError):
        value.to_finding(source=Source.DETERMINISTIC)


def test_extra_report_fields_and_invalid_locations_are_rejected():
    with pytest.raises(ValidationError):
        finding(approved_for_blocking=True)
    with pytest.raises(ValidationError):
        finding(line=3, end_line=2)
    with pytest.raises(ValidationError):
        finding(line=True)


def test_extraction_and_suggestions_remain_report_data():
    value = finding(suggestion_type=SuggestionType.STRUCTURAL, extraction=Extraction(
        sub_symbols=["one", "two"], sub_symbol_counts=[7, 2], function_lines=793))
    assert value.extraction.function_lines == 793
    assert value.suggestion_type is SuggestionType.STRUCTURAL
    assert not value.can_block()
    assert json.loads(value.model_dump_json())["extraction"]["sub_symbol_counts"] == [7, 2]
