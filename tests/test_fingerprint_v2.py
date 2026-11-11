"""Input identity, full evidence and immutable context counterexamples."""
from dataclasses import replace
import hashlib
import json

import pytest

from codesentry.core.fingerprint import (
    FingerprintEvidence, FingerprintIdentity, FingerprintV2,
    compute_fingerprint, content_hash, fingerprint_v2, normalize_snippet,
)


def identity(**changes):
    return replace(FingerprintIdentity("rule.length", "1", "workspace-a/src/service.py", "service.py::Service.run",
                                       "structure-anchor", 1), **changes)


def evidence(**changes):
    return replace(FingerprintEvidence("def run():\n    return 'two  words'\n",
        {"physical_lines": 2, "threshold": 1}, {"config.json": {"state": "missing"}},
        "rule-implementation-a", "policy-a", "analyzer-a", "python-3.11",
        config={"mode": "strict"}, environment={"runtime": "declared-3.11"}), **changes)


def test_semantic_changes_after_legacy_twelve_line_cutoff_are_not_lost():
    prefix = "".join(f"field_{index} = {index}\n" for index in range(12))
    left, right = prefix + "result = 1\n", prefix + "result = 2\n"
    assert compute_fingerprint("r", "m.py::f", left) != compute_fingerprint("r", "m.py::f", right)
    assert normalize_snippet(left, 1) == normalize_snippet(left, 0) == left
    assert fingerprint_v2(identity(), evidence(source=left)).evidence_digest != fingerprint_v2(identity(), evidence(source=right)).evidence_digest


def test_string_internal_whitespace_and_suppression_directives_are_kept():
    snippets = ['value = "two  words"\n', 'value = "two words"\n',
                'value = "two  words"  # type: ignore\n', 'value = "two  words"\n\n']
    assert len({fingerprint_v2(identity(), evidence(source=source)).evidence_digest for source in snippets}) == len(snippets)


def test_identity_and_evidence_have_independent_domain_separated_digests():
    original = fingerprint_v2(identity(), evidence())
    changed_source = fingerprint_v2(identity(), evidence(source="changed complete source"))
    changed_identity = fingerprint_v2(identity(structural_anchor="other-anchor"), evidence())
    assert original.identity_digest == changed_source.identity_digest
    assert original.evidence_digest != changed_source.evidence_digest
    assert original.identity_digest != changed_identity.identity_digest
    assert original.evidence_digest == changed_identity.evidence_digest
    assert len({original.combined_digest, changed_source.combined_digest, changed_identity.combined_digest}) == 3
    assert original.identity_digest.startswith("v2:sha256:identity:")
    assert original.evidence_digest.startswith("v2:sha256:evidence:")


@pytest.mark.parametrize("field,value", [
    ("rule_id", "other.rule"), ("rule_version", "2"), ("file_scope", "workspace-b/src/service.py"),
    ("symbol", "service.py::Other.run"), ("structural_anchor", "other-anchor"), ("occurrence", 2),
])
def test_each_issue_identity_dimension_is_bound(field, value):
    assert fingerprint_v2(identity(), evidence()).identity_digest != fingerprint_v2(identity(**{field: value}), evidence()).identity_digest


@pytest.mark.parametrize("field,value", [
    ("source", "changed source beyond any display budget"), ("facts", {"physical_lines": 3, "threshold": 1}),
    ("dependencies", {"config.json": {"state": "present", "sha256": "a" * 64}}),
    ("rule_implementation", "rule-implementation-b"), ("policy", "policy-b"),
    ("analyzer", "analyzer-b"), ("language", "python-3.12"), ("normalization", "raw-v2"),
    ("config", {"mode": "permissive"}), ("environment", {"runtime": "declared-3.12"}),
])
def test_each_evidence_dependency_changes_combined_without_changing_issue_identity(field, value):
    original = fingerprint_v2(identity(), evidence())
    changed = fingerprint_v2(identity(), evidence(**{field: value}))
    assert original.identity_digest == changed.identity_digest
    assert original.evidence_digest != changed.evidence_digest
    assert original.combined_digest != changed.combined_digest


def test_absent_dependency_and_undeclared_dependency_are_distinct():
    assert fingerprint_v2(identity(), evidence(dependencies={})).evidence_digest != fingerprint_v2(identity(), evidence()).evidence_digest


def test_input_dict_order_does_not_change_digest_but_arrays_keep_order():
    left = evidence(facts={"a": 1, "b": [1, 2]})
    right = evidence(facts={"b": [1, 2], "a": 1})
    assert fingerprint_v2(identity(), left) == fingerprint_v2(identity(), right)
    assert fingerprint_v2(identity(), left) != fingerprint_v2(identity(), evidence(facts={"b": [2, 1], "a": 1}))


def test_context_deep_freezes_aliases_and_exported_dict_cannot_modify_it():
    facts = {"nested": [{"threshold": 10}]}
    context = evidence(facts=facts)
    expected = fingerprint_v2(identity(), context)
    facts["nested"][0]["threshold"] = 999
    exported = context.to_dict()
    exported["facts"]["nested"][0]["threshold"] = 1000
    assert fingerprint_v2(identity(), context) == expected
    with pytest.raises(TypeError):
        context.facts["new"] = "forbidden"


def test_roundtrip_checks_schema_and_combined_consistency_without_issuing_authority():
    value = fingerprint_v2(identity(), evidence())
    assert FingerprintV2.from_dict(json.loads(json.dumps(value.to_dict()))) == value
    for document in (dict(value.to_dict(), approved=True), dict(value.to_dict(), version=True),
                     dict(value.to_dict(), combined_digest="v2:sha256:" + "a" * 64)):
        with pytest.raises(ValueError):
            FingerprintV2.from_dict(document)


@pytest.mark.parametrize("value", [0, -1, True, 1.0])
def test_occurrence_requires_positive_integer(value):
    with pytest.raises(ValueError):
        identity(occurrence=value)


@pytest.mark.parametrize("value", [{"bad": float("nan")}, {"bad": object()}, {1: "non-string-key"}])
def test_evidence_rejects_non_json_values(value):
    with pytest.raises(ValueError):
        evidence(facts=value)


def test_typed_function_rejects_a_report_dict_as_context():
    with pytest.raises(TypeError):
        fingerprint_v2(identity().to_dict(), evidence())


def test_cache_sha1_contract_stays_byte_compatible_and_legacy_report_digest_is_v2():
    assert content_hash("abc") == hashlib.sha1(b"abc").hexdigest()
    assert content_hash("\ud800") == hashlib.sha1("\ud800".encode("utf-8", errors="replace")).hexdigest()
    assert compute_fingerprint("r", None, "source", 12).startswith("v2:sha256:")
    assert not compute_fingerprint("r", None, "source", 12).startswith("sha1:")
