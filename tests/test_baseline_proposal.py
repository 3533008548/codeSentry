"""Baseline data can suggest review, never grant production exemptions."""
from dataclasses import replace

import pytest

from codesentry.core.fingerprint import FingerprintEvidence, FingerprintIdentity, fingerprint_v2
from codesentry.review.baseline import propose_baseline


def fingerprint(*, occurrence=1, source="source", symbol="m.py::C.run", scope="workspace/m.py", anchor="anchor"):
    return fingerprint_v2(FingerprintIdentity("rule", "1", scope, symbol, anchor, occurrence),
                          FingerprintEvidence(source, {}, {}, "rule-hash", "policy-hash", "analyzer-hash", "python"))


def test_legacy_or_unknown_fingerprints_do_not_transfer_approval():
    proposal = propose_baseline([
        {"id": "old", "fingerprint": "sha1:" + "a" * 40, "approved": True},
        {"id": "unknown", "fingerprint": "v9:other", "approved": True},
    ], [fingerprint()])
    assert [row["status"] for row in proposal["previous_records"]] == [
        "legacy_sha1_requires_migration", "unknown_version_requires_review"]
    assert all(row["approval_claim_ignored"] for row in proposal["previous_records"])
    assert proposal["current_issues"][0]["status"] == "new_issue_pending_review"
    assert not proposal["automatic_exemptions"] and not proposal["production_exemptions_enabled"]


def test_even_exact_v2_json_approved_claim_is_only_a_review_proposal():
    value = fingerprint()
    proposal = propose_baseline([{"id": "known", "fingerprint": value.to_dict(), "approved": True}], [value])
    assert proposal["current_issues"][0]["status"] == "exact_inputs_pending_review"
    assert proposal["previous_records"][0]["current_indices"] == [0]
    assert not proposal["current_issues"][0]["exemption_granted"]
    assert not proposal["authoritative_baseline_written"]


def test_changed_complete_evidence_requires_new_review_despite_stable_identity():
    before, after = fingerprint(), fingerprint(source="source\nchanged after line 12")
    proposal = propose_baseline([{"id": "old", "fingerprint": before.to_dict()}], [after])
    assert proposal["current_issues"][0]["status"] == "evidence_changed_pending_review"
    assert not proposal["previous_records"][0]["exemption_granted"]


def test_copied_issues_keep_occurrence_count_and_do_not_inherit_blanket_exemption():
    first, copied = fingerprint(), fingerprint(occurrence=2)
    proposal = propose_baseline([{"id": "one", "fingerprint": first.to_dict(), "approved": True}], [first, copied])
    assert proposal["current_issue_count"] == 2
    assert [row["status"] for row in proposal["current_issues"]] == ["exact_inputs_pending_review", "new_issue_pending_review"]
    assert all(not row["exemption_granted"] for row in proposal["current_issues"])


def test_ambiguous_duplicate_identity_and_legacy_duplicate_records_are_not_deduplicated():
    value = fingerprint()
    proposal = propose_baseline([{"id": "same", "fingerprint": value.to_dict()}], [value, value])
    assert proposal["current_issue_count"] == 2
    assert proposal["previous_records"][0]["current_indices"] == [0, 1]
    assert all(row["status"] == "ambiguous_identity_pending_review" for row in proposal["current_issues"])
    duplicated_old = propose_baseline([{"id": "old", "fingerprint": value.to_dict()},
                                       {"id": "old", "fingerprint": value.to_dict()}], [value])
    assert duplicated_old["previous_record_count"] == 2
    assert duplicated_old["current_issues"][0]["status"] == "ambiguous_identity_pending_review"


@pytest.mark.parametrize("changes", [{"scope": "other-workspace/m.py"}, {"symbol": "m.py::Other.run"}, {"anchor": "reordered-ambiguous"}])
def test_scope_or_ambiguous_anchor_changes_do_not_transfer_old_record(changes):
    old = fingerprint()
    proposal = propose_baseline([{"id": "old", "fingerprint": old.to_dict()}], [fingerprint(**changes)])
    assert proposal["previous_records"][0]["status"] == "no_current_match_pending_review"
    assert proposal["current_issues"][0]["status"] == "new_issue_pending_review"


def test_reordered_or_new_evidence_never_automatically_exempts_any_occurrence():
    old = [fingerprint(occurrence=1, source="first"), fingerprint(occurrence=2, source="second")]
    current = [fingerprint(occurrence=1, source="second"), fingerprint(occurrence=2, source="first")]
    proposal = propose_baseline([{"id": str(i), "fingerprint": item.to_dict(), "approved": True}
                                for i, item in enumerate(old)], current)
    assert all(row["status"] == "evidence_changed_pending_review" and not row["exemption_granted"]
               for row in proposal["current_issues"])


def test_combined_only_or_inconsistent_v2_report_cannot_suggest_valid_match():
    value = fingerprint()
    bad = dict(value.to_dict(), evidence_digest="v2:sha256:evidence:" + "b" * 64)
    proposal = propose_baseline([{"id": "combined-only", "fingerprint": value.combined_digest},
                                 {"id": "tampered", "fingerprint": bad}], [value])
    assert all(row["status"] == "unknown_version_requires_review" for row in proposal["previous_records"])


def test_empty_proposal_is_not_an_approval_and_current_json_is_rejected():
    proposal = propose_baseline([], [])
    assert proposal["status"] == "pending_human_review" and not proposal["automatic_exemptions"]
    with pytest.raises(ValueError):
        propose_baseline([], [fingerprint().to_dict()])
