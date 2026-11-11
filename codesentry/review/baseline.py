"""Read-only baseline diagnostics and migration proposals.

There is deliberately no approval/apply/exemption API. Even an exact v2 input
match is a review suggestion. JSON claims cannot authorize an approved baseline,
and a legacy sha1 value cannot transfer its historical exemptions to v2.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence

from codesentry.core.fingerprint import FingerprintV2


def _previous_fingerprint(value) -> tuple[FingerprintV2 | None, str]:
    if type(value) is FingerprintV2:
        return value, "v2"
    if isinstance(value, str) and value.startswith("sha1:"):
        return None, "legacy_sha1_requires_migration"
    if isinstance(value, dict):
        try:
            return FingerprintV2.from_dict(value), "v2"
        except (TypeError, ValueError):
            pass
    return None, "unknown_version_requires_review"


def propose_baseline(previous: Sequence[Mapping], current: Sequence[FingerprintV2]) -> dict:
    """Preserve every issue occurrence and return non-authoritative suggestions.

    Previous records have an id and fingerprint; other metadata, including any
    approved flag, has no authority. Current fingerprints must come from the
    trusted caller's recomputation. The typed value itself confers no trust.
    """
    if (isinstance(previous, (str, bytes)) or not isinstance(previous, Sequence)
            or isinstance(current, (str, bytes)) or not isinstance(current, Sequence)
            or any(type(item) is not FingerprintV2 for item in current)):
        raise ValueError("baseline records and typed current fingerprints are required")
    records, previous_by_identity, current_by_identity = [], defaultdict(list), defaultdict(list)
    for index, row in enumerate(previous):
        if (not isinstance(row, Mapping) or not isinstance(row.get("id"), str)
                or not row["id"] or "fingerprint" not in row):
            raise ValueError("previous records require id and fingerprint")
        fingerprint, status = _previous_fingerprint(row["fingerprint"])
        records.append({"record_index": index, "record_id": row["id"], "status": status,
                        "approval_claim_ignored": "approved" in row, "current_indices": [], "exemption_granted": False})
        if fingerprint is not None:
            previous_by_identity[fingerprint.identity_digest].append((index, fingerprint))
    for index, fingerprint in enumerate(current):
        current_by_identity[fingerprint.identity_digest].append(index)

    issues = []
    for index, fingerprint in enumerate(current):
        matches = previous_by_identity[fingerprint.identity_digest]
        same_current = current_by_identity[fingerprint.identity_digest]
        if len(same_current) > 1 or len(matches) > 1:
            status = "ambiguous_identity_pending_review"
        elif not matches:
            status = "new_issue_pending_review"
        else:
            status = ("exact_inputs_pending_review" if matches[0][1].evidence_digest == fingerprint.evidence_digest
                      else "evidence_changed_pending_review")
        issues.append({"current_index": index, "fingerprint": fingerprint.to_dict(), "status": status,
                       "previous_record_indices": [previous_index for previous_index, _ in matches], "exemption_granted": False})
        for previous_index, _ in matches:
            records[previous_index]["current_indices"].append(index)
            records[previous_index]["status"] = status
    for record in records:
        if record["status"] == "v2":
            record["status"] = "no_current_match_pending_review"
    return {"schema_version": 1, "kind": "baseline-review-proposal", "status": "pending_human_review",
            "previous_record_count": len(records), "current_issue_count": len(issues),
            "previous_records": records, "current_issues": issues,
            "automatic_exemptions": False, "production_exemptions_enabled": False,
            "authoritative_baseline_written": False}
