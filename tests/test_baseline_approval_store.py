"""Explicit local decisions, exact occurrence matching, and atomic review state."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import threading

import pytest

from codesentry.access import AccessPolicy
from codesentry.review.approvals import BaselineConflict, BaselineContext, BaselineStore
from codesentry.review.scan import scan_preview


PROVENANCE = "web-analysis-v1:" + "a" * 64


def code(name="subject"):
    return f"def {name}():\n    first = 1\n    second = 2\n    return first + second\n"


@pytest.fixture
def state(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.py").write_text(code(), encoding="utf-8")
    access = AccessPolicy(root, {}, confirmed=True)
    current = scan_preview(access, max_function_lines=2)
    current["analysis_id"] = "trusted-analysis-1"
    context = BaselineContext(root, access.fingerprint, 1, PROVENANCE, current["policy_sha256"])
    store = BaselineStore(tmp_path / "external-state")
    return root, access, current, context, store


def propose(state):
    _, _, current, context, store = state
    return store.create_proposal("workspace-a", context, current)


def approve(state, proposal=None):
    _, _, current, context, store = state
    proposal = proposal or propose(state)
    return store.approve("workspace-a", proposal["id"], context, current,
                         [issue["id"] for issue in proposal["issues"] if issue["status"] == "pending"],
                         "local user reviewed this policy debt", proposal["revision"])


def test_explicit_decision_is_saved_and_exactly_annotated_without_hiding_or_gate_pass(state):
    _, _, current, context, store = state
    proposal = propose(state)
    assert proposal["status"] == "pending" and proposal["source_analysis_id"] == current["analysis_id"]
    assert len(proposal["issues"]) == 1 and proposal["issues"][0]["status"] == "pending"
    assert store.snapshot("workspace-a", context)["records"] == []
    result = approve(state, proposal)
    assert result["revision"] == 2 and len(result["records"]) == 1
    record = result["records"][0]
    assert record["status"] == "approved" and record["actor"] == "local_user"
    assert record["approval_reason"] == "local user reviewed this policy debt"
    assert record["source_analysis_id"] == current["analysis_id"]
    annotated = store.annotate("workspace-a", context, current)
    assert len(annotated["findings"]) == len(current["findings"]) == 1
    assert annotated["findings"][0]["finding"] == current["findings"][0]["finding"]
    assert annotated["findings"][0]["baseline"]["status"] == "approved"
    assert not annotated["findings"][0]["baseline"]["exemption_applied"]
    assert annotated["gate_status"] == "not_evaluated" and not annotated["formal_acceptance"]["passed"]
    assert not result["independent_identity_verified"]


def test_revoke_is_explicit_audited_and_keeps_the_issue_visible(state):
    _, _, current, context, store = state
    approved = approve(state)
    record_id = approved["approved_record_ids"][0]
    result = store.revoke("workspace-a", record_id, context, "reopen the previous decision", approved["revision"])
    assert result["records"][0]["status"] == "revoked"
    assert result["records"][0]["revocation_reason"] == "reopen the previous decision"
    assert store.annotate("workspace-a", context, current)["findings"][0]["baseline"]["status"] == "revoked"
    assert [row["action"] for row in result["audit"]] == ["proposal_created", "issues_approved", "approval_revoked"]
    assert all(row["actor"] == "local_user" for row in result["audit"])
    with pytest.raises(BaselineConflict):
        store.revoke("workspace-a", record_id, context, "duplicate revoke", result["revision"])


def test_positive_fresh_rescan_ignores_only_volatile_finding_timestamps(state):
    _, access, current, context, store = state
    proposal = propose(state)
    fresh = scan_preview(access, max_function_lines=2)
    fresh["analysis_id"] = current["analysis_id"]
    assert fresh["findings"][0]["finding"]["created_at"] != current["findings"][0]["finding"]["created_at"]
    result = store.approve("workspace-a", proposal["id"], context, fresh, [proposal["issues"][0]["id"]],
                           "same complete current inputs", proposal["revision"])
    assert len(result["approved_record_ids"]) == 1


def test_extra_imported_approval_flags_never_create_local_decisions(state):
    _, _, current, context, store = state
    imported = deepcopy(current)
    imported["approved"] = True
    imported["records"] = [{"approved": True, "actor": "trusted-ci"}]
    imported["findings"][0]["baseline"] = {"status": "approved", "record_id": "forged"}
    proposal = store.create_proposal("workspace-a", context, imported)
    assert proposal["issues"][0]["status"] == "pending" and store.snapshot("workspace-a", context)["records"] == []
    assert store.annotate("workspace-a", context, imported)["findings"][0]["baseline"]["status"] == "new"


def test_repository_baseline_file_is_never_read(state, monkeypatch):
    root, _, _, _, _ = state
    path = root / ".codesentry-baseline.json"
    path.write_text('{"approved":true}', encoding="utf-8")
    original = Path.open
    def forbidden(selected, *args, **kwargs):
        if selected == path:
            pytest.fail("repository baseline content was read")
        return original(selected, *args, **kwargs)
    monkeypatch.setattr(Path, "open", forbidden)
    assert approve(state)["records"][0]["actor"] == "local_user"


def test_byte_or_semantic_source_drift_needs_a_new_review_before_approval(state):
    root, access, current, context, store = state
    proposal = propose(state)
    (root / "a.py").write_text(code().replace("second = 2", "second = 3"), encoding="utf-8")
    fresh = scan_preview(access, max_function_lines=2)
    fresh["analysis_id"] = current["analysis_id"]
    with pytest.raises(BaselineConflict):
        store.approve("workspace-a", proposal["id"], context, fresh, [proposal["issues"][0]["id"]], "changed source", proposal["revision"])
    assert store.snapshot("workspace-a", context)["records"] == []


@pytest.mark.parametrize("field,value", [("access_fingerprint", "c" * 64), ("access_version", 2),
                                        ("analysis_provenance", "web-analysis-v2:" + "d" * 64),
                                        ("policy_sha256", "e" * 64)])
def test_context_drift_never_reuses_pending_decisions_or_approved_records(state, field, value):
    _, _, current, context, store = state
    proposal = propose(state)
    changed = replace(context, **{field: value})
    with pytest.raises(BaselineConflict):
        store.approve("workspace-a", proposal["id"], changed, current, [proposal["issues"][0]["id"]],
                      "wrong context", proposal["revision"])
    assert store.snapshot("workspace-a", changed)["records"] == []


def test_workspace_root_and_issue_ids_do_not_cross_between_projects(state, tmp_path):
    _, _, current, context, store = state
    proposal = propose(state)
    with pytest.raises(KeyError):
        store.get_proposal("workspace-b", proposal["id"])
    other_root = tmp_path / "other-root"
    other_root.mkdir()
    changed = replace(context, root=other_root)
    with pytest.raises(BaselineConflict):
        store.approve("workspace-a", proposal["id"], changed, current, [proposal["issues"][0]["id"]], "wrong root", proposal["revision"])
    approved = approve(state, proposal)
    with pytest.raises(KeyError):
        store.get_record("workspace-b", approved["approved_record_ids"][0])


@pytest.mark.parametrize("change", ["incomplete", "issues", "coverage", "source_inventory", "policy_hash", "summary", "not_applicable"])
def test_candidate_preview_must_account_for_all_declared_inputs_and_issues(state, change):
    _, _, current, context, store = state
    invalid = deepcopy(current)
    if change == "incomplete":
        invalid["review_status"] = "incomplete"
    elif change == "not_applicable":
        invalid["review_status"] = "not_applicable"
    elif change == "issues":
        invalid["issues"] = [{"file": "a.py", "status": "parse_failed"}]
    elif change == "coverage":
        invalid["coverage"]["within_scope_complete"] = False
    elif change == "source_inventory":
        invalid["coverage"]["analyzed_python"] = 0
    elif change == "policy_hash":
        invalid["policy"]["max_function_lines"] = 100
    else:
        invalid["summary"]["policy_debt_findings"] = 0
    with pytest.raises(ValueError):
        store.create_proposal("workspace-a", context, invalid)
    assert store.snapshot("workspace-a", context)["revision"] == 0


def test_duplicate_identity_occurrences_are_preserved_but_never_mass_exempted(state):
    _, _, current, context, store = state
    invalid = deepcopy(current)
    invalid["findings"].append(deepcopy(invalid["findings"][0]))
    invalid["summary"]["policy_debt_findings"] = 2
    proposal = store.create_proposal("workspace-a", context, invalid)
    assert len(proposal["issues"]) == 2 and len({row["id"] for row in proposal["issues"]}) == 2
    assert all(row["ambiguous"] for row in proposal["issues"])
    with pytest.raises(BaselineConflict):
        store.approve("workspace-a", proposal["id"], context, invalid, [row["id"] for row in proposal["issues"]],
                      "cannot select ambiguous copies", proposal["revision"])
    assert all(row["baseline"]["status"] == "ambiguous" for row in store.annotate("workspace-a", context, invalid)["findings"])


def test_real_duplicate_definitions_keep_distinct_occurrences_and_one_to_one_decisions(state):
    root, access, _, _, store = state
    (root / "a.py").write_text(code() * 2, encoding="utf-8")
    current = scan_preview(access, max_function_lines=2)
    current["analysis_id"] = "duplicate-definitions-analysis"
    context = BaselineContext(root, access.fingerprint, 1, PROVENANCE, current["policy_sha256"])
    proposal = store.create_proposal("workspace-a", context, current)
    assert [row["occurrence"] for row in proposal["issues"]] == [1, 2]
    result = store.approve("workspace-a", proposal["id"], context, current, [proposal["issues"][0]["id"]],
                           "approve exactly the first occurrence", proposal["revision"])
    assert len(result["records"]) == 1
    annotations = store.annotate("workspace-a", context, current)["findings"]
    assert [row["baseline"]["status"] for row in annotations] == ["approved", "new"]


def test_legacy_sha1_or_inconsistent_combined_digest_cannot_inherit_v2_approval(state):
    _, _, current, context, store = state
    approve(state)
    for field, value in (("fingerprint", "sha1:" + "a" * 40), ("combined_digest", "v2:sha256:" + "0" * 64)):
        legacy = deepcopy(current)
        legacy["findings"][0]["finding"][field] = value
        with pytest.raises(ValueError):
            store.create_proposal("workspace-a", context, legacy)
        annotation = store.annotate("workspace-a", context, legacy)["findings"][0]["baseline"]
        assert annotation["status"] == "unsupported_fingerprint" and not annotation["exemption_applied"]


def test_unrelated_file_change_keeps_exact_approved_issue_without_global_source_scope_binding(state):
    root, access, _, _, store = state
    (root / "b.py").write_text("value = 1\n", encoding="utf-8")
    original = scan_preview(access, max_function_lines=2)
    original["analysis_id"] = "original-complete-analysis"
    context = BaselineContext(root, access.fingerprint, 1, PROVENANCE, original["policy_sha256"])
    proposal = store.create_proposal("workspace-a", context, original)
    store.approve("workspace-a", proposal["id"], context, original, [proposal["issues"][0]["id"]],
                  "reviewed exact a.py evidence", proposal["revision"])
    (root / "b.py").write_text("value = 2\n", encoding="utf-8")
    current = scan_preview(access, max_function_lines=2)
    current["analysis_id"] = "new-analysis"
    assert current["source_sha256"] != original["source_sha256"]
    annotated = store.annotate("workspace-a", context, current)
    assert annotated["findings"][0]["baseline"]["status"] == "approved"


def test_workspace_revision_cas_and_replayed_approval_do_not_duplicate_records(state):
    _, _, current, context, store = state
    first = propose(state)
    second = propose(state)
    with pytest.raises(BaselineConflict):
        store.approve("workspace-a", first["id"], context, current, [first["issues"][0]["id"]], "stale revision", first["revision"])
    state_after = store.approve("workspace-a", second["id"], context, current, [second["issues"][0]["id"]], "current revision", second["revision"])
    with pytest.raises(BaselineConflict):
        store.approve("workspace-a", second["id"], context, current, [second["issues"][0]["id"]], "replay", state_after["revision"])
    assert len(store.snapshot("workspace-a", context)["records"]) == 1


def test_concurrent_approvals_commit_only_one_explicit_cas_decision(state):
    _, _, current, context, store = state
    proposal = propose(state)
    barrier = threading.Barrier(2)
    def contender(_):
        instance = BaselineStore(store.data_dir)
        barrier.wait()
        try:
            instance.approve("workspace-a", proposal["id"], context, current, [proposal["issues"][0]["id"]],
                             "one explicit local decision", proposal["revision"])
            return "approved"
        except BaselineConflict:
            return "conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(contender, range(2)))
    assert sorted(results) == ["approved", "conflict"]
    assert len(store.snapshot("workspace-a", context)["records"]) == 1


def test_write_failure_rolls_back_records_and_revision_as_one_transaction(state, monkeypatch):
    _, _, current, context, store = state
    proposal = propose(state)
    def failed(*args, **kwargs):
        raise OSError("synthetic audit persistence failure")
    monkeypatch.setattr(store, "_audit", failed)
    with pytest.raises(OSError):
        approve(state, proposal)
    current_state = store.snapshot("workspace-a", context)
    assert current_state["revision"] == proposal["revision"] and current_state["records"] == []
    assert current_state["proposals"][0]["issues"][0]["status"] == "pending"


def test_invalidate_removes_all_sensitive_pending_and_current_rows_but_keeps_minimal_audit(state):
    _, _, _, context, store = state
    proposal = propose(state)
    approved = approve(state, proposal)
    record_id = approved["approved_record_ids"][0]
    store.invalidate_workspace("workspace-a")
    current = store.snapshot("workspace-a", context)
    assert current["proposals"] == current["records"] == []
    assert current["revision"] == 3 and current["audit"][-1]["action"] == "workspace_invalidated"
    audit = json.dumps(current["audit"])
    assert "a.py" not in audit and "local user reviewed this policy debt" not in audit
    assert "fingerprint" not in audit and str(context.root) not in audit
    with pytest.raises(KeyError):
        store.get_proposal("workspace-a", proposal["id"])
    with pytest.raises(KeyError):
        store.get_record("workspace-a", record_id)


@pytest.mark.parametrize("reason", ["", "   ", "x" * 2001])
def test_reason_is_required_and_bounded(state, reason):
    _, _, current, context, store = state
    proposal = propose(state)
    with pytest.raises(ValueError):
        store.approve("workspace-a", proposal["id"], context, current, [proposal["issues"][0]["id"]], reason, proposal["revision"])


@pytest.mark.parametrize("selected", [[], ["unknown"], ["unknown", "unknown"], ["id"] * 2001])
def test_explicit_unique_selection_is_required(state, selected):
    _, _, current, context, store = state
    proposal = propose(state)
    with pytest.raises(ValueError):
        store.approve("workspace-a", proposal["id"], context, current, selected, "explicit selection", proposal["revision"])


def test_state_is_outside_the_reviewed_source_and_survives_reopen(state):
    root, _, _, context, store = state
    approve(state)
    reopened = BaselineStore(store.data_dir)
    assert reopened.snapshot("workspace-a", context) == store.snapshot("workspace-a", context)
    inside = BaselineStore(root / "local-baseline")
    with pytest.raises(ValueError, match="outside"):
        inside.snapshot("workspace-a", context)


def test_context_dict_cannot_smuggle_an_approved_or_role_field(state):
    _, _, _, context, _ = state
    assert BaselineContext.from_dict(context.to_dict()) == context
    with pytest.raises(ValueError):
        BaselineContext.from_dict(context.to_dict() | {"approved": True, "actor": "independent-ci"})
