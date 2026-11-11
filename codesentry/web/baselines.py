"""Explicit local baseline review over server-selected, freshly recomputed reports."""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from typing import Annotated

from codesentry.review.approvals import BaselineContext
from codesentry.review.scan import preview_policy, scan_preview

Identifier = Annotated[str, StringConstraints(min_length=1, max_length=128)]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class ProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: Identifier


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selected_ids: list[Identifier] = Field(min_length=1, max_length=2000)
    reason: Reason
    expected_revision: int = Field(ge=0, strict=True)


class RevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Reason
    expected_revision: int = Field(ge=0, strict=True)


def review_context(store, workspace, policy_sha256):
    access = workspace["access_policy"]
    return BaselineContext(root=workspace["path"], access_fingerprint=access["fingerprint"],
        access_version=access["version"], analysis_provenance=store.analysis_provenance,
        policy_sha256=policy_sha256)


def _identity(workspace):
    return {"workspace_id": workspace["id"], "policy_version": workspace["access_policy"]["version"],
            "policy_fingerprint": workspace["access_policy"]["fingerprint"]}


def _report(store, workspace_id, analysis_id):
    job = store.get_analysis(workspace_id, analysis_id, include_result=True)
    if job["kind"] != "review_preview" or job["status"] != "succeeded" or not job.get("result"):
        raise HTTPException(409, "请先生成完整、有效的审查预览，再复核基线")
    return job


def _snapshot(result):
    # Full source inventory and every original report row are compared. A
    # matching selected item alone cannot cover changes in the remaining input.
    snapshot = {key: result.get(key) for key in (
        "review_status", "policy", "policy_sha256", "source_sha256", "coverage", "issues")}
    snapshot["findings"] = [row | {"finding": {key: value for key, value in row["finding"].items()
        if key != "created_at"}} for row in result.get("findings", [])]
    return snapshot


def _fresh_report(store, manager, workspace, access, analysis_id):
    if any(row["status"] in {"queued", "running"}
           for row in store.list_analyses(workspace["id"], metadata_only=True)):
        raise HTTPException(409, "当前有任务正在进行，结束或取消后再复核基线")
    original = _report(store, workspace["id"], analysis_id)
    previous = original["result"]
    current = scan_preview(access, max_function_lines=original["config"]["max_function_lines"])
    if (current["review_status"] != "report_only" or current["coverage"]["within_scope_complete"] is not True
            or _snapshot(current) != _snapshot(previous)):
        raise HTTPException(409, "源码、范围或规则证据已变化，请重新审查后生成基线提案")
    access.refresh_if_changed()
    access.check_current()
    if (access.fingerprint != workspace["access_policy"]["fingerprint"]
            or not store.policy_matches(workspace["id"], workspace["access_policy"])):
        raise HTTPException(409, "文件访问范围已变化，请重新确认范围并审查")
    current["analysis_id"] = original["id"]
    return current, review_context(store, workspace, current["policy_sha256"])


def install_baseline_routes(app, store):
    @app.get("/api/workspaces/{workspace_id}/baseline")
    def baseline(workspace_id: str, analysis_id: str | None = None):
        with app.state.manager.authorized(workspace_id) as (workspace, _access):
            if analysis_id is not None:
                job = store.get_analysis(workspace_id, analysis_id, include_result=True)
                if job["kind"] != "review_preview" or not job.get("result"):
                    raise HTTPException(409, "所选审查报告不可用，请刷新或重新审查")
                policy_hash = job["result"]["policy_sha256"]
            else:
                policy_hash = hashlib.sha256(json.dumps(preview_policy(), sort_keys=True,
                    separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            state = app.state.manager.baselines.snapshot(workspace_id, review_context(store, workspace, policy_hash))
            return state | _identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/baseline/proposals", status_code=201)
    def propose(workspace_id: str, body: ProposalRequest):
        manager = app.state.manager
        with manager.authorized(workspace_id) as (workspace, access):
            current, context = _fresh_report(store, manager, workspace, access, body.analysis_id)
            proposal = manager.baselines.create_proposal(workspace_id, context, current)
            return proposal | _identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/baseline/proposals/{proposal_id}/approve")
    def approve(workspace_id: str, proposal_id: str, body: ApprovalRequest):
        manager = app.state.manager
        with manager.authorized(workspace_id) as (workspace, access):
            proposal = manager.baselines.get_proposal(workspace_id, proposal_id)
            current, context = _fresh_report(store, manager, workspace, access, proposal["source_analysis_id"])
            state = manager.baselines.approve(workspace_id, proposal_id, context, current,
                selected_ids=body.selected_ids, reason=body.reason, expected_revision=body.expected_revision)
            return state | _identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/baseline/records/{record_id}/revoke")
    def revoke(workspace_id: str, record_id: str, body: RevocationRequest):
        manager = app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            record = manager.baselines.get_record(workspace_id, record_id)
            context = review_context(store, workspace, record["context"]["policy_sha256"])
            state = manager.baselines.revoke(workspace_id, record_id, context,
                reason=body.reason, expected_revision=body.expected_revision)
            return state | _identity(workspace)
