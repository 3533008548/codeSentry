"""User-facing approval and change tasks use current server-owned evidence."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from fastapi.testclient import TestClient
import pytest

from codesentry.web.app import create_app
from codesentry.cli.main import main


@pytest.fixture
def workbench(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_text("def oversized():\n" + "    value = 1\n" * 82 + "    return value\n", encoding="utf-8")
    app = create_app(tmp_path / "state")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        workspace = client.post("/api/workspaces", json={"path": str(root),
            "access_policy": {"confirmed": True, "settings": {}}}).json()
        yield client, workspace, root


def run(client, workspace_id, **options):
    started = client.post(f"/api/workspaces/{workspace_id}/analyses", json=options)
    assert started.status_code == 202, started.text
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        response = client.get(f"/api/workspaces/{workspace_id}/analyses/{started.json()['id']}")
        assert response.status_code == 200, response.text
        if response.json()["status"] not in {"queued", "running"}:
            return response.json()
        time.sleep(.04)
    pytest.fail("trusted local worker did not finish")


def proposal(client, workspace_id, job):
    response = client.post(f"/api/workspaces/{workspace_id}/baseline/proposals", json={"analysis_id": job["id"]})
    assert response.status_code == 201, response.text
    return response.json()


def approve(client, workspace_id, draft):
    return client.post(f"/api/workspaces/{workspace_id}/baseline/proposals/{draft['id']}/approve", json={
        "selected_ids": [draft["issues"][0]["id"]], "reason": "Reviewed existing policy debt",
        "expected_revision": draft["revision"]})


def test_explicit_approval_is_persistent_reversible_and_never_hides_findings(workbench):
    client, workspace, root = workbench
    workspace_id = workspace["id"]
    job = run(client, workspace_id, kind="review_preview")
    assert job["status"] == "succeeded"
    draft = proposal(client, workspace_id, job)
    assert draft["source_analysis_id"] == job["id"]
    assert not client.get(f"/api/workspaces/{workspace_id}/baseline").json()["records"]
    response = approve(client, workspace_id, draft)
    assert response.status_code == 200, response.text
    state = response.json()
    assert state["records"][0]["status"] == "approved"
    assert not (root / "baselines.sqlite3").exists()
    assert approve(client, workspace_id, draft).status_code == 409
    updated = client.get(f"/api/workspaces/{workspace_id}/analyses/{job['id']}").json()["result"]
    assert len(updated["findings"]) == 1
    assert updated["findings"][0]["baseline"]["status"] == "approved"
    assert updated["gate_status"] == "not_evaluated"
    record_id = state["records"][0]["id"]
    revoked = client.post(f"/api/workspaces/{workspace_id}/baseline/records/{record_id}/revoke", json={
        "reason": "Reopen this debt", "expected_revision": state["revision"]})
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["records"][0]["status"] == "revoked"
    assert len(client.get(f"/api/workspaces/{workspace_id}/analyses/{job['id']}").json()["result"]["findings"]) == 1


def test_stale_input_and_permission_changes_cannot_reuse_proposal(workbench):
    client, workspace, root = workbench
    identity = workspace["id"]
    draft = proposal(client, identity, run(client, identity, kind="review_preview"))
    (root / "main.py").write_text((root / "main.py").read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    assert approve(client, identity, draft).status_code == 409
    patched = client.patch(f"/api/workspaces/{identity}", json={"access_policy": {
        "confirmed": True, "settings": {"exclude": ["main.py"]},
        "expected_version": workspace["access_policy"]["version"]}})
    assert patched.status_code == 200, patched.text
    state = client.get(f"/api/workspaces/{identity}/baseline").json()
    assert state["records"] == state["proposals"] == []
    assert "oversized" not in json.dumps(state)
    assert "Reviewed existing policy debt" not in json.dumps(state)


def test_incomplete_or_cross_workspace_reports_cannot_become_baselines(workbench, tmp_path):
    client, workspace, root = workbench
    (root / "broken.py").write_text("def broken(:", encoding="utf-8")
    job = run(client, workspace["id"], kind="review_preview")
    assert job["status"] == "incomplete"
    assert client.post(f"/api/workspaces/{workspace['id']}/baseline/proposals", json={"analysis_id": job["id"]}).status_code == 409
    other = tmp_path / "other"
    other.mkdir()
    second = client.post("/api/workspaces", json={"path": str(other),
        "access_policy": {"confirmed": True, "settings": {}}}).json()
    assert client.post(f"/api/workspaces/{second['id']}/baseline/proposals", json={"analysis_id": job["id"]}).status_code == 404


def git(root, *arguments):
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git not installed")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_SYSTEM="NUL", GIT_CONFIG_GLOBAL="NUL", GIT_TERMINAL_PROMPT="0")
    result = subprocess.run([executable, "-c", "core.hooksPath=NUL", "-c", "user.name=CodeSentry Fixture",
        "-c", "user.email=fixture@example.invalid", *arguments], cwd=root, env=environment, capture_output=True, check=True)
    return result.stdout.decode().strip()


def test_change_scope_worker_preserves_layers_and_real_report_contract(workbench, capsys):
    client, workspace, root = workbench
    git(root, "init", "-q")
    git(root, "add", "main.py")
    git(root, "commit", "-qm", "initial synthetic snapshot")
    before = git(root, "rev-parse", "HEAD")
    (root / "caller.py").write_text("import main\n", encoding="utf-8")
    git(root, "add", "caller.py")
    (root / "main.py").write_text("def small():\n    return 1\n", encoding="utf-8")
    (root / "untracked.py").write_text("import caller\n", encoding="utf-8")
    job = run(client, workspace["id"], kind="change_scope")
    assert job["status"] == "succeeded", job
    result = job["result"]
    assert result["gate_status"] == "not_evaluated"
    assert result["base_sha"] == before
    assert result["summary"]["staged"] >= 1
    assert result["summary"]["unstaged"] >= 1
    assert result["summary"]["untracked"] >= 1
    assert result["coverage"]["whole_repository_evaluated"] is False
    assert result["impact"]["call_analysis"] == "not_evaluated"
    assert not (root / "baselines.sqlite3").exists()
    exit_code = main(["changes", str(root), "--workspace-data-dir", str(root.parent / "state"), "--json"])
    assert exit_code == 3
    assert json.loads(capsys.readouterr().out)["gate_status"] == "not_evaluated"
    for body in ({"kind": "navigation", "base_ref": "HEAD"},
                 {"kind": "change_scope", "base_ref": "--help"},
                 {"kind": "change_scope", "comparison": "commit"},
                 {"kind": "review_preview", "comparison": "staged"}):
        assert client.post(f"/api/workspaces/{workspace['id']}/analyses", json=body).status_code == 422
