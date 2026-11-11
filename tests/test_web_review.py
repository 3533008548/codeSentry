"""Real local review workers keep preview, navigation, and workspace evidence separate."""
import hashlib
import json
from pathlib import Path
import time

from fastapi.testclient import TestClient
import pytest

from codesentry.web.app import create_app
from codesentry.workspaces.store import WorkspaceStore


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    marker = root / "executed.txt"
    code = ("from pathlib import Path\n" + f"Path({str(marker)!r}).write_text('must never run')\n"
            + "def oversized():\n" + "    value = 1\n" * 82 + "    return value\n")
    (root / "main.py").write_text(code, encoding="utf-8")
    (root / ".env").write_text("API_KEY=excluded-secret", encoding="utf-8")
    return root


@pytest.fixture
def api(tmp_path):
    application = create_app(tmp_path / "state")
    with TestClient(application, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        client.application = application
        yield client


def register(api, source, settings=None):
    response = api.post("/api/workspaces", json={"path": str(source),
                         "access_policy": {"confirmed": True, "settings": settings or {}}})
    assert response.status_code == 201, response.text
    return response.json()


def wait(api, workspace_id, identity):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = api.get(f"/api/workspaces/{workspace_id}/analyses/{identity}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(.04)
    pytest.fail("local synthetic review worker did not finish")


def run(api, workspace_id, body=None):
    response = api.post(f"/api/workspaces/{workspace_id}/analyses", json=body or {"kind": "review_preview"})
    assert response.status_code == 202, response.text
    return wait(api, workspace_id, response.json()["id"])


def test_real_review_is_explicit_report_only_and_never_executes_source(api, source):
    workspace = register(api, source)
    job = run(api, workspace["id"])
    result = job["result"]
    assert job["kind"] == "review_preview" and job["status"] == "succeeded"
    assert result["kind"] == "review_preview" and result["analysis_mode"] == "static"
    assert result["workspace_id"] == workspace["id"] and result["analysis_id"] == job["id"]
    assert result["analysis_provenance"] == api.application.state.store.analysis_provenance
    assert result["policy_version"] == workspace["access_policy"]["version"]
    assert result["policy_fingerprint"] == workspace["access_policy"]["fingerprint"]
    assert result["config"]["max_function_lines"] == 80 and "max_function_lines" not in workspace["config"]
    assert result["review_status"] == "report_only" and result["gate_status"] == "not_evaluated"
    assert result["summary"]["policy_debt_findings"] == 1
    assert result["summary"]["blocking_findings"] == 0 and not result["formal_acceptance"]["passed"]
    assert result["findings"][0]["finding"]["verified"] and not result["findings"][0]["can_block"]
    assert "file_details" not in result and "reading_order" not in result
    assert ".env" not in result["source_sha256"] and "excluded-secret" not in json.dumps(result)
    assert not (source / "executed.txt").exists()
    assert any("门禁未评估" in line for line in job["logs"])


def test_navigation_and_review_results_have_independent_job_and_result_kinds(api, source):
    workspace = register(api, source)
    review = run(api, workspace["id"])
    navigation = run(api, workspace["id"], {"mode": "static"})
    assert navigation["kind"] == "navigation" and navigation["result"]["kind"] == "navigation"
    assert "reading_order" in navigation["result"] and "file_details" in navigation["result"]
    assert "findings" not in navigation["result"]
    records = api.get(f"/api/workspaces/{workspace['id']}/analyses").json()["analyses"]
    assert {item["kind"] for item in records} == {"navigation", "review_preview"}
    assert api.get(f"/api/workspaces/{workspace['id']}/analyses/{review['id']}").json()["kind"] == "review_preview"


def test_review_uses_raw_sha256_for_bom_and_content_staleness(api, source):
    raw = (source / "main.py").read_bytes()
    (source / "main.py").write_bytes(b"\xef\xbb\xbf" + raw)
    workspace = register(api, source)
    job = run(api, workspace["id"])
    url = f"/api/workspaces/{workspace['id']}/file"
    params = {"path": "main.py", "analysis_id": job["id"]}
    before = api.get(url, params=params).json()
    assert before["is_stale"] is False
    assert before["snapshot_content_hash_algorithm"] == "sha256-raw-bytes"
    assert before["snapshot_content_hash"] == hashlib.sha256(b"\xef\xbb\xbf" + raw).hexdigest()
    (source / "main.py").write_bytes(raw)
    after = api.get(url, params=params).json()
    assert after["content_hash"] == before["content_hash"] and after["is_stale"] is True


def test_unknown_snapshot_hash_is_not_reported_as_fresh(api, source):
    (source / "notes.txt").write_text("not part of Python review", encoding="utf-8")
    workspace = register(api, source)
    job = run(api, workspace["id"])
    result = api.get(f"/api/workspaces/{workspace['id']}/file",
                     params={"path": "notes.txt", "analysis_id": job["id"]}).json()
    assert result["snapshot_content_hash"] is None and result["is_stale"] is None


@pytest.mark.parametrize("case,job_status,review_status", [("zero", "succeeded", "report_only"),
    ("syntax", "incomplete", "incomplete"), ("excluded", "succeeded", "not_applicable")])
def test_zero_findings_parse_failure_and_excluded_scope_never_become_gate_pass(api, source, case, job_status, review_status):
    if case == "zero":
        (source / "main.py").write_text("def short():\n    return 1\n", encoding="utf-8")
    if case == "syntax":
        (source / "main.py").write_text("def broken(:\n", encoding="utf-8")
    workspace = register(api, source, {"exclude": ["main.py"]} if case == "excluded" else None)
    job = run(api, workspace["id"])
    assert job["status"] == job_status and job["result"]["review_status"] == review_status
    assert job["result"]["summary"]["policy_debt_findings"] == 0
    assert job["result"]["gate_status"] == "not_evaluated" and not job["result"]["formal_acceptance"]["passed"]
    if case == "excluded":
        assert "main.py" not in job["result"]["source_sha256"]


def test_same_filename_in_two_workspaces_never_crosses_review_scope(api, source, tmp_path):
    other = tmp_path / "second"
    other.mkdir()
    (other / "main.py").write_text("def short():\n    return 1\n", encoding="utf-8")
    first, second = register(api, source), register(api, other)
    before, after = run(api, first["id"]), run(api, second["id"])
    assert before["result"]["summary"]["policy_debt_findings"] == 1
    assert after["result"]["summary"]["policy_debt_findings"] == 0
    assert before["result"]["source_sha256"]["main.py"] != after["result"]["source_sha256"]["main.py"]
    assert api.get(f"/api/workspaces/{second['id']}/analyses/{before['id']}").status_code == 404
    assert api.get(f"/api/workspaces/{second['id']}/file",
                   params={"path": "main.py", "analysis_id": before["id"]}).status_code == 404


@pytest.mark.parametrize("damage", ["kind", "config"])
def test_result_kind_and_frozen_review_options_must_match_the_job(api, source, damage):
    workspace = register(api, source)
    job = run(api, workspace["id"])
    store = api.application.state.store
    artifact = store.result_file(workspace["id"], job["id"])
    result = json.loads(artifact.read_text(encoding="utf-8"))
    if damage == "kind":
        result["kind"] = "navigation"
    else:
        result["config"]["max_function_lines"] = 1
    artifact.write_text(json.dumps(result), encoding="utf-8")
    invalid = api.get(f"/api/workspaces/{workspace['id']}/analyses/{job['id']}").json()
    assert invalid["status"] == "invalidated" and invalid["result"] is None and invalid["kind"] == "review_preview"
    assert api.get(f"/api/workspaces/{workspace['id']}/file",
                   params={"path": "main.py", "analysis_id": job["id"]}).status_code == 409
    assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "main.py"}).status_code == 200


@pytest.mark.parametrize("body", [{"kind": "gate"}, {"kind": "review_preview", "mode": "dynamic"},
    {"kind": "review_preview", "max_function_lines": True}, {"kind": "review_preview", "max_function_lines": 0},
    {"kind": "review_preview", "max_function_lines": 10001}, {"kind": "navigation", "max_function_lines": 80}])
def test_unknown_modes_and_invalid_review_options_are_rejected(api, source, body):
    workspace = register(api, source)
    assert api.post(f"/api/workspaces/{workspace['id']}/analyses", json=body).status_code == 422
    assert api.get(f"/api/workspaces/{workspace['id']}/analyses").json()["analyses"] == []


def test_review_threshold_is_frozen_per_task_not_written_into_workspace_settings(api, source):
    workspace = register(api, source)
    job = run(api, workspace["id"], {"kind": "review_preview", "max_function_lines": 100})
    assert job["config"]["max_function_lines"] == 100 and job["result"]["policy"]["max_function_lines"] == 100
    assert job["result"]["summary"]["policy_debt_findings"] == 0
    assert "max_function_lines" not in api.get(f"/api/workspaces/{workspace['id']}").json()["config"]


def test_review_kind_and_result_survive_service_restart(tmp_path, source):
    state = tmp_path / "persistent-state"
    with TestClient(create_app(state), base_url="http://127.0.0.1") as first:
        first.headers["X-CodeSentry-Token"] = first.get("/api/session").json()["token"]
        workspace = register(first, source)
        job = run(first, workspace["id"])
    with TestClient(create_app(state), base_url="http://127.0.0.1") as second:
        second.headers["X-CodeSentry-Token"] = second.get("/api/session").json()["token"]
        restored = second.get(f"/api/workspaces/{workspace['id']}/analyses/{job['id']}").json()
        assert restored["kind"] == "review_preview" and restored["result"]["kind"] == "review_preview"
        assert restored["config"]["max_function_lines"] == 80


def test_historical_missing_kind_defaults_to_navigation_without_schema_migration(tmp_path, source):
    store = WorkspaceStore(tmp_path / "old-state")
    workspace = store.create_workspace(str(source), access_policy={"confirmed": True, "settings": {}})
    job = store.create_analysis(workspace["id"])
    config = dict(job["config"])
    config.pop("kind")
    with store.connection() as connection:
        connection.execute("UPDATE analyses SET config=? WHERE id=?", (json.dumps(config), job["id"]))
    restored = store.get_analysis(workspace["id"], job["id"])
    assert restored["kind"] == "navigation" and restored["config"] == workspace["config"]
