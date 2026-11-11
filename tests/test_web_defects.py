"""Independent candidate jobs keep unconfirmed syntax facts out of gate/debt approval."""
import json
import time

from fastapi.testclient import TestClient
import pytest

from codesentry.cli.main import main
from codesentry.web.app import create_app
from codesentry.web import worker
from codesentry.web.provenance import analysis_provenance


@pytest.fixture
def workbench(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_text("raise RuntimeError('MUST_NOT_EXECUTE_TARGET')\ndef inspect(flag):\n    assert (flag, 'required')\n", encoding="utf-8")
    (root / ".env").write_text("API_KEY=FAKE_EXCLUDED_VALUE", encoding="utf-8")
    app = create_app(tmp_path / "state")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        workspace = client.post("/api/workspaces", json={"path": str(root),
            "access_policy": {"confirmed": True, "settings": {}}}).json()
        yield client, workspace, root


def run(client, identity):
    started = client.post(f"/api/workspaces/{identity}/analyses", json={"kind": "defect_preview"})
    assert started.status_code == 202, started.text
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        response = client.get(f"/api/workspaces/{identity}/analyses/{started.json()['id']}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(.04)
    pytest.fail("trusted candidate worker did not finish")


def test_syntax_fact_is_only_a_candidate_with_own_source_snapshot(workbench):
    client, workspace, root = workbench
    job = run(client, workspace["id"])
    assert job["status"] == "succeeded", job
    result = job["result"]
    assert result["mode"] == "defect_preview" and result["gate_status"] == "not_evaluated"
    assert result["summary"] == {"candidate_findings": 1, "confirmed_behavior_bug_findings": 0, "blocking_findings": 0}
    assert job["config"]["defect_policy_sha256"] == result["policy_sha256"]
    row, = result["findings"]
    assert row["classification"] == "behavior_bug_candidate" and row["confirmed_behavior_bug"] is False
    assert not row["can_block"] and row["finding"]["rule_id"] == "python.assert_tuple"
    assert row["finding"]["line"] == 3
    assert row["finding"]["facts"]["always_truthy_after_successful_construction"] is True
    assert result["formal_acceptance"]["passed"] is False
    assert all(rule["rule_id"] != "python.assert_tuple" for rule in client.get("/api/gate-policy").json()["required_rules"])
    assert client.post(f"/api/workspaces/{workspace['id']}/baseline/proposals", json={"analysis_id": job["id"]}).status_code == 409
    location = f"/api/workspaces/{workspace['id']}/file?path=main.py&analysis_id={job['id']}"
    assert client.get(location).json()["is_stale"] is False
    (root / "main.py").write_bytes(b'\xef\xbb\xbf' + (root / "main.py").read_bytes())
    assert client.get(location).json()["is_stale"] is True


def test_normal_assert_is_not_reported_but_not_a_gate_pass(workbench):
    client, workspace, root = workbench
    (root / "main.py").write_text("def inspect(flag):\n    assert flag, 'required'\n", encoding="utf-8")
    result = run(client, workspace["id"])["result"]
    assert result["findings"] == []
    assert result["review_status"] == "report_only" and result["gate_status"] == "not_evaluated"
    assert result["summary"]["confirmed_behavior_bug_findings"] == 0


def test_broken_input_is_incomplete_without_erasing_other_candidates(workbench):
    client, workspace, root = workbench
    (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    job = run(client, workspace["id"])
    assert job["status"] == "incomplete"
    assert job["result"]["review_status"] == "incomplete"
    assert len(job["result"]["findings"]) == 1
    assert any(issue["file"] == "broken.py" for issue in job["result"]["issues"])


def test_candidate_cli_modes_and_no_client_rule_override(workbench, capsys):
    client, workspace, root = workbench
    options = ["--workspace-data-dir", str(root.parent / "state"), "--json"]
    assert main(["scan", str(root), "--defects", *options]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["candidate_findings"] == 1
    assert result["summary"]["confirmed_behavior_bug_findings"] == 0
    assert main(["scan", str(root), "--defects", "--max-function-lines", "1", *options]) == 2
    assert json.loads(capsys.readouterr().out)["review_status"] == "error"
    for body in ({"kind": "defect_preview", "max_function_lines": 1},
                 {"kind": "defect_preview", "base_ref": "HEAD"},
                 {"kind": "defect_preview", "rule_id": "arbitrary"}):
        assert client.post(f"/api/workspaces/{workspace['id']}/analyses", json=body).status_code == 422


def test_stale_candidate_policy_refuses_to_open_project(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("stale candidate policy opened a project")
    monkeypatch.setattr(worker, "RegisteredAccessPolicy", forbidden)
    destination = tmp_path / "result.json"
    status = worker.main([str(tmp_path / "not-opened"), str(destination), "workspace", "analysis",
        json.dumps({"kind": "defect_preview", "defect_policy_sha256": "outdated"}),
        json.dumps({"analysis_provenance": analysis_provenance()}), str(tmp_path / "state")])
    assert status == 2 and not destination.exists()
