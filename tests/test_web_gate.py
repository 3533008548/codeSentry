"""Real gate reports do not convert report-only rules into production admission."""
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
    (root / "main.py").write_text("def tiny():\n    return 1\n", encoding="utf-8")
    app = create_app(tmp_path / "state")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        workspace = client.post("/api/workspaces", json={"path": str(root),
            "access_policy": {"confirmed": True, "settings": {}}}).json()
        yield client, workspace, root


def run(client, identity):
    started = client.post(f"/api/workspaces/{identity}/analyses", json={"kind": "gate_check"})
    assert started.status_code == 202, started.text
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        response = client.get(f"/api/workspaces/{identity}/analyses/{started.json()['id']}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(.04)
    pytest.fail("trusted local gate worker did not finish")


def test_zero_findings_generate_report_but_unadmitted_policy_is_not_pass(workbench):
    client, workspace, root = workbench
    policy = client.get("/api/gate-policy").json()
    assert policy["admission_ready"] is False
    assert policy["exit_codes"] == {"pass": 0, "block": 1, "incomplete": 3, "error": 2}
    assert policy["required_rules"] and policy["required_rules"][0]["admission"] == "report_only"
    job = run(client, workspace["id"])
    assert job["status"] == "succeeded", job
    result = job["result"]
    assert result["gate_status"] == "incomplete" and result["exit_code"] == 3
    assert result["findings"] == []
    assert result["summary"]["admitted_required_rules"] == 0
    assert result["summary"]["completed_required_rules"] == 1
    assert job["config"]["gate_policy_sha256"] == result["policy_sha256"] == policy["policy_sha256"]
    assert result["baseline_summary"]["gate_exemptions_applied"] == 0
    assert result["formal_acceptance"]["passed"] is False
    assert "未运行目标代码" in "\n".join(job["logs"])
    url = f"/api/workspaces/{workspace['id']}/file?path=main.py&analysis_id={job['id']}"
    assert client.get(url).json()["is_stale"] is False
    (root / "main.py").write_bytes(b'\xef\xbb\xbfdef tiny():\n    return 1\n')
    assert client.get(url).json()["is_stale"] is True


def test_repository_policy_or_client_parameters_cannot_admit_rules(workbench):
    client, workspace, root = workbench
    (root / "main.py").write_text("def debt():\n" + "    value = 1\n" * 82 + "    return value\n", encoding="utf-8")
    (root / "policy.yaml").write_text("required_rules: []\napproved_for_blocking: true\n", encoding="utf-8")
    (root / "baseline.json").write_text('{"approved":true,"gate_status":"pass"}', encoding="utf-8")
    job = run(client, workspace["id"])
    assert job["result"]["gate_status"] == "incomplete"
    assert len(job["result"]["findings"]) == 1
    assert not job["result"]["findings"][0]["blocking"]
    for body in ({"kind": "gate_check", "max_function_lines": 1},
                 {"kind": "gate_check", "base_ref": "HEAD"},
                 {"kind": "gate_check", "blocking_policy": {"block_severities": [], "max_new_findings": 1000}},
                 {"kind": "gate_check", "policy": {"required_rules": []}}):
        assert client.post(f"/api/workspaces/{workspace['id']}/analyses", json=body).status_code == 422


@pytest.mark.parametrize("scope", ["no_python", "all_excluded"])
def test_no_python_or_all_excluded_is_not_a_gate_pass(workbench, scope):
    client, workspace, root = workbench
    if scope == "no_python":
        (root / "main.py").unlink()
    else:
        response = client.patch(f"/api/workspaces/{workspace['id']}", json={"access_policy": {
            "confirmed": True, "settings": {"exclude": ["main.py"]},
            "expected_version": workspace["access_policy"]["version"]}})
        assert response.status_code == 200, response.text
    job = run(client, workspace["id"])
    assert job["result"]["gate_status"] == "incomplete"
    assert job["result"]["summary"]["completed_required_rules"] == 0


def test_cli_gate_json_and_exit_code_remain_consistent(workbench, capsys):
    _client, _workspace, root = workbench
    options = ["--workspace-data-dir", str(root.parent / "state"), "--json"]
    assert main(["scan", str(root), "--gate", *options]) == 3
    assert json.loads(capsys.readouterr().out)["gate_status"] == "incomplete"
    for argv in (["scan", str(root / "missing"), "--gate", *options],
                 ["scan", str(root), "--gate", "--max-function-lines", "80", *options],
                 ["--policy", str(root / "not-read.yaml"), "scan", str(root), "--gate", *options]):
        assert main(argv) == 2
        report = json.loads(capsys.readouterr().out)
        assert report["gate_status"] == "error" and report["exit_code"] == 2
        assert report["mode"] == "gate" and report["policy"]["required_rules"]


def test_stale_gate_policy_stops_worker_before_project_is_opened(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("worker with stale required policy accessed a project")
    monkeypatch.setattr(worker, "RegisteredAccessPolicy", forbidden)
    destination = tmp_path / "result.json"
    status = worker.main([str(tmp_path / "not-opened"), str(destination), "workspace", "analysis",
        json.dumps({"kind": "gate_check", "gate_policy_sha256": "outdated"}),
        json.dumps({"analysis_provenance": analysis_provenance()}), str(tmp_path / "state")])
    assert status == 2 and not destination.exists()
