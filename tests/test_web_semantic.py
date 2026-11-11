"""Synthetic projects only: model consent, publication and revocation end to end."""
import json
import threading
import time

from fastapi.testclient import TestClient
import pytest

from codesentry.semantic.transport import TransportResponse
from codesentry.web.app import create_app


KEY = "synthetic-session-key-12345678"
SOURCE = "def inspect(flag):\n    assert (flag, 'required')\n"


class Transport:
    def __init__(self):
        self.calls = []
        self.started = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.body = json.dumps({"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps({
            "warnings": [{"line": 2, "end_line": 2, "reason": "Tuple condition may be unintended",
                          "evidence_quote": "assert (flag, 'required')", "suggestion": "Check intended assertion"}]})}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}}).encode()

    def send(self, body, *, api_key, timeout_seconds, cancel_event, live_guard):
        live_guard()
        self.calls.append((body, api_key))
        self.started.set()
        while not self.release.wait(.01):
            live_guard()
        live_guard()
        return TransportResponse(200, self.body)


@pytest.fixture
def bench(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "user-data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_text(SOURCE, encoding="utf-8")
    (root / "local.py").write_text("LOCAL_ONLY_MARKER = True\n", encoding="utf-8")
    (root / ".env").write_text("API_KEY=PRIVATE_NEVER_SENT", encoding="utf-8")
    transport = Transport()
    app = create_app(tmp_path / "state", semantic_transport=transport)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        workspace = client.post("/api/workspaces", json={"path": str(root), "access_policy": {
            "confirmed": True, "settings": {"model_scope": ["main.py"], "local_only": ["local.py"]}}}).json()
        assert not workspace["access_policy"]["cleanup_pending"], workspace["access_policy"]["cleanup_error"]
        base = f"/api/workspaces/{workspace['id']}"
        yield client, app, base, root, transport
        transport.release.set()


def configure(client, base, *, enabled=True, key=KEY):
    response = client.get(base + "/semantic-profile")
    assert response.status_code == 200, response.text
    profile = response.json()
    body = {"expected_revision": profile["revision"], "settings": {"enabled": enabled, "model": "deepseek-flash"}}
    if key is not None:
        body["api_key"] = key
    response = client.put(base + "/semantic-profile", json=body)
    assert response.status_code == 200, response.text
    assert KEY not in response.text
    return response.json()


def preview(client, base, profile, **changes):
    return client.post(base + "/semantic-previews", json={"path": "main.py", "start_line": 1,
        "end_line": 2, "expected_profile_revision": profile["revision"], **changes})


def send(client, base, value, **changes):
    return client.post(base + f"/semantic-previews/{value['preview_id']}/send", json={"confirmed": True,
        "expected_profile_revision": value["profile_revision"], "expected_request_sha256": value["expected_request_sha256"], **changes})


def wait(client, base, identity):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        response = client.get(base + f"/analyses/{identity}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(.02)
    pytest.fail("semantic job did not terminate")


def test_defaults_no_send_and_no_generic_job_bypass(bench):
    client, app, base, root, transport = bench
    response = client.get(base + "/semantic-profile")
    assert response.status_code == 200, response.text
    profile = response.json()
    assert profile["provider"] == "deepseek" and not profile["enabled"] and not profile["key_configured"]
    assert preview(client, base, profile).status_code == 409
    assert client.post(base + "/analyses", json={"kind": "semantic_review"}).status_code == 422
    with pytest.raises(ValueError):
        app.state.manager.submit(base.split("/")[-1], kind="semantic_review")
    assert transport.calls == []


def test_explicit_preview_send_warning_report_and_single_use(bench):
    client, app, base, root, transport = bench
    profile = configure(client, base)
    response = preview(client, base, profile)
    assert response.status_code == 200, response.text
    value = response.json()
    assert transport.calls == [] and KEY not in response.text
    assert SOURCE == json.loads(value["request"]["messages"][1]["content"])["source"].replace("\r\n", "\n")
    started = send(client, base, value)
    assert started.status_code == 202, started.text
    assert send(client, base, value).status_code == 409
    job = wait(client, base, started.json()["id"])
    assert job["status"] == "succeeded", job
    report = job["result"]
    assert report["gate_status"] == "not_evaluated" and not report["formal_acceptance"]["passed"]
    warning, = report["warnings"]
    assert warning["source"] == "llm" and not warning["verified"] and not warning["can_block"]
    assert report["summary"]["blocking_findings"] == 0
    assert len(transport.calls) == 1 and transport.calls[0][1] == KEY
    assert transport.calls[0][0].decode() == value["request_json"]
    assert client.get(base + f"/file?path=main.py&analysis_id={job['id']}").json()["is_stale"] is False
    assert client.post(base + "/baseline/proposals", json={"analysis_id": job["id"]}).status_code == 409
    config = job["config"]
    assert not ({"path", "messages", "api_key", "request_json"} & config.keys())
    for path in app.state.store.data_dir.rglob("*"):
        if path.is_file() and path.name != ".instance.lock":
            assert KEY.encode() not in path.read_bytes(), path.name


@pytest.mark.parametrize("body", [{"api_key": 5}, {"api_key": {"secret": KEY}}, {"unknown": KEY},
    {KEY: "unknown"}, {"api_key": KEY, "settings": {"enabled": "oops", "model": "bad"}}])
def test_invalid_credentials_never_echo_in_validation(bench, body):
    client, app, base, root, transport = bench
    response = client.put(base + "/semantic-profile", json=body)
    assert response.status_code == 422 and KEY not in response.text
    assert transport.calls == []


@pytest.mark.parametrize("path", ["local.py", ".env"])
def test_model_candidate_never_overrides_deny_or_local_only(bench, path):
    client, app, base, root, transport = bench
    profile = configure(client, base)
    assert preview(client, base, profile, path=path, end_line=1).status_code == 403
    assert transport.calls == []


def test_source_change_and_profile_change_invalidate_before_send(bench):
    client, app, base, root, transport = bench
    profile = configure(client, base)
    value = preview(client, base, profile).json()
    (root / "main.py").write_text(SOURCE + "# changed outside selected range\n", encoding="utf-8")
    assert send(client, base, value).status_code == 409
    value = preview(client, base, profile).json()
    configure(client, base, key=None)
    assert send(client, base, value).status_code == 409
    assert transport.calls == []


def test_cross_workspace_preview_is_not_authority(bench, tmp_path):
    client, app, base, root, transport = bench
    profile = configure(client, base)
    value = preview(client, base, profile).json()
    other = tmp_path / "other"
    other.mkdir()
    (other / "main.py").write_text(SOURCE, encoding="utf-8")
    workspace = client.post("/api/workspaces", json={"path": str(other), "access_policy": {
        "confirmed": True, "settings": {"model_scope": ["main.py"]}}}).json()
    other_base = f"/api/workspaces/{workspace['id']}"
    configure(client, other_base)
    assert send(client, other_base, value).status_code == 409
    assert send(client, base, value).status_code == 202


def test_cancel_inflight_discards_late_response(bench):
    client, app, base, root, transport = bench
    transport.release.clear()
    profile = configure(client, base)
    value = preview(client, base, profile).json()
    started = send(client, base, value).json()
    assert transport.started.wait(2)
    response = client.post(base + f"/analyses/{started['id']}/cancel", json={})
    assert response.status_code == 200, response.text
    transport.release.set()
    job = wait(client, base, started["id"])
    assert job["status"] == "cancelled" and job["result"] is None


def test_profile_clear_cancels_inflight_and_deletes_semantic_only(bench):
    client, app, base, root, transport = bench
    profile = configure(client, base)
    first = send(client, base, preview(client, base, profile).json()).json()
    assert wait(client, base, first["id"])["result"]
    transport.started.clear()
    transport.release.clear()
    second = send(client, base, preview(client, base, profile).json()).json()
    assert transport.started.wait(2)
    response = client.put(base + "/semantic-profile", json={"expected_revision": profile["revision"],
        "settings": {"enabled": False, "model": "deepseek-flash"}, "clear_key": True})
    assert response.status_code == 200, response.text
    assert not response.json()["key_configured"]
    for identity in (first["id"], second["id"]):
        job = wait(client, base, identity)
        assert job["status"] == "invalidated" and job["result"] is None
        assert not (app.state.store.data_dir / "workspaces" / base.split("/")[-1] / "analyses" / identity).exists()


def test_scope_revocation_stops_inflight_and_clears_results(bench):
    client, app, base, root, transport = bench
    transport.release.clear()
    profile = configure(client, base)
    started = send(client, base, preview(client, base, profile).json()).json()
    assert transport.started.wait(2)
    response = client.patch(base, json={"access_policy": {"confirmed": True, "settings": {}}})
    assert response.status_code == 200, response.text
    job = wait(client, base, started["id"])
    assert job["status"] == "invalidated" and job["result"] is None
    assert client.get(base + "/semantic-profile").json()["key_configured"]


def test_invalid_provider_output_is_incomplete_never_pass(bench):
    client, app, base, root, transport = bench
    transport.body = b'{"choices":[{"finish_reason":"length","message":{"content":"{}"}}]}'
    profile = configure(client, base)
    started = send(client, base, preview(client, base, profile).json()).json()
    job = wait(client, base, started["id"])
    assert job["status"] == "incomplete" and job["result"]["gate_status"] == "not_evaluated"
    assert job["result"]["warnings"] == []


def test_cancel_while_semantic_report_is_staged_cannot_publish_late_success(bench, monkeypatch):
    from pathlib import Path
    client, app, base, _root, _transport = bench
    staged, release = threading.Event(), threading.Event()
    original_write = Path.write_text

    def pause_after_staging(path, data, *args, **kwargs):
        result = original_write(path, data, *args, **kwargs)
        if path.name == "result.tmp" and '"mode": "semantic_review"' in data:
            staged.set()
            assert release.wait(8), "synthetic staging pause was not released"
        return result

    monkeypatch.setattr(Path, "write_text", pause_after_staging)
    profile = configure(client, base)
    started = send(client, base, preview(client, base, profile).json()).json()
    identity = (base.split("/")[-1], started["id"])
    cancelled = []
    cancel_thread = threading.Thread(target=lambda: cancelled.append(
        client.post(base + f"/analyses/{started['id']}/cancel", json={})), daemon=True)
    try:
        assert staged.wait(5), "semantic report never reached the staging boundary"
        cancel_thread.start()
        assert app.state.manager.cancellations[identity].wait(3)
        release.set()
        cancel_thread.join(timeout=5)
        assert not cancel_thread.is_alive() and cancelled[0].status_code == 200
        job = wait(client, base, started["id"])
        assert job["status"] == "cancelled" and job["result"] is None
        directory = app.state.store.data_dir / "workspaces" / identity[0] / "analyses" / identity[1]
        assert not (directory / "result.json").exists()
    finally:
        release.set()
        if cancel_thread.ident is not None:
            cancel_thread.join(timeout=5)
