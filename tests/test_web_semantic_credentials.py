"""Application-owned .env snapshots stay separate from reviewed source."""
from contextlib import contextmanager
import json
import threading
import time

from fastapi.testclient import TestClient
import pytest

from codesentry.semantic.credentials import load_deepseek_credentials
from codesentry.semantic.transport import TransportResponse
from codesentry.web.app import create_app
from codesentry.web.jobs import AnalysisManager


CONFIGURED = "sk-SYNTHETIC_SERVER_ENV_KEY_123456"
OVERRIDE = "sk-SYNTHETIC_WORKSPACE_SESSION_KEY"
SOURCE = "def inspect(flag):\n    assert flag\n"


class Transport:
    def __init__(self):
        self.keys = []

    def send(self, body, *, api_key, timeout_seconds, cancel_event, live_guard):
        live_guard()
        self.keys.append(api_key)
        return TransportResponse(200, json.dumps({"choices": [{"finish_reason": "stop", "message": {
            "role": "assistant", "content": '{"warnings":[]}'}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}).encode())


@contextmanager
def serve(state, env_file, transport):
    value = load_deepseek_credentials(env_file, environ={})
    app = create_app(state, semantic_transport=transport, configured_api_key=value.api_key,
                     configured_key_source=value.source if value.api_key else None)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        yield client, app


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "user-data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    root = tmp_path / "reviewed-source"
    root.mkdir()
    (root / "main.py").write_bytes(SOURCE.encode())
    (root / ".env").write_text("DEEPSEEK_API_KEY=sk-UNTRUSTED_PROJECT_ENV_NOT_USED", encoding="utf-8")
    env_file = tmp_path / "trusted-app.env"
    env_file.write_text(f"DEEPSEEK_API_KEY={CONFIGURED}", encoding="utf-8")
    return tmp_path / "state", root, env_file, Transport()


def workspace(client, root, scope=None):
    response = client.post("/api/workspaces", json={"path": str(root), "access_policy": {
        "confirmed": True, "settings": {"model_scope": [] if scope is None else scope}}})
    assert response.status_code == 201, response.text
    value = response.json()
    assert not value["access_policy"]["cleanup_pending"]
    return f"/api/workspaces/{value['id']}"


def profile(client, base):
    response = client.get(base + "/semantic-profile")
    assert response.status_code == 200, response.text
    assert CONFIGURED not in response.text and OVERRIDE not in response.text
    return response.json()


def update(client, base, current, **changes):
    response = client.put(base + "/semantic-profile", json={"expected_revision": current["revision"],
        "settings": {"enabled": True, "model": "deepseek-flash"}, **changes})
    assert response.status_code == 200, response.text
    assert CONFIGURED not in response.text and OVERRIDE not in response.text
    return response.json()


def preview(client, base, current):
    return client.post(base + "/semantic-previews", json={"path": "main.py", "start_line": 1, "end_line": 2,
        "expected_profile_revision": current["revision"]})


def send(client, base, current):
    response = preview(client, base, current)
    assert response.status_code == 200, response.text
    value = response.json()
    response = client.post(base + f"/semantic-previews/{value['preview_id']}/send", json={"confirmed": True,
        "expected_request_sha256": value["expected_request_sha256"], "expected_profile_revision": current["revision"]})
    assert response.status_code == 202, response.text
    return wait(client, base, response.json()["id"])


def wait(client, base, identity):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        value = client.get(base + f"/analyses/{identity}").json()
        if value["status"] not in {"queued", "running"}:
            return value
        time.sleep(.02)
    pytest.fail("synthetic credential job did not terminate")


def test_env_key_reused_after_restart_with_explicit_scope_and_enable(setup):
    state, root, env_file, transport = setup
    with serve(state, env_file, transport) as (client, app):
        base = workspace(client, root)
        current = profile(client, base)
        assert current["key_source"] == "env_file" and current["key_configured"] and not current["enabled"]
        assert preview(client, base, current).status_code == 409
        current = update(client, base, current)
        assert preview(client, base, current).status_code == 403
        assert client.patch(base, json={"access_policy": {"confirmed": True,
            "settings": {"model_scope": ["main.py"]}}}).status_code == 200
        assert send(client, base, current)["status"] == "succeeded"
        assert transport.keys == [CONFIGURED]
    with serve(state, env_file, transport) as (client, app):
        current = profile(client, base)
        assert current["key_source"] == "env_file" and current["enabled"]
        assert client.get(base).json()["access_policy"]["settings"]["model_scope"] == ["main.py"]
        assert send(client, base, current)["status"] == "succeeded"
        assert transport.keys == [CONFIGURED, CONFIGURED]
    for path in state.rglob("*"):
        if path.is_file():
            assert CONFIGURED.encode() not in path.read_bytes() and OVERRIDE.encode() not in path.read_bytes()


def test_clear_stays_cleared_on_restart_and_restore_is_explicit_and_scoped(setup, tmp_path):
    state, root, env_file, transport = setup
    with serve(state, env_file, transport) as (client, app):
        base = workspace(client, root, ["main.py"])
        current = update(client, base, profile(client, base), api_key=OVERRIDE)
        assert current["key_source"] == "workspace_session"
        assert send(client, base, current)["status"] == "succeeded"
        assert transport.keys == [OVERRIDE]
        pending = preview(client, base, current).json()
        current = update(client, base, current, clear_key=True)
        assert not current["key_configured"] and not current["configured_key_enabled"]
        assert current["configured_key_available"] and current["key_source"] == "none"
        assert preview(client, base, current).status_code == 409
        prior = client.get(base + "/analyses").json()["analyses"][0]
        assert prior["status"] == "invalidated"
    with serve(state, env_file, transport) as (client, app):
        current = profile(client, base)
        assert not current["key_configured"] and not current["configured_key_enabled"]
        other = tmp_path / "other-source"
        other.mkdir()
        (other / "main.py").write_bytes(SOURCE.encode())
        other_base = workspace(client, other)
        other_profile = profile(client, other_base)
        assert other_profile["key_source"] == "env_file" and not other_profile["enabled"]
        current = update(client, base, current, use_configured_key=True)
        assert current["key_source"] == "env_file" and current["configured_key_enabled"]
        assert send(client, base, current)["status"] == "succeeded"
        assert transport.keys == [OVERRIDE, CONFIGURED]
        assert not profile(client, other_base)["enabled"]


def test_key_file_changes_only_take_effect_at_service_restart(setup):
    state, root, env_file, transport = setup
    replacement = "sk-SYNTHETIC_NEXT_STARTUP_KEY"
    with serve(state, env_file, transport) as (client, app):
        base = workspace(client, root, ["main.py"])
        current = update(client, base, profile(client, base))
        env_file.write_text(f"DEEPSEEK_API_KEY={replacement}", encoding="utf-8")
        assert send(client, base, current)["status"] == "succeeded" and transport.keys[-1] == CONFIGURED
    with serve(state, env_file, transport) as (client, app):
        assert send(client, base, profile(client, base))["status"] == "succeeded"
        assert transport.keys[-1] == replacement


def test_app_does_not_read_ambient_keys_without_trusted_injection(setup, monkeypatch):
    state, root, _env_file, transport = setup
    monkeypatch.setenv("DEEPSEEK_API_KEY", CONFIGURED)
    with TestClient(create_app(state, semantic_transport=transport), base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        base = workspace(client, root)
        assert not profile(client, base)["key_configured"]


def test_startup_key_is_not_forwarded_to_analysis_worker(setup, monkeypatch):
    state, root, env_file, transport = setup
    monkeypatch.setenv("DEEPSEEK_API_KEY", CONFIGURED)
    checked = threading.Event()

    def capture(arguments, *, cwd, env, stdout):
        assert "DEEPSEEK_API_KEY" not in env and CONFIGURED not in json.dumps(env)
        assert CONFIGURED not in json.dumps(arguments)
        checked.set()
        raise ValueError("synthetic_worker_not_started")

    monkeypatch.setattr(AnalysisManager, "_spawn", staticmethod(capture))
    with serve(state, env_file, transport) as (client, app):
        base = workspace(client, root)
        response = client.post(base + "/analyses", json={"kind": "navigation"})
        assert response.status_code == 202
        job = wait(client, base, response.json()["id"])
        assert checked.is_set() and job["status"] == "failed"
        assert CONFIGURED not in json.dumps(job)
        assert transport.keys == []
