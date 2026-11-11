"""Access confirmation, revocation and output provenance across the real API."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import sys
import time
import uuid

from fastapi.testclient import TestClient
import pytest

from codesentry.access import AccessPolicy, prepare_model_input
from codesentry.index.cache import default_cache_dir, default_index_dir
from codesentry.web.app import create_app
from codesentry.web.worker import RegisteredAccessPolicy
from codesentry.workspaces.lease import DirectoryLease


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_text("def public():\n    return 1\n", encoding="utf-8")
    (root / "private.py").write_text("PRIVATE_VALUE = 'retain-only-in-source'\n", encoding="utf-8")
    (root / ".env").write_text("SECRET=never-read\n", encoding="utf-8")
    return root


@pytest.fixture
def api(tmp_path, monkeypatch):
    # Legacy global caches are application-owned, but tests keep them local.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "user-data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    app = create_app(tmp_path / "state")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        client.application = app
        yield client


def open_confirmed(api, root, settings=None):
    response = api.post("/api/workspaces", json={
        "path": str(root), "access_policy": {"confirmed": True, "settings": settings or {}},
    })
    assert response.status_code == 201, response.text
    assert response.json()["access_policy"]["confirmed"]
    assert not response.json()["access_policy"]["cleanup_pending"]
    return response.json()


def save_policy(api, workspace_id, settings):
    response = api.patch(f"/api/workspaces/{workspace_id}",
                         json={"access_policy": {"confirmed": True, "settings": settings}})
    assert response.status_code == 200, response.text
    return response.json()


def finished(api, workspace_id, identity):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        value = api.get(f"/api/workspaces/{workspace_id}/analyses/{identity}")
        assert value.status_code == 200, value.text
        if value.json()["status"] not in {"queued", "running"}:
            return value.json()
        time.sleep(.03)
    pytest.fail("analysis did not finish")


def analyze(api, workspace_id):
    response = api.post(f"/api/workspaces/{workspace_id}/analyses", json={})
    assert response.status_code == 202, response.text
    return finished(api, workspace_id, response.json()["id"])


def test_preview_and_unconfirmed_workspace_do_not_open_source(api, source, monkeypatch):
    source_reads = []
    original = Path.open
    def spy(path, *args, **kwargs):
        if path.parent == source and path.name in {"main.py", "private.py", ".env"}:
            source_reads.append(path.name)
            raise AssertionError("unconfirmed source was opened")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", spy)
    settings = {"exclude": ["private.py"], "local_only": ["main.py"]}
    preview = api.post("/api/access/preview", json={"path": str(source), "settings": settings})
    assert preview.status_code == 200, preview.text
    names = {item["path"]: item for item in preview.json()["entries"]}
    assert names["private.py"]["mode"] == "exclude"
    assert names["main.py"]["mode"] == "local_only"
    assert names[".env"]["mode"] == "exclude"
    created = api.post("/api/workspaces", json={"path": str(source)}).json()
    assert not created["access_policy"]["confirmed"]
    identity = created["id"]
    assert api.get(f"/api/workspaces/{identity}/files").status_code == 403
    assert api.get(f"/api/workspaces/{identity}/file", params={"path": "main.py"}).status_code == 403
    assert api.post(f"/api/workspaces/{identity}/analyses", json={}).status_code == 403
    assert api.get(f"/api/workspaces/{identity}/analyses").json()["analyses"] == []
    assert source_reads == []
    confirmed = api.patch(f"/api/workspaces/{identity}", json={"access_policy": {
        "confirmed": True, "settings": settings, "fingerprint": preview.json()["access_policy"]["fingerprint"],
    }})
    assert confirmed.status_code == 200 and confirmed.json()["access_policy"]["confirmed"]
    assert source_reads == []  # Confirmation itself still does not pre-read code.


def test_two_workspaces_policy_isolation_and_explicit_reopen_updates_scope(api, source, tmp_path):
    second = tmp_path / "second"
    second.mkdir()
    (second / "private.py").write_text("value = 2\n", encoding="utf-8")
    first = open_confirmed(api, source, {"exclude": ["private.py"]})
    other = open_confirmed(api, second)
    assert api.get(f"/api/workspaces/{first['id']}/file", params={"path": "private.py"}).status_code == 403
    assert api.get(f"/api/workspaces/{other['id']}/file", params={"path": "private.py"}).status_code == 200
    previous = first
    reopened = open_confirmed(api, source, {"exclude": ["private.py", "main.py"]})
    assert reopened["id"] == first["id"]
    assert reopened["access_policy"]["settings"]["exclude"] == ["private.py", "main.py"]
    assert reopened["access_policy"]["version"] > previous["access_policy"]["version"]
    assert api.get(f"/api/workspaces/{first['id']}/file", params={"path": "main.py"}).status_code == 403
    assert api.get(f"/api/workspaces/{other['id']}/file", params={"path": "private.py"}).status_code == 200


def test_preview_confirmation_rejects_rules_changed_since_preview(api, source):
    ignore = source / ".gitignore"
    ignore.write_text("", encoding="utf-8")
    preview = api.post("/api/access/preview", json={"path": str(source), "settings": {}}).json()
    ignore.write_text("private.py\n", encoding="utf-8")
    response = api.post("/api/workspaces", json={"path": str(source), "access_policy": {
        "confirmed": True, "settings": {}, "fingerprint": preview["access_policy"]["fingerprint"],
    }})
    assert response.status_code == 400 and "重新预览" in response.json()["detail"]
    workspace = api.get("/api/workspaces").json()["workspaces"][0]
    assert not workspace["access_policy"]["confirmed"]


def test_actual_worker_never_opens_excluded_source_and_outputs_bind_policy(api, source, tmp_path, monkeypatch):
    workspace = open_confirmed(api, source, {"exclude": ["private.py"], "local_only": ["main.py"]})
    manager = api.application.state.manager
    original = manager._spawn
    audit = tmp_path / "opened-source.jsonl"
    prefix = (
        "import sys,os,json\n"
        f"watched_root={str(source.resolve())!r}\n"
        f"audit_file={str(audit)!r}\n"
        "def source_open(event,args):\n"
        " if event == 'open' and isinstance(args[0],str):\n"
        "  candidate=os.path.abspath(args[0])\n"
        "  if os.path.dirname(candidate) == watched_root:\n"
        "   with open(audit_file,'a',encoding='utf-8') as out: out.write(json.dumps(os.path.basename(candidate))+'\\n')\n"
        "sys.addaudithook(source_open)\n"
    )
    def audited(arguments, **kwargs):
        arguments = list(arguments)
        arguments[3] = prefix + arguments[3]
        return original(arguments, **kwargs)
    monkeypatch.setattr(manager, "_spawn", audited)
    job = analyze(api, workspace["id"])
    assert job["status"] == "incomplete", job
    opens = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert "main.py" in opens
    assert "private.py" not in opens and ".env" not in opens
    payload = job["result"]
    assert payload["policy_version"] == workspace["access_policy"]["version"]
    assert payload["policy_fingerprint"] == workspace["access_policy"]["fingerprint"]
    assert {item["path"] for item in payload["file_details"]} == {"main.py"}
    assert "retain-only-in-source" not in json.dumps(payload)
    assert not payload["is_complete"]
    policy = AccessPolicy(source, workspace["access_policy"]["settings"], confirmed=True)
    with pytest.raises((PermissionError, ValueError)):
        prepare_model_input(policy, ["main.py"], service="test-spy", purpose="test", authorized=True)
    with pytest.raises((PermissionError, ValueError)):
        prepare_model_input(policy, [], service="test-spy", purpose="test", authorized=True, derived=payload)


@pytest.mark.parametrize("kind", ["navigation", "review_preview", "gate_check", "defect_preview"])
def test_revocation_denies_before_cleanup_kills_worker_and_rejects_late_publish(api, source, monkeypatch, kind):
    workspace = open_confirmed(api, source)
    manager = api.application.state.manager
    store = api.application.state.store
    original_spawn, original_cleanup = manager._spawn, manager._cleanup_workspace
    spawned = []
    def slow(arguments, **kwargs):
        process = original_spawn([sys.executable, "-I", "-c",
                                  "import time; print('private-derived-log',flush=True); time.sleep(30)"], **kwargs)
        spawned.append(process)
        return process
    monkeypatch.setattr(manager, "_spawn", slow)
    identity = api.post(f"/api/workspaces/{workspace['id']}/analyses", json={"kind": kind}).json()["id"]
    deadline = time.monotonic() + 10
    while not spawned and time.monotonic() < deadline:
        time.sleep(.01)
    assert spawned
    artifact = store.result_file(workspace["id"], identity)
    artifact.write_text("old-private-result", encoding="utf-8")
    def verify_deny(identity):
        access = store.workspace_policy(identity)
        assert access["cleanup_pending"] and access["settings"]["exclude"] == ["private.py"]
        assert spawned[0].poll() is not None
        assert store.get_analysis(identity, job_id)["logs"] == []
        original_cleanup(identity)
    job_id = identity
    monkeypatch.setattr(manager, "_cleanup_workspace", verify_deny)
    changed = save_policy(api, workspace["id"], {"exclude": ["private.py"]})
    assert changed["access_policy"]["version"] > workspace["access_policy"]["version"]
    assert not changed["access_policy"]["cleanup_pending"]
    assert not artifact.exists() and not artifact.with_name("worker.log").exists()
    store.update_analysis(workspace["id"], identity, status="succeeded", result_path="late-forged-result")
    late = api.get(f"/api/workspaces/{workspace['id']}/analyses/{identity}").json()
    assert late["status"] == "invalidated" and late["result"] is None and late["logs"] == []
    assert "retain-only-in-source" in (source / "private.py").read_text()
    assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "private.py"}).status_code == 403


def test_cleanup_failure_remains_denied_until_explicit_retry(api, source, monkeypatch):
    workspace = open_confirmed(api, source)
    job = analyze(api, workspace["id"])
    assert job["status"] == "succeeded"
    manager = api.application.state.manager
    original = manager._cleanup_workspace
    def fail(_identity):
        raise PermissionError("test-owned artifact locked")
    monkeypatch.setattr(manager, "_cleanup_workspace", fail)
    changed = save_policy(api, workspace["id"], {"exclude": ["private.py"]})
    assert changed["access_policy"]["cleanup_pending"]
    assert "尚未完成" in changed["access_policy"]["cleanup_error"]
    assert changed["last_analysis"]["logs"] == [] and changed["last_analysis"]["result"] is None
    for path in ("/files", f"/analyses/{job['id']}"):
        assert api.get(f"/api/workspaces/{workspace['id']}{path}").status_code == 403
    assert api.post(f"/api/workspaces/{workspace['id']}/analyses", json={}).status_code == 403
    monkeypatch.setattr(manager, "_cleanup_workspace", original)
    retried = save_policy(api, workspace["id"], {"exclude": ["private.py"]})
    assert not retried["access_policy"]["cleanup_pending"]
    assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "main.py"}).status_code == 200


def test_git_rule_change_increments_version_and_removes_previous_outputs(api, source):
    ignore = source / ".gitignore"
    ignore.write_text("", encoding="utf-8")
    workspace = open_confirmed(api, source)
    job = analyze(api, workspace["id"])
    assert job["status"] == "succeeded", job
    artifact = api.application.state.store.result_file(workspace["id"], job["id"])
    ignore.write_text("private.py\n", encoding="utf-8")
    assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "private.py"}).status_code == 403
    current = api.get(f"/api/workspaces/{workspace['id']}").json()
    assert current["access_policy"]["version"] > workspace["access_policy"]["version"]
    assert current["access_policy"]["fingerprint"] != workspace["access_policy"]["fingerprint"]
    invalid = api.get(f"/api/workspaces/{workspace['id']}/analyses/{job['id']}").json()
    assert invalid["status"] == "invalidated" and invalid["logs"] == [] and invalid["result"] is None
    assert not artifact.exists()


def test_local_only_then_relaxation_never_restores_old_results_or_authorizes_models(api, source):
    workspace = open_confirmed(api, source, {"model_scope": ["main.py"]})
    job = analyze(api, workspace["id"])
    assert job["status"] == "succeeded"
    local = save_policy(api, workspace["id"], {"local_only": ["main.py"], "model_scope": ["main.py"]})
    policy = AccessPolicy(source, local["access_policy"]["settings"], confirmed=True)
    with pytest.raises((PermissionError, ValueError)):
        prepare_model_input(policy, ["main.py"], service="test-spy", purpose="test", authorized=True)
    assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "main.py"}).status_code == 200
    save_policy(api, workspace["id"], {"model_scope": ["main.py"]})
    invalid = api.get(f"/api/workspaces/{workspace['id']}/analyses/{job['id']}").json()
    assert invalid["status"] == "invalidated" and invalid["result"] is None
    eligible = AccessPolicy(source, {"model_scope": ["main.py"]}, confirmed=True)
    with pytest.raises((PermissionError, ValueError)):
        prepare_model_input(eligible, ["main.py"], service="test-spy", purpose="test", authorized=False)


def test_old_worker_checks_registry_before_every_source_and_git_control_read(api, source, monkeypatch):
    (source / ".gitignore").write_text("", encoding="utf-8")
    workspace = open_confirmed(api, source)
    store = api.application.state.store
    snapshot = workspace["access_policy"]
    worker_access = RegisteredAccessPolicy(source, store.data_dir, workspace["id"], snapshot)
    opened = []
    original = Path.open
    def spy(path, *args, **kwargs):
        if path.parent == source:
            opened.append(path.name)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", spy)
    try:
        assert worker_access.read_bytes("private.py")
        store.begin_policy_change(workspace["id"], AccessPolicy(source, {"exclude": ["private.py", ".gitignore"]}))
        before = list(opened)
        with pytest.raises(PermissionError):
            worker_access.read_bytes("private.py")
        with pytest.raises(PermissionError):
            worker_access.refresh()  # Denied control files are not read either.
        assert opened == before
    finally:
        worker_access.close()


def test_confirmation_cleans_legacy_managed_caches_without_loading_payload(api, source, monkeypatch):
    cache, index = default_cache_dir(source), default_index_dir(source)
    cache.mkdir(parents=True)
    index.mkdir(parents=True)
    artifacts = [cache / "parse_cache.json", cache / "parse_cache.access.json",
                 index / "index.json", index / "index.json.access.json"]
    for artifact in artifacts:
        artifact.write_text("old-private-derived-content", encoding="utf-8")
    original = Path.open
    def deny_old_payload(path, *args, **kwargs):
        if path in artifacts:
            raise AssertionError("old managed payload was loaded during cleanup")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", deny_old_payload)
    workspace = open_confirmed(api, source, {"exclude": ["private.py"]})
    assert not workspace["access_policy"]["cleanup_pending"]
    assert all(not artifact.exists() for artifact in artifacts)
    assert (source / "private.py").is_file()


def test_stale_git_sync_cannot_restore_older_broader_user_settings(api, source):
    workspace = open_confirmed(api, source)
    manager = api.application.state.manager
    version = workspace["access_policy"]["version"]
    changed = save_policy(api, workspace["id"], {"exclude": ["private.py"]})
    stale = manager.confirm_policy(workspace["id"], workspace["access_policy"]["settings"],
                                   expected_version=version, stale_ok=True)
    assert stale["access_policy"]["version"] == changed["access_policy"]["version"]
    assert stale["access_policy"]["settings"]["exclude"] == ["private.py"]
    assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "private.py"}).status_code == 403


@pytest.mark.parametrize("submit", ["patch", "reopen"])
def test_old_broader_preview_cannot_undo_another_windows_restriction(api, source, submit):
    workspace = open_confirmed(api, source)
    preview = api.post("/api/access/preview", json={"path": str(source), "settings": {}}).json()
    changed = save_policy(api, workspace["id"], {"exclude": ["private.py"]})
    confirmation = {"confirmed": True, "settings": {}, "fingerprint": preview["access_policy"]["fingerprint"],
                    "expected_version": preview["expected_version"]}
    response = (api.patch(f"/api/workspaces/{workspace['id']}", json={"access_policy": confirmation})
                if submit == "patch" else
                api.post("/api/workspaces", json={"path": str(source), "access_policy": confirmation}))
    assert response.status_code == 409 and "重新预览" in response.json()["detail"]
    current = api.get(f"/api/workspaces/{workspace['id']}").json()
    assert current["access_policy"]["version"] == changed["access_policy"]["version"]
    assert current["access_policy"]["settings"]["exclude"] == ["private.py"]
    assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "private.py"}).status_code == 403


def test_new_directory_preview_cannot_override_a_workspace_created_in_another_window(api, source):
    preview = api.post("/api/access/preview", json={"path": str(source), "settings": {}}).json()
    assert preview["expected_version"] == 0
    workspace = open_confirmed(api, source, {"exclude": ["private.py"]})
    response = api.post("/api/workspaces", json={"path": str(source), "access_policy": {
        "confirmed": True, "settings": {}, "fingerprint": preview["access_policy"]["fingerprint"],
        "expected_version": preview["expected_version"],
    }})
    assert response.status_code == 409
    assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "private.py"}).status_code == 403


def test_metadata_endpoints_never_restore_source_derived_logs_or_errors(api, source):
    workspace = open_confirmed(api, source)
    job = analyze(api, workspace["id"])
    store = api.application.state.store
    store.append_log(workspace["id"], job["id"], "source-derived-private-marker")
    store.update_analysis(workspace["id"], job["id"], error="source-derived-private-marker")
    detail = api.get(f"/api/workspaces/{workspace['id']}/analyses/{job['id']}").json()
    assert "source-derived-private-marker" in detail["logs"]
    for path in ("/api/workspaces", f"/api/workspaces/{workspace['id']}",
                 f"/api/workspaces/{workspace['id']}/analyses"):
        response = api.get(path)
        assert response.status_code == 200
        assert "source-derived-private-marker" not in response.text
    changed = save_policy(api, workspace["id"], {"exclude": ["private.py"]})
    assert changed["last_analysis"]["logs"] == [] and changed["last_analysis"]["result"] is None


def test_revoking_queued_workspace_does_not_wait_for_other_workspace_worker(api, source, tmp_path, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    (other / "main.py").write_text("value = 1\n", encoding="utf-8")
    first, second = open_confirmed(api, source), open_confirmed(api, other)
    manager = api.application.state.manager
    original = manager._spawn
    spawned = []
    def slow(arguments, **kwargs):
        process = original([sys.executable, "-I", "-c", "import time; time.sleep(30)"], **kwargs)
        spawned.append(process)
        return process
    monkeypatch.setattr(manager, "_spawn", slow)
    running = api.post(f"/api/workspaces/{first['id']}/analyses", json={}).json()["id"]
    deadline = time.monotonic() + 10
    while not spawned and time.monotonic() < deadline:
        time.sleep(.01)
    queued = api.post(f"/api/workspaces/{second['id']}/analyses", json={}).json()["id"]
    changed = save_policy(api, second["id"], {"exclude": ["main.py"]})
    assert not changed["access_policy"]["cleanup_pending"]
    assert spawned[0].poll() is None
    assert api.application.state.store.get_analysis(second["id"], queued)["status"] == "invalidated"
    assert api.post(f"/api/workspaces/{first['id']}/analyses/{running}/cancel").json()["status"] == "cancelled"


@pytest.mark.skipif(os.name != "nt", reason="Windows application-state junction safety")
def test_cleanup_refuses_redirected_job_directory_and_never_touches_source(api, source):
    import _winapi
    workspace = open_confirmed(api, source)
    job = analyze(api, workspace["id"])
    assert job["status"] == "succeeded"
    store = api.application.state.store
    artifact = store.result_file(workspace["id"], job["id"])
    directory = artifact.parent
    saved = directory.with_name(directory.name + "-saved")
    assert directory.resolve().is_relative_to(store.data_dir)
    directory.rename(saved)
    _winapi.CreateJunction(str(source), str(directory))
    try:
        changed = save_policy(api, workspace["id"], {"exclude": ["private.py"]})
        assert changed["access_policy"]["cleanup_pending"]
        assert (source / "main.py").read_text().startswith("def public")
        assert (source / "private.py").read_text().startswith("PRIVATE_VALUE")
        assert api.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "main.py"}).status_code == 403
    finally:
        directory.rmdir()  # Remove only the junction itself.
        saved.rename(directory)
    assert not save_policy(api, workspace["id"], {"exclude": ["private.py"]})["access_policy"]["cleanup_pending"]


def test_thousand_file_worker_cancellation_does_not_wait_for_metadata_scan(api, source, record_property):
    for number in range(1000):
        (source / f"unit_{number:04}.py").write_text(
            "".join(f"def function_{item}():\n    return {item}\n" for item in range(40)), encoding="utf-8")
    workspace = open_confirmed(api, source)
    manager = api.application.state.manager
    created = api.post(f"/api/workspaces/{workspace['id']}/analyses", json={})
    assert created.status_code == 202
    identity = created.json()["id"]
    deadline = time.monotonic() + 15
    while not manager.processes and time.monotonic() < deadline:
        time.sleep(.01)
    assert manager.processes
    process = next(iter(manager.processes.values()))
    with ThreadPoolExecutor(max_workers=1) as readers:
        polling = readers.submit(api.get, "/api/workspaces")
        started = time.monotonic()
        response = api.post(f"/api/workspaces/{workspace['id']}/analyses/{identity}/cancel")
        elapsed = time.monotonic() - started
        record_property("cancel_seconds_with_1000_files", round(elapsed, 4))
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "cancelled"
        assert response.json()["logs"] == [] and response.json()["result"] is None
        assert process.poll() is not None
        assert elapsed < 5, f"cancel waited for metadata/source scan: {elapsed:.3f}s"
        assert polling.result(timeout=15).status_code == 200


def test_legacy_sqlite_migrates_unconfirmed_without_loading_old_content(tmp_path, source, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    workspace_id, analysis_id = uuid.uuid4().hex, uuid.uuid4().hex
    artifact = state / "workspaces" / workspace_id / "analyses" / analysis_id / "result.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"old-sensitive-payload": true}', encoding="utf-8")
    connection = sqlite3.connect(state / "workspaces.sqlite3")
    connection.executescript("""
        CREATE TABLE workspaces(id TEXT PRIMARY KEY,name TEXT,path TEXT,canonical_key TEXT UNIQUE,
                                created_at TEXT,updated_at TEXT,config TEXT);
        CREATE TABLE analyses(id TEXT PRIMARY KEY,workspace_id TEXT,status TEXT,created_at TEXT,
                              started_at TEXT,finished_at TEXT,elapsed_seconds REAL,error TEXT,
                              logs TEXT,config TEXT,result_path TEXT);
    """)
    connection.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?,?)",
                       (workspace_id, "Legacy", str(source), os.path.normcase(str(source.resolve())),
                        "2020-01-01", "2020-01-01", '{"max_depth":4,"max_items":30}'))
    connection.execute("INSERT INTO analyses VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       (analysis_id, workspace_id, "succeeded", "2020-01-01", None, None, 1.0, None,
                        '["old-sensitive-log"]', '{"max_depth":4,"max_items":30}', str(artifact.relative_to(state))))
    connection.commit()
    connection.close()
    reads = []
    original = Path.open
    def forbidden(path, *args, **kwargs):
        if path == artifact or path in {source / "main.py", source / "private.py", source / ".env"}:
            reads.append(str(path))
            raise AssertionError("legacy output or unconfirmed source was read")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "user-data"))
    app = create_app(state)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        legacy = client.get("/api/workspaces").json()["workspaces"][0]
        assert not legacy["access_policy"]["confirmed"] and legacy["access_policy"]["version"] == 0
        assert legacy["last_analysis"]["logs"] == [] and legacy["last_analysis"]["result"] is None
        assert client.get(f"/api/workspaces/{workspace_id}/file", params={"path": "main.py"}).status_code == 403
        assert client.get(f"/api/workspaces/{workspace_id}/analyses/{analysis_id}").status_code == 403
        assert client.post(f"/api/workspaces/{workspace_id}/analyses", json={}).status_code == 403
        save_policy(client, workspace_id, {"exclude": ["private.py"]})
        assert not artifact.exists()
        invalid = client.get(f"/api/workspaces/{workspace_id}/analyses/{analysis_id}").json()
        assert invalid["status"] == "invalidated" and invalid["logs"] == [] and invalid["result"] is None
        assert reads == []


def test_upgrade_refuses_live_data_directory_before_altering_legacy_schema(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    database = state / "workspaces.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE workspaces(id TEXT PRIMARY KEY,name TEXT,path TEXT,canonical_key TEXT UNIQUE,"
                       "created_at TEXT,updated_at TEXT,config TEXT)")
    connection.commit()
    connection.close()
    lease = DirectoryLease(state)
    try:
        with pytest.raises(RuntimeError, match="另一个"):
            create_app(state)
        connection = sqlite3.connect(database)
        try:
            assert "access_policy" not in {row[1] for row in connection.execute("PRAGMA table_info(workspaces)")}
        finally:
            connection.close()
    finally:
        lease.close()
