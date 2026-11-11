"""Workspace boundaries, source-only viewing and the real local analysis worker."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from fastapi.testclient import TestClient
import pytest

from codesentry.index.cache import hash_content
from codesentry.web.app import create_app
from codesentry.web.jobs import AnalysisManager
from codesentry.web.processes import track_family, stop_family
from codesentry.workspaces.store import WorkspaceStore
from codesentry.workspaces.lease import DirectoryLease


@pytest.fixture
def projects(tmp_path):
    roots = [tmp_path / "alpha", tmp_path / "beta"]
    for number, root in enumerate(roots):
        root.mkdir()
        (root / "main.py").write_text(f"PROJECT = {number}\ndef run():\n    return PROJECT\n", encoding="utf-8")
        (root / "README.md").write_text(f"Project {number}", encoding="utf-8")
        (root / ".env").write_text("API_KEY=do-not-read", encoding="utf-8")
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text("private", encoding="utf-8")
        (root / "node_modules").mkdir()
        (root / "node_modules" / "bad.js").write_text("throw Error('never load');", encoding="utf-8")
    return roots


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "state")
    with TestClient(app, base_url="http://127.0.0.1") as selected:
        session = selected.get("/api/session")
        assert session.status_code == 200
        selected.headers["X-CodeSentry-Token"] = session.json()["token"]
        selected.app_instance = app
        yield selected


def register(client, root, name=None):
    response = client.post("/api/workspaces", json={"path": str(root), "name": name,
                           "access_policy": {"confirmed": True, "settings": {}}})
    assert response.status_code == 201, response.text
    return response.json()


def wait_job(client, workspace_id, identity, *, limit=20):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        response = client.get(f"/api/workspaces/{workspace_id}/analyses/{identity}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(0.05)
    pytest.fail(f"analysis did not finish: {identity}")


def test_two_workspaces_isolate_files_settings_and_reopen(client, projects):
    first, second = [register(client, root) for root in projects]
    assert first["id"] != second["id"]
    assert register(client, projects[0] / ".")["id"] == first["id"]
    changed = client.patch(f"/api/workspaces/{first['id']}", json={"name": "Renamed", "config": {"max_depth": 7}})
    assert changed.status_code == 200 and changed.json()["config"]["max_depth"] == 7
    assert client.get(f"/api/workspaces/{second['id']}").json()["config"]["max_depth"] == 4
    for expected, workspace in enumerate([first, second]):
        viewed = client.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "main.py"})
        assert viewed.status_code == 200
        assert viewed.json()["workspace_id"] == workspace["id"]
        assert f"PROJECT = {expected}" in viewed.json()["content"]
        names = {item["path"] for item in client.get(f"/api/workspaces/{workspace['id']}/files").json()["files"]}
        assert names == {"README.md", "main.py"}


@pytest.mark.parametrize("path", [
    "../beta/main.py", "folder/../../main.py", "/etc/passwd", r"C:\Windows\win.ini",
    "main.py:stream", ".env", ".git/config", "node_modules/bad.js",
    "%2e%2e/beta/main.py", "%252e%252e/beta/main.py", r"\\server\share\file.py",
])
def test_unsafe_or_secret_source_paths_are_rejected(client, projects, path):
    workspace = register(client, projects[0])
    response = client.get(f"/api/workspaces/{workspace['id']}/file", params={"path": path})
    assert response.status_code in {400, 403, 404}, response.text


def test_symlink_cannot_cross_source_root(client, projects):
    link = projects[0] / "escape.py"
    try:
        link.symlink_to(projects[1] / "main.py")
    except OSError:
        pytest.skip("This Windows account cannot create symlinks")
    workspace = register(client, projects[0])
    assert client.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "escape.py"}).status_code in {400, 403}


@pytest.mark.skipif(os.name != "nt", reason="Windows junction boundary")
def test_windows_junction_cannot_cross_source_root(client, projects):
    import _winapi
    _winapi.CreateJunction(str(projects[1]), str(projects[0] / "linked"))
    workspace = register(client, projects[0])
    assert client.get(f"/api/workspaces/{workspace['id']}/file",
                      params={"path": "linked/main.py"}).status_code in {400, 403}
    names = {item["path"] for item in client.get(f"/api/workspaces/{workspace['id']}/files").json()["files"]}
    assert "linked/main.py" not in names


def test_host_origin_and_session_are_enforced(client, projects):
    assert client.get("/api/workspaces", headers={"X-CodeSentry-Token": ""}).status_code == 401
    assert client.get("/api/session", headers={"Host": "attacker.example"}).status_code == 400
    assert client.get("/api/session", headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.get("/api/session", headers={"Origin": "null"}).status_code == 403
    assert client.get("/api/session", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/api/workspaces", headers={"Origin": "http://127.0.0.1"}).status_code == 200
    denied = client.post("/api/workspaces", content="path=x", headers={"Content-Type": "text/plain"})
    assert denied.status_code == 415
    response = client.get("/api/session")
    assert "access-control-allow-origin" not in response.headers
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["capabilities"] == {"analysis": True, "review": True, "chat": True}
    assert response.json()["review_mode"] == "preview"


@pytest.mark.parametrize("raw,decoded,suffix", [
    (b"first\r\nsecond\r\n", "first\r\nsecond\r\n", ".txt"),
    (b"\xef\xbb\xbfexport const value = 1;\r\n", "export const value = 1;\r\n", ".ts"),
    (b'# coding: cp1252\r\nname = "caf\xe9"\r\n', '# coding: cp1252\r\nname = "caf\u00e9"\r\n', ".py"),
])
def test_view_hash_matches_decoded_builder_semantics(client, projects, raw, decoded, suffix):
    path = projects[0] / ("encoding" + suffix)
    path.write_bytes(raw)
    workspace = register(client, projects[0])
    response = client.get(f"/api/workspaces/{workspace['id']}/file", params={"path": path.name})
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["content"] == decoded
    assert value["sha256"] == hashlib.sha256(raw).hexdigest()
    assert value["content_hash"] == hash_content(decoded)
    assert value["content_hash_algorithm"] == "sha1-decoded-text"


@pytest.mark.parametrize("raw", [b"# coding: no-such-codec\nvalue = 1\n", b"\xffinvalid\n"])
def test_invalid_python_encoding_is_a_readable_client_error(client, projects, raw):
    (projects[0] / "invalid.py").write_bytes(raw)
    workspace = register(client, projects[0])
    response = client.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "invalid.py"})
    assert response.status_code == 400
    assert "编码" in response.json()["detail"]


def test_workspace_registry_and_configuration_survive_service_restart(tmp_path, projects):
    state = tmp_path / "state"
    with TestClient(create_app(state), base_url="http://127.0.0.1") as first:
        first.headers["X-CodeSentry-Token"] = first.get("/api/session").json()["token"]
        workspace = register(first, projects[0])
        first.patch(f"/api/workspaces/{workspace['id']}", json={"config": {"max_items": 50}})
    with TestClient(create_app(state), base_url="http://127.0.0.1") as second:
        second.headers["X-CodeSentry-Token"] = second.get("/api/session").json()["token"]
        restored = second.get(f"/api/workspaces/{workspace['id']}").json()
        assert restored["path"] == str(projects[0].resolve())
        assert restored["config"]["max_items"] == 50


def test_real_analysis_result_is_workspace_scoped_and_source_is_not_executed(client, projects):
    marker = projects[0] / "executed.txt"
    (projects[0] / "main.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\ndef run():\n    return 1\n",
        encoding="utf-8",
    )
    first, second = [register(client, root) for root in projects]
    created = client.post(f"/api/workspaces/{first['id']}/analyses", json={})
    assert created.status_code == 202, created.text
    job = wait_job(client, first["id"], created.json()["id"])
    assert job["status"] == "succeeded", job
    assert job["result"]["workspace_id"] == first["id"]
    assert job["result"]["analysis_id"] == job["id"]
    assert job["result"]["analysis_mode"] == "static"
    assert job["result"]["review_status"] == "not_implemented"
    assert job["result"]["analysis_provenance"] == client.app_instance.state.store.analysis_provenance
    logs = '\n'.join(job['logs'])
    assert '读取环境声明并解析源码（未运行目标代码）' in logs
    assert '个文件；导航报告已生成，审查需另行启动' in logs
    assert '\ufffd' not in logs
    assert job["result"]["file_details"] and job["result"]["symbol_details"]
    assert not marker.exists()
    assert client.get(f"/api/workspaces/{second['id']}/analyses/{job['id']}").status_code == 404
    assert client.post(f"/api/workspaces/{second['id']}/analyses/{job['id']}/cancel").status_code == 404
    assert client.get(f"/api/workspaces/{second['id']}/analyses").json()["analyses"] == []
    before = client.get(f"/api/workspaces/{first['id']}/file", params={"path": "main.py", "analysis_id": job["id"]})
    assert before.json()["is_stale"] is False
    (projects[0] / "main.py").write_text("changed = True\n", encoding="utf-8")
    after = client.get(f"/api/workspaces/{first['id']}/file", params={"path": "main.py", "analysis_id": job["id"]})
    assert after.json()["is_stale"] is True
    assert client.get(f"/api/workspaces/{second['id']}/file",
                      params={"path": "main.py", "analysis_id": job["id"]}).status_code == 404
    other_created = client.post(f"/api/workspaces/{second['id']}/analyses", json={})
    other = wait_job(client, second["id"], other_created.json()["id"])
    assert other["status"] == "succeeded"
    assert other["result"]["workspace_id"] == second["id"]
    assert other["result"]["analysis_id"] != job["id"]
    first_hash = next(item["content_hash"] for item in job["result"]["file_details"] if item["path"] == "main.py")
    second_hash = next(item["content_hash"] for item in other["result"]["file_details"] if item["path"] == "main.py")
    assert first_hash != second_hash


def test_tool_upgrade_invalidates_history_before_payload_read_and_keeps_file_view(client, projects, monkeypatch):
    workspace = register(client, projects[0])
    store = client.app_instance.state.store
    job = store.create_analysis(workspace["id"])
    artifact = store.result_file(workspace["id"], job["id"])
    artifact.write_text("do not open an old implementation's payload", encoding="utf-8")
    store.update_analysis(workspace["id"], job["id"], status="succeeded",
                          result_path=str(artifact.relative_to(store.data_dir)))
    store.analysis_provenance = "web-analysis-v2:" + "a" * 64
    original = Path.read_text
    def forbid_old_payload(path, *args, **kwargs):
        if path == artifact:
            pytest.fail("outdated implementation payload was opened")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", forbid_old_payload)
    summary = client.get(f"/api/workspaces/{workspace['id']}").json()["last_analysis"]
    assert summary["status"] == "invalidated" and summary["result_state"] == "unavailable"
    detail = client.get(f"/api/workspaces/{workspace['id']}/analyses/{job['id']}").json()
    assert detail["result"] is None and "工具" in detail["error"]
    assert client.get(f"/api/workspaces/{workspace['id']}/analyses").json()["analyses"][0]["status"] == "invalidated"
    assert client.get(f"/api/workspaces/{workspace['id']}/file",
                      params={"path": "main.py", "analysis_id": job["id"]}).status_code == 409
    assert client.get(f"/api/workspaces/{workspace['id']}/file", params={"path": "main.py"}).status_code == 200


@pytest.mark.parametrize("missing_location", ["snapshot", "payload"])
def test_legacy_result_without_implementation_identity_is_not_current(client, projects, missing_location):
    workspace = register(client, projects[0])
    store = client.app_instance.state.store
    job = store.create_analysis(workspace["id"])
    snapshot = store.analysis_policy(workspace["id"], job["id"])
    payload = {"workspace_id": workspace["id"], "analysis_id": job["id"],
               "policy_version": snapshot["version"], "policy_fingerprint": snapshot["fingerprint"],
               "analysis_provenance": store.analysis_provenance}
    if missing_location == "snapshot":
        snapshot.pop("analysis_provenance")
        with store.connection() as connection:
            connection.execute("UPDATE analyses SET access_policy=? WHERE id=?", (json.dumps(snapshot), job["id"]))
    else:
        payload.pop("analysis_provenance")
    artifact = store.result_file(workspace["id"], job["id"])
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    store.update_analysis(workspace["id"], job["id"], status="succeeded",
                          result_path=str(artifact.relative_to(store.data_dir)))
    result = client.get(f"/api/workspaces/{workspace['id']}/analyses/{job['id']}").json()
    assert result["status"] == "invalidated" and result["result"] is None
    assert "格式已更新" in result["error"]


def test_unknown_analysis_modes_are_not_silently_run(client, projects):
    workspace = register(client, projects[0])
    assert client.post(f"/api/workspaces/{workspace['id']}/analyses", json={"mode": "review"}).status_code == 422
    assert client.patch(f"/api/workspaces/{workspace['id']}", json={"config": {"max_depth": True}}).status_code == 422


def test_interrupted_analysis_is_not_restored_as_success(tmp_path, projects):
    store = WorkspaceStore(tmp_path / "state")
    workspace = store.create_workspace(str(projects[0]), access_policy={"confirmed": True, "settings": {}})
    job = store.create_analysis(workspace["id"])
    store.update_analysis(workspace["id"], job["id"], status="running")
    with TestClient(create_app(tmp_path / "state"), base_url="http://127.0.0.1") as selected:
        selected.headers["X-CodeSentry-Token"] = selected.get("/api/session").json()["token"]
        restored = selected.get(f"/api/workspaces/{workspace['id']}/analyses/{job['id']}").json()
        assert restored["status"] == "interrupted"
        assert restored["result"] is None


def test_second_manager_cannot_interrupt_live_first_instance(tmp_path, projects):
    store = WorkspaceStore(tmp_path / "state")
    workspace = store.create_workspace(str(projects[0]), access_policy={"confirmed": True, "settings": {}})
    first = AnalysisManager(store)
    try:
        job = store.create_analysis(workspace["id"])
        store.update_analysis(workspace["id"], job["id"], status="running")
        with pytest.raises(RuntimeError, match="另一个"):
            AnalysisManager(WorkspaceStore(tmp_path / "state"))
        assert store.get_analysis(workspace["id"], job["id"])["status"] == "running"
    finally:
        first.close()
    restarted = AnalysisManager(store)
    try:
        assert store.get_analysis(workspace["id"], job["id"])["status"] == "interrupted"
    finally:
        restarted.close()


def test_os_releases_data_directory_lock_after_holder_process_exits(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    ready = tmp_path / "ready"
    bootstrap = (
        f"import sys; sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r}); "
        "from pathlib import Path; from codesentry.workspaces.lease import DirectoryLease; import os,time; "
        f"lease=DirectoryLease(Path({str(state)!r})); Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(30)"
    )
    process = subprocess.Popen([sys.executable, "-I", "-c", bootstrap])
    track_family(process)
    owner_handle = None
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists()
        if os.name == "nt":
            import _winapi
            # A Windows venv launcher can have a different PID from the actual
            # interpreter that holds the lock. Wait for that owner, not merely
            # for its launcher; do not weaken the lease with retries.
            owner_handle = _winapi.OpenProcess(0x100000, False, int(ready.read_text()))
        with pytest.raises(RuntimeError, match="另一个"):
            DirectoryLease(state)
    finally:
        stop_family(process)
        if owner_handle is not None:
            try:
                assert _winapi.WaitForSingleObject(owner_handle, 5000) == 0
            finally:
                _winapi.CloseHandle(owner_handle)
    lease = DirectoryLease(state)
    lease.close()
    assert (state / ".instance.lock").is_file()


@pytest.mark.parametrize("damage", ["deleted", "corrupt", "wrong_identity"])
def test_finished_result_damage_is_persistently_invalidated(client, projects, damage):
    workspace = register(client, projects[0])
    identity = client.post(f"/api/workspaces/{workspace['id']}/analyses", json={}).json()["id"]
    completed = wait_job(client, workspace["id"], identity)
    assert completed["status"] == "succeeded"
    artifact = client.app_instance.state.store.result_file(workspace["id"], identity)
    if damage == "deleted":
        artifact.unlink()
        # Workspace summary must not claim successful analysis after deletion.
        assert client.get(f"/api/workspaces/{workspace['id']}").json()["last_analysis"]["status"] == "invalidated"
    else:
        artifact.write_text("{" if damage == "corrupt" else json.dumps({"workspace_id": "other", "analysis_id": identity}),
                            encoding="utf-8")
    url = f"/api/workspaces/{workspace['id']}/analyses/{identity}"
    invalid = client.get(url).json()
    assert invalid["status"] == "invalidated"
    assert invalid["result"] is None and invalid["result_state"] == "unavailable"
    assert "重新分析" in invalid["error"]
    assert client.get(url).json()["status"] == "invalidated"
    assert client.get(f"/api/workspaces/{workspace['id']}/analyses").json()["analyses"][0]["status"] == "invalidated"


def test_worker_can_be_cancelled_and_queue_remains_usable(tmp_path, projects, monkeypatch):
    store = WorkspaceStore(tmp_path / "state")
    workspace = store.create_workspace(str(projects[0]), access_policy={"confirmed": True, "settings": {}})
    manager = AnalysisManager(store)
    original = manager._spawn
    spawned = []
    child_pid_file = tmp_path / "children.json"
    grandchild = "import time; time.sleep(30)"
    child = (
        "import subprocess,sys,time,json; from pathlib import Path; "
        f"grandchild=subprocess.Popen([sys.executable,'-I','-c',{grandchild!r}]); "
        f"Path({str(child_pid_file)!r}).write_text(json.dumps([__import__('os').getpid(), grandchild.pid])); time.sleep(30)"
    )
    parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-I','-c',{child!r}]); time.sleep(30)"
    def slow(arguments, **kwargs):
        process = original([sys.executable, "-I", "-c", parent], **kwargs)
        spawned.append(process)
        return process
    monkeypatch.setattr(manager, "_spawn", slow)
    try:
        job = manager.submit(workspace["id"])
        deadline = time.monotonic() + 10
        while (not spawned or not child_pid_file.exists()) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert spawned and child_pid_file.exists()
        child_pids = json.loads(child_pid_file.read_text())
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            handles = [kernel.OpenProcess(0x100000, False, pid) for pid in child_pids]
            assert all(handles)
        manager.cancel(workspace["id"], job["id"])
        while store.get_analysis(workspace["id"], job["id"])["status"] not in {"cancelled", "failed"} and time.monotonic() < deadline:
            time.sleep(0.02)
        assert store.get_analysis(workspace["id"], job["id"])["status"] == "cancelled"
        assert spawned[0].poll() is not None
        if os.name == "nt":
            try:
                assert all(kernel.WaitForSingleObject(handle, 3000) == 0 for handle in handles)
            finally:
                for handle in handles:
                    kernel.CloseHandle(handle)
        monkeypatch.setattr(manager, "_spawn", original)
        following = manager.submit(workspace["id"])
        deadline = time.monotonic() + 20
        while store.get_analysis(workspace["id"], following["id"])["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(0.02)
        assert store.get_analysis(workspace["id"], following["id"])["status"] == "succeeded"
    finally:
        manager.close()


def test_queued_cancellation_and_worker_failure_are_explicit(tmp_path, projects, monkeypatch):
    store = WorkspaceStore(tmp_path / "state")
    first, second = [store.create_workspace(str(root), access_policy={"confirmed": True, "settings": {}}) for root in projects]
    manager = AnalysisManager(store)
    original = manager._spawn
    spawned = []
    def slow(arguments, **kwargs):
        process = original([sys.executable, "-I", "-c", "import time; time.sleep(30)"], **kwargs)
        spawned.append(process)
        return process
    monkeypatch.setattr(manager, "_spawn", slow)
    try:
        running = manager.submit(first["id"])
        deadline = time.monotonic() + 10
        while not spawned and time.monotonic() < deadline:
            time.sleep(0.01)
        queued = manager.submit(second["id"])
        assert queued["status"] == "queued"
        assert manager.cancel(second["id"], queued["id"])["status"] == "cancelled"
        manager.cancel(first["id"], running["id"])
        while manager.processes and time.monotonic() < deadline:
            time.sleep(0.02)
        assert len(spawned) == 1
        def failing(arguments, **kwargs):
            return original([sys.executable, "-I", "-c", "raise SystemExit(2)"], **kwargs)
        monkeypatch.setattr(manager, "_spawn", failing)
        failed = manager.submit(second["id"])
        while store.get_analysis(second["id"], failed["id"])["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(0.02)
        result = store.get_analysis(second["id"], failed["id"])
        assert result["status"] == "failed"
        assert result["error"] and result["result"] is None
    finally:
        manager.close()


def test_shutdown_reaps_running_worker_and_persists_interrupted(tmp_path, projects, monkeypatch):
    store = WorkspaceStore(tmp_path / "state")
    first, second = [store.create_workspace(str(root), access_policy={"confirmed": True, "settings": {}}) for root in projects]
    manager = AnalysisManager(store)
    original = manager._spawn
    spawned = []
    def slow(arguments, **kwargs):
        process = original([sys.executable, "-I", "-c", "import time; time.sleep(30)"], **kwargs)
        spawned.append(process)
        return process
    monkeypatch.setattr(manager, "_spawn", slow)
    running = manager.submit(first["id"])
    deadline = time.monotonic() + 10
    while not spawned and time.monotonic() < deadline:
        time.sleep(0.01)
    assert spawned
    queued = manager.submit(second["id"])
    manager.close()
    assert spawned[0].poll() is not None
    assert store.get_analysis(first["id"], running["id"])["status"] == "interrupted"
    assert store.get_analysis(second["id"], queued["id"])["status"] == "interrupted"
    replacement = AnalysisManager(store)
    replacement.close()


def test_frontend_is_served_with_local_security_headers(tmp_path):
    frontend = tmp_path / "dist"
    frontend.mkdir()
    (frontend / "index.html").write_text("<h1>Workbench</h1>", encoding="utf-8")
    with TestClient(create_app(tmp_path / "state", frontend), base_url="http://127.0.0.1") as selected:
        response = selected.get("/")
        assert response.status_code == 200 and "Workbench" in response.text
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
