"""Synthetic fixtures only: project chat consent, evidence and revocation."""
import copy
import json
from pathlib import Path
import threading
import time

from fastapi.testclient import TestClient
import pytest

from codesentry.semantic.transport import TransportResponse
from codesentry.web.app import create_app


KEY = "synthetic-conversation-key-1234"


class Transport:
    def __init__(self):
        self.calls = []
        self.started = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.bad_quote = False
        self.status = 200
        self.transform = lambda response, context: response
        self.answer = "## 从入口开始\n\n先阅读 main.py，再核对存储边界。这里没有运行代码。"

    def send(self, body, *, api_key, cancel_event, live_guard, **_kwargs):
        live_guard()
        assert api_key == KEY
        request = json.loads(body)
        self.calls.append(request)
        self.started.set()
        while not self.release.wait(.01):
            live_guard()
        live_guard()
        context = json.loads(request["messages"][-1]["content"])["context"]
        source = context["sources"][0]
        result = {"answer": self.answer, "citations": [{"path": source["path"], "line": source["start_line"],
                  "end_line": source["start_line"], "quote": "invented quote" if self.bad_quote else source["source"].splitlines()[0]}],
                  "followups": ["继续解释下一步"]}
        response = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(result, ensure_ascii=False)}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130}}
        response = self.transform(response, context)
        return TransportResponse(self.status, json.dumps(response, ensure_ascii=False).encode())


@pytest.fixture
def bench(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_text("from store import save\n\ndef run():\n    return save('hello')\n", encoding="utf-8")
    (root / "store.py").write_text("def save(value):\n    return value\n", encoding="utf-8")
    (root / "local.py").write_text("LOCAL_ONLY_NEVER_SEND = True\n", encoding="utf-8")
    (root / "private.py").write_text("EXCLUDED_NEVER_SEND = True\n", encoding="utf-8")
    (root / "unsafe.py").write_text("api_key = 'sk-this-is-a-fake-sensitive-key'\n", encoding="utf-8")
    (root / ".env").write_text("ENV_NEVER_SEND=whatever", encoding="utf-8")
    transport = Transport()
    data = tmp_path / "state"
    app = create_app(data, semantic_transport=transport, configured_api_key=KEY, configured_key_source="env_file")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
        ws = client.post("/api/workspaces", json={"path": str(root), "access_policy": {"confirmed": True,
            "settings": {"model_scope": ["*.py"], "local_only": ["local.py"], "exclude": ["private.py"]}}}).json()
        base = f"/api/workspaces/{ws['id']}"
        yield client, app, base, root, transport, data
        transport.release.set()


def configure(client, base):
    profile = client.get(base + "/semantic-profile").json()
    response = client.put(base + "/semantic-profile", json={"expected_revision": profile["revision"],
        "settings": {"enabled": True, "model": "deepseek-flash"}})
    assert response.status_code == 200, response.text
    return response.json()


def authorize(client, base, *, consent=True, context="本项目优先清晰可改；性能目标未知"):
    settings = client.get(base + "/chat-settings").json()
    response = client.put(base + "/chat-settings", json={"consent": consent, "context": context,
        "expected_revision": settings["revision"], "expected_policy_version": settings["policy_version"],
        "expected_profile_revision": settings["profile_revision"]})
    assert response.status_code == 200, response.text
    return response.json()


def topic(client, base):
    response = client.post(base + "/conversations", json={})
    assert response.status_code == 201, response.text
    return base + "/conversations/" + response.json()["id"]


def send(client, base, url, question="带我理解项目结构和启动方式", **kwargs):
    settings = client.get(base + "/chat-settings").json()
    return client.post(url + "/messages", json={"question": question, "expected_settings_revision": settings["revision"], **kwargs})


def wait(client, url):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        response = client.get(url)
        assert response.status_code == 200, response.text
        value = response.json()
        if not any(turn["status"] == "running" for turn in value["turns"]):
            return value
        time.sleep(.02)
    pytest.fail("conversation did not settle")


def test_insight_scope_lifecycle_cleanup_and_no_model_injection(bench, tmp_path):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    cid = url.rsplit("/", 1)[-1]
    assert send(client, base, url, selected_path="main.py").status_code == 202
    turn = wait(client, url)["turns"][0]
    origin = url + f"/turns/{turn['id']}/insights"
    local = {"statement": "LOCAL_PROJECT_NOTE", "kind": "hypothesis", "scope": "project", "expected_policy_version": 1}
    trusted_before = {path: client.get(path).json() for path in ("/api/gate-policy", base + "/baseline")}
    assert client.post(origin, json=local | {"citations": []}).status_code == 422
    assert client.post(origin, json=local | {"expected_policy_version": 2}).status_code == 409
    assert client.post(origin, json=local | {"statement": KEY}).status_code == 403
    created = client.post(origin, json=local)
    assert created.status_code == 201, created.text
    note = created.json()["insight"]
    assert note["citations"] == [{k: turn["citations"][0][k] for k in ("path", "line", "end_line", "sha256")}]
    assert client.post(origin, json=local).json()["insight"]["id"] == note["id"]
    scoped = client.post(origin, json=local | {"statement": "TOPIC_NOTE", "scope": "topic", "kind": "observation"}).json()["insight"]
    listing = base + "/insights"
    assert {n["id"] for n in client.get(listing, params={"conversation_id": cid}).json()["insights"]} == {note["id"], scoped["id"]}
    other_topic = topic(client, base)
    other_cid = other_topic.rsplit("/", 1)[-1]
    assert [n["id"] for n in client.get(listing, params={"conversation_id": other_cid}).json()["insights"]] == [note["id"]]
    assert client.post(other_topic + f"/turns/{turn['id']}/insights", json=local).status_code == 404
    mutation = {"action": "retire", "cid": other_cid, "expected_policy_version": 1}
    assert client.patch(listing + "/" + scoped["id"], json=mutation).status_code == 404

    other = tmp_path / "other-insight"
    other.mkdir()
    ws = client.post("/api/workspaces", json={"path": str(other), "access_policy": {"confirmed": True, "settings": {}}}).json()
    other_listing = f"/api/workspaces/{ws['id']}/insights"
    assert client.get(other_listing).json()["insights"] == []
    assert client.get(other_listing, params={"conversation_id": cid}).status_code == 404
    assert client.patch(other_listing + "/" + note["id"], json=mutation).status_code == 404

    assert len(transport.calls) == 1
    assert send(client, base, other_topic, "继续看入口", selected_path="main.py").status_code == 202
    wait(client, other_topic)
    assert "LOCAL_PROJECT_NOTE" not in json.dumps(transport.calls)
    assert "TOPIC_NOTE" not in json.dumps(transport.calls)
    assert client.patch(listing + "/" + note["id"], json=mutation | {"action": "delete"}).status_code == 409
    assert client.patch(listing + "/" + note["id"], json=mutation).status_code == 200
    assert client.post(origin, json=local).json()["insight"]["status"] == "retired"
    assert client.delete(url).status_code == 200
    with app.state.manager.store.connection() as db:
        assert db.execute("SELECT 1 FROM conversation_insights WHERE id=?", (scoped["id"],)).fetchone() is None
    assert client.get(listing).json()["insights"][0]["status"] == "retired"
    assert client.patch(listing + "/" + note["id"], json=mutation | {"action": "delete"}).status_code == 200
    assert {path: client.get(path).json() for path in trusted_before} == trusted_before

    new_turn = wait(client, other_topic)["turns"][0]
    assert client.post(other_topic + f"/turns/{new_turn['id']}/insights", json=local).status_code == 201
    policy = client.get(base).json()["access_policy"]
    settings = policy["settings"] | {"model_scope": ["store.py"]}
    assert client.patch(base, json={"access_policy": {"confirmed": True, "settings": settings,
                                                     "expected_version": policy["version"]}}).status_code == 200
    assert client.get(listing).json()["insights"] == []
    with app.state.manager.store.connection() as db:
        assert db.execute("SELECT count(*) FROM conversation_insights").fetchone()[0] == 0


DRIFT_CASES = json.loads((Path(__file__).resolve().parents[1] / "evals/datasets/p5_insight_drift_v1.json").read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", DRIFT_CASES, ids=lambda case: case["id"])
def test_insight_drift_change_set(bench, case):
    client, app, base, root, transport, data = bench
    for path, text in case.get("before", {}).items():
        (root / path).write_text(text, encoding="utf-8")
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    assert send(client, base, url, selected_path="main.py").status_code == 202
    turn = wait(client, url)["turns"][0]
    assert turn["status"] == "completed" and {source["path"] for source in turn["sources"]} == {"main.py", "store.py"}
    origin = url + f"/turns/{turn['id']}/insights"
    draft = {"statement": "观察入口调用存储，运行版本另行核对", "kind": "observation", "scope": "project",
             "track_environment": case.get("track_environment", False), "expected_policy_version": 1}
    saved = client.post(origin, json=draft)
    assert saved.status_code == 201, saved.text
    assert saved.json()["insight"]["status"] == "active"
    originals = {path: (root / path).read_bytes() if (root / path).exists() else None for path in case["after"]}
    for path, text in case["after"].items():
        if text is None:
            (root / path).unlink()
        else:
            (root / path).write_text(text, encoding="utf-8")
    listing = base + "/insights"
    response = client.get(listing)
    assert response.status_code == 200, response.text
    note = response.json()["insights"][0]
    assert note["status"] == case["expected_status"]
    assert note["drift_reason"] == case.get("reason")
    if note["drift_reason"] == "source":
        assert client.post(origin, json=draft).status_code == 409
    if note["status"] == "stale":
        for path, content in originals.items():
            if content is None:
                (root / path).unlink()
            else:
                (root / path).write_bytes(content)
        assert client.get(listing).json()["insights"][0]["status"] == "stale"
    assert len(transport.calls) == 1


P5_CHALLENGES = json.loads((Path(__file__).resolve().parents[1] / "evals/datasets/p5_insight_drift_v2.json").read_text(encoding="utf-8"))["cases"]
FRESH_QUESTION = "核对 main store fresh_a fresh_b，并沿用上一轮的模式信息"


def historical_source_turn(client, base, url, root, transport):
    for name, content in {"history_only.py": "MODE = 'stable'\n", "fresh_a.py": "def first(): return 1\n",
                          "fresh_b.py": "def second(): return 2\n"}.items():
        (root / name).write_text(content, encoding="utf-8")
    transport.answer = "上一轮依据说明默认模式为 stable。"
    assert send(client, base, url, "先读所选文件", selected_path="history_only.py").status_code == 202
    prior = wait(client, url)["turns"][-1]
    assert prior["status"] == "completed" and {source["path"] for source in prior["sources"]} >= {"history_only.py"}
    return prior


@pytest.mark.parametrize("case", P5_CHALLENGES, ids=lambda case: case["id"])
def test_insight_drift_challenge(bench, case):
    client, _, base, root, transport, _ = bench
    for name, content in case.get("before", {}).items():
        (root / name).write_text(content, encoding="utf-8")
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    if case.get("followup"):
        historical_source_turn(client, base, url, root, transport)
        transport.answer = "入口补充说明，沿用上一轮得到的默认模式 stable。"
        question = FRESH_QUESTION
        statement = "默认模式为 stable"
    else:
        question = "核对入口"
        statement = "入口说明适用于当前根目录的环境声明"
    assert send(client, base, url, question, selected_path="main.py").status_code == 202
    turn = wait(client, url)["turns"][-1]
    assert turn["status"] == "completed"
    if case.get("followup"):
        assert len(transport.calls[-1]["messages"]) == 4
        assert "stable" in transport.calls[-1]["messages"][2]["content"]
        assert {source["path"] for source in turn["sources"]} == {"main.py", "store.py", "fresh_a.py", "fresh_b.py"}
    origin = url + f"/turns/{turn['id']}/insights"
    draft = {"statement": statement, "kind": "observation", "scope": "project",
             "track_environment": case.get("track_environment", False), "expected_policy_version": 1}
    saved = client.post(origin, json=draft)
    assert saved.status_code == 201, saved.text
    assert saved.json()["insight"]["status"] == "active"
    for name, content in case["after"].items():
        if content is None:
            (root / name).unlink()
        else:
            (root / name).write_text(content, encoding="utf-8")
    response = client.get(base + "/insights")
    assert response.status_code == 200, response.text
    note = response.json()["insights"][0]
    print(f"P5 {case['id']} gold={case['gold_drift']} observed={note['status']} reason={note['drift_reason']}")
    expected = "stale" if case["gold_drift"] or case.get("conservative_stale") else "active"
    assert note["status"] == expected
    assert note["drift_reason"] == case.get("reason")


def test_followup_history_omits_answers_with_stale_transitive_sources(bench):
    client, _, base, root, transport, _ = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    historical_source_turn(client, base, url, root, transport)
    for number in range(3):
        transport.answer = f"FOLLOWUP_{number} 沿用默认模式 stable。"
        assert send(client, base, url, FRESH_QUESTION, selected_path="main.py").status_code == 202
        turn = wait(client, url)["turns"][-1]
        assert turn["status"] == "completed"
        assert "history_only.py" not in {source["path"] for source in turn["sources"]}

    # The origin is now outside the three-turn prompt window.
    (root / "history_only.py").write_text("MODE = 'compat'\n", encoding="utf-8")
    draft = {"statement": "默认模式为 stable", "kind": "observation", "scope": "project", "expected_policy_version": 1}
    assert client.post(url + f"/turns/{turn['id']}/insights", json=draft).status_code == 409
    assert send(client, base, url, FRESH_QUESTION, selected_path="main.py").status_code == 202
    assert wait(client, url)["turns"][-1]["status"] == "completed"
    assert len(transport.calls[-1]["messages"]) == 2


def test_history_only_source_change_during_model_request_prevents_publish(bench):
    client, _, base, root, transport, _ = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    historical_source_turn(client, base, url, root, transport)
    transport.started.clear()
    transport.release.clear()
    assert send(client, base, url, FRESH_QUESTION, selected_path="main.py").status_code == 202
    assert transport.started.wait(3)
    (root / "history_only.py").write_text("MODE = 'compat'\n", encoding="utf-8")
    transport.release.set()
    turn = wait(client, url)["turns"][-1]
    assert turn["status"] == "failed" and turn["answer"] == ""


def test_legacy_note_provenance_preserves_traceable_first_turn_and_flags_unknown_history(bench):
    client, app, base, root, transport, _ = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    first = historical_source_turn(client, base, url, root, transport)
    transport.answer = "LEGACY_UNBOUND_FOLLOWUP"
    assert send(client, base, url, FRESH_QUESTION, selected_path="main.py").status_code == 202
    second = wait(client, url)["turns"][-1]
    draft = {"statement": "旧笔记", "kind": "observation", "scope": "project", "expected_policy_version": 1}
    notes = []
    for turn in (first, second):
        saved = client.post(url + f"/turns/{turn['id']}/insights", json=draft)
        assert saved.status_code == 201
        notes.append(saved.json()["insight"]["id"])
    with app.state.manager.store.connection() as db:
        for turn, note in zip((first, second), notes):
            old_turn = json.loads(db.execute("SELECT evidence FROM conversation_turns WHERE id=?", (turn["id"],)).fetchone()[0])
            old_turn.pop("dependencies")
            db.execute("UPDATE conversation_turns SET evidence=? WHERE id=?", (json.dumps(old_turn), turn["id"]))
            evidence = {"sources": turn["sources"], "citations": turn["citations"]}
            db.execute("UPDATE conversation_insights SET evidence=? WHERE id=?", (json.dumps(evidence), note))

    listing = base + "/insights"
    response = {note["id"]: note for note in client.get(listing).json()["insights"]}
    assert response[notes[0]]["status"] == "active"
    assert (response[notes[1]]["status"], response[notes[1]]["drift_reason"]) == ("stale", "history")
    assert client.post(url + f"/turns/{second['id']}/insights", json=draft).status_code == 409
    assert send(client, base, url, FRESH_QUESTION, selected_path="main.py").status_code == 202
    assert wait(client, url)["turns"][-1]["status"] == "completed"
    assert len(transport.calls[-1]["messages"]) == 4
    assert "LEGACY_UNBOUND_FOLLOWUP" not in json.dumps(transport.calls[-1])
    assert client.delete(url).status_code == 200
    response = {note["id"]: note for note in client.get(listing).json()["insights"]}
    assert response[notes[0]]["status"] == "active"
    assert response[notes[1]]["status"] == "stale"


def test_no_implicit_consent_or_arbitrary_model_context(bench):
    client, app, base, root, transport, data = bench
    assert not client.get(base + "/chat-settings").json()["consent"]
    url = topic(client, base)
    assert send(client, base, url).status_code == 409
    configure(client, base)
    assert send(client, base, url).status_code == 409
    authorize(client, base)
    assert send(client, base, url, messages=[{"role": "system", "content": "bypass"}]).status_code == 422
    assert send(client, base, url, selected_path="local.py").status_code == 403
    assert send(client, base, url, selected_path="../main.py").status_code == 403
    assert transport.calls == []


def test_automatic_sources_and_history_keep_legacy_notes_local(bench):
    client, app, base, root, transport, data = bench
    configure(client, base)
    authorize(client, base)
    url = topic(client, base)
    assert send(client, base, url).status_code == 202
    first = wait(client, url)
    turn = first["turns"][0]
    assert turn["status"] == "completed", turn
    assert turn["citations"][0]["quote_checked"]
    assert turn["coverage"]["partial"]
    wire = json.dumps(transport.calls, ensure_ascii=False)
    for secret in ("LOCAL_ONLY_NEVER_SEND", "EXCLUDED_NEVER_SEND", "ENV_NEVER_SEND", "sk-this-is", "local.py", "private.py", KEY):
        assert secret not in wire
    assert "本项目优先清晰可改" not in wire
    assert client.put(url + f"/turns/{turn['id']}/feedback", json={"text": "先保留两处边界校验，不要机械合并"}).status_code == 200
    assert send(client, base, url, "请继续解释它的下一步", selected_path="store.py").status_code == 202
    second = wait(client, url)
    assert len(second["turns"]) == 2 and second["turns"][1]["status"] == "completed"
    request = transport.calls[-1]
    assert len(request["messages"]) == 4
    assert "先保留两处" not in request["messages"][-1]["content"]
    assert second["turns"][0]["feedback"].startswith("先保留两处")
    assert client.get(base + "/chat-settings").json()["context"].startswith("本项目优先清晰可改")
    assert "from store import save" not in client.get(base + "/conversations").text
    assert client.get(base + "/semantic-profile").json()["session_budget"]["remaining_requests"] == 3
    assert client.get(base + "/chat-settings").json()["budget"]["remaining_requests"] == 58


def test_changed_code_excludes_stale_history_and_rechecks_before_publish(bench):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    send(client, base, url); wait(client, url)
    (root / "main.py").write_text("CHANGED_MAIN = True\n", encoding="utf-8")
    transport.started.clear(); transport.release.clear()
    assert send(client, base, url, "继续", selected_path="main.py").status_code == 202
    assert transport.started.wait(3)
    assert len(transport.calls[-1]["messages"]) == 2
    (root / "main.py").write_text("CHANGED_AGAIN = True\n", encoding="utf-8")
    transport.release.set()
    turn = wait(client, url)["turns"][-1]
    assert turn["status"] == "failed" and not turn["answer"]


@pytest.mark.parametrize("action", ["cancel", "revoke", "scope", "profile", "delete"])
def test_inflight_response_cannot_outlive_revocation(bench, action):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    transport.release.clear()
    send(client, base, url)
    assert transport.started.wait(3)
    if action == "cancel":
        assert client.post(url + "/cancel").status_code == 200
    elif action == "revoke":
        authorize(client, base, consent=False)
    elif action == "scope":
        ws = client.get(base).json()
        settings = copy.deepcopy(ws["access_policy"]["settings"])
        settings["model_scope"] = ["store.py"]
        assert client.patch(base, json={"access_policy": {"confirmed": True, "settings": settings,
            "expected_version": ws["access_policy"]["version"]}}).status_code == 200
    elif action == "profile":
        configure(client, base)
    else:
        assert client.delete(url).status_code == 200
    transport.release.set()
    if action in {"scope", "delete"}:
        assert client.get(url).status_code == 404
        assert not client.get(base + "/conversations").json()["conversations"]
    else:
        turn = wait(client, url)["turns"][0]
        assert turn["status"] == "cancelled" and not turn["answer"]
    if action in {"scope", "revoke", "profile"}:
        assert not client.get(base + "/chat-settings").json()["consent"]


@pytest.mark.parametrize("problem", ["quote", "key", "status"])
def test_untrusted_output_is_never_published_as_usable_answer(bench, problem):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    if problem == "quote": transport.bad_quote = True
    elif problem == "key": transport.answer = KEY
    else: transport.status = 401
    send(client, base, url)
    turn = wait(client, url)["turns"][0]
    assert turn["status"] == "failed" and not turn["answer"] and not turn["citations"]
    assert KEY not in client.get(url).text
    if problem == "status": assert "HTTP 401" in turn["error"]


def test_cross_workspace_ids_notes_and_history_cannot_mix(bench, tmp_path):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    send(client, base, url); wait(client, url)
    other = tmp_path / "other"; other.mkdir(); (other / "main.py").write_text("OTHER_PROJECT = True\n")
    ws = client.post("/api/workspaces", json={"path": str(other), "access_policy": {"confirmed": True, "settings": {"model_scope": ["main.py"]}}}).json()
    other_base = f"/api/workspaces/{ws['id']}"
    assert client.get(other_base + "/conversations").json()["conversations"] == []
    assert client.get(other_base + "/chat-settings").json()["context"] == ""
    other_url = other_base + "/conversations/" + url.rsplit("/", 1)[-1]
    assert client.get(other_url).status_code == 404
    assert client.delete(other_url).status_code == 404
    assert send(client, base, url, KEY).status_code == 403
    assert client.put(base + "/chat-settings", json={"consent": True, "context": KEY,
        "expected_revision": 1, "expected_policy_version": 1, "expected_profile_revision": 2}).status_code == 403


def test_settings_revision_prevents_stale_grant_and_failed_requests_consume_budget(bench):
    client, app, base, root, transport, data = bench
    configure(client, base)
    settings = authorize(client, base)
    url = topic(client, base)
    authorize(client, base, consent=False)
    assert client.post(url + "/messages", json={"question": "hello", "expected_settings_revision": settings["revision"]}).status_code == 409
    authorize(client, base)
    transport.status = 401
    send(client, base, url); wait(client, url)
    assert client.get(base + "/chat-settings").json()["budget"]["remaining_requests"] == 59
    assert len(transport.calls) == 1


def test_conversations_and_consent_survive_service_restart(bench):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    send(client, base, url); before = wait(client, url)
    turn_id = before["turns"][0]["id"]
    response = client.post(url + f"/turns/{turn_id}/insights", json={"statement": "RESTART_NOTE", "kind": "hypothesis",
        "scope": "project", "expected_policy_version": 1})
    assert response.status_code == 201, response.text
    note_id = response.json()["insight"]["id"]
    app.state.manager.close()
    new_app = create_app(data, semantic_transport=Transport(), configured_api_key=KEY, configured_key_source="env_file")
    with TestClient(new_app, base_url="http://127.0.0.1") as after:
        after.headers["X-CodeSentry-Token"] = after.get("/api/session").json()["token"]
        assert after.get(url).json()["turns"] == before["turns"]
        assert after.get(base + "/chat-settings").json()["consent"]
        assert after.get(base + "/chat-settings").json()["budget"]["remaining_requests"] == 60
        note = after.get(base + "/insights").json()["insights"][0]
        assert (note["id"], note["statement"], note["status"]) == (note_id, "RESTART_NOTE", "active")


def test_crap_tool_reports_local_evidence_without_adding_it_to_cloud_history(bench):
    client, app, base, root, transport, data = bench
    (root / "main.py").write_text("def decide(x, y):\n    if x and y:\n        return 1\n    if x:\n        return 2\n    return 3\n", encoding="utf-8")
    (root / "local.py").write_text("def local_only_report_detail():\n    return 42\n", encoding="utf-8")
    (root / "private.py").write_text("def excluded_report_detail():\n    return 42\n", encoding="utf-8")
    (root / "coverage.json").write_text(json.dumps({"meta": {"format": 3, "branch_coverage": True}, "files": {
        "main.py": {"functions": {"decide": {"start_line": 1, "executed_lines": [2, 3], "missing_lines": [4, 5, 6],
            "missing_branches": [[2, 4], [4, 5], [4, 6], [99, 100]],
            "summary": {"covered_lines": 2, "num_statements": 5, "covered_branches": 1, "num_branches": 4}}}},
    }}), encoding="utf-8")
    url = topic(client, base)
    assert not client.get(base + "/chat-settings").json()["consent"]
    payload = {"coverage_path": "coverage.json", "expected_policy_version": 1, "reference": 10}
    assert client.post(url + "/tools/crap", json=payload | {"expected_policy_version": 2}).status_code == 409
    assert client.post(url + "/tools/crap", json=payload | {"command": "pytest"}).status_code == 422
    assert client.post(url + "/tools/crap", json=payload).status_code == 202
    result = wait(client, url)
    turn = result["turns"][0]
    assert turn["status"] == "completed", turn["error"]
    report = turn["tool"]["report"]
    assert report["branch_totals"] == {"covered": 1, "total": 4, "functions": 1}
    assert report["functions"][0]["crap"] == 10.75
    assert report["functions"][0]["complexity"] == 4
    assert report["functions"][0]["statement_coverage"]["ratio"] == 0.4
    assert report["functions"][0]["missing_branches"] == [[2, 4], [4, 5], [4, 6]]
    assert "行为测试" in report["functions"][0]["suggestion"]
    assert any(row["function"] == "local_only_report_detail" and row["crap"] is None for row in report["functions"])
    assert "excluded_report_detail" not in json.dumps(result)
    assert not transport.calls
    assert client.get(base + "/chat-settings").json()["budget"]["remaining_requests"] == 60
    assert client.put(url + f"/turns/{turn['id']}/feedback", json={"text": "仅本地报告"}).status_code == 404

    configure(client, base); authorize(client, base)
    assert send(client, base, url, "解释项目入口").status_code == 202
    assert wait(client, url)["turns"][-1]["status"] == "completed"
    assert len(transport.calls[0]["messages"]) == 2
    assert "local_only_report_detail" not in json.dumps(transport.calls)
    assert wait(client, url)["turns"][0]["tool"]["report"] == report


def test_cancelled_crap_tool_cannot_publish_a_late_report(bench, monkeypatch):
    from codesentry.review import crap

    client, app, base, root, transport, data = bench
    started, release = threading.Event(), threading.Event()
    original = crap.scan_crap

    def slow_scan(*args, **kwargs):
        result = original(*args, **kwargs)
        started.set()
        release.wait(4)
        return result

    monkeypatch.setattr(crap, "scan_crap", slow_scan)
    url = topic(client, base)
    assert client.post(url + "/tools/crap", json={"expected_policy_version": 1}).status_code == 202
    try:
        assert started.wait(4)
        assert client.post(url + "/cancel").status_code == 200
    finally:
        release.set()
    turn = wait(client, url)["turns"][0]
    assert turn["status"] == "cancelled" and "report" not in turn["tool"]
    assert not transport.calls


def crap_target_for(client, url, function):
    assert client.post(url + "/tools/crap", json={"expected_policy_version": 1}).status_code == 202
    turn = wait(client, url)["turns"][-1]
    row = next(row for row in turn["tool"]["report"]["functions"] if row["function"] == function)
    return {"turn_id": turn["id"], "file": row["file"], "line": row["line"]}, row


def test_crap_discussion_sends_only_the_bound_function_and_rejects_forged_or_stale_rows(bench):
    client, app, base, root, transport, data = bench
    decoy = 'def decoy():\r\n    return "SAME_FILE_DECOY\x0bstill_one_line"\r\n\r\n'
    chosen = "def chosen(value):\r\n    if value < 0:\r\n        return 0\r\n    return value\r\n"
    (root / "main.py").write_bytes((decoy + "# padding\r\n" * 125 + chosen + "\r\n" + decoy).encode())
    (root / "local.py").write_text("def only_local():\n    return 12\n", encoding="utf-8")
    configure(client, base)
    url = topic(client, base)
    target, row = crap_target_for(client, url, "chosen")
    assert send(client, base, url, crap_target=target).status_code == 409
    authorize(client, base)
    assert send(client, base, topic(client, base), crap_target=target).status_code == 409
    assert send(client, base, url, crap_target=target | {"line": target["line"] + 1}).status_code == 409
    assert send(client, base, url, crap_target=target | {"sha256": "forged"}).status_code == 422
    local, _ = crap_target_for(client, url, "only_local")
    assert send(client, base, url, crap_target=local).status_code == 409
    assert not transport.calls

    assert send(client, base, url, "如何改进这个函数", crap_target=target).status_code == 202
    turn = wait(client, url)["turns"][-1]
    assert turn["status"] == "completed", turn["error"]
    assert turn["crap_target"] == target
    request = transport.calls[0]
    assert len(request["messages"]) == 2
    payload = json.loads(request["messages"][-1]["content"])
    context = payload["context"]
    assert context["files"] == ["main.py"]
    assert len(context["sources"]) == 1
    assert context["sources"][0]["source"] == chosen
    assert context["sources"][0]["start_line"] == row["line"]
    assert context["sources"][0]["end_line"] == row["end_line"]
    assert context["focus"]["complete"]
    assert "SAME_FILE_DECOY" not in json.dumps(request)
    assert "crap_target" not in payload and "report" not in payload

    (root / "main.py").write_bytes((root / "main.py").read_bytes() + b"# changed outside the old span\r\n")
    assert send(client, base, url, crap_target=target).status_code == 202
    stale = wait(client, url)["turns"][-1]
    assert stale["status"] == "failed" and "重新生成 CRAP" in stale["error"]
    assert not stale["answer"] and len(transport.calls) == 1


def test_crap_discussion_checks_the_source_again_after_the_model_returns(bench):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    target, _ = crap_target_for(client, url, "run")
    transport.release.clear()
    try:
        assert send(client, base, url, crap_target=target).status_code == 202
        assert transport.started.wait(3)
        (root / "main.py").write_text("def run():\n    return 'changed'\n", encoding="utf-8")
    finally:
        transport.release.set()
    turn = wait(client, url)["turns"][-1]
    assert turn["status"] == "failed" and "重新生成 CRAP" in turn["error"]
    assert not turn["answer"] and not turn["citations"]


def test_model_selects_current_excerpt_and_server_builds_the_citation(bench):
    client, app, base, root, transport, data = bench
    # The chosen evidence starts well past line 1 and preserves significant spaces.
    (root / "main.py").write_bytes(("# padding\r\n" * 65 + "def launch():\r\n    return 'a  b'\r\n").encode())
    configure(client, base); authorize(client, base)
    url = topic(client, base)

    def choose_excerpt(response, context):
        source = next(item for item in context["sources"] if item["path"] == "main.py")
        result = {"answer": "先看启动函数，运行行为仍需验证。", "citations": [{"source_id": source.get("source_id", "S1")}], "followups": []}
        response["choices"][0]["message"]["content"] = json.dumps(result, ensure_ascii=False)
        return response

    transport.transform = choose_excerpt
    send(client, base, url, "解释 launch 启动", selected_path="main.py")
    turn = wait(client, url)["turns"][0]
    assert turn["status"] == "completed", turn["error"]
    source = next(item for item in json.loads(transport.calls[0]["messages"][-1]["content"])["context"]["sources"] if item["path"] == "main.py")
    citation = turn["citations"][0]
    assert source["start_line"] > 1
    assert (citation["path"], citation["line"], citation["end_line"]) == (source["path"], source["start_line"], source["end_line"])
    assert citation["quote"] == source["source"] and "'a  b'" in citation["quote"]
    assert citation["quote_checked"] and citation["sha256"] == source["sha256"]
    assert len(transport.calls) == 1


@pytest.mark.parametrize("problem,expected", [
    ("blank", "空白回答"),
    ("length", "输出上限"),
    ("json", "JSON"),
    ("unknown_source", "本轮未提供"),
    ("legacy_quote", "未匹配原文"),
    ("tool", "工具调用"),
    ("followups", "追问格式"),
])
def test_output_failures_are_distinct_safe_and_never_automatically_retried(bench, problem, expected):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)
    sentinel = "UNTRUSTED_RESPONSE_MUST_NOT_BE_STORED"

    def broken_response(response, context):
        choice = response["choices"][0]
        message = choice["message"]
        result = json.loads(message["content"])
        if problem == "blank": message["content"] = "   \r\n  "
        elif problem == "length": choice["finish_reason"] = "length"; message["content"] = '{"answer":"' + sentinel
        elif problem == "json": message["content"] = '{"answer":"' + sentinel
        elif problem == "tool": message["function_call"] = {"name": sentinel, "arguments": "{}"}
        else:
            result["answer"] = sentinel
            if problem == "unknown_source": result["citations"] = [{"source_id": "not-current-source"}]
            elif problem == "legacy_quote": result["citations"][0]["quote"] = sentinel
            else: result["followups"] = sentinel
            message["content"] = json.dumps(result)
        return response

    transport.transform = broken_response
    send(client, base, url)
    turn = wait(client, url)["turns"][0]
    assert turn["status"] == "failed" and expected in turn["error"]
    assert not turn["answer"] and not turn["citations"]
    assert sentinel not in client.get(url).text
    with app.state.manager.store.connection() as db:
        assert sentinel not in json.dumps(tuple(db.execute("SELECT * FROM conversation_turns WHERE id=?", (turn["id"],)).fetchone()))
    assert len(transport.calls) == 1
    assert client.get(base + "/chat-settings").json()["budget"]["remaining_requests"] == 59


def test_nullable_function_metadata_and_structured_history_do_not_break_json_chat(bench):
    client, app, base, root, transport, data = bench
    configure(client, base); authorize(client, base)
    url = topic(client, base)

    def nullable_metadata(response, context):
        response["choices"][0]["message"].update({"function_call": None, "tool_calls": None})
        return response

    transport.transform = nullable_metadata
    send(client, base, url)
    assert wait(client, url)["turns"][0]["status"] == "completed"
    send(client, base, url, "继续下一步")
    assert wait(client, url)["turns"][-1]["status"] == "completed"
    previous = next(item for item in transport.calls[-1]["messages"] if item["role"] == "assistant")
    history = json.loads(previous["content"])
    assert history == {"answer": transport.answer, "citations": [], "followups": []}
