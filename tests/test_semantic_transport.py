"""Actual local HTTP wire tests; no provider credentials or external requests."""
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
import threading
import time

import pytest

from codesentry.semantic import transport
from codesentry.semantic.transport import DeepSeekTransport, SemanticTransportError


KEY = "synthetic-test-key-only"
REQUEST = b'{"model":"deepseek-flash","messages":[{"role":"user","content":"synthetic"}]}'


@contextmanager
def server(action):
    observed = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            observed.append((self.path, dict(self.headers), raw))
            try:
                action(self)
            except (OSError, ConnectionError):
                pass

        def log_message(self, *_args):
            pass

        def handle(self):
            try:
                super().handle()
            except ConnectionError:
                # Closing an unsuccessful response deliberately leaves its
                # body unread; a reset while awaiting keep-alive is expected.
                pass

    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    instance.daemon_threads = True
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield DeepSeekTransport._loopback_for_test(host="127.0.0.1", port=instance.server_port), observed
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=1)


def reply(handler, body=b'{"choices":[]}', *, status=200, headers=()):
    handler.send_response(status)
    for name, value in headers:
        handler.send_header(name, value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
    handler.wfile.flush()


def send(selected, *, guard=lambda: None, cancel=None, timeout=1, body=REQUEST, key=KEY):
    return selected.send(body, api_key=key, timeout_seconds=timeout,
                         cancel_event=threading.Event() if cancel is None else cancel, live_guard=guard)


def test_real_wire_exact_request_headers_and_no_proxy_or_debug_output(monkeypatch, capsys):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setattr(http.client.HTTPConnection, "debuglevel", 1)
    with server(lambda handler: reply(handler, b'{"synthetic":true}')) as (selected, observed):
        result = send(selected)
    assert result.status == 200 and result.body == b'{"synthetic":true}'
    assert len(observed) == 1
    path, headers, raw = observed[0]
    assert path == "/chat/completions" and raw == REQUEST
    assert headers["Authorization"] == "Bearer " + KEY
    assert headers["Content-Type"] == "application/json" and headers["Accept-Encoding"] == "identity"
    assert int(headers["Content-Length"]) == len(REQUEST)
    assert "synthetic" not in repr(result)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 401, 429, 500, 503])
def test_http_errors_and_redirects_are_single_attempt_without_original_body(status, capsys):
    secret = ("private-error-" + KEY).encode()
    with server(lambda handler: reply(handler, secret, status=status,
                headers=(("Location", "http://127.0.0.1:1/not-followed"),))) as (selected, observed):
        with pytest.raises(SemanticTransportError) as raised:
            send(selected)
        assert len(observed) == 1
    assert raised.value.code == f"http_{status}"
    assert KEY not in str(raised.value) + repr(raised.value)
    assert "private-error" not in str(raised.value) + repr(raised.value)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("declared", [True, False])
def test_response_body_is_bounded_even_without_content_length(declared):
    def action(handler):
        handler.send_response(200)
        if declared:
            handler.send_header("Content-Length", str(transport.MAX_RESPONSE_BYTES + 1))
        else:
            handler.send_header("Connection", "close")
            handler.close_connection = True
        handler.end_headers()
        handler.wfile.write(b"x" * (transport.MAX_RESPONSE_BYTES + 1))
        handler.wfile.flush()
    with server(action) as (selected, _):
        with pytest.raises(SemanticTransportError, match="response_too_large"):
            send(selected)


def test_response_headers_are_bounded():
    def action(handler):
        handler.wfile.write(b"HTTP/1.1 200 OK\r\nX-Private: " + b"x" * transport.MAX_HEADER_BYTES + b"\r\n\r\n")
        handler.wfile.flush()
    with server(action) as (selected, _):
        with pytest.raises(SemanticTransportError, match="response_headers_too_large"):
            send(selected)


def test_chunked_json_response_works_without_decompression():
    def action(handler):
        handler.send_response(200)
        handler.send_header("Transfer-Encoding", "chunked")
        handler.end_headers()
        handler.wfile.write(b'4\r\n{"a"\r\n3\r\n:1}\r\n0\r\n\r\n')
        handler.wfile.flush()
    with server(action) as (selected, _):
        assert send(selected).body == b'{"a":1}'


def test_body_read_timeout_is_an_overall_deadline():
    entered, release = threading.Event(), threading.Event()
    def action(handler):
        handler.send_response(200)
        handler.send_header("Content-Length", "100")
        handler.end_headers()
        handler.wfile.flush()
        entered.set()
        release.wait(2)
    try:
        with server(action) as (selected, observed):
            started = time.monotonic()
            with pytest.raises(SemanticTransportError, match="timeout"):
                send(selected, timeout=.15)
            elapsed = time.monotonic() - started
            assert entered.is_set() and len(observed) == 1 and elapsed < .8
    finally:
        release.set()


@pytest.mark.parametrize("connection_close", [False, True])
def test_cancel_shutdown_interrupts_a_blocked_file_buffered_response_read(connection_close):
    entered, release, cancel = threading.Event(), threading.Event(), threading.Event()
    def action(handler):
        handler.send_response(200)
        handler.send_header("Content-Length", "100")
        if connection_close:
            handler.send_header("Connection", "close")
            handler.close_connection = True
        handler.end_headers()
        handler.wfile.flush()
        entered.set()
        release.wait(2)
    timer = threading.Thread(target=lambda: (entered.wait(1), cancel.set()), daemon=True)
    timer.start()
    try:
        with server(action) as (selected, observed):
            started = time.monotonic()
            with pytest.raises(SemanticTransportError, match="cancelled"):
                send(selected, timeout=2, cancel=cancel)
            assert time.monotonic() - started < .8 and len(observed) == 1
    finally:
        release.set()
        timer.join(timeout=1)


def test_guard_denial_before_connection_sends_nothing_and_is_sanitized(capsys):
    def denied():
        raise PermissionError("must-never-print-" + KEY)
    with server(lambda handler: reply(handler)) as (selected, observed):
        with pytest.raises(SemanticTransportError, match="authorization_changed") as raised:
            send(selected, guard=denied)
        assert observed == []
    assert KEY not in repr(raised.value)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_service_cancellation_code_is_preserved_without_turning_into_an_authorization_error():
    def cancelled():
        raise SemanticTransportError("cancelled")
    with server(lambda handler: reply(handler)) as (selected, observed):
        with pytest.raises(SemanticTransportError, match="cancelled"):
            send(selected, guard=cancelled)
        assert observed == []


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_cancel_between_guard_and_write_cannot_implicitly_reconnect(monkeypatch, phase):
    cancel = threading.Event()
    connects, writes = [], []
    original_connect, original_send = http.client.HTTPConnection.connect, http.client.HTTPConnection.send
    def connect(connection):
        connects.append(1)
        return original_connect(connection)
    def write(connection, data):
        is_body = data == REQUEST
        if (phase == "body") == is_body:
            cancel.set()
            connection.close()
        else:
            writes.append(data)
        return original_send(connection, data)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", connect)
    monkeypatch.setattr(http.client.HTTPConnection, "send", write)
    with server(lambda handler: reply(handler)) as (selected, _):
        with pytest.raises(SemanticTransportError, match="cancelled"):
            send(selected, cancel=cancel)
        assert len(connects) == 1
        assert REQUEST not in writes


@pytest.mark.parametrize("reason", ["cancel", "revoke"])
def test_connected_socket_is_rechecked_before_authorization_and_body(monkeypatch, reason):
    cancel, denied = threading.Event(), threading.Event()
    original = http.client.HTTPConnection.connect
    def connected(connection):
        original(connection)
        (cancel if reason == "cancel" else denied).set()
    monkeypatch.setattr(http.client.HTTPConnection, "connect", connected)
    def guard():
        if denied.is_set():
            raise PermissionError("changed")
    with server(lambda handler: reply(handler)) as (selected, observed):
        with pytest.raises(SemanticTransportError, match="cancelled" if reason == "cancel" else "authorization_changed"):
            send(selected, cancel=cancel, guard=guard)
        assert observed == []


def test_dns_stall_returns_at_deadline_and_cannot_send_after_late_connect(monkeypatch):
    entered, release, connected = threading.Event(), threading.Event(), threading.Event()
    original = socket.getaddrinfo
    def delayed(*args, **kwargs):
        entered.set()
        release.wait(2)
        result = original(*args, **kwargs)
        connected.set()
        return result
    with server(lambda handler: reply(handler)) as (selected, observed):
        monkeypatch.setattr(socket, "getaddrinfo", delayed)
        started = time.monotonic()
        with pytest.raises(SemanticTransportError, match="timeout"):
            send(selected, timeout=.1)
        assert entered.is_set() and time.monotonic() - started < .7
        with pytest.raises(SemanticTransportError, match="transport_busy"):
            send(selected)
        release.set()
        assert connected.wait(1)
        deadline = time.monotonic() + 1
        while selected._flight.locked() and time.monotonic() < deadline:
            time.sleep(.005)
        assert not selected._flight.locked() and observed == []


def test_concurrency_is_one_wire_request():
    entered, release = threading.Event(), threading.Event()
    def action(handler):
        entered.set()
        release.wait(1)
        reply(handler)
    with server(action) as (selected, observed):
        result = []
        first = threading.Thread(target=lambda: result.append(send(selected)), daemon=True)
        first.start()
        assert entered.wait(1)
        with pytest.raises(SemanticTransportError, match="transport_busy"):
            send(selected)
        release.set()
        first.join(timeout=1)
        assert len(result) == len(observed) == 1


def test_production_connection_has_fixed_origin_tls_validation_and_no_ssl_keylog(monkeypatch, tmp_path):
    destination = tmp_path / "must-not-create-keylog"
    monkeypatch.setenv("SSLKEYLOGFILE", str(destination))
    selected = DeepSeekTransport()
    connection = selected._connection(1)
    assert type(connection) is http.client.HTTPSConnection
    assert (connection.host, connection.port) == ("api.deepseek.com", 443)
    assert connection._context.verify_mode == ssl.CERT_REQUIRED and connection._context.check_hostname
    assert connection._context.keylog_filename is None
    assert not destination.exists()
    connection.close()


def test_actual_service_and_registry_guards_complete_one_loopback_request(tmp_path):
    from fastapi.testclient import TestClient
    from codesentry.web.app import create_app
    root = tmp_path / "synthetic-source"
    root.mkdir()
    (root / "main.py").write_bytes(b"value = 1\n")
    content = {"warnings": [{"line": 1, "end_line": 1, "reason": "Possible concern",
                             "evidence_quote": "value = 1", "suggestion": "Review intent"}]}
    completion = json.dumps({"choices": [{"finish_reason": "stop", "message": {
        "role": "assistant", "content": json.dumps(content)}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}}).encode()
    with server(lambda handler: reply(handler, completion)) as (selected, observed):
        with TestClient(create_app(tmp_path / "state", semantic_transport=selected),
                        base_url="http://127.0.0.1") as client:
            client.headers["X-CodeSentry-Token"] = client.get("/api/session").json()["token"]
            workspace = client.post("/api/workspaces", json={"path": str(root), "access_policy": {
                "confirmed": True, "settings": {"model_scope": ["main.py"]}}}).json()
            base = f"/api/workspaces/{workspace['id']}"
            profile = client.get(base + "/semantic-profile").json()
            updated = client.put(base + "/semantic-profile", json={"expected_revision": profile["revision"],
                "settings": {"enabled": True, "model": "deepseek-flash"}, "api_key": KEY})
            assert updated.status_code == 200
            revision = updated.json()["revision"]
            preview = client.post(base + "/semantic-previews", json={"path": "main.py", "start_line": 1,
                "end_line": 1, "expected_profile_revision": revision})
            assert preview.status_code == 200
            prepared = preview.json()
            started = client.post(base + f"/semantic-previews/{prepared['preview_id']}/send", json={
                "confirmed": True, "expected_request_sha256": prepared["expected_request_sha256"],
                "expected_profile_revision": revision})
            assert started.status_code == 202
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                job = client.get(base + f"/analyses/{started.json()['id']}").json()
                if job["status"] not in {"queued", "running"}:
                    break
                time.sleep(.01)
            assert job["status"] == "succeeded", job
            assert job["result"]["review_status"] == "warnings"
            assert job["result"]["warnings"][0]["evidence_checked"] is True
            assert job["result"]["warnings"][0]["can_block"] is False
            assert KEY not in json.dumps(job)
        assert len(observed) == 1 and observed[0][2] == prepared["request_json"].encode("utf-8")


@pytest.mark.parametrize("host", ["api.deepseek.com", "localhost", "192.0.2.1", "0.0.0.0", "::"])
def test_test_factory_never_accepts_external_or_named_hosts(host):
    with pytest.raises(ValueError):
        DeepSeekTransport._loopback_for_test(host=host, port=12345)


@pytest.mark.parametrize("timeout", [0, -1, 31, True, float("nan"), float("inf")])
def test_invalid_timeout_is_rejected_before_connect(monkeypatch, timeout):
    selected = DeepSeekTransport()
    monkeypatch.setattr(selected, "_connection", lambda *_: pytest.fail("invalid request connected"))
    with pytest.raises(SemanticTransportError, match="invalid_request"):
        send(selected, timeout=timeout)


@pytest.mark.parametrize("key", ["", "secret\r\nX-Injected: value", "unicode-密钥", " " + KEY])
def test_invalid_key_never_becomes_a_header_or_exception_text(monkeypatch, key):
    selected = DeepSeekTransport()
    monkeypatch.setattr(selected, "_connection", lambda *_: pytest.fail("invalid key connected"))
    with pytest.raises(SemanticTransportError, match="invalid_api_key") as raised:
        send(selected, key=key)
    assert key not in str(raised.value) if key else str(raised.value) == "invalid_api_key"
