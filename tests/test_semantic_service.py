"""Synthetic excerpts/fake transport only; no provider calls or private code."""
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import pickle
import threading

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.semantic import SemanticBudgetExceeded, SemanticConflict, SemanticService
from codesentry.semantic.service import MAX_PREVIEWS
from codesentry.semantic.transport import SemanticTransportError, TransportResponse


FAKE_KEY = "synthetic-deepseek-private-key-for-tests"


def response(warnings=None, *, content=None, finish="stop", usage=True, tool_calls=None):
    if warnings is None:
        warnings = [{"line": 2, "end_line": 2, "reason": "check this condition", "evidence_quote": "assert flag",
                     "suggestion": "consider documenting the assumption"}]
    message = {"role": "assistant", "content": json.dumps({"warnings": warnings}) if content is None else content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    envelope = {"choices": [{"finish_reason": finish, "message": message}]}
    if usage:
        envelope["usage"] = {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70}
    return TransportResponse(200, json.dumps(envelope).encode())


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.result = response()
        self.callback = None
        self.error = None

    def send(self, body, *, api_key, timeout_seconds, cancel_event, live_guard):
        live_guard()
        self.calls.append((body, api_key))
        if self.callback:
            self.callback()
        live_guard()
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "synthetic-source"
    root.mkdir()
    (root / "main.py").write_bytes(b"def check(flag):\n    assert flag\n    return flag\n")
    access = AccessPolicy(root, {"model_scope": ["main.py"]})
    transport = FakeTransport()
    service = SemanticService(tmp_path / "external-state", transport=transport)
    service.update_profile("workspace", {"enabled": True}, expected_revision=1, api_key=FAKE_KEY)
    yield root, access, service, transport
    service.close()


def preview(service, access, **kwargs):
    return service.preview("workspace", access, path="main.py", start_line=2, end_line=2, access_version=1,
                           expected_profile_revision=2, **kwargs)


def reserve(service, access, value=None, **kwargs):
    value = preview(service, access) if value is None else value
    return service.reserve("workspace", access, preview_id=value["preview_id"], confirmed=True,
        expected_request_sha256=value["expected_request_sha256"], access_version=1, expected_profile_revision=2, **kwargs)


def execute(service, access, request):
    return service.execute(request, access, cancel_event=threading.Event(), live_guard=lambda: None)


def test_workspace_profiles_are_disabled_by_default_and_keys_never_persist(setup):
    _root, _access, service, _transport = setup
    current = service.read_profile("workspace")
    assert current["enabled"] and current["key_configured"] and current["model"] == "deepseek-flash"
    assert current["limits"] == {"max_requests": 3, "max_input_bytes": 8192, "max_excerpt_lines": 120,
        "max_output_tokens": 1024, "total_token_budget": 32768, "timeout_seconds": 30, "preview_ttl_seconds": 300}
    other = service.read_profile("other-workspace")
    assert not other["enabled"] and not other["key_configured"]
    assert FAKE_KEY not in json.dumps(current) and FAKE_KEY.encode() not in service.database.read_bytes()
    restarted = SemanticService(service.database.parent, transport=FakeTransport())
    try:
        assert not restarted.read_profile("workspace")["key_configured"]
    finally:
        restarted.close()


@pytest.mark.parametrize("changes", [
    {"endpoint": "http://localhost"}, {"provider": "other"}, {"purpose": "anything"},
    {"model": "deepseek-chat"}, {"enabled": 1}, {"approved": True},
    {"limits": {"max_requests": True}}, {"limits": {"max_requests": 21}},
    {"limits": {"timeout_seconds": 31}}, {"limits": {"timeout_seconds": 0}},
    {"limits": {"total_token_budget": 262145}}, {"limits": {"max_input_bytes": 16384}},
    {"limits": {"max_output_tokens": 2048}}, {"limits": {"preview_ttl_seconds": 600}},
])
def test_profile_rejects_unbounded_or_external_configuration(setup, changes):
    _, _, service, _ = setup
    with pytest.raises(ValueError):
        service.update_profile("workspace", changes, expected_revision=2)
    assert service.read_profile("workspace")["revision"] == 2


@pytest.mark.parametrize("key", ["", "short", "secret\r\nInjected: true", "contains spaces secret", 123])
def test_key_validation_never_echoes_input(setup, key):
    _, _, service, _ = setup
    with pytest.raises(ValueError) as error:
        service.update_profile("workspace", {}, expected_revision=2, api_key=key)
    assert str(error.value) == "invalid_api_key"


def test_profile_cas_change_and_clear_key_invalidate_previews_without_budget_reset(setup):
    _, access, service, transport = setup
    first = preview(service, access)
    pending = reserve(service, access)
    current = service.update_profile("workspace", {"model": "deepseek-v4-pro"}, expected_revision=2)
    assert current["revision"] == 3 and current["key_configured"]
    assert current["session_budget"]["requests_reserved"] == 1
    with pytest.raises(SemanticConflict):
        service.reserve("workspace", access, preview_id=first["preview_id"], expected_request_sha256=first["expected_request_sha256"],
                        confirmed=True, access_version=1)
    with pytest.raises(SemanticConflict):
        execute(service, access, pending)
    with pytest.raises(SemanticConflict):
        service.update_profile("workspace", {"enabled": False}, expected_revision=2)
    current = service.update_profile("workspace", {}, expected_revision=3, clear_key=True)
    assert not current["key_configured"] and current["session_budget"]["requests_reserved"] == 1
    assert transport.calls == []


def test_preview_is_exact_bounded_body_without_key_or_unsent_source(setup):
    root, access, service, transport = setup
    value = preview(service, access)
    body = value["request_json"].encode()
    assert hashlib.sha256(body).hexdigest() == value["expected_request_sha256"]
    assert json.loads(body) == value["request"]
    request = value["request"]
    assert request["model"] == "deepseek-flash" and request["thinking"] == {"type": "disabled"}
    assert request["stream"] is False and request["max_tokens"] == 1024
    assert request["response_format"] == {"type": "json_object"} and "tools" not in request
    user = json.loads(request["messages"][1]["content"])
    assert user == {"path": "main.py", "start_line": 2, "end_line": 2, "source": "    assert flag\n"}
    assert "def check" not in body.decode() and "return flag" not in body.decode() and FAKE_KEY not in body.decode()
    assert value["source_sha256"] == hashlib.sha256((root / "main.py").read_bytes()).hexdigest()
    assert value["provider_may_retain_or_cache"] and not value["cost_estimate_is_guarantee"]
    assert service.read_profile("workspace")["session_budget"]["requests_reserved"] == 0 and not transport.calls


@pytest.mark.parametrize("settings", [{}, {"exclude": ["main.py"]}, {"model_scope": ["main.py"], "local_only": ["main.py"]}])
def test_local_only_or_excluded_files_cannot_be_previewed(setup, settings):
    root, _, service, _ = setup
    with pytest.raises(AccessDenied):
        preview(service, AccessPolicy(root, settings))


@pytest.mark.parametrize("start,end", [(0, 1), (1, 121), (2, 1), (True, 2), (2, 1000)])
def test_excerpt_range_is_strict_and_bounded(setup, start, end):
    _, access, service, _ = setup
    with pytest.raises(ValueError):
        service.preview("workspace", access, path="main.py", start_line=start, end_line=end, access_version=1)


@pytest.mark.parametrize("source", ["password = 'synthetic-should-not-send'\n", "label='" + "界" * 3000 + "'\n"])
def test_secret_detection_and_utf8_byte_limit_block_preview(setup, source):
    root, access, service, _ = setup
    (root / "main.py").write_text(source, encoding="utf-8")
    with pytest.raises((AccessDenied, ValueError)):
        service.preview("workspace", access, path="main.py", start_line=1, end_line=1, access_version=1)


def test_source_file_is_only_read_fresh_and_target_code_is_never_executed(setup):
    root, access, service, _ = setup
    marker = root / "MUST_NOT_EXECUTE"
    (root / "main.py").write_text("from pathlib import Path\nPath('MUST_NOT_EXECUTE').touch()\nraise RuntimeError('no')\n")
    value = preview(service, access)
    assert "MUST_NOT_EXECUTE" in value["request_json"] and not marker.exists()


def test_expiry_and_memory_bound_cannot_be_replayed(setup):
    _, access, service, _ = setup
    now = [10.0]
    service._clock = lambda: now[0]
    expired = preview(service, access)
    now[0] += 301
    with pytest.raises(SemanticConflict):
        reserve(service, access, expired)
    oldest = preview(service, access)
    for _ in range(MAX_PREVIEWS):
        preview(service, access)
    assert len(service._previews) == MAX_PREVIEWS
    with pytest.raises(SemanticConflict):
        reserve(service, access, oldest)


@pytest.mark.parametrize("mutation", ["hash", "profile", "version", "source", "permission"])
def test_confirmation_refuses_any_drift_and_single_use_nonce(setup, mutation):
    root, access, service, transport = setup
    value = preview(service, access)
    kwargs = {"preview_id": value["preview_id"], "expected_request_sha256": value["expected_request_sha256"],
              "confirmed": True, "access_version": 1, "expected_profile_revision": 2}
    if mutation == "hash":
        kwargs["expected_request_sha256"] = "0" * 64
    elif mutation == "profile":
        service.update_profile("workspace", {"enabled": False}, expected_revision=2)
    elif mutation == "version":
        kwargs["access_version"] = 2
    elif mutation == "source":
        (root / "main.py").write_bytes(b'\xef\xbb\xbf' + (root / "main.py").read_bytes())
    else:
        access.confirmed = False
    with pytest.raises((SemanticConflict, AccessDenied)):
        service.reserve("workspace", access, **kwargs)
    assert transport.calls == []
    with pytest.raises((SemanticConflict, AccessDenied)):
        service.reserve("workspace", access, **kwargs)


def test_concurrent_confirmation_spends_one_request_once(setup):
    _, access, service, _ = setup
    value = preview(service, access)
    def claim():
        try:
            return reserve(service, access, value)
        except SemanticConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))
    assert sum(item is not None for item in results) == 1
    assert service.read_profile("workspace")["session_budget"]["requests_reserved"] == 1


def test_opaque_reservation_has_metadata_only_and_copies_or_json_do_not_send(setup):
    _, access, service, transport = setup
    pending = reserve(service, access)
    config = pending.to_config()
    assert set(config) == {"kind", "provider", "model", "profile_revision", "request_sha256", "source_digest", "request_id"}
    assert "main.py" not in json.dumps(config) and "assert flag" not in repr(pending) and FAKE_KEY not in repr(pending)
    with pytest.raises(TypeError):
        pickle.dumps(pending)
    with pytest.raises(TypeError):
        copy.copy(pending)
    for forged in (replace(pending), config):
        with pytest.raises(SemanticConflict):
            execute(service, access, forged)
    assert transport.calls == []


def test_success_has_only_unverified_llm_warnings_and_matching_evidence(setup):
    _, access, service, transport = setup
    value = preview(service, access)
    pending = reserve(service, access, value)
    result = execute(service, access, pending)
    assert result["review_status"] == "warnings" and result["gate_status"] == "not_evaluated"
    warning, = result["warnings"]
    assert warning["source"] == "llm" and not warning["verified"] and not warning["can_block"]
    assert warning["evidence_checked"] and not warning["confirmed_behavior_bug"]
    assert result["summary"] == {"warnings": 1, "confirmed_behavior_bug_findings": 0, "blocking_findings": 0}
    assert result["usage"] == {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70}
    assert transport.calls == [(value["request_json"].encode(), FAKE_KEY)]
    service.validate_current(pending, access, access_version=1, allow_completed=True)
    with pytest.raises(SemanticConflict):
        execute(service, access, pending)


@pytest.mark.parametrize("failure", ["length", "tool_calls", "empty", "bad_json", "duplicate_json", "self_verified", "out_of_range", "bool_line", "missing", "not_list"])
def test_incomplete_and_forged_model_output_cannot_claim_verified_findings(setup, failure):
    _, access, service, transport = setup
    if failure in {"length", "tool_calls"}:
        transport.result = response(finish=failure, tool_calls=[{"name": "execute"}] if failure == "tool_calls" else None)
    elif failure == "empty":
        transport.result = response(content="")
    elif failure == "bad_json":
        transport.result = response(content="not json")
    elif failure == "duplicate_json":
        transport.result = response(content='{"warnings":[],"warnings":[]}')
    elif failure == "not_list":
        transport.result = response(content='{"warnings":{}}')
    else:
        warning = {"line": 2, "end_line": 2, "reason": "warning", "evidence_quote": "assert flag", "suggestion": "check"}
        if failure == "self_verified":
            warning.update(source="deterministic", verified=True, can_block=True)
        elif failure == "out_of_range":
            warning["line"] = warning["end_line"] = 3
        elif failure == "bool_line":
            warning["line"] = True
        else:
            warning.pop("evidence_quote")
        transport.result = response(warnings=[warning])
    result = execute(service, access, reserve(service, access))
    assert result["review_status"] == "incomplete" and result["warnings"] == []
    assert result["summary"]["confirmed_behavior_bug_findings"] == result["summary"]["blocking_findings"] == 0
    assert service.read_profile("workspace")["session_budget"]["tokens_reported"] == 70


def test_unmatched_quote_is_explicit_incomplete_warning_not_verified_evidence(setup):
    _, access, service, transport = setup
    transport.result = response(warnings=[{"line": 2, "end_line": 2, "reason": "warning", "evidence_quote": "fabricated",
                                          "suggestion": "check"}])
    result = execute(service, access, reserve(service, access))
    assert result["review_status"] == "incomplete" and not result["warnings"][0]["evidence_checked"]
    assert result["issues"] == [{"status": "evidence_quote_not_matched"}]


def test_empty_warning_array_and_missing_usage_never_mean_gate_pass(setup):
    _, access, service, transport = setup
    transport.result = response(warnings=[], usage=False)
    result = execute(service, access, reserve(service, access))
    assert result["review_status"] == "incomplete" and result["issues"] == [{"status": "usage_unavailable"}]
    assert result["warnings"] == [] and result["gate_status"] == "not_evaluated" and not result["formal_acceptance"]["passed"]


@pytest.mark.parametrize("failure", ["network", "cancel", "profile", "source", "scope"])
def test_failure_or_late_response_never_refunds_or_restores_content(setup, failure):
    root, access, service, transport = setup
    pending = reserve(service, access)
    if failure == "network":
        transport.error = SemanticTransportError("http_429")
    elif failure == "cancel":
        transport.callback = lambda: pending._cancel.set()
    elif failure == "profile":
        transport.callback = lambda: service.update_profile("workspace", {"enabled": False}, expected_revision=2)
    elif failure == "source":
        transport.callback = lambda: (root / "main.py").write_text("changed = True\n")
    else:
        transport.callback = lambda: setattr(access, "confirmed", False)
    result = execute(service, access, pending)
    assert result["review_status"] != "warnings" and not result["warnings"]
    current = service.read_profile("workspace")
    assert current["session_budget"]["requests_reserved"] == 1
    assert current["session_budget"]["tokens_reserved"] > 0


def test_request_count_and_token_budgets_are_reserved_before_send_and_never_reset_by_toggle(setup):
    _, access, service, transport = setup
    for _ in range(3):
        transport.error = SemanticTransportError("timeout")
        execute(service, access, reserve(service, access))
    with pytest.raises(SemanticBudgetExceeded):
        reserve(service, access)
    service.update_profile("workspace", {"enabled": False}, expected_revision=2)
    current = service.update_profile("workspace", {"enabled": True}, expected_revision=3)
    assert current["session_budget"]["requests_reserved"] == 3
    low = service.update_profile("workspace", {"limits": {"max_requests": 20, "total_token_budget": 1}}, expected_revision=4)
    value = service.preview("workspace", access, path="main.py", start_line=2, end_line=2, access_version=1,
                            expected_profile_revision=low["revision"])
    with pytest.raises(SemanticBudgetExceeded):
        service.reserve("workspace", access, preview_id=value["preview_id"], confirmed=True,
                        expected_request_sha256=value["expected_request_sha256"], access_version=1)
    assert len(transport.calls) == 3


def test_key_echo_and_transport_errors_are_sanitized(setup):
    _, access, service, transport = setup
    transport.result = response(content=json.dumps({"warnings": [{"line": 2, "end_line": 2, "reason": FAKE_KEY,
        "evidence_quote": "assert flag", "suggestion": "none"}]}))
    result = execute(service, access, reserve(service, access))
    assert FAKE_KEY not in json.dumps(result) and result["issues"] == [{"status": "sensitive_model_response"}]
    transport.result = response()
    transport.error = RuntimeError("provider response secret " + FAKE_KEY)
    result = execute(service, access, reserve(service, access))
    assert FAKE_KEY not in json.dumps(result) and "provider response" not in json.dumps(result)


def test_workspace_cleanup_cancels_pending_and_completed_receipts_without_clearing_other_workspace(setup):
    _, access, service, transport = setup
    pending = reserve(service, access)
    service.read_profile("other")
    service.clear_workspace_content("workspace")
    assert pending._cancel.is_set()
    with pytest.raises(SemanticConflict):
        execute(service, access, pending)
    assert service.read_profile("workspace")["session_budget"]["requests_reserved"] == 1
    assert not service.read_profile("other")["key_configured"] and transport.calls == []


def test_commit_validation_detects_drift_after_successful_network_response(setup):
    root, access, service, _ = setup
    pending = reserve(service, access)
    execute(service, access, pending)
    (root / "main.py").write_text("changed = True\n")
    with pytest.raises((SemanticConflict, ValueError)):
        service.validate_current(pending, access, access_version=1, allow_completed=True)


def test_change_outside_selected_lines_invalidates_whole_raw_source_snapshot(setup):
    root, access, service, transport = setup
    value = preview(service, access)
    raw = (root / "main.py").read_bytes()
    (root / "main.py").write_bytes(raw.replace(b"return flag", b"return not flag"))
    with pytest.raises(SemanticConflict, match="snapshot_changed"):
        reserve(service, access, value)
    assert transport.calls == []


def test_boolean_access_version_cannot_equal_a_real_permission_version(setup):
    _, access, service, _ = setup
    value = preview(service, access)
    with pytest.raises(SemanticConflict):
        service.reserve("workspace", access, preview_id=value["preview_id"], confirmed=True,
                        expected_request_sha256=value["expected_request_sha256"], access_version=True)


def test_external_cancellation_before_dispatch_spends_budget_without_network_send(setup):
    _, access, service, transport = setup
    pending = reserve(service, access)
    event = threading.Event()
    event.set()
    result = service.execute(pending, access, cancel_event=event, live_guard=lambda: None)
    assert result["review_status"] == "cancelled" and result["issues"] == [{"status": "cancelled"}]
    assert not transport.calls and service.read_profile("workspace")["session_budget"]["requests_reserved"] == 1


def test_profile_transaction_failure_cannot_rotate_secret_or_invalidate_existing_preview(setup):
    import sqlite3
    _, access, service, _ = setup
    value = preview(service, access)
    connection = sqlite3.connect(service.database)
    connection.execute("CREATE TRIGGER reject_profile_update BEFORE UPDATE ON semantic_profiles BEGIN SELECT RAISE(FAIL,'synthetic'); END")
    connection.commit()
    connection.close()
    with pytest.raises(sqlite3.IntegrityError):
        service.update_profile("workspace", {}, expected_revision=2, api_key="synthetic-key-rotated")
    assert service._keys["workspace"] == FAKE_KEY
    assert service.read_profile("workspace")["revision"] == 2
    reserve(service, access, value)


def test_unicode_escaped_key_in_model_json_is_never_returned_to_browser(setup):
    _, access, service, transport = setup
    escaped = "".join("\\u%04x" % ord(character) for character in FAKE_KEY)
    content = '{"warnings":[{"line":2,"end_line":2,"reason":"' + escaped + '","evidence_quote":"assert flag","suggestion":"check"}]}'
    transport.result = response(content=content)
    assert FAKE_KEY.encode() not in transport.result.body
    result = execute(service, access, reserve(service, access))
    assert result["issues"] == [{"status": "sensitive_model_response"}]
    assert result["warnings"] == [] and FAKE_KEY not in json.dumps(result)


CONFIGURED_KEY = "synthetic-startup-configured-private-key"


@pytest.fixture
def configured_setup(tmp_path):
    root = tmp_path / "synthetic-configured-source"
    root.mkdir()
    (root / "main.py").write_bytes(b"def check(flag):\n    assert flag\n    return flag\n")
    access = AccessPolicy(root, {"model_scope": ["main.py"]})
    state = tmp_path / "configured-state"
    transport = FakeTransport()
    service = SemanticService(state, transport=transport, configured_api_key=CONFIGURED_KEY,
                              configured_key_source="env_file")
    yield root, access, state, service, transport
    service.close()


@pytest.mark.parametrize("source", ["environment", "env_file"])
def test_startup_key_survives_new_service_without_enabling_or_expanding_scope(tmp_path, source):
    state = tmp_path / "state"
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_bytes(b"def check(flag):\n    assert flag\n")
    access = AccessPolicy(root, {"model_scope": ["main.py"]})
    transport = FakeTransport()
    service = SemanticService(state, transport=transport, configured_api_key=CONFIGURED_KEY,
                              configured_key_source=source)
    try:
        current = service.read_profile("workspace")
        assert current["key_configured"] and current["key_source"] == source
        assert current["configured_key_available"] and current["configured_key_enabled"]
        assert current["configured_key_source"] == source and not current["enabled"]
        with pytest.raises(SemanticConflict, match="semantic_profile_not_ready"):
            service.preview("workspace", access, path="main.py", start_line=2, end_line=2, access_version=1)
        service.update_profile("workspace", {"enabled": True}, expected_revision=1)
        with pytest.raises(AccessDenied):
            preview(service, AccessPolicy(root, {}))
        report = execute(service, access, reserve(service, access))
        assert report["review_status"] == "warnings" and len(transport.calls) == 1
        assert transport.calls[0][1] == CONFIGURED_KEY
        assert CONFIGURED_KEY.encode() not in transport.calls[0][0]
        assert CONFIGURED_KEY not in json.dumps(current) and CONFIGURED_KEY not in json.dumps(report)
        assert CONFIGURED_KEY.encode() not in service.database.read_bytes()
    finally:
        service.close()
    restarted_transport = FakeTransport()
    restarted = SemanticService(state, transport=restarted_transport, configured_api_key=CONFIGURED_KEY,
                                configured_key_source=source)
    try:
        profile = restarted.read_profile("workspace")
        assert profile["revision"] == 2 and profile["enabled"] and profile["key_source"] == source
        assert profile["key_configured"] and profile["session_budget"]["requests_reserved"] == 0
        assert not restarted_transport.calls
    finally:
        restarted.close()


def test_workspace_override_clear_and_persisted_suppression_do_not_affect_other_workspaces(configured_setup):
    _, access, state, service, transport = configured_setup
    profile = service.update_profile("workspace", {"enabled": True}, expected_revision=1, api_key=FAKE_KEY)
    assert profile["key_source"] == "workspace_session" and profile["configured_key_available"]
    assert service.read_profile("other")["key_source"] == "env_file"
    pending = reserve(service, access)
    cleared = service.update_profile("workspace", {}, expected_revision=2, clear_key=True)
    assert cleared["key_source"] == "none" and not cleared["key_configured"]
    assert not cleared["configured_key_enabled"] and cleared["configured_key_available"]
    assert cleared["session_budget"]["requests_reserved"] == 1
    with pytest.raises(SemanticConflict):
        execute(service, access, pending)
    assert not transport.calls
    service.close()
    restarted = SemanticService(state, transport=transport, configured_api_key=CONFIGURED_KEY,
                                configured_key_source="env_file")
    try:
        current = restarted.read_profile("workspace")
        assert current["revision"] == 3 and not current["key_configured"] and not current["configured_key_enabled"]
        assert restarted.read_profile("other")["key_source"] == "env_file"
        with pytest.raises(SemanticConflict, match="semantic_profile_not_ready"):
            restarted.preview("workspace", access, path="main.py", start_line=2, end_line=2, access_version=1)
        restored = restarted.update_profile("workspace", {}, expected_revision=3, use_configured_key=True)
        assert restored["revision"] == 4 and restored["configured_key_enabled"] and restored["key_source"] == "env_file"
        value = restarted.preview("workspace", access, path="main.py", start_line=2, end_line=2,
                                  access_version=1, expected_profile_revision=4)
        request = restarted.reserve("workspace", access, preview_id=value["preview_id"], confirmed=True,
            expected_request_sha256=value["expected_request_sha256"], access_version=1, expected_profile_revision=4)
        assert execute(restarted, access, request)["review_status"] == "warnings"
        assert transport.calls[0][1] == CONFIGURED_KEY
    finally:
        restarted.close()


def test_returning_to_configured_key_drops_override_and_revokes_old_previews(configured_setup):
    _, access, _, service, transport = configured_setup
    service.update_profile("workspace", {"enabled": True}, expected_revision=1, api_key=FAKE_KEY)
    value = preview(service, access)
    pending = reserve(service, access)
    profile = service.update_profile("workspace", {}, expected_revision=2, use_configured_key=True)
    assert profile["revision"] == 3 and profile["key_source"] == "env_file"
    assert profile["session_budget"]["requests_reserved"] == 1 and "workspace" not in service._keys
    with pytest.raises(SemanticConflict):
        reserve(service, access, value)
    with pytest.raises(SemanticConflict):
        execute(service, access, pending)
    assert not transport.calls


@pytest.mark.parametrize("key,source", [("short", "env_file"), ("secret\nheader", "environment"),
    (123, "env_file"), (CONFIGURED_KEY, None), (None, "environment"), (CONFIGURED_KEY, "repository"),
    (CONFIGURED_KEY, []), (CONFIGURED_KEY, True)])
def test_invalid_startup_credentials_fail_with_fixed_error_before_state_creation(tmp_path, key, source):
    with pytest.raises(ValueError) as error:
        SemanticService(tmp_path / "state", configured_api_key=key, configured_key_source=source)
    assert str(error.value) in {"invalid_api_key", "invalid_configured_key_source"}
    assert CONFIGURED_KEY not in str(error.value) and not (tmp_path / "state").exists()


@pytest.mark.parametrize("options", [{"use_configured_key": 1}, {"use_configured_key": "true"},
    {"use_configured_key": True, "api_key": FAKE_KEY}, {"use_configured_key": False, "clear_key": True}])
def test_conflicting_or_invalid_key_source_preferences_do_not_change_profile(configured_setup, options):
    _, _, _, service, _ = configured_setup
    with pytest.raises(ValueError):
        service.update_profile("workspace", {}, expected_revision=1, **options)
    profile = service.read_profile("workspace")
    assert profile["revision"] == 1 and profile["key_source"] == "env_file" and profile["configured_key_enabled"]


def test_configured_key_restore_requires_an_available_startup_key(setup):
    _, access, service, _ = setup
    value = preview(service, access)
    with pytest.raises(SemanticConflict, match="configured_key_unavailable"):
        service.update_profile("workspace", {}, expected_revision=2, use_configured_key=True)
    assert service.read_profile("workspace")["revision"] == 2 and service._keys["workspace"] == FAKE_KEY
    reserve(service, access, value)


def test_failed_suppression_transaction_preserves_key_and_existing_preview(configured_setup):
    import sqlite3
    _, access, _, service, _ = configured_setup
    service.update_profile("workspace", {"enabled": True}, expected_revision=1, api_key=FAKE_KEY)
    value = preview(service, access)
    with sqlite3.connect(service.database) as connection:
        connection.execute("CREATE TRIGGER reject_suppression BEFORE UPDATE ON semantic_profiles BEGIN SELECT RAISE(FAIL,'synthetic'); END")
    with pytest.raises(sqlite3.IntegrityError):
        service.update_profile("workspace", {}, expected_revision=2, clear_key=True)
    profile = service.read_profile("workspace")
    assert profile["revision"] == 2 and profile["key_source"] == "workspace_session" and profile["configured_key_enabled"]
    reserve(service, access, value)


def test_v1_schema_migration_preserves_existing_nonsecret_settings(tmp_path):
    import sqlite3
    state = tmp_path / "state"
    state.mkdir()
    database = state / "semantic_profiles.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE semantic_metadata(version INTEGER NOT NULL);
            INSERT INTO semantic_metadata VALUES(1);
            CREATE TABLE semantic_profiles(workspace_id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
                enabled INTEGER NOT NULL, model TEXT NOT NULL, max_requests INTEGER NOT NULL,
                total_token_budget INTEGER NOT NULL, timeout_seconds INTEGER NOT NULL);
            INSERT INTO semantic_profiles VALUES('workspace',7,1,'deepseek-v4-pro',5,50000,12);
        """)
    service = SemanticService(state, configured_api_key=CONFIGURED_KEY, configured_key_source="environment")
    try:
        profile = service.read_profile("workspace")
        assert profile["revision"] == 7 and profile["enabled"] and profile["model"] == "deepseek-v4-pro"
        assert profile["limits"]["max_requests"] == 5 and profile["limits"]["total_token_budget"] == 50000
        assert profile["limits"]["timeout_seconds"] == 12 and profile["configured_key_enabled"]
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version FROM semantic_metadata").fetchall() == [(2,)]
            assert connection.execute("SELECT * FROM semantic_profiles").fetchall() == [("workspace", 7, 1, "deepseek-v4-pro", 5, 50000, 12, 1)]
        assert CONFIGURED_KEY.encode() not in database.read_bytes()
    finally:
        service.close()


def test_configured_key_in_excerpt_or_response_is_protected(configured_setup):
    root, access, _, service, transport = configured_setup
    service.update_profile("workspace", {"enabled": True}, expected_revision=1)
    (root / "main.py").write_text("def check(flag):\n    assert '" + CONFIGURED_KEY + "'\n", encoding="utf-8")
    with pytest.raises(AccessDenied, match="suspected_secret_in_excerpt"):
        preview(service, access)
    (root / "main.py").write_bytes(b"def check(flag):\n    assert flag\n")
    escaped = "".join("\\u%04x" % ord(character) for character in CONFIGURED_KEY)
    content = '{"warnings":[{"line":2,"end_line":2,"reason":"' + escaped + '","evidence_quote":"assert flag","suggestion":"check"}]}'
    transport.result = response(content=content)
    result = execute(service, access, reserve(service, access))
    assert result["issues"] == [{"status": "sensitive_model_response"}] and result["warnings"] == []
    assert CONFIGURED_KEY not in json.dumps(result) and CONFIGURED_KEY.encode() not in service.database.read_bytes()


@pytest.mark.parametrize("suppressed", [False, True])
def test_inactive_configured_key_cannot_leave_in_excerpt_path_or_encoded_response(configured_setup, suppressed):
    root, access, _, service, transport = configured_setup
    if suppressed:
        service.update_profile("workspace", {}, expected_revision=1, clear_key=True)
    version = service.read_profile("workspace")["revision"]
    service.update_profile("workspace", {"enabled": True}, expected_revision=version, api_key=FAKE_KEY)
    revision = service.read_profile("workspace")["revision"]
    assert service.read_profile("workspace")["key_source"] == "workspace_session"
    (root / "main.py").write_text("value = '" + CONFIGURED_KEY + "'\n", encoding="utf-8")
    with pytest.raises(AccessDenied, match="suspected_secret_in_excerpt"):
        service.preview("workspace", access, path="main.py", start_line=1, end_line=1,
                        access_version=1, expected_profile_revision=revision)
    sensitive_path = CONFIGURED_KEY + ".py"
    (root / sensitive_path).write_bytes(b"assert flag\n")
    with pytest.raises(AccessDenied, match="suspected_secret_in_request"):
        service.preview("workspace", AccessPolicy(root, {"model_scope": [sensitive_path]}), path=sensitive_path,
                        start_line=1, end_line=1, access_version=1, expected_profile_revision=revision)
    (root / "main.py").write_bytes(b"def check(flag):\n    assert flag\n")
    value = service.preview("workspace", access, path="main.py", start_line=2, end_line=2,
                            access_version=1, expected_profile_revision=revision)
    request = service.reserve("workspace", access, preview_id=value["preview_id"], confirmed=True,
        expected_request_sha256=value["expected_request_sha256"], access_version=1, expected_profile_revision=revision)
    escaped = "".join("\\u%04x" % ord(character) for character in CONFIGURED_KEY)
    transport.result = response(content='{"warnings":[{"line":2,"end_line":2,"reason":"' + escaped + '","evidence_quote":"assert flag","suggestion":"check"}]}')
    result = execute(service, access, request)
    assert result["issues"] == [{"status": "sensitive_model_response"}] and result["warnings"] == []
    assert transport.calls[0][1] == FAKE_KEY and CONFIGURED_KEY not in json.dumps(result)
