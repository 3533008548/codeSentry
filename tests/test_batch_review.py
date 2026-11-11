import json

import pytest

from codesentry.cli.main import main
from codesentry.semantic import service
from codesentry.semantic.transport import SemanticTransportError, TransportResponse
from codesentry.workspaces.store import WorkspaceStore


KEY = "synthetic-batch-review-key-123"


class MockTransport:
    def __init__(self):
        self.calls = []
        self.action = None

    def send(self, body, *, api_key, cancel_event, live_guard, **_kwargs):
        assert api_key == KEY
        live_guard()
        request = json.loads(body)
        payload = json.loads(request["messages"][-1]["content"])
        self.calls.append(payload)
        if "sources" not in payload:
            index = (payload["evidence_index"] if "sections" in payload else
                     {row["id"]: row for row in payload["observations"] if row["evidence_line"] is not None})
            ids = list(index)[:2]
            claim = {"text": "待核对的跨文件观察", "range_ids": ids}
            if '"evidence":[' in request["messages"][0]["content"]:
                claim.pop("range_ids")
                claim["evidence"] = []
                claim["sums"] = []
                for identity in ids:
                    line, quote = index[identity]["source"].splitlines()[0].split(" | ", 1)
                    claim["evidence"].append({"id": identity, "line": int(line), "quote": quote})
            value = {"claims": [claim] if ids else [],
                     "unknowns": ["运行环境待核对"]}
            if self.action:
                self.action(value)
            live_guard()
            return TransportResponse(200, json.dumps({"choices": [{"finish_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(value)}}]}).encode())
        assert payload["required_ids"] == [item["id"] for item in payload["sources"]]
        reviews = []
        for item in payload["sources"]:
            lines = item["source"].splitlines()
            for number, line in enumerate(lines, item["start_line"]):
                assert line.startswith(f"{number} | ")
            reviews.append({"id": item["id"], "observation": "观察到赋值，实际运行情况待验证。",
                            "line": item["start_line"], "quote": lines[0].split(" | ", 1)[1]})
        if self.action:
            self.action(reviews)
        live_guard()
        value = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant",
                            "content": json.dumps({"reviews": reviews})}}],
                 "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}}
        return TransportResponse(200, json.dumps(value).encode())


@pytest.fixture
def bench(tmp_path, monkeypatch, capsys):
    root, data = tmp_path / "source", tmp_path / "state"
    root.mkdir()
    (root / "main.py").write_bytes(b"value = 1\n" * 900)
    (root / "local.py").write_text("LOCAL_ONLY_SENTINEL = 1\n")
    (root / "private.py").write_text("EXCLUDED_SENTINEL = 2\n")
    ws = WorkspaceStore(data).create_workspace(str(root), access_policy={"confirmed": True, "settings": {
        "model_scope": ["*.py"], "exclude": ["private.py"], "local_only": ["local.py"]}})
    transport = MockTransport()
    monkeypatch.setattr(service, "DeepSeekTransport", lambda: transport)
    monkeypatch.setenv("DEEPSEEK_API_KEY", KEY)
    semantic = service.SemanticService(data, configured_api_key=KEY, configured_key_source="environment")
    profile = semantic.read_profile(ws["id"])
    semantic.update_profile(ws["id"], {"enabled": True}, expected_revision=profile["revision"])
    semantic.close()
    common = [str(root), "--workspace-data-dir", str(data)]

    def plan(*, expected=0):
        assert main(["review-plan", *common, "--json"]) == expected
        return json.loads(capsys.readouterr().out)["plan_sha256"]

    def run(digest, *, first=1, limit=3, retries=0, model="deepseek-flash"):
        code = main(["review-run", *common, "--approve-plan", digest, "--question", "检查源码行为",
                     "--model", model, "--first-batch", str(first), "--max-batches", str(limit),
                     "--retry-requests", str(retries)])
        captured = capsys.readouterr()
        return code, json.loads(captured.out) if captured.out else None

    return root, transport, plan, run


def test_cli_review_requires_current_approval_and_reports_full_model_scope(bench):
    root, transport, plan, run = bench
    approved = plan()
    assert run("0" * 64) == (2, None)
    assert run(approved, model="deepseek-v4-pro") == (2, None)
    assert transport.calls == []
    code, report = run(approved)
    assert code == 0
    assert report["review_status"] == "model_scope_complete"
    assert report["plan_scope"]["planned_lines"] == 901
    assert report["completed_lines"] == 900
    assert report["range_counts"] == {"completed": 9, "failed": 0, "blocked": 0, "pending": 0, "interrupted": 0}
    assert [len(call["sources"]) for call in transport.calls] == [4, 4, 1]
    assert [row["evidence_line"] for row in report["ranges"]] == list(range(1, 901, 100))
    assert "SENTINEL" not in json.dumps(transport.calls) and "local.py" not in json.dumps(report)
    assert [row["total_tokens"] for row in report["usage"]] == [150, 150, 150]


@pytest.mark.parametrize("problem,failed", [("missing", 1), ("quote", 1), ("timeout", 4), ("duplicate", 1), ("unknown_id", 4)])
def test_only_valid_attributable_ranges_count_and_later_batches_can_be_selected(bench, problem, failed):
    _root, transport, plan, run = bench
    approved = plan()

    def bad(reviews):
        if problem == "missing":
            reviews.pop()
        elif problem == "quote":
            reviews[0]["quote"] = "FAKE_QUOTE"
        elif problem == "duplicate":
            reviews.append(dict(reviews[0]))
        elif problem == "unknown_id":
            reviews.append({**reviews[0], "id": "R9999"})
        else:
            raise SemanticTransportError("timeout")

    transport.action = bad
    code, report = run(approved, limit=1)
    assert code == 1
    assert report["range_counts"] == {"completed": 4 - failed, "failed": failed, "blocked": 0,
                                      "pending": 5, "interrupted": 0}
    assert report["attempted_requests"] == 1 and report["retries"] == []
    assert "FAKE_QUOTE" not in json.dumps(report)
    transport.action = None
    code, selected = run(approved, first=2, limit=1)
    assert code == 1 and selected["completed_lines"] == 400
    assert [row["id"] for row in transport.calls[-1]["sources"]] == ["R5", "R6", "R7", "R8"]
    assert selected["range_counts"]["pending"] == 5


def test_retry_only_sends_failed_ranges_and_uses_budget_once(bench):
    _, transport, plan, run = bench
    approved = plan()
    assert run(approved, limit=100, retries=1) == (2, None)

    def bad_first_response(reviews):
        if len(transport.calls) == 1:
            reviews[0]["quote"] = "FAKE_QUOTE"
            reviews.pop()
        if len(transport.calls) >= 3:
            reviews[0]["quote"] = "STILL_FAKE"

    transport.action = bad_first_response
    code, report = run(approved, retries=1)
    assert code == 1 and report["attempted_batches"] == 3 and report["attempted_requests"] == 4
    assert [call["required_ids"] for call in transport.calls] == [
        ["R1", "R2", "R3", "R4"], ["R1", "R4"], ["R5", "R6", "R7", "R8"], ["R9"]]
    assert report["retries"] == [{"batch": 1, "reasons": {"R1": "invalid_review_citation", "R4": "incomplete_review_batch"}}]
    assert [row["status"] for row in report["ranges"]] == ["completed"] * 4 + ["failed", "completed", "completed", "completed", "failed"]
    assert all("reason" not in row for row in report["ranges"][:4])
    assert [(row["batch"], row["attempt"]) for row in report["usage"]] == [(1, 1), (1, 2), (2, 1), (3, 1)]


@pytest.mark.parametrize("change", ["source", "policy"])
def test_change_during_request_discards_unpublished_output(bench, change):
    root, transport, plan, run = bench
    approved = plan()

    def modify(_reviews):
        if change == "source":
            (root / "main.py").write_bytes(b"value = 2\n" * 900)
        else:
            (root / ".gitignore").write_text("main.py\n")

    transport.action = modify
    code, report = run(approved)
    assert code == 1 and report["review_status"] == "invalidated"
    assert len(transport.calls) == 1 and "ranges" not in report
    assert run(approved) == (2, None)
    assert len(transport.calls) == 1


def test_credential_screen_blocks_entire_file_and_cancellation_reports_pending(bench):
    root, transport, plan, run = bench
    (root / "a.py").write_text(f"private = '{KEY}'\n")
    approved = plan()
    code, report = run(approved, limit=1)
    assert code == 1 and report["range_counts"]["blocked"] == 1
    assert report["range_counts"]["completed"] == 3
    assert KEY not in json.dumps(transport.calls) and "a.py" not in json.dumps(transport.calls)
    assert KEY not in json.dumps(report)

    def interrupt(_reviews):
        raise KeyboardInterrupt

    transport.action = interrupt
    code, report = run(approved, first=2, limit=1)
    assert code == 130 and report["stop_reason"] == "cancelled"
    assert report["range_counts"]["interrupted"] == 4 and report["range_counts"]["pending"] == 6


def test_rate_limit_stops_before_the_remaining_batches(bench):
    _root, transport, plan, run = bench

    def rate_limit(_reviews):
        raise SemanticTransportError("http_429")

    transport.action = rate_limit
    code, report = run(plan(), retries=2)
    assert code == 1 and report["stop_reason"] == "http_429"
    assert len(transport.calls) == 1 and report["range_counts"]["pending"] == 5


def test_change_to_a_previously_processed_file_invalidates_the_final_report(bench):
    root, transport, plan, run = bench
    previous = root / "a.py"
    previous.write_bytes(b"value = 1\n" * 400)

    def modify_previous(_reviews):
        if len(transport.calls) == 2:
            previous.write_bytes(b"value = 2\n" * 400)

    transport.action = modify_previous
    code, report = run(plan(), limit=2)
    assert code == 1 and report["review_status"] == "invalidated"
    assert len(transport.calls) == 2 and "ranges" not in report


def test_known_plan_gap_prevents_complete_scope_even_when_all_sent_ranges_succeed(bench):
    root, transport, plan, run = bench
    (root / "main.py").write_bytes(b"value = 1\n#" + b"x" * 3100 + b"\nvalue = 2\n")
    code, report = run(plan(expected=1))
    assert code == 1 and report["review_status"] == "partial"
    assert report["plan_status"] == "incomplete"
    assert report["range_counts"]["completed"] == 2
    assert report["completed_lines"] == 2
    assert len(transport.calls) == 1


def _merge(bench, capsys, approved, reports, *, budget=0, question="检查源码行为", source=False):
    root, *_ = bench
    arguments = ["review-merge", str(root), "--workspace-data-dir", str(root.parent / "state"),
                 "--approve-plan", approved, "--question", question, "--model", "deepseek-flash",
                 "--summary-requests", str(budget)]
    if source:
        arguments.append("--summary-source-evidence")
    for index, report in enumerate(reports):
        path = root.parent / f"report-{index}.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        arguments.extend(("--report", str(path)))
    code = main(arguments)
    output = capsys.readouterr().out
    return code, json.loads(output) if output else None


def test_merge_completes_separate_runs_and_summary_is_explicit(bench, capsys):
    _, transport, plan, run = bench
    approved = plan()
    _, first = run(approved, limit=1)
    _, second = run(approved, first=2, limit=2)
    assert len(transport.calls) == 3
    code, partial = _merge(bench, capsys, approved, [first], budget=1)
    assert code == 1 and partial["summary"]["status"] == "coverage_incomplete"
    code, merged = _merge(bench, capsys, approved, [second, first, first])
    assert code == 0 and merged["completed_lines"] == 900 and merged["summary"]["status"] == "not_requested"
    assert len(merged["source_reports"]) == 2 and len(transport.calls) == 3
    code, merged = _merge(bench, capsys, approved, [first, second], budget=1)
    assert code == 0 and merged["summary"]["status"] == "completed"
    assert merged["summary"]["claims"][0]["evidence"] == [
        {"id": "R1", "path": "main.py", "line": 1}, {"id": "R2", "path": "main.py", "line": 101},
    ]
    assert "sources" not in transport.calls[-1] and len(transport.calls) == 4
    assert all("source" not in note for note in transport.calls[-1]["observations"])


def test_source_summary_requires_opt_in_and_checks_exact_live_quote(bench, capsys):
    root, transport, plan, run = bench
    (root / "main.py").write_text("first = 1\nsecond = 2\nthird = 3\n")

    def no_evidence(reviews):
        for review in reviews[1:]:
            review.update(line=None, quote=None)

    (root / "other.py").write_text("UNCITED = 1\n")
    transport.action = no_evidence
    approved = plan()
    _, report = run(approved)
    transport.action = None
    assert _merge(bench, capsys, approved, [report], source=True) == (2, None)
    assert len(transport.calls) == 1

    def precise_location(value):
        value["claims"][0]["evidence"] = [{"id": "R1", "line": 2, "quote": "second = 2"}]
        value["claims"][0]["sums"] = [{"terms": [0, 3, -2], "result": 1}]

    transport.action = precise_location
    code, merged = _merge(bench, capsys, approved, [report], budget=1, source=True)
    assert code == 0 and merged["summary"]["evidence_mode"] == "source"
    assert merged["summary"]["claims"][0]["evidence"] == [{"id": "R1", "path": "main.py", "line": 2}]
    assert merged["summary"]["claims"][0]["sums"] == [{"terms": [0, 3, -2], "result": 1}]
    assert "2 | second = 2" in transport.calls[-1]["observations"][0]["source"]
    assert "SENTINEL" not in json.dumps(transport.calls[-1]) and "UNCITED" not in json.dumps(transport.calls[-1])
    assert "second = 2" not in json.dumps(merged)

    def wrong_location(value):
        value["claims"][0]["evidence"] = [{"id": "R1", "line": 1, "quote": "second = 2"}]

    transport.action = wrong_location
    code, merged = _merge(bench, capsys, approved, [report], budget=1, source=True)
    assert code == 1 and merged["summary"] == {"status": "failed", "reason": "invalid_review_citation", "requests": 1}

    def wrong_arithmetic(value):
        value["claims"][0]["sums"] = [{"terms": [0, 3, -2], "result": -2}]

    transport.action = wrong_arithmetic
    code, merged = _merge(bench, capsys, approved, [report], budget=1, source=True)
    assert code == 1 and merged["summary"] == {"status": "failed", "reason": "invalid_review_calculation", "requests": 1}

    first = len(transport.calls) + 1

    def recalculate(value):
        if len(transport.calls) == first:
            wrong_arithmetic(value)
        else:
            precise_location(value)

    transport.action = recalculate
    code, merged = _merge(bench, capsys, approved, [report], budget=2, source=True)
    assert code == 0 and merged["summary"]["requests"] == 2
    assert merged["summary"]["retries"] == [{"stage": "final", "reason": "invalid_review_calculation"}]
    assert merged["summary"]["claims"][0]["sums"] == [{"terms": [0, 3, -2], "result": 1}]
    assert transport.calls[-1] == transport.calls[-2]


def test_merge_refuses_forged_digest_and_another_question(bench, capsys):
    from codesentry.review.batch_review import report_digest

    _, transport, plan, run = bench
    approved = plan()
    _, report = run(approved)
    assert _merge(bench, capsys, approved, [report], question="不同的问题") == (2, None)
    report["ranges"][0]["observation"] = "伪造内容"
    report["report_sha256"] = report_digest({key: value for key, value in report.items() if key != "report_sha256"})
    assert _merge(bench, capsys, approved, [report], budget=1) == (2, None)
    assert len(transport.calls) == 3


def test_conflicting_completed_observations_stay_out_of_summary(bench, capsys):
    _, transport, plan, run = bench
    approved = plan()
    _, first = run(approved)

    def conflict(reviews):
        reviews[0]["observation"] = "不同的观察"

    transport.action = conflict
    _, second = run(approved, limit=1)
    code, report = _merge(bench, capsys, approved, [first, second], budget=1)
    assert code == 1 and report["range_counts"]["conflict"] == 1
    assert report["summary"]["status"] == "coverage_incomplete"
    assert len(transport.calls) == 4


@pytest.mark.parametrize("case", ["citation", "changed_source", "changed_source_on_retry"])
def test_summary_rejects_forged_citations_and_live_source_change(bench, capsys, case):
    root, transport, plan, run = bench
    approved = plan()
    _, report = run(approved)

    def fail(value):
        if case == "citation" or (case == "changed_source_on_retry" and len(transport.calls) == 4):
            value["claims"][0]["range_ids"] = ["R9999"]
        else:
            (root / "main.py").write_bytes(b"value = 2\n" * 900)

    transport.action = fail
    code, merged = _merge(bench, capsys, approved, [report], budget=2 if case == "changed_source_on_retry" else 1)
    assert code == 1
    if case == "citation":
        assert merged["summary"]["status"] == "failed" and "claims" not in merged["summary"]
    else:
        assert merged["review_status"] == "invalidated" and "ranges" not in merged
        assert len(transport.calls) == (5 if case == "changed_source_on_retry" else 4)


@pytest.mark.parametrize("source", [False, True])
def test_summary_groups_large_inputs_without_silently_truncating(bench, capsys, monkeypatch, source):
    from codesentry.review import review_merge

    _, transport, plan, run = bench
    approved = plan()
    _, report = run(approved)
    monkeypatch.setattr(review_merge, "SUMMARY_BYTES", 6000 if source else 780)
    if source:
        def one_range(value):
            value["claims"][0]["evidence"] = value["claims"][0]["evidence"][:1]

        transport.action = one_range
    code, bounded = _merge(bench, capsys, approved, [report], budget=1, source=source)
    assert code == 1 and bounded["summary"]["status"] == "request_budget" and len(transport.calls) == 3
    code, merged = _merge(bench, capsys, approved, [report], budget=10, source=source)
    assert code == 0 and merged["summary"]["status"] == "completed"
    requests = transport.calls[3:]
    assert [row["id"] for request in requests[:-1] for row in request["observations"]] == [
        f"R{number}" for number in range(1, 10)]
    assert "sections" in requests[-1] and merged["summary"]["requests"] == len(requests)
    if source:
        final_index = requests[-1]["evidence_index"]
        assert set(final_index) == {group["observations"][0]["id"] for group in requests[:-1]}
        assert all("source" in entry for entry in final_index.values())


@pytest.mark.parametrize("repair_succeeds", [False, True])
def test_group_retry_uses_only_spare_budget_and_reuses_valid_groups(bench, capsys, monkeypatch, repair_succeeds):
    from codesentry.review import review_merge

    _, transport, plan, run = bench
    approved = plan()
    _, report = run(approved)
    initial_calls = len(transport.calls)
    monkeypatch.setattr(review_merge, "SUMMARY_BYTES", 780)
    _, bounded = _merge(bench, capsys, approved, [report], budget=1)
    required = bounded["summary"]["minimum_requests"]
    assert required >= 3 and len(transport.calls) == initial_calls

    def bad_group(value):
        calls = len(transport.calls) - initial_calls
        if calls == 2 or (calls == 3 and not repair_succeeds):
            value["claims"][0]["range_ids"] = ["R9999"]

    transport.action = bad_group
    code, merged = _merge(bench, capsys, approved, [report], budget=required + 1)
    requests = transport.calls[initial_calls:]
    summary = merged["summary"]
    assert summary["retries"] == [{"stage": "group", "group": 2, "reason": "invalid_review_summary_citation"}]
    assert requests[0] != requests[1] and requests[1] == requests[2]
    if repair_succeeds:
        assert code == 0 and summary["status"] == "completed"
        assert summary["requests"] == len(requests) == required + 1 and "sections" in requests[-1]
    else:
        assert code == 1 and summary["status"] == "failed"
        assert summary["requests"] == len(requests) == 3 and "claims" not in summary


@pytest.mark.parametrize("mode", ["observations", "source", "uncited_target", "grouped"])
def test_cross_batch_call_evidence_uses_only_resolved_and_authorized_sources(bench, capsys, monkeypatch, mode):
    from codesentry.review import review_merge

    root, transport, plan, run = bench
    (root / "b.py").write_text("from z_worker import emit\ndef go(emit):\n    return emit('shadowed')\n")
    (root / "c.py").write_text("def go(key):\n    return emit(key)  # Unbound bare name\n")
    (root / "d.py").write_text("unused = True\n")
    (root / "main.py").write_text("from z_worker import emit as dispatch\ndef go(key):\n    return dispatch(key)\n")
    (root / "z_worker.py").write_text("def emit(key):\n    return 'queued:' + key\n")
    if mode == "uncited_target":
        def omit_target_evidence(reviews):
            for row in reviews:
                if row["id"] == "R5":
                    row.update(line=None, quote=None)

        transport.action = omit_target_evidence
    approved = plan()
    _, report = run(approved)
    transport.action = None
    assert [call["required_ids"] for call in transport.calls] == [["R1", "R2", "R3", "R4"], ["R5"]]
    if mode == "grouped":
        monkeypatch.setattr(review_merge, "SUMMARY_BYTES", 800)

        def leave_worker_out_of_group_claims(value):
            if "observations" not in transport.calls[-1]:
                return
            group = transport.calls[-1]["observations"]
            if any(row["id"] == "R4" for row in group):
                value["claims"][0]["evidence"] = [{"id": "R4", "line": 3, "quote": "return dispatch(key)"}]
            else:
                value["claims"] = []

        transport.action = leave_worker_out_of_group_claims
    code, merged = _merge(bench, capsys, approved, [report], budget=10 if mode == "grouped" else 1,
                          source=mode != "observations")
    assert code == 0
    summary, outbound = merged["summary"], transport.calls[-1]
    link = {"source_id": "R4", "line": 3, "target_id": "R5", "target_line": 1}
    if mode == "grouped":
        assert set(outbound["evidence_index"]) == {"R4", "R5"}
        assert outbound["evidence_index"]["R4"]["calls"] == [link]
        assert "1 | def emit(key):" in outbound["evidence_index"]["R5"]["source"]
        assert summary["static_call_links"] == [link]
    elif mode == "source":
        assert [hint for row in outbound["observations"] for hint in row.get("calls", [])] == [link]
        assert summary["static_call_links"] == [link]
    else:
        assert all("calls" not in row for row in outbound["observations"])
        assert "static_call_links" not in summary
