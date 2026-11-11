import hashlib
import json

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.cli.main import main
from codesentry.conversation.context import select_context
from codesentry.review.coverage_plan import build_coverage_plan
from codesentry.review.scan import PreviewLimits


def test_cli_plan_has_exact_physical_ranges_and_omits_restricted_paths(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    state = root / "workbench-data"
    state.mkdir()
    (state / "artifact.json").write_text("STATE_SENTINEL")
    raw = b"value = 'COVERAGE_SENTINEL'\r\ntext = '''a\vb'''\r\n" + b"v = 3\r\n" * 101
    (root / "main.py").write_bytes(raw)
    (root / "local.py").write_text("LOCAL_SENTINEL = True\n")
    (root / "private.py").write_text("PRIVATE_SENTINEL = True\n")
    (root / "ignored.py").write_text("IGNORED_SENTINEL = True\n")
    (root / ".gitignore").write_text("ignored.py\n")
    (root / "asset.png").write_bytes(b"asset")
    arguments = ["review-plan", str(root), "--workspace-data-dir", str(state), "--exclude", "private.py", "--json"]
    assert main(arguments) == 2
    assert not capsys.readouterr().out
    assert main([*arguments, "--confirm-access"]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert (report["plan_status"], report["review_status"]) == ("ready", "not_started")
    assert report["summary"]["planned_lines"] == 104
    rows = {item["path"]: item for item in report["files"]}
    assert set(rows) == {"local.py", "main.py"}
    assert rows["main.py"]["lines"] == 103
    assert rows["main.py"]["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert [(r["start_line"], r["end_line"]) for r in rows["main.py"]["ranges"]] == [(1, 100), (101, 103)]
    assert report["summary"]["excluded_files_seen"] >= 2
    assert report["summary"]["excluded_directories_seen"] >= 1
    assert "SENTINEL" not in output and "ignored.py" not in output and "private.py" not in output


def test_plan_records_a_long_line_gap_and_keeps_later_lines(tmp_path):
    (tmp_path / "main.py").write_text("a = 1\n" + "# " + "字" * 1100 + "\nb = 2\n", encoding="utf-8")
    access = AccessPolicy(tmp_path, {"model_scope": ["*.py"]}, confirmed=True)
    result = build_coverage_plan(access)
    assert result["plan_status"] == "incomplete"
    assert result["summary"]["planned_lines"] == 2
    row, = result["files"]
    assert row["access_mode"] == "model_eligible"
    assert [(span["start_line"], span["end_line"], span["status"]) for span in row["ranges"]] == [
        (1, 1, "planned"), (2, 2, "line_limit"), (3, 3, "planned"),
    ]
    limited = build_coverage_plan(access, max_ranges=1)
    assert limited["files"][0]["ranges"][-1] == {"start_line": 2, "end_line": 3, "status": "range_limit"}
    assert limited["plan_status"] == "incomplete"


def test_plan_budget_and_binary_do_not_look_complete(tmp_path):
    (tmp_path / "a.py").write_bytes(b"x\0")
    (tmp_path / "b.py").write_bytes(b"x" * 30)
    (tmp_path / "c.py").write_bytes(b"x" * 7)
    (tmp_path / "d.py").write_bytes(b"x = 1")
    access = AccessPolicy(tmp_path, confirmed=True)
    plan = build_coverage_plan(access, limits=PreviewLimits(max_files=3, max_total_bytes=8, max_file_bytes=10))
    assert plan["summary"]["files_omitted_by_limit"] == 1
    assert plan["summary"]["planned_lines"] == 0
    assert plan["plan_status"] == "incomplete" and "no_plannable_source" in plan["issues"]
    assert [row["status"] for row in plan["files"]] == ["unsupported_content", "file_byte_limit", "total_byte_limit"]


@pytest.mark.parametrize("change", ["source", "inventory", "policy"])
def test_plan_rejects_or_reports_input_changes(tmp_path, monkeypatch, change):
    file = tmp_path / "main.py"
    file.write_bytes(b"x = 1\n")
    access = AccessPolicy(tmp_path, confirmed=True)
    read_bytes = access.read_bytes
    calls = 0

    def read(path, limit):
        nonlocal calls
        value = read_bytes(path, limit)
        calls += 1
        if calls == 1:
            if change == "source":
                file.write_bytes(b"x = 2\n")
            elif change == "inventory":
                (tmp_path / "added.py").write_bytes(b"y = 1\n")
            else:
                (tmp_path / ".gitignore").write_bytes(b"main.py\n")
        return value

    monkeypatch.setattr(access, "read_bytes", read)
    if change == "policy":
        with pytest.raises(AccessDenied):
            build_coverage_plan(access)
    else:
        result = build_coverage_plan(access)
        assert result["plan_status"] == "incomplete"
        if change == "source":
            assert result["files"][0]["status"] == "source_changed"
            assert result["files"][0]["ranges"] == []
            assert result["summary"]["planned_lines"] == 0
        else:
            assert "inventory_changed" in result["issues"]


@pytest.mark.parametrize(("source", "question", "expected_partial"), [
    ("v = 1\n" * 300, "overview", True),
    ("v = 1\n" * 30 + "needle = 1\n", "needle", True),
    ("v = 1\n" * 30, "overview", False),
])
def test_single_file_chat_marks_partial_lines_not_just_partial_files(tmp_path, source, question, expected_partial):
    (tmp_path / "main.py").write_bytes(source.encode())
    access = AccessPolicy(tmp_path, {"model_scope": ["*.py"]}, confirmed=True)
    result = select_context(access, None, question, check_text=lambda _text: None)
    assert result["coverage"]["selected_files"] == 1
    assert result["coverage"]["partial"] is expected_partial
