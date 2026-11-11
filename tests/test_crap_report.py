import json

import pytest

from codesentry.access import AccessPolicy
from codesentry.cli.main import main
from codesentry.review.crap import scan_crap


BRANCHY = "def decide(x, y):\n    if x and y:\n        return 1\n    if x:\n        return 2\n    return 3\n"


def report_file(root, files, *, branch=False):
    (root / "coverage.json").write_text(json.dumps({
        "meta": {"format": 3, "branch_coverage": branch}, "files": files,
    }), encoding="utf-8")


def region(*, start=1, executed=(), missing=(), branches=None):
    summary = {"covered_lines": len(executed), "num_statements": len(executed) + len(missing)}
    if branches is not None:
        summary.update(covered_branches=branches[0], num_branches=branches[1])
    return {"start_line": start, "executed_lines": list(executed), "missing_lines": list(missing), "summary": summary}


def test_cli_ranks_zero_partial_full_and_unmeasured_coverage(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    for name in ("zero", "partial", "full", "unknown"):
        (src / f"{name}.py").write_text(BRANCHY, encoding="utf-8")
    report_file(tmp_path, {
        r"src\zero.py": {"functions": {"decide": region(missing=(2, 3, 4, 5, 6), branches=(0, 4))}},
        "src/partial.py": {"functions": {"decide": region(executed=(2, 3, 4, 5, 6), branches=(2, 4))}},
        "src/full.py": {"functions": {"decide": region(executed=(2, 3, 4, 5, 6), branches=(4, 4))}},
    }, branch=True)
    assert main(["crap", str(tmp_path), "--confirm-access", "--coverage-json", "coverage.json", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    rows = report["functions"]
    assert [row["file"] for row in rows] == [f"src/{name}.py" for name in ("zero", "partial", "full", "unknown")]
    assert [row["crap"] for row in rows] == [20, 6, 4, None]
    assert [row["at_or_above_reference"] for row in rows] == [True, False, False, None]
    assert rows[1]["coverage"] == {"basis": "branches", "covered": 2, "total": 4, "ratio": 0.5}
    assert report["gate_status"] == "not_evaluated"
    assert report["summary"] == {"python_files": 4, "functions": 4, "scored": 3, "unscored": 1,
                                 "at_or_above_reference": 1}


def test_nested_functions_and_methods_use_their_own_scope_and_statement_counts(tmp_path):
    (tmp_path / "module.py").write_text(
        "class Group:\n"
        "    def outer(self, x):\n"
        "        def inner(value):\n"
        "            return 1 if value else 2\n"
        "        return inner(x)\n", encoding="utf-8")
    report_file(tmp_path, {"module.py": {"functions": {
        "Group.outer": region(start=2, executed=(3, 5), branches=(0, 0)),
        "Group.outer.inner": region(start=3, missing=(4,), branches=(0, 0)),
    }}}, branch=True)
    report = scan_crap(AccessPolicy(tmp_path, confirmed=True), coverage_path="coverage.json")
    rows = {row["function"]: row for row in report["functions"]}
    assert rows["Group.outer"]["complexity"] == rows["Group.outer"]["crap"] == 1
    assert rows["Group.outer.inner"]["complexity"] == 2
    assert rows["Group.outer.inner"]["crap"] == 6
    assert rows["Group.outer.inner"]["coverage"]["basis"] == "statements"


@pytest.mark.parametrize("entry,reason", [
    (region(start=2, executed=(3,)), "location_mismatch"),
    (region(executed=(60,)), "invalid_region_lines"),
    (region(), "no_measurable_coverage"),
    ({"summary": {}}, "missing_start_line"),
])
def test_unmatched_or_unusable_coverage_does_not_become_zero(tmp_path, entry, reason):
    (tmp_path / "module.py").write_text(BRANCHY, encoding="utf-8")
    report_file(tmp_path, {"module.py": {"functions": {"decide": entry}}})
    result = scan_crap(AccessPolicy(tmp_path, confirmed=True), coverage_path="coverage.json")
    row = result["functions"][0]
    assert row["coverage_status"] == reason
    assert row["crap"] is row["coverage"] is row["at_or_above_reference"] is None


def test_cli_preserves_gitignore_confirmation_and_complexity_only(tmp_path, capsys):
    (tmp_path / ".gitignore").write_text("ignored.py\ncoverage.json\n", encoding="utf-8")
    for name in ("allowed", "ignored", "private"):
        (tmp_path / f"{name}.py").write_text(BRANCHY, encoding="utf-8")
    report_file(tmp_path, {})
    args = ["crap", str(tmp_path), "--json", "--exclude", "private.py"]
    assert main(args) == 2
    assert "请先" in capsys.readouterr().err
    assert main(args + ["--confirm-access", "--coverage-json", "coverage.json"]) == 2
    assert not capsys.readouterr().out
    assert main(args + ["--confirm-access"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert set(result["source_sha256"]) == {"allowed.py"}
    assert result["functions"][0]["complexity"] == 4
    assert result["functions"][0]["coverage_status"] == "coverage_not_provided"


def test_coverage_of_one_redefinition_is_not_attributed_to_another(tmp_path):
    (tmp_path / "module.py").write_text("def same(): return 1\n\ndef same(): return 2\n", encoding="utf-8")
    report_file(tmp_path, {"module.py": {"functions": {"same": region(start=3, executed=(3,))}}})
    result = scan_crap(AccessPolicy(tmp_path, confirmed=True), coverage_path="coverage.json")
    assert [(row["line"], row["crap"], row["coverage_status"]) for row in result["functions"]] == [
        (1, None, "ambiguous_function_name"), (3, None, "ambiguous_function_name"),
    ]
