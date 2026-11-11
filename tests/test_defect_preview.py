"""The candidate rule proves syntax only, with the normal access/current guards."""
import hashlib
import json
from pathlib import Path

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.core.finding import Finding
from codesentry.review import defects
from codesentry.review.scan import PreviewLimits


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    root = tmp_path / "project"
    root.mkdir()
    return root


def write(root, text, name="main.py"):
    (root / name).write_bytes(text.encode())


def scan(root, **kwargs):
    return defects.scan_defect_preview(AccessPolicy(root), **kwargs)


@pytest.mark.parametrize("source,arity", [
    ("assert (condition, 'message')\n", 2),
    ("assert (False,)\n", 1),
    ("assert ((False, 'inner'),)\n", 1),
    ("assert (False, 'inner'), 'outer'\n", 2),
    ("assert (\n    condition,\n    'message',\n)\n", 2),
    ("if False:\n    assert (False, 'unreachable')\n", 2),
    ("assert (effect(), 'message')\n", 2),
    ("assert (1 / 0, 'construction can fail')\n", 2),
])
def test_nonempty_tuple_is_only_a_syntax_candidate(project, source, arity):
    write(project, source)
    result = scan(project)
    assert result["mode"] == "defect_preview" and result["review_status"] == "report_only"
    assert result["gate_status"] == "not_evaluated"
    assert result["summary"] == {"candidate_findings": 1, "confirmed_behavior_bug_findings": 0, "blocking_findings": 0}
    row = result["findings"][0]
    finding = row["finding"]
    assert row["classification"] == "behavior_bug_candidate"
    assert not row["can_block"] and not row["confirmed_behavior_bug"]
    assert finding["source"] == "deterministic" and finding["verified"]
    assert finding["severity"] == "medium" and finding["confidence"] == 1.0
    assert finding["facts"] == {
        "classification": "behavior_bug_candidate", "tuple_arity": arity, "no_starred": True,
        "always_truthy_after_successful_construction": True, "assertions_enabled_requirement": True,
        "unreachable_or_side_effects_not_assessed": True, "intent_not_confirmed": True,
        "confirmed_behavior_bug": False,
    }
    assert not Finding.model_validate(finding).can_block()
    assert not result["rules"][0]["approved_for_blocking"] and not result["formal_acceptance"]["passed"]
    assert result["source_sha256"]["main.py"] == hashlib.sha256(source.encode()).hexdigest()
    assert "side effects" in " ".join(result["limitations"])


@pytest.mark.parametrize("source", [
    "assert ()\n", "assert (*items,)\n", "assert (False, *items)\n",
    "assert ((*items,),)\n", "assert condition, 'message'\n", "assert (condition), 'message'\n",
    "assert tuple(items)\n", "assert [False]\n", "text = \"assert (False, 'message')\"\n",
    "# assert (False, 'message')\npass\n",
])
def test_outside_narrow_rule_is_not_a_confirmed_clean_bug_free_result(project, source):
    write(project, source)
    result = scan(project)
    assert not result["findings"] and result["review_status"] == "report_only"
    assert result["gate_status"] == "not_evaluated" and not result["formal_acceptance"]["passed"]


def test_scopes_multiline_and_duplicate_occurrences_are_separate(project):
    write(project, "assert (False,)\nassert (False,)\nclass C:\n    assert (False,)\n    def m(self):\n        assert (\n            condition,\n            'message',\n        )\n        def inner():\n            assert (False,)\n")
    findings = [row["finding"] for row in scan(project)["findings"]]
    assert [(f["symbol"], f["line"], f["end_line"], f["occurrence"]) for f in findings] == [
        ("main.py::<module>", 1, 1, 1), ("main.py::<module>", 2, 2, 2),
        ("main.py::C", 4, 4, 1), ("main.py::C.m", 6, 9, 1),
        ("main.py::C.m.<locals>.inner", 11, 11, 1),
    ]
    assert len({f["identity_digest"] for f in findings}) == 5


def test_target_is_not_executed_and_excluded_source_is_never_opened(project, monkeypatch):
    marker = project / "executed"
    write(project, "from pathlib import Path\nPath('executed').touch()\nassert (side_effect(), 'message')\n")
    write(project, "private sentinel", "private.py")
    original = Path.open
    def guarded(path, *args, **kwargs):
        if path == project / "private.py":
            pytest.fail("excluded source opened")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded)
    result = defects.scan_defect_preview(AccessPolicy(project, {"exclude": ["private.py"]}))
    assert not marker.exists()
    assert result["coverage"]["excluded_python"] == 1
    assert result["coverage"]["permissions_limited"] and len(result["findings"]) == 1


def test_syntax_and_failed_input_keep_remaining_scope_explicit(project):
    write(project, "assert (False,)\n", "a.py")
    write(project, "assert (", "b.py")
    result = scan(project)
    assert result["review_status"] == "incomplete" and len(result["findings"]) == 1
    assert result["coverage"]["analyzed_python"] == 1 and not result["coverage"]["within_scope_complete"]
    assert result["issues"] == [{"file": "b.py", "status": "syntax_error", "line": 1}]
    assert "b.py" not in result["source_sha256"]


def test_failed_load_reservation_and_file_budget_are_not_bypassed(project):
    (project / "a.py").write_bytes(b"\xff")
    write(project, "assert (False,)\n", "b.py")
    result = scan(project, limits=PreviewLimits(max_total_bytes=8, max_file_bytes=64))
    assert result["coverage"]["bytes_accounted_for_budget"] == 8
    assert result["coverage"]["attempted_python"] == 1 and not result["findings"]
    assert {issue["status"] for issue in result["issues"]} == {"syntax_error", "budget_exhausted"}
    result = scan(project, limits=PreviewLimits(max_files=1))
    assert result["coverage"]["attempted_python"] == 1 and result["review_status"] == "incomplete"


@pytest.mark.parametrize("empty", [True, False])
def test_empty_and_non_python_are_never_passes(project, empty):
    if not empty:
        write(project, "export const x = 1;", "main.ts")
    result = scan(project)
    assert result["review_status"] == "not_applicable" and not result["coverage"]["within_scope_complete"]
    assert not result["coverage"]["whole_repository_evaluated"]


@pytest.mark.parametrize("change", ["source", "inventory", "permission"])
def test_current_recheck_drops_stale_facts_or_entire_revoked_result(project, monkeypatch, change):
    write(project, "assert (False,)\n")
    permitted = True
    def guard():
        if not permitted:
            raise AccessDenied("revoked")
    access = AccessPolicy(project, read_guard=guard)
    original = defects.VerificationContext.evaluate
    def evaluate(context):
        nonlocal permitted
        findings = original(context)
        if change == "source":
            write(project, "assert condition, 'message'\n")
        elif change == "inventory":
            write(project, "not source", "new.txt")
        else:
            permitted = False
        return findings
    monkeypatch.setattr(defects.VerificationContext, "evaluate", evaluate)
    if change == "permission":
        with pytest.raises(AccessDenied):
            defects.scan_defect_preview(access)
        return
    result = defects.scan_defect_preview(access)
    assert result["review_status"] == "incomplete"
    if change == "source":
        assert not result["findings"] and not result["source_sha256"]
        assert result["coverage"]["analyzed_python"] == 0
    else:
        assert any(i["status"] == "source_inventory_changed" for i in result["issues"])


def test_unconfirmed_or_untyped_arguments_cannot_read(project):
    write(project, "assert (False,)\n")
    with pytest.raises(AccessDenied):
        defects.scan_defect_preview(AccessPolicy(project, confirmed=False))
    with pytest.raises(TypeError):
        defects.scan_defect_preview(AccessPolicy(project), limits={"max_files": 1})


def test_inventory_added_during_final_context_recheck_is_incomplete(project, monkeypatch):
    write(project, "assert (False,)\n")
    access = AccessPolicy(project)
    original_walk = access.walk
    original_check = defects.VerificationContext.check_current
    walks = 0
    changed = False
    def walk(*args, **kwargs):
        nonlocal walks
        walks += 1
        return original_walk(*args, **kwargs)
    def check_current(context):
        nonlocal changed
        original_check(context)
        if walks >= 2 and not changed:
            changed = True
            write(project, "assert (False,)\n", "late.py")
    monkeypatch.setattr(access, "walk", walk)
    monkeypatch.setattr(defects.VerificationContext, "check_current", check_current)
    result = defects.scan_defect_preview(access)
    assert changed
    assert result["review_status"] == "incomplete"
    assert not result["coverage"]["within_scope_complete"]
    assert {issue["status"] for issue in result["issues"]} == {"source_inventory_changed"}
    assert "late.py" not in result["source_sha256"]


def test_policy_hash_is_recomputable_and_has_no_debt_threshold():
    policy = defects.defect_preview_policy()
    assert "max_function_lines" not in policy and policy["rule_id"] == "python.assert_tuple"
    assert json.loads(json.dumps(policy)) == policy


def test_frozen_synthetic_contract_matches_locations_and_facts_without_bug_quality_claim(tmp_path):
    from evals.assert_tuple_contract import register_contract, run_contract
    registration, output = tmp_path / "registration.json", tmp_path / "report.json"
    binding = register_contract(registration)
    report = run_contract(registration, output)
    assert len(binding["case_ids"]) == 25
    assert report["summary"]["case_count"] == report["summary"]["consistent_cases"] == 25
    assert report["summary"]["contract_hits"] == report["summary"]["expected_syntax_candidates"]
    assert report["summary"]["contract_missing"] == report["summary"]["contract_extra"] == 0
    assert not report["bug_gold"] and not report["formal_acceptance"]["passed"]
    assert report["registration_sha256"] == hashlib.sha256(registration.read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        register_contract(registration)
    with pytest.raises(FileExistsError):
        run_contract(registration, output)


@pytest.mark.parametrize("mutation", ["denominator", "implementation", "scope"])
def test_registered_contract_cannot_change_denominator_implementation_or_scope(tmp_path, monkeypatch, mutation):
    from evals import assert_tuple_contract as contract
    registration, output = tmp_path / "registration.json", tmp_path / "report.json"
    binding = contract.register_contract(registration)
    if mutation == "denominator":
        binding["expected_syntax_candidates"] = 0
    elif mutation == "implementation":
        binding["implementation_sha256"]["codesentry/review/defects.py"] = "0" * 64
    else:
        binding["case_ids"] = binding["case_ids"][:1]
    registration.write_text(json.dumps(binding), encoding="utf-8")
    def forbidden(*args, **kwargs):
        pytest.fail("prediction ran after changed registration")
    monkeypatch.setattr(contract, "scan_defect_preview", forbidden)
    with pytest.raises(ValueError, match="registered contract"):
        contract.run_contract(registration, output)
    assert not output.exists()


def test_frozen_v1_source_and_registration_are_preserved_but_cannot_run_as_v2(tmp_path, monkeypatch):
    from evals import assert_tuple_contract as contract
    root = Path(__file__).resolve().parents[1]
    frozen = root / "evals/fixtures/assert_tuple_before_inventory_v1/defects.py"
    assert hashlib.sha256(frozen.read_bytes()).hexdigest() == "d0d0608c78f3890a0eb88e6e618b2c8254580f538ff84facb35d11013ddaa601"
    registration = root / "evals/reports/p3_assert_tuple_contract_registration_20261028_v1.json"
    assert hashlib.sha256(registration.read_bytes()).hexdigest() == "e16c6535fc453aa1aab11a829acb0a1f43d88931360a01f735fe58833192b683"
    def forbidden(*args, **kwargs):
        pytest.fail("v1 registration reached v2 predictions")
    monkeypatch.setattr(contract, "scan_defect_preview", forbidden)
    with pytest.raises(ValueError, match="registered contract"):
        contract.run_contract(registration, tmp_path / "report.json")


@pytest.mark.parametrize("mutation", ["duplicate", "missing"])
def test_synthetic_contract_counts_duplicate_and_missing_predictions_without_extra_credit(tmp_path, monkeypatch, mutation):
    from evals import assert_tuple_contract as contract
    registration = tmp_path / "registration.json"
    binding = contract.register_contract(registration)
    original = contract.scan_defect_preview
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        result["findings"] = result["findings"] * 2 if mutation == "duplicate" else []
        return result
    monkeypatch.setattr(contract, "scan_defect_preview", changed)
    report = contract.run_contract(registration, tmp_path / "report.json")
    expected = binding["expected_syntax_candidates"]
    if mutation == "duplicate":
        assert report["summary"]["contract_hits"] == expected
        assert report["summary"]["contract_extra"] == expected
    else:
        assert report["summary"]["contract_hits"] == 0
        assert report["summary"]["contract_missing"] == expected
    assert report["summary"]["consistent_cases"] < 25
