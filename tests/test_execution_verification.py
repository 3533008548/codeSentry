"""Host-computed behavior checks do not consume target-reported test counts."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from codesentry.access import AccessPolicy
from codesentry.execution.runner import DockerRunner, ExecutionResult, ResourceLimits
from codesentry.execution.snapshot import prepare_snapshot
from codesentry.execution.verification import TestCase, TestPlan, load_trusted_plan, verify_plan


IMAGE = "sha256:" + "a" * 64
OUTPUT = hashlib.sha256(b"trusted expected raw output\n").hexdigest()
OTHER_OUTPUT = hashlib.sha256(b'{"passed": true, "tests": 1000000}\n').hexdigest()
LIMITS = ResourceLimits(64 * 1024 * 1024, 0.5, 32, 2, 1024, 16 * 1024 * 1024)


class FakeRunner(DockerRunner):
    def __init__(self, executable):
        super().__init__(executable, image_ref=IMAGE, expected_image_id=IMAGE, limits=LIMITS)
        self.calls, self.overrides, self.after_run = [], {}, None
        self.return_dict, self.raise_error = False, False

    def run(self, task, snapshot_dir, snapshot_digest, *, snapshot_check=None, cancel_event=None):
        assert task.kind == "test" and task.expected_output_sha256 is None
        assert snapshot_check is not None
        snapshot_check()
        self.calls.append(task)
        if self.raise_error:
            raise RuntimeError("trusted tool failed; target was not verified")
        result = ExecutionResult("not_verified", True, task.task_id, "test", snapshot_digest, IMAGE, IMAGE,
                                 "linux", "amd64", 0, 0, "[REDACTED]", OUTPUT, False, False, (), 0.1, asdict(LIMITS))
        result = replace(result, **self.overrides.get(task.task_id, {}))
        if self.after_run:
            self.after_run()
        snapshot_check()
        return result.to_dict() if self.return_dict else result


@pytest.fixture
def context(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    (root / "input.py").write_text("not executed by verification unit tests\n", encoding="utf-8")
    access = AccessPolicy(root, {}, confirmed=True)
    snapshot = prepare_snapshot(access, tmp_path / "export", paths=["input.py"],
                                max_files=1, max_bytes=1024, max_file_bytes=1024)
    runner = FakeRunner(tmp_path / "docker.exe")
    plan = TestPlan("trusted-plan", (TestCase("first", ("python3", "-I", "input.py", "first"), OUTPUT),
                                     TestCase("second", ("python3", "-I", "input.py", "second"), OUTPUT)))
    yield root, snapshot, runner, plan
    snapshot.close()


def test_all_required_checks_are_computed_on_host_and_raw_test_status_is_preserved(context):
    _, snapshot, runner, plan = context
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "passed" and result.evidence_valid and not result.cleanup_pending
    assert result.planned_cases == result.attempted_cases == result.executed_cases == result.completed_cases == 2
    assert result.passed_cases == 2 and result.failed_cases == result.incomplete_cases == result.not_run_cases == 0
    assert result.host_behavior_checks_planned == result.host_behavior_checks_evaluated == result.host_behavior_checks_passed == 4
    assert result.host_behavior_checks_failed == 0
    assert result.plan_digest == plan.digest and result.snapshot_digest == snapshot.digest
    assert result.policy_fingerprint == snapshot.policy_fingerprint and result.image_id == IMAGE
    assert len(runner.calls) == 2 and all(case.execution.status == "not_verified" for case in result.cases)
    assert all(case.execution.assertion_count == 0 for case in result.cases)
    assert result.to_dict()["cases"][0]["execution"]["output_sha256"] == OUTPUT


def test_self_reported_json_and_test_counts_cannot_make_a_case_pass(context):
    _, snapshot, runner, plan = context
    runner.overrides["first"] = {"logs": '{"passed":true,"tests":1000000}',
                                  "output_sha256": OTHER_OUTPUT, "assertion_count": 1000000}
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "failed" and result.completed_cases == 2 and result.failed_cases == 1
    assert result.host_behavior_checks_evaluated == 4 and result.host_behavior_checks_passed == 3
    assert result.host_behavior_checks_failed == 1
    assert result.cases[0].exit_zero is True and result.cases[0].output_digest_matches is False


def test_exit_zero_and_empty_output_do_not_prove_required_behavior(context):
    _, snapshot, runner, plan = context
    runner.overrides["first"] = {"logs": "", "output_sha256": hashlib.sha256(b"").hexdigest()}
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "failed" and result.failed_cases == 1


def test_hash_comparison_uses_raw_digest_instead_of_redacted_logs(context):
    _, snapshot, runner, plan = context
    runner.overrides["first"] = {"logs": "completely different after redaction", "output_sha256": OUTPUT}
    assert verify_plan(runner, snapshot, plan).status == "passed"


@pytest.mark.parametrize("status", ["timeout", "cancelled", "unavailable", "unsupported", "environment_error", "not_run", "passed"])
def test_raw_status_cannot_be_upgraded_to_verified(context, status):
    _, snapshot, runner, plan = context
    runner.overrides["first"] = {"status": status}
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "incomplete" and result.completed_cases == 0
    assert result.incomplete_cases == 1 and result.not_run_cases == 1
    assert result.host_behavior_checks_evaluated == 0


@pytest.mark.parametrize("overrides", [
    {"cleanup_pending": True}, {"log_truncated": True}, {"executed": False},
    {"output_sha256": None}, {"output_sha256": "not-a-digest"}, {"exit_code": None}, {"exit_code": True},
    {"status": "failed", "exit_code": 1, "output_sha256": None},
])
def test_incomplete_evidence_never_passes(context, overrides):
    _, snapshot, runner, plan = context
    runner.overrides["first"] = overrides
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "incomplete" and result.passed_cases <= 1
    if overrides.get("cleanup_pending"):
        assert result.cleanup_pending


@pytest.mark.parametrize("overrides", [
    {"task_id": "other-case"}, {"kind": "probe"}, {"snapshot_digest": "c" * 64},
    {"image_reference": "different"}, {"image_id": "sha256:" + "d" * 64},
    {"platform": "windows"}, {"architecture": None}, {"limits": asdict(LIMITS) | {"pids": True}},
])
def test_execution_identity_must_match_the_fixed_plan_and_policy(context, overrides):
    _, snapshot, runner, plan = context
    runner.overrides["first"] = overrides
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "incomplete" and not result.evidence_valid
    assert result.not_run_cases == 1 and result.host_behavior_checks_evaluated == 0


def test_architecture_cannot_change_between_cases(context):
    _, snapshot, runner, plan = context
    runner.overrides["second"] = {"architecture": "arm64"}
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "incomplete" and not result.evidence_valid


def test_deserialized_execution_reports_are_rejected(context):
    _, snapshot, runner, plan = context
    runner.return_dict = True
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "incomplete" and result.host_behavior_checks_evaluated == 0
    assert result.cases[0].execution is None


def test_trusted_tool_error_is_incomplete_and_not_a_target_bug(context):
    _, snapshot, runner, plan = context
    runner.raise_error = True
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "incomplete" and result.failed_cases == 0 and result.executed_cases == 0
    assert result.not_run_cases == 1 and not result.evidence_valid


def test_cancelled_plan_leaves_required_cases_explicitly_unrun(context):
    _, snapshot, runner, plan = context
    event = threading.Event()
    event.set()
    result = verify_plan(runner, snapshot, plan, cancel_event=event)
    assert result.status == "incomplete" and result.not_run_cases == 2 and not runner.calls


def test_admission_guard_runs_before_during_after_each_case_and_finally(context):
    _, snapshot, runner, plan = context
    checks = []
    result = verify_plan(runner, snapshot, plan, admission_check=lambda: checks.append(len(runner.calls)))
    assert result.status == "passed" and checks.count(0) >= 3 and checks.count(1) >= 3 and checks.count(2) >= 3


def test_revoked_admission_stops_and_rechecks_finally(context):
    _, snapshot, runner, plan = context
    checks = []
    def denied():
        checks.append(True)
        if runner.calls:
            raise PermissionError("revoked task receipt")
    result = verify_plan(runner, snapshot, plan, admission_check=denied)
    assert result.status == "incomplete" and not result.evidence_valid and len(runner.calls) == 1
    assert result.not_run_cases == 1 and len(checks) >= 4


def test_snapshot_or_runner_drift_cannot_publish_pass(context):
    _, snapshot, runner, plan = context
    runner.after_run = lambda: setattr(runner, "image_ref", "sha256:" + "f" * 64)
    result = verify_plan(runner, snapshot, plan)
    assert result.status == "incomplete" and not result.evidence_valid and result.not_run_cases == 1


def test_final_guard_failure_after_completed_cases_still_prevents_pass(context):
    _, snapshot, runner, plan = context
    calls = []
    def guard():
        calls.append(len(runner.calls))
        # The fourth check with both cases returned is the final publication.
        if calls.count(2) == 4:
            raise PermissionError("final admission check revoked")
    result = verify_plan(runner, snapshot, plan, admission_check=guard)
    assert result.status == "incomplete" and not result.evidence_valid


def write_plan(path, plan):
    path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
    return path


def test_external_operator_plan_is_strictly_loaded_and_digest_covers_all_case_inputs(context, tmp_path):
    root, _, _, plan = context
    path = write_plan(tmp_path / "trusted.json", plan)
    loaded = load_trusted_plan(path, source_root=root)
    assert loaded.digest == plan.digest
    changes = [replace(plan.cases[0], argv=("python3", "different.py")),
               replace(plan.cases[0], cwd="subdirectory"),
               replace(plan.cases[0], expected_output_sha256="c" * 64)]
    assert all(TestPlan(plan.plan_id, (case, plan.cases[1])).digest != plan.digest for case in changes)
    assert replace(plan, plan_id="other-plan").digest != plan.digest


def test_project_plan_is_rejected_before_reading_its_bytes(context, monkeypatch):
    root, _, _, plan = context
    path = write_plan(root / "plan.json", plan)
    original = Path.open
    def deny(path_to_open, *args, **kwargs):
        if path_to_open == path:
            pytest.fail("project attempted to authorize its own checks")
        return original(path_to_open, *args, **kwargs)
    monkeypatch.setattr(Path, "open", deny)
    with pytest.raises(ValueError, match="project file"):
        load_trusted_plan(path, source_root=root)


@pytest.mark.parametrize("where", ["top", "case"])
def test_duplicate_json_keys_are_rejected(context, tmp_path, where):
    root, _, _, plan = context
    text = json.dumps(plan.to_dict())
    text = text.replace('"plan_id":', '"plan_id":"duplicate", "plan_id":', 1) if where == "top" else text.replace(
        '"cwd":', '"cwd":"different", "cwd":', 1)
    path = tmp_path / "duplicate.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_trusted_plan(path, source_root=root)


@pytest.mark.parametrize("location", ["top", "case"])
def test_extra_fields_cannot_grant_trust_or_add_test_counts(context, tmp_path, location):
    root, _, _, plan = context
    data = plan.to_dict()
    (data if location == "top" else data["cases"][0])["approved"] = True
    path = tmp_path / "extra.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        load_trusted_plan(path, source_root=root)


def test_loaded_plan_raw_hash_or_path_identity_drift_is_rejected(context, tmp_path):
    root, snapshot, runner, plan = context
    path = write_plan(tmp_path / "trusted.json", plan)
    loaded = load_trusted_plan(path, source_root=root)
    path.write_text(json.dumps(plan.to_dict()) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        loaded.check()
    result = verify_plan(runner, snapshot, loaded)
    assert result.status == "incomplete" and result.not_run_cases == 2 and not runner.calls


def test_plan_copied_into_valid_snapshot_cannot_supply_candidate_visible_answers(context, tmp_path):
    root, original_snapshot, runner, plan = context
    write_plan(root / "plan.json", plan)
    snapshot = prepare_snapshot(original_snapshot._access, tmp_path / "answer-containing-export",
                                paths=["input.py", "plan.json"], max_files=2, max_bytes=8192, max_file_bytes=8192)
    try:
        loaded = load_trusted_plan(snapshot.directory / "plan.json", source_root=root)
        snapshot.check()  # The copy itself is valid; answer placement is the refusal.
        result = verify_plan(runner, snapshot, loaded)
        assert result.status == "incomplete" and result.not_run_cases == 2 and not runner.calls
    finally:
        snapshot.close()


def test_incorrect_load_time_source_root_cannot_authorize_actual_project_plan(context, tmp_path):
    root, snapshot, runner, plan = context
    path = write_plan(root / "plan.json", plan)
    loaded = load_trusted_plan(path, source_root=tmp_path / "unrelated-root")
    result = verify_plan(runner, snapshot, loaded)
    assert result.status == "incomplete" and not result.evidence_valid and not runner.calls


def test_redirected_plan_or_parent_is_rejected(context, tmp_path, monkeypatch):
    from codesentry.execution import verification
    root, _, _, plan = context
    folder = tmp_path / "redirected"
    folder.mkdir()
    path = write_plan(folder / "plan.json", plan)
    monkeypatch.setattr(verification, "is_link", lambda item: item == folder)
    with pytest.raises(ValueError, match="redirected"):
        load_trusted_plan(path, source_root=root)


def test_handle_ctime_difference_does_not_misidentify_a_stable_plan(context, tmp_path, monkeypatch):
    from codesentry.execution import verification
    root, _, _, plan = context
    path = write_plan(tmp_path / "handle-times.json", plan)
    original = verification.os.fstat
    def another_ctime(descriptor):
        current = original(descriptor)
        fields = {name: getattr(current, name) for name in
                  ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink", "st_mode")}
        return SimpleNamespace(**fields, st_ctime_ns=current.st_ctime_ns + 1)
    monkeypatch.setattr(verification.os, "fstat", another_ctime)
    assert load_trusted_plan(path, source_root=root).digest == plan.digest


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink", "st_mode"])
def test_handle_identity_size_time_alias_and_type_still_must_match(context, tmp_path, monkeypatch, field):
    from codesentry.execution import verification
    root, _, _, plan = context
    path = write_plan(tmp_path / "different-handle.json", plan)
    original = verification.os.fstat
    def mismatch(descriptor):
        current = original(descriptor)
        fields = {name: getattr(current, name) for name in
                  ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink", "st_mode")}
        fields[field] += 1
        return SimpleNamespace(**fields)
    monkeypatch.setattr(verification.os, "fstat", mismatch)
    with pytest.raises(ValueError, match="open file identity"):
        load_trusted_plan(path, source_root=root)


@pytest.mark.parametrize("cases", [(), (TestCase("same", ("true",), OUTPUT), TestCase("same", ("false",), OUTPUT))])
def test_empty_or_duplicate_required_cases_are_invalid(cases):
    with pytest.raises(ValueError):
        TestPlan("plan", cases)


def test_serialized_inputs_cannot_call_the_trusted_api(context):
    _, snapshot, runner, plan = context
    with pytest.raises(TypeError):
        verify_plan(runner, snapshot, plan.to_dict())
