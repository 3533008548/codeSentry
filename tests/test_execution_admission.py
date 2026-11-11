"""Fixed development task scope cannot be widened by output JSON or drift."""
from dataclasses import replace
from pathlib import Path

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.execution.admission import BuiltinTaskPolicy, admit_execution
from codesentry.execution.runner import DockerRunner, ResourceLimits
from codesentry.execution.snapshot import prepare_snapshot
from codesentry.execution.verification import TestCase, TestPlan


IMAGE_REF = "docker.io/library/python@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64


@pytest.fixture
def task(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_text("print('observed')\n", encoding="utf-8")
    snapshot = prepare_snapshot(AccessPolicy(root), tmp_path / "snapshot", paths=["main.py"],
        max_files=1, max_bytes=4096, max_file_bytes=4096)
    limits = ResourceLimits(128*1024*1024, 1, 32, 10, 4096, 8*1024*1024)
    runner = DockerRunner(tmp_path / "docker", image_ref=IMAGE_REF, expected_image_id=IMAGE_ID, limits=limits)
    plan = TestPlan("fixed", (TestCase("case", ("python3", "main.py"), "c" * 64),))
    policy = BuiltinTaskPolicy("fixed-policy", plan.digest, (snapshot.digest,), IMAGE_REF, IMAGE_ID, limits)
    yield policy, runner, snapshot, plan
    snapshot.close()


def test_admission_binds_fixed_task_and_has_no_general_project_grant(task):
    policy, runner, snapshot, plan = task
    receipt = admit_execution(policy, runner, snapshot, plan)
    receipt.check()
    report = receipt.to_dict()
    assert report["source_snapshot_digest"] == snapshot.digest
    assert report["plan_digest"] == plan.digest
    assert report["arbitrary_project_execution_authorized"] is False
    assert "expected_output_sha256" not in str(report)


@pytest.mark.parametrize("field,value", [
    ("plan_digest", "d" * 64), ("snapshot_digests", ("d" * 64,)),
    ("image_reference", "docker.io/library/python@sha256:" + "d" * 64),
    ("image_id", "sha256:" + "d" * 64),
    ("limits", ResourceLimits(128*1024*1024, 2, 32, 10, 4096, 8*1024*1024)),
])
def test_scope_mismatch_is_rejected_before_any_execution(task, field, value):
    policy, runner, snapshot, plan = task
    with pytest.raises(AccessDenied):
        admit_execution(replace(policy, **{field: value}), runner, snapshot, plan)


def test_serialized_reports_cannot_restore_execution_scope(task):
    policy, runner, snapshot, plan = task
    with pytest.raises(ValueError):
        admit_execution({"approved": True, "plan_digest": plan.digest}, runner, snapshot, plan)


@pytest.mark.parametrize("attribute,new_value", [
    ("image_ref", "docker.io/library/python@sha256:" + "d" * 64),
    ("endpoint", "tcp://elsewhere:2375"), ("executable", Path("other-docker")),
    ("limits", ResourceLimits(128*1024*1024, 2, 32, 10, 4096, 8*1024*1024)),
])
def test_post_admission_runner_drift_is_rejected(task, attribute, new_value):
    policy, runner, snapshot, plan = task
    receipt = admit_execution(policy, runner, snapshot, plan)
    setattr(runner, attribute, new_value)
    with pytest.raises(AccessDenied):
        receipt.check()


def test_input_or_current_permission_drift_cannot_reuse_receipt(task):
    policy, runner, snapshot, plan = task
    receipt = admit_execution(policy, runner, snapshot, plan)
    (snapshot._access.root / ".gitignore").write_text("main.py\n", encoding="utf-8")
    with pytest.raises(AccessDenied):
        receipt.check()


@pytest.mark.parametrize("field,value", [
    ("snapshot_digests", ()), ("snapshot_digests", ("a" * 64, "a" * 64)),
    ("purpose", "arbitrary-project-execution"), ("image_reference", "python:latest"),
])
def test_policy_does_not_accept_empty_or_unpinned_scope(task, field, value):
    policy, *_ = task
    with pytest.raises(ValueError):
        replace(policy, **{field: value})
