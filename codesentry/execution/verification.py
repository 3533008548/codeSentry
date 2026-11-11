"""Trusted host checks for fixed black-box tasks, separate from raw execution.

The host checks exit zero and an expected digest of combined raw output. It does
not trust target test counts, parse JUnit, establish that Python assert ran, or
issue Finding/gate credentials. Trusted Python callers remain inside one process
boundary; this module does not provide independent OS identities.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable

from codesentry.access.policy import is_link
from codesentry.execution.runner import DockerRunner, ExecutionResult, ExecutionTask
from codesentry.execution.snapshot import SourceSnapshot


SCHEMA_VERSION = 1
MAX_PLAN_BYTES = 256 * 1024
MAX_CASES = 32
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class TestCase:
    __test__ = False
    case_id: str
    argv: tuple[str, ...]
    expected_output_sha256: str
    cwd: str = "."

    def __post_init__(self):
        ExecutionTask(self.case_id, "test", self.argv, self.cwd,
                      expected_output_sha256=self.expected_output_sha256)
        if not isinstance(self.expected_output_sha256, str) or not _SHA.fullmatch(self.expected_output_sha256):
            raise ValueError("each required case needs a trusted expected output digest")

    def to_dict(self):
        return {"case_id": self.case_id, "argv": list(self.argv), "cwd": self.cwd,
                "expected_output_sha256": self.expected_output_sha256}


@dataclass(frozen=True)
class _PlanSource:
    path: Path
    source_root: Path
    identity: tuple
    raw_sha256: str

    def check(self):
        data, identity = _read_external_plan(self.path, self.source_root)
        if identity != self.identity or hashlib.sha256(data).hexdigest() != self.raw_sha256:
            raise ValueError("trusted plan changed after loading")


@dataclass(frozen=True)
class TestPlan:
    __test__ = False
    plan_id: str
    cases: tuple[TestCase, ...]
    schema_version: int = SCHEMA_VERSION
    _source: _PlanSource | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if (type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION
                or not isinstance(self.plan_id, str)
                or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", self.plan_id) is None
                or not isinstance(self.cases, tuple) or not 0 < len(self.cases) <= MAX_CASES
                or any(type(case) is not TestCase for case in self.cases)
                or len({case.case_id for case in self.cases}) != len(self.cases)):
            raise ValueError("invalid, empty, or duplicate trusted behavior plan")

    def to_dict(self):
        return {"schema_version": self.schema_version, "plan_id": self.plan_id,
                "cases": [case.to_dict() for case in self.cases]}

    @property
    def digest(self):
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()

    def check(self):
        if self._source is not None:
            self._source.check()


def _file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def _read_external_plan(path: Path, source_root: Path):
    if path.is_relative_to(source_root):
        raise ValueError("a project file cannot authorize its own behavior checks")
    if any(is_link(component) for component in (path, *path.parents)):
        raise ValueError("trusted plan path is redirected")
    if path.resolve().is_relative_to(source_root):
        raise ValueError("trusted plan resolves into the target project")
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_size > MAX_PLAN_BYTES or metadata.st_ino == 0):
        raise ValueError("trusted plan must be a bounded regular file without aliases")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        # Windows lstat/fstat can report different ctime meanings for the same
        # file. Keep the lstat ctime pin before/after reading, while comparing
        # handle identity, size, mtime, type, and alias count directly.
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink", "st_mode")
        if any(getattr(opened, key) != getattr(metadata, key) for key in fields):
            raise ValueError("trusted plan open file identity changed")
        data = stream.read(MAX_PLAN_BYTES + 1)
    current = path.lstat()
    if (len(data) > MAX_PLAN_BYTES or _file_identity(metadata) != _file_identity(current)
            or current.st_nlink != 1 or is_link(path)):
        raise ValueError("trusted plan changed while being read")
    return data, _file_identity(current)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in trusted behavior plan")
        result[key] = value
    return result


def load_trusted_plan(path: Path, *, source_root: Path) -> TestPlan:
    """Load an operator-selected external plan, then pin its bytes and identity.

    Calling this function is an explicit trusted-operator decision, not automatic
    approval based on a JSON field, repository configuration, or filename.
    """
    selected = Path(path).expanduser().absolute()
    root = Path(source_root).expanduser().resolve()
    data, identity = _read_external_plan(selected, root)
    raw = json.loads(data, object_pairs_hook=_unique_keys)
    if (not isinstance(raw, dict) or set(raw) != {"schema_version", "plan_id", "cases"}
            or not isinstance(raw["cases"], list)):
        raise ValueError("unexpected trusted plan schema")
    cases = []
    for case in raw["cases"]:
        if (not isinstance(case, dict) or set(case) != {"case_id", "argv", "cwd", "expected_output_sha256"}
                or not isinstance(case["argv"], list)):
            raise ValueError("unexpected behavior case schema")
        cases.append(TestCase(case["case_id"], tuple(case["argv"]), case["expected_output_sha256"], case["cwd"]))
    plan = TestPlan(raw["plan_id"], tuple(cases), raw["schema_version"],
                    _PlanSource(selected, root, identity, hashlib.sha256(data).hexdigest()))
    plan.check()
    return plan


@dataclass(frozen=True)
class CaseVerification:
    case_id: str
    status: str
    exit_zero: bool | None
    output_digest_matches: bool | None
    expected_output_sha256: str
    actual_output_sha256: str | None
    execution: ExecutionResult | None
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationResult:
    schema_version: int
    status: str
    plan_id: str
    plan_digest: str
    snapshot_digest: str
    policy_fingerprint: str
    image_reference: str
    image_id: str
    limits: dict
    planned_cases: int
    attempted_cases: int
    executed_cases: int
    completed_cases: int
    passed_cases: int
    failed_cases: int
    incomplete_cases: int
    not_run_cases: int
    host_behavior_checks_planned: int
    host_behavior_checks_evaluated: int
    host_behavior_checks_passed: int
    host_behavior_checks_failed: int
    cleanup_pending: bool
    evidence_valid: bool
    issues: tuple[str, ...]
    cases: tuple[CaseVerification, ...]

    def to_dict(self):
        return asdict(self)


def verify_plan(runner: DockerRunner, snapshot: SourceSnapshot, plan: TestPlan, *,
                cancel_event=None, admission_check: Callable[[], None] | None = None) -> VerificationResult:
    """Run each required case separately; only host-computed checks can pass.

    The optional admission hook is called with every snapshot/plan guard. This
    lower-level API presumes a trusted caller; it does not grant task permission.
    """
    if not isinstance(runner, DockerRunner) or not isinstance(snapshot, SourceSnapshot) or type(plan) is not TestPlan:
        raise TypeError("typed trusted runner, snapshot, and plan objects are required")
    pinned = (Path(snapshot.directory), snapshot.digest, snapshot.policy_fingerprint, plan.digest,
              runner.image_ref, runner.expected_image_id, _canonical(asdict(runner.limits)),
              str(runner.executable), runner.endpoint)
    cases, issues, attempted, cleanup_pending, evidence_valid = [], [], 0, False, True
    architecture = None

    def guard():
        if plan._source is not None:
            selected = plan._source.path
            # Guard the actual mounted input as well as load-time source_root.
            # A mistaken load-time root must not expose expected answers to the
            # candidate, even when those bytes form a valid prepared snapshot.
            for excluded in (Path(snapshot.directory).absolute(), snapshot._access.root):
                if selected.is_relative_to(excluded) or selected.resolve().is_relative_to(excluded.resolve()):
                    raise ValueError("trusted behavior plan is inside candidate-accessible input")
        plan.check()
        snapshot.check()
        current = (Path(snapshot.directory), snapshot.digest, snapshot.policy_fingerprint, plan.digest,
                   runner.image_ref, runner.expected_image_id, _canonical(asdict(runner.limits)),
                   str(runner.executable), runner.endpoint)
        if current != pinned:
            raise ValueError("verification input or execution policy drifted")
        if admission_check is not None:
            admission_check()

    def not_run(case, reason):
        return CaseVerification(case.case_id, "not_run", None, None, case.expected_output_sha256,
                                None, None, (reason,))

    stop = False
    try:
        guard()
    except Exception:
        evidence_valid, stop = False, True
        issues.append("initial snapshot, plan, or execution authorization is unavailable")
    for case in plan.cases:
        if stop:
            cases.append(not_run(case, "a required prerequisite or earlier execution is incomplete"))
            continue
        if cancel_event is not None and cancel_event.is_set():
            cases.append(not_run(case, "verification was cancelled"))
            stop = True
            continue
        execution = None
        exit_zero = output_match = None
        case_issues = []
        case_status = "incomplete"
        try:
            guard()
            attempted += 1
            execution = runner.run(ExecutionTask(case.case_id, "test", case.argv, case.cwd),
                                   pinned[0], pinned[1], cancel_event=cancel_event, snapshot_check=guard)
            # Accept an internal typed return value, never a deserialized report.
            if type(execution) is not ExecutionResult:
                execution = None
                raise TypeError("runner returned an untrusted report object")
            cleanup_pending = cleanup_pending or execution.cleanup_pending
            guard()
            if (execution.kind != "test" or execution.task_id != case.case_id
                    or execution.snapshot_digest != pinned[1]
                    or execution.image_reference != pinned[4] or execution.image_id != pinned[5]
                    or execution.platform != "linux" or not isinstance(execution.architecture, str)
                    or not execution.architecture or _canonical(execution.limits) != pinned[6]):
                raise ValueError("execution evidence does not match this plan, snapshot, image, and limits")
            if architecture is not None and execution.architecture != architecture:
                raise ValueError("execution architecture changed between required cases")
            architecture = execution.architecture
            if (execution.cleanup_pending or execution.log_truncated or execution.executed is not True
                    or execution.status not in {"not_verified", "failed"}
                    or type(execution.exit_code) is not int):
                case_issues.append("raw execution is incomplete or cannot support behavioral verification")
                stop = True
            elif cancel_event is not None and cancel_event.is_set():
                case_issues.append("verification was cancelled before publishing this case")
                stop = True
            else:
                exit_zero = execution.exit_code == 0
                digest = execution.output_sha256
                if isinstance(digest, str) and _SHA.fullmatch(digest):
                    output_match = digest == case.expected_output_sha256
                if execution.status == "not_verified" and exit_zero and output_match is not None:
                    case_status = "passed" if output_match else "failed"
                else:
                    case_issues.append("not all required host checks have complete execution evidence")
            guard()
        except Exception:
            case_status, evidence_valid, stop = "incomplete", False, True
            exit_zero = output_match = None
            case_issues.append("trusted execution or a snapshot/plan/admission guard failed")
        cases.append(CaseVerification(case.case_id, case_status, exit_zero, output_match,
                                      case.expected_output_sha256,
                                      execution.output_sha256 if execution is not None else None,
                                      execution, tuple(case_issues)))
    try:
        guard()
    except Exception:
        evidence_valid = False
        issues.append("final snapshot, plan, or execution authorization check failed")
    if cancel_event is not None and cancel_event.is_set():
        evidence_valid = False
        issues.append("verification was cancelled before the final result")
    values = [check for case in cases for check in (case.exit_zero, case.output_digest_matches)]
    completed = sum(case.status in {"passed", "failed"} for case in cases)
    passed = sum(case.status == "passed" for case in cases)
    failed = sum(case.status == "failed" for case in cases)
    status = ("incomplete" if not evidence_valid or cleanup_pending or completed != len(plan.cases)
              else "failed" if failed else "passed")
    return VerificationResult(SCHEMA_VERSION, status, plan.plan_id, pinned[3], pinned[1], pinned[2], pinned[4], pinned[5],
                              json.loads(pinned[6]), len(plan.cases), attempted,
                              sum(case.execution is not None and case.execution.executed is True for case in cases),
                              completed, passed, failed, sum(case.status == "incomplete" for case in cases),
                              sum(case.status == "not_run" for case in cases), len(plan.cases) * 2,
                              sum(value is not None for value in values), sum(value is True for value in values),
                              sum(value is False for value in values), cleanup_pending, evidence_valid,
                              tuple(issues), tuple(cases))
