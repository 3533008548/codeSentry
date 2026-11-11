"""Bind a trusted, fixed development-task policy to an execution instance.

The operator-owned policy is chosen by the host application, never restored
from candidate reports. Receipts are audit bindings, not signatures, model
approval, OS isolation or Finding/gate credentials.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re

from codesentry.access import AccessDenied
from codesentry.execution.runner import DockerRunner, ResourceLimits
from codesentry.execution.snapshot import SourceSnapshot


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def _sha(value) -> bool:
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


@dataclass(frozen=True)
class BuiltinTaskPolicy:
    policy_id: str
    plan_digest: str
    snapshot_digests: tuple[str, ...]
    image_reference: str
    image_id: str
    limits: ResourceLimits
    purpose: str = "p2-tool-development-reproduction"

    def __post_init__(self):
        if (not isinstance(self.policy_id, str) or not self.policy_id.strip()
                or not _sha(self.plan_digest) or not isinstance(self.snapshot_digests, tuple)
                or not self.snapshot_digests or len(self.snapshot_digests) > 16
                or not all(_sha(item) for item in self.snapshot_digests)
                or len(set(self.snapshot_digests)) != len(self.snapshot_digests)
                or not isinstance(self.limits, ResourceLimits)
                or self.purpose != "p2-tool-development-reproduction"):
            raise ValueError("Invalid fixed development task policy")
        if (not isinstance(self.image_reference, str) or "@sha256:" not in self.image_reference
                or not _sha(self.image_reference.rsplit("@sha256:", 1)[1])
                or not isinstance(self.image_id, str) or not self.image_id.startswith("sha256:")
                or not _sha(self.image_id[7:])):
            raise ValueError("Policy requires a fixed image reference and identity")

    @property
    def digest(self) -> str:
        return _digest(asdict(self))


def _binding(runner, snapshot, plan, policy) -> dict:
    return {"policy_digest": policy.digest, "plan_digest": plan.digest,
        "snapshot_digest": snapshot.digest, "access_fingerprint": snapshot.policy_fingerprint,
        "snapshot_directory": str(Path(snapshot.directory).absolute()),
        "image_reference": runner.image_ref, "image_id": runner.expected_image_id,
        "limits": asdict(runner.limits), "endpoint": runner.endpoint,
        "docker_executable": str(runner.executable)}


@dataclass(frozen=True)
class TaskAdmission:
    policy_id: str
    binding_digest: str
    _policy: BuiltinTaskPolicy = field(repr=False)
    _runner: DockerRunner = field(repr=False)
    _snapshot: SourceSnapshot = field(repr=False)
    _plan: object = field(repr=False)
    _binding_value: dict = field(repr=False)

    def check(self) -> None:
        self._snapshot.check()
        self._plan.check()
        current = _binding(self._runner, self._snapshot, self._plan, self._policy)
        if current != self._binding_value or _digest(current) != self.binding_digest:
            raise AccessDenied("Execution task admission no longer matches its fixed scope")

    def to_dict(self) -> dict:
        return {"schema_version": 1, "kind": "fixed-development-task-admission",
            "policy_id": self.policy_id, "policy_digest": self._policy.digest,
            "binding_digest": self.binding_digest, "purpose": self._policy.purpose,
            "source_snapshot_digest": self._snapshot.digest, "plan_digest": self._plan.digest,
            "image_reference": self._runner.image_ref, "image_id": self._runner.expected_image_id,
            "limits": asdict(self._runner.limits), "arbitrary_project_execution_authorized": False}


def admit_execution(policy: BuiltinTaskPolicy, runner: DockerRunner,
                    snapshot: SourceSnapshot, plan) -> TaskAdmission:
    from codesentry.execution.verification import TestPlan
    if (not isinstance(policy, BuiltinTaskPolicy) or not isinstance(runner, DockerRunner)
            or not isinstance(snapshot, SourceSnapshot) or not isinstance(plan, TestPlan)):
        raise ValueError("Task admission requires trusted typed host inputs, not report JSON")
    snapshot.check()
    plan.check()
    if (snapshot.digest not in policy.snapshot_digests or plan.digest != policy.plan_digest
            or runner.image_ref != policy.image_reference or runner.expected_image_id != policy.image_id
            or runner.limits != policy.limits):
        raise AccessDenied("Task, source, image or resource budget falls outside the fixed policy")
    binding = _binding(runner, snapshot, plan, policy)
    receipt = TaskAdmission(policy.policy_id, _digest(binding), policy, runner, snapshot, plan, binding)
    receipt.check()
    return receipt
