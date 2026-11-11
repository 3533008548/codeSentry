"""Synthetic Docker replies exercise refusal/cleanup without running a daemon."""
import hashlib
import io
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest

from codesentry.execution.runner import (
    CommandResult, DockerRunner, DockerTransport, ExecutionTask, ResourceLimits,
)


IMAGE = "sha256:" + "a" * 64
DIGEST = "b" * 64
OUTPUT = b"synthetic probe passed\n"
LIMITS = ResourceLimits(64 * 1024 * 1024, 0.5, 32, 2, 1024, 16 * 1024 * 1024)


class FakeDocker:
    def __init__(self, *, output=OUTPUT, exit_code=0, fault=None, outcome=None, cleanup_fails=False):
        self.output, self.exit_code, self.fault = output, exit_code, fault
        self.outcome, self.cleanup_fails = outcome, cleanup_fails
        self.calls, self.container, self.removed, self.started = [], None, False, False
        self.cleanup_reply = None
        self.image = {"Id": IMAGE, "Os": "linux", "Architecture": "amd64", "Config": {"Volumes": None}}
        self.info = {"OSType": "linux", "Architecture": "x86_64", "MemoryLimit": True, "SwapLimit": True,
                     "PidsLimit": True, "CpuCfsQuota": True, "CpuCfsPeriod": True}

    def call(self, argv, **options):
        args = argv[5:]
        self.calls.append(args)
        assert argv[1] == "--config" and argv[3] == "--host"
        assert json.loads((Path(argv[2]) / "config.json").read_text()) == {}
        assert not any(key.startswith(("DOCKER_", "AWS_", "OPENAI_")) for key in options["env"])
        assert options["cwd"] == argv[2]
        if args[0] == "info":
            return self.json(self.info)
        if args[:2] == ["image", "inspect"]:
            return self.json([self.image])
        if args[:2] == ["container", "create"]:
            mount = args[args.index("--mount") + 1]
            source = mount.split("source=", 1)[1].split(",", 1)[0]
            self.container = {
                "Image": IMAGE,
                "Config": {"User": "10001:10001", "Entrypoint": ["/bin/sh"],
                           "Cmd": args[args.index(IMAGE) + 1:], "WorkingDir": "/work", "Tty": False, "OpenStdin": False},
                "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "NetworkMode": "none",
                               "IpcMode": "none", "CgroupnsMode": "private", "PidMode": "", "UsernsMode": "",
                               "CapDrop": ["ALL"], "CapAdd": None, "SecurityOpt": ["no-new-privileges=true"],
                               "Memory": LIMITS.memory_bytes, "MemorySwap": LIMITS.memory_bytes,
                               "NanoCpus": 500000000, "PidsLimit": LIMITS.pids,
                               "Devices": [], "DeviceRequests": None, "PortBindings": {}, "PublishAllPorts": False,
                               "Binds": None, "VolumesFrom": None, "RestartPolicy": {"Name": "no"},
                               "LogConfig": {"Type": "none"},
                               "Tmpfs": {"/work": "rw,nosuid,nodev,size=16777216,mode=0700,uid=10001,gid=10001",
                                         "/tmp": "rw,noexec,nosuid,nodev,size=4194304,mode=1777"},
                               "Mounts": [{"Type": "bind", "Source": source, "Target": "/input", "ReadOnly": True}]},
                "Mounts": [{"Type": "bind", "Destination": "/input", "RW": False}],
                "State": {"Status": "created", "Running": False, "ExitCode": 0, "StartedAt": "0001-01-01T00:00:00Z"},
            }
            if self.fault:
                self.fault(self.container)
            return CommandResult(0, b"c" * 64)
        if args[:2] == ["container", "inspect"]:
            if self.removed:
                return self.cleanup_reply or CommandResult(1, ("Error: No such container: " + args[-1]).encode())
            return self.json([self.container])
        if args[:2] == ["container", "start"]:
            self.started = True
            self.container["State"] = {"Status": "exited", "Running": False, "ExitCode": self.exit_code,
                                       "StartedAt": "2026-10-28T00:00:00Z", "OOMKilled": False, "Error": ""}
            if options.get("check"):
                options["check"]()
            return self.outcome or CommandResult(0, self.output)
        if args[:2] == ["container", "kill"]:
            return CommandResult(0)
        if args[:2] == ["container", "rm"]:
            self.removed = not self.cleanup_fails
            return CommandResult(1 if self.cleanup_fails else 0)
        raise AssertionError(f"unexpected Docker operation {args[0:2]}")

    @staticmethod
    def json(data):
        return CommandResult(0, json.dumps(data).encode())


@pytest.fixture
def setup(tmp_path, monkeypatch):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    calls = []
    def validate(directory, digest):
        assert directory == snapshot and digest == DIGEST
        calls.append((directory, digest))
    monkeypatch.setitem(sys.modules, "codesentry.execution.snapshot", SimpleNamespace(validate_snapshot=validate))
    def create(fake=None):
        fake = fake or FakeDocker()
        runner = DockerRunner(tmp_path / "docker.exe", image_ref=IMAGE, expected_image_id=IMAGE,
                              limits=LIMITS, transport=fake)
        return runner, fake
    return snapshot, calls, create


def probe(**changes):
    return ExecutionTask("synthetic-probe", "probe", ("python3", "-I", "probe.py"),
                         expected_output_sha256=hashlib.sha256(OUTPUT).hexdigest(), **changes)


def test_probe_checks_constraints_uses_only_snapshot_and_confirms_cleanup(setup):
    snapshot, checks, create = setup
    runner, fake = create()
    result = runner.run(probe(), snapshot, DIGEST)
    assert result.status == "passed" and result.executed and result.exit_code == 0
    assert result.snapshot_digest == DIGEST and result.image_id == IMAGE and result.platform == "linux"
    assert result.assertion_count == 0 and not result.cleanup_pending
    assert len(checks) >= 4 and fake.removed
    args = next(args for args in fake.calls if args[:2] == ["container", "create"])
    for flag, value in (("--pull", "never"), ("--user", "10001:10001"), ("--network", "none"),
                        ("--cap-drop", "ALL"), ("--log-driver", "none"), ("--memory", str(LIMITS.memory_bytes)),
                        ("--memory-swap", str(LIMITS.memory_bytes)), ("--pids-limit", "32")):
        assert args[args.index(flag) + 1] == value
    assert args.count("--mount") == 1
    assert str(snapshot) in args[args.index("--mount") + 1]
    assert "readonly" in args[args.index("--mount") + 1] and "--read-only" in args
    assert not any(value in args for value in ("--privileged", "--volume", "--env-file", "--device"))
    assert "chmod -R u+rwX /work" in args[args.index(IMAGE) + 2]


@pytest.mark.parametrize("kind,expected", [("test", "not_verified"), ("build", "not_verified"), ("probe", "not_verified")])
def test_exit_zero_without_a_trusted_success_condition_is_not_verified(setup, kind, expected):
    snapshot, _, create = setup
    runner, _ = create()
    result = runner.run(ExecutionTask("no-assertions", kind, ("true",)), snapshot, DIGEST)
    assert result.status == expected and result.assertion_count == 0


def test_test_cannot_be_verified_by_printing_a_known_output(setup):
    snapshot, _, create = setup
    runner, _ = create()
    task = ExecutionTask("tests", "test", ("python3", "-I", "tests.py"),
                         expected_output_sha256=hashlib.sha256(OUTPUT).hexdigest())
    assert runner.run(task, snapshot, DIGEST).status == "not_verified"


@pytest.mark.parametrize("exit_code,status", [(1, "failed"), (126, "environment_error"), (127, "environment_error")])
def test_command_failure_is_not_success(setup, exit_code, status):
    snapshot, _, create = setup
    runner, _ = create(FakeDocker(exit_code=exit_code))
    assert runner.run(probe(), snapshot, DIGEST).status == status


@pytest.mark.parametrize("outcome,status", [
    (CommandResult(-1, b"partial", timed_out=True), "timeout"),
    (CommandResult(-1, b"partial", cancelled=True), "cancelled"),
    (CommandResult(-1, b"bounded", truncated=True), "failed"),
])
def test_timeout_cancellation_and_output_limit_reclaim_container(setup, outcome, status):
    snapshot, _, create = setup
    runner, fake = create(FakeDocker(outcome=outcome))
    result = runner.run(probe(), snapshot, DIGEST)
    assert result.status == status and not result.cleanup_pending
    assert fake.removed and any(args[:2] == ["container", "kill"] for args in fake.calls)


def test_cleanup_failure_prevents_a_pass(setup):
    snapshot, _, create = setup
    runner, _ = create(FakeDocker(cleanup_fails=True))
    result = runner.run(probe(), snapshot, DIGEST)
    assert result.status == "environment_error" and result.cleanup_pending


@pytest.mark.parametrize("output", [
    b"Cannot connect to unix:///var/run/docker.sock: no such file or directory",
    b"Error: No such container: some-other-container",
    b"Error: No such object: codesentry-unrelated",
])
def test_cleanup_only_accepts_absence_of_this_container(setup, output):
    snapshot, _, create = setup
    runner, fake = create()
    fake.cleanup_reply = CommandResult(1, output)
    result = runner.run(probe(), snapshot, DIGEST)
    assert result.cleanup_pending and result.status == "environment_error"


@pytest.mark.parametrize("field,value", [
    ("ReadonlyRootfs", False), ("Privileged", True), ("NetworkMode", "host"), ("Memory", 0),
    ("MemorySwap", -1), ("NanoCpus", 0), ("PidsLimit", -1), ("CapDrop", []),
    ("CapAdd", ["SYS_ADMIN"]), ("SecurityOpt", ["seccomp=unconfined"]), ("PidMode", "host"),
    ("Devices", [{"PathOnHost": "/dev/sda"}]), ("VolumesFrom", ["gold"]),
    ("LogConfig", {"Type": "json-file"}), ("Tmpfs", {"/work": "rw,size=999999999"}),
])
def test_backend_constraints_are_verified_before_any_task_start(setup, field, value):
    snapshot, _, create = setup
    runner, fake = create(FakeDocker(fault=lambda container: container["HostConfig"].update({field: value})))
    result = runner.run(probe(), snapshot, DIGEST)
    assert result.status == "environment_error" and not result.executed and not fake.started
    assert fake.removed


def test_extra_gold_mount_is_rejected(setup):
    snapshot, _, create = setup
    def inject(container):
        container["Mounts"].append({"Type": "bind", "Destination": "/gold", "RW": False})
    runner, fake = create(FakeDocker(fault=inject))
    assert runner.run(probe(), snapshot, DIGEST).status == "environment_error"
    assert not fake.started


@pytest.mark.parametrize("change", ["identity", "platform", "volume"])
def test_untrusted_or_incompatible_image_is_not_run(setup, change):
    snapshot, _, create = setup
    runner, fake = create()
    fake.image.update({"Id": "sha256:" + "c" * 64} if change == "identity" else
                      {"Os": "windows"} if change == "platform" else {"Config": {"Volumes": {"/data": {}}}})
    result = runner.run(probe(), snapshot, DIGEST)
    assert result.status == "unsupported" and not result.executed
    assert not any(args[:2] == ["container", "create"] for args in fake.calls)


@pytest.mark.parametrize("field", ["MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota", "CpuCfsPeriod"])
@pytest.mark.parametrize("value", [False, None])
def test_backend_must_confirm_real_resource_limit_capabilities(setup, field, value):
    snapshot, _, create = setup
    runner, fake = create()
    fake.info[field] = value
    result = runner.run(probe(), snapshot, DIGEST)
    assert result.status == "unsupported" and not result.executed
    assert not any(args[:2] == ["container", "create"] for args in fake.calls)


def test_missing_docker_never_falls_back_to_host(setup):
    snapshot, _, create = setup
    class Missing:
        def call(self, *args, **kwargs):
            raise FileNotFoundError("Docker unavailable")
    runner, _ = create(Missing())
    result = runner.run(probe(), snapshot, DIGEST)
    assert result.status == "unavailable" and not result.executed and not result.cleanup_pending


def test_snapshot_rejection_and_initial_cancellation_do_not_start_docker(setup):
    snapshot, _, create = setup
    runner, fake = create()
    def denied():
        raise PermissionError("scope revoked")
    result = runner.run(probe(), snapshot, DIGEST, snapshot_check=denied)
    assert result.status == "unavailable" and fake.calls == []
    cancelled = threading.Event()
    cancelled.set()
    assert runner.run(probe(), snapshot, DIGEST, cancel_event=cancelled).status == "cancelled"
    assert fake.calls == []


def test_revocation_while_attached_reclaims_container(setup):
    snapshot, _, create = setup
    runner, fake = create()
    def guard():
        if fake.started:
            raise PermissionError("scope revoked during task")
    result = runner.run(probe(), snapshot, DIGEST, snapshot_check=guard)
    assert result.status == "environment_error" and fake.removed and not result.cleanup_pending


def test_cancellation_observed_at_completion_does_not_publish_pass(setup):
    snapshot, _, create = setup
    event = threading.Event()
    runner, fake = create()
    def guard():
        if fake.started:
            event.set()
    result = runner.run(probe(), snapshot, DIGEST, cancel_event=event, snapshot_check=guard)
    assert result.status == "cancelled" and fake.removed


def test_linux_runner_rejects_windows_task_without_docker_queries(setup):
    snapshot, _, create = setup
    runner, fake = create()
    assert runner.run(probe(platform="windows"), snapshot, DIGEST).status == "unsupported"
    assert fake.calls == []


@pytest.mark.parametrize("cwd", ["../outside", "/host", r"..\outside", "C:/gold", "nested/../../gold"])
def test_working_directory_cannot_escape(cwd):
    with pytest.raises(ValueError):
        ExecutionTask("task", "probe", ("true",), cwd=cwd)


def test_shell_metacharacters_remain_literal_arguments(setup):
    snapshot, _, create = setup
    runner, fake = create()
    task = ExecutionTask("literal", "probe", ("printf", "; cat /gold", "$(read-secret)"))
    runner.run(task, snapshot, DIGEST)
    assert fake.container["Config"]["Cmd"][-3:] == ["printf", "; cat /gold", "$(read-secret)"]


def test_task_logs_are_bounded_and_common_secrets_redacted(setup):
    snapshot, _, create = setup
    runner, _ = create(FakeDocker(output=b"\x1b[31mAPI_KEY=private-value\npassword: hidden\x00"))
    result = runner.run(ExecutionTask("logs", "probe", ("true",)), snapshot, DIGEST)
    assert "private-value" not in result.logs and "hidden" not in result.logs
    assert "[REDACTED]" in result.logs and "\x1b" not in result.logs and "\0" not in result.logs


@pytest.mark.parametrize("reference", ["python:latest", "python:3.14", "--privileged", "sha256:abc"])
def test_mutable_image_references_are_rejected(tmp_path, reference):
    with pytest.raises(ValueError):
        DockerRunner(tmp_path / "docker.exe", image_ref=reference, expected_image_id=IMAGE, limits=LIMITS)


@pytest.mark.parametrize("endpoint", ["tcp://localhost:2375", "ssh://remote", "tcp://remote:2376"])
def test_remote_or_context_selected_endpoints_are_rejected(tmp_path, endpoint):
    with pytest.raises(ValueError):
        DockerRunner(tmp_path / "docker.exe", image_ref=IMAGE, expected_image_id=IMAGE, limits=LIMITS, endpoint=endpoint)


@pytest.mark.parametrize("changes", [{"pids": 0}, {"cpus": float("nan")}, {"memory_bytes": True},
                                     {"max_log_bytes": -1}, {"timeout_seconds": 0}, {"work_bytes": 128 * 1024 * 1024}])
def test_resource_limits_must_be_explicit_and_enforceable(changes):
    arguments = vars(LIMITS) | changes
    with pytest.raises(ValueError):
        ResourceLimits(**arguments)


def test_default_transport_bounds_output_and_reclaims_its_cli(monkeypatch):
    from codesentry.execution import runner as module
    process = SimpleNamespace(stdout=io.BytesIO(b"x" * 100), returncode=0, poll=lambda: 0)
    stopped = []
    monkeypatch.setattr(module.subprocess, "Popen", lambda argv, **kwargs: process)
    monkeypatch.setattr(module, "track_family", lambda process: None)
    monkeypatch.setattr(module, "stop_family", lambda process: stopped.append(process))
    reply = DockerTransport().call(["only-fake-docker"], timeout=1, max_bytes=8, env={}, cwd=".")
    assert reply.output == b"x" * 8 and reply.truncated and stopped == [process]


def test_default_transport_does_not_spawn_after_cancellation(monkeypatch):
    from codesentry.execution import runner as module
    monkeypatch.setattr(module.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("cancelled task spawned"))
    event = threading.Event()
    event.set()
    reply = DockerTransport().call(["only-fake-docker"], timeout=1, max_bytes=8, env={}, cwd=".", cancel_event=event)
    assert reply.cancelled
