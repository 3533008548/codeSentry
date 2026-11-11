"""Small Docker/Linux backend for trusted, explicitly selected tasks.

No image builds, pulls, dependency installation, remote daemon, host fallback,
extra mounts, or automatic project/test discovery are supported here. Container
configuration checks are implementation evidence, not platform qualification.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import threading
import time
from typing import Callable
import uuid

from codesentry.environment.toolchain import clean_process_environment, is_link
from codesentry.web.processes import stop_family, track_family


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"(?:[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@)?sha256:[0-9a-f]{64}\Z")
_BOOTSTRAP = ('set -eu; cp -R /input/. /work/; chmod -R u+rwX /work; '
              'cd "/work/$1"; shift; exec env -i PATH=/usr/local/bin:/usr/bin:/bin '
              'HOME=/work TMPDIR=/tmp "$@"')
_USER = "10001:10001"
_CONTROL_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ResourceLimits:
    memory_bytes: int
    cpus: float
    pids: int
    timeout_seconds: float
    max_log_bytes: int
    work_bytes: int

    def __post_init__(self):
        for name in ("memory_bytes", "pids", "max_log_bytes", "work_bytes"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be an explicit positive integer")
        for name in ("cpus", "timeout_seconds"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        if self.memory_bytes < 16 * 1024 * 1024 or self.work_bytes > self.memory_bytes:
            raise ValueError("memory must cover the bounded work filesystem")
        if self.max_log_bytes > 4 * 1024 * 1024 or self.timeout_seconds > 600:
            raise ValueError("first-backend log/time policy exceeded")


@dataclass(frozen=True)
class ExecutionTask:
    task_id: str
    kind: str
    argv: tuple[str, ...]
    cwd: str = "."
    platform: str = "linux"
    expected_output_sha256: str | None = None

    def __post_init__(self):
        if not isinstance(self.task_id, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", self.task_id) is None:
            raise ValueError("invalid task identity")
        if self.kind not in {"probe", "build", "test"}:
            raise ValueError("unsupported task kind")
        if (not isinstance(self.argv, tuple) or not self.argv or len(self.argv) > 128
                or any(not isinstance(value, str) or not value or "\0" in value or len(value) > 4096 for value in self.argv)
                or sum(map(len, self.argv)) > 16384):
            raise ValueError("argv must be a bounded tuple of literal arguments")
        if (not isinstance(self.cwd, str) or not self.cwd or len(self.cwd) > 1024
                or "\\" in self.cwd or ":" in self.cwd or "\0" in self.cwd
                or PurePosixPath(self.cwd).is_absolute() or ".." in PurePosixPath(self.cwd).parts):
            raise ValueError("task cwd must stay inside /work")
        if self.expected_output_sha256 is not None and (
                not isinstance(self.expected_output_sha256, str) or not _SHA.fullmatch(self.expected_output_sha256)):
            raise ValueError("expected output must be a SHA-256 digest")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: bytes = b""
    timed_out: bool = False
    cancelled: bool = False
    truncated: bool = False


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    executed: bool
    task_id: str
    kind: str
    snapshot_digest: str
    image_reference: str
    image_id: str | None
    platform: str | None
    architecture: str | None
    exit_code: int | None
    assertion_count: int
    logs: str
    output_sha256: str | None
    log_truncated: bool
    cleanup_pending: bool
    issues: tuple[str, ...]
    elapsed_seconds: float
    limits: dict

    def to_dict(self):
        return asdict(self)


class DockerTransport:
    """Bounded CLI output and process-family cleanup; never invoke a shell."""

    def call(self, argv, *, timeout, max_bytes, env, cwd, cancel_event=None, check=None):
        if cancel_event is not None and cancel_event.is_set():
            return CommandResult(-1, cancelled=True)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=env, cwd=cwd,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                   start_new_session=os.name != "nt")
        try:
            track_family(process)
        except BaseException:
            process.kill()
            process.wait(timeout=3)
            raise
        data = bytearray()
        overflow = threading.Event()
        def read():
            try:
                while chunk := process.stdout.read(4096):
                    available = max_bytes - len(data)
                    data.extend(chunk[:max(available, 0)])
                    if len(chunk) > available:
                        overflow.set()
            finally:
                process.stdout.close()
        reader = threading.Thread(target=read, name="codesentry-docker-output", daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        timed_out = cancelled = False
        try:
            while process.poll() is None:
                if check is not None:
                    check()
                cancelled = bool(cancel_event is not None and cancel_event.is_set())
                timed_out = time.monotonic() >= deadline
                if cancelled or timed_out or overflow.is_set():
                    break
                time.sleep(0.05)
        finally:
            stop_family(process)
            reader.join(timeout=3)
        if reader.is_alive():
            raise RuntimeError("docker output pipe could not be reclaimed")
        return CommandResult(process.returncode, bytes(data), timed_out, cancelled, overflow.is_set())


def _redact(output: bytes) -> str:
    text = output.decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = "".join(char for char in text if char in "\n\t" or ord(char) >= 32)
    return re.sub(r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", text)


class DockerRunner:
    def __init__(self, executable: Path, *, image_ref: str, expected_image_id: str,
                 limits: ResourceLimits, endpoint: str | None = None, transport=None):
        executable = Path(executable)
        if not executable.is_absolute():
            raise ValueError("Docker executable must be an operator-selected absolute path")
        if not isinstance(image_ref, str) or not _IMAGE.fullmatch(image_ref):
            raise ValueError("only pinned immutable image references are supported")
        if not isinstance(expected_image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id):
            raise ValueError("an independently trusted image ID is required")
        if not isinstance(limits, ResourceLimits):
            raise ValueError("explicit resource limits are required")
        selected = endpoint or ("npipe:////./pipe/docker_engine" if os.name == "nt" else "unix:///var/run/docker.sock")
        if selected not in {"unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine",
                            "npipe:////./pipe/dockerDesktopLinuxEngine"}:
            raise ValueError("only known local Docker endpoints are supported")
        self.executable, self.image_ref, self.expected_image_id = executable, image_ref, expected_image_id
        self.limits, self.endpoint = limits, selected
        self.transport = transport or DockerTransport()

    def run(self, task: ExecutionTask, snapshot_dir: Path, snapshot_digest: str, *,
            cancel_event=None, snapshot_check: Callable[[], None] | None = None) -> ExecutionResult:
        if not isinstance(task, ExecutionTask) or not isinstance(snapshot_digest, str) or not _SHA.fullmatch(snapshot_digest):
            raise ValueError("a structured task and snapshot digest are required")
        snapshot = Path(snapshot_dir).absolute()
        if (not snapshot.is_dir() or snapshot.resolve() != snapshot
                or any(is_link(part) for part in [snapshot, *snapshot.parents])
                or any(char in str(snapshot) for char in ",\n\r\0")):
            raise ValueError("snapshot must be a direct, non-redirected local directory")
        from codesentry.execution.snapshot import validate_snapshot
        def check():
            validate_snapshot(snapshot, snapshot_digest)
            if snapshot_check is not None:
                snapshot_check()
        started = time.monotonic()
        status, executed, exit_code = "not_run", False, None
        image_id = platform = architecture = None
        output, truncated, cleanup_pending, output_digest = b"", False, False, None
        issues = []
        name = "codesentry-" + uuid.uuid4().hex
        attempted = False
        with tempfile.TemporaryDirectory(prefix="codesentry-docker-config-") as config:
            Path(config, "config.json").write_text("{}", encoding="utf-8")
            environment = clean_process_environment()
            def invoke(arguments, *, timeout=10, max_bytes=_CONTROL_BYTES, cancel=None, guard=None):
                return self.transport.call([str(self.executable), "--config", config, "--host", self.endpoint, *arguments],
                                           timeout=timeout, max_bytes=max_bytes, env=environment, cwd=config,
                                           cancel_event=cancel, check=guard)
            def json_call(arguments):
                reply = invoke(arguments)
                if reply.returncode or reply.timed_out or reply.cancelled or reply.truncated:
                    raise RuntimeError("backend query failed")
                return json.loads(reply.output)
            try:
                if task.platform != "linux":
                    status = "unsupported"
                    issues.append("only Linux tasks are supported; target platform was not verified")
                elif cancel_event is not None and cancel_event.is_set():
                    status = "cancelled"
                else:
                    check()
                    info = json_call(["info", "--format", "{{json .}}"])
                    if info.get("OSType") != "linux":
                        status = "unsupported"
                        issues.append("Docker backend does not report Linux")
                    elif any(info.get(field) is not True for field in (
                            "MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota", "CpuCfsPeriod")):
                        status = "unsupported"
                        issues.append("Docker backend cannot confirm all required resource-limit capabilities")
                    else:
                        image = json_call(["image", "inspect", self.image_ref])[0]
                        image_id, platform, architecture = image.get("Id"), image.get("Os"), image.get("Architecture")
                        host_arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(info.get("Architecture"), info.get("Architecture"))
                        if image_id != self.expected_image_id or platform != "linux" or architecture != host_arch:
                            status = "unsupported"
                            issues.append("trusted image identity or native Linux platform does not match")
                        elif image.get("Config", {}).get("Volumes"):
                            status = "unsupported"
                            issues.append("images with implicit volume mounts are unsupported")
                        else:
                            arguments = self._create(name, snapshot, task, architecture)
                            check()
                            attempted = True
                            created = invoke(arguments)
                            if created.returncode or created.timed_out or created.cancelled or created.truncated:
                                raise RuntimeError("container creation failed")
                            container = json_call(["container", "inspect", name])[0]
                            self._verify(container, snapshot, task)
                            check()
                            reply = invoke(["container", "start", "--attach", name], timeout=self.limits.timeout_seconds,
                                           max_bytes=self.limits.max_log_bytes, cancel=cancel_event, guard=check)
                            output, truncated = reply.output, reply.truncated
                            observed = json_call(["container", "inspect", name])[0]
                            self._verify(observed, snapshot, task)
                            state = observed.get("State", {})
                            executed = (state.get("Status") != "created" and isinstance(state.get("StartedAt"), str)
                                        and not state["StartedAt"].startswith("0001-"))
                            if reply.cancelled or (cancel_event is not None and cancel_event.is_set()):
                                status = "cancelled"
                            elif reply.timed_out:
                                status = "timeout"
                            elif reply.truncated:
                                status = "failed"
                                issues.append("task output exceeded its configured limit")
                            else:
                                if (not executed or state.get("Status") != "exited" or state.get("Running") is not False
                                        or type(state.get("ExitCode")) is not int):
                                    raise RuntimeError("container did not provide a terminal exit state")
                                exit_code = state["ExitCode"]
                                if state.get("OOMKilled"):
                                    status = "failed"
                                    issues.append("container reached its memory limit")
                                elif state.get("Error") or exit_code in {126, 127}:
                                    status = "environment_error"
                                elif exit_code != 0:
                                    status = "failed"
                                elif reply.returncode:
                                    status = "environment_error"
                                else:
                                    output_digest = hashlib.sha256(output).hexdigest()
                                    status = ("passed" if task.kind != "test" and task.expected_output_sha256 is not None
                                              and output_digest == task.expected_output_sha256 else "not_verified")
                                    if task.kind == "test":
                                        issues.append("no trusted test-assertion adapter; exit zero is not test verification")
                                    elif task.expected_output_sha256 is not None and output_digest != task.expected_output_sha256:
                                        status = "failed"
                                        issues.append("trusted output success condition was not met")
                            check()
            except (OSError, RuntimeError, ValueError, KeyError, IndexError, TypeError):
                status = "environment_error" if attempted else "unavailable"
                issues.append("execution prerequisites, snapshot authorization, or backend verification failed")
            finally:
                if attempted:
                    try:
                        invoke(["container", "kill", name])
                        invoke(["container", "rm", "--force", "--volumes", name])
                        absent = invoke(["container", "inspect", name])
                        missing = re.search(
                            rf"(?im)^(?:error(?: response from daemon)?:\s*)?no such (?:object|container):\s*{re.escape(name)}\s*$",
                            absent.output.decode("utf-8", errors="replace"),
                        ) is not None
                        cleanup_pending = not (absent.returncode != 0 and missing and not absent.timed_out and not absent.truncated)
                    except (OSError, RuntimeError, ValueError):
                        cleanup_pending = True
                    if cleanup_pending:
                        issues.append("container cleanup could not be confirmed; operator cleanup required")
                        if status in {"passed", "not_verified"}:
                            status = "environment_error"
        return ExecutionResult(status, executed, task.task_id, task.kind, snapshot_digest, self.image_ref,
                               image_id, platform, architecture, exit_code, 0, _redact(output), output_digest,
                               truncated, cleanup_pending, tuple(issues), round(time.monotonic() - started, 4),
                               asdict(self.limits))

    def _create(self, name: str, snapshot: Path, task: ExecutionTask, architecture: str):
        limits = self.limits
        tmpfs = self._tmpfs()
        return ["container", "create", "--name", name, "--pull", "never", "--platform", f"linux/{architecture}",
                "--user", _USER, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
                "--network", "none", "--ipc", "none", "--cgroupns", "private", "--pids-limit", str(limits.pids),
                "--cpus", str(limits.cpus), "--memory", str(limits.memory_bytes), "--memory-swap", str(limits.memory_bytes),
                "--restart", "no", "--no-healthcheck", "--log-driver", "none", "--workdir", "/work",
                "--mount", f"type=bind,source={snapshot},target=/input,readonly,bind-propagation=rprivate",
                "--tmpfs", "/work:" + tmpfs["/work"], "--tmpfs", "/tmp:" + tmpfs["/tmp"],
                "--entrypoint", "/bin/sh", self.image_ref, "-c", _BOOTSTRAP, "codesentry-task", task.cwd, *task.argv]

    def _tmpfs(self):
        temporary = min(16 * 1024 * 1024, max(1024 * 1024, self.limits.work_bytes // 4))
        return {"/work": f"rw,nosuid,nodev,size={self.limits.work_bytes},mode=0700,uid=10001,gid=10001",
                "/tmp": f"rw,noexec,nosuid,nodev,size={temporary},mode=1777"}

    def _verify(self, container, snapshot: Path, task: ExecutionTask):
        host, config = container["HostConfig"], container["Config"]
        limits = self.limits
        requested = host.get("Mounts", [])
        source_mounts = [mount for mount in requested if mount.get("Type") == "bind"]
        tmpfs = host.get("Tmpfs", {})
        expected_cmd = ["-c", _BOOTSTRAP, "codesentry-task", task.cwd, *task.argv]
        actual_mounts = container.get("Mounts", [])
        caps = {value.upper() for value in (host.get("CapDrop") or [])}
        options = host.get("SecurityOpt") or []
        if (container.get("Image") != self.expected_image_id or config.get("User") != _USER
                or config.get("Entrypoint") != ["/bin/sh"] or config.get("Cmd") != expected_cmd
                or config.get("WorkingDir") != "/work" or config.get("Tty") or config.get("OpenStdin")
                or host.get("ReadonlyRootfs") is not True or host.get("Privileged") is not False
                or host.get("NetworkMode") != "none" or host.get("IpcMode") != "none"
                or host.get("CgroupnsMode") != "private" or host.get("PidMode") not in {"", "private"}
                or host.get("UsernsMode") == "host" or "ALL" not in caps or host.get("CapAdd")
                or not any(value in {"no-new-privileges", "no-new-privileges=true"} for value in options)
                or any("unconfined" in value for value in options)
                or host.get("Memory") != limits.memory_bytes or host.get("MemorySwap") != limits.memory_bytes
                or host.get("NanoCpus") != int(limits.cpus * 1_000_000_000) or host.get("PidsLimit") != limits.pids
                or host.get("Devices") or host.get("DeviceRequests") or host.get("PortBindings") or host.get("PublishAllPorts")
                or host.get("Binds") or host.get("VolumesFrom")
                or host.get("RestartPolicy", {}).get("Name") != "no"
                or host.get("LogConfig", {}).get("Type") != "none"
                or tmpfs != self._tmpfs() or len(requested) != 1 or len(source_mounts) != 1
                or source_mounts[0].get("Source") != str(snapshot) or source_mounts[0].get("Target") != "/input"
                or source_mounts[0].get("ReadOnly") is not True
                or any(mount.get("Destination") not in {"/input", "/work", "/tmp"} for mount in actual_mounts)
                or any(mount.get("Destination") == "/input" and (mount.get("Type") != "bind" or mount.get("RW") is not False)
                       for mount in actual_mounts)):
            raise ValueError("container does not enforce the requested constraints")
