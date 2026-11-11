"""Read-only backend diagnosis and tool-owned synthetic execution checks.

There is deliberately no target-project execution CLI in this first delivery.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading

from codesentry.access import AccessPolicy
from codesentry.environment.toolchain import clean_process_environment
from codesentry.execution.runner import DockerRunner, DockerTransport, ExecutionTask, ResourceLimits
from codesentry.execution.snapshot import prepare_snapshot


CAPABILITIES = ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota", "CpuCfsPeriod")
ENDPOINTS = {"unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine",
             "npipe:////./pipe/dockerDesktopLinuxEngine"}


def default_executable() -> Path:
    candidates = ([Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe")] if os.name == "nt"
                  else [Path("/usr/bin/docker"), Path("/usr/local/bin/docker")])
    return next((path for path in candidates if path.is_file()), candidates[0])


def default_endpoint() -> str:
    return "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock"


def backend_doctor(executable: Path, endpoint: str, *, transport=None) -> dict:
    executable = Path(executable)
    if not executable.is_absolute() or endpoint not in ENDPOINTS:
        raise ValueError("Select an absolute Docker CLI path and supported local endpoint")
    result = {"schema_version": 1, "kind": "execution-backend-doctor",
        "cli_present": executable.is_file(), "daemon_connected": False,
        "guest_os": None, "architecture": None, "server_version": None,
        "resource_capabilities": {key: False for key in CAPABILITIES},
        "backend_prerequisites_available": False, "target_execution_enabled": False,
        "qualification": "synthetic boundary checks and task admission still required"}
    if not result["cli_present"]:
        return result
    with tempfile.TemporaryDirectory(prefix="codesentry-doctor-config-") as config:
        Path(config, "config.json").write_text("{}", encoding="utf-8")
        reply = (transport or DockerTransport()).call(
            [str(executable), "--config", config, "--host", endpoint, "info", "--format", "{{json .}}"],
            timeout=10, max_bytes=1024*1024, env=clean_process_environment(), cwd=config)
    if reply.returncode or reply.timed_out or reply.cancelled or reply.truncated:
        return result
    try:
        info = json.loads(reply.output)
        result.update(daemon_connected=True, guest_os=info["OSType"],
            architecture=info.get("Architecture"), server_version=info.get("ServerVersion"),
            resource_capabilities={key: info.get(key) is True for key in CAPABILITIES})
    except (ValueError, TypeError, KeyError):
        return result
    result["backend_prerequisites_available"] = (result["guest_os"] == "linux"
        and all(result["resource_capabilities"].values()))
    return result


BOUNDARY_SOURCE = '''import json, os, pathlib, socket
def can_write(name):
    try:
        with open(name, "w") as stream: stream.write("only-in-copy")
        return True
    except OSError: return False
def network_available():
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=0.3): return True
    except OSError: return False
group = pathlib.Path("/sys/fs/cgroup")
quota, period = (group / "cpu.max").read_text().split()
checks = {
    "non_root": os.geteuid() == 10001,
    "root_read_only": not can_write("/codesentry-root-write"),
    "input_read_only": not can_write("/input/input.txt"),
    "work_copy_writable": can_write("/work/input.txt"),
    "docker_socket_absent": not pathlib.Path("/var/run/docker.sock").exists(),
    "host_home_absent": not os.path.exists("/root/.aws/credentials"),
    "gold_not_mounted": not pathlib.Path("/gold").exists(),
    "network_unavailable": not network_available(),
    "memory_limit": int((group / "memory.max").read_text()) == 268435456,
    "pids_limit": int((group / "pids.max").read_text()) == 32,
    "cpu_limit": quota != "max" and int(quota) == int(period),
}
print(json.dumps(checks, sort_keys=True))
'''
BOUNDARY_KEYS = ("non_root", "root_read_only", "input_read_only", "work_copy_writable",
    "docker_socket_absent", "host_home_absent", "gold_not_mounted", "network_unavailable",
    "memory_limit", "pids_limit", "cpu_limit")


def synthetic_smoke(executable: Path, endpoint: str, image_ref: str, image_id: str) -> dict:
    """Exercise only fixed tool-owned inputs; this cannot select a user project."""
    limits = ResourceLimits(256*1024*1024, 1, 32, 10, 2048, 8*1024*1024)
    runner = DockerRunner(executable, image_ref=image_ref, expected_image_id=image_id,
                          limits=limits, endpoint=endpoint)
    expected = (json.dumps({key: True for key in BOUNDARY_KEYS}, sort_keys=True) + "\n").encode()
    tasks = [
        (ExecutionTask("boundary", "probe", ("/usr/local/bin/python", "-I", "/work/boundary.py"),
            expected_output_sha256=hashlib.sha256(expected).hexdigest()), "passed"),
        (ExecutionTask("no-assertions", "test", ("/usr/local/bin/python", "-I", "-c", "pass")), "not_verified"),
        (ExecutionTask("nonzero", "test", ("/usr/local/bin/python", "-I", "-c", "raise SystemExit(3)")), "failed"),
        (ExecutionTask("timeout", "probe", ("/usr/local/bin/python", "-I", "-c", "import time;time.sleep(20)")), "timeout"),
        (ExecutionTask("cancel", "probe", ("/usr/local/bin/python", "-I", "-c", "import time;time.sleep(20)")), "cancelled"),
        (ExecutionTask("output-limit", "probe", ("/usr/local/bin/python", "-I", "-c", "print('x'*9000)")), "failed"),
    ]
    observations = []
    with tempfile.TemporaryDirectory(prefix="codesentry-synthetic-runner-") as temporary:
        base = Path(temporary)
        source = base / "source"
        source.mkdir()
        (source / "boundary.py").write_text(BOUNDARY_SOURCE, encoding="utf-8")
        (source / "input.txt").write_text("original-only", encoding="utf-8")
        before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in source.iterdir()}
        with prepare_snapshot(AccessPolicy(source), base / "snapshot",
                paths=["boundary.py", "input.txt"], max_files=2, max_bytes=16384, max_file_bytes=8192) as snapshot:
            for task, expected_status in tasks:
                selected = runner
                cancel, timer = None, None
                if task.task_id == "timeout":
                    selected = DockerRunner(executable, image_ref=image_ref, expected_image_id=image_id,
                        limits=replace(limits, timeout_seconds=1), endpoint=endpoint)
                if task.task_id == "cancel":
                    cancel = threading.Event()
                    timer = threading.Timer(2, cancel.set)
                    timer.start()
                try:
                    result = selected.run(task, snapshot.directory, snapshot.digest,
                                          snapshot_check=snapshot.check, cancel_event=cancel)
                finally:
                    if timer:
                        timer.cancel()
                        timer.join()
                matched = result.status == expected_status and result.executed and not result.cleanup_pending
                if task.task_id == "output-limit":
                    matched = matched and result.log_truncated
                observations.append({"task_id": task.task_id, "expected_status": expected_status,
                    "expectation_met": matched, "result": result.to_dict()})
            digest = snapshot.digest
        after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in source.iterdir()}
    return {"schema_version": 1, "kind": "synthetic-docker-boundary-smoke",
        "synthetic_only": True, "target_projects_executed": False,
        "image_ref": image_ref, "image_id": image_id, "limits": asdict(limits),
        "snapshot_digest": digest, "source_unchanged": before == after,
        "boundary_checks": list(BOUNDARY_KEYS), "observations": observations,
        "synthetic_smoke_passed": before == after and all(row["expectation_met"] for row in observations),
        "target_execution_enabled": False, "test_assertion_adapter_available": False,
        "formal_acceptance": {"passed": False, "reason": "tool-owned synthetic task subset only"}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Local execution backend preparation")
    parser.add_argument("action", choices=["doctor", "smoke"])
    parser.add_argument("--docker-executable", type=Path, default=default_executable())
    parser.add_argument("--endpoint", choices=sorted(ENDPOINTS), default=default_endpoint())
    parser.add_argument("--image-ref")
    parser.add_argument("--image-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "doctor":
            report = backend_doctor(args.docker_executable, args.endpoint)
            print(json.dumps(report, ensure_ascii=False))
            return 0 if report["backend_prerequisites_available"] else 1
        if args.output is None or args.image_ref is None or args.image_id is None:
            parser.error("smoke requires --image-ref, --image-id and a new --output")
        # Reserve output before execution so a refused overwrite runs no tasks.
        with args.output.open("x", encoding="utf-8") as stream:
            report = synthetic_smoke(args.docker_executable, args.endpoint, args.image_ref, args.image_id)
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print(json.dumps({"synthetic_smoke_passed": report["synthetic_smoke_passed"],
            "tasks": len(report["observations"]), "target_execution_enabled": False}))
        return 0 if report["synthetic_smoke_passed"] else 1
    except (OSError, ValueError, RuntimeError):
        print(json.dumps({"status": "unavailable", "target_execution_enabled": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
