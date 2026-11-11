"""Diagnosis and synthetic-only entry points never select user project paths."""
import json
from pathlib import Path

import pytest

from codesentry.cli.main import main as cli_main
from codesentry.execution import commands
from codesentry.execution.runner import CommandResult


class InfoTransport:
    def __init__(self, data=None, reply=None):
        self.data = data or {"OSType": "linux", "Architecture": "x86_64", "ServerVersion": "test",
                             **{key: True for key in commands.CAPABILITIES}}
        self.reply = reply
        self.calls = []

    def call(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        config = Path(argv[argv.index("--config") + 1])
        assert json.loads((config / "config.json").read_text(encoding="utf-8")) == {}
        assert not any(key.upper() in {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
                                       "AWS_SECRET_ACCESS_KEY", "HTTP_PROXY"} for key in kwargs["env"])
        return self.reply or CommandResult(0, json.dumps(self.data).encode())


def test_doctor_reads_explicit_local_backend_without_execution(tmp_path, monkeypatch):
    executable = tmp_path / "docker.exe"
    executable.touch()
    monkeypatch.setenv("DOCKER_HOST", "tcp://private.example:2375")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "private-sentinel")
    transport = InfoTransport()
    report = commands.backend_doctor(executable, "npipe:////./pipe/dockerDesktopLinuxEngine", transport=transport)
    assert report["backend_prerequisites_available"]
    assert report["target_execution_enabled"] is False
    assert len(transport.calls) == 1
    assert transport.calls[0][0][-3:] == ["info", "--format", "{{json .}}"]


@pytest.mark.parametrize("capability", commands.CAPABILITIES)
def test_doctor_does_not_accept_unknown_resource_limit_capability(tmp_path, capability):
    executable = tmp_path / "docker.exe"
    executable.touch()
    transport = InfoTransport()
    transport.data.pop(capability)
    report = commands.backend_doctor(executable, "unix:///var/run/docker.sock", transport=transport)
    assert report["daemon_connected"]
    assert not report["backend_prerequisites_available"]
    assert report["resource_capabilities"][capability] is False


def test_missing_docker_is_unavailable_without_transport_call(tmp_path):
    transport = InfoTransport()
    report = commands.backend_doctor(tmp_path / "missing", "unix:///var/run/docker.sock", transport=transport)
    assert not report["cli_present"] and not report["backend_prerequisites_available"]
    assert not transport.calls


@pytest.mark.parametrize("reply", [CommandResult(1, b"daemon missing"), CommandResult(0, b"broken json"),
                                   CommandResult(0, b"{}", truncated=True)])
def test_invalid_backend_reply_cannot_be_qualified(tmp_path, reply):
    executable = tmp_path / "docker.exe"
    executable.touch()
    report = commands.backend_doctor(executable, "unix:///var/run/docker.sock", transport=InfoTransport(reply=reply))
    assert not report["backend_prerequisites_available"]
    assert report["target_execution_enabled"] is False


def test_doctor_rejects_remote_backend_or_relative_executable(tmp_path):
    with pytest.raises(ValueError):
        commands.backend_doctor(tmp_path / "docker", "tcp://example:2375")
    with pytest.raises(ValueError):
        commands.backend_doctor(Path("docker"), "unix:///var/run/docker.sock")


def test_smoke_refused_overwrite_runs_no_tasks(tmp_path, monkeypatch, capsys):
    output = tmp_path / "existing.json"
    output.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(commands, "synthetic_smoke", lambda *args: pytest.fail("executed on refused output"))
    assert commands.main(["smoke", "--image-ref", "unused", "--image-id", "unused", "--output", str(output)]) == 2
    assert output.read_text(encoding="utf-8") == "keep"
    assert not json.loads(capsys.readouterr().out)["target_execution_enabled"]


def test_cli_runner_doctor_delegates_to_read_only_diagnosis(monkeypatch, capsys):
    calls = []
    def doctor(executable, endpoint):
        calls.append((executable, endpoint))
        return {"backend_prerequisites_available": True, "target_execution_enabled": False}
    monkeypatch.setattr(commands, "backend_doctor", doctor)
    assert cli_main(["runner", "doctor", "--json"]) == 0
    assert len(calls) == 1
    assert json.loads(capsys.readouterr().out)["target_execution_enabled"] is False
