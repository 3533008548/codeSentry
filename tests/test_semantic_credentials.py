"""Startup credentials are trusted application config, never reviewed data."""
import importlib
import json
import os
from pathlib import Path

import pytest

from codesentry.cli.main import main
from codesentry.environment.toolchain import clean_process_environment
from codesentry.semantic import credentials


FAKE_KEY = "sk-SYNTHETIC_STARTUP_ENV_ONLY_12345678"


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    path = tmp_path / "application" / ".env"
    path.parent.mkdir()
    monkeypatch.setattr(credentials, "DEFAULT_ENV_FILE", path)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    return path


@pytest.mark.parametrize("line", [f"DEEPSEEK_API_KEY={FAKE_KEY}",
    f"DEEPSEEK_API_KEY = '{FAKE_KEY}' # local", f'export DEEPSEEK_API_KEY="{FAKE_KEY}"',
    f"\ufeff# header\nDEEPSEEK_API_KEY={FAKE_KEY} # comment\nOTHER_PASSWORD=not-loaded"])
def test_env_file_parses_only_one_literal_key_without_export(env_file, line):
    env_file.write_bytes(line.encode("utf-8"))
    before = dict(os.environ)
    value = credentials.load_deepseek_credentials(environ={})
    assert value.api_key == FAKE_KEY and value.source == "env_file"
    assert FAKE_KEY not in str(value) and FAKE_KEY not in repr(value)
    assert dict(os.environ) == before


def test_process_environment_precedes_file_even_when_empty(env_file):
    env_file.write_text(f"DEEPSEEK_API_KEY={FAKE_KEY}\n", encoding="utf-8")
    key = "sk-SYNTHETIC_PROCESS_OVERRIDES_FILE"
    value = credentials.load_deepseek_credentials(environ={"DEEPSEEK_API_KEY": key})
    assert value.api_key == key and value.source == "environment"
    value = credentials.load_deepseek_credentials(environ={"DEEPSEEK_API_KEY": ""})
    assert value.api_key is None and value.source == "none"
    with pytest.raises(ValueError) as error:
        credentials.load_deepseek_credentials(environ={"DEEPSEEK_API_KEY": "bad$value"})
    assert "bad$value" not in str(error.value)


def test_default_env_is_anchored_to_application_not_current_target(env_file, tmp_path, monkeypatch):
    target = tmp_path / "reviewed-source"
    target.mkdir()
    (target / ".env").write_text(f"DEEPSEEK_API_KEY={FAKE_KEY}", encoding="utf-8")
    monkeypatch.chdir(target)
    assert credentials.load_deepseek_credentials(environ={}).api_key is None
    env_file.write_text("DEEPSEEK_API_KEY=sk-TRUSTED_APP_ONLY_KEY", encoding="utf-8")
    assert credentials.load_deepseek_credentials(environ={}).api_key == "sk-TRUSTED_APP_ONLY_KEY"


def test_explicit_env_file_is_not_combined_with_default(env_file, tmp_path):
    env_file.write_text(f"DEEPSEEK_API_KEY={FAKE_KEY}", encoding="utf-8")
    alternate = tmp_path / "trusted.env"
    alternate.write_text("DEEPSEEK_API_KEY=sk-EXPLICIT_TRUSTED_CONFIG", encoding="utf-8")
    assert credentials.load_deepseek_credentials(alternate, environ={}).api_key == "sk-EXPLICIT_TRUSTED_CONFIG"
    alternate.write_text("DEEPSEEK_API_KEY=", encoding="utf-8")
    assert credentials.load_deepseek_credentials(alternate, environ={}).api_key is None
    with pytest.raises(ValueError):
        credentials.load_deepseek_credentials(tmp_path / "missing.env", environ={})


@pytest.mark.parametrize("text", ["DEEPSEEK_API_KEY=${OTHER_SECRET}", "DEEPSEEK_API_KEY=$(echo missing)",
    "DEEPSEEK_API_KEY=`echo missing`", "DEEPSEEK_API_KEY=sk-abc\\nabc", "DEEPSEEK_API_KEY='unterminated",
    "DEEPSEEK_API_KEY='sk-SYNTHETIC_KEY' extra", "DEEPSEEK_API_KEY=no", "DEEPSEEK_API_KEY value",
    f"DEEPSEEK_API_KEY={FAKE_KEY}\nDEEPSEEK_API_KEY=", f'DEEPSEEK_API_KEY="{FAKE_KEY}\nother"'])
def test_ambiguous_or_executable_values_are_rejected_without_echo(env_file, text):
    env_file.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError) as error:
        credentials.load_deepseek_credentials(environ={})
    assert FAKE_KEY not in str(error.value) and text not in str(error.value)


@pytest.mark.parametrize("content", [b"\xffDEEPSEEK_API_KEY=bad", b"#" * 65537], ids=["invalid_utf8", "oversized"])
def test_invalid_encoding_and_oversized_files_fail_closed(env_file, content):
    env_file.write_bytes(content)
    with pytest.raises(ValueError):
        credentials.load_deepseek_credentials(environ={})


def test_link_and_hardlink_are_not_accepted_as_credential_file(env_file, tmp_path, monkeypatch):
    env_file.write_text(f"DEEPSEEK_API_KEY={FAKE_KEY}", encoding="utf-8")
    original = credentials.is_link
    monkeypatch.setattr(credentials, "is_link", lambda path: path == env_file or original(path))
    with pytest.raises(ValueError):
        credentials.load_deepseek_credentials(environ={})
    monkeypatch.setattr(credentials, "is_link", original)
    alias = tmp_path / "key-alias"
    os.link(env_file, alias)
    with pytest.raises(ValueError):
        credentials.load_deepseek_credentials(environ={})


def test_process_key_does_not_enter_analysis_child_environment(env_file, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", FAKE_KEY)
    value = credentials.load_deepseek_credentials()
    assert value.api_key == FAKE_KEY
    child = clean_process_environment()
    assert "DEEPSEEK_API_KEY" not in child and FAKE_KEY not in json.dumps(child)


@pytest.mark.parametrize("value,source", [("", None), (FAKE_KEY, "env_file")])
def test_serve_injects_startup_snapshot_without_echo(env_file, tmp_path, monkeypatch, capsys, value, source):
    uvicorn = pytest.importorskip("uvicorn")
    web = importlib.import_module("codesentry.web.app")
    env_file.write_text(f"DEEPSEEK_API_KEY={value}\n", encoding="utf-8")
    frontend = tmp_path / "dist"
    frontend.mkdir()
    (frontend / "index.html").write_text("<main>fixture</main>", encoding="utf-8")
    captured = {}
    app = object()

    def factory(**kwargs):
        captured.update(kwargs)
        return app

    monkeypatch.setattr(web, "create_app", factory)
    monkeypatch.setattr(uvicorn, "run", lambda selected, **_kwargs: selected is app)
    assert main(["serve", "--frontend-dir", str(frontend), "--data-dir", str(tmp_path / "state")]) == 0
    assert captured["configured_api_key"] == (value or None) and captured["configured_key_source"] == source
    output = capsys.readouterr()
    assert FAKE_KEY not in output.out + output.err


def test_bad_explicit_env_fails_before_server_without_echo(tmp_path, monkeypatch, capsys):
    uvicorn = pytest.importorskip("uvicorn")
    frontend = tmp_path / "dist"
    frontend.mkdir()
    (frontend / "index.html").write_text("<main>fixture</main>", encoding="utf-8")
    env_file = tmp_path / "invalid.env"
    secret = FAKE_KEY + "$invalid"
    env_file.write_text(f"DEEPSEEK_API_KEY={secret}", encoding="utf-8")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setattr(uvicorn, "run", lambda *_args, **_kwargs: pytest.fail("invalid config started server"))
    assert main(["serve", "--env-file", str(env_file), "--frontend-dir", str(frontend)]) == 2
    output = capsys.readouterr()
    assert FAKE_KEY not in output.out + output.err and "格式无效" in output.err
