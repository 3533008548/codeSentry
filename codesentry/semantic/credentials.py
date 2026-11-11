"""Read the application's startup key, never a reviewed workspace's .env.

Only DEEPSEEK_API_KEY is consumed. Values are not expanded, executed, exported
to os.environ, logged, or returned by the workbench API.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from codesentry.access.policy import is_link


DEFAULT_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
MAX_ENV_BYTES = 65536
VARIABLE = "DEEPSEEK_API_KEY"
KEY_PATTERN = re.compile(r"[A-Za-z0-9_.-]{8,512}")


@dataclass(frozen=True)
class StartupCredentials:
    api_key: str | None = field(default=None, repr=False)
    source: str = "none"


def _key(value):
    if not isinstance(value, str):
        raise ValueError("DeepSeek启动密钥格式无效")
    value = value.strip()
    if not value:
        return None
    if not KEY_PATTERN.fullmatch(value):
        raise ValueError("DeepSeek启动密钥格式无效")
    return value


def _value(raw):
    raw = raw.strip()
    if raw.startswith(("'", '"')):
        end = raw.find(raw[0], 1)
        if end < 0 or (raw[end + 1:].strip() and not raw[end + 1:].strip().startswith("#")):
            raise ValueError("DeepSeek环境文件格式无效")
        return _key(raw[1:end])
    if raw.startswith("#"):
        return None
    return _key(re.split(r"\s+#", raw, maxsplit=1)[0].rstrip())


def _read(path):
    try:
        if any(is_link(part) for part in (path, *path.parents)):
            raise ValueError("DeepSeek环境文件不能使用重定向路径")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_ENV_BYTES:
            raise ValueError("DeepSeek环境文件必须是受限大小的普通文件")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_nlink) != (before.st_dev, before.st_ino, 1):
                raise ValueError("DeepSeek环境文件在读取时发生变化")
            content = stream.read(MAX_ENV_BYTES + 1)
        after = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink)
        if identity(before) != identity(after) or len(content) > MAX_ENV_BYTES:
            raise ValueError("DeepSeek环境文件在读取时发生变化")
        return content.decode("utf-8-sig")
    except (OSError, UnicodeError):
        raise ValueError("DeepSeek环境文件不存在、不可读取或不是UTF-8格式") from None


def load_deepseek_credentials(env_file: Path | None = None, *, environ: Mapping[str, str] | None = None):
    environment = os.environ if environ is None else environ
    # An explicitly empty environment value also wins, disabling file fallback.
    if VARIABLE in environment:
        value = _key(environment[VARIABLE])
        return StartupCredentials(value, "environment" if value else "none")
    path = DEFAULT_ENV_FILE if env_file is None else Path(env_file).expanduser().absolute()
    if env_file is None and not path.exists() and not is_link(path):
        return StartupCredentials()
    text = _read(path)
    found, value = False, None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?DEEPSEEK_API_KEY\s*=(.*)", stripped)
        if match:
            if found:
                raise ValueError("DeepSeek环境文件重复定义了密钥")
            found, value = True, _value(match[1])
        elif re.match(r"(?:export\s+)?DEEPSEEK_API_KEY(?:\s|$)", stripped):
            raise ValueError("DeepSeek环境文件格式无效")
    return StartupCredentials(value, "env_file" if value else "none")
