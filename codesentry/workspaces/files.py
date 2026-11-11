"""Read explicitly registered source trees without following redirects or secrets."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import tokenize

from codesentry.access import AccessPolicy
from codesentry.environment.toolchain import is_link
from codesentry.index.cache import hash_content

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 5000
LANGUAGES = {
    ".py": "python", ".pyi": "python", ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".json": "json", ".md": "markdown", ".markdown": "markdown", ".html": "html",
    ".css": "css", ".scss": "scss", ".yaml": "yaml", ".yml": "yaml", ".toml": "plaintext",
    ".txt": "plaintext", ".ini": "ini", ".cfg": "ini", ".sql": "sql", ".sh": "shell",
    ".bat": "bat", ".ps1": "powershell", ".xml": "xml", ".svg": "xml", ".lock": "plaintext",
}


def supported_text(path: Path) -> bool:
    return path.suffix.lower() in LANGUAGES or path.name in {"Dockerfile", "Makefile"}


def checked_root(root: Path) -> Path:
    if not root.is_dir() or is_link(root) or os.path.normcase(str(root.resolve())) != os.path.normcase(str(root)):
        raise ValueError("代码目录已移动、不可访问或被重定向，请重新打开")
    return root


def resolve_file(root: Path, relative: str, *, access: AccessPolicy, data_dir: Path | None = None) -> Path:
    checked_root(root)
    resolved = access.resolve(relative)
    if not resolved.is_relative_to(root) or (data_dir is not None and resolved.is_relative_to(data_dir)):
        raise ValueError("文件不在当前工作空间源码范围")
    if not resolved.is_file() or not supported_text(resolved):
        raise ValueError("该文件类型暂不支持文本阅读")
    return resolved


def list_files(root: Path, *, access: AccessPolicy, data_dir: Path | None = None) -> dict:
    checked_root(root)
    files, truncated = [], False
    for relative, path, is_dir, decision in access.walk():
        if is_dir or decision["mode"] == "exclude":
            continue
        if data_dir is not None and path.resolve().is_relative_to(data_dir):
            continue
        if not supported_text(path):
            continue
        try:
            files.append({"path": relative, "language": LANGUAGES.get(path.suffix.lower(), "plaintext"),
                          "size": path.stat().st_size, "access_mode": decision["mode"]})
        except OSError:
            truncated = True
            continue
        if len(files) >= MAX_FILES:
            truncated = True
            break
    return {"files": files, "truncated": truncated}


def decode_source(raw: bytes, path: Path) -> str:
    if b"\0" in raw:
        raise ValueError("暂不显示二进制文件")
    try:
        encoding = tokenize.detect_encoding(io.BytesIO(raw).readline)[0] if path.suffix.lower() in {".py", ".pyi"} else "utf-8-sig"
        return raw.decode(encoding)
    except (SyntaxError, LookupError, UnicodeError) as error:
        raise ValueError("文件编码无法安全读取，请检查源码编码声明") from error


def read_file(root: Path, relative: str, *, access: AccessPolicy, data_dir: Path | None = None) -> dict:
    path = resolve_file(root, relative, access=access, data_dir=data_dir)
    raw = access.read_bytes(relative, limit=MAX_FILE_BYTES)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("文件超过2MiB阅读上限")
    content = decode_source(raw, path)
    # Detect a changed redirect after the read as well; this is not an OS sandbox.
    if resolve_file(root, relative, access=access, data_dir=data_dir) != path:
        raise ValueError("读取期间文件路径发生变化，请重试")
    return {"path": path.relative_to(root).as_posix(), "content": content,
            "language": LANGUAGES.get(path.suffix.lower(), "plaintext"),
            "sha256": hashlib.sha256(raw).hexdigest(), "lines": len(content.splitlines()),
            "content_hash": hash_content(content), "content_hash_algorithm": "sha1-decoded-text",
            "access_mode": access.decision(relative)["mode"]}
