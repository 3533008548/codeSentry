"""CodeSentry-owned parsing tools; never discover executable packages in a target."""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from urllib.parse import urlparse
from urllib.request import urlopen

TYPESCRIPT_VERSION = "5.9.3"
TYPESCRIPT_URL = "https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz"
TYPESCRIPT_INTEGRITY = (
    "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdia"
    "UpFT4bXlb1RHhLpp8wtm6M5TgSw=="
)
# The compiler entry was obtained from the pinned, SHA-512-verified official archive.
TYPESCRIPT_COMPILER_SHA256 = (
    "3ae902c92cc44dace175c0e69e13a4b0899f6983c6121d76b9ab8dd5795e7675"
)
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_EXPANDED_BYTES = 80 * 1024 * 1024
MAX_ARCHIVE_FILES = 512


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def managed_tools_root() -> Path:
    """Installation belongs to the analyzer's interpreter, not the target repository."""
    return Path(sys.prefix).resolve() / "toolchains"


def managed_typescript_dir() -> Path:
    return managed_tools_root() / "typescript" / TYPESCRIPT_VERSION


def is_link(path: Path) -> bool:
    if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
        return True
    if os.name == "nt":
        try:
            return bool(getattr(path.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        except OSError:
            return False
    return False


def _safe_managed_path(path: Path, base: Path) -> bool:
    """Reject package redirects even if they happen to point at an identical file."""
    try:
        relative = path.relative_to(base)
        current = base
        if is_link(current):
            return False
        for part in relative.parts:
            current = current / part
            if is_link(current):
                return False
        return path.resolve().is_relative_to(base.resolve())
    except (OSError, ValueError):
        return False


def clean_process_environment() -> dict[str, str]:
    """Allow only OS process essentials, excluding package loaders and credentials."""
    allowed = {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC"}
    result = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    result["NODE_DISABLE_COMPILE_CACHE"] = "1"
    return result


@dataclass(frozen=True)
class Toolchain:
    node: str | None = None
    typescript_path: str | None = None
    fingerprint: str = ""
    diagnostics: list[str] = field(default_factory=list)
    node_version: str | None = None
    typescript_version: str | None = None
    node_sha256: str | None = None
    compiler_sha256: str | None = None

    def to_dict(self) -> dict:
        return {
            "node": self.node,
            "node_version": self.node_version,
            "node_sha256": self.node_sha256,
            "typescript_path": self.typescript_path,
            "typescript_version": self.typescript_version,
            "compiler_sha256": self.compiler_sha256,
            "fingerprint": self.fingerprint,
            "diagnostics": list(self.diagnostics),
            "ready": bool(self.node and self.typescript_path),
            "source": "codesentry-pinned-typescript-and-operator-node",
            "node_source": "operator-setting-or-host-PATH",
            "typescript_source": "official-npm-pinned-archive",
        }


def _find_node(project_root: Path | None) -> tuple[str | None, str | None, str | None, str | None]:
    # This override is an operator process setting, never read from target config.
    selected = os.environ.get("CODESENTRY_NODE") or shutil.which("node")
    if not selected:
        return None, None, None, "node_unavailable"
    path = Path(selected).resolve()
    if not path.is_file() or (os.name == "nt" and path.suffix.lower() != ".exe"):
        return None, None, None, "node_not_a_native_executable"
    if project_root is not None and path.is_relative_to(project_root.resolve()):
        return None, None, None, "node_executable_inside_target_rejected"
    try:
        response = subprocess.run(
            [str(path), "--version"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=5,
            env=clean_process_environment(), cwd=path.parent,
        )
        version = response.stdout.strip()
        if response.returncode or not re.fullmatch(r"v\d+\.\d+\.\d+", version):
            return None, None, None, "node_version_probe_failed"
        return str(path), version, _digest_file(path), None
    except (OSError, subprocess.TimeoutExpired):
        return None, None, None, "node_version_probe_failed"


def get_toolchain(project_root: Path | None = None) -> Toolchain:
    """Read installed provenance and bytes; no network, installation, or target import."""
    diagnostics: list[str] = []
    node, node_version, node_hash, problem = _find_node(project_root)
    if problem:
        diagnostics.append(problem)
    package = managed_typescript_dir()
    entry = package / "lib" / "typescript.js"
    receipt = package / "codesentry-toolchain.json"
    compiler: str | None = None
    compiler_hash: str | None = None
    try:
        if not _safe_managed_path(package, managed_tools_root()) or not _safe_managed_path(entry, managed_tools_root()):
            raise ValueError("typescript_managed_path_redirected")
        if not _safe_managed_path(receipt, managed_tools_root()):
            raise ValueError("typescript_managed_path_redirected")
        data = json.loads(receipt.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not all(
            isinstance(data.get(name), str) for name in ("version", "integrity")
        ):
            raise ValueError("typescript_provenance_invalid")
        if data.get("version") != TYPESCRIPT_VERSION or data.get("integrity") != TYPESCRIPT_INTEGRITY:
            raise ValueError("typescript_provenance_mismatch")
        compiler_hash = _digest_file(entry)
        if compiler_hash != TYPESCRIPT_COMPILER_SHA256:
            raise ValueError("typescript_compiler_integrity_mismatch")
        compiler = str(entry.resolve())
    except FileNotFoundError:
        diagnostics.append("typescript_managed_package_missing")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        diagnostics.append(str(error) if isinstance(error, ValueError) else "typescript_managed_package_unreadable")
    identity = {
        "schema": 1,
        "python": list(sys.version_info[:3]),
        "node": node,
        "node_version": node_version,
        "node_sha256": node_hash,
        "compiler": compiler,
        "compiler_sha256": compiler_hash,
        "typescript_version": TYPESCRIPT_VERSION,
        "diagnostics": diagnostics,
    }
    return Toolchain(
        node=node, node_version=node_version, node_sha256=node_hash,
        typescript_path=compiler, compiler_sha256=compiler_hash,
        typescript_version=TYPESCRIPT_VERSION if compiler else None,
        fingerprint=_digest(identity), diagnostics=diagnostics,
    )


def _verified_archive(data: bytes) -> list[tuple[str, bytes]]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds download limit")
    actual = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    if actual != TYPESCRIPT_INTEGRITY:
        raise ValueError("official archive integrity mismatch")
    files: list[tuple[str, bytes]] = []
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts
            if (
                not parts or parts[0] != "package" or len(parts) < 2
                or any(part in (".", "..") or ":" in part or "\\" in part for part in parts)
            ):
                if member.isdir() and parts == ("package",):
                    continue
                raise ValueError("unsafe archive path")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("archive links and special files are forbidden")
            expanded += member.size
            if expanded > MAX_EXPANDED_BYTES or len(files) >= MAX_ARCHIVE_FILES:
                raise ValueError("archive exceeds expansion limit")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("archive file cannot be read")
            payload = stream.read(member.size + 1)
            if len(payload) != member.size:
                raise ValueError("archive file size mismatch")
            files.append((str(PurePosixPath(*parts[1:])), payload))
    by_name = dict(files)
    if len(by_name) != len(files):
        raise ValueError("duplicate archive entry")
    if hashlib.sha256(by_name.get("lib/typescript.js", b"")).hexdigest() != TYPESCRIPT_COMPILER_SHA256:
        raise ValueError("compiler entry integrity mismatch")
    metadata = json.loads(by_name["package.json"])
    if metadata.get("name") != "typescript" or metadata.get("version") != TYPESCRIPT_VERSION:
        raise ValueError("package version mismatch")
    return files


def install_typescript(archive_path: Path | None = None) -> Path:
    """Install only the pinned archive; no npm scripts, project code, or Docker build."""
    if archive_path is None:
        with urlopen(TYPESCRIPT_URL, timeout=30) as response:
            final = urlparse(response.url)
            if final.scheme != "https" or final.hostname != "registry.npmjs.org":
                raise ValueError("unexpected package download origin")
            data = response.read(MAX_ARCHIVE_BYTES + 1)
    else:
        if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("archive exceeds download limit")
        data = archive_path.read_bytes()
    files = _verified_archive(data)
    package = managed_typescript_dir()
    base = managed_tools_root()
    if not _safe_managed_path(package, base):
        raise ValueError("managed package path is redirected")
    if package.exists():
        raise FileExistsError(f"managed package already exists: {package}")
    package.mkdir(parents=True)
    for relative, payload in files:
        destination = package / relative
        if not destination.resolve().is_relative_to(package.resolve()):
            raise ValueError("unsafe installation target")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    receipt = {
        "schema": 1, "version": TYPESCRIPT_VERSION, "url": TYPESCRIPT_URL,
        "integrity": TYPESCRIPT_INTEGRITY, "compiler_sha256": TYPESCRIPT_COMPILER_SHA256,
    }
    (package / "codesentry-toolchain.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8",
    )
    return package


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install the fixed CodeSentry TypeScript parser toolchain")
    parser.add_argument("action", choices=["install-typescript", "status"])
    parser.add_argument("--archive", type=Path, help="use an already downloaded archive, with the same integrity checks")
    args = parser.parse_args(argv)
    if args.action == "install-typescript":
        print(install_typescript(args.archive))
    else:
        print(json.dumps(get_toolchain().to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
