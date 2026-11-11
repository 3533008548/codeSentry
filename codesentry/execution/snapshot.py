"""Bounded, permission-checked input copies for a local execution backend.

Snapshots are operator-owned local exports, never model inputs. A snapshot is
identified by its bytes; it does not prove that today's source still matches it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.access.policy import is_link


MAX_FILES = 10_000
MAX_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024


class SnapshotCleanupPending(OSError):
    """A failed export left artifacts; they cannot be used as execution input."""


def _name(value: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 4096
            or "\\" in value or ":" in value or any(ord(char) < 32 for char in value)):
        raise ValueError("Invalid snapshot-relative name")
    parts = value.split("/")
    for part in parts:
        if (part in {"", ".", ".."} or part.endswith((" ", "."))
                or re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)):
            raise ValueError("Unsupported snapshot-relative name")
    return value


def _identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino


def _safe_ancestors(path: Path) -> None:
    for component in (path, *path.parents):
        if is_link(component):
            raise AccessDenied("Snapshot location is redirected")


def _digest(rows: list[dict]) -> str:
    return hashlib.sha256(json.dumps(sorted(rows, key=lambda row: row["path"]),
        ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _inventory(directory: Path) -> list[dict]:
    _safe_ancestors(directory)
    if not directory.is_dir():
        raise ValueError("Snapshot directory is unavailable")
    pending, rows, actual_dirs, aliases, total = [directory], [], set(), set(), 0
    while pending:
        parent = pending.pop()
        _safe_ancestors(parent)
        with os.scandir(parent) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = _name(path.relative_to(directory).as_posix())
                alias = relative.casefold()
                if alias in aliases:
                    raise ValueError("Snapshot contains aliased names")
                aliases.add(alias)
                if len(aliases) > MAX_FILES * 2:
                    raise ValueError("Snapshot entry limit exceeded")
                metadata = path.lstat()
                if is_link(path):
                    raise AccessDenied("Snapshot contains a redirected entry")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                    actual_dirs.add(relative)
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise AccessDenied("Snapshot contains a non-regular or shared file")
                if metadata.st_size > MAX_FILE_BYTES or len(rows) >= MAX_FILES:
                    raise ValueError("Snapshot file limit exceeded")
                digest, size = hashlib.sha256(), 0
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        size += len(chunk)
                        total += len(chunk)
                        if size > MAX_FILE_BYTES or total > MAX_BYTES:
                            raise ValueError("Snapshot byte limit exceeded")
                        digest.update(chunk)
                current = path.lstat()
                if (is_link(path) or current.st_nlink != 1
                        or (current.st_dev, current.st_ino, current.st_size,
                            current.st_mtime_ns, current.st_ctime_ns) !=
                           (metadata.st_dev, metadata.st_ino, metadata.st_size,
                            metadata.st_mtime_ns, metadata.st_ctime_ns)):
                    raise AccessDenied("Snapshot changed while being validated")
                rows.append({"path": relative, "sha256": digest.hexdigest(), "size": size})
    parents = {parent.as_posix() for row in rows
        for parent in Path(row["path"]).parents if parent != Path(".")}
    if actual_dirs != parents or not rows:
        raise ValueError("Snapshot has empty or unexplained directories")
    return rows


def validate_snapshot(directory: Path, expected_digest: str) -> None:
    """Validate a byte-frozen copy, without reading its original project."""
    if not isinstance(expected_digest, str) or not re.fullmatch("[0-9a-f]{64}", expected_digest):
        raise ValueError("Invalid snapshot digest")
    if _digest(_inventory(Path(directory).absolute())) != expected_digest:
        raise AccessDenied("Snapshot bytes no longer match the declared input")


def _cleanup(created: list[tuple[Path, tuple[int, int], bool]]) -> bool:
    complete = True
    for path, identity, directory in reversed(created):
        try:
            # Exact paths only: never recurse or follow a replaced export root.
            _safe_ancestors(path)
            if _identity(path) != identity:
                complete = False
                continue
            if directory:
                path.rmdir()
            else:
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    complete = False
                    continue
                path.chmod(stat.S_IREAD | stat.S_IWRITE)
                path.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            complete = False
    return complete


@dataclass
class SourceSnapshot:
    directory: Path
    digest: str
    manifest_path: Path
    file_count: int
    byte_count: int
    policy_fingerprint: str
    _access: AccessPolicy = field(repr=False)
    _created: list = field(repr=False)
    _closed: bool = field(default=False, repr=False)

    def check(self) -> None:
        """Check current read authorization and copy integrity, not source freshness."""
        if self._closed:
            raise AccessDenied("Snapshot has been disposed")
        self._access.refresh_if_changed()
        self._access.check_current()
        if self._access.fingerprint != self.policy_fingerprint:
            raise AccessDenied("Snapshot authorization changed")
        validate_snapshot(self.directory, self.digest)
        self._access.check_current()

    def close(self) -> None:
        if self._closed:
            return
        if not _cleanup(self._created):
            raise SnapshotCleanupPending("Snapshot cleanup incomplete; exports require local attention")
        self._closed = True

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        self.close()


def prepare_snapshot(access: AccessPolicy, destination: Path, *, paths: list[str] | tuple[str, ...],
                     max_files: int, max_bytes: int, max_file_bytes: int) -> SourceSnapshot:
    """Export exactly the declared permitted files, with explicit task limits.

    No target module is imported. Denied necessary inputs cause failure, rather
    than silently creating a partial execution environment. No model use is granted.
    """
    for value, ceiling in ((max_files, MAX_FILES), (max_bytes, MAX_BYTES),
                           (max_file_bytes, MAX_FILE_BYTES)):
        if type(value) is not int or not 0 < value <= ceiling:
            raise ValueError("Snapshot limits must be explicit positive integers within supported bounds")
    if (not isinstance(paths, (list, tuple)) or not paths or len(paths) > max_files
            or len({_name(name).casefold() for name in paths}) != len(paths)):
        raise ValueError("Invalid snapshot input list")
    destination = Path(destination).expanduser().absolute()
    _safe_ancestors(destination)
    destination = destination.resolve()
    if (destination.is_relative_to(access.root) or access.root.is_relative_to(destination)
            or destination.exists() or not destination.parent.is_dir()):
        raise ValueError("Snapshot needs a new directory outside the source tree")
    access.refresh_if_changed()
    if not access.confirmed or access.issues:
        raise AccessDenied("Snapshot requires a confirmed readable scope")
    fingerprint = access.fingerprint
    created, rows, total = [], [], 0

    def mkdir(path):
        _safe_ancestors(path)
        path.mkdir()
        created.append((path, _identity(path), True))

    def write(path, data):
        _safe_ancestors(path)
        with path.open("xb") as stream:
            created.append((path, _identity(path), False))
            stream.write(data)

    try:
        mkdir(destination)
        directory = destination / "files"
        mkdir(directory)
        for relative in sorted(paths):
            # AccessPolicy denies credentials, Git/user exclusions and aliases
            # before opening bytes, and checks its live registry on both sides.
            data = access.read_bytes(relative, limit=max_file_bytes)
            total += len(data)
            if total > max_bytes:
                raise ValueError("Snapshot task byte budget exceeded")
            target = directory / relative
            for parent in reversed(target.parent.parents):
                if parent.is_relative_to(directory) and not parent.exists():
                    mkdir(parent)
            if not target.parent.exists():
                mkdir(target.parent)
            write(target, data)
            rows.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        # Re-read declared inputs to detect ordinary source drift during export.
        # This is not atomic filesystem capture or proof against arbitrary ABA
        # edits. Excluded bytes remain unread throughout.
        for row in rows:
            current = access.read_bytes(row["path"], limit=max_file_bytes)
            if hashlib.sha256(current).hexdigest() != row["sha256"]:
                raise AccessDenied("Source changed while exporting snapshot")
        access.refresh_if_changed()
        if access.fingerprint != fingerprint or access.issues:
            raise AccessDenied("Snapshot scope changed during export")
        digest = _digest(rows)
        manifest_path = destination / "manifest.json"
        manifest = {"schema_version": 1, "kind": "local-execution-snapshot",
            "content_sha256": digest, "policy_fingerprint": fingerprint,
            "files": rows, "model_use_authorized": False,
            "source_freshness_after_export": "not_asserted"}
        write(manifest_path, json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        snapshot = SourceSnapshot(directory, digest, manifest_path, len(rows), total,
                                  fingerprint, access, created)
        snapshot.check()
        return snapshot
    except BaseException:
        if not _cleanup(created):
            raise SnapshotCleanupPending("Snapshot export failed with cleanup pending") from None
        raise
