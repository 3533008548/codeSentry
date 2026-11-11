"""Permission-scoped local Git comparisons and two-sided Python import impact.

Only metadata plumbing and explicitly authorized raw blobs are read. A private
Git directory supplies trusted configuration, so repository config/includes,
filters, hooks, external diff, submodules and network helpers are not used.
The graph describes declared imports, not observed calls or a reviewed gate.
"""
from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.access.policy import is_link


PYTHON = {".py", ".pyi"}
CONFIG_NAMES = {"pyproject.toml", "setup.cfg", "setup.py", "package.json", "package-lock.json",
    "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock",
    ".gitignore", ".gitattributes", "Dockerfile", "docker-compose.yml", "docker-compose.yaml"}
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


@dataclass(frozen=True)
class ChangeLimits:
    max_paths: int = 5000
    max_files: int = 1000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_git_output_bytes: int = 4 * 1024 * 1024
    max_metadata_entries: int = 20000
    max_seconds: float = 30

    def __post_init__(self):
        values = asdict(self)
        if any(type(value) is not int or value <= 0 for key, value in values.items() if key != "max_seconds"):
            raise ValueError("change limits must be positive integers")
        if (type(self.max_seconds) not in (int, float) or not math.isfinite(self.max_seconds)
                or not 0 < self.max_seconds <= 120 or self.max_paths > 20000 or self.max_files > 5000
                or self.max_file_bytes > 8*1024*1024 or self.max_total_bytes > 128*1024*1024
                or self.max_git_output_bytes > 16*1024*1024 or self.max_metadata_entries > 100000):
            raise ValueError("change limits exceed the supported scope")


class _Unavailable(ValueError):
    pass


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _safe(path: Path, *, directory=False):
    for component in reversed((path, *path.parents)):
        if is_link(component):
            raise _Unavailable("git_metadata_redirected")
    metadata = path.lstat()
    if directory:
        valid = stat.S_ISDIR(metadata.st_mode)
    else:
        valid = stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    if not valid:
        raise _Unavailable("git_metadata_not_regular")
    return metadata


def _bounded_process(argv: list[str], *, cwd: Path, env: dict, payload: bytes | None,
                     timeout: float, maximum: int) -> bytes:
    """Drain both pipes while enforcing output and wall-clock bounds."""
    process = subprocess.Popen(argv, cwd=cwd, env=env, shell=False,
        stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    output, errors, exceeded = bytearray(), bytearray(), threading.Event()

    def drain(stream, destination, limit):
        try:
            while chunk := stream.read(65536):
                remaining = max(0, limit + 1 - len(destination))
                destination.extend(chunk[:remaining])
                if len(destination) > limit:
                    exceeded.set()
                    process.kill()
                    break
        finally:
            stream.close()

    def send():
        try:
            process.stdin.write(payload)
        except (OSError, BrokenPipeError):
            pass
        finally:
            process.stdin.close()

    threads = [threading.Thread(target=drain, args=(process.stdout, output, maximum), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, errors, 65536), daemon=True)]
    if payload is not None:
        threads.append(threading.Thread(target=send, daemon=True))
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=max(.001, timeout))
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise _Unavailable("git_timeout") from error
    finally:
        for thread in threads:
            thread.join(timeout=1)
    if exceeded.is_set():
        raise _Unavailable("git_output_limit")
    if process.returncode != 0:
        raise _Unavailable("git_command_failed")
    return bytes(output)


class _Repository:
    def __init__(self, access, limits, deadline, temporary, git_executable=None):
        self.access, self.limits, self.deadline = access, limits, deadline
        self.root, self.directory = access.root, access.root / ".git"
        _safe(self.directory, directory=True)  # .git files/linked worktrees are unsupported.
        self.objects = self.directory / "objects"
        _safe(self.objects, directory=True)
        for name in ("commondir", "shallow", "objects/info/alternates", "objects/info/http-alternates"):
            candidate = self.directory / name
            if candidate.exists() or is_link(candidate):
                raise _Unavailable("git_linked_alternate_or_shallow_unsupported")
        self.object_state = self._object_state()
        self.metadata = {}
        self.index = self.directory / "index"
        if self.index.exists() or is_link(self.index):
            self._read_metadata(self.index, limit=8*1024*1024)
        selected = git_executable if git_executable is not None else shutil.which("git")
        if selected is None or not Path(selected).is_absolute():
            raise _Unavailable("git_executable_unavailable")
        executable = Path(selected).resolve(strict=True)
        if (not executable.is_file() or executable.is_relative_to(self.root)
                or not os.access(executable, os.X_OK)
                or (os.name == "nt" and executable.suffix.casefold() != ".exe")):
            raise _Unavailable("git_executable_unavailable")
        self.git = str(executable)
        self.view = temporary
        (self.view / "objects").mkdir()
        (self.view / "refs").mkdir()
        (self.view / "HEAD").write_text("ref: refs/heads/codesentry\n", encoding="ascii")
        self.format = None

    def _object_state(self):
        state, pending = {}, [self.objects]
        while pending:
            self.time_check()
            folder = pending.pop()
            _safe(folder, directory=True)
            with os.scandir(folder) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    if len(state) >= self.limits.max_metadata_entries:
                        raise _Unavailable("git_metadata_limit")
                    if is_link(path):
                        raise _Unavailable("git_objects_redirected")
                    metadata = path.lstat()
                    state[path.relative_to(self.objects).as_posix()] = _identity(metadata)
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(path)
                    elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise _Unavailable("git_objects_alias_or_special_file")
        return state

    def time_check(self):
        if time.monotonic() >= self.deadline:
            raise _Unavailable("analysis_time_limit")

    def _read_metadata(self, path, *, limit=1024*1024):
        if not path.is_relative_to(self.directory):
            raise _Unavailable("git_metadata_outside_repository")
        before = _safe(path)
        if before.st_size > limit:
            raise _Unavailable("git_metadata_limit")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if any(getattr(opened, key) != getattr(before, key) for key in
                   ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")):
                raise _Unavailable("git_metadata_changed")
            raw = stream.read(limit + 1)
        if len(raw) > limit or _identity(before) != _identity(_safe(path)):
            raise _Unavailable("git_metadata_changed")
        digest = _sha(raw)
        previous = self.metadata.get(path)
        if previous is not None and previous != digest:
            raise _Unavailable("git_metadata_changed")
        self.metadata[path] = digest
        return raw

    def resolve(self, reference):
        if reference == "HEAD":
            value = self._read_metadata(self.directory / "HEAD").decode("ascii").strip()
            if value.startswith("ref: "):
                relative = value[5:]
                if (not re.fullmatch(r"refs/(?:heads|tags)/[A-Za-z0-9_./-]+", relative)
                        or any(part in {"", ".", ".."} for part in relative.split("/"))):
                    raise _Unavailable("git_head_reference_unsupported")
                path = self.directory / relative
                if path.exists() or is_link(path):
                    value = self._read_metadata(path).decode("ascii").strip()
                else:
                    packed = self._read_metadata(self.directory / "packed-refs").decode("ascii")
                    values = [line.split(" ", 1)[0] for line in packed.splitlines() if line.endswith(" " + relative)]
                    if len(values) != 1:
                        raise _Unavailable("git_base_unavailable")
                    value = values[0]
        elif isinstance(reference, str) and OID.fullmatch(reference):
            value = reference
        else:
            raise _Unavailable("git_reference_unsupported")
        if not OID.fullmatch(value):
            raise _Unavailable("git_base_unavailable")
        object_format = "sha256" if len(value) == 64 else "sha1"
        if self.format is not None and self.format != object_format:
            raise _Unavailable("git_object_format_mismatch")
        if self.format is None:
            self.format = object_format
            config = "[core]\nrepositoryformatversion = 0\nbare = false\n"
            if object_format == "sha256":
                config = "[core]\nrepositoryformatversion = 1\nbare = false\n[extensions]\nobjectFormat = sha256\n"
            (self.view / "config").write_text(config, encoding="ascii")
        resolved = self.run(["rev-parse", "--verify", "--end-of-options", value + "^{commit}"]).decode("ascii").strip()
        if not OID.fullmatch(resolved):
            raise _Unavailable("git_base_unavailable")
        return resolved

    def guard(self):
        self.time_check()
        self.access.check_current()
        _safe(self.directory, directory=True)
        if self._object_state() != self.object_state:
            raise _Unavailable("git_objects_changed")
        for path, digest in tuple(self.metadata.items()):
            if _sha(self._read_metadata(path, limit=8*1024*1024)) != digest:
                raise _Unavailable("git_metadata_changed")

    def run(self, arguments, *, payload=None, maximum=None):
        self.guard()
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1",
            GIT_ATTR_NOSYSTEM="1", GIT_CONFIG_COUNT="0", GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
            GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_LITERAL_PATHSPECS="1",
            GIT_OBJECT_DIRECTORY=str(self.objects), GIT_INDEX_FILE=str(self.index))
        argv = [self.git, "--no-pager", "--no-replace-objects", "--git-dir=" + str(self.view),
            "--work-tree=" + str(self.root), "-c", "core.hooksPath=" + os.devnull,
            "-c", "core.fsmonitor=false", "-c", "core.attributesFile=" + os.devnull,
            "-c", "protocol.allow=never", *arguments]
        result = _bounded_process(argv, cwd=self.view, env=env, payload=payload,
            timeout=self.deadline-time.monotonic(), maximum=maximum or self.limits.max_git_output_bytes)
        self.guard()
        return result


def _language(path):
    name = Path(path).name
    if name in CONFIG_NAMES or name.startswith(("tsconfig", "requirements")) or path.startswith(".github/workflows/"):
        return "configuration"
    return "python" if Path(path).suffix.casefold() in PYTHON else "unsupported"


def _parse_inventory(raw, *, index, issues):
    result = {}
    for row in raw.split(b"\0"):
        if not row:
            continue
        try:
            header, name = row.split(b"\t", 1)
            path = name.decode("utf-8", errors="strict")
            if ("\\" in path or ":" in path or path.startswith("/")
                    or any(part in {"", ".", ".."} for part in path.split("/"))):
                raise ValueError()
            mode, kind_or_oid, oid_or_stage = header.decode("ascii").split(" ")
            oid, stage = (kind_or_oid, oid_or_stage) if index else (oid_or_stage, "0")
            if not OID.fullmatch(oid) or not re.fullmatch(r"[0-7]{6}", mode):
                raise ValueError()
            if stage != "0":
                issues.append({"file": path, "status": "index_conflict", "message": "暂存区有未解决的合并冲突。"})
                result[path] = {"mode": "conflict", "oid": None, "data": None}
            elif path not in result or result[path]["mode"] != "conflict":
                result[path] = {"mode": mode, "oid": oid, "data": None}
        except (ValueError, UnicodeError):
            issues.append({"file": ".", "status": "invalid_git_path", "message": "Git 名称或元数据编码无法安全解析。"})
    return result


def _load_blobs(repo, versions, access, limits, guard, issues):
    by_oid = defaultdict(set)
    for version in versions:
        for path, entry in version.items():
            if entry["mode"] not in {"100644", "100755"}:
                issues.append({"file": path, "status": "historical_entry_not_regular", "message": "历史链接、子模块或冲突项不读取内容。"})
            elif entry["oid"]:
                guard(path)
                by_oid[entry["oid"]].add(path)
    if not by_oid:
        return 0
    identifiers = sorted(by_oid)
    request = ("\n".join(identifiers) + "\n").encode("ascii")
    metadata = repo.run(["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], payload=request)
    sizes, total = {}, 0
    for row in metadata.decode("ascii").splitlines():
        values = row.split(" ")
        if len(values) != 3 or values[0] not in by_oid or values[1] != "blob" or not values[2].isdigit():
            raise _Unavailable("git_blob_unavailable")
        oid, size = values[0], int(values[2])
        if size > limits.max_file_bytes or total + size > limits.max_total_bytes:
            for path in by_oid[oid]:
                issues.append({"file": path, "status": "blob_budget_exhausted", "message": "历史内容达到文件或总字节限额。"})
            continue
        sizes[oid], total = size, total + size
    if set(values[0] for values in (line.split(" ") for line in metadata.decode("ascii").splitlines())) != set(identifiers):
        raise _Unavailable("git_blob_metadata_incomplete")
    if not sizes:
        return 0
    for oid in sizes:
        for path in by_oid[oid]:
            guard(path)
    request = ("\n".join(sorted(sizes)) + "\n").encode("ascii")
    raw = repo.run(["cat-file", "--batch"], payload=request,
                   maximum=total + len(sizes)*160 + 1)
    blobs, offset = {}, 0
    for requested in sorted(sizes):
        end = raw.find(b"\n", offset)
        if end < 0:
            raise _Unavailable("git_blob_output_incomplete")
        header = raw[offset:end].decode("ascii").split(" ")
        if header != [requested, "blob", str(sizes[requested])]:
            raise _Unavailable("git_blob_identity_mismatch")
        start, end = end + 1, end + 1 + sizes[requested]
        if end >= len(raw) or raw[end:end+1] != b"\n":
            raise _Unavailable("git_blob_output_incomplete")
        data = raw[start:end]
        algorithm = hashlib.sha256 if len(requested) == 64 else hashlib.sha1
        if algorithm(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() != requested:
            raise _Unavailable("git_blob_identity_mismatch")
        blobs[requested], offset = data, end + 1
    if offset != len(raw):
        raise _Unavailable("git_blob_output_incomplete")
    for version in versions:
        for path, entry in version.items():
            if entry["oid"] in blobs:
                guard(path)
                entry["data"] = blobs[entry["oid"]]
    return total


def _module(path):
    parts = path.rsplit(".", 1)[0].split("/")
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _graph(version, *, side, known_modules, issues, deadline):
    modules = defaultdict(list)
    graph = {path: set() for path in version if _language(path) == "python"}
    parsed, binding_trees = 0, {}
    for path in graph:
        modules[_module(path)].append(path)
    for path in graph:
        if time.monotonic() >= deadline:
            issues.append({"file": ".", "status": "analysis_time_limit", "message": "影响图达到时间限额。"})
            break
        data = version[path]["data"]
        if data is None:
            continue
        try:
            tree = ast.parse(data, filename=path)
        except (SyntaxError, UnicodeError, ValueError, RecursionError):
            issues.append({"file": path, "status": "python_parse_incomplete", "side": side, "message": "该侧 Python 语法或编码无法解析。"})
            continue
        parsed += 1
        package = _module(path).split(".") if Path(path).stem == "__init__" else _module(path).split(".")[:-1]
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    if node.level > len(package):
                        issues.append({"file": path, "status": "relative_import_unresolved", "side": side, "message": "相对导入超出已知包范围。"})
                        continue
                    names = [".".join(package[:len(package)-node.level+1] + ([node.module] if node.module else []))]
                elif node.module:
                    names = [node.module]
            for name in names:
                candidates = modules.get(name, [])
                if len(candidates) == 1:
                    graph[path].add(candidates[0])
                elif len(candidates) > 1 or name in known_modules:
                    issues.append({"file": path, "status": "local_import_unresolved", "side": side, "message": "本地导入目标缺失或不唯一。"})
                if isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        submodule = name + "." + alias.name if name else alias.name
                        submodules = modules.get(submodule, [])
                        ambiguous = len(submodules) > 1
                        if len(submodules) == 1:
                            # A declared from-import can resolve a package
                            # member or its submodule fallback. Include the
                            # known submodule conservatively, never omit it.
                            graph[path].add(submodules[0])
                            for parent in candidates:
                                if parent not in binding_trees:
                                    try:
                                        binding_trees[parent] = ast.parse(version[parent]["data"])
                                    except (SyntaxError, TypeError, UnicodeError, ValueError, RecursionError):
                                        binding_trees[parent] = None
                                parent_tree = binding_trees[parent]
                                if parent_tree is None or any(
                                        (isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                                         and item.name in {alias.name, "__getattr__"})
                                        or (isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store) and item.id == alias.name)
                                        or (isinstance(item, ast.alias) and (item.asname or item.name.split(".")[0]) in {alias.name, "*"})
                                        for item in ast.walk(parent_tree)):
                                    ambiguous = True
                        elif submodule in known_modules or (node.module is None and not candidates):
                            ambiguous = True
                        if ambiguous:
                            issues.append({"file": path, "status": "from_import_binding_unknown", "side": side,
                                "message": "包成员与子模块绑定不唯一；影响面保守包含已知子模块。"})
                for length in range(1, len(name.split("."))):
                    parent = ".".join(name.split(".")[:length])
                    initializers = [candidate for candidate in modules.get(parent, []) if Path(candidate).stem == "__init__"]
                    if len(initializers) == 1:
                        graph[path].add(initializers[0])
        graph[path].discard(path)
    return graph, parsed


def _impact(graph, direct, *, all_paths, configuration_changed):
    if configuration_changed:
        affected = set(all_paths)
    else:
        reverse = defaultdict(set)
        for source, targets in graph.items():
            for target in targets:
                reverse[target].add(source)
        affected, pending = set(direct), deque(sorted(direct))
        while pending:
            for dependent in sorted(reverse[pending.popleft()]):
                if dependent not in affected:
                    affected.add(dependent)
                    pending.append(dependent)
    return {"direct": sorted(direct), "dependents": sorted(affected - set(direct)),
            "edges": sum(len(targets) for targets in graph.values())}


def _compare(before, after, layer, index_paths):
    rows = []
    for path in sorted(before.keys() | after.keys()):
        old, new = before.get(path), after.get(path)
        if old and new and old["mode"] == new["mode"]:
            if old["oid"] and old["oid"] == new["oid"]:
                continue
            if old["data"] is not None and new["data"] is not None and old["data"] == new["data"]:
                continue
            if old["data"] is None or new["data"] is None:
                if not old["oid"] or not new["oid"]:
                    continue  # Unknown content is reported by coverage/issues, never as unchanged.
        status = "added" if old is None else "deleted" if new is None else "type_changed" if old["mode"] != new["mode"] else "modified"
        rows.append({"old_path": path if old else None, "new_path": path if new else None,
            "status": status, "layer": layer, "language": _language(path),
            "untracked": new is not None and path not in index_paths and layer in {"combined", "unstaged"},
            "old_sha256": _sha(old["data"]) if old and old["data"] is not None else None,
            "new_sha256": _sha(new["data"]) if new and new["data"] is not None else None})
    return rows


def analyze_changes(access: AccessPolicy, *, base_ref="HEAD", comparison="working_tree",
                    target_ref=None, limits: ChangeLimits | None = None,
                    git_executable: str | Path | None = None) -> dict:
    # Only the trusted caller can choose this executable; repository settings or
    # CODESENTRY_GIT are deliberately not consulted by this analysis module.
    limits = limits or ChangeLimits()
    access.refresh_if_changed()
    if not access.confirmed:
        raise AccessDenied("请先确认文件访问范围")
    initial_access, deadline = access.fingerprint, time.monotonic() + limits.max_seconds
    issues, before, after, index, current = [], {}, {}, {}, {}
    base_sha = target_sha = None
    excluded, allowed, total_bytes = set(), set(), 0
    unavailable = False

    def guard(path=None):
        access.refresh_if_changed()
        access.check_current()
        if access.fingerprint != initial_access:
            raise AccessDenied("变更分析期间文件访问范围变化，输出已丢弃")
        if path is not None and access.decision(path)["mode"] == "exclude":
            raise AccessDenied("变更分析期间路径访问范围变化，输出已丢弃")

    def inventory():
        result = set()
        for path, _, directory, decision in access.walk():
            if directory:
                continue
            try:
                path.encode("utf-8", errors="strict")
            except UnicodeError:
                issues.append({"file": ".", "status": "invalid_working_path", "message": "文件名编码无法安全解析。"})
                continue
            if decision["mode"] != "exclude":
                result.add(path)
            else:
                excluded.add(path)
        return result

    try:
        if not isinstance(comparison, str) or comparison not in {"working_tree", "staged", "commit"} or (comparison == "commit" and target_ref is None):
            raise _Unavailable("comparison_unsupported_or_target_missing")
        if comparison != "commit" and target_ref is not None:
            raise _Unavailable("target_only_supported_for_commit")
        temporary_base = Path(tempfile.gettempdir()).resolve()
        if temporary_base.is_relative_to(access.root):
            raise _Unavailable("trusted_temporary_directory_inside_project")
        with tempfile.TemporaryDirectory(prefix="codesentry-git-metadata-") as temporary:
            repo = _Repository(access, limits, deadline, Path(temporary), git_executable=git_executable)
            base_sha = repo.resolve(base_ref)
            before = _parse_inventory(repo.run(["ls-tree", "-r", "-z", "--full-tree", base_sha]), index=False, issues=issues)
            if comparison == "commit":
                target_sha = repo.resolve(target_ref)
                after = _parse_inventory(repo.run(["ls-tree", "-r", "-z", "--full-tree", target_sha]), index=False, issues=issues)
            else:
                index = _parse_inventory(repo.run(["ls-files", "--stage", "-z"]), index=True, issues=issues)
                after = index
            initial_inventory = inventory() if comparison == "working_tree" else set()
            paths = sorted(before.keys() | after.keys() | initial_inventory)
            if len(paths) > limits.max_paths:
                issues.append({"file": ".", "status": "path_budget_exhausted", "message": "路径清单达到限额，剩余范围未评估。"})
                paths = paths[:limits.max_paths]
            for path in paths:
                if access.decision(path)["mode"] == "exclude":
                    excluded.add(path)
                else:
                    allowed.add(path)
            if len(allowed) > limits.max_files:
                issues.append({"file": ".", "status": "file_budget_exhausted", "message": "文件数量达到限额，剩余范围未评估。"})
                allowed = set(sorted(allowed)[:limits.max_files])
            issues[:] = [issue for issue in issues if issue["file"] == "." or issue["file"] in allowed]
            before = {path: value for path, value in before.items() if path in allowed}
            after = {path: value for path, value in after.items() if path in allowed}
            if comparison != "commit":
                index = after
            total_bytes += _load_blobs(repo, [before, after], access, limits, guard, issues)
            if comparison == "working_tree":
                for path in sorted(initial_inventory & allowed):
                    repo.time_check()
                    guard(path)
                    mode = index.get(path, before.get(path, {})).get("mode", "100644")
                    current[path] = {"mode": mode if mode in {"100644", "100755"} else "100644", "oid": None, "data": None}
                    remaining = limits.max_total_bytes - total_bytes
                    if remaining <= 0:
                        issues.append({"file": path, "status": "working_budget_exhausted", "message": "工作树读取达到总字节限额。"})
                        continue
                    try:
                        raw = access.read_bytes(path, min(limits.max_file_bytes, remaining))
                        current[path]["data"] = raw
                        total_bytes += len(raw)
                    except (OSError, ValueError) as error:
                        if isinstance(error, AccessDenied):
                            raise
                        issues.append({"file": path, "status": "working_input_incomplete", "message": "工作树内容超过限额或无法读取。"})
                after = current
            guard()
            for path in allowed:
                guard(path)
            repo.guard()
            if comparison == "working_tree":
                if inventory() != initial_inventory:
                    issues.append({"file": ".", "status": "source_inventory_changed", "message": "工作树文件清单在分析中变化。"})
                for path, entry in current.items():
                    repo.time_check()
                    if entry["data"] is not None and access.read_bytes(path, limits.max_file_bytes) != entry["data"]:
                        issues.append({"file": path, "status": "source_changed_during_analysis", "message": "工作树内容在分析中变化。"})
    except AccessDenied:
        raise
    except (_Unavailable, OSError, UnicodeError, ValueError) as error:
        unavailable = True
        before, after, index, current = {}, {}, {}, {}
        issues.append({"file": ".", "status": str(error) if isinstance(error, _Unavailable) else "git_input_unavailable",
                       "message": "Git 基点、元数据或读取条件不可用；没有运行仓库配置，也未选择替代基点。"})

    primary_layer = "combined" if comparison == "working_tree" else "staged" if comparison == "staged" else "commit"
    changes = _compare(before, after, primary_layer, set(index))
    if comparison == "working_tree" and not unavailable:
        changes += _compare(before, index, "staged", set(index)) + _compare(index, after, "unstaged", set(index))
    primary = [row for row in changes if row["layer"] == primary_layer]
    changed = {row["new_path"] or row["old_path"] for row in primary}
    for row in primary:
        if row["language"] == "unsupported":
            issues.append({"file": row["new_path"] or row["old_path"], "status": "changed_language_not_evaluated", "message": "该文件的变化已列出，但尚不支持其依赖影响分析。"})
    known_modules = {_module(path) for path in before.keys() | after.keys() if _language(path) == "python"}
    before_graph, before_count = _graph(before, side="before", known_modules=known_modules, issues=issues, deadline=deadline)
    after_graph, after_count = _graph(after, side="after", known_modules=known_modules, issues=issues, deadline=deadline)
    configuration_changed = any(row["language"] == "configuration" for row in primary)
    before_impact = _impact(before_graph, changed & before.keys(), all_paths=before, configuration_changed=configuration_changed)
    after_impact = _impact(after_graph, changed & after.keys(), all_paths=after, configuration_changed=configuration_changed)
    guard()
    if access.issues:
        issues.append({"file": ".", "status": "access_scope_incomplete", "message": "文件访问范围仍有待确认或未完整枚举项。"})
    direct = sorted(set(before_impact["direct"]) | set(after_impact["direct"]))
    dependents = sorted((set(before_impact["dependents"]) | set(after_impact["dependents"])) - set(direct))
    return {"schema_version": 1, "mode": "change_scope", "gate_status": "not_evaluated",
        "change_status": "unavailable" if unavailable else "incomplete" if issues else "report_only",
        "comparison": comparison, "base_sha": base_sha, "target_sha": target_sha,
        "comparison_semantics": "raw_bytes_without_git_filters", "merge_base_evaluated": False,
        "rename_detection": "not_performed_delete_add_preserved", "changes": changes,
        "impact": {"before": before_impact, "after": after_impact, "direct": direct, "dependents": dependents,
            "configuration_changed": configuration_changed, "call_analysis": "not_evaluated",
            "import_binding_semantics": "conservative declared imports; member/submodule ambiguity is incomplete",
            "dependency_model": "declared_python_imports_repository_root_only", "whole_repository_evaluated": False},
        "coverage": {"allowed_paths": len(allowed), "before_python": before_count, "after_python": after_count,
            "excluded_paths": len(excluded), "unsupported_paths": sum(_language(path) == "unsupported" for path in allowed),
            "permissions_limited": bool(excluded or access.to_dict()["restricted"]),
            "within_scope_complete": not issues and not unavailable, "whole_repository_evaluated": False,
            "bytes_read_for_evidence": total_bytes, "limits": asdict(limits)},
        "source_sha256": {path: _sha(entry["data"]) for path, entry in after.items()
                          if _language(path) == "python" and entry["data"] is not None},
        "issues": issues,
        "summary": {"changed_files": len(changed), "staged": sum(row["layer"] == "staged" for row in changes),
            "unstaged": sum(row["layer"] == "unstaged" and not row["untracked"] for row in changes),
            "untracked": sum(row["layer"] in {"combined", "unstaged"} and row["untracked"] for row in primary),
            "affected_files": len(set(direct) | set(dependents))},
        "formal_acceptance": {"passed": False, "reason": "local permission-scoped static change preview; no gate, PR merge-base or whole-repository review"}}
