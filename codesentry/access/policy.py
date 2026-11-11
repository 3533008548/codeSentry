"""One deny-first policy for source readers, environment readers and model input."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
from pathlib import Path, PureWindowsPath
import tokenize
from typing import Callable
from urllib.parse import unquote

from pathspec import GitIgnoreSpec

def is_link(path: Path) -> bool:
    # A fresh no-follow stat covers symlinks, junctions and other Windows
    # reparse points. Repeating the higher-level predicates only re-read the
    # same metadata; permission and path checks still run at every read point.
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(metadata, 'st_file_attributes', 0)
                    & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)))

MAX_RULE_BYTES = 128 * 1024
MAX_RULE_FILES = 512
MAX_DIRECTORIES = 10000
MAX_ENTRIES = 50000
HARD_DIRS = {".git", ".ssh", ".aws", ".azure", ".venv", "venv", "node_modules",
             "__pycache__", "dist", "build", ".pytest_cache", ".codesentry"}


class AccessDenied(PermissionError):
    """An application permission denied a read before opening file content."""


def _spec(lines):
    return GitIgnoreSpec.from_lines([line.casefold() if os.name == 'nt' else line for line in lines], backend="simple")


def _match_path(value: str) -> str:
    return value.casefold() if os.name == 'nt' else value


def validate_settings(settings: dict | None = None) -> dict:
    settings = {} if settings is None else settings
    if not isinstance(settings, dict) or set(settings) - {"respect_gitignore", "exclude", "local_only", "model_scope"}:
        raise ValueError("无效文件访问设置")
    respect = settings.get("respect_gitignore", True)
    if type(respect) is not bool:
        raise ValueError("遵守.gitignore必须为布尔值")
    result = {"respect_gitignore": respect}
    for key in ("exclude", "local_only", "model_scope"):
        values = settings.get(key, [])
        if not isinstance(values, list) or len(values) > 256:
            raise ValueError("每组文件规则最多256条")
        normalized = []
        for value in values:
            if not isinstance(value, str) or not value.strip() or len(value) > 512:
                raise ValueError("文件规则必须是非空相对路径或匹配模式")
            value = value.strip().replace("\\", "/")
            if (value.startswith(("!", "#", "/")) or PureWindowsPath(value).drive
                    or "\0" in value or ":" in value or unquote(value) != value
                    or any(part in {".", "..", ""} for part in value.rstrip("/").split("/"))):
                raise ValueError("文件规则只接受工作空间相对路径，不能使用!、绝对路径或路径穿越")
            try:
                _spec([value])
            except Exception as error:
                raise ValueError("不支持的文件匹配规则") from error
            if value not in normalized:
                normalized.append(value)
        result[key] = normalized
    return result


def _relative(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise AccessDenied("无效文件路径")
    value = value.replace("\\", "/")
    if (value.startswith("/") or PureWindowsPath(value).drive or unquote(value) != value
            or "\0" in value or ":" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise AccessDenied("只允许工作空间内的严格相对路径")
    return value


def is_managed_index_name(name: str) -> bool:
    return bool(re.fullmatch(r'.+\.[0-9a-f]{64}\.json(?:\.access\.json)?', name.casefold()))


def _hard(relative: str, *, managed: bool = False) -> bool:
    parts = [part.casefold() for part in relative.split("/")]
    scoped_cache = (len(parts) >= 3 and parts[-3] == 'scopes'
                    and bool(re.fullmatch(r'[0-9a-f]{64}', parts[-2]))
                    and parts[-1] in {'parse_cache.json', 'parse_cache.access.json'})
    return (scoped_cache or not managed and any(is_managed_index_name(part) for part in parts)
            or any(part.endswith('.codesentry-index-tmp') for part in parts)
            or any(part in HARD_DIRS or part == ".env" or part.startswith(".env.")
               or part.startswith(("credentials", "secrets", "id_rsa", "id_ed25519"))
               or part.endswith((".pem", ".key", ".p12", ".pfx")) for part in parts))


class AccessPolicy:
    def __init__(self, root: Path, settings: dict | None = None, *, confirmed: bool = True,
                 read_guard: Callable[[], None] | None = None):
        self.root = Path(root).expanduser().resolve()
        self.settings = validate_settings(settings)
        self.confirmed = confirmed
        self.read_guard = read_guard
        self._exclude = _spec(self.settings["exclude"])
        self._local = _spec(self.settings["local_only"])
        self._model = _spec(self.settings["model_scope"])
        self._rules: dict[str, dict] = {}
        self._directory_signatures: dict[str, tuple] = {}
        self.issues: list[dict] = []
        self._check_root()
        # Only directory entries and permitted .gitignore controls are read here.
        if confirmed:
            self.refresh()

    def check_current(self) -> None:
        if self.read_guard is not None:
            self.read_guard()

    def _check_root(self):
        if not self.root.is_dir() or is_link(self.root) or self.root.resolve() != self.root:
            raise AccessDenied("工作空间目录不存在或已被重定向")

    def _safe_path(self, relative: str) -> Path:
        self._check_root()
        path = self.root
        for part in relative.split("/"):
            path = path / part
            if is_link(path):
                raise AccessDenied("不读取链接或重定向的文件")
        if not path.resolve().is_relative_to(self.root):
            raise AccessDenied("文件不在当前工作空间")
        if path.is_file() and path.stat().st_nlink > 1:
            raise AccessDenied('不读取具有多个硬链接名称的文件，无法确认所有别名的权限')
        return path

    def _base_deny(self, relative: str, is_dir: bool = False, *, managed: bool = False) -> str | None:
        if not self.confirmed:
            return "尚未确认文件访问范围"
        if any(issue['status'] == 'access_scope_limit' for issue in self.issues):
            return '文件范围超过安全枚举上限，需缩小范围后确认'
        if _hard(relative, managed=managed):
            return "系统默认排除敏感文件或产物目录"
        parts = relative.split("/")
        for index in range(1, len(parts) + 1):
            candidate = "/".join(parts[:index])
            directory = index < len(parts) or is_dir
            if self._exclude.match_file(_match_path(candidate + ("/" if directory else ""))):
                return "用户设置为完全排除"
        return None

    def _load_rule(self, directory: str, parent_specs: list[tuple[str, GitIgnoreSpec]]) -> dict:
        relative = (directory + "/" if directory else "") + ".gitignore"
        path = self.root / relative
        try:
            exists = path.exists() or is_link(path)
            metadata = path.lstat() if exists else None
            signature = (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) if metadata else None
        except OSError:
            signature = "unreadable"
            exists = True
        denied = self._base_deny(relative)
        if denied is None:
            ignored = False
            for base, spec in parent_specs:
                target = relative[len(base) + 1:] if base else relative
                match = spec.check_file(_match_path(target)).include
                if match is not None:
                    ignored = match
            if ignored:
                denied = "父级.gitignore排除了该规则文件"
        previous = self._rules.get(directory)
        if previous is not None and previous["signature"] == signature and previous.get('denied') == denied:
            return previous
        record = {"signature": signature, "spec": None, "digest": "missing", "error": None, 'denied': denied}
        self._rules[directory] = record
        if not exists:
            return record
        if denied:
            record.update(digest="denied", error="忽略规则文件被禁止读取，需确认访问范围")
            return record
        self.check_current()
        try:
            if len([item for item in self._rules.values() if item["digest"] != "missing"]) > MAX_RULE_FILES:
                raise ValueError("忽略规则文件数量超过上限")
            safe = self._safe_path(relative)
            with safe.open("rb") as stream:
                data = stream.read(MAX_RULE_BYTES + 1)
            self.check_current()
            if len(data) > MAX_RULE_BYTES:
                raise ValueError("忽略规则文件超过大小上限")
            lines = data.decode("utf-8-sig").splitlines()
            existing = sum(len(item['spec'].patterns) for item in self._rules.values() if item['spec'] is not None)
            if len(lines) > 4096 or existing + len(lines) > 8192:
                raise ValueError('忽略匹配规则数量超过上限')
            record.update(spec=_spec(lines), digest=hashlib.sha256(data).hexdigest())
        except (OSError, UnicodeError, ValueError) as error:
            record.update(digest="unreadable", error="忽略规则无法安全读取或匹配，需确认访问范围")
        return record

    def decision(self, relative: str, is_dir: bool = False) -> dict:
        return self._decision(relative, is_dir)

    def managed_artifact_decision(self, relative: str) -> dict:
        if not isinstance(relative, str) or '/' in relative or '\\' in relative or not is_managed_index_name(relative):
            return {'mode': 'exclude', 'reason': '不属于当前应用受管索引文件'}
        current = self.fingerprint
        if not relative.casefold().endswith((f'.{current}.json', f'.{current}.json.access.json')):
            return {'mode': 'exclude', 'reason': '受管索引不是当前访问范围的产物'}
        return self._decision(relative, managed=True)

    def _decision(self, relative: str, is_dir: bool = False, *, managed: bool = False) -> dict:
        try:
            relative = _relative(relative)
            reason = self._base_deny(relative, is_dir, managed=managed)
            if reason:
                return {"mode": "exclude", "reason": reason}
            path = self._safe_path(relative)
            canonical = path.resolve().relative_to(self.root).as_posix()
            if canonical != relative:
                relative = _relative(canonical)
                reason = self._base_deny(relative, is_dir, managed=managed)
                if reason:
                    return {"mode": "exclude", "reason": reason}
            if self.settings["respect_gitignore"]:
                specs: list[tuple[str, GitIgnoreSpec]] = []
                parts = relative.split("/")
                for index in range(len(parts)):
                    base = "/".join(parts[:index])
                    record = self._load_rule(base, specs)
                    if record["error"]:
                        return {"mode": "exclude", "reason": record["error"]}
                    if record["spec"] is not None:
                        specs.append((base, record["spec"]))
                    candidate = "/".join(parts[:index + 1])
                    directory = index + 1 < len(parts) or is_dir
                    ignored = False
                    for spec_base, spec in specs:
                        target = candidate[len(spec_base) + 1:] if spec_base else candidate
                        match = spec.check_file(_match_path(target + ("/" if directory else ""))).include
                        if match is not None:
                            ignored = match
                    if ignored:
                        return {"mode": "exclude", "reason": "匹配.gitignore规则"}
            if self._local.match_file(_match_path(relative + ("/" if is_dir else ""))):
                return {"mode": "local_only", "reason": "用户设置为仅限本地分析"}
            if self._model.match_file(_match_path(relative + ("/" if is_dir else ""))):
                return {"mode": "model_eligible", "reason": "模型可用候选，仍需具体服务和用途授权"}
            return {"mode": "local_only", "reason": "默认仅在本地分析"}
        except (OSError, ValueError) as error:
            return {"mode": "exclude", "reason": str(error)[:250]}

    def resolve(self, relative: str, require_file: bool = True) -> Path:
        relative = _relative(relative)
        decision = self.decision(relative, is_dir=not require_file)
        if decision["mode"] == "exclude":
            raise AccessDenied(decision["reason"])
        path = self._safe_path(relative)
        if require_file and not path.is_file():
            raise FileNotFoundError("文件不存在或不是普通文件")
        return path

    def read_bytes(self, relative: str, limit: int = 8 * 1024 * 1024) -> bytes:
        self.check_current()
        if type(limit) is not int or limit <= 0:
            raise ValueError("读取上限必须为正整数")
        path = self.resolve(relative)
        self._check_ancestor_controls(relative)
        path = self.resolve(relative)
        fingerprint = self.fingerprint
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("文件超过读取大小上限")
        self._check_ancestor_controls(relative)
        if self.resolve(relative) != path or self.fingerprint != fingerprint:
            raise AccessDenied("读取期间路径或权限变化")
        self.check_current()
        return data

    def read_text(self, relative: str, limit: int = 8 * 1024 * 1024) -> str:
        raw = self.read_bytes(relative, limit)
        encoding = tokenize.detect_encoding(io.BytesIO(raw).readline)[0] if relative.endswith((".py", ".pyi")) else "utf-8-sig"
        return raw.decode(encoding)

    def read_managed_text(self, relative: str, limit: int = 32 * 1024 * 1024) -> str:
        """IndexStore only: reserved artifact names still obey user/Git bans."""
        self.check_current()
        self._check_ancestor_controls(relative)
        if self.managed_artifact_decision(relative)['mode'] == 'exclude':
            raise AccessDenied('受管索引文件被当前用户权限排除')
        fingerprint = self.fingerprint
        path = self._safe_path(_relative(relative))
        with path.open('rb') as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('受管索引文件超过读取上限')
        self._check_ancestor_controls(relative)
        if self.managed_artifact_decision(relative)['mode'] == 'exclude' or fingerprint != self.fingerprint:
            raise AccessDenied('读取受管索引期间权限已变化')
        self.check_current()
        return data.decode('utf-8')

    def walk(self, *, file_filter: Callable[[str], bool] | None = None,
             descend_filter: Callable[[str], bool] | None = None):
        """Enumerate permitted scope, optionally narrowing a caller's search.

        Predicates receive workspace-relative names, never file contents. File
        filtering precedes expensive path decisions; directories always retain
        their permission decision before a caller can prune traversal. Entries
        still count against enumeration limits, even when a filter rejects
        them. These search filters do not change the global control scan or
        access fingerprint performed by refresh().
        """
        if file_filter is not None and not callable(file_filter):
            raise ValueError('文件过滤器必须可调用')
        if descend_filter is not None and not callable(descend_filter):
            raise ValueError('目录过滤器必须可调用')
        self._check_root()
        if not self.confirmed:
            return
        count = visited = 0
        pending = [self.root]
        while pending:
            parent = pending.pop()
            visited += 1
            if visited > MAX_DIRECTORIES:
                self._issue({"file": ".", "status": "access_scope_limit", "message": "目录枚举超过上限"})
                return
            try:
                with os.scandir(parent) as entries:
                    children = []
                    for entry in entries:
                        if count + len(children) >= MAX_ENTRIES:
                            self._issue({"file": ".", "status": "access_scope_limit", "message": "文件枚举超过上限"})
                            return
                        children.append(entry)
                    children.sort(key=lambda item: item.name)
            except OSError:
                self._issue({"file": parent.relative_to(self.root).as_posix(), "status": "access_scope_unreadable", "message": "目录项无法枚举"})
                continue
            for item in children:
                count += 1
                if count > MAX_ENTRIES:
                    self._issue({"file": ".", "status": "access_scope_limit", "message": "文件枚举超过上限"})
                    return
                path = Path(item.path)
                relative = path.relative_to(self.root).as_posix()
                directory = item.is_dir(follow_symlinks=False)
                if not directory and file_filter is not None and not file_filter(relative):
                    continue
                decision = self.decision(relative, is_dir=directory)
                yield relative, path, directory, decision
                if (directory and decision["mode"] != "exclude"
                        and (descend_filter is None or descend_filter(relative))):
                    pending.append(path)

    def _issue(self, issue: dict) -> None:
        if issue not in self.issues:
            self.issues.append(issue)

    def refresh(self):
        self.check_current()
        self._rules = {}
        self._directory_signatures = {}
        self.issues = []
        if self.confirmed:
            self._scan_controls()
        self.check_current()
        return self

    @staticmethod
    def _directory_signature(path: Path) -> tuple:
        metadata = path.lstat()
        return metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_mode

    def _scan_controls(self) -> None:
        """Inspect directories and rule files, never resolve every source file."""
        count = 0
        pending = [self.root]
        while pending:
            parent = pending.pop()
            if len(self._directory_signatures) >= MAX_DIRECTORIES:
                self._issue({'file': '.', 'status': 'access_scope_limit', 'message': '目录枚举超过上限'})
                return
            relative = parent.relative_to(self.root).as_posix()
            base = '' if relative == '.' else relative
            try:
                self._safe_path(base) if base else self._check_root()
                self._directory_signatures[base] = self._directory_signature(parent)
                if self.settings['respect_gitignore']:
                    ancestors = [''] + ['/'.join(base.split('/')[:i]) for i in range(1, len(base.split('/')))] if base else []
                    specs = [(name, self._rules[name]['spec']) for name in ancestors
                             if name in self._rules and self._rules[name]['spec'] is not None]
                    record = self._load_rule(base, specs)
                    if record['error']:
                        continue
                with os.scandir(parent) as entries:
                    children = []
                    for entry in entries:
                        count += 1
                        if count > MAX_ENTRIES:
                            self._issue({'file': '.', 'status': 'access_scope_limit', 'message': '文件枚举超过上限'})
                            return
                        if entry.is_dir(follow_symlinks=False):
                            children.append(entry)
                for item in sorted(children, key=lambda entry: entry.name):
                    path = Path(item.path)
                    name = path.relative_to(self.root).as_posix()
                    if self.decision(name, is_dir=True)['mode'] != 'exclude':
                        pending.append(path)
            except OSError:
                self._issue({'file': relative, 'status': 'access_scope_unreadable', 'message': '目录项无法枚举'})

    def _control_changed(self, directory: str, record: dict | None) -> bool:
        relative = (directory + '/' if directory else '') + '.gitignore'
        path = self.root / relative
        try:
            metadata = path.lstat()
            signature = metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns
        except FileNotFoundError:
            signature = None
        except OSError:
            return True
        if record is None or signature != record['signature']:
            return True
        if record['spec'] is None or self._base_deny(relative):
            return False
        # Hash only known, permitted control files; mtime/size alone cannot
        # prove a rule was unchanged after an editor restores timestamps.
        self.check_current()
        try:
            safe = self._safe_path(relative)
            with safe.open('rb') as stream:
                data = stream.read(MAX_RULE_BYTES + 1)
            self.check_current()
            return len(data) > MAX_RULE_BYTES or hashlib.sha256(data).hexdigest() != record['digest']
        except OSError:
            return True

    def _check_ancestor_controls(self, relative: str) -> None:
        if not self.settings['respect_gitignore']:
            return
        parts = _relative(relative).split('/')
        for index in range(len(parts)):
            base = '/'.join(parts[:index])
            if self._control_changed(base, self._rules.get(base)):
                self.refresh()
                return

    def refresh_if_changed(self):
        self.check_current()
        if not self.confirmed or not self.settings['respect_gitignore']:
            return self
        for name, expected in self._directory_signatures.items():
            try:
                if self._directory_signature(self.root / name) != expected:
                    return self.refresh()
            except OSError:
                return self.refresh()
        for name, record in sorted(self._rules.items(), key=lambda item: (item[0].count('/'), len(item[0]), item[0])):
            if self._control_changed(name, record):
                return self.refresh()
        self.check_current()
        return self

    @property
    def fingerprint(self) -> str:
        self.check_current()
        payload = {"schema": 1, "root": os.path.normcase(str(self.root)),
                   "settings": self.settings, "rules": {name: {"digest": record["digest"], "error": record["error"]}
                   for name, record in sorted(self._rules.items()) if record["digest"] != "missing"}, "issues": self.issues}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def to_dict(self) -> dict:
        problems = self.issues + [{"file": (name + "/" if name else "") + ".gitignore",
                                   "status": "access_rules_blocked", "message": value["error"]}
                                  for name, value in self._rules.items() if value["error"]]
        return {"settings": self.settings, "confirmed": self.confirmed,
                "fingerprint": self.fingerprint, "issues": problems,
                "restricted": bool(self.settings["exclude"] or problems or any(
                    value["digest"] not in {"missing", "denied", "unreadable"} for value in self._rules.values()))}
