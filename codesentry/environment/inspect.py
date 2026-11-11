"""Bounded, read-only environment declarations; never evaluate project configuration."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import tomllib

from codesentry.environment.toolchain import Toolchain, get_toolchain, is_link
from codesentry.access.policy import AccessPolicy, AccessDenied

MAX_CONFIG_BYTES = 16 * 1024 * 1024
MAX_CONFIG_FILES = 256
MAX_DIRECTORIES = 4096
EXCLUDED_DIRECTORIES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
    ".next", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".workbuddy",
}
LOCK_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "uv.lock", "poetry.lock", "Pipfile.lock",
}
DECLARATION_NAMES = {
    "package.json", "pyproject.toml", "requirements.txt", "Pipfile",
    ".nvmrc", ".node-version", ".python-version",
}


def _hash(data: object) -> str:
    return hashlib.sha256(json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def _jsonc(text: str) -> object:
    """Remove comments and trailing commas only outside quoted strings."""
    output: list[str] = []
    index = 0
    quoted = False
    escaped = False
    while index < len(text):
        char = text[index]
        if quoted:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            index += 1
            continue
        if char == '"':
            quoted = True
            output.append(char)
            index += 1
            continue
        if text[index:index + 2] == "//":
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if text[index:index + 2] == "/*":
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated JSON comment")
            output.append("\n" * text[index:end + 2].count("\n") or " ")
            index = end + 2
            continue
        output.append(char)
        index += 1
    stripped = "".join(output)
    result: list[str] = []
    quoted = escaped = False
    for index, char in enumerate(stripped):
        if quoted:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        if char == ",":
            rest = stripped[index + 1:].lstrip()
            if rest.startswith(("}", "]")):
                continue
        result.append(char)
    return json.loads("".join(result).lstrip("\ufeff"))


def _safe_spec(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    # URLs, VCS credentials and shell-like values do not belong in an environment report.
    if len(value) <= 200 and (
        re.fullmatch(r"[0-9xX.*^~<>=!+ |,-]+", value)
        or value in ("latest", "next", "stable")
        or re.fullmatch(r"(?:npm|pnpm|yarn|bun)@[0-9][A-Za-z0-9.+-]*", value)
    ):
        return value
    return "<non-version-specification>"


def _workspace_patterns(value: object) -> list[str]:
    if isinstance(value, dict):
        value = value.get("packages", [])
    if not isinstance(value, list):
        return []
    return [
        item if isinstance(item, str) and len(item) <= 256
        and re.fullmatch(r"[A-Za-z0-9_./*?!-]+", item)
        and not item.startswith(("/", "../")) else "<unsupported-workspace-pattern>"
        for item in value[:256]
    ]


@dataclass
class EnvironmentProfile:
    root: str
    project_units: list[dict] = field(default_factory=list)
    declared: dict = field(default_factory=dict)
    observed: dict = field(default_factory=dict)
    unknowns: list[str] = field(default_factory=list)
    configuration_files: dict[str, str] = field(default_factory=dict)
    fingerprint: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "root": self.root,
            "project_units": self.project_units,
            "declared": self.declared,
            "observed": self.observed,
            "unknowns": self.unknowns,
            "configuration_files": dict(self.configuration_files),
            "fingerprint": self.fingerprint,
            "execution": "not_run",
            "type_resolution": "not_performed",
        }


def inspect_environment(root: Path, toolchain: Toolchain | None = None, *, access: AccessPolicy | None = None) -> EnvironmentProfile:
    root = Path(root).resolve()
    access = access or AccessPolicy(root)
    if access.root != root:
        raise ValueError('访问策略不属于当前项目')
    toolchain = toolchain or get_toolchain(root)
    profile = EnvironmentProfile(root=str(root))
    profile.observed = {
        "analyzer": {
            "python": platform.python_version(), "os": platform.system(),
            "architecture": platform.machine(),
        },
        "parsing_toolchain": toolchain.to_dict(),
        "target_runtime": "not_observed",
        "target_installed_dependencies": "not_observed",
    }
    records: dict[str, dict] = {}
    declarations: dict[str, dict] = {}
    active_configs: set[str] = set()

    def unknown(message: str) -> None:
        if message not in profile.unknowns and len(profile.unknowns) < MAX_CONFIG_FILES:
            profile.unknowns.append(message)

    def read_config(path: Path, stack: tuple[str, ...] = ()) -> None:
        try:
            relative = path.relative_to(root).as_posix()
            current = root
            redirected = False
            for part in path.relative_to(root).parts:
                current = current / part
                if is_link(current):
                    redirected = True
                    break
            if not path.resolve().is_relative_to(root) or redirected:
                unknown(f"{relative}: outside-project or redirected configuration not read")
                profile.configuration_files[relative] = "unread:outside-project-or-link"
                return
        except (ValueError, OSError):
            unknown("extends refers outside the declared project; configuration not read")
            return
        if relative in stack:
            unknown(f"{relative}: cyclic tsconfig extends")
            return
        if relative in records:
            return
        if access.decision(relative)['mode'] == 'exclude':
            profile.configuration_files[relative] = 'unread:access-policy'
            records[relative] = {'kind': 'unread', 'access_mode': 'exclude'}
            unknown(f'{relative}: access policy excludes configuration; declaration not observed')
            return
        if len(records) >= MAX_CONFIG_FILES:
            unknown("configuration discovery truncated: file limit")
            profile.configuration_files["__truncated__"] = "unread:file-limit"
            return
        try:
            if path.stat().st_size > MAX_CONFIG_BYTES:
                raise ValueError("configuration exceeds size limit")
            data = access.read_bytes(relative, limit=MAX_CONFIG_BYTES)
            if len(data) > MAX_CONFIG_BYTES:
                raise ValueError("configuration exceeds size limit")
        except (OSError, ValueError) as error:
            profile.configuration_files[relative] = "unread:" + type(error).__name__
            records[relative] = {"kind": "unread"}
            unknown(f"{relative}: {type(error).__name__}; declaration not observed")
            return
        profile.configuration_files[relative] = hashlib.sha256(data).hexdigest()
        record: dict = {"kind": "text", "path": relative, "access_mode": access.decision(relative)['mode']}
        records[relative] = record
        try:
            text = data.decode("utf-8-sig")
            if path.name == "package.json":
                value = json.loads(text)
                if not isinstance(value, dict):
                    raise ValueError("package declaration is not an object")
                record["kind"] = "package"
                engines = value.get("engines", {})
                unit = declarations.setdefault(path.parent.relative_to(root).as_posix(), {})
                unit["javascript"] = {
                    **unit.get("javascript", {}),
                    "engines": {key: _safe_spec(val) for key, val in engines.items()} if isinstance(engines, dict) else {},
                    "package_manager": _safe_spec(value.get("packageManager")),
                    "dependency_specs": {
                        group: {name: _safe_spec(spec) for name, spec in values.items()}
                        for group in ("dependencies", "devDependencies", "peerDependencies")
                        if isinstance((values := value.get(group)), dict)
                    },
                    "script_names": sorted(value.get("scripts", {})) if isinstance(value.get("scripts"), dict) else [],
                    "workspace_patterns": _workspace_patterns(value.get("workspaces", [])),
                }
            elif path.name == "pyproject.toml":
                value = tomllib.loads(text)
                unit = declarations.setdefault(path.parent.relative_to(root).as_posix(), {})
                project = value.get("project", {})
                record["kind"] = "pyproject"
                unit["python"] = {
                    **unit.get("python", {}),
                    "requires_python": _safe_spec(project.get("requires-python")) if isinstance(project, dict) else None,
                    "dependency_names": [
                        (re.match(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(item)).group(0)
                         if re.match(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(item)) else "<invalid-name>")
                        for item in project.get("dependencies", [])
                    ] if isinstance(project, dict) and isinstance(project.get("dependencies"), list) else [],
                    "build_backend_declared": bool(value.get("build-system")),
                }
            elif path.name.startswith(("tsconfig", "jsconfig")) and path.suffix == ".json" or relative in active_configs:
                value = _jsonc(text)
                if not isinstance(value, dict):
                    raise ValueError("TypeScript configuration is not an object")
                record["kind"] = "typescript-config"
                options = value.get("compilerOptions", {})
                record["declared_options"] = {
                    key: options[key] for key in ("module", "moduleResolution", "target", "baseUrl", "paths")
                    if isinstance(options, dict) and key in options
                }
                if isinstance(options, dict) and options.get("plugins"):
                    unknown(f"{relative}: executable compiler plugins are not loaded")
                extends = value.get("extends", [])
                extends = [extends] if isinstance(extends, str) else extends
                record["extends"] = []
                if not isinstance(extends, list):
                    raise ValueError("unsupported extends declaration")
                for item in extends:
                    if not isinstance(item, str):
                        unknown(f"{relative}: unsupported extends entry")
                        continue
                    if not item.startswith(("./", "../")):
                        unknown(f"{relative}: package or absolute extends is unresolved without loading dependencies")
                        continue
                    candidate = path.parent / item
                    if not candidate.suffix:
                        candidate = candidate.with_suffix(".json")
                    try:
                        name = candidate.resolve().relative_to(root).as_posix()
                    except (ValueError, OSError):
                        unknown(f"{relative}: extends outside project not read")
                        continue
                    record["extends"].append(name)
                    active_configs.add(name)
                    read_config(candidate, (*stack, relative))
                unknown(f"{relative}: declarations recorded; effective module/type resolution is not performed")
            elif path.name in (".nvmrc", ".node-version", ".python-version"):
                record["declared_version"] = _safe_spec(text.strip())
                unit = declarations.setdefault(path.parent.relative_to(root).as_posix(), {})
                language = "python" if path.name == ".python-version" else "javascript"
                unit.setdefault(language, {}).setdefault("version_files", {})[path.name] = record["declared_version"]
            elif path.name == "Pipfile" or path.name.startswith("requirements") and path.suffix == ".txt":
                record["kind"] = "python-dependency-declaration"
                parents = [
                    name for name, unit in declarations.items()
                    if "python" in unit and path.parent.is_relative_to(root if name == "." else root / name)
                ]
                owner = max(parents, key=lambda name: len(Path(name).parts)) if parents else path.parent.relative_to(root).as_posix()
                unit = declarations.setdefault(owner, {})
                unit.setdefault("python", {}).setdefault("dependency_declaration_files", []).append(relative)
        except (RecursionError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
            record["status"] = "invalid"
            unknown(f"{relative}: invalid text configuration ({type(error).__name__})")

    visited = 0
    for directory, children, names in os.walk(root, followlinks=False):
        visited += 1
        if visited > MAX_DIRECTORIES:
            unknown("configuration discovery truncated: directory limit")
            break
        parent = Path(directory)
        allowed: list[str] = []
        for child in sorted(children):
            path = parent / child
            if child in EXCLUDED_DIRECTORIES or child.startswith(".") and child != ".github":
                continue
            if access.decision(path.relative_to(root).as_posix(), is_dir=True)['mode'] == 'exclude':
                relative = path.relative_to(root).as_posix() + '/'
                profile.configuration_files[relative] = 'unread:access-policy'
                unknown(f'{relative}: access policy excludes directory; declarations not observed')
                continue
            if is_link(path):
                unknown(f"{path.relative_to(root).as_posix()}: redirected directory not inspected")
                continue
            allowed.append(child)
        children[:] = allowed
        for name in sorted(names):
            if (
                name in DECLARATION_NAMES or name in LOCK_NAMES
                or name.startswith(("tsconfig", "jsconfig")) and name.endswith(".json")
                or name.startswith("requirements") and name.endswith(".txt")
            ):
                read_config(parent / name)
    unit_paths = set(declarations)
    for name, record in records.items():
        if record.get("kind") != "typescript-config" or not Path(name).name.startswith(("tsconfig", "jsconfig")):
            continue
        directory = (root / name).parent
        if not any(directory.is_relative_to(root if unit == "." else root / unit) for unit in declarations):
            unit_paths.add(directory.relative_to(root).as_posix())
    if not unit_paths:
        unit_paths.add(".")
    for unit_path in sorted(unit_paths):
        unit_root = root if unit_path == "." else root / unit_path
        exact_files = []
        for name in profile.configuration_files:
            directory = (root / name).parent
            owners = [
                root if unit == "." else root / unit for unit in unit_paths
                if directory.is_relative_to(root if unit == "." else root / unit)
            ]
            if owners and max(owners, key=lambda value: len(value.parts)) == unit_root:
                exact_files.append(name)
        locks = [name for name in exact_files if Path(name).name in LOCK_NAMES and (root / name).parent == unit_root]
        if not locks:
            unknown(f"{unit_path}: no supported lockfile declared in this project unit")
        profile.project_units.append({
            "path": unit_path,
            "declarations": declarations.get(unit_path, {}),
            "configuration_files": sorted(exact_files),
            "lockfiles": sorted(locks),
            "installed_dependencies": "not_observed",
        })
    profile.declared = {
        "configuration_records": {name: value for name, value in sorted(records.items())},
        "target_platform": "not_inferred_from_analyzer_os",
    }
    profile.unknowns.sort()
    profile.fingerprint = _hash({
        "schema": 1, "configuration_files": profile.configuration_files,
        "access_fingerprint": access.fingerprint,
        "unknowns": profile.unknowns, "toolchain": toolchain.fingerprint,
        "python": list(sys.version_info[:3]),
    })
    return profile
