"""Evidence-based startup roles; a familiar filename is only a candidate."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
import re

from codesentry.core.symbol import CallSite, FileMeta

APP_ENTRY_NAMES = re.compile(r'^(main|index|app|server|cli|wsgi|asgi|manage|run|__main__|application|electron|worker|preload)$', re.I)
APP_FACTORY_NAMES = re.compile(r'^(main_app|app_factory|create_app|build_app|make_app|get_app|setup_app)$')
CONFIG_NAMES = re.compile(r'^(vite|vitest|jest|webpack|rollup|esbuild|tsconfig|babel|postcss|tailwind|eslint|prettier)\.', re.I)


@dataclass
class EntryPoint:
    file: str
    level: str
    reason: str
    out_degree: int = 0
    in_degree: int = 0
    kind: str = 'candidate'
    confidence: str = 'heuristic'
    line: int | None = None
    evidence: list[dict] = field(default_factory=list)


def _main_guard(content: str) -> int | None:
    try:
        tree = ast.parse(content)
    except (SyntaxError, RecursionError, ValueError):
        return None
    for node in tree.body:
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        test = node.test
        if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
            continue
        left, right = test.left, test.comparators[0]
        if isinstance(right, ast.Name):
            left, right = right, left
        if (isinstance(left, ast.Name) and left.id == '__name__'
                and isinstance(right, ast.Constant) and right.value == '__main__'):
            return node.lineno
    return None


def detect(metas: dict[str, FileMeta], contents: dict[str, str],
           out_degree: dict[str, int], in_degree: dict[str, int],
           production_files: set[str], *, root: Path | None = None,
           access=None, calls: list[CallSite] | None = None,
           startup_snapshot=None, issues: list[dict] | None = None,
           input_hashes: dict[str, str] | None = None,
           exclude_config=None) -> tuple[list[EntryPoint], list[EntryPoint]]:
    """Separate declared processes/mounts from registration and name hints."""
    from codesentry.index.startup import collect_startup_inputs, declarations
    records: dict[str, EntryPoint] = {}
    priority = {'heuristic': 0, 'static': 1, 'declared': 2}
    roles = {'candidate': 0, 'assembly': 1, 'bridge': 2, 'mount': 3, 'process': 4}

    def add(file: str, kind: str, confidence: str, reason: str, line: int | None, evidence: list[dict]):
        meta = metas.get(file)
        if not meta or not meta.is_parsed:
            return
        level = 'script' if meta.is_script or meta.is_test else 'app'
        current = records.get(file)
        if current:
            combined = current.evidence + [item for item in evidence if item not in current.evidence]
            if (roles[kind], priority[confidence]) <= (roles[current.kind], priority[current.confidence]):
                current.evidence = combined
                return
            if line is None:
                line = current.line
        else:
            combined = evidence
        records[file] = EntryPoint(file, level, reason, out_degree.get(file, 0),
                                   in_degree.get(file, 0), kind, confidence, line, combined)

    for rel, meta in sorted(metas.items()):
        if not meta.is_parsed or CONFIG_NAMES.match(Path(rel).name):
            continue
        stem = Path(rel).stem
        if APP_ENTRY_NAMES.fullmatch(stem) or APP_FACTORY_NAMES.fullmatch(stem):
            add(rel, 'candidate', 'heuristic', '文件名提示，尚无应用启动证据', None,
                [{'file': rel, 'line': None, 'type': 'filename_hint'}])
        if rel.endswith('.py'):
            line = _main_guard(contents.get(rel, ''))
            if line:
                add(rel, 'candidate', 'static', '模块有直接main守卫；应用角色仍需启动声明', line,
                    [{'file': rel, 'line': line, 'type': 'python_main_guard'}])

    for call in calls or []:
        if call.binding_kind not in {'symbol', 'namespace'}:
            continue
        module = call.module
        original = call.imported_name or call.callee_name
        kind = None
        if module in {'fastapi', 'flask', 'argparse', 'typer', 'celery'} and original in {
                'FastAPI', 'Flask', 'APIRouter', 'ArgumentParser', 'Typer', 'Celery'}:
            kind = 'assembly'
        elif module == 'uvicorn' and call.callee_name == 'run':
            kind = 'process' if call.is_module_level is True else 'assembly'
        elif (module == 'react-dom/client' and original == 'createRoot'
              or module == 'react-dom' and call.callee_name == 'render') and call.is_module_level is True:
            kind = 'mount'
        elif module == 'electron':
            if original == 'app' and call.callee_name == 'whenReady' and call.is_module_level is True:
                kind = 'process'
            elif original in {'BrowserWindow', 'contextBridge'}:
                kind = 'assembly'
        if kind:
            add(call.file, kind, 'static', '解析器确认导入绑定及真实调用，运行行为未验证', call.line,
                [{'file': call.file, 'line': call.line, 'type': 'bound_framework_call', 'kind': kind}])

    if startup_snapshot is None and root is not None and access is not None:
        startup_snapshot = collect_startup_inputs(access, exclude=exclude_config)
    if startup_snapshot is not None:
        if issues is not None:
            issues.extend(startup_snapshot.issues)
        if input_hashes is not None:
            input_hashes.update(startup_snapshot.hashes)
        for declaration in declarations(startup_snapshot, metas, contents, calls or [], issues=issues, exclude=exclude_config):
            add(**declaration)

    return ([record for _, record in sorted(records.items()) if record.level == 'app'],
            [record for _, record in sorted(records.items()) if record.level == 'script'])
