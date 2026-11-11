"""Read bounded launch declarations as data, never execute repository commands."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib
from html.parser import HTMLParser
import json
from pathlib import PurePosixPath
import posixpath
import re
import shlex
import tomllib

import yaml

from codesentry.core.policy import ExcludeConfig
from codesentry.index.discovery import classify

MAX_CONFIG_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_CONFIG_FILES = 128
CONFIG_NAMES = {'pyproject.toml', 'package.json', 'Dockerfile', 'docker-compose.yml',
                'docker-compose.yaml', 'compose.yml', 'compose.yaml'}


@dataclass
class StartupSnapshot:
    hashes: dict[str, str] = field(default_factory=dict)
    texts: dict[str, str] = field(default_factory=dict)
    issues: list[dict] = field(default_factory=list)


def collect_startup_inputs(access, *, exclude: ExcludeConfig | None = None) -> StartupSnapshot:
    snapshot = StartupSnapshot()
    exclude = exclude or ExcludeConfig()
    remaining = MAX_TOTAL_BYTES

    def candidate(relative: str) -> bool:
        path = PurePosixPath(relative)
        return ((path.name in CONFIG_NAMES or path.suffix.lower() == '.html')
                and not any(classify(relative, exclude)))

    def descend(relative: str) -> bool:
        # classify expects a file path: use a neutral basename so a directory
        # such as test_component is not mistaken for a test_*.html file.
        return not any(classify(relative + '/__startup_scope__', exclude))

    for relative, path, directory, decision in access.walk(file_filter=candidate, descend_filter=descend):
        if directory or (path.name not in CONFIG_NAMES and path.suffix.lower() != '.html'):
            continue
        is_data, not_parsed, is_script, is_test = classify(relative, exclude)
        if is_data or not_parsed or is_script or is_test:
            continue
        if len(snapshot.hashes) >= MAX_CONFIG_FILES:
            snapshot.issues.append({'file': '.', 'status': 'startup_config_limit', 'message': '启动声明数量超过上限'})
            snapshot.hashes['__truncated__'] = 'unread:file-count-limit'
            break
        if decision['mode'] == 'exclude':
            snapshot.hashes[relative] = 'unread:access-policy'
            snapshot.issues.append({'file': relative, 'status': 'startup_config_excluded', 'message': '启动声明在禁止读取范围，入口证据不完整'})
            continue
        try:
            limit = min(MAX_CONFIG_BYTES, remaining)
            if limit <= 0:
                raise ValueError('startup total byte limit')
            raw = access.read_bytes(relative, limit=limit)
            remaining -= len(raw)
            snapshot.hashes[relative] = hashlib.sha256(raw).hexdigest()
            snapshot.texts[relative] = raw.decode('utf-8-sig')
        except (OSError, ValueError, UnicodeError):
            snapshot.hashes[relative] = 'unread:unsupported-or-limit'
            snapshot.issues.append({'file': relative, 'status': 'startup_config_unreadable', 'message': '启动声明无法安全读取，未推断入口'})
    return snapshot


def _line(text: str, key: str) -> int | None:
    hits = [number for number, line in enumerate(text.splitlines(), 1)
            if re.search(r'(?:["\']' + re.escape(key) + r'["\']\s*:|^\s*' + re.escape(key) + r'\s*=)', line)]
    return hits[0] if len(hits) == 1 else None


def _path(base: str, target: str, *, html=False) -> str | None:
    if not isinstance(target, str) or not target or len(target) > 4096:
        return None
    if html:
        target = target.split('?', 1)[0].split('#', 1)[0]
    if any(value in target for value in ('\\', ':', '$', '`', '*', '\0')) or target.startswith('//'):
        return None
    if target.startswith('/'):
        if not html:
            return None
        target = target.lstrip('/')
    relative = posixpath.normpath(posixpath.join(base, target))
    return relative if relative not in {'.', '..'} and not relative.startswith('../') else None


def _tokens(command) -> list[str] | None:
    if isinstance(command, list):
        return command if command and len(command) <= 128 and all(isinstance(item, str) and len(item) <= 4096 for item in command) else None
    if not isinstance(command, str) or len(command) > 16384 or re.search(r'[;&|`\n\r]|\$\(', command):
        return None
    try:
        return shlex.split(command)
    except ValueError:
        return None


def _source_line(file: str, contents: dict[str, str], symbol: str | None = None) -> int | None:
    if not file.endswith('.py'):
        return None
    try:
        tree = ast.parse(contents.get(file, ''))
    except (SyntaxError, ValueError, RecursionError):
        return None
    if symbol:
        found = [node.lineno for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol]
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Name) and target.id == symbol for target in targets):
                    found.append(node.lineno)
            elif isinstance(node, ast.ImportFrom):
                if any((alias.asname or alias.name) == symbol for alias in node.names if alias.name != '*'):
                    found.append(node.lineno)
        return found[0] if len(found) == 1 else None
    body = [node for node in tree.body if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))]
    return body[0].lineno if body else None


class _HTMLScripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.inline_scripts = []
        self.inert = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() in {'template', 'noscript'}:
            self.inert.append(tag.lower())
        if self.inert:
            return
        if tag.lower() == 'script':
            attrs = dict(attrs)
            if attrs.get('src') and attrs.get('type', 'module') in {'module', 'text/javascript', 'application/javascript'}:
                self.scripts.append((attrs['src'], self.getpos()[0]))
            elif not attrs.get('src') and attrs.get('type', 'module') in {'module', 'text/javascript', 'application/javascript'}:
                self.inline_scripts.append(self.getpos()[0])
    def handle_endtag(self, tag):
        if self.inert and tag.lower() == self.inert[-1]:
            self.inert.pop()


_JS_TOKEN = re.compile(r'''//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|/(?:\\.|[^/\n\\])+/[a-z]*|[A-Za-z_$][\w$]*|[^\s]''')


def _js_tokens(text):
    tokens, line, previous = [], 1, 0
    for match in _JS_TOKEN.finditer(text):
        line += text[previous:match.start()].count('\n')
        value = match[0]
        token_line = line
        line += value.count('\n')
        previous = match.end()
        if value.startswith(('//', '/*', '`', '/')):
            continue
        if value.startswith(('"', "'")):
            try:
                tokens.append(('string', ast.literal_eval(value), token_line))
            except (ValueError, SyntaxError):
                tokens.append(('opaque', '', token_line))
        else:
            tokens.append(('code', value, token_line))
    return tokens


def _object_fields(tokens):
    if not tokens or tokens[0][1] != '{':
        return None
    fields, index = {}, 1
    while index < len(tokens) and tokens[index][1] != '}':
        if tokens[index][1] == ',':
            index += 1
            continue
        name = tokens[index][1]
        if index + 1 >= len(tokens) or tokens[index + 1][1] != ':' or name in fields:
            return None
        start = index = index + 2
        depth = 0
        while index < len(tokens):
            value = tokens[index][1]
            if tokens[index][0] == 'code' and value in ('(', '[', '{'):
                depth += 1
            elif tokens[index][0] == 'code' and value in (')', ']', '}'):
                if depth == 0:
                    break
                depth -= 1
            elif tokens[index][0] == 'code' and value == ',' and depth == 0:
                break
            index += 1
        fields[name] = tokens[start:index]
        if index < len(tokens) and tokens[index][1] == ',':
            index += 1
    return fields


def _preloads(base, build_map, contents, calls):
    """Recognize only literal BrowserWindow options and immutable path joins."""
    reverse = {}
    calls_by_file = {}
    for call in calls:
        calls_by_file.setdefault(call.file, []).append(call)
    for output, (source, evidence) in build_map.items():
        if output != '__package_main__':
            reverse.setdefault(source, []).append(output)
    for host in sorted(contents):
        if base and not host.startswith(base + '/'):
            continue
        host_calls = calls_by_file.get(host, [])
        window_calls = [call for call in host_calls if call.module == 'electron'
                        and call.imported_name == 'BrowserWindow' and call.binding_kind == 'symbol']
        if not window_calls:
            continue
        tokens = _js_tokens(contents[host])
        constants = {}
        brace = 0
        for index, token in enumerate(tokens):
            if token[0] == 'code' and token[1] == '{':
                brace += 1
            elif token[0] == 'code' and token[1] == '}':
                brace -= 1
            if brace == 0 and token[1] == 'const' and index + 2 < len(tokens) and tokens[index + 2][1] == '=':
                end = index + 3
                while end < len(tokens) and tokens[end][1] != ';':
                    end += 1
                name = tokens[index + 1][1]
                constants[name] = tokens[index + 3:end] if name not in constants else None

        def literal(value):
            if len(value) == 1 and value[0][0] == 'code':
                value = constants.get(value[0][1])
            if not value:
                return None
            if len(value) == 1 and value[0][0] == 'string':
                return value[0][1]
            values = [item[1] for item in value]
            member = len(value) == 8 and values[1:6] == ['.', 'join', '(', '__dirname', ','] and values[-1] == ')'
            named = len(value) == 6 and values[1:4] == ['(', '__dirname', ','] and values[-1] == ')'
            string = value[6] if member else value[4] if named else None
            if not string or string[0] != 'string':
                return None
            matching = any(call.file == host and call.line == value[0][2] and call.module in {'path', 'node:path'}
                           and call.callee_name == (values[2] if member else values[0])
                           and call.binding_kind in {'symbol', 'namespace'} for call in host_calls)
            return string[1] if matching else None

        for call in window_calls:
            for index, token in enumerate(tokens):
                if token[0] != 'code' or token[1] != call.callee_name or token[2] != call.line or index + 2 >= len(tokens) or tokens[index + 1][1] != '(':
                    continue
                options = _object_fields(tokens[index + 2:])
                preferences = _object_fields(options.get('webPreferences', [])) if options else None
                target = literal(preferences.get('preload', [])) if preferences else None
                if not target:
                    continue
                host_outputs = reverse.get(host, [])
                dirname = posixpath.dirname(host_outputs[0]) if len(host_outputs) == 1 else posixpath.dirname(host)
                loaded = _path(dirname, target)
                if loaded in contents:
                    yield loaded, host, call.line, []
                elif loaded in build_map:
                    source, evidence = build_map[loaded]
                    yield source, host, call.line, evidence


def declarations(snapshot: StartupSnapshot, metas: dict, contents: dict,
                 calls: list, *, issues: list[dict] | None = None,
                 exclude: ExcludeConfig | None = None) -> list[dict]:
    result = []
    exclude = exclude or ExcludeConfig()
    issues = issues if issues is not None else []

    def unknown(file, status='startup_target_unresolved'):
        value = {'file': file, 'status': status, 'message': '声明的启动目标无法由受支持的静态映射确认；未执行命令或猜测源码'}
        if value not in issues:
            issues.append(value)

    def bounded(values, file, limit=128):
        if len(values) > limit:
            unknown(file, 'startup_declaration_limit')
        return list(values.items())[:limit] if isinstance(values, dict) else values[:limit]

    def add(file, kind, config, line, evidence_type, symbol=None, extra=None):
        if file not in metas or not metas[file].is_parsed:
            unknown(config)
            return
        location = _source_line(file, contents, symbol)
        if symbol and location is None:
            unknown(config, 'startup_attribute_unresolved')
            return
        evidence = [{'file': config, 'line': line, 'type': evidence_type}]
        if extra:
            evidence.extend(extra)
        result.append({'file': file, 'kind': kind, 'confidence': 'declared',
                       'reason': ('启动参数指向该候选源码，但执行上下文仍未确认' if kind == 'candidate'
                                  else '本地启动声明指向该源码，尚未验证实际运行'),
                       'line': location, 'evidence': evidence})

    def module_target(base, target, source_prefix=''):
        if not isinstance(target, str) or not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', target):
            return None, None
        module, _, symbol = target.partition(':')
        stem = _path(base, posixpath.join(source_prefix, module.replace('.', '/')))
        if not stem:
            return None, None
        options = [name for name in (stem + '.py', stem + '/__init__.py') if name in metas]
        return (options[0], symbol or None) if len(options) == 1 else (None, None)

    def resolve_target(base, target, build_map):
        direct = _path(base, target)
        if direct in metas:
            return direct, []
        mapped = build_map.get(direct)
        return (mapped[0], mapped[1]) if mapped else (None, [])

    def command(base, value, config, line, build_map=None, source_prefix='', role='process'):
        tokens = _tokens(value)
        if not tokens:
            unknown(config, 'startup_command_unsupported')
            return
        executable = PurePosixPath(tokens[0]).name.lower()
        file = symbol = None
        extra = []
        if executable in {'python', 'python3', 'python.exe', 'python3.exe'}:
            args = tokens[1:]
            while args and args[0] in {'-u', '-B', '-I', '-s', '-S'}:
                args = args[1:]
            if len(args) >= 3 and args[:2] == ['-m', 'uvicorn']:
                file, symbol = module_target(base, args[2], source_prefix)
            elif len(args) >= 2 and args[0] == '-m':
                module = args[1]
                if re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', module):
                    stem = _path(base, posixpath.join(source_prefix, module.replace('.', '/')))
                    options = [name for name in (stem + '.py', stem + '/__main__.py') if name in metas]
                    file = options[0] if len(options) == 1 else None
            elif args and not args[0].startswith('-'):
                file = _path(base, args[0])
        elif executable in {'uvicorn', 'uvicorn.exe', 'gunicorn', 'gunicorn.exe'} and len(tokens) >= 2 and not tokens[1].startswith('-'):
            file, symbol = module_target(base, tokens[1], source_prefix)
        elif executable in {'node', 'node.exe', 'tsx', 'ts-node'} and len(tokens) >= 2 and not tokens[1].startswith('-'):
            file, extra = resolve_target(base, tokens[1], build_map or {})
        elif executable in {'electron', 'electron.exe'} and len(tokens) >= 2 and tokens[1] == '.':
            file, extra = (build_map or {}).get('__package_main__', (None, []))
        else:
            if executable not in {'vite', 'vitest', 'tsc', 'esbuild', 'pytest', 'eslint'}:
                unknown(config, 'startup_command_unsupported')
            return
        if file:
            add(file, role, config, line, 'launch_command', symbol, extra)
        else:
            unknown(config)

    for config, text in sorted(snapshot.texts.items()):
        if any(classify(config, exclude)):
            continue
        base = posixpath.dirname(config)
        name = PurePosixPath(config).name
        try:
            if name == 'pyproject.toml':
                data = tomllib.loads(text)
                prefix = data.get('tool', {}).get('setuptools', {}).get('package-dir', {}).get('', '')
                if not isinstance(prefix, str) or prefix and _path('', prefix) is None:
                    prefix = ''
                project = data.get('project', {})
                if not isinstance(project, dict):
                    raise ValueError('project declaration')
                for key in ('scripts', 'gui-scripts'):
                    values = project.get(key, {})
                    if not isinstance(values, dict):
                        unknown(config, 'startup_declaration_unsupported')
                        continue
                    for script, target in bounded(values, config):
                        file, symbol = module_target(base, target, prefix)
                        if file:
                            add(file, 'process', config, _line(text, script), 'python_console_script', symbol)
                        else:
                            unknown(config)
            elif name == 'package.json':
                data = json.loads(text)
                if not isinstance(data, dict):
                    raise ValueError('package declaration')
                scripts = data.get('scripts', {})
                if not isinstance(scripts, dict):
                    unknown(config, 'startup_declaration_unsupported')
                scripts = scripts if isinstance(scripts, dict) else {}
                build_map = {}
                ambiguous = set()
                for key, value in bounded(scripts, config):
                    tokens = _tokens(value)
                    if not tokens or PurePosixPath(tokens[0]).name not in {'esbuild', 'esbuild.exe'}:
                        continue
                    sources = [arg for arg in tokens[1:] if not arg.startswith('-') and _path(base, arg) in metas]
                    outputs = [arg.split('=', 1)[1] for arg in tokens if arg.startswith('--outfile=')]
                    if '--outfile' in tokens and tokens.index('--outfile') + 1 < len(tokens):
                        outputs.append(tokens[tokens.index('--outfile') + 1])
                    if len(sources) == len(outputs) == 1:
                        output, source = _path(base, outputs[0]), _path(base, sources[0])
                        evidence = [{'file': config, 'line': _line(text, key), 'type': 'explicit_build_mapping'}]
                        if output in build_map and build_map[output][0] != source:
                            ambiguous.add(output)
                        build_map[output] = source, evidence
                for key in ambiguous:
                    build_map.pop(key, None)
                    unknown(config, 'startup_build_mapping_ambiguous')
                main = data.get('main')
                if isinstance(main, str):
                    file, extra = resolve_target(base, main, build_map)
                    if file:
                        add(file, 'assembly', config, _line(text, 'main'), 'package_main', extra=extra)
                        build_map['__package_main__'] = file, extra + [{'file': config, 'line': _line(text, 'main'), 'type': 'package_main'}]
                    else:
                        unknown(config)
                bins = data.get('bin', {})
                bins = {data.get('name', 'bin'): bins} if isinstance(bins, str) else bins
                if isinstance(bins, dict):
                    for key, target in bounded(bins, config):
                        if isinstance(target, str):
                            file, extra = resolve_target(base, target, build_map)
                            if file:
                                add(file, 'process', config, _line(text, 'bin'), 'package_bin', extra=extra)
                            else:
                                unknown(config)
                for key, value in bounded(scripts, config):
                    if key.split(':', 1)[0] in {'build', 'test', 'lint', 'check', 'format', 'typecheck', 'prepare', 'preinstall', 'postinstall', 'prepublish'}:
                        continue
                    command(base, value, config, _line(text, key), build_map)
                for source, host, host_line, evidence in _preloads(base, build_map, contents, calls):
                    add(source, 'bridge', host, host_line, 'electron_preload_load', extra=evidence)
            elif name.endswith('.html'):
                parser = _HTMLScripts()
                parser.feed(text)
                if parser.inline_scripts:
                    unknown(config, 'startup_inline_script_unsupported')
                for target, line in bounded(parser.scripts, config):
                    if target.startswith(('http:', 'https:', '//', 'data:')):
                        continue
                    file = _path(base, target, html=True)
                    if file:
                        add(file, 'mount', config, line, 'html_script_source')
            elif name == 'Dockerfile':
                lines = list(enumerate(text.splitlines(), 1))
                final_stage = max((index for index, (_, line) in enumerate(lines) if re.match(r'^\s*FROM\s', line, re.I)), default=0)
                stage = lines[final_stage:]
                workdir = next((line.split(None, 1)[1].strip() for _, line in reversed(stage) if re.match(r'^\s*WORKDIR\s', line, re.I)), None)
                copied_root = any(re.fullmatch(r'\s*COPY\s+\.\s+(?:\.|' + re.escape(workdir or '__none__') + r')\s*', line, re.I) for _, line in stage)
                if not copied_root:
                    unknown(config, 'startup_container_mapping_unknown')
                    continue
                entry = cmd = None
                for line_no, line in stage:
                    match = re.match(r'^\s*(ENTRYPOINT|CMD)\s+(.+)$', line, re.I)
                    if match:
                        raw = match[2].strip()
                        value = json.loads(raw) if raw.startswith('[') else raw
                        if match[1].upper() == 'ENTRYPOINT':
                            entry = value, line_no
                        else:
                            cmd = value, line_no
                if entry and cmd and isinstance(entry[0], list) and isinstance(cmd[0], list):
                    command(base, entry[0] + cmd[0], config, cmd[1])
                elif entry or cmd:
                    value, line_no = entry or cmd
                    if entry:
                        command(base, value, config, line_no)
                    else:
                        unknown(config, 'startup_container_entrypoint_unknown')
                        command(base, value, config, line_no, role='candidate')
            elif name in CONFIG_NAMES:
                data = yaml.safe_load(text)
                services = data.get('services', {}) if isinstance(data, dict) else {}
                if not isinstance(services, dict):
                    continue
                for service, value in bounded(services, config, limit=64):
                    if not isinstance(value, dict) or 'command' not in value:
                        continue
                    workdir = value.get('working_dir')
                    bind = None
                    for volume in value.get('volumes', []) if isinstance(value.get('volumes', []), list) else []:
                        if isinstance(volume, str):
                            parts = volume.split(':')
                            if len(parts) in {2, 3} and parts[1] == workdir:
                                bind = _path(base, parts[0]) if parts[0] != '.' else base
                    if bind is None:
                        unknown(config, 'startup_container_mapping_unknown')
                        continue
                    if 'entrypoint' in value:
                        entry_tokens = _tokens(value['entrypoint']) if value['entrypoint'] not in ([], '') else []
                        command_tokens = _tokens(value['command'])
                        if entry_tokens is None or command_tokens is None:
                            unknown(config, 'startup_command_unsupported')
                        else:
                            command(bind, entry_tokens + command_tokens, config, _line(text, 'command'))
                    else:
                        unknown(config, 'startup_container_entrypoint_unknown')
                        command(bind, value['command'], config, _line(text, 'command'), role='candidate')
        except (ValueError, TypeError, AttributeError, yaml.YAMLError, RecursionError):
            unknown(config, 'startup_declaration_unsupported')
    return result
