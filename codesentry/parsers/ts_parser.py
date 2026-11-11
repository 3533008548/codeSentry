"""TypeScript syntax extraction with a pinned analyzer-owned compiler.

Target source is input data. This parser does not evaluate target configuration,
load target packages, or claim OS-level execution isolation.
"""
from __future__ import annotations

import json
import hashlib
import queue
import subprocess
import threading
import time
from pathlib import Path

from codesentry.environment.toolchain import (
    Toolchain, TYPESCRIPT_COMPILER_SHA256, clean_process_environment,
    get_toolchain, managed_typescript_dir,
)

from codesentry.core.symbol import (
    CallSite,
    FileMeta,
    Language,
    Symbol,
    SymbolKind,
)


def find_node() -> str | None:
    """Compatibility accessor; target packages are never searched."""
    return get_toolchain().node


def find_typescript(project_root: Path) -> str | None:
    """Compatibility accessor for the managed compiler entry, not node_modules."""
    return get_toolchain(project_root).typescript_path


# Node 侧脚本：读 stdin 的 JSON Lines，输出 JSON Lines
_NODE_SCRIPT = r"""


const crypto = require("node:crypto");
const Module = require("node:module");
const path = require("node:path");
const compiler = process.argv[2];
if (!compiler || !path.isAbsolute(compiler)) {
  process.stderr.write("TS_MANAGED_PATH_REQUIRED\n"); process.exit(3);
}
const builtins = new Set(Module.builtinModules.flatMap(name => [name, "node:" + name]));
const load = Module._load;
Module._load = function(request, parent, isMain) {
  if (request !== compiler && !builtins.has(request)) throw new Error("UNMANAGED_MODULE_REJECTED");
  return load.call(this, request, parent, isMain);
};
let ts = null;
try { ts = require(compiler); }
catch (e) { process.stderr.write("TS_MANAGED_LOAD_FAILED\n"); process.exit(3); }

function extract(absPath, relPath, source) {
  const kind = absPath.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(absPath, source, ts.ScriptTarget.Latest, true, kind);
  if (sf.parseDiagnostics.some(diagnostic => diagnostic.category === ts.DiagnosticCategory.Error)) {
    return { symbols: [], calls: [], imports: [], import_map: {}, exports: [], parse_ok: false };
  }
  const symbols = [], calls = [], descriptors = [], imports = {};
  const importKinds = {};
  const markImport = (module, kind) => {
    if (!module) return;
    if (!imports[module]) imports[module] = new Set();
    const previous = importKinds[module];
    importKinds[module] = previous === "runtime" || kind === "runtime" ? "runtime"
      : previous === "conditional" || kind === "conditional" ? "conditional"
      : previous === "unknown" || kind === "unknown" ? "unknown" : kind;
  };
  const writes = [], localExports = [];
  const scopes = new Map(), definitions = new Map();
  const makeScope = (node, parent, owner) => {
    const scope = { node, parent, owner, bindings: new Map() };
    scopes.set(node, scope);
    return scope;
  };
  const top = makeScope(sf, null, null);
  const nameOf = (node) => node && (ts.isIdentifier(node) || ts.isStringLiteral(node)
    || ts.isPrivateIdentifier(node)) ? node.text : null;
  const bind = (scope, name, value) => {
    if (!name) return;
    if (!scope.bindings.has(name)) scope.bindings.set(name, []);
    scope.bindings.get(name).push(value);
  };
  const bindNames = (scope, node, value) => {
    if (!node) return;
    if (ts.isIdentifier(node)) bind(scope, node.text, value);
    else if (ts.isObjectBindingPattern(node) || ts.isArrayBindingPattern(node)) {
      for (const element of node.elements) if (element.name) bindNames(scope, element.name, value);
    }
  };
  const isFunction = (node) => ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node) || ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node)
    || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node);
  const isClass = (node) => ts.isClassDeclaration(node) || ts.isClassExpression(node);
  const functionValue = (node) => node && (ts.isArrowFunction(node) || ts.isFunctionExpression(node));
  const register = (node, scope, name, kind, bound = true) => {
    const descriptor = { node, name, kind, parent: scope.owner, qname: null,
      bindingScope: bound ? scope : null };
    descriptors.push(descriptor);
    definitions.set(node, descriptor);
    if (bound) bind(scope, name, { kind: "local", definition: descriptor });
    return descriptor;
  };
  const importsAt = (node, scope) => {
    const module = node.moduleSpecifier.text;
    if (!imports[module]) imports[module] = new Set();
    const clause = node.importClause;
    const namedElements = clause && clause.namedBindings && ts.isNamedImports(clause.namedBindings)
      ? clause.namedBindings.elements : [];
    const typeOnly = !!clause && (clause.isTypeOnly || !clause.name && namedElements.length > 0
      && namedElements.every(element => element.isTypeOnly));
    markImport(module, typeOnly ? "type" : "runtime");
    if (!clause) return;
    if (clause.name) {
      imports[module].add("default");
      bind(scope, clause.name.text, { kind: clause.isTypeOnly ? "shadowed" : "symbol", module, original: "default" });
    }
    const named = clause.namedBindings;
    if (named && ts.isNamedImports(named)) {
      for (const element of named.elements) {
        const original = (element.propertyName || element.name).text;
        imports[module].add(original);
        bind(scope, element.name.text, { kind: clause.isTypeOnly || element.isTypeOnly ? "shadowed" : "symbol", module, original });
      }
    } else if (named && ts.isNamespaceImport(named)) {
      imports[module].add("*");
      bind(scope, named.name.text, { kind: clause.isTypeOnly ? "shadowed" : "namespace", module, original: "" });
    }
  };
  const collect = (node, scope) => {
    if (ts.isImportDeclaration(node) && node.moduleSpecifier) { importsAt(node, scope); return; }
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const argument = node.arguments[0];
      if (argument && ts.isStringLiteral(argument)) markImport(argument.text, "conditional");
    }
    if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)
        && ts.isStringLiteral(node.argument.literal)) markImport(node.argument.literal.text, "type");
    if (ts.isExportDeclaration(node)) {
      if (node.moduleSpecifier) {
        const elements = node.exportClause && ts.isNamedExports(node.exportClause)
          ? node.exportClause.elements : [];
        const typeOnly = node.isTypeOnly || elements.length > 0 && elements.every(item => item.isTypeOnly);
        markImport(node.moduleSpecifier.text, typeOnly ? "type" : "runtime");
      } else if (!node.isTypeOnly && node.exportClause && ts.isNamedExports(node.exportClause)) {
        for (const element of node.exportClause.elements) {
          if (!element.isTypeOnly) localExports.push({
            local: (element.propertyName || element.name).text, exported: element.name.text });
        }
      }
    }
    let descriptor = definitions.get(node) || null;
    if (!descriptor && isClass(node) && node.name) {
      descriptor = register(node, scope, node.name.text, "class", !ts.isClassExpression(node));
    } else if (!descriptor && ts.isFunctionDeclaration(node) && node.name) {
      descriptor = register(node, scope, node.name.text, "function");
    } else if (!descriptor && (ts.isMethodDeclaration(node) || ts.isGetAccessorDeclaration(node)
        || ts.isSetAccessorDeclaration(node)) && nameOf(node.name)) {
      descriptor = register(node, scope, nameOf(node.name), "method", isClass(node.parent));
    } else if (!descriptor && ts.isConstructorDeclaration(node)) {
      descriptor = register(node, scope, "constructor", "method");
    } else if (ts.isInterfaceDeclaration(node)) {
      descriptor = register(node, scope, node.name.text, "interface");
    } else if (ts.isTypeAliasDeclaration(node)) {
      descriptor = register(node, scope, node.name.text, "type_alias");
    } else if (ts.isEnumDeclaration(node)) {
      descriptor = register(node, scope, node.name.text, "enum");
    } else if (ts.isVariableDeclaration(node)) {
      // var is function-scoped even when syntactically inside a block.
      let bindingScope = scope;
      if (ts.isVariableDeclarationList(node.parent) && !(node.parent.flags & ts.NodeFlags.BlockScoped)) {
        while (bindingScope.parent && !isFunction(bindingScope.node)) bindingScope = bindingScope.parent;
      }
      if (nameOf(node.name) && functionValue(node.initializer)) {
        descriptor = register(node.initializer, bindingScope, nameOf(node.name), "function");
        // The initializer itself owns the new function scope below.
        collect(node.initializer, scope);
        return;
      }
      const constant = nameOf(node.name);
      if (constant && constant.length > 1 && constant === constant.toUpperCase()) {
        register(node, bindingScope, constant, "constant", false);
      }
      bindNames(bindingScope, node.name, { kind: "shadowed" });
    } else if (ts.isPropertyDeclaration(node) && nameOf(node.name)) {
      if (functionValue(node.initializer)) {
        register(node.initializer, scope, nameOf(node.name), "method");
        collect(node.initializer, scope);
        return;
      }
      if ((node.modifiers || []).some(m => m.kind === ts.SyntaxKind.StaticKeyword)) {
        descriptor = register(node, scope, nameOf(node.name), "property");
      }
    }
    if (isClass(node) || isFunction(node) || ts.isInterfaceDeclaration(node)) {
      const inner = makeScope(node, scope, descriptor || scope.owner);
      if (ts.isClassExpression(node) && node.name && descriptor) {
        descriptor.bindingScope = inner;
        bind(inner, node.name.text, { kind: "local", definition: descriptor });
      }
      if (node.parameters) {
        for (const parameter of node.parameters) bindNames(inner, parameter.name, { kind: "shadowed" });
      }
      // Named function expressions have their own binding, never the enclosing one.
      if (ts.isFunctionExpression(node) && node.name) bind(inner, node.name.text, { kind: "shadowed" });
      ts.forEachChild(node, child => collect(child, inner));
      return;
    }
    if (ts.isBlock(node) || ts.isCatchClause(node) || ts.isForStatement(node)
        || ts.isForInStatement(node) || ts.isForOfStatement(node)) {
      const inner = makeScope(node, scope, scope.owner);
      if (ts.isCatchClause(node) && node.variableDeclaration) {
        bindNames(inner, node.variableDeclaration.name, { kind: "shadowed" });
      }
      ts.forEachChild(node, child => collect(child, inner));
      return;
    }
    if (ts.isBinaryExpression(node)
        && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
        && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
      const roots = [];
      const assigned = target => {
        if (ts.isIdentifier(target)) roots.push(target.text);
        else if (ts.isArrayLiteralExpression(target)) target.elements.forEach(assigned);
        else if (ts.isObjectLiteralExpression(target)) target.properties.forEach(property => {
          if (ts.isShorthandPropertyAssignment(property)) roots.push(property.name.text);
          else if (ts.isPropertyAssignment(property)) assigned(property.initializer);
        });
      };
      assigned(node.left);
      for (const name of roots) writes.push({ scope, name });
    }
    ts.forEachChild(node, child => collect(child, scope));
  };
  collect(sf, top);
  // Writes in a nested block affect the nearest lexical binding, not a new local.
  for (const { scope, name } of writes) {
    let target = scope;
    while (target.parent && !target.bindings.has(name)) target = target.parent;
    bind(target, name, { kind: "shadowed" });
  }
  for (const descriptor of descriptors) {
    const values = descriptor.bindingScope && descriptor.bindingScope.bindings.get(descriptor.name);
    descriptor.bindingStatic = !!values && values.every(value => value.kind === "local");
    let declaration = descriptor.node;
    if (functionValue(declaration) && declaration.parent && ts.isVariableDeclaration(declaration.parent)) {
      declaration = declaration.parent.parent.parent;
    }
    const modifiers = declaration.modifiers || [];
    descriptor.exportNames = modifiers.some(m => m.kind === ts.SyntaxKind.DefaultKeyword) ? ["default"]
      : modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword) ? [descriptor.name] : [];
  }
  for (const { local, exported } of localExports) {
    const values = top.bindings.get(local) || [];
    if (values.length === 1 && values[0].kind === "local" && values[0].definition.bindingStatic) {
      values[0].definition.exportNames.push(exported);
    }
  }

  // A syntax-token digest ignores source locations and formatting, retaining literal
  // contents. Only duplicate definitions need the suffix; identical duplicates use
  // an occurrence suffix (indistinguishable ASTs have no stronger static identity).
  const digest = node => {
    const parts = [];
    const visit = n => {
      parts.push(n.kind);
      if (typeof n.text === "string") parts.push(n.text);
      ts.forEachChild(n, visit);
    };
    visit(node);
    return crypto.createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 12);
  };
  const groups = new Map();
  for (const descriptor of descriptors) {
    const owner = descriptor.parent;
    if (!groups.has(owner)) groups.set(owner, new Map());
    const byName = groups.get(owner);
    if (!byName.has(descriptor.name)) byName.set(descriptor.name, []);
    byName.get(descriptor.name).push(descriptor);
  }
  const assign = descriptor => {
    if (descriptor.qname) return descriptor.qname;
    const group = groups.get(descriptor.parent).get(descriptor.name);
    let part = descriptor.name;
    if (group.length > 1) {
      const hash = digest(descriptor.node);
      const same = group.filter(other => digest(other.node) === hash);
      const ordinal = same.indexOf(descriptor) + 1;
      part += "~" + hash + (ordinal > 1 ? "~" + ordinal : "");
    }
    descriptor.qname = descriptor.parent ? assign(descriptor.parent) + "." + part : relPath + "::" + part;
    return descriptor.qname;
  };
  for (const descriptor of descriptors) {
    const node = descriptor.node;
    let signature = node.getText(sf);
    if (node.body) signature = signature.slice(0, Math.max(0, node.body.getStart(sf) - node.getStart(sf)));
    const docs = ts.getJSDocCommentsAndTags(node);
    const comment = docs.length && docs[0].comment;
    symbols.push({
      qname: assign(descriptor), name: descriptor.name, kind: descriptor.kind,
      file: relPath, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
      end_line: sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1,
      signature: signature.replace(/\s+/g, " ").trim().slice(0, 200),
      parent: descriptor.parent ? assign(descriptor.parent) : null,
      docstring: typeof comment === "string" ? comment : null,
      export_names: descriptor.exportNames, binding_is_static: descriptor.bindingStatic,
    });
  }
  const findBinding = (scope, root) => {
    for (let current = scope; current; current = current.parent) {
      // Member names are not lexical locals inside methods.
      if (isClass(current.node)) continue;
      const values = current.bindings.get(root);
      if (!values || !values.length) continue;
      if (values.every(value => value.kind === "local")) {
        return { binding_kind: "local", binding_scope: current.owner ? assign(current.owner) : null,
          binding_target: values.length === 1 ? assign(values[0].definition) : null };
      }
      if (values.length !== 1) return { binding_kind: "shadowed" };
      const value = values[0];
      return { binding_kind: value.kind, module: value.module || "", imported_name: value.original || "" };
    }
    return { binding_kind: "unbound" };
  };
  const visitCalls = (node, scope) => {
    scope = scopes.get(node) || scope;
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const expression = node.expression;
      let name = null, receiver = null;
      if (ts.isIdentifier(expression)) name = expression.text;
      else if (ts.isPropertyAccessExpression(expression)) {
        name = nameOf(expression.name);
        receiver = expression.expression.getText(sf);
      }
      if (name) {
        let moduleLevel = true;
        for (let ancestor = node.parent; ancestor && !ts.isSourceFile(ancestor); ancestor = ancestor.parent) {
          if (isFunction(ancestor) || isClass(ancestor)) { moduleLevel = false; break; }
        }
        let root = expression;
        while (ts.isPropertyAccessExpression(root)) root = root.expression;
        const binding = ts.isIdentifier(root) ? findBinding(scope, root.text) : { binding_kind: "shadowed" };
        calls.push({ caller_qname: scope.owner ? assign(scope.owner) : null,
          is_module_level: moduleLevel,
          callee_name: name, file: relPath,
          line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
          receiver, expression: expression.getText(sf), ...binding });
      }
    }
    ts.forEachChild(node, child => visitCalls(child, scope));
  };
  visitCalls(sf, top);
  const importMap = {};
  for (const [module, names] of Object.entries(imports)) importMap[module] = Array.from(names).sort();
  return { symbols, calls, imports: Object.keys(imports), import_map: importMap, import_kinds: importKinds,
    exports: [], lines: source.split("\n").length - 1, parse_ok: true };
}

let buffer = "";
process.stdin.on("data", data => {
  buffer += data.toString();
  let index;
  while ((index = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, index);
    buffer = buffer.slice(index + 1);
    if (!line.trim()) continue;
    let message;
    try { message = JSON.parse(line); } catch (error) { continue; }
    try {
      if (typeof message.source !== "string") throw new Error("SOURCE_SNAPSHOT_REQUIRED");
      const source = message.source;
      process.stdout.write(JSON.stringify({ id: message.id, ok: true,
        result: extract(message.abs, message.rel, source) }) + "\n");
    } catch (error) {
      process.stdout.write(JSON.stringify({ id: message.id, ok: false,
        error: String(error && error.message || error) }) + "\n");
    }
  }
});
process.stdin.on("end", () => process.exit(0));
"""


class TypeScriptParser:
    """Persistent, bounded syntax-only Node worker using the managed compiler."""

    language = Language.TYPESCRIPT
    MAX_SOURCE_BYTES = 8 * 1024 * 1024
    MAX_RESPONSE_BYTES = 32 * 1024 * 1024

    def __init__(self, project_root: Path, toolchain: Toolchain | None = None, *, timeout_seconds: float = 10):
        self.project_root = Path(project_root).resolve()
        self.toolchain = toolchain or get_toolchain(self.project_root)
        self.node = self.toolchain.node
        self.ts_path = self.toolchain.typescript_path
        self.timeout_seconds = timeout_seconds
        self._proc: subprocess.Popen[str] | None = None
        self._counter = 0
        self._last_parse_ok = True
        self._last_parse_error: str | None = None
        self._last_import_kinds: dict[str, str] = {}
        self._responses: queue.Queue | None = None
        self._stderr: list[str] = []
        self._readers: list[threading.Thread] = []

    def _ensure_proc(self) -> subprocess.Popen[str]:
        if self._proc is not None and self._proc.poll() is None:
            return self._proc
        if not self.node or not self.ts_path:
            details = ', '.join(self.toolchain.diagnostics)
            raise RuntimeError('managed_typescript_unavailable: ' + details)
        compiler = Path(self.ts_path).resolve()
        expected = (managed_typescript_dir() / 'lib' / 'typescript.js').resolve()
        if compiler != expected or hashlib.sha256(compiler.read_bytes()).hexdigest() != TYPESCRIPT_COMPILER_SHA256:
            raise RuntimeError('unmanaged_or_modified_typescript_rejected')
        node = Path(self.node).resolve()
        if node.is_relative_to(self.project_root):
            raise RuntimeError('node_executable_inside_target_rejected')
        if not self.toolchain.node_sha256 or hashlib.sha256(node.read_bytes()).hexdigest() != self.toolchain.node_sha256:
            raise RuntimeError('node_identity_changed')
        script_path = Path(__file__).with_name('_ts_extract.js').resolve()
        if script_path.read_text(encoding='utf-8') != _NODE_SCRIPT:
            raise RuntimeError('parser_script_identity_mismatch')
        try:
            proc = subprocess.Popen(
                [str(node), '--no-global-search-paths', '--no-addons', '--max-old-space-size=512',
                 str(script_path), str(compiler)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=node.parent, env=clean_process_environment(), text=True,
                encoding='utf-8', errors='strict', bufsize=1,
            )
        except OSError as error:
            raise RuntimeError('typescript_worker_start_failed') from error
        self._proc = proc
        responses: queue.Queue = queue.Queue(maxsize=4)
        self._responses = responses
        self._stderr = []

        def stdout_reader():
            try:
                assert proc.stdout
                while True:
                    line = proc.stdout.readline(self.MAX_RESPONSE_BYTES + 1)
                    if not line:
                        responses.put_nowait(RuntimeError('typescript_worker_closed'))
                        return
                    if len(line.encode('utf-8')) > self.MAX_RESPONSE_BYTES or not line.endswith('\n'):
                        responses.put_nowait(RuntimeError('typescript_worker_output_limit'))
                        return
                    responses.put_nowait(line)
            except Exception:
                try:
                    responses.put_nowait(RuntimeError('typescript_worker_protocol_error'))
                except queue.Full:
                    pass

        def stderr_reader():
            try:
                assert proc.stderr
                while chunk := proc.stderr.read(1024):
                    self._stderr = [(("".join(self._stderr)) + chunk)[-8192:]]
            except (OSError, ValueError):
                pass

        self._readers = [threading.Thread(target=stdout_reader, daemon=True),
                         threading.Thread(target=stderr_reader, daemon=True)]
        for reader in self._readers:
            reader.start()
        return proc

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
        for reader in self._readers:
            reader.join(timeout=0.2)
        self._readers = []
        self._responses = None

    def __enter__(self) -> "TypeScriptParser":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------- 解析 ----------

    _KIND_MAP = {
        "class": SymbolKind.CLASS,
        "function": SymbolKind.FUNCTION,
        "method": SymbolKind.METHOD,
        "interface": SymbolKind.INTERFACE,
        "type_alias": SymbolKind.TYPE_ALIAS,
        "enum": SymbolKind.ENUM,
        "constant": SymbolKind.CONSTANT,
        "property": SymbolKind.PROPERTY,
    }

    def parse_with_meta(
        self, path: Path, rel_path: str, text: str
    ) -> tuple[list[Symbol], list[CallSite], FileMeta, dict[str, set[str]]]:
        """一次读取 + 一次解析，产出符号、调用点、元数据与 import 表。"""
        symbols, calls, imports = self._extract_via_node(path, rel_path, text)

        stat = path.stat() if path.exists() else None
        meta = FileMeta(
            path=rel_path,
            language=Language.TYPESCRIPT,
            lines=text.count("\n"),
            content_hash=hashlib.sha1(
                text.encode("utf-8", errors="replace")).hexdigest(),
            mtime=stat.st_mtime if stat else 0.0,
            imports=sorted(imports.keys()),
            is_parsed=self._last_parse_ok,
            parse_error=self._last_parse_error,
            import_kinds=dict(self._last_import_kinds),
        )
        return symbols, calls, meta, imports

    def _extract_via_node(
        self, path: Path, rel_path: str, text: str | None = None,
    ) -> tuple[list[Symbol], list[CallSite], dict[str, set[str]]]:
        path = Path(path)
        if not path.resolve().is_relative_to(self.project_root):
            raise RuntimeError('typescript_source_outside_project')
        text = path.read_text(encoding='utf-8') if text is None else text
        if len(text.encode('utf-8')) > self.MAX_SOURCE_BYTES:
            raise RuntimeError('typescript_source_size_limit')
        self._last_parse_ok = False
        self._last_parse_error = None
        self._last_import_kinds = {}
        proc = self._ensure_proc()
        deadline = time.monotonic() + self.timeout_seconds
        self._counter += 1
        msg_id = self._counter
        assert proc.stdin and self._responses is not None
        sent: queue.Queue = queue.Queue(maxsize=1)
        payload = json.dumps({'id': msg_id, 'abs': str(path), 'rel': rel_path, 'source': text}) + '\n'

        def write_request():
            try:
                proc.stdin.write(payload)
                proc.stdin.flush()
                sent.put_nowait(None)
            except Exception as error:
                sent.put_nowait(error)

        writer = threading.Thread(target=write_request, daemon=True)
        writer.start()
        try:
            write_error = sent.get(timeout=max(0.000001, deadline - time.monotonic()))
            if write_error is not None:
                raise RuntimeError('typescript_worker_write_failed') from write_error
            line = self._responses.get(timeout=max(0.000001, deadline - time.monotonic()))
            if isinstance(line, Exception):
                raise line
            resp = json.loads(line)
            if resp.get('id') != msg_id:
                raise RuntimeError('typescript_worker_response_mismatch')
        except queue.Empty as error:
            self.close()
            writer.join(timeout=0.2)
            raise RuntimeError('typescript_parse_timeout') from error
        except (RuntimeError, ValueError) as error:
            self.close()
            raise RuntimeError(str(error)) from error
        if not resp.get('ok'):
            self._last_parse_error = 'typescript_extraction_failed'
            return [], [], {}

        result = resp["result"]
        self._last_parse_ok = result.get("parse_ok", True)
        self._last_parse_error = None if self._last_parse_ok else 'typescript_syntax_error'
        self._last_import_kinds = result.get('import_kinds', {})
        symbols = [
            Symbol(
                qname=s["qname"], name=s["name"],
                kind=self._KIND_MAP.get(s["kind"], SymbolKind.FUNCTION),
                file=s["file"], line=s["line"], end_line=s["end_line"],
                signature=s.get("signature", ""),
                docstring=s.get("docstring"),
                parent=s.get("parent"),
                export_names=s.get("export_names", []),
                binding_is_static=s.get("binding_is_static", False),
            )
            for s in result.get("symbols", [])
        ]
        calls = [
            CallSite(
                caller_qname=c.get("caller_qname"),
                callee_name=c["callee_name"],
                file=c["file"], line=c["line"],
                receiver=c.get("receiver"), expression=c.get("expression", ""),
                module=c.get("module", ""), imported_name=c.get("imported_name", ""),
                binding_kind=c.get("binding_kind", ""),
                binding_scope=c.get("binding_scope"), binding_target=c.get("binding_target"),
                is_module_level=c.get("is_module_level"),
            )
            for c in result.get("calls", [])
        ]
        # Node 侧已抽出的 import 映射
        imports: dict[str, set[str]] = {}
        for mod, names in (result.get("import_map") or {}).items():
            imports[mod] = set(names)
        return symbols, calls, imports

    def parse(
        self, path: Path, rel_path: str
    ) -> tuple[list[Symbol], list[CallSite]]:
        symbols, calls, _ = self._extract_via_node(path, rel_path)
        return symbols, calls

    def file_meta(
        self, path: Path, rel_path: str, is_test: bool, is_script: bool,
        is_data: bool,
    ) -> FileMeta:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        stat = path.stat() if path.exists() else None
        return FileMeta(
            path=rel_path,
            language=Language.TYPESCRIPT,
            lines=text.count("\n"),
            is_test=is_test,
            is_script=is_script,
            is_data=is_data,
            content_hash=hashlib.sha1(
                text.encode("utf-8", errors="replace")
            ).hexdigest(),
            mtime=stat.st_mtime if stat else 0.0,
        )
