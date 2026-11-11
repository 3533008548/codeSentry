


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
