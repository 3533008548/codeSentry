
const path = require("path");
let ts = null;
try { ts = require("typescript"); }
catch (e) { process.stderr.write("TS_NOT_FOUND\n"); process.exit(3); }

function extract(absPath, relPath, source) {
  const kind = absPath.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(absPath, source, ts.ScriptTarget.Latest, true, kind);

  const symbols = [];
  const spans = [];
  const classSpans = [];

  const isTest = /(^|[\\/])tests?[\\/]|(^|[\\/])__tests__[\\/]|\.(test|spec)\.[jt]sx?$/.test(relPath);

  const nameOf = (n) => {
    if (ts.isIdentifier(n) || ts.isStringLiteral(n) || ts.isPrivateIdentifier(n)) return n.text;
    return null;
  };

  // 先收集 class 区间（用于方法的 parent 归属）
  const visit1 = (node) => {
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      const nm = node.name ? node.name.text : null;
      if (nm) {
        classSpans.push([
          sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
          sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1,
          nm,
        ]);
      }
    }
    ts.forEachChild(node, visit1);
  };
  visit1(sf);

  const findParent = (line) => {
    let best = null, bestW = null;
    for (const [s, e, nm] of classSpans) {
      if (s <= line && line <= e) {
        const w = e - s;
        if (bestW === null || w < bestW) { bestW = w; best = nm; }
      }
    }
    return best;
  };

  const sig = (node) => {
    try {
      const text = node.getText(sf);
      const b = text.indexOf("{");
      return (b > 0 ? text.slice(0, b) : text).replace(/\s+/g, " ").trim().slice(0, 200);
    } catch (e) { return ""; }
  };

  const doc = (node) => {
    try {
      const d = ts.getJSDocCommentsAndTags(node);
      if (d && d.length && d[0].comment) {
        return typeof d[0].comment === "string"
          ? d[0].comment
          : (d[0].comment.map((x) => x.text || "").join(" "));
      }
    } catch (e) {}
    return null;
  };

  const visit = (node) => {
    let name = null, kind = null;
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      if (node.name) { name = node.name.text; kind = "class"; }
    } else if (ts.isFunctionDeclaration(node) && node.name) {
      name = node.name.text; kind = "function";
    } else if (ts.isMethodDeclaration(node) && node.name) {
      name = nameOf(node.name); kind = "method";
    } else if (ts.isInterfaceDeclaration(node)) {
      name = node.name.text; kind = "interface";
    } else if (ts.isTypeAliasDeclaration(node)) {
      name = node.name.text; kind = "type_alias";
    } else if (ts.isEnumDeclaration(node)) {
      name = node.name.text; kind = "enum";
    } else if (ts.isPropertyDeclaration(node) && node.name) {
      const n = nameOf(node.name);
      const parent = node.parent;
      if (n && !n.startsWith("_") && parent && ts.isClassDeclaration(parent)
          && node.modifiers && node.modifiers.some(
            (m) => m.kind === ts.SyntaxKind.StaticKeyword)) {
        name = n; kind = "property";
      }
    } else if (ts.isVariableStatement(node)) {
      const isConst = node.declarationList.flags & ts.NodeFlags.Const;
      if (isConst) {
        for (const d of node.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.name.text === d.name.text.toUpperCase()
              && d.name.text.length > 1) {
            name = d.name.text; kind = "constant";
          }
        }
      }
    }
    if (name) {
      const start = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
      const end = sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
      const parent = kind === "method" ? findParent(start) : null;
      symbols.push({
        qname: relPath + "::" + name,
        name: name,
        kind: kind,
        file: relPath,
        line: start,
        end_line: end,
        signature: sig(node),
        docstring: doc(node),
        parent: parent ? relPath + "::" + parent : null,
      });
      spans.push([start, end, relPath + "::" + name]);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  spans.sort((a, b) => a[0] - b[0]);

  const owner = (line) => {
    let best = null, bestW = null;
    for (const [s, e, q] of spans) {
      if (s <= line && line <= e) {
        const w = e - s;
        if (bestW === null || w < bestW) { bestW = w; best = q; }
      }
    }
    return best;
  };

  const calls = [];
  const visit2 = (node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      let nm = null;
      if (ts.isIdentifier(callee)) nm = callee.text;
      else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.name)) {
        nm = callee.name.text;
      }
      if (nm) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        calls.push({
          caller_qname: owner(line),
          callee_name: nm,
          file: relPath,
          line: line,
        });
      }
    }
    ts.forEachChild(node, visit2);
  };
  visit2(sf);

  // import / export：模块路径 → 导入的符号名
  const imports = {}, exports = [];
  const visit3 = (node) => {
    if (ts.isImportDeclaration(node) && node.moduleSpecifier) {
      const mod = node.moduleSpecifier.text;
      if (!imports[mod]) imports[mod] = [];
      const clause = node.importClause;
      if (clause && clause.name) {
        imports[mod].push(clause.name.text);
        exports.push(clause.name.text);
      }
      if (clause && clause.namedBindings) {
        if (ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            imports[mod].push(el.name.text);
            exports.push(el.name.text);
          }
        } else if (ts.isNamespaceImport(clause.namedBindings)) {
          imports[mod].push(clause.namedBindings.name.text);
          exports.push(clause.namedBindings.name.text);
        }
      }
    }
    if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
      const mod = node.moduleSpecifier.text;
      if (!imports[mod]) imports[mod] = [];
    }
    ts.forEachChild(node, visit3);
  };
  visit3(sf);

  const importMap = {};
  for (const k of Object.keys(imports)) importMap[k] = imports[k];

  return {
    symbols: symbols,
    calls: calls,
    imports: Array.from(new Set(imports)),
    import_map: importMap,
    exports: Array.from(new Set(exports)),
    lines: source.split("\n").length - 1,
  };
}

let buf = "";
process.stdin.on("data", (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, idx);
    buf = buf.slice(idx + 1);
    if (!line.trim()) continue;
    let msg;
    try { msg = JSON.parse(line); }
    catch (e) { continue; }
    try {
      const src = require("fs").readFileSync(msg.abs, "utf8");
      const r = extract(msg.abs, msg.rel, src);
      process.stdout.write(JSON.stringify({ id: msg.id, ok: true, result: r }) + "\n");
    } catch (e) {
      process.stdout.write(JSON.stringify({
        id: msg.id, ok: false, error: String(e && e.message || e)
      }) + "\n");
    }
  }
});
process.stdin.on("end", () => process.exit(0));
