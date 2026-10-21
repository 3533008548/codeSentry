"""TypeScript 解析器。

v0.2 修订：TS 解析器用 **TypeScript 编译器 API**（`ts.createSourceFile`），
不是正则，也**不需要 ts-morph**（ts-morph 的核心价值是类型信息，M4 才用得上）。

实现方式：起一个常驻 Node 子进程，通过 JSON Lines 协议通信。
这样：
  - 复用目标项目已装的 typescript，零新增依赖
  - 避免每个文件起一次进程的开销
  - 与 Python 侧产出同构的数据结构
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from codesentry.core.symbol import (
    CallSite,
    FileMeta,
    Language,
    Symbol,
    SymbolKind,
)


def find_node() -> str | None:
    """定位 node 可执行文件。"""
    for name in ("node", "node.exe"):
        p = shutil.which(name)
        if p:
            return p
    return None


def find_typescript(project_root: Path) -> str | None:
    """在目标项目里找 typescript 模块。"""
    for base in (project_root, project_root.parent):
        candidate = base / "node_modules" / "typescript"
        if candidate.is_dir():
            return str(candidate)
    return None


# Node 侧脚本：读 stdin 的 JSON Lines，输出 JSON Lines
_NODE_SCRIPT = r"""
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
    imports: Object.keys(imports),
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
"""


class TypeScriptParser:
    """通过 Node 子进程调用 TypeScript 编译器 API。"""

    language = Language.TYPESCRIPT

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.node = find_node()
        self.ts_path = find_typescript(project_root)
        self._proc: subprocess.Popen[str] | None = None
        self._counter = 0
        self._tmp_script: Path | None = None

    # ---------- 生命周期 ----------

    def _ensure_proc(self) -> subprocess.Popen[str]:
        if self._proc is not None and self._proc.poll() is None:
            return self._proc
        if not self.node:
            raise RuntimeError("未找到 node 可执行文件，无法解析 TypeScript")
        if not self.ts_path:
            raise RuntimeError(
                f"在 {self.project_root} 下未找到 typescript 模块，"
                "无法解析 TypeScript"
            )
        # 脚本放在包内（固定路径），避免临时文件在 Windows 上的 fd 泄漏
        # 与扩展名问题（mkstemp 生成的文件没有 .js 后缀，Node 的模块
        # 解析行为不稳定）。
        script_path = Path(__file__).parent / "_ts_extract.js"
        script_path.write_text(_NODE_SCRIPT, encoding="utf-8")

        env = dict(os.environ)
        # ts_path 指向 .../node_modules/typescript，其父目录就是 node_modules
        node_modules = str(Path(self.ts_path).parent)
        env["NODE_PATH"] = node_modules + os.pathsep + env.get("NODE_PATH", "")
        try:
            self._proc = subprocess.Popen(
                [self.node, str(script_path)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, text=True,
                encoding="utf-8", bufsize=1,
            )
        except OSError as e:
            raise RuntimeError(f"无法启动 TypeScript 解析进程: {e}") from e
        return self._proc

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None
        self._tmp_script = None

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
        import hashlib
        import re

        symbols, calls, imports = self._extract_via_node(path, rel_path)

        stat = path.stat() if path.exists() else None
        meta = FileMeta(
            path=rel_path,
            language=Language.TYPESCRIPT,
            lines=text.count("\n"),
            content_hash=hashlib.sha1(
                text.encode("utf-8", errors="replace")).hexdigest(),
            mtime=stat.st_mtime if stat else 0.0,
            imports=sorted(imports.keys()),
        )
        return symbols, calls, meta, imports

    def _extract_via_node(
        self, path: Path, rel_path: str
    ) -> tuple[list[Symbol], list[CallSite], dict[str, set[str]]]:
        """通过 Node 进程抽取。"""
        proc = self._ensure_proc()
        self._counter += 1
        msg_id = self._counter
        assert proc.stdin and proc.stdout
        proc.stdin.write(json.dumps({
            "id": msg_id, "abs": str(path), "rel": rel_path,
        }) + "\n")
        proc.stdin.flush()

        line = proc.stdout.readline()
        if not line:
            err = ""
            if proc.stderr:
                err = proc.stderr.read() or ""
            raise RuntimeError(f"TypeScript 解析进程无响应: {err[:400]}")
        resp = json.loads(line)
        if not resp.get("ok"):
            return [], [], {}

        result = resp["result"]
        symbols = [
            Symbol(
                qname=s["qname"], name=s["name"],
                kind=self._KIND_MAP.get(s["kind"], SymbolKind.FUNCTION),
                file=s["file"], line=s["line"], end_line=s["end_line"],
                signature=s.get("signature", ""),
                docstring=s.get("docstring"),
                parent=s.get("parent"),
            )
            for s in result.get("symbols", [])
        ]
        calls = [
            CallSite(
                caller_qname=c.get("caller_qname"),
                callee_name=c["callee_name"],
                file=c["file"], line=c["line"],
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
        import hashlib
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
