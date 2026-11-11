import { useEffect, useRef } from "react";
import * as monaco from "monaco-editor/editor/editor.api";
import EditorWorker from "monaco-editor/editor/editor.worker.js?worker";
import "monaco-editor/languages/definitions/python/register";
import "monaco-editor/languages/definitions/typescript/register";
import "monaco-editor/languages/definitions/javascript/register";
import "monaco-editor/languages/definitions/markdown/register";
import "monaco-editor/languages/definitions/yaml/register";
import "monaco-editor/languages/definitions/shell/register";
import type { FileContent } from "./api";
import { registerReader, readReaderView, saveReaderView } from "./readerCache";
(
  globalThis as typeof globalThis & {
    MonacoEnvironment: {
      getWorker: (moduleId: string, label: string) => Worker;
    };
  }
).MonacoEnvironment = { getWorker: () => new EditorWorker() };
monaco.editor.defineTheme("codesentry-night", {
  base: "vs-dark",
  inherit: true,
  rules: [
    { token: "comment", foreground: "738273" },
    { token: "keyword", foreground: "C4A7E7" },
    { token: "string", foreground: "B7CD96" },
    { token: "number", foreground: "DAB986" },
  ],
  colors: {
    "editor.background": "#151b23",
    "editor.foreground": "#d4dce7",
    "editorLineNumber.foreground": "#4e5c6d",
    "editorLineNumber.activeForeground": "#a8b5c7",
    "editor.selectionBackground": "#294d5b",
    "editor.lineHighlightBackground": "#1c2430",
    "editorCursor.foreground": "#71d5bb",
    "editorWidget.background": "#202935",
    "editorIndentGuide.background1": "#25313f",
  },
});
function language(file: FileContent) {
  const suffix = file.path.split(".").pop()?.toLowerCase();
  if (suffix === "tsx" || suffix === "ts") return "typescript";
  if (suffix === "py") return "python";
  if (suffix === "jsx" || suffix === "js") return "javascript";
  if (suffix === "md") return "markdown";
  if (suffix === "yaml" || suffix === "yml") return "yaml";
  if (suffix === "sh" || suffix === "bat") return "shell";
  return file.language === "unknown" ? "plaintext" : file.language;
}
export function CodeViewer({
  file,
  jumpLine = 0,
  jumpRequest = 0,
  evidenceRange,
}: {
  file: FileContent;
  jumpLine?: number;
  jumpRequest?: number;
  evidenceRange?: { start: number; end: number };
}) {
  const host = useRef<HTMLDivElement>(null);
  const editor = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  useEffect(() => {
    if (!host.current) return;
    const key = `${file.workspace_id}:${file.policy_version}:${file.policy_fingerprint}:${file.path}`;
    const uri = monaco.Uri.from({
      scheme: "codesentry",
      authority: file.workspace_id,
      path: "/" + file.path,
      query: `policy=${file.policy_version}&fingerprint=${file.policy_fingerprint}`,
    });
    monaco.editor.getModel(uri)?.dispose();
    const model = monaco.editor.createModel(file.content, language(file), uri);
    const instance = monaco.editor.create(host.current, {
      model,
      theme: "codesentry-night",
      readOnly: true,
      domReadOnly: true,
      automaticLayout: true,
      fontFamily: "Cascadia Code, Consolas, monospace",
      fontSize: 13,
      lineHeight: 23,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      padding: { top: 16, bottom: 24 },
      lineNumbers: "on",
      renderLineHighlight: "line",
      wordWrap: "off",
      smoothScrolling: true,
      folding: true,
      quickSuggestions: false,
      suggestOnTriggerCharacters: false,
      hover: { enabled: "off" },
      codeLens: false,
      ariaLabel: `代码阅读器 ${file.path}`,
    });
    editor.current = instance;
    const saved = readReaderView<monaco.editor.ICodeEditorViewState>(key);
    if (saved) instance.restoreViewState(saved);
    let revoked = false;
    const unregister = registerReader(file.workspace_id, () => {
      revoked = true;
      instance.setModel(null);
      if (!model.isDisposed()) model.dispose();
    });
    return () => {
      const view = !revoked && instance.saveViewState();
      if (view) saveReaderView(key, view);
      unregister();
      editor.current = null;
      instance.dispose();
      if (!model.isDisposed()) model.dispose();
    };
  }, [
    file.workspace_id,
    file.path,
    file.sha256,
    file.policy_version,
    file.policy_fingerprint,
  ]);
  useEffect(() => {
    const collection = editor.current?.createDecorationsCollection(evidenceRange ? [{
      range: new monaco.Range(evidenceRange.start, 1, evidenceRange.end, 1),
      options: { isWholeLine: true, className: "source-evidence-highlight", linesDecorationsClassName: "source-evidence-marker" },
    }] : []);
    return () => collection?.clear();
  }, [evidenceRange?.start, evidenceRange?.end, file.sha256, file.path]);
  useEffect(() => {
    const line = Math.max(
      1,
      Math.min(jumpLine, editor.current?.getModel()?.getLineCount() || 1),
    );
    if (jumpLine > 0) {
      editor.current?.setPosition({ lineNumber: line, column: 1 });
      editor.current?.revealLineInCenter(line);
    }
  }, [jumpLine, jumpRequest, file.path, file.sha256]);
  return <div className="code-editor" data-testid="code-editor" ref={host} />;
}
