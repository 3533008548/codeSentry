import { lazy, Suspense, useEffect, useState } from "react";
import { Check, FileCode2, FolderOpen, LoaderCircle, Maximize2, PanelLeftClose, PanelLeftOpen,
  PanelRightClose, PanelRightOpen, Plus, RefreshCw, RotateCcw, Search, Settings2, ShieldCheck, TriangleAlert, X } from "lucide-react";
import { api, type Api, type ChatSourceLocation } from "./api";
import { AccessDialog } from "./AccessDialog";
import { accessConfirmed } from "./access";
import { FileTree } from "./FileTree";
import { shortPath } from "./format";
import { ModelSettingsDialog } from "./ModelSettingsDialog";
import { ProjectChatPane } from "./ProjectChat";
import { usePanelLayout } from "./usePanelLayout";
import { useProjectChat } from "./useProjectChat";
import { useWorkbench } from "./useWorkbench";

const CodeViewer = lazy(() => import("./CodeViewer").then(module => ({ default: module.CodeViewer })));

export default function App({ client = api }: { client?: Api }) {
  const [draft, setDraft] = useState("");
  const [citation, setCitation] = useState<ChatSourceLocation | null>(null);
  const [dialog, setDialog] = useState<"add" | "access" | "confirm" | "model" | null>(null);
  const bench = useWorkbench(client);
  const { activeId, workspace, scope, accessReady, current, view, content } = bench;
  const layout = usePanelLayout(activeId, 0);
  const { showLeft, setShowLeft, setShowRight } = layout;
  const showRight = layout.showRight && accessReady;
  const chat = useProjectChat(client, accessReady ? workspace : undefined, bench.authorizationLost);
  const citationStale = !!(citation && content?.path === citation.path && content.sha256 !== citation.sha256);

  useEffect(() => { setDialog(null); }, [activeId]);
  useEffect(() => { setDraft(""); setCitation(null); }, [scope]);
  useEffect(() => {
    if (workspace && !accessConfirmed(workspace) && bench.verifiedScope === scope) {
      setDialog(previous => previous === "add" || previous === "access" ? previous : "confirm");
    }
  }, [scope, bench.verifiedScope]);

  function openFile(path: string, location?: ChatSourceLocation) {
    bench.openFile(path, location?.line);
    setCitation(location ?? null);
    if (innerWidth <= 760) setShowLeft(false);
    setShowRight(true);
  }

  return <div ref={layout.container} style={layout.style}
    className={`app-shell workbench-layout learning-mode ${showLeft ? "" : "left-hidden"} ${showRight ? "" : "right-hidden"}`}>
    <header className="app-topbar">
      <div className="brand"><span className="brand-mark"><ShieldCheck size={20} /></span><strong>CodeSentry</strong></div>
      <div className="topbar-divider" />
      <span className="topbar-workspace"><FolderOpen size={14} />{workspace?.name || "工作空间"}</span>
      <div className="topbar-actions">
        <button className="icon-button" title={showLeft ? "收起文件栏" : "显示文件栏"} aria-label={showLeft ? "收起文件栏" : "显示文件栏"}
          aria-expanded={showLeft} onClick={() => setShowLeft(value => !value)}>
          {showLeft ? <PanelLeftClose size={17} /> : <PanelLeftOpen size={17} />}
        </button>
        <button className="icon-button" title={showRight ? "收起源码预览" : "显示源码预览"} aria-label={showRight ? "收起源码预览" : "显示源码预览"}
          aria-expanded={showRight} disabled={!accessReady} onClick={() => setShowRight(value => !value)}>
          {showRight ? <PanelRightClose size={17} /> : <PanelRightOpen size={17} />}
        </button>
        <button className="layout-action" onClick={layout.focus} aria-label={!showLeft && !showRight ? "退出专注" : "专注对话"} title="专注对话">
          <Maximize2 size={14} /><span>{!showLeft && !showRight ? "退出专注" : "专注对话"}</span>
        </button>
        <button className="layout-action" onClick={layout.reset} aria-label="恢复布局" title="恢复布局"><RotateCcw size={14} /><span>恢复布局</span></button>
        <button className="icon-button" disabled={!workspace} aria-label="工作空间设置" title="文件访问范围" onClick={() => setDialog("access")}><Settings2 size={17} /></button>
      </div>
    </header>

    <aside className="explorer" aria-label="文件和工作空间">
      <div className="explorer-heading"><span>工作空间</span>
        <button className="icon-button collapse-panel" aria-label="收起左侧栏" onClick={() => setShowLeft(false)}><PanelLeftClose size={15} /></button>
        <button className="icon-button" aria-label="添加工作空间" title="添加工作空间" disabled={bench.initialLoading} onClick={() => setDialog("add")}><Plus size={16} /></button>
      </div>
      <div className="workspace-list">{bench.workspaces.map(item =>
        <button data-testid="workspace-card" data-workspace-id={item.id} key={item.id}
          className={`workspace-item ${activeId === item.id ? "active" : ""}`} title={item.path} onClick={() => bench.selectWorkspace(item.id)}>
          <span className="workspace-initial">{item.name.slice(0, 1).toUpperCase()}</span>
          <span className="workspace-item-text"><strong>{item.name}</strong><span>{shortPath(item.path)}</span></span>
          {activeId === item.id && <span className="workspace-selected"><Check size={13} /></span>}
        </button>)}</div>
      {!workspace && <button className="add-workspace-inline" disabled={bench.initialLoading} onClick={() => setDialog("add")}><Plus size={13} />打开项目目录</button>}
      <div className="source-explorer">
        <div className="explorer-subhead"><span>文件</span><div><span className="muted-count">{current?.files.length || 0}</span>
          <button className="icon-button small" title="刷新文件列表" aria-label="刷新文件列表" disabled={!accessReady} onClick={bench.refreshFiles}><RefreshCw size={13} /></button></div></div>
        {accessReady && <div className="file-search"><Search size={13} /><input aria-label="筛选文件" placeholder="筛选文件…" value={bench.query}
          onChange={event => bench.setQuery(event.target.value)} />
          {bench.query && <button className="icon-button small" aria-label="清除文件筛选" onClick={() => bench.setQuery("")}><X size={12} /></button>}</div>}
        <div className="tree-scroll">
          {workspace && !accessReady ? <p className="empty-inline">确认访问范围后显示文件。</p>
            : current?.loading || accessReady && !current ? <p className="tree-loading"><LoaderCircle size={15} className="spin" />读取项目文件…</p>
            : current?.error ? <p className="empty-inline" role="alert">{current.error}</p>
            : current ? <FileTree files={current.files} query={bench.query} expanded={view.expanded} selected={view.selected}
              onToggle={path => activeId && bench.updateView(activeId, { expanded: view.expanded.includes(path)
                ? view.expanded.filter(item => item !== path) : [...view.expanded, path] })} onOpen={path => openFile(path)} />
            : <p className="empty-inline">打开项目后，文件会显示在这里。</p>}
          {current?.truncated && <p className="tree-warning">文件列表已达到显示上限。</p>}
        </div>
      </div>
    </aside>
    {layout.separator("left")}

    {workspace && accessReady && !bench.connectionError
      ? <ProjectChatPane key={scope} chat={chat} files={current?.files || []} selectedPath={view.selected}
          draft={draft} setDraft={setDraft} onOpen={location => openFile(location.path, location)}
          onModel={() => setDialog("model")} onAccess={() => setDialog("access")} />
      : <main className="main-pane">
        {bench.connectionError ? <div className="center-state" role="alert"><TriangleAlert size={34} /><h2>暂时无法连接工作台</h2>
          <p>{bench.connectionError}</p><button className="button primary" onClick={bench.retryConnection}>重新连接</button></div>
          : bench.initialLoading ? <div className="center-state"><LoaderCircle size={29} className="spin" /><p>正在打开本地工作空间…</p></div>
          : !workspace ? <div className="welcome-screen"><div className="welcome-emblem"><ShieldCheck size={42} /></div><h1>从一个项目开始。</h1>
            <p>理解代码，检查复杂度，讨论重构。</p><button className="button primary large" onClick={() => setDialog("add")}><FolderOpen size={17} />打开项目目录</button></div>
          : <div className="center-state access-gate" data-testid="access-gate"><ShieldCheck size={34} />
            <h2>{workspace.access_policy?.cleanup_pending ? "访问范围待清理" : accessConfirmed(workspace) ? "正在核对文件访问范围" : "确认文件访问范围"}</h2>
            {bench.accessError && <p role="alert">{bench.accessError}</p>}
            {workspace.access_policy?.issues?.map((issue, index) => <p key={index}>{issue}</p>)}
            <button className="button primary" onClick={() => setDialog("confirm")}>确认文件访问范围</button>
            <button className="text-button" onClick={() => void bench.refreshWorkspace()}>重新核对状态</button></div>}
      </main>}
    {showRight && <aside className="main-pane source-pane" aria-label="源码预览">
      <div className="source-heading"><h2>源码预览</h2><button className="icon-button" aria-label="收起右侧栏" onClick={() => setShowRight(false)}><PanelRightClose size={15} /></button></div>
      {view.selected ? <>
        <div className="file-breadcrumb"><FileCode2 size={14} /><strong title={view.selected}>{view.selected}</strong>
          <button className="icon-button small" aria-label="刷新当前文件" onClick={bench.reloadFile}><RefreshCw size={13} /></button>
          <span className="readonly-tag">只读</span>
          {content?.access_mode === "local_only" && <span className="local-source-tag">仅限本地分析</span>}</div>
        {citationStale && <div className="stale-banner" role="status"><TriangleAlert size={15} />文件已在本轮引用后变化，当前显示最新内容；旧引用行号不再定位。</div>}
        {bench.fileError ? <div className="center-state" role="alert"><p>{bench.fileError}</p><button className="text-button" onClick={bench.reloadFile}>重新读取</button></div>
          : bench.fileLoading ? <div className="center-state"><LoaderCircle size={22} className="spin" /><p>正在读取源码…</p></div>
          : content && <Suspense fallback={<div className="center-state"><LoaderCircle size={22} className="spin" /><p>准备源码预览…</p></div>}>
            <CodeViewer key={scope + ":" + content.path} file={content} jumpLine={citationStale ? 0 : bench.jumpLine} jumpRequest={bench.jumpRequest}
              evidenceRange={citation && !citationStale && citation.path === content.path ? { start: citation.line, end: citation.end_line } : undefined} />
          </Suspense>}
      </> : <div className="source-placeholder"><FileCode2 size={28} /><p>从文件列表或对话引用打开源码。</p>
        {!showLeft && <button className="button secondary" onClick={() => setShowLeft(true)}>显示文件列表</button>}</div>}
    </aside>}
    {layout.separator("right")}
    <footer className="status-bar"><span><span className="live-dot" />本地工作台</span>
      {workspace && <span className="status-path" title={workspace.path}>{workspace.path}</span>}
      <span className="status-spacer" />{content && <span>{content.lines} 行 · {content.language}</span>}</footer>

    {dialog === "add" && <AccessDialog client={client} knownWorkspaces={bench.workspaces} onClose={() => setDialog(null)}
      onSaved={value => { bench.finishPolicySave(value); bench.created(value); setDialog(null); }}
      onPolicySaveStart={bench.beginPolicySave} onPolicySaveFailed={bench.policySaveFailed} />}
    {(dialog === "access" || dialog === "confirm") && workspace && <AccessDialog key={workspace.id + ":" + dialog} client={client}
      workspace={workspace} settingsMode={dialog === "access"} onClose={() => setDialog(null)}
      onSaved={value => { bench.finishPolicySave(value); setDialog(null); }}
      onPolicySaveStart={bench.beginPolicySave} onPolicySaveFailed={bench.policySaveFailed} />}
    {dialog === "model" && workspace && accessReady && <ModelSettingsDialog key={scope} client={client} workspace={workspace}
      onClose={() => setDialog(null)} onSaved={() => void chat.refreshSettings()} onPermissionLost={() => { setDialog(null); bench.authorizationLost(); }} />}
  </div>;
}
