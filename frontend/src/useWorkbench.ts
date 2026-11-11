import { useEffect, useRef, useState } from "react";
import { ApiError, type Api, type FileContent, type SourceFile, type Workspace } from "./api";
import { accessConfirmed, accessKey, ensureAccess } from "./access";
import { aborted, errorMessage } from "./format";
import { clearView, emptyView, initialWorkspace, readView, writeView, type WorkspaceView } from "./state";
import { clearReaderCache } from "./readerCache";

interface WorkspaceData {
  id: string; scope: string; files: SourceFile[]; truncated: boolean; loading: boolean; error: string | null;
}
interface FileRecord {
  id: string; scope: string; path: string; content?: FileContent; error?: string;
}

export function useWorkbench(client: Api) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [activeId, setActiveId] = useState<string | null>(initialWorkspace);
  const [initialLoading, setInitialLoading] = useState(true);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [verifiedScope, setVerifiedScope] = useState<string | null>(null);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [data, setData] = useState<WorkspaceData | null>(null);
  const [fileRecord, setFileRecord] = useState<FileRecord | null>(null);
  const [views, setViews] = useState<Record<string, WorkspaceView>>({});
  const [query, setQuery] = useState("");
  const [jump, setJump] = useState({ line: 0, request: 0 });
  const [fileReload, setFileReload] = useState(0);
  const [listReload, setListReload] = useState(0);
  const generation = useRef(0);
  const activeRef = useRef(activeId);
  activeRef.current = activeId;
  const workspacesRef = useRef(workspaces);
  workspacesRef.current = workspaces;
  const savingPolicies = useRef(new Set<string>());
  const workspace = workspaces.find(item => item.id === activeId);
  const scope = accessKey(workspace);
  const accessReady = accessConfirmed(workspace) && verifiedScope === scope;
  const authorized = useRef<Workspace | undefined>(undefined);
  authorized.current = accessReady ? workspace : undefined;
  const current = accessReady && data?.id === activeId && data.scope === scope ? data : null;
  const view = accessReady && activeId ? views[scope] || readView(activeId, scope) : emptyView();
  const selectedPath = useRef(view.selected);
  selectedPath.current = view.selected;
  const ownedFile = accessReady && fileRecord?.id === activeId && fileRecord.scope === scope
    && fileRecord.path === view.selected ? fileRecord : null;

  function currentGeneration(id: string, epoch: number, key: string) {
    return activeRef.current === id && generation.current === epoch && accessKey(authorized.current) === key;
  }
  function revoke(id: string) {
    if (activeRef.current === id) {
      generation.current += 1;
      authorized.current = undefined;
      setVerifiedScope(null);
    }
    clearReaderCache(id);
    clearView(id);
    setViews(previous => Object.fromEntries(Object.entries(previous).filter(([key]) => !key.startsWith(id + ":"))));
    setData(previous => previous?.id === id ? null : previous);
    setFileRecord(previous => previous?.id === id ? null : previous);
  }
  function adoptWorkspace(value: Workspace) {
    const previous = workspacesRef.current.find(item => item.id === value.id);
    if ((value.access_policy?.version ?? 0) < (previous?.access_policy?.version ?? 0)) return;
    if (accessKey(previous) !== accessKey(value) || !accessConfirmed(value)) revoke(value.id);
    const next = previous ? workspacesRef.current.map(item => item.id === value.id ? value : item)
      : [value, ...workspacesRef.current];
    workspacesRef.current = next;
    setWorkspaces(next);
    if (activeRef.current === value.id && !savingPolicies.current.has(value.id)) {
      setVerifiedScope(accessKey(value));
      setAccessError(null);
    }
  }
  async function refreshWorkspace(id = activeRef.current, signal?: AbortSignal) {
    if (!id || savingPolicies.current.has(id)) return;
    try {
      const value = await client.workspace(id, signal);
      if (!signal?.aborted && activeRef.current === id && !savingPolicies.current.has(id)) adoptWorkspace(value);
    } catch (error) {
      if (!signal?.aborted && !aborted(error) && activeRef.current === id) setAccessError(errorMessage(error));
    }
  }
  function beginPolicySave(id: string) {
    savingPolicies.current.add(id);
    revoke(id);
  }
  function finishPolicySave(value: Workspace) {
    savingPolicies.current.delete(value.id);
    adoptWorkspace(value);
  }
  function policySaveFailed(id: string) {
    savingPolicies.current.delete(id);
    void refreshWorkspace(id);
  }
  function authorizationLost() {
    const id = authorized.current?.id;
    if (id) {
      revoke(id);
      setAccessError("文件访问范围已变化，正在重新核对工作空间。");
      void refreshWorkspace(id);
    }
  }
  function selectWorkspace(id: string) {
    if (id === activeRef.current) {
      void refreshWorkspace(id);
      return;
    }
    generation.current += 1;
    authorized.current = undefined;
    setVerifiedScope(null);
    setActiveId(id);
    setQuery("");
    setJump(previous => ({ line: 0, request: previous.request + 1 }));
  }
  function updateView(id: string, patch: Partial<WorkspaceView>) {
    const allowed = authorized.current;
    if (!allowed || allowed.id !== id) return;
    const key = accessKey(allowed);
    setViews(previous => {
      const next = { ...(previous[key] || readView(id, key)), ...patch };
      writeView(id, next, key);
      return { ...previous, [key]: next };
    });
  }
  function openFile(path: string, line = 0) {
    if (!activeId || !accessReady) return;
    const parts = path.split("/");
    updateView(activeId, {
      tabs: [path],
      selected: path,
      expanded: [...new Set([...view.expanded, ...parts.slice(0, -1).map((_, index) => parts.slice(0, index + 1).join("/"))])],
    });
    setJump(previous => ({ line, request: previous.request + 1 }));
  }
  function created(value: Workspace) {
    adoptWorkspace(value);
    if (value.id !== activeRef.current) selectWorkspace(value.id);
    else void refreshWorkspace(value.id);
  }

  useEffect(() => {
    const controller = new AbortController();
    setInitialLoading(true);
    setConnectionError(null);
    client.workspaces(controller.signal).then(items => {
      if (controller.signal.aborted) return;
      workspacesRef.current = items;
      setWorkspaces(items);
      setActiveId(previous => items.some(item => item.id === previous) ? previous : items[0]?.id || null);
    }).catch(error => {
      if (!controller.signal.aborted && !aborted(error)) setConnectionError(errorMessage(error));
    }).finally(() => {
      if (!controller.signal.aborted) setInitialLoading(false);
    });
    return () => controller.abort();
  }, [client, reload]);

  const available = !!workspace;
  useEffect(() => {
    if (!activeId || !available) return;
    const id = activeId;
    const controller = new AbortController();
    generation.current += 1;
    authorized.current = undefined;
    setVerifiedScope(null);
    setAccessError(null);
    setQuery("");
    try {
      history.replaceState(null, "", "#/workspace/" + encodeURIComponent(id));
      localStorage.setItem("codesentry.last-workspace", id);
    } catch {
      /* Browsing is available without persistence. */
    }
    const refresh = () => void refreshWorkspace(id, controller.signal);
    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => { controller.abort(); window.clearInterval(interval); };
  }, [activeId, available, client]);

  useEffect(() => {
    if (!activeId || !workspace || !accessReady) return;
    const id = activeId, key = scope, expected = workspace, epoch = generation.current;
    const controller = new AbortController();
    setData(previous => ({ id, scope: key, files: previous?.id === id && previous.scope === key ? previous.files : [],
      truncated: false, loading: true, error: null }));
    client.files(id, controller.signal).then(files => {
      if (controller.signal.aborted || !currentGeneration(id, epoch, key)) return;
      ensureAccess(files, expected);
      if (files.workspace_id !== id) throw new ApiError("文件列表不属于当前工作空间", 403);
      setData({ id, scope: key, files: files.files, truncated: files.truncated, loading: false, error: null });
    }).catch(error => {
      if (controller.signal.aborted || aborted(error) || !currentGeneration(id, epoch, key)) return;
      if (error instanceof ApiError && error.status === 403) authorizationLost();
      else setData(previous => previous?.id === id && previous.scope === key
        ? { ...previous, loading: false, error: errorMessage(error) } : previous);
    });
    return () => controller.abort();
  }, [activeId, scope, accessReady, client, listReload]);

  useEffect(() => {
    if (!activeId || !workspace || !accessReady || !view.selected) return;
    const id = activeId, key = scope, expected = workspace, path = view.selected, epoch = generation.current;
    const controller = new AbortController();
    const alive = () => !controller.signal.aborted && currentGeneration(id, epoch, key) && selectedPath.current === path;
    setFileRecord(null);
    client.file(id, path, undefined, controller.signal).then(value => {
      if (!alive()) return;
      ensureAccess(value, expected);
      if (value.workspace_id !== id || value.path !== path) throw new ApiError("源码不属于当前文件", 403);
      setFileRecord({ id, scope: key, path, content: value });
    }).catch(error => {
      if (!alive() || aborted(error)) return;
      if (error instanceof ApiError && error.status === 403) authorizationLost();
      else setFileRecord({ id, scope: key, path, error: errorMessage(error) });
    });
    return () => controller.abort();
  }, [activeId, scope, accessReady, view.selected, client, fileReload]);

  return {
    workspaces, activeId, initialLoading, connectionError, workspace, accessReady, accessError,
    verifiedScope, scope, current, view, query, setQuery,
    content: ownedFile?.content, fileError: ownedFile?.error, fileLoading: !!view.selected && !ownedFile,
    jumpLine: jump.line, jumpRequest: jump.request,
    retryConnection: () => setReload(value => value + 1),
    selectWorkspace, updateView, openFile, authorizationLost,
    refreshFiles: () => { setListReload(value => value + 1); setFileReload(value => value + 1); },
    reloadFile: () => setFileReload(value => value + 1),
    refreshWorkspace, created, beginPolicySave, finishPolicySave, policySaveFailed,
  };
}
