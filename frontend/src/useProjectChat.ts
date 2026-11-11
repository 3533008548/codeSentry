import { useEffect, useRef, useState } from "react";
import { ApiError, type Api, type ChatSettings, type Conversation, type ConversationSummary, type CrapDiscussionTarget, type CrapToolOptions, type InsightDraft, type PolicyIdentity, type Workspace } from "./api";
import { accessKey, ensureAccess } from "./access";

interface ChatState { key: string; settings?: ChatSettings; topics: ConversationSummary[]; current?: Conversation; loading: boolean; error: string | null }
const empty = (key: string): ChatState => ({ key, topics: [], loading: false, error: null });
const latestSettings = (current: ChatSettings | undefined, incoming: ChatSettings) => current &&
  (current.revision > incoming.revision || current.revision === incoming.revision && current.profile_revision > incoming.profile_revision) ? current : incoming;

export function useProjectChat(client: Api, workspace: Workspace | undefined, onPermissionLost: () => void) {
  const key = accessKey(workspace);
  const epoch = useRef(key); epoch.current = key;
  const topicRef = useRef<string | null>(null);
  const mounted = useRef(true);
  const [state, setState] = useState<ChatState>(() => empty(key));
  const [working, setWorking] = useState<string | null>(null);
  const [pollRevision, setPollRevision] = useState(0);
  const busy = useRef(false);
  const visible = state.key === key ? state : empty(key);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  function alive(requestKey: string) { return mounted.current && epoch.current === requestKey; }
  function fail(error: unknown, requestKey: string) {
    if (!alive(requestKey) || (error as Error)?.name === "AbortError") return;
    if (error instanceof ApiError && error.status === 403) {
      setState(empty(requestKey)); onPermissionLost();
    } else setState(value => ({ ...value, loading: false, error: error instanceof Error ? error.message : "暂时无法完成请求，请重试" }));
  }
  function checked<T extends { workspace_id: string; policy_version?: number; policy_fingerprint?: string | null }>(value: T, ws: Workspace) {
    if (value.workspace_id !== ws.id) throw new ApiError("对话工作空间不匹配", 403);
    return ensureAccess(value, ws);
  }
  function remember(id: string, topicId: string) {
    try { localStorage.setItem(`codesentry.chat.last.${id}`, topicId); } catch { /* Optional. */ }
  }
  useEffect(() => {
    topicRef.current = null;
    setWorking(null); busy.current = false;
    setState(empty(key));
    if (!workspace || !client.chatSettings || !client.conversations || !client.conversation) return;
    setState({ ...empty(key), loading: true });
    const ws = workspace, requestKey = key, controller = new AbortController();
    void (async () => {
      try {
        const [settings, topics] = await Promise.all([client.chatSettings!(ws.id, controller.signal), client.conversations!(ws.id, controller.signal)]);
        checked(settings, ws);
        topics.forEach(topic => checked(topic, ws));
        if (!alive(requestKey)) return;
        let remembered: string | null = null;
        try { remembered = localStorage.getItem(`codesentry.chat.last.${ws.id}`); } catch { /* Optional. */ }
        const topic = topics.find(item => item.id === remembered) || topics[0];
        topicRef.current = topic?.id || null;
        const current = topic ? checked(await client.conversation!(ws.id, topic.id, controller.signal), ws) : undefined;
        if (alive(requestKey)) setState(previous => ({ key: requestKey, settings: latestSettings(previous.key === requestKey ? previous.settings : undefined, settings), topics, current, loading: false, error: null }));
      } catch (error) { fail(error, requestKey); }
      finally { if (alive(requestKey)) setState(value => ({ ...value, loading: false })); }
    })();
    return () => controller.abort();
  }, [key, client]);

  const running = visible.current?.turns.some(turn => turn.status === "running") || false;
  useEffect(() => {
    if (!running || !workspace || !visible.current || !client.conversation) return;
    const ws = workspace, cid = visible.current.id, requestKey = key, controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const current = checked(await client.conversation!(ws.id, cid, controller.signal), ws);
        if (!alive(requestKey) || topicRef.current !== cid) return;
        setState(value => ({ ...value, current }));
        if (current.turns.some(turn => turn.status === "running")) timer = setTimeout(poll, 800);
        else if (client.chatSettings) {
          const settings = checked(await client.chatSettings(ws.id, controller.signal), ws);
          if (alive(requestKey)) setState(value => ({ ...value, settings: latestSettings(value.settings, settings) }));
        }
      } catch (error) { fail(error, requestKey); }
    }
    timer = setTimeout(poll, 500);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [key, visible.current?.id, running, client, pollRevision]);

  async function mutate(label: string, action: (ws: Workspace, requestKey: string) => Promise<void>) {
    if (!workspace || busy.current) return false;
    const ws = workspace, requestKey = key;
    busy.current = true; setWorking(label);
    setState(value => ({ ...value, error: null }));
    try { await action(ws, requestKey); return alive(requestKey); }
    catch (error) { fail(error, requestKey); return false; }
    finally { if (alive(requestKey)) { busy.current = false; setWorking(null); } }
  }
  async function refreshSettings() {
    if (!workspace || !client.chatSettings) return;
    const ws = workspace, requestKey = key;
    try { const settings = checked(await client.chatSettings(ws.id), ws); if (alive(requestKey)) { setState(value => ({ ...value, settings: latestSettings(value.settings, settings) })); setPollRevision(value => value + 1); } }
    catch (error) { fail(error, requestKey); }
  }
  async function select(cid?: string) {
    return mutate("topic", async (ws, requestKey) => {
      topicRef.current = cid || null;
      setState(value => ({ ...value, current: undefined, loading: !!cid }));
      const current = cid ? checked(await client.conversation!(ws.id, cid), ws) : undefined;
      if (current && current.id !== cid) throw new ApiError("对话身份不匹配", 403);
      if (alive(requestKey)) { if (cid) remember(ws.id, cid); setState(value => ({ ...value, current, loading: false })); }
    });
  }
  function submitTurn(label: string, submit: (ws: Workspace, cid: string) => Promise<Conversation>) {
    return mutate(label, async (ws, requestKey) => {
      let cid = visible.current?.id;
      if (!cid) {
        const topic = checked(await client.createConversation!(ws.id), ws);
        if (!alive(requestKey)) return;
        cid = topic.id; topicRef.current = cid; remember(ws.id, cid);
        setState(value => ({ ...value, current: { ...topic, turns: [] }, topics: [topic, ...value.topics] }));
      }
      const current = checked(await submit(ws, cid), ws);
      if (current.id !== cid) throw new ApiError("对话身份不匹配", 403);
      if (alive(requestKey)) setState(value => ({ ...value, current, topics: value.topics.map(topic => topic.id === cid ? { ...topic, title: current.title } : topic) }));
    });
  }
  function send(question: string, selectedPath?: string, crapTarget?: CrapDiscussionTarget) {
    const settings = visible.settings;
    if (!settings?.consent || running || !question.trim()) return Promise.resolve(false);
    return submitTurn("send", (ws, cid) => crapTarget
      ? client.sendQuestion!(ws.id, cid, question, settings.revision, undefined, crapTarget)
      : client.sendQuestion!(ws.id, cid, question, settings.revision, selectedPath));
  }
  const canRunCrap = !!client.runCrapTool;
  function runCrap(options: CrapToolOptions) {
    if (!client.runCrapTool || running || visible.loading) return Promise.resolve(false);
    return submitTurn("crap", (ws, cid) => client.runCrapTool!(ws.id, cid, options, ws.access_policy!.version));
  }
  async function save(consent: boolean) {
    const settings = visible.settings;
    if (!settings) return false;
    return mutate("settings", async (ws, requestKey) => {
      const saved = checked(await client.saveChatSettings!(ws.id, { consent, context: settings.context, expected_revision: settings.revision,
        expected_policy_version: ws.access_policy!.version, expected_profile_revision: settings.profile_revision }), ws);
      if (alive(requestKey)) setState(value => ({ ...value, settings: latestSettings(value.settings, saved) }));
    });
  }
  async function cancel() {
    const cid = visible.current?.id;
    if (!cid) return;
    return mutate("cancel", async (ws, requestKey) => {
      const current = checked(await client.cancelConversation!(ws.id, cid), ws);
      if (current.id !== cid) throw new ApiError("对话身份不匹配", 403);
      if (alive(requestKey) && topicRef.current === cid) setState(value => ({ ...value, current }));
    });
  }
  async function remove() {
    const cid = visible.current?.id;
    if (!cid) return;
    return mutate("delete", async (ws, requestKey) => {
      await client.deleteConversation!(ws.id, cid);
      if (alive(requestKey)) { topicRef.current = null; setState(value => ({ ...value, current: undefined, topics: value.topics.filter(topic => topic.id !== cid) })); }
    });
  }
  async function insightRequest<T extends PolicyIdentity & { workspace_id: string }>(action: (ws: Workspace) => Promise<T>) {
    if (!workspace) return;
    try {
      const result = checked(await action(workspace), workspace);
      if (alive(key)) return result;
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) fail(error, key);
      if (alive(key)) throw error;
    }
  }
  const insightsSupported = !!(client.insights && client.saveInsight && client.changeInsight);
  function listInsights(cid?: string, signal?: AbortSignal) {
    return insightRequest(ws => client.insights!(ws.id, cid, signal));
  }
  function saveInsight(cid: string, tid: string, draft: InsightDraft) {
    return insightRequest(ws => client.saveInsight!(ws.id, cid, tid, draft, ws.access_policy!.version));
  }
  function changeInsight(noteId: string, action: "retire" | "delete", cid?: string) {
    return insightRequest(ws => client.changeInsight!(ws.id, noteId, action, ws.access_policy!.version, cid));
  }
  return { ...visible, working, running, send, canRunCrap, runCrap, select, save, cancel, remove, refreshSettings,
    insightsSupported, listInsights, saveInsight, changeInsight };
}
export type ProjectChat = ReturnType<typeof useProjectChat>;
