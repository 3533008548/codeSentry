import { useEffect, useState } from "react";
import { FileCode2, X } from "lucide-react";
import type { ChatSourceLocation, InsightDraft, ProjectInsight } from "./api";
import type { ProjectChat } from "./useProjectChat";

const driftReasons = {
  source: "相关源码已变化、移动、删除，或当前无法核对。",
  environment: "依赖或版本声明已变化，或当前无法核对。",
  history: "旧笔记缺少可核对的历史取材记录。",
};

export function InsightDialog({ chat, topicId, turnId, onClose, onOpen }: {
  chat: ProjectChat; topicId?: string; turnId?: string;
  onClose: () => void; onOpen: (location: ChatSourceLocation) => void;
}) {
  const [draft, setDraft] = useState<InsightDraft | null>(turnId ? {
    statement: "", kind: "hypothesis", scope: "topic", track_environment: false,
  } : null);
  const [notes, setNotes] = useState<ProjectInsight[] | null>(null);
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const showingList = !draft;

  useEffect(() => {
    if (!showingList) return;
    const controller = new AbortController();
    setNotes(null);
    setError("");
    void chat.listInsights(topicId, controller.signal).then(result => {
      if (result && !controller.signal.aborted) setNotes(result.insights);
    }).catch(reason => {
      if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "暂时无法读取笔记");
    });
    return () => controller.abort();
  }, [topicId, showingList, reload]);

  async function save() {
    if (!draft?.statement.trim() || !turnId || !topicId || busy) return;
    setBusy(true);
    setError("");
    try {
      if (await chat.saveInsight(topicId, turnId, draft)) setDraft(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "暂时无法保存笔记");
    } finally {
      setBusy(false);
    }
  }

  async function change(id: string, action: "retire" | "delete") {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      if (await chat.changeInsight(id, action, topicId)) setReload(value => value + 1);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "暂时无法更新笔记");
    } finally {
      setBusy(false);
    }
  }

  return <div className="dialog-backdrop"><section className="dialog insight-dialog" role="dialog" aria-modal="true" aria-label={draft ? "保存项目笔记" : "项目笔记"}>
    <div className="dialog-header"><h2>{draft ? "记下这点" : "项目笔记"}</h2><button className="icon-button" aria-label="关闭笔记" onClick={onClose}><X size={18} /></button></div>
    {draft ? <form onSubmit={event => { event.preventDefault(); void save(); }}>
      <p>写下你想保留的一条观察或判断。笔记会关联本轮引用，保存在本机。</p>
      <label>笔记内容<textarea rows={4} autoFocus required maxLength={1200} value={draft.statement}
        onChange={event => setDraft({ ...draft, statement: event.target.value })} /></label>
      <div className="insight-options">
        <label>判断类型<select value={draft.kind} onChange={event => setDraft({ ...draft, kind: event.target.value === "observation" ? "observation" : "hypothesis" })}>
          <option value="hypothesis">待验证的判断</option><option value="observation">我已核对的源码观察</option>
        </select></label>
        <label>保存范围<select value={draft.scope} onChange={event => setDraft({ ...draft, scope: event.target.value === "project" ? "project" : "topic" })}>
          <option value="topic">仅本话题</option><option value="project">本项目</option>
        </select></label>
      </div>
      <label className="insight-track"><input type="checkbox" checked={draft.track_environment} onChange={event => setDraft({ ...draft, track_environment: event.target.checked })} />同时跟踪根目录的依赖和版本声明</label>
      {error && <p role="alert" className="chat-failure">{error}</p>}
      <div className="dialog-actions"><button type="button" className="button secondary" onClick={onClose}>取消</button><button type="submit" className="button primary" disabled={busy || !draft.statement.trim()}>保存笔记</button></div>
    </form> : <>
      <p>这里显示本项目和当前话题的笔记。打开时核对源码快照，环境检查只覆盖选择跟踪的声明文件。</p>
      {error && <p role="alert" className="chat-failure">{error}</p>}
      {!notes && !error && <p role="status">正在核对笔记证据…</p>}
      {notes?.length === 0 && <p>还没有笔记。可以在带源码引用的回答下点「记下这点」。</p>}
      {notes?.map(note => <article className="insight-note" key={note.id}>
        <div className="insight-note-meta">
          <strong>{note.status === "retired" ? "已归档" : note.status === "stale" ? "证据已过期" : "证据快照一致"}</strong>
          <span>{note.scope === "project" ? "本项目" : "仅本话题"}</span>
          <span>{note.kind === "observation" ? "用户核对的源码观察" : "待验证的判断"}</span>
          {note.tracks_environment && <span>跟踪环境声明</span>}
        </div>
        <p>{note.statement}</p>
        {note.status === "stale" && <small>{note.drift_reason && driftReasons[note.drift_reason]}请基于当前源码重新核对后另存一条。</small>}
        {note.status === "active" && <div className="chat-citations">{note.citations.map((citation, index) => <button key={index} onClick={() => { onClose(); onOpen(citation); }}><FileCode2 size={12} />{citation.path}:{citation.line}</button>)}</div>}
        <button className="text-button" disabled={busy} onClick={() => void change(note.id, note.status === "retired" ? "delete" : "retire")}>{note.status === "retired" ? "删除归档笔记" : "归档笔记"}</button>
      </article>)}
      <div className="dialog-actions"><button className="button secondary" disabled={busy || (!notes && !error)} onClick={() => setReload(value => value + 1)}>重新核对</button><button className="button primary" onClick={onClose}>完成</button></div>
    </>}
  </section></div>;
}
