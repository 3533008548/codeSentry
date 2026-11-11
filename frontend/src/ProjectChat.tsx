import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowUp, BookOpen, ChevronRight, FileCode2, LoaderCircle, NotebookPen, Plus, Settings2, Square, Trash2, X } from "lucide-react";
import type { ChatSourceLocation, SourceFile } from "./api";
import type { ProjectChat } from "./useProjectChat";
import { CrapReportView } from "./CrapReport";
import { InsightDialog } from "./InsightDialog";

const starters = [
  { name: "理解代码", detail: "找出入口和关键流程", prompt: "带我了解这个项目的目标、核心模块和启动方式。先讲清全貌，再指出一条主要流程和源码位置。" },
  { name: "讨论重构", detail: "定位复杂函数并核查调用与测试", prompt: "帮我找一处值得重构的 Python 函数。检查复杂度、调用关系和相关测试，给出能保持行为的改法或保留理由。" },
];

const toolLabels = { search_code: "检索源码", read_source: "读取源码", trace_calls: "追踪调用", run_crap: "计算复杂度" };
const toolStatuses = { completed: "已完成", unavailable: "暂无可用证据", already_called: "已使用同一结果" };

export function ProjectChatPane({ chat, files, selectedPath, draft, setDraft, onOpen, onModel, onAccess }: {
  chat: ProjectChat; files: SourceFile[]; selectedPath?: string | null;
  draft: string; setDraft: (value: string) => void; onOpen: (location: ChatSourceLocation) => void;
  onModel: () => void; onAccess: () => void;
}) {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [attach, setAttach] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [notes, setNotes] = useState<{ turnId?: string } | null>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const nearBottom = useRef(true);
  const eligible = files.filter(file => file.access_mode === "model_eligible");
  const attachable = !!selectedPath && eligible.some(file => file.path === selectedPath);
  useEffect(() => { setAttach(false); }, [selectedPath]);
  useEffect(() => { if (draft) input.current?.focus(); }, [draft]);
  useEffect(() => { if (nearBottom.current && scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight; }, [chat.current]);
  useEffect(() => { nearBottom.current = true; setNotes(null); }, [chat.current?.id]);
  async function send() {
    const question = draft.trim();
    if (!question || chat.running || chat.working) return;
    if (chat.loading) return;
    if (!chat.settings?.consent) { setSettingsOpen(true); return; }
    if (await chat.send(question, attach && attachable ? selectedPath! : undefined)) {
      setDraft(""); setAttach(false); nearBottom.current = true;
    }
  }
  const turns = chat.current?.turns || [];
  return <main className="project-chat" data-testid="project-chat" aria-label="项目对话">
    <div className="chat-heading">
      <div><h1>{chat.current?.title || "项目对话"}</h1><p>理解代码 · 检查复杂度 · 讨论重构</p></div>
      <div className="chat-heading-actions">
        {!!chat.topics.length && <select className="chat-topic-select" aria-label="对话历史" value={chat.current?.id || ""}
          disabled={!!chat.working || chat.loading} onChange={event => { setDraft(""); void chat.select(event.target.value || undefined); }}>
          <option value="">新话题</option>{chat.topics.map(topic => <option key={topic.id} value={topic.id}>{topic.title}</option>)}
        </select>}
        {!!turns.length && <button className="icon-button" aria-label="新话题" title="新话题" disabled={!!chat.working}
          onClick={() => { setDraft(""); void chat.select(); }}><Plus size={16} /></button>}
        {chat.insightsSupported && <button className="icon-button" aria-label="项目笔记" title="项目笔记" disabled={chat.loading}
          onClick={() => setNotes({})}><NotebookPen size={16} /></button>}
        <button className="icon-button" aria-label="对话设置" title="对话授权与用量"
          onClick={() => { void chat.refreshSettings(); setSettingsOpen(true); }}><Settings2 size={16} /></button>
        {chat.current && <button className="icon-button" aria-label="删除当前话题" title="删除当前话题"
          disabled={!!chat.working || chat.running} onClick={() => setDeleteOpen(true)}><Trash2 size={15} /></button>}
      </div>
    </div>
    <div className="chat-scroll" ref={scroller} onScroll={() => { const element = scroller.current; if (element) nearBottom.current = element.scrollHeight - element.scrollTop - element.clientHeight < 120; }}>
      <div className="chat-messages">
        {chat.loading && <p className="chat-loading"><LoaderCircle size={17} className="spin" />正在恢复本项目的对话…</p>}
        {!chat.loading && !turns.length && <div className="chat-introduction"><div className="chat-avatar"><BookOpen size={22} /></div><h2>从一个代码问题开始</h2><p>问项目怎么运行，或者让 Agent 找一处值得重构的代码。</p>
          <div className="chat-starters">{starters.map(step => <button key={step.name} onClick={() => setDraft(step.prompt)}><span>{step.name}</span><small>{step.detail}</small><ChevronRight size={15} /></button>)}</div>
          <p className="chat-intro-note">{eligible.length ? `当前有 ${eligible.length} 个模型候选文件。` : "尚未设置模型候选文件。"}开始对话前确认一次取材范围，后续可直接提问。<button onClick={onAccess}>调整范围</button></p>
        </div>}
        {turns.map(turn => <section className="chat-turn" key={turn.id} data-testid="chat-turn">
          <div className="chat-user">{turn.question}</div>
          <div className="chat-speaker"><span className="chat-avatar">✧</span><strong>CodeSentry</strong><span>{turn.status === "running" ? "正在处理任务…" : turn.status === "completed" ? (turn.answer ? `参考 ${turn.sources.length} 个源码片段` : "本地 CRAP 报告") : "本轮未完成"}</span></div>
          {turn.status === "running" && <div className="chat-loading" role="status"><LoaderCircle size={17} className="spin" />正在查阅证据并组织回答。</div>}
          {turn.error && <div className="chat-failure" role="alert"><p>{turn.error}</p><button className="text-button" disabled={!!chat.working || chat.running}
            onClick={() => { setAttach(false); setDraft(turn.question); }}>重新提问</button></div>}
          {!!turn.steps?.length && <details className="chat-evidence"><summary>工具记录 · {turn.steps.length} 步</summary>
            <ol>{turn.steps.map((step, index) => <li key={index}>
              <span>{toolLabels[step.tool]} · {toolStatuses[step.status]}{step.trigger === "task" ? " · 按任务要求" : ""}</span>
              <div className="chat-citations">{step.locations.map((location, position) => <button key={position} onClick={() => onOpen(location)}><FileCode2 size={12} />{location.path}:{location.line}</button>)}</div>
            </li>)}</ol>
          </details>}
          {turn.tool?.report && <CrapReportView tool={turn.tool} onOpen={onOpen} />}
          {turn.answer && <><MarkdownText text={turn.answer} />
            {!!turn.citations.length && <div className="chat-citations">{turn.citations.map((citation, index) => <button key={index} onClick={() => onOpen(citation)} title={citation.quote}><FileCode2 size={12} />{citation.path}:{citation.line}{citation.end_line !== citation.line ? `–${citation.end_line}` : ""}<span>↗</span></button>)}</div>}
            <details className="chat-evidence"><summary>查看本轮取材依据{turn.coverage?.partial ? " · 局部检索" : ""}</summary><p>以下为本轮直接取材的文件和行段。引用已按发送时快照核对，模型结论仍需验证。</p>{turn.sources.map(source => <div key={`${source.path}:${source.start_line}:${source.end_line}`}>{source.path}:{source.start_line}–{source.end_line}</div>)}</details>
            {chat.insightsSupported && !!turn.citations.length && <button className="text-button chat-save-insight" onClick={() => setNotes({ turnId: turn.id })}><NotebookPen size={12} />记下这点</button>}
            {!!turn.followups.length && turn.id === turns.at(-1)?.id && <div className="chat-followups">{turn.followups.map(text => <button key={text} onClick={() => setDraft(text)}>{text}</button>)}</div>}
          </>}
        </section>)}
        {chat.error && <div className="chat-failure" role="alert">{chat.error}<button className="text-button" onClick={() => void chat.refreshSettings()}>重新核对设置</button></div>}
      </div>
    </div>
    <div className="chat-compose-wrap"><form className="chat-composer" onSubmit={event => { event.preventDefault(); void send(); }}>
      <textarea ref={input} aria-label="向项目Agent提问" placeholder="直接问项目问题，或告诉我想从哪一步继续…" value={draft} maxLength={4000} onChange={event => setDraft(event.target.value)} onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); void send(); } }} />
      {attach && attachable && <div className="chat-attachment"><FileCode2 size={12} />{selectedPath}<button type="button" aria-label="移除引用文件" onClick={() => setAttach(false)}><X size={12} /></button></div>}
      <div className="chat-compose-actions"><button type="button" title={attachable ? `引用 ${selectedPath}` : "先在源码栏打开一个模型候选文件"} disabled={!attachable} onClick={() => setAttach(value => !value)}><Plus size={13} />引用当前文件</button><button type="button" className="chat-scope" onClick={onAccess}>范围：{eligible.length} 个模型候选文件</button>
        {chat.running ? <button type="button" className="chat-send" disabled={!!chat.working} onClick={() => void chat.cancel()}><Square size={12} />停止</button> : <button type="submit" className="chat-send" disabled={!draft.trim() || !!chat.working || chat.loading}>{chat.working === "send" ? <LoaderCircle size={14} className="spin" /> : <ArrowUp size={15} />}发送</button>}
      </div></form><div className="chat-compose-note">{chat.settings?.consent ? "已允许本项目自动取材 · 只读讲解 · Shift + Enter 换行" : "首次发送前确认一次对话授权 · 只读讲解"}<button onClick={() => { void chat.refreshSettings(); setSettingsOpen(true); }}>授权与用量</button></div></div>
    {settingsOpen && <div className="dialog-backdrop"><section className="dialog chat-settings-dialog" role="dialog" aria-modal="true" aria-label="项目对话设置"><div className="dialog-header"><h2>本项目的对话授权</h2><button className="icon-button" aria-label="关闭对话设置" onClick={() => setSettingsOpen(false)}><X size={18} /></button></div>
      <p>服务：DeepSeek · 模型：{chat.settings?.model || "读取中"}。仅使用当前项目，不调用其他项目的记忆。</p>
      <p>开启后，Agent 可在本轮自行调用检索、源码读取、静态调用分析和 CRAP。每轮最多 5 次只读工具调用、12 个代码片段和 18 KiB 源码。模型可接收候选文件的必要证据及最多最近 3 轮有效对话的节选，CRAP 分数和覆盖率显示在本地报告里。</p>
      <p>DeepSeek 可能缓存或保留请求。对话保存在本机；关闭授权后停止后续发送，不能撤回已交给服务商的内容。访问范围或模型设置变化后需要重新开启。</p>
      <div className="chat-settings-summary"><span>{eligible.length} 个模型候选文件</span><button className="text-button" onClick={() => { setSettingsOpen(false); onAccess(); }}>查看或调整范围</button><span>{chat.settings?.key_configured ? "密钥已配置" : "尚未配置密钥"} · {chat.settings?.profile_enabled ? "模型已启用" : "模型未启用"}</span><button className="text-button" onClick={() => { setSettingsOpen(false); onModel(); }}>打开模型设置</button></div>
      <p>本次服务剩余 {chat.settings?.budget.remaining_requests ?? "—"} / 60 次模型请求，Token 预算 {chat.settings?.budget.remaining_tokens.toLocaleString() ?? "—"}。一轮对话可能包含多次请求，失败也计入预留用量。重启服务后预算重新计数。</p>
      {chat.error && <p role="alert" className="chat-failure">{chat.error}</p>}
      <div className="dialog-actions"><button className="button secondary" disabled={!chat.settings || !!chat.working} onClick={() => void chat.save(false).then(saved => { if (saved) setSettingsOpen(false); })}>关闭自动取材</button><button className="button primary" disabled={!chat.settings?.key_configured || !chat.settings?.profile_enabled || !eligible.length || !!chat.working} onClick={() => void chat.save(true).then(saved => { if (saved) setSettingsOpen(false); })}>允许本项目自动取材与对话</button></div>
    </section></div>}
    {notes && <InsightDialog key={chat.current?.id} chat={chat} topicId={chat.current?.id} turnId={notes.turnId} onClose={() => setNotes(null)} onOpen={onOpen} />}
    {deleteOpen && <div className="dialog-backdrop"><section className="dialog" role="dialog" aria-modal="true" aria-label="删除话题确认"><h2>删除这个话题？</h2><p>将删除本机保存的对话、报告和仅本话题的笔记。本项目笔记可以从笔记列表单独删除。已经发送给模型服务的内容无法撤回。</p><div className="dialog-actions"><button className="button secondary" onClick={() => setDeleteOpen(false)}>取消</button><button className="button primary" disabled={!!chat.working} onClick={() => void chat.remove().then(() => setDeleteOpen(false))}>删除话题</button></div></section></div>}
  </main>;
}

function inline(text: string): ReactNode[] {
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((part, index) => part.startsWith("`") && part.endsWith("`") ? <code key={index}>{part.slice(1, -1)}</code> : part.startsWith("**") && part.endsWith("**") ? <strong key={index}>{part.slice(2, -2)}</strong> : part);
}
function MarkdownText({ text }: { text: string }) {
  const blocks = text.split(/(```[\s\S]*?```)/g).flatMap(block => block.startsWith("```") ? [block] : block.split(/\n\s*\n/).filter(Boolean));
  const sections: ReactNode[] = [];
  let recommendation: { title: string; body: ReactNode[] } | null = null;
  function finishCard() {
    if (recommendation) sections.push(<section className="chat-refactor-card" key={`card-${sections.length}`}><div><h2>{inline(recommendation.title)}</h2><span>建议 · 待核对</span></div><div className="chat-refactor-body">{recommendation.body}</div></section>);
    recommendation = null;
  }
  blocks.forEach((block, index) => {
    const heading = /^#{1,4} /.test(block), title = block.replace(/^#{1,4} /, "");
    if (heading) {
      finishCard();
      if (/重构|改进机会/.test(title)) { recommendation = { title, body: [] }; return; }
    }
    const element = block.startsWith("```") ? <pre key={index}><code>{block.replace(/^```[^\n]*\n?/, "").replace(/```$/, "")}</code></pre>
      : heading ? <div key={index}><h2>{inline(title)}</h2>{title.includes("→") && title.split("→").length <= 5 && <div className="chat-flow" aria-label="回答中的流程概括">{title.replace(/^.*[：:]/, "").split("→").map((step, n) => <span key={n}>{step.trim()}</span>)}</div>}</div>
      : block.startsWith("> ") ? <blockquote key={index}>{inline(block.replace(/^> ?/gm, ""))}</blockquote>
      : <p key={index}>{inline(block)}</p>;
    if (recommendation) recommendation.body.push(element); else sections.push(element);
  });
  finishCard();
  return <div className="chat-answer">{sections}</div>;
}
