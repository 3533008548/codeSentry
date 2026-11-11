import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import App from "./App";
import type { Api, ChatSettings, Conversation, Workspace } from "./api";

vi.mock("./CodeViewer", () => ({ CodeViewer: ({ file, jumpLine }: { file: { content: string }; jumpLine: number }) => <pre data-testid="code-editor" data-line={jumpLine}>{file.content}</pre> }));
const workspace = (id = "a"): Workspace => ({ id, name: `项目${id}`, path: `/projects/${id}`, created_at: "", updated_at: "", config: { max_depth: 4, max_items: 30 },
  access_policy: { confirmed: true, cleanup_pending: false, version: 1, fingerprint: `scope-${id}`, settings: { respect_gitignore: true, local_only: [], exclude: [], model_scope: ["main.py"] }, issues: [], restricted: false } });
const identity = (id: string) => ({ workspace_id: id, policy_version: 1, policy_fingerprint: `scope-${id}` });
const settings = (id: string): ChatSettings => ({ ...identity(id), consent: true, revision: 1, context: "", profile_revision: 2, model: "deepseek-flash", key_configured: true, profile_enabled: true,
  budget: { remaining_requests: 60, remaining_tokens: 1048576, max_requests: 60, total_token_budget: 1048576 } });
const conversation = (id: string): Conversation => ({ ...identity(id), id: "topic-" + id, title: "理解任务创建", created_at: "", turns: [] });
function client(overrides: Partial<Api> = {}): Api {
  return {
    workspaces: vi.fn(async () => [workspace("a"), workspace("b")]), workspace: vi.fn(async id => workspace(id)), files: vi.fn(async (id: string): ReturnType<Api["files"]> => ({ ...identity(id), files: [{ path: "main.py", language: "python", size: 1, access_mode: "model_eligible" }], truncated: false })),
    file: vi.fn(async (id, path) => ({ ...identity(id), path, content: "CHANGED_CONTENT", language: "python", sha256: "new-sha", lines: 3 })),
    jobs: vi.fn(async () => []), job: vi.fn(), analyze: vi.fn(), cancel: vi.fn(), previewAccess: vi.fn(), createWorkspace: vi.fn(), updateWorkspace: vi.fn(),
    chatSettings: vi.fn(async id => settings(id)), conversations: vi.fn(async () => []), conversation: vi.fn(async id => conversation(id)), createConversation: vi.fn(async id => conversation(id)),
    saveChatSettings: vi.fn(async (id, body) => ({ ...settings(id), consent: body.consent, context: body.context, revision: 2 })),
    sendQuestion: vi.fn(async (id: string, _cid: string, question: string): Promise<Conversation> => ({ ...conversation(id), turns: [{ id: "turn-1", question, status: "completed", answer: "## 从入口开始\n\n这是一个待核对的说明。", error: null, created_at: "", feedback: "", citations: [{ path: "main.py", line: 2, end_line: 2, quote: "original", sha256: "old-sha", quote_checked: true }], followups: ["继续看存储"], sources: [{ path: "main.py", start_line: 1, end_line: 3, sha256: "old-sha" }] }] })),
    cancelConversation: vi.fn(), deleteConversation: vi.fn(), conversationFeedback: vi.fn(), ...overrides,
  };
}
beforeEach(() => { localStorage.clear(); history.replaceState(null, "", "/"); });
afterEach(cleanup);

it("makes conversation primary without any implicit provider request", async () => {
  const api = client(); render(<App client={api} />);
  await screen.findByRole("textbox", { name: "向项目Agent提问" });
  await screen.findByText("当前有 1 个模型候选文件。", { exact: false });
  expect(api.sendQuestion).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: /理解代码/ }));
  expect((screen.getByRole("textbox", { name: "向项目Agent提问" }) as HTMLTextAreaElement).value).toContain("核心模块");
});

it("sends a complexity request through conversation after chat restoration", async () => {
  let finish!: (value: ChatSettings) => void;
  const pending = new Promise<ChatSettings>(resolve => { finish = resolve; });
  const api = client({ chatSettings: vi.fn(() => pending) });
  render(<App client={api} />);
  await screen.findByText("正在恢复本项目的对话…");
  const input = screen.getByRole("textbox", { name: "向项目Agent提问" });
  fireEvent.change(input, { target: { value: "帮我检查项目复杂度" } });
  fireEvent.keyDown(input, { key: "Enter" });
  expect(api.sendQuestion).not.toHaveBeenCalled();
  await act(async () => { finish(settings("a")); await pending; });
  expect(screen.queryByRole("button", { name: "CRAP 报告" })).toBeNull();
  fireEvent.keyDown(input, { key: "Enter" });
  await waitFor(() => expect(api.sendQuestion).toHaveBeenCalledWith("a", "topic-a", "帮我检查项目复杂度", 1, undefined));
});

it("asks once for project consent, then sends the user's question directly", async () => {
  const api = client({ chatSettings: vi.fn(async id => ({ ...settings(id), consent: false })) }); render(<App client={api} />);
  const input = await screen.findByRole("textbox", { name: "向项目Agent提问" });
  await waitFor(() => expect(api.chatSettings).toHaveBeenCalled());
  fireEvent.change(input, { target: { value: "先带我看入口" } }); fireEvent.click(screen.getByRole("button", { name: "发送" }));
  await screen.findByRole("dialog", { name: "项目对话设置" });
  expect(api.sendQuestion).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "允许本项目自动取材与对话" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  fireEvent.click(screen.getByRole("button", { name: "发送" }));
  await screen.findByText("这是一个待核对的说明。");
  expect(api.sendQuestion).toHaveBeenCalledWith("a", "topic-a", "先带我看入口", 2, undefined);
  expect(api.previewSemantic).toBeUndefined();
});

it("keeps the conversation open while source citations open on the right and marks changed lines", async () => {
  const api = client(); render(<App client={api} />);
  const input = await screen.findByRole("textbox", { name: "向项目Agent提问" });
  fireEvent.change(input, { target: { value: "解释入口" } }); fireEvent.click(screen.getByRole("button", { name: "发送" }));
  fireEvent.click(await screen.findByRole("button", { name: /main.py:2/ }));
  expect((await screen.findByTestId("code-editor")).textContent).toContain("CHANGED_CONTENT");
  expect(screen.getByTestId("code-editor").getAttribute("data-line")).toBe("0");
  expect(screen.getByText(/文件已在本轮引用后变化/)).toBeTruthy();
  expect(screen.getByRole("textbox", { name: "向项目Agent提问" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "继续看存储" }));
  expect((input as HTMLTextAreaElement).value).toBe("继续看存储");
});

it("discards a late send response after switching projects", async () => {
  let resolve!: (value: Conversation) => void;
  const pending = new Promise<Conversation>(done => { resolve = done; });
  const api = client({ sendQuestion: vi.fn(() => pending) }); render(<App client={api} />);
  const input = await screen.findByRole("textbox", { name: "向项目Agent提问" });
  fireEvent.change(input, { target: { value: "a 的私人问题" } });
  await waitFor(() => expect((screen.getByRole("button", { name: "发送" }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByRole("button", { name: "发送" }));
  await waitFor(() => expect(api.sendQuestion).toHaveBeenCalled());
  fireEvent.click(screen.getByTitle("/projects/b"));
  await waitFor(() => expect(api.chatSettings).toHaveBeenCalledWith("b", expect.anything()));
  await act(async () => { resolve({ ...conversation("a"), title: "迟到的 a 的私人话题" }); await pending; });
  expect(screen.queryByText("迟到的 a 的私人话题")).toBeNull();
  expect((screen.getByRole("textbox", { name: "向项目Agent提问" }) as HTMLTextAreaElement).value).toBe("");
});

it("ignores an old reading preference and exposes only source preview beside the agent", async () => {
  localStorage.setItem("codesentry.workbench.view", "reading");
  const api = client(); render(<App client={api} />);
  await screen.findByRole("textbox", { name: "向项目Agent提问" });
  fireEvent.click(await screen.findByRole("treeitem", { name: "打开 main.py" }));
  expect((await screen.findByTestId("code-editor")).textContent).toContain("CHANGED_CONTENT");
  const preview = screen.getByRole("complementary", { name: "源码预览" });
  expect(preview.querySelectorAll('[role="tab"]')).toHaveLength(0);
  for (const name of ["项目概览", "变更范围", "门禁检查", "本项目约束", "设计判断", "分析与审查工具"]) {
    expect(screen.queryByRole("button", { name })).toBeNull();
  }
  expect(api.jobs).not.toHaveBeenCalled();
  expect(api.analyze).not.toHaveBeenCalled();
});

it("does not let an older settings response overwrite a newly confirmed grant", async () => {
  let resolve!: (value: ChatSettings) => void;
  const older = new Promise<ChatSettings>(done => { resolve = done; });
  const load = vi.fn().mockResolvedValueOnce({ ...settings("a"), consent: false }).mockReturnValue(older);
  const api = client({ chatSettings: load }); render(<App client={api} />);
  const input = await screen.findByRole("textbox", { name: "向项目Agent提问" });
  await waitFor(() => expect(load).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole("button", { name: "对话设置" }));
  await screen.findByRole("dialog", { name: "项目对话设置" });
  fireEvent.click(screen.getByRole("button", { name: "允许本项目自动取材与对话" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await act(async () => { resolve({ ...settings("a"), consent: false }); await older; });
  fireEvent.change(input, { target: { value: "继续学习" } });
  fireEvent.click(screen.getByRole("button", { name: "发送" }));
  await waitFor(() => expect(api.sendQuestion).toHaveBeenCalledWith("a", "topic-a", "继续学习", 2, undefined));
});
