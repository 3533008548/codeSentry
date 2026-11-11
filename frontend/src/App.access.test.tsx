import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import {
  ApiError,
  type AccessConfirmation,
  type AccessPreview,
  type AccessSettings,
  type AnalysisJob,
  type AnalysisResult,
  type Api,
  type FileContent,
  type Workspace,
} from "./api";
import { accessKey, defaultAccessSettings } from "./access";
import { registerReader } from "./readerCache";
import { writeView } from "./state";

vi.mock("./CodeViewer", () => ({
  CodeViewer: ({ file }: { file: FileContent }) => (
    <pre data-testid="code-editor">{file.content}</pre>
  ),
}));
const fingerprint = (settings: AccessSettings) => JSON.stringify(settings);
const project = (
  id: string,
  version = 1,
  settings = defaultAccessSettings(),
): Workspace => ({
  id,
  name: `项目${id.toUpperCase()}`,
  path: `/projects/${id}`,
  created_at: "2026-01-01",
  updated_at: "2026-01-01",
  config: { max_depth: 4, max_items: 30 },
  access_policy: {
    confirmed: true,
    version,
    settings,
    fingerprint: fingerprint(settings),
    cleanup_pending: false,
    issues: [],
    restricted: settings.exclude.length > 0,
  },
});
const identity = (workspace: Workspace) => ({
  policy_version: workspace.access_policy!.version,
  policy_fingerprint: workspace.access_policy!.fingerprint,
});
const source = (
  workspace: Workspace,
  path: string,
  content = `${workspace.id}:${path}:SOURCE`,
): FileContent => ({
  workspace_id: workspace.id,
  path,
  content,
  sha256: content,
  lines: 1,
  language: "python",
  ...identity(workspace),
});
const result = (workspace: Workspace): AnalysisResult => ({
  root: workspace.path,
  analysis_mode: "static",
  dynamic_verification: "not_run",
  is_complete: true,
  parse_failures: 0,
  files: 1,
  symbols: 1,
  edges: 0,
  reading_order: [{ file: "OLD_PRIVATE_RESULT.py", label: "旧模块", depth: 0 }],
  ...identity(workspace),
});
const job = (workspace: Workspace): AnalysisJob => ({
  id: "old-job",
  workspace_id: workspace.id,
  status: "succeeded",
  created_at: "2026-01-01",
  started_at: null,
  finished_at: "2026-01-01",
  logs: ["OLD_PRIVATE_LOG"],
  error: null,
  result: result(workspace),
  ...identity(workspace),
});
const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done,fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
};
function preview(path: string, settings: AccessSettings): AccessPreview {
  return {
    path,
    expected_version: 0,
    access_policy: {
      ...project("a", 0, settings).access_policy!,
      confirmed: false,
    },
    entries: ["public.py", "secret.py"].map((path) => ({
      path,
      is_dir: false,
      mode: settings.exclude.includes(path)
        ? "exclude"
        : settings.local_only.includes(path)
          ? "local_only"
          : "model_eligible",
      reason: settings.exclude.includes(path)
        ? "用户完全排除规则"
        : "当前访问范围",
    })),
    truncated: false,
  };
}
function harness(initial: Workspace[]) {
  const projects = new Map(initial.map((item) => [item.id, item]));
  const histories = new Map<string, AnalysisJob[]>();
  function apply(id: string, confirmation: AccessConfirmation) {
    const prior = projects.get(id) || project(id, 0);
    const same =
      projects.has(id) && prior.access_policy?.confirmed &&
      fingerprint(prior.access_policy.settings) ===
        fingerprint(confirmation.settings) &&
      prior.access_policy.fingerprint === confirmation.fingerprint;
    const next = project(
      id,
      same
        ? prior.access_policy!.version
        : (prior.access_policy?.version || 0) + 1,
      confirmation.settings,
    );
    projects.set(id, next);
    if (!same) histories.set(id, []);
    return next;
  }
  const api: Api = {
    workspaces: vi.fn(async () => [...projects.values()]),
    workspace: vi.fn(async (id) => projects.get(id)!),
    createWorkspace: vi.fn(async (path, _name, confirmation) => {
      const id = path.split("/").at(-1)!;
      return apply(id, confirmation!);
    }),
    updateWorkspace: vi.fn(async (id, patch) => {
      if (patch.access_policy) return apply(id, patch.access_policy);
      const value = { ...projects.get(id)!, ...patch };
      projects.set(id, value as Workspace);
      return value as Workspace;
    }),
    previewAccess: vi.fn(async (path, settings) => ({
      ...preview(path, settings),
      expected_version:
        projects.get(path.split("/").at(-1)!)?.access_policy?.version || 0,
    })),
    files: vi.fn(async (id) => {
      const workspace = projects.get(id)!;
      return {
        workspace_id: id,
        files: ["public.py", "secret.py"]
          .filter(
            (path) => !workspace.access_policy?.settings.exclude.includes(path),
          )
          .map((path) => ({ path, language: "python", size: 1 })),
        truncated: false,
        ...identity(workspace),
      };
    }),
    file: vi.fn(async (id, path) => source(projects.get(id)!, path)),
    jobs: vi.fn(async (id) => histories.get(id) || []),
    job: vi.fn(async (id, jobId) =>
      histories.get(id)!.find((item) => item.id === jobId)!,
    ),
    analyze: vi.fn(),
    cancel: vi.fn(),
  };
  return { api, projects, histories, apply };
}
async function confirm(dialog: HTMLElement) {
  fireEvent.click(within(dialog).getByTestId("access-preview-button"));
  fireEvent.click(
    await within(dialog).findByLabelText("我已核对以上文件访问范围"),
  );
  fireEvent.click(within(dialog).getByTestId("access-confirm-button"));
}
beforeEach(() => {
  localStorage.clear();
  history.replaceState(null, "", "/");
});
afterEach(cleanup);

describe("confirmed file access boundary", () => {
  it("offers ordinary files to models by default for a new web workspace without submitting source", async () => {
    const { api } = harness([]);
    render(<App client={api} />);
    await screen.findByRole("heading", { name: "从一个项目开始。" });
    fireEvent.click(screen.getAllByRole("button", { name: /打开项目目录/ }).at(-1)!);
    const dialog = screen.getByRole("dialog");
    expect((within(dialog).getByRole("checkbox", { name: "普通文件默认允许模型取材" }) as HTMLInputElement).checked).toBe(true);
    expect((within(dialog).getByTestId("model-scope-input") as HTMLTextAreaElement).value).toBe("**");
    fireEvent.change(within(dialog).getByLabelText("项目目录"), { target: { value: "/projects/a" } });
    await confirm(dialog);
    await waitFor(() => expect(api.createWorkspace).toHaveBeenCalledWith("/projects/a", undefined,
      expect.objectContaining({ settings: expect.objectContaining({ model_scope: ["**"], local_only: [], exclude: [], respect_gitignore: true }) })));
    expect(api.file).not.toHaveBeenCalled();
    expect(api.analyze).not.toHaveBeenCalled();
  });

  it("upgrades the legacy fallback while preserving explicit local and exclude rules, and can undo the draft", async () => {
    const saved = { respect_gitignore: true, exclude: ["secret.py"], local_only: ["public.py"], model_scope: ["selected.py"] };
    const { api } = harness([project("a", 1, saved)]);
    render(<App client={api} />);
    const openSettings = await screen.findByRole("button", { name: "工作空间设置" });
    await waitFor(() => expect((openSettings as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(openSettings);
    const dialog = await screen.findByRole("dialog");
    const toggle = within(dialog).getByRole("checkbox", { name: "普通文件默认允许模型取材" });
    expect((toggle as HTMLInputElement).checked).toBe(false);
    fireEvent.click(toggle);
    expect((within(dialog).getByTestId("model-scope-input") as HTMLTextAreaElement).value).toBe("selected.py\n**");
    expect((within(dialog).getByTestId("exclude-input") as HTMLTextAreaElement).value).toBe("secret.py");
    expect((within(dialog).getByTestId("local-only-input") as HTMLTextAreaElement).value).toBe("public.py");
    fireEvent.click(toggle);
    expect((within(dialog).getByTestId("model-scope-input") as HTMLTextAreaElement).value).toBe("selected.py");
    fireEvent.click(toggle);
    await confirm(dialog);
    await waitFor(() => expect(api.updateWorkspace).toHaveBeenCalledWith("a", expect.objectContaining({ access_policy: expect.objectContaining({
      settings: { ...saved, model_scope: ["selected.py", "**"] }, expected_version: 1,
    }) })));
    expect(api.file).not.toHaveBeenCalled();
  });

  it("discards a server-rejected preview and requires a new version before opening the project", async () => {
    const { api,projects } = harness([]);
    const staleRequest=deferred<Workspace>();
    vi.mocked(api.createWorkspace).mockReturnValueOnce(staleRequest.promise);
    vi.mocked(api.previewAccess)
      .mockResolvedValueOnce({
        ...preview("/projects/a", defaultAccessSettings()),
        expected_version: 0,
      })
      .mockResolvedValueOnce({
        ...preview("/projects/a", defaultAccessSettings()),
        expected_version: 2,
      });
    render(<App client={api} />);
    await screen.findByRole("heading", { name: "从一个项目开始。" });
    fireEvent.click(
      screen.getAllByRole("button", { name: /打开项目目录/ }).at(-1)!,
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("项目目录"), {
      target: { value: "/projects/a" },
    });
    await confirm(dialog);
    await act(async()=>{staleRequest.reject(new ApiError('其他窗口已经修改访问范围',409));});
    await waitFor(()=>{
      expect(within(dialog).getByRole('alert').textContent).toContain('文件访问范围已变化，请重新预览并确认');
      expect(within(dialog).queryByTestId('access-preview')).toBeNull();
      expect(within(dialog).queryByLabelText('我已核对以上文件访问范围')).toBeNull();
      expect((within(dialog).getByTestId('access-confirm-button') as HTMLButtonElement).disabled).toBe(true);
    });
    expect(
      vi.mocked(api.createWorkspace).mock.calls[0][2]?.expected_version,
    ).toBe(0);
    expect(screen.getByRole("main").textContent).toContain("从一个项目开始。");
    expect(api.files).not.toHaveBeenCalled();
    expect(api.file).not.toHaveBeenCalled();
    expect(api.jobs).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByTestId("access-confirm-button"));
    expect(api.createWorkspace).toHaveBeenCalledTimes(1);
    projects.set('a',project('a',2));
    await confirm(dialog);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(
      vi.mocked(api.createWorkspace).mock.calls[1][2]?.expected_version,
    ).toBe(2);
  });
  it("never restores legacy source, history or analysis before access is saved", async () => {
    const legacy = { ...project("a"), access_policy: undefined };
    const { api } = harness([legacy]);
    writeView("a", {
      tabs: ["secret.py"],
      selected: "secret.py",
      expanded: [],
    });
    render(<App client={api} />);
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByRole("heading", { name: "确认文件访问范围" }),
    ).toBeTruthy();
    expect(api.files).not.toHaveBeenCalled();
    expect(api.file).not.toHaveBeenCalled();
    expect(api.jobs).not.toHaveBeenCalled();
    expect(api.job).not.toHaveBeenCalled();
    expect(api.analyze).not.toHaveBeenCalled();
    expect(localStorage.getItem("codesentry.workspace.a")).toBeNull();
    fireEvent.change(within(dialog).getByTestId("exclude-input"), {
      target: { value: "secret.py" },
    });
    fireEvent.change(within(dialog).getByTestId("local-only-input"), {
      target: { value: "public.py" },
    });
    await confirm(dialog);
    await screen.findByRole("treeitem", { name: "打开 public.py" });
    expect(
      screen.queryByRole("treeitem", { name: "打开 secret.py" }),
    ).toBeNull();
    expect(api.file).not.toHaveBeenCalled();
    expect(api.updateWorkspace).toHaveBeenCalledWith(
      "a",
      expect.objectContaining({
        access_policy: expect.objectContaining({
          confirmed: true,
          settings: expect.objectContaining({
            exclude: ["secret.py"],
            local_only: ["public.py"],
            respect_gitignore: true,
          }),
        }),
      }),
    );
  });

  it("clears the active reader and rejects late source responses when reopening with tighter rules", async () => {
    const a = project("a"),
      b = project("b");
    const { api, projects, histories } = harness([a, b]);
    const pendingFile = deferred<FileContent>();
    histories.set("a", [{ ...job(a), result: null }]);
    api.file = vi.fn(() => pendingFile.promise);
    writeView(
      "b",
      { tabs: ["public.py"], selected: "public.py", expanded: [] },
      accessKey(b),
    );
    localStorage.setItem("codesentry.last-workspace", "a");
    const clearA = vi.fn(),
      clearB = vi.fn();
    const removeA = registerReader("a", clearA),
      removeB = registerReader("b", clearB);
    try {
      render(<App client={api} />);
      fireEvent.click(
        await screen.findByRole("treeitem", { name: "打开 secret.py" }),
      );
      await waitFor(() => expect(api.file).toHaveBeenCalledTimes(1));
      fireEvent.click(screen.getByRole("button", { name: "添加工作空间" }));
      const dialog = screen.getByRole("dialog");
      fireEvent.change(within(dialog).getByLabelText("项目目录"), {
        target: { value: a.path },
      });
      fireEvent.change(within(dialog).getByTestId("exclude-input"), {
        target: { value: "secret.py" },
      });
      await confirm(dialog);
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      await screen.findByRole("treeitem", { name: "打开 public.py" });
      await act(async () => {
        pendingFile.resolve(source(a, "secret.py", "OLD_PRIVATE_SOURCE"));
      });
      expect(screen.queryByTestId("code-editor")).toBeNull();
      expect(document.body.textContent).not.toContain("OLD_PRIVATE");
      expect(api.jobs).not.toHaveBeenCalled();
      expect(api.job).not.toHaveBeenCalled();
      expect(
        screen.queryByRole("treeitem", { name: "打开 secret.py" }),
      ).toBeNull();
      expect(localStorage.getItem("codesentry.workspace.a")).toBeNull();
      expect(localStorage.getItem("codesentry.workspace.b")).toContain(
        "public.py",
      );
      expect(projects.get("b")!.access_policy).toEqual(b.access_policy);
      expect(clearA).toHaveBeenCalled();
      expect(clearB).not.toHaveBeenCalled();
      expect(projects.get("a")!.access_policy!.version).toBe(2);
    } finally {
      removeA();
      removeB();
    }
  });

  it("detects a remote policy version change and clears displayed source and saved tabs", async () => {
    const a = project("a");
    const { api, projects } = harness([a]);
    render(<App client={api} />);
    fireEvent.click(
      await screen.findByRole("treeitem", { name: "打开 secret.py" }),
    );
    expect((await screen.findByTestId("code-editor")).textContent).toContain(
      "a:secret.py:SOURCE",
    );
    projects.set(
      "a",
      project("a", 2, { ...defaultAccessSettings(), exclude: ["secret.py"] }),
    );
    await waitFor(
      () => expect(screen.queryByTestId("code-editor")).toBeNull(),
      { timeout: 3500 },
    );
    await screen.findByRole("treeitem", { name: "打开 public.py" });
    expect(
      screen.queryByRole("treeitem", { name: "打开 secret.py" }),
    ).toBeNull();
    expect(localStorage.getItem("codesentry.workspace.a")).toBeNull();
    expect(api.file).toHaveBeenCalledTimes(1);
  });

  it("ignores an obsolete preview and requires a fresh confirmation after rules change", async () => {
    const { api } = harness([]);
    const old = deferred<AccessPreview>();
    vi.mocked(api.previewAccess).mockImplementationOnce(() => old.promise);
    render(<App client={api} />);
    await screen.findByRole("heading", { name: "从一个项目开始。" });
    fireEvent.click(
      screen.getAllByRole("button", { name: /打开项目目录/ }).at(-1)!,
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("项目目录"), {
      target: { value: "/projects/a" },
    });
    fireEvent.click(within(dialog).getByTestId("access-preview-button"));
    fireEvent.change(within(dialog).getByTestId("exclude-input"), {
      target: { value: "private/\nsecret.py\n" },
    });
    await act(async () =>
      old.resolve(preview("/projects/a", defaultAccessSettings())),
    );
    expect(within(dialog).queryByTestId("access-preview")).toBeNull();
    expect(
      (within(dialog).getByTestId("access-confirm-button") as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(api.createWorkspace).not.toHaveBeenCalled();
    expect(api.file).not.toHaveBeenCalled();
    await confirm(dialog);
    await waitFor(() =>
      expect(api.createWorkspace).toHaveBeenCalledWith(
        "/projects/a",
        undefined,
        expect.objectContaining({
          confirmed: true,
          settings: expect.objectContaining({
            exclude: ["private/", "secret.py"],
          }),
        }),
      ),
    );
  });

  it("keeps content unavailable when permission cleanup fails", async () => {
    const a = project("a");
    const { api, projects } = harness([a]);
    api.updateWorkspace = vi.fn(async () => {
      projects.set("a", {
        ...project("a", 2, {
          ...defaultAccessSettings(),
          exclude: ["secret.py"],
        }),
        access_policy: {
          ...project("a", 2).access_policy!,
          cleanup_pending: true,
        },
      });
      throw new ApiError("权限已收紧，旧数据清理未完成", 503);
    });
    render(<App client={api} />);
    fireEvent.click(
      await screen.findByRole("treeitem", { name: "打开 secret.py" }),
    );
    await screen.findByTestId("code-editor");
    fireEvent.click(screen.getByRole("button", { name: "工作空间设置" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByTestId("exclude-input"), {
      target: { value: "secret.py" },
    });
    await confirm(dialog);
    await within(dialog).findByText("权限已收紧，旧数据清理未完成");
    await waitFor(() => expect(screen.queryByTestId("code-editor")).toBeNull());
    expect(screen.getByTestId("access-gate").textContent).toContain(
      "访问范围待清理",
    );
    expect(localStorage.getItem("codesentry.workspace.a")).toBeNull();
    expect(api.file).toHaveBeenCalledTimes(1);
  });
});
