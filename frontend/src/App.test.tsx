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
import type {
  Api,
  FileContent,
  Workspace,
} from "./api";

vi.mock("./CodeViewer", () => ({
  CodeViewer: ({
    file,
    jumpLine,
    jumpRequest,
  }: {
    file: FileContent;
    jumpLine?: number;
    jumpRequest?: number;
  }) => (
    <pre
      data-testid="code-editor"
      data-jump-line={jumpLine}
      data-jump-request={jumpRequest}
    >
      {file.content}
    </pre>
  ),
}));

const project = (id: string): Workspace => ({
  id,
  name: `项目${id.toUpperCase()}`,
  path: `/projects/${id}`,
  created_at: "2026-01-01",
  updated_at: "2026-01-01",
  config: { max_depth: 4, max_items: 30 },
  access_policy: {
    confirmed: true,
    version: 1,
    settings: {
      respect_gitignore: true,
      exclude: [],
      local_only: [],
      model_scope: [],
    },
    fingerprint: `policy-${id}-1`,
    cleanup_pending: false,
    issues: [],
    restricted: false,
  },
});
const source = (id: string, path: string, content: string): FileContent => ({
  workspace_id: id,
  policy_version: 1,
  policy_fingerprint: `policy-${id}-1`,
  path,
  content,
  language: "python",
  sha256: content,
  lines: 1,
});
const listing = (id: string, path = `${id}.py`) => ({
  workspace_id: id,
  policy_version: 1,
  policy_fingerprint: `policy-${id}-1`,
  files: [{ path, language: "python", size: 1 }],
  truncated: false,
});
const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};
function client(overrides: Partial<Api> = {}): Api {
  return {
    workspaces: vi.fn(async () => [project("a"), project("b")]),
    previewAccess: vi.fn(async (path) => ({
      path,
      expected_version: path.endsWith("/a") ? 1 : 0,
      access_policy: project(path.endsWith("/a") ? "a" : "c").access_policy!,
      entries: [],
      truncated: false,
    })),
    workspace: vi.fn(async (id) => project(id)),
    createWorkspace: vi.fn(async () => project("c")),
    updateWorkspace: vi.fn(async (id) => project(id)),
    files: vi.fn(async (id) => listing(id)),
    file: vi.fn(async (id, path) => source(id, path, `${id} source`)),
    jobs: vi.fn(async () => []),
    job: vi.fn(),
    analyze: vi.fn(),
    cancel: vi.fn(),
    ...overrides,
  };
}
beforeEach(() => {
  localStorage.clear();
  history.replaceState(null, "", "/");
});
afterEach(cleanup);

describe("workspace navigation under delayed requests", () => {
  it("ignores an old project file list after switching projects", async () => {
    const old = deferred<ReturnType<typeof listing>>();
    render(
      <App
        client={client({
          files: vi.fn((id) =>
            id === "a" ? old.promise : Promise.resolve(listing("b")),
          ),
        })}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: /项目B/ }));
    await screen.findByRole("treeitem", { name: "打开 b.py" });
    expect(localStorage.getItem("codesentry.last-workspace")).toBe("b");
    await act(async () => {
      old.resolve(listing("a"));
    });
    expect(screen.queryByRole("treeitem", { name: "打开 a.py" })).toBeNull();
    expect(screen.getByTestId("project-chat")).toBeTruthy();
  });

  it("does not accept the first A response after navigating A → B → A", async () => {
    const old = deferred<ReturnType<typeof listing>>();
    let aLoads = 0;
    render(
      <App
        client={client({
          files: vi.fn((id) =>
            id === "a" && aLoads++ === 0
              ? old.promise
              : Promise.resolve(listing(id, `${id}-current.py`)),
          ),
        })}
      />,
    );
    const switchB = await screen.findByRole("button", { name: /项目B/ });
    await waitFor(() => expect(aLoads).toBe(1));
    fireEvent.click(switchB);
    await screen.findByRole("treeitem", { name: "打开 b-current.py" });
    fireEvent.click(screen.getByRole("button", { name: /项目A/ }));
    await screen.findByRole("treeitem", { name: "打开 a-current.py" });
    await act(async () => {
      old.resolve(listing("a", "old-a.py"));
    });
    expect(
      screen.queryByRole("treeitem", { name: "打开 old-a.py" }),
    ).toBeNull();
  });

  it("discards late source content and restores each project’s own source preview", async () => {
    const old = deferred<FileContent>();
    const api = client({
      file: vi.fn((id, path) =>
        id === "a"
          ? old.promise
          : Promise.resolve(source(id, path, "B_ONLY_SOURCE")),
      ),
    });
    render(<App client={api} />);
    fireEvent.click(await screen.findByRole("treeitem", { name: "打开 a.py" }));
    await waitFor(() =>
      expect(api.file).toHaveBeenCalledWith(
        "a",
        "a.py",
        undefined,
        expect.any(AbortSignal),
      ),
    );
    const signal = vi.mocked(api.file).mock.calls[0][3]!;
    fireEvent.click(screen.getByRole("button", { name: /项目B/ }));
    fireEvent.click(await screen.findByRole("treeitem", { name: "打开 b.py" }));
    expect((await screen.findByTestId("code-editor")).textContent).toBe(
      "B_ONLY_SOURCE",
    );
    await act(async () => {
      old.resolve(source("a", "a.py", "A_LATE_SOURCE"));
    });
    expect(screen.getByTestId("code-editor").textContent).toBe("B_ONLY_SOURCE");
    expect(signal.aborted).toBe(true);
    expect(screen.getByLabelText("源码预览").textContent).not.toContain("a.py");
    fireEvent.click(screen.getByRole("button", { name: /项目A/ }));
    await waitFor(() => expect(screen.getByLabelText("源码预览").textContent).toContain("A_LATE_SOURCE"));
    expect(screen.getByLabelText("源码预览").textContent).not.toContain("b.py");
  });
});

it("reopens the active directory without invalidating its pending source requests", async () => {
  const pending = deferred<FileContent>();
  const api = client({
    file: vi.fn(() => pending.promise),
    createWorkspace: vi.fn(async () => project("a")),
  });
  render(<App client={api} />);
  fireEvent.click(await screen.findByRole("treeitem", { name: "打开 a.py" }));
  await waitFor(() => expect(api.file).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole("button", { name: "添加工作空间" }));
  const dialog = screen.getByRole("dialog");
  fireEvent.change(within(dialog).getByLabelText("项目目录"), {
    target: { value: "/projects/a" },
  });
  fireEvent.click(within(dialog).getByTestId("access-preview-button"));
  fireEvent.click(
    await within(dialog).findByLabelText("我已核对以上文件访问范围"),
  );
  fireEvent.click(within(dialog).getByRole("button", { name: "打开工作空间" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await act(async () => {
    pending.resolve(source("a", "a.py", "REOPENED_A_SOURCE"));
  });
  expect((await screen.findByTestId("code-editor")).textContent).toBe(
    "REOPENED_A_SOURCE",
  );
  expect(screen.getAllByTestId("workspace-card")).toHaveLength(2);
});

it("opens a project directory from a blank start and shows service errors in the form", async () => {
  const api = client({
    workspaces: vi.fn(async () => []),
    createWorkspace: vi.fn(async () => {
      throw new Error("目录不存在");
    }),
  });
  render(<App client={api} />);
  await screen.findByRole("heading", { name: "从一个项目开始。" });
  fireEvent.click(
    screen.getAllByRole("button", { name: /打开项目目录/ }).at(-1)!,
  );
  const dialog = screen.getByRole("dialog");
  const path = within(dialog).getByLabelText("项目目录") as HTMLInputElement;
  expect(path.value).toBe("");
  fireEvent.change(path, { target: { value: "/missing/project" } });
  fireEvent.click(within(dialog).getByTestId("access-preview-button"));
  fireEvent.click(
    await within(dialog).findByLabelText("我已核对以上文件访问范围"),
  );
  fireEvent.click(within(dialog).getByRole("button", { name: "打开工作空间" }));
  expect((await within(dialog).findByRole("alert")).textContent).toContain(
    "目录不存在",
  );
  expect(api.createWorkspace).toHaveBeenCalledWith(
    "/missing/project",
    undefined,
    expect.objectContaining({ confirmed: true }),
  );
});
