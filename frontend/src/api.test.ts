import { describe, expect, it, vi } from "vitest";
import {
  isFileStale,
  isConfigStale,
  isNavigationResult,
  LocalApi,
  type AnalysisResult,
  type NavigationResult,
  type ReviewPreviewResult,
  type FileContent,
  type AnalysisJob,
  type Workspace,
} from "./api";

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status });

describe("local API ownership and session", () => {
  it("submits an explicit static review request and keeps its workspace identity", async () => {
    const transport = vi.fn<typeof fetch>().mockResolvedValueOnce(json({ token: "token" }))
      .mockResolvedValueOnce(json({ id: "review-1", workspace_id: "a", kind: "review_preview" }));
    await new LocalApi(transport).analyze("a", "review_preview");
    expect(JSON.parse(String(transport.mock.calls[1][1]?.body))).toEqual({ mode: "static", kind: "review_preview" });
  });

  it("rejects a different task returned inside the selected workspace", async () => {
    const transport = vi.fn<typeof fetch>().mockResolvedValueOnce(json({ token: "token" }))
      .mockResolvedValueOnce(json({ id: "other", workspace_id: "a" }));
    await expect(new LocalApi(transport).job("a", "requested")).rejects.toThrow("任务数据不匹配");
  });
  it("opens one session, sends its token, and rejects another workspace response", async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json({ token: "local-only" }))
      .mockResolvedValueOnce(
        json({ workspace_id: "other", files: [], truncated: false }),
      );
    const api = new LocalApi(transport);
    await expect(api.files("selected")).rejects.toThrow("工作空间数据不匹配");
    expect(transport.mock.calls[0][0]).toBe("/api/session");
    expect(
      new Headers(transport.mock.calls[1][1]?.headers).get(
        "X-CodeSentry-Token",
      ),
    ).toBe("local-only");
  });

  it("refreshes an expired local session once and preserves the request signal", async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json({ token: "old" }))
      .mockResolvedValueOnce(json({ detail: "expired" }, 401))
      .mockResolvedValueOnce(json({ token: "new" }))
      .mockResolvedValueOnce(json({ workspaces: [] }));
    const controller = new AbortController();
    await expect(
      new LocalApi(transport).workspaces(controller.signal),
    ).resolves.toEqual([]);
    expect(transport).toHaveBeenCalledTimes(4);
    expect(transport.mock.calls[3][1]?.signal).toBe(controller.signal);
    expect(
      new Headers(transport.mock.calls[3][1]?.headers).get(
        "X-CodeSentry-Token",
      ),
    ).toBe("new");
  });

  it("does not render nested task data owned by a different workspace", async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json({ token: "token" }))
      .mockResolvedValueOnce(
        json({
          workspace_id: "a",
          analyses: [{ id: "job", workspace_id: "b" }],
        }),
      );
    await expect(new LocalApi(transport).jobs("a")).rejects.toThrow(
      "工作空间数据不匹配",
    );
  });

  it("passes analysis context as query data without confusing file path separators", async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json({ token: "token" }))
      .mockResolvedValueOnce(json({ workspace_id: "a", path: "src/a #1.py" }));
    await new LocalApi(transport).file("a", "src/a #1.py", "job-1");
    const url = new URL(String(transport.mock.calls[1][0]), "http://localhost");
    expect(url.searchParams.get("path")).toBe("src/a #1.py");
    expect(url.searchParams.get("analysis_id")).toBe("job-1");
  });
});

describe("analysis snapshot freshness", () => {
  const file: FileContent = {
    workspace_id: "a",
    path: "main.py",
    content: "text",
    language: "python",
    sha256: "raw-sha256",
    lines: 1,
    content_hash: "decoded-sha1",
    content_hash_algorithm: "sha1-decoded-text",
  };
  const result = {
    file_details: [{ path: "main.py", content_hash: "decoded-sha1" }],
  } as NavigationResult;

  it("compares decoded text hashes and ignores the raw file hash", () => {
    expect(isFileStale(file, result)).toBe(false);
    expect(isFileStale({ ...file, content_hash: "changed" }, result)).toBe(
      true,
    );
  });
  it("recognizes historical navigation with an unimplemented review marker", () => {
    expect(isNavigationResult({ ...result, review_status: "not_implemented" } as NavigationResult)).toBe(true);
  });
  it("compares review raw SHA256 even when decoded navigation content stays unchanged", () => {
    const review: ReviewPreviewResult = { kind: "review_preview", source_sha256: { "main.py": "a".repeat(64) },
      review_status: "report_only", gate_status: "not_evaluated", mode: "preview", findings: [], issues: [],
      coverage: { discovered_python: 1, analyzed_python: 1, attempted_python: 1, excluded_python: 0,
        other_language_files_not_evaluated: 0, permissions_limited: false, within_scope_complete: true, whole_repository_evaluated: false },
      summary: { policy_debt_findings: 0, behavior_bug_findings: 0, blocking_findings: 0 } };
    expect(isFileStale({ ...file, sha256: "a".repeat(64), is_stale: false }, review)).toBe(false);
    expect(isFileStale({ ...file, sha256: "b".repeat(64), is_stale: false }, review)).toBe(true);
    expect(isFileStale({ ...file, sha256: "a".repeat(64), is_stale: true }, review)).toBe(true);
  });

  it("does not compare unknown algorithms or unrelated files", () => {
    expect(
      isFileStale({ ...file, content_hash_algorithm: "sha256" }, result),
    ).toBe(false);
    expect(isFileStale({ ...file, path: "other.py" }, result)).toBe(false);
    expect(isFileStale({ ...file, is_stale: true }, null)).toBe(true);
  });
  it("compares startup declarations using raw SHA256 without mixing decoded source hashes", () => {
    const config = { ...file, path: "package.json", sha256: "a".repeat(64) };
    const snapshot = {
      ...result,
      startup_inputs: { "package.json": "a".repeat(64) },
    };
    expect(isFileStale(config, snapshot)).toBe(false);
    expect(
      isFileStale(
        { ...config, sha256: "b".repeat(64), is_stale: false },
        snapshot,
      ),
    ).toBe(true);
    expect(
      isFileStale(config, {
        ...result,
        startup_inputs: { "package.json": "unread:access-policy" },
      }),
    ).toBe(false);
  });
});

it("requires an actual workspace-owned settings snapshot before reporting stale settings", () => {
  const workspace: Workspace = {
    id: "a",
    name: "A",
    path: "/a",
    created_at: "",
    updated_at: "",
    config: { max_depth: 6, max_items: 40 },
  };
  const job: AnalysisJob = {
    id: "job",
    workspace_id: "a",
    status: "succeeded",
    created_at: "",
    started_at: null,
    finished_at: null,
    logs: [],
    error: null,
  };
  expect(isConfigStale(workspace, job)).toBe(false);
  expect(
    isConfigStale(workspace, { ...job, config: { ...workspace.config } }),
  ).toBe(false);
  expect(
    isConfigStale(workspace, {
      ...job,
      result: { config: { max_depth: 4, max_items: 30 } } as AnalysisResult,
    }),
  ).toBe(true);
  expect(
    isConfigStale(workspace, {
      ...job,
      workspace_id: "other",
      config: { max_depth: 4, max_items: 30 },
    }),
  ).toBe(false);
});
