import { beforeEach, describe, expect, it } from "vitest";
import { fileTree, readView, writeView } from "./state";

beforeEach(() => localStorage.clear());

describe("workspace-specific reading state", () => {
  it("removes old policy state before restoring a workspace, without touching other projects", () => {
    writeView(
      "a",
      { tabs: ["private.py"], selected: "private.py", expanded: [] },
      "a:1:old",
    );
    writeView(
      "b",
      { tabs: ["public.py"], selected: "public.py", expanded: [] },
      "b:1:current",
    );
    expect(readView("a", "a:2:new").tabs).toEqual([]);
    expect(localStorage.getItem("codesentry.workspace.a")).toBeNull();
    expect(readView("b", "b:1:current").selected).toBe("public.py");
  });
  it("keeps tabs and expanded directories isolated and never stores source text", () => {
    writeView("a", {
      tabs: ["src/main.py"],
      selected: "src/main.py",
      expanded: ["src"],
    });
    writeView("b", { tabs: ["index.ts"], selected: "index.ts", expanded: [] });
    expect(readView("a").selected).toBe("src/main.py");
    expect(readView("b").selected).toBe("index.ts");
    expect(
      Object.keys(
        JSON.parse(localStorage.getItem("codesentry.workspace.a")!),
      ).sort(),
    ).toEqual(["expanded", "selected", "tabs", "workspace_id"]);
  });

  it("ignores malformed and mismatched saved state", () => {
    localStorage.setItem("codesentry.workspace.a", "{broken");
    expect(readView("a").tabs).toEqual([]);
    localStorage.setItem(
      "codesentry.workspace.a",
      JSON.stringify({
        workspace_id: "b",
        tabs: ["secret.py"],
        selected: "secret.py",
      }),
    );
    expect(readView("a").selected).toBeNull();
  });

  it("only restores selected files that belong to the retained tabs", () => {
    localStorage.setItem(
      "codesentry.workspace.a",
      JSON.stringify({
        workspace_id: "a",
        tabs: ["a.py", 12],
        selected: "missing.py",
      }),
    );
    expect(readView("a")).toEqual({
      tabs: ["a.py"],
      selected: null,
      expanded: [],
    });
  });
});

it("builds deterministic file navigation with folders before files", () => {
  const tree = fileTree(
    ["z.py", "src/b.ts", "src/a.ts", "a.md"].map((path) => ({
      path,
      language: "text",
      size: 1,
    })),
  );
  expect(tree.map((node) => node.name)).toEqual(["src", "a.md", "z.py"]);
  expect(tree[0].children.map((node) => node.path)).toEqual([
    "src/a.ts",
    "src/b.ts",
  ]);
});
