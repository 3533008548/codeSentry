export interface WorkspaceView {
  tabs: string[];
  selected: string | null;
  expanded: string[];
}
import { clearReaderCache } from "./readerCache";
const prefix = "codesentry.workspace.";
export const emptyView = (): WorkspaceView => ({
  tabs: [],
  selected: null,
  expanded: [],
});
export function readView(id: string, policyKey?: string): WorkspaceView {
  try {
    const stored = JSON.parse(localStorage.getItem(prefix + id) || "null");
    if (!stored || stored.workspace_id !== id) return emptyView();
    if (policyKey !== undefined && stored.policy_key !== policyKey) {
      localStorage.removeItem(prefix + id);
      clearReaderCache(id);
      return emptyView();
    }
    const tabs = Array.isArray(stored.tabs)
      ? stored.tabs
          .filter((path: unknown): path is string => typeof path === "string")
          .slice(-12)
      : [];
    return {
      tabs,
      selected:
        typeof stored.selected === "string" && tabs.includes(stored.selected)
          ? stored.selected
          : null,
      expanded: Array.isArray(stored.expanded)
        ? stored.expanded.filter(
            (path: unknown): path is string => typeof path === "string",
          )
        : [],
    };
  } catch {
    return emptyView();
  }
}
export function clearView(id: string) {
  try {
    localStorage.removeItem(prefix + id);
  } catch {
    /* The session remains protected when storage is unavailable. */
  }
}
export function writeView(id: string, view: WorkspaceView, policyKey?: string) {
  try {
    localStorage.setItem(
      prefix + id,
      JSON.stringify({
        workspace_id: id,
        ...(policyKey ? { policy_key: policyKey } : {}),
        ...view,
        tabs: view.tabs.slice(-12),
      }),
    );
    localStorage.setItem("codesentry.last-workspace", id);
  } catch {
    /* private mode or full storage still permits browsing */
  }
}
export function initialWorkspace(): string | null {
  const hash = location.hash.match(/^#\/workspace\/([^/?]+)/);
  if (hash) {
    try {
      return decodeURIComponent(hash[1]);
    } catch {
      return null;
    }
  }
  try {
    return localStorage.getItem("codesentry.last-workspace");
  } catch {
    return null;
  }
}
export interface TreeNode {
  name: string;
  path: string;
  file?: { path: string; language: string; size: number };
  children: TreeNode[];
}
export function fileTree(
  files: { path: string; language: string; size: number }[],
): TreeNode[] {
  const root: TreeNode = { name: "", path: "", children: [] };
  for (const file of files) {
    const parts = file.path.split("/");
    let current = root;
    parts.forEach((part, index) => {
      const path = parts.slice(0, index + 1).join("/");
      let node = current.children.find((child) => child.name === part);
      if (!node) {
        node = { name: part, path, children: [] };
        current.children.push(node);
      }
      if (index === parts.length - 1) node.file = file;
      current = node;
    });
  }
  const sort = (nodes: TreeNode[]) => {
    nodes.sort(
      (a, b) =>
        Number(!!a.file) - Number(!!b.file) || a.name.localeCompare(b.name),
    );
    for (const node of nodes) sort(node.children);
  };
  sort(root.children);
  return root.children;
}
