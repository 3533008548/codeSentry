import {
  ChevronDown,
  ChevronRight,
  FileCode2,
  FileText,
  Folder,
  FolderOpen,
} from "lucide-react";
import { useMemo } from "react";
import type { SourceFile } from "./api";
import { fileTree, type TreeNode } from "./state";
export function FileTree({
  files,
  query,
  expanded,
  selected,
  onToggle,
  onOpen,
}: {
  files: SourceFile[];
  query: string;
  expanded: string[];
  selected: string | null;
  onToggle: (path: string) => void;
  onOpen: (path: string) => void;
}) {
  const nodes = useMemo(
    () =>
      fileTree(
        files.filter(
          (file) =>
            !query ||
            file.path.toLocaleLowerCase().includes(query.toLocaleLowerCase()),
        ),
      ),
    [files, query],
  );
  const open = new Set(expanded);
  const render = (node: TreeNode, depth: number) => {
    const isOpen = open.has(node.path) || !!query;
    if (node.file) {
      const Icon = /\.(md|txt|toml|json|yml|yaml)$/i.test(node.name)
        ? FileText
        : FileCode2;
      return (
        <li key={node.path} role="none">
          <button
            role="treeitem"
            aria-selected={selected === node.path}
            aria-label={`打开 ${node.path}`}
            className={`tree-file ${selected === node.path ? "selected" : ""}`}
            style={{ paddingLeft: 14 + depth * 15 }}
            onClick={() => onOpen(node.path)}
            title={node.path}
            data-path={node.path}
          >
            <Icon
              size={14}
              className={`file-icon lang-${node.file.language}`}
            />
            <span>{node.name}</span>
          </button>
        </li>
      );
    }
    return (
      <li key={node.path} role="none">
        <button
          role="treeitem"
          aria-expanded={isOpen}
          className="tree-folder"
          style={{ paddingLeft: 8 + depth * 15 }}
          onClick={() => onToggle(node.path)}
          title={node.path}
        >
          {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          {isOpen ? <FolderOpen size={14} /> : <Folder size={14} />}
          <span>{node.name}</span>
        </button>
        {isOpen && (
          <ul role="group">
            {node.children.map((child) => render(child, depth + 1))}
          </ul>
        )}
      </li>
    );
  };
  return (
    <ul
      role="tree"
      aria-label="项目文件"
      className="file-tree"
      data-testid="file-tree"
    >
      {nodes.map((node) => render(node, 0))}
      {!nodes.length && (
        <li className="empty-inline">
          {query ? "没有匹配的文件" : "没有可浏览的文本文件"}
        </li>
      )}
    </ul>
  );
}
