"""从项目自带的文档中提取 ground truth（核心文件清单）。

**为什么自动提取**：v0.2 §4.3.2 记录的循环论证教训——手工挑的样本会
带着主观偏向（本次是"按角色多样性挑"，恰好与被测机制相关）。

自动提取的清单是**文档里出现的全部**核心文件，不做人工筛选。

用法:
    python evals/extract_groundtruth.py <project_root> [--out gt.json]

支持的来源:
  - README.md 的「项目结构」/「目录结构」章节（代码块里的文件标注）
  - 《项目接手指南.md》的目录与关键文件表
  - 任意 .md 中的 `路径/文件名.ext` 反引号引用
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# 目录树行：├── dir/     或  ├── xxx.py
TREE_DIR = re.compile(
    r"^(?P<indent>[│\s├└─]*)(?P<name>[A-Za-z0-9_.-]+)/?\s*(?:#.*)?$"
)
# 代码块里的文件标注行：├── xxx.py    # 说明
TREE_LINE = re.compile(
    r"^(?P<indent>[│├└─\s]*)"
    r"(?P<path>[A-Za-z0-9_./\\-]+\.(?:py|ts|tsx))\s*"
    r"(?:#.*)?$",
    re.MULTILINE,
)
# 反引号包裹的路径
BACKTICK_PATH = re.compile(r"`([A-Za-z0-9_./\\-]+\.(?:py|ts|tsx))`")
# Markdown 表格里的路径
TABLE_PATH = re.compile(
    r"\|\s*`(?P<path>[A-Za-z0-9_./\\-]+\.(?:py|ts|tsx))`"
)

# 这些是目录聚合项，不是具体文件
DIR_ONLY = re.compile(r"/$")

# 明确排除的：测试/脚本/配置类，不是"读懂项目必读"的清单
# 注意：tools/ 与 evals/ 下虽然是被 README 标注的模块，但它们按设计
# 不参与重要度排序（v0.2 §4.2.1），所以也不该进 ground truth——
# 否则等于要求工具给它们排名，分母被无意义地拉低。
EXCLUDE_PATTERNS = (
    re.compile(r"(^|/)tests?(/|$)"),
    re.compile(r"(^|/)scripts?(/|$)"),
    re.compile(r"(^|/)evals?(/|$)"),
    re.compile(r"(^|/)tools?(/|$)"),
    re.compile(r"(^|/)benchmarks?(/|$)"),
    re.compile(r"\.config\."),
    re.compile(r"^conftest"),
    re.compile(r"(^|/)__"),
)


def normalize(p: str) -> str:
    """统一为相对路径（/ 分隔，去掉 ./ 前缀）。"""
    p = p.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def extract_from_tree(text: str) -> set[str]:
    """从目录树代码块中提取文件，**带目录上下文**。

    为什么需要上下文：README 的目录树里，工具目录下的条目常写成
    裸文件名（`search.py`）而不是完整路径（`tools/search.py`）。
    不跟踪目录就分不清 `search.py` 是 `tools/search.py`（工具实现，
    按设计不参与重要度排序）还是 `core/search.py`（核心模块）。

    目录栈的维护：按缩进层级推入/弹出目录项。
    """
    found: set[str] = set()
    # 目录栈：(缩进宽度, 目录名)
    stack: list[tuple[int, str]] = []

    for line in text.splitlines():
        m = TREE_LINE.match(line)
        if m:
            indent = len(m.group("indent").rstrip())
            raw = m.group("path")
            # 路径里已含目录 → 直接用
            if "/" in raw or "\\" in raw:
                p = normalize(raw)
            else:
                # 只有裸文件名 → 拼上目录栈
                prefix = "/".join(d for _, d in stack)
                p = normalize(f"{prefix}/{raw}" if prefix else raw)
            if p and is_core_file(p):
                found.add(p)
            continue

        # 目录行
        md = TREE_DIR.match(line)
        if md and "│" not in md.group("indent")[:1] or (
            md and md.group("name") not in ("py", "ts", "tsx")
        ):
            indent_raw = md.group("indent")
            # 计算视觉缩进：树形字符按 1 宽，保留空格
            width = 0
            for ch in indent_raw:
                width += 4 if ch in "│├└─" else 1
            name = md.group("name")
            if name.endswith("/") or (
                "─" in indent_raw or "├" in indent_raw or "│" in indent_raw
            ):
                # 弹出比当前更深的目录
                while stack and stack[-1][0] >= width:
                    stack.pop()
                stack.append((width, name.rstrip("/")))
    return found


def is_core_file(path: str) -> bool:
    """是否属于"读懂项目必读"的清单。"""
    if DIR_ONLY.search(path):
        return False
    return not any(p.search(path) for p in EXCLUDE_PATTERNS)


def extract_from_text(text: str) -> set[str]:
    found: set[str] = set()
    # 1. 目录树（带目录上下文，能区分 tools/search.py 与 core/search.py）
    found |= extract_from_tree(text)
    # 2. 反引号路径
    for m in BACKTICK_PATH.finditer(text):
        p = normalize(m.group(1))
        if p and is_core_file(p):
            found.add(p)
    # 3. Markdown 表格
    for m in TABLE_PATH.finditer(text):
        p = normalize(m.group("path"))
        if p and is_core_file(p):
            found.add(p)
    return found


def find_docs(root: Path) -> list[Path]:
    """找候选文档。

    只用**架构类**文档，不用方案/日志类文档。
    原因：方案文档（"重构说明.md""需求决策日志.md"）里提到的文件是
    "历史改动涉及的文件"，不是"读懂项目必读的文件"，混进来会污染
    ground truth（实测会引入 40+ 个 scripts/evals 下的文件）。
    """
    docs: list[Path] = []
    for name in ("README.md", "项目接手指南.md", "ARCHITECTURE.md",
                 "架构.md", "CONTRIBUTING.md", "GETTING_STARTED.md"):
        p = root / name
        if p.exists():
            docs.append(p)
    return docs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("project")
    ap.add_argument("--out", help="输出 JSON 路径")
    args = ap.parse_args()

    root = Path(args.project).resolve()
    docs = find_docs(root)
    if not docs:
        print(f"未找到文档: {root}")
        return 2

    all_found: set[str] = set()
    per_doc: dict[str, list[str]] = {}
    for doc in docs:
        text = doc.read_text(encoding="utf-8", errors="replace")
        found = extract_from_text(text)
        if found:
            per_doc[doc.name] = sorted(found)
            all_found |= found

    print(f"来源文档: {', '.join(d.name for d in docs)}")
    for name, items in per_doc.items():
        print(f"  {name}: {len(items)} 项")
    print(f"\n合计去重: {len(all_found)} 个文件")

    out = sorted(all_found)
    print("\n前 20 项:")
    for p in out[:20]:
        print(f"  {p}")

    if args.out:
        Path(args.out).write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n→ {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
