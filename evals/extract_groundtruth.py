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

# 代码块里的文件标注行：├── xxx.py    # 说明
TREE_LINE = re.compile(
    r"^[│├└─\s]*"
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


def is_core_file(path: str) -> bool:
    """是否属于"读懂项目必读"的清单。"""
    if DIR_ONLY.search(path):
        return False
    return not any(p.search(path) for p in EXCLUDE_PATTERNS)


def extract_from_text(text: str) -> set[str]:
    found: set[str] = set()
    for m in TREE_LINE.finditer(text):
        p = normalize(m.group("path"))
        if p and is_core_file(p):
            found.add(p)
    for m in BACKTICK_PATH.finditer(text):
        p = normalize(m.group(1))
        if p and is_core_file(p):
            found.add(p)
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
