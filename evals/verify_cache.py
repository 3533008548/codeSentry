"""历史增量缓存验证逻辑；命令入口已停用，禁止无权限复制项目。

以下为历史目的说明；现有缓存反例使用工具自身的合成测试。

关键验证点：
  1. 二次扫描命中缓存，耗时显著下降
  2. 改动一个文件 → 只重解析该文件（其余命中缓存）
  3. 增量结果与全量重建**完全一致**
  4. 缓存不写进被审查项目

用法: python evals/verify_cache.py <project_root> [--keep]
"""
from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codesentry.core.policy import Policy
from codesentry.index.builder import build_index
from codesentry.index.cache import ParseCache, default_cache_dir


def snapshot(r) -> dict:
    """提取可比较的结果快照。"""
    return {
        "files": len(r.files),
        "symbols": len(r.symbols),
        "edges": len(r.edges),
        "file_pr": {k: round(v, 10) for k, v in sorted(r.file_pr.items())},
        "entrypoints": sorted(e.file for e in r.entrypoints),
        "call_stats": dict(sorted(r.call_stats.items())),
    }


def diff(a: dict, b: dict) -> list[str]:
    """比较两个快照的差异。"""
    out = []
    for key in ("files", "symbols", "edges"):
        if a[key] != b[key]:
            out.append(f"{key}: {a[key]} vs {b[key]}")
    if a["file_pr"] != b["file_pr"]:
        diffs = [
            k for k in set(a["file_pr"]) | set(b["file_pr"])
            if a["file_pr"].get(k) != b["file_pr"].get(k)
        ]
        out.append(f"file_pr 差异 {len(diffs)} 个: {diffs[:5]}")
    if a["entrypoints"] != b["entrypoints"]:
        out.append(f"entrypoints: {a['entrypoints']} vs {b['entrypoints']}")
    if a["call_stats"] != b["call_stats"]:
        out.append(f"call_stats: {a['call_stats']} vs {b['call_stats']}")
    return out


def main() -> int:
    """Retired: this historical helper predates workspace access permissions."""
    print("Historical helper disabled: workspace access permissions are required. "
          "Use python -m evals.navigation_development and "
          "python -m evals.navigation_comparison; see the P1 navigation report.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
