"""索引落盘与陈旧检测。

v0.2 §4.5 原文：「索引陈旧问题必须在 README 回答：Greptile 栽在这一点上
——索引是快照，代码改了索引不知道，直到下次重建。本项目的答案是内容哈希
+ 增量重解析，**但必须承认一个残留窗口：单次扫描过程中代码被修改，索引
与工作区会短暂不一致**。这个窗口是显式声明的，不是隐藏的。」

## 为什么用 JSON 不用 SQLite

流程约定：「基线用 git 跟踪的 JSON，不用 SQLite（要能 diff / review / 回滚）」。
索引同理——它要能被 review、能 diff、能回滚。

## 陈旧检测

回答三个问题：
1. **索引在吗？** 没有 → 需要先构建
2. **索引过期了吗？** 有文件的内容哈希与索引记录不符 → 需要重建
3. **差多少？** 列出变化的文件，让用户知道重建会动多少东西
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from codesentry.index.builder import IndexResult
from codesentry.index.cache import default_index_dir

INDEX_VERSION = 2
DEFAULT_INDEX_FILE = "index.json"


@dataclass
class StaleInfo:
    """陈旧检测结果。"""

    exists: bool = False
    stale: bool = False
    added: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    built_at: str = ""
    age_seconds: float = 0.0

    @property
    def changed_count(self) -> int:
        return len(self.added) + len(self.modified) + len(self.removed)

    def summary(self) -> str:
        if not self.exists:
            return "索引不存在，需要先构建"
        if not self.stale:
            age = f"{self.age_seconds / 3600:.1f} 小时前"
            return f"索引是最新的（{age}构建）"
        parts = []
        if self.added:
            parts.append(f"新增 {len(self.added)}")
        if self.modified:
            parts.append(f"修改 {len(self.modified)}")
        if self.removed:
            parts.append(f"删除 {len(self.removed)}")
        return "索引已过期：" + "、".join(parts)


class IndexStore:
    """索引落盘与读取。

    ## 落盘位置

    **默认写到用户缓存目录**，不写进被审查项目——
    理由同 ParseCache：工具不该在被审查方留垃圾、污染其 git status。

    `save_to_project=True` 时写到项目根（`<root>/index.json`），
    适合希望把索引纳入版本控制、便于 review 与 diff 的场景。
    """

    def __init__(
        self,
        root: Path,
        filename: str = DEFAULT_INDEX_FILE,
        save_to_project: bool = False,
    ):
        self.root = root
        self.filename = filename
        self.save_to_project = save_to_project

    @property
    def index_file(self) -> Path:
        if self.save_to_project:
            return self.root / self.filename
        return default_index_dir(self.root) / self.filename

    # ---------- 落盘 ----------

    def save(self, result: IndexResult) -> bool:
        """保存索引。

        落盘内容是**摘要**而非全量符号表——全量符号表可能有几 MB，
        落盘后难以 review。摘要足够回答「索引是否过期」。
        """
        payload = {
            "version": INDEX_VERSION,
            "root": result.root,
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "built_at_epoch": time.time(),
            "file_count": len(result.files),
            "symbol_count": len(result.symbols),
            "edge_count": len(result.edges),
            "files": {
                f.path: {
                    "content_hash": f.content_hash,
                    "lines": f.lines,
                    "language": f.language.value,
                    "is_test": f.is_test,
                    "is_script": f.is_script,
                }
                for f in result.files
            },
            "entrypoints": [
                {"file": e.file, "level": e.level, "reason": e.reason}
                for e in result.entrypoints
            ],
            "top_files": [
                {"file": f, "score": round(s, 6)}
                for f, s in result.top_files(30)
            ],
        }
        try:
            self.index_file.write_text(
                json.dumps(payload, ensure_ascii=False, indent=1),
                encoding="utf-8",
            )
            return True
        except OSError:
            return False

    def load(self) -> dict | None:
        """读取索引。"""
        if not self.index_file.exists():
            return None
        try:
            data = json.loads(self.index_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if data.get("version") != INDEX_VERSION:
            return None
        return data

    # ---------- 陈旧检测 ----------

    def check_stale(self, result: IndexResult | None = None) -> StaleInfo:
        """检测索引是否过期。

        用**内容哈希**比对，不用 mtime（mtime 在 git checkout 后可能不变
        但内容变了，或反之）。
        """
        info = StaleInfo()
        data = self.load()
        if data is None:
            return info

        info.exists = True
        info.built_at = data.get("built_at", "")
        info.age_seconds = max(0.0, time.time() - data.get("built_at_epoch", 0))

        recorded = data.get("files", {})
        if not result:
            # 没给当前结果 → 只能报告存在与年龄
            return info

        current = {f.path: f.content_hash for f in result.files}
        recorded_paths = set(recorded)
        current_paths = set(current)

        for p in sorted(current_paths - recorded_paths):
            info.added.append(p)
        for p in sorted(recorded_paths - current_paths):
            info.removed.append(p)
        for p in sorted(current_paths & recorded_paths):
            if recorded[p].get("content_hash") != current[p]:
                info.modified.append(p)

        info.stale = bool(info.added or info.modified or info.removed)
        return info

    def stale_report(self, info: StaleInfo) -> str:
        """渲染陈旧报告。"""
        lines = [f"索引状态: {info.summary()}"]
        if info.stale:
            if info.added:
                lines.append(f"  新增 ({len(info.added)}): "
                             f"{', '.join(info.added[:5])}"
                             f"{' ...' if len(info.added) > 5 else ''}")
            if info.modified:
                lines.append(f"  修改 ({len(info.modified)}): "
                             f"{', '.join(info.modified[:5])}"
                             f"{' ...' if len(info.modified) > 5 else ''}")
            if info.removed:
                lines.append(f"  删除 ({len(info.removed)}): "
                             f"{', '.join(info.removed[:5])}"
                             f"{' ...' if len(info.removed) > 5 else ''}")
        return "\n".join(lines)
