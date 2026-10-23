"""增量缓存。

v0.2 §4.5 已定：**内容哈希失效**。

## 缓存什么

每个文件缓存 `(mtime, content_hash, symbols, calls, imports)`。
**只缓存解析结果，不缓存全局计算**（PageRank / 符号解析 / 入口点识别
每次都重算）——因为实测这些都很便宜：

| 阶段 | 耗时（research_agent 42k 行） |
|---|---|
| parse | **0.87 s** ← 唯一贵的，缓存它 |
| resolve | 0.014 s |
| pagerank（文件级） | 0.002 s |
| symbol_pagerank | 0.004 s |
| entrypoints | 0.020 s |
| roles | 0.060 s |

**为什么 PageRank 也要重算而不是缓存**：v0.2 §4.3 已定"每次全量算，
不做局部近似"——实测 30,000 节点仅 169 ms，而局部近似的 Top50 重合度
只有 11/50。缓存 PageRank 会引入"索引陈旧"的第二个来源，得不偿失。

## 失效判据

用**内容哈希**而不是 mtime：
- mtime 在 git checkout / 文件复制后可能不变但内容变了（或反之）
- 内容哈希是语义判据，"文件是否真的改了"

mtime 只作为快速预筛（mtime 相同且哈希相同 → 一定没变）。

## 残留窗口（必须显式承认）

v0.2 §4.5 原文：「索引陈旧问题必须在 README 回答……本项目的答案是
内容哈希 + 增量重解析，**但必须承认一个残留窗口：单次扫描过程中代码被
修改，索引与工作区会短暂不一致**。这个窗口是显式声明的，不是隐藏的。」

本模块在扫描开始时对每个文件算哈希，扫描过程中不重新检查。
若文件在扫描期间被修改，本轮索引可能包含旧内容。
`store.py` 的陈旧检测会在下次运行时发现这一点。
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from codesentry.core.symbol import CallSite, FileMeta, Symbol

# 缓存格式版本 —— 解析逻辑变化时必须 bump，否则旧缓存会被误用
CACHE_VERSION = 2

DEFAULT_CACHE_DIR = ".codesentry"


@dataclass
class FileCacheEntry:
    """单个文件的缓存条目。"""

    path: str
    content_hash: str
    mtime: float
    symbols: list[Symbol] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "content_hash": self.content_hash,
            "mtime": self.mtime,
            "symbols": [s.model_dump() for s in self.symbols],
            "calls": [c.model_dump() for c in self.calls],
            "imports": {k: sorted(v) for k, v in self.imports.items()},
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileCacheEntry":
        return cls(
            path=d["path"],
            content_hash=d["content_hash"],
            mtime=d.get("mtime", 0.0),
            symbols=[Symbol.model_validate(s) for s in d.get("symbols", [])],
            calls=[CallSite.model_validate(c) for c in d.get("calls", [])],
            imports={k: set(v) for k, v in d.get("imports", {}).items()},
            meta=d.get("meta", {}),
        )


class ParseCache:
    """解析结果缓存。

    ## 缓存位置

    **默认写到用户缓存目录**（`%LOCALAPPDATA%/codesentry/cache/<hash>/`），
    不写进被审查的项目里。

    **理由**：工具不该在被审查方留垃圾。实测写到项目内会生成 4.7 MB 的
    `parse_cache.json`，还会污染被审查项目的 `git status`——
    这对一个"帮你审查代码"的工具是减分项。

    项目内缓存（`.codesentry/`）仍可通过 `cache_dir` 参数启用，
    适合希望把缓存纳入版本控制、便于 review 的场景。
    """

    def __init__(
        self,
        root: Path,
        enabled: bool = True,
        cache_dir: Path | None = None,
    ):
        self.root = root
        self.enabled = enabled
        self.entries: dict[str, FileCacheEntry] = {}
        self.hits = 0
        self.misses = 0
        self._dirty = False
        self._loaded = False
        self._cache_dir = cache_dir or default_cache_dir(root)

    # ---------- 路径 ----------

    @property
    def cache_dir(self) -> Path:
        return self._cache_dir

    @property
    def cache_file(self) -> Path:
        return self.cache_dir / "parse_cache.json"

    # ---------- 读写 ----------

    def load(self) -> None:
        """加载缓存。版本不匹配则整个作废（不报错，静默重建）。"""
        if not self.enabled:
            return
        self._loaded = True
        if not self.cache_file.exists():
            return
        try:
            raw = json.loads(self.cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if raw.get("version") != CACHE_VERSION:
            # 解析逻辑变了，旧缓存不可信 —— 静默作废
            return
        for d in raw.get("files", []):
            try:
                entry = FileCacheEntry.from_dict(d)
            except Exception:
                continue
            self.entries[entry.path] = entry

    def save(self) -> bool:
        """保存缓存。返回是否真的写了。"""
        if not self.enabled or not self._dirty:
            return False
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": CACHE_VERSION,
                "files": [e.to_dict() for e in self.entries.values()],
            }
            self.cache_file.write_text(
                json.dumps(payload, ensure_ascii=False, indent=1),
                encoding="utf-8",
            )
            return True
        except OSError:
            return False

    def clear(self) -> None:
        """清空缓存（refresh-index 用）。"""
        self.entries.clear()
        self.hits = 0
        self.misses = 0
        self._dirty = True
        if self.cache_file.exists():
            try:
                self.cache_file.unlink()
            except OSError:
                pass

    # ---------- 查询与更新 ----------

    def get(self, rel_path: str, content_hash: str) -> FileCacheEntry | None:
        """取缓存条目。哈希一致才算命中。"""
        if not self.enabled:
            return None
        entry = self.entries.get(rel_path)
        if entry is None:
            self.misses += 1
            return None
        if entry.content_hash != content_hash:
            self.misses += 1
            return None
        self.hits += 1
        return entry

    def put(self, entry: FileCacheEntry) -> None:
        """写入缓存条目。"""
        if not self.enabled:
            return
        self.entries[entry.path] = entry
        self._dirty = True

    def prune(self, alive_paths: set[str]) -> int:
        """移除已删除文件的缓存条目。返回移除数量。"""
        if not self.enabled:
            return 0
        stale = [p for p in self.entries if p not in alive_paths]
        for p in stale:
            del self.entries[p]
        if stale:
            self._dirty = True
        return len(stale)

    # ---------- 统计 ----------

    @property
    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hits / total if total else 0.0,
            "entries": len(self.entries),
        }


def hash_content(text: str) -> str:
    """内容哈希。"""
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()


def default_cache_dir(root: Path) -> Path:
    """默认缓存目录：用户缓存目录下的 `<项目路径哈希>/`。

    **不写进被审查项目**——理由见 ParseCache 的类文档。
    """
    key = hashlib.sha1(
        str(root.resolve()).encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    if base:
        base_path = Path(base)
    else:
        base_path = Path.home() / ".cache"
    return base_path / "codesentry" / "cache" / key


def project_cache_dir(root: Path) -> Path:
    """项目内缓存目录（可选启用）。"""
    return root / DEFAULT_CACHE_DIR


def default_index_dir(root: Path) -> Path:
    """索引落盘目录（用户目录，不污染被审查项目）。"""
    key = hashlib.sha1(
        str(root.resolve()).encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    base_path = Path(base) if base else Path.home() / ".cache"
    return base_path / "codesentry" / "index" / key


def hash_file(path: Path) -> tuple[str, float]:
    """算文件内容哈希与 mtime。

    Returns:
        (content_hash, mtime)
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        mtime = path.stat().st_mtime
    except OSError:
        return "", 0.0
    return hash_content(text), mtime
