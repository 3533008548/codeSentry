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
import math
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from codesentry.index.builder import IndexResult
from codesentry.index.cache import default_index_dir
from codesentry.access import AccessPolicy
from codesentry.access.policy import is_link

INDEX_VERSION = 4  # Include input/environment identity and completeness.
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
    environment_changed: bool = False
    input_changed: bool = False
    incomplete: bool = False

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
        if self.environment_changed:
            parts.append('环境或配置已变')
        if self.input_changed and not self.environment_changed:
            parts.append('策略或输入身份已变')
        if self.incomplete:
            parts.append('解析结果不完整')
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

    `save_to_project=True` 时写到项目根（`<root>/index.<权限摘要>.json`），
    适合希望把索引纳入版本控制、便于 review 与 diff 的场景。
    """

    def __init__(
        self,
        root: Path,
        filename: str = DEFAULT_INDEX_FILE,
        save_to_project: bool = False,
        access: AccessPolicy | None = None,
    ):
        self.root = root
        self.filename = filename
        if not isinstance(filename, str) or Path(filename).name != filename or not filename.endswith('.json'):
            raise ValueError('索引文件名必须是不含目录的JSON文件名')
        self.save_to_project = save_to_project
        self.access = access or AccessPolicy(root)
        if self.access.root != Path(root).resolve():
            raise ValueError('索引访问策略不属于当前项目')
        self._scope_id = self.access.fingerprint

    def _project_names(self) -> tuple[str, ...]:
        # Honour both the user's logical destination and the real namespaced
        # artifact, including a ban on either sidecar name.
        return self.filename, self.filename + '.access.json', self.index_file.name, self.scope_file.name

    def _project_allowed(self) -> bool:
        logical = (self.filename, self.filename + '.access.json')
        actual = (self.index_file.name, self.scope_file.name)
        return (all(self.access.decision(name)['mode'] != 'exclude' for name in logical)
                and all(self.access.managed_artifact_decision(name)['mode'] != 'exclude' for name in actual))

    @property
    def scope_file(self) -> Path:
        return self.index_file.with_name(self.index_file.name + '.access.json')

    def _scope_matches(self) -> bool:
        self.access.check_current()
        self.access.refresh_if_changed()
        if self.access.fingerprint != self._scope_id:
            return False
        try:
            if self.save_to_project:
                if not self._project_allowed():
                    return False
            if is_link(self.scope_file) or is_link(self.index_file):
                return False
            text = self.access.read_managed_text(self.scope_file.name, limit=4096) if self.save_to_project else self.scope_file.read_text(encoding='utf-8')
            scope = json.loads(text)
            return isinstance(scope, dict) and scope.get('fingerprint') == self.access.fingerprint
        except (OSError, ValueError, UnicodeError):
            return False

    @property
    def index_file(self) -> Path:
        if self.save_to_project:
            name = Path(self.filename)
            return self.root / f'{name.stem}.{self._scope_id}{name.suffix}'
        return default_index_dir(self.root) / 'scopes' / self._scope_id / self.filename

    # ---------- 落盘 ----------

    def save(self, result: IndexResult) -> bool:
        """保存索引。

        落盘内容是**摘要**而非全量符号表——全量符号表可能有几 MB，
        落盘后难以 review。摘要足够回答「索引是否过期」。
        """
        self.access.check_current()
        self.access.refresh_if_changed()
        if self.access.fingerprint != self._scope_id:
            return False
        if (not self.access.confirmed or any(self.access.decision(item.path)['mode'] == 'exclude' for item in result.files)
                or result.access_fingerprint and result.access_fingerprint != self.access.fingerprint):
            return False
        if any(is_link(parent) for parent in (self.index_file.parent.absolute(), *self.index_file.parent.absolute().parents)):
            return False
        if is_link(self.index_file) or is_link(self.scope_file):
            return False
        if self.save_to_project and not self._project_allowed():
            return False
        payload = {
            "version": INDEX_VERSION,
            "root": result.root,
            "environment_fingerprint": result.environment_fingerprint,
            "input_fingerprint": result.input_fingerprint,
            'access_fingerprint': self.access.fingerprint,
            'source_permissions': result.source_permissions,
            "is_complete": result.is_complete,
            "parse_failures": result.parse_failures,
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
        temporary = None
        wrote = False
        try:
            destination = self.index_file
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                             dir=destination.parent, suffix='.codesentry-index-tmp',
                                             delete=False) as output:
                temporary = Path(output.name)
                json.dump(payload, output, ensure_ascii=False, indent=1)
                output.flush()
            os.replace(temporary, destination)
            wrote = True
            self.access.check_current()
            self.access.refresh_if_changed()
            if self.access.fingerprint != self._scope_id:
                raise OSError('索引写入期间文件范围已变化')
            self.scope_file.write_text(json.dumps({'fingerprint': self.access.fingerprint}), encoding='utf-8')
            self.access.check_current()
            self.access.refresh_if_changed()
            if self.access.fingerprint != self._scope_id:
                raise OSError('索引写入期间文件范围已变化')
            return True
        except OSError:
            if wrote:
                self.index_file.unlink(missing_ok=True)
                self.scope_file.unlink(missing_ok=True)
            return False
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink(missing_ok=True)

    def load(self) -> dict | None:
        """读取索引。"""
        self.access.check_current()
        self.access.refresh_if_changed()
        if self.access.fingerprint != self._scope_id:
            return None
        if not self.save_to_project:
            base = default_index_dir(self.root)
            if any(is_link(parent) for parent in (base.absolute(), *base.absolute().parents)):
                return None
            for name in ('index.json', 'index.json.access.json'):
                legacy = base / name
                if is_link(legacy):
                    return None
                legacy.unlink(missing_ok=True)
        if not self.index_file.exists():
            return None
        if any(is_link(parent) for parent in (self.index_file.parent.absolute(), *self.index_file.parent.absolute().parents)):
            return None
        if not self.access.confirmed or not self._scope_matches():
            # Scope metadata is deliberately separate: never read old content
            # merely to decide that its permissions have been revoked.
            if not self.save_to_project:
                self.index_file.unlink(missing_ok=True)
                self.scope_file.unlink(missing_ok=True)
            return None
        if self.save_to_project and self.access.decision(self.filename)['mode'] == 'exclude':
            return None
        try:
            text = self.access.read_managed_text(self.index_file.name) if self.save_to_project else self.index_file.read_text(encoding="utf-8")
            data = json.loads(text)
            self.access.check_current()
            self.access.refresh_if_changed()
            if self.access.fingerprint != self._scope_id:
                return None
        except (json.JSONDecodeError, OSError, UnicodeError):
            return None
        if not isinstance(data, dict) or data.get("version") != INDEX_VERSION:
            return None
        files = data.get('files')
        if not isinstance(files, dict) or any(
            not isinstance(name, str) or not isinstance(value, dict)
            or not isinstance(value.get('content_hash'), str)
            for name, value in files.items()
        ):
            return None
        epoch = data.get('built_at_epoch')
        if not isinstance(epoch, (int, float)) or not math.isfinite(epoch) or epoch < 0:
            return None
        if not isinstance(data.get('is_complete'), bool):
            return None
        for key in ['input_fingerprint', 'environment_fingerprint', 'built_at']:
            if not isinstance(data.get(key), str):
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

        info.environment_changed = data.get('environment_fingerprint', '') != result.environment_fingerprint
        info.input_changed = data.get('input_fingerprint', '') != result.input_fingerprint
        info.incomplete = not result.is_complete or not data.get('is_complete', False)
        info.stale = bool(info.added or info.modified or info.removed or
                          info.environment_changed or info.input_changed or info.incomplete)
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
