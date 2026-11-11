"""生成仅限本地的人工标注草稿，不预填答案，不批准金标，不读取源码。

只核验本地冻结清单的摘要和当前工作空间权限身份。源码未重新哈希，
故本工具永远不产生正式评分或“人工已批准”状态。
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from codesentry.access import AccessDenied
from evals.navigation_development import _confirmed_access, _digest

MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_FILES = 10_000
HEX = re.compile(r"[0-9a-f]{64}")
ENTRY_ROLES = ("process", "mount", "bridge", "assembly", "candidate")

INSTRUCTIONS = """# 人工导航标注草稿说明

本文件是待填写草稿，不是金标，不代表标签完整或已通过 P1。

1. 先填写 task.prompt（具体理解任务）、reading_key_definition（什么算关键文件）和 deployment_context（启动/部署方式及适用范围），再开始标注；不能看得分后改口径。
2. files 包含冻结清单中的全部允许源码，不仅是工具推荐的前十项，也包括不参与排序的源码。ranking_scope 只保留原范围，不能因标注而自动扩大。清单可能已经过时：source_snapshot_revalidated 为 false，没有重新读取/哈希源码。
3. reading_key 的 null 表示尚未判断；true 表示对已固定任务关键，false 表示人工核对后不关键。不要把文档没提到或工具没推荐当作 false。
4. entry_roles 的 null 表示未知；人工核对后 [] 表示不是所定义任务的入口。process 是进程启动/外部加载目标，mount 是界面挂载，bridge 是桥接上下文，assembly 是工厂/路由/组件装配，candidate 是仍需证据的线索。应用入口指标只合并 process/mount 文件，桥接、装配、候选分别说明；文件关键不等于入口。
5. evidence 由人填写来源文件、行号和依据；不确定行号时保留未知，不能默认第 1 行。阅读源码时使用当前工作空间的受控文件入口，不能越过排除规则或运行项目。
6. 填写 reviewer 身份、日期、方法和分歧说明。草稿不展示当前排序或将旧文档正例预填为答案；允许补充遗漏，但范围变化必须另建版本，旧记录保留。
7. 填完仍是草稿。此工具不批准/导入金标、不把自报 reviewed 或模型输出当成人工裁决。正式评分前须重新完整验证源码、配置、权限和任务范围，并完成独立人工核对。
8. 文件名、摘要、标签及证据也是项目衍生信息，仅限本地保留，不自动发送给任何模型。本草稿是本地导出文件；工作台权限变更不会自动删除该副本，操作者需按现行权限处置，不能用旧草稿恢复读取或发送授权。
"""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _relative(value):
    if (not isinstance(value, str) or not value or len(value) > 4096
            or any(char in value for char in ("\\", ":"))
            or any(ord(char) < 32 for char in value)):
        raise ValueError("Invalid frozen relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or part.endswith((".", " ")) for part in parts):
        raise ValueError("Invalid frozen relative path")
    if PurePosixPath(value).is_absolute():
        raise ValueError("Invalid frozen relative path")
    return value


def _manifest(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest exceeds draft size limit")
    expected = path.with_name(path.name + ".sha256").read_text(encoding="ascii").strip()
    digest = hashlib.sha256(raw).hexdigest()
    if not HEX.fullmatch(expected) or digest != expected:
        raise ValueError("Frozen manifest hash changed")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    if (type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or value.get("manifest_kind") != "navigation-development-allowed-run"
            or value.get("holdout") is not False or value.get("role") != "dev-regression"):
        raise ValueError("Only frozen development manifests can create drafts")
    if _digest(value.get("inputs")) != value.get("input_snapshot_sha256"):
        raise ValueError("Frozen input snapshot digest mismatch")
    rows = value["inputs"]["source_inventory"]
    if not isinstance(rows, list) or len(rows) > MAX_FILES:
        raise ValueError("Invalid frozen source inventory")
    seen = set()
    for row in rows:
        relative = _relative(row["path"])
        if relative.casefold() in seen:
            raise ValueError("Duplicate or aliased frozen source path")
        seen.add(relative.casefold())
        if (not isinstance(row.get("sha256"), str) or not HEX.fullmatch(row["sha256"])
                or type(row.get("ranking_scope")) is not bool):
            raise ValueError("Invalid frozen source identity")
    return value, digest


def _close(access):
    close = getattr(access, "close", None)
    if callable(close):
        close()


def _check_scope(root, state, identity):
    access, current = _confirmed_access(root, state)
    try:
        if current != identity:
            raise AccessDenied("Workspace policy changed; no annotation draft is valid")
        access.check_current()
    finally:
        _close(access)


def validate_draft_structure(draft):
    """Validate a draft's structure, never its human truth or approval."""
    if not isinstance(draft, dict):
        raise ValueError("Annotation draft must be an object")
    if (type(draft.get("schema_version")) is not int or draft["schema_version"] != 1
            or draft.get("kind") != "navigation-annotation-draft"
            or draft.get("status") != "draft_unknown"
            or draft.get("human_labels_approved") is not False
            or draft.get("source_snapshot_revalidated") is not False
            or draft.get("formal_acceptance", {}).get("passed") is not False):
        raise ValueError("Draft cannot claim approval, source revalidation or formal acceptance")
    rows = draft.get("files")
    if not isinstance(rows, list) or len(rows) > MAX_FILES:
        raise ValueError("Invalid annotation rows")
    seen = set()
    for row in rows:
        name = _relative(row["file"])
        if name.casefold() in seen:
            raise ValueError("Duplicate annotation file")
        seen.add(name.casefold())
        if row.get("reading_key") is not None and type(row["reading_key"]) is not bool:
            raise ValueError("reading_key must be boolean or unknown")
        roles = row.get("entry_roles")
        if roles is not None and (not isinstance(roles, list)
                                  or any(role not in ENTRY_ROLES for role in roles)
                                  or len(set(roles)) != len(roles)):
            raise ValueError("Invalid entry roles")
        if not isinstance(row.get("evidence"), list):
            raise ValueError("Evidence must remain a list of human notes")
    return {"valid_draft_structure": True, "files": len(rows), "formal_passed": False}


def create_annotation_draft(manifest_path: Path, workspace_data_dir: Path, *, output: Path):
    """Read trusted metadata and permitted rule controls, never target source."""
    manifest_path = Path(manifest_path).resolve(strict=True)
    value, digest = _manifest(manifest_path)
    root = Path(value["root"]).resolve(strict=True)
    if manifest_path.is_relative_to(root):
        raise ValueError("Trusted manifest must be outside target source")
    output = Path(output).absolute()
    if output.suffix.lower() != ".json":
        raise ValueError("Annotation output must be JSON")
    if output.is_relative_to(root):
        raise ValueError("Annotation export must stay outside target source")
    for ancestor in (output, *output.parents):
        if ancestor.is_symlink() or getattr(ancestor, "is_junction", lambda: False)():
            raise ValueError("Annotation export cannot follow links or junctions")
    # Resolving the output is only for the trusted export destination, not any
    # source inventory path. No source file gets stat/read/hash/parse calls.
    output = output.resolve()
    notes = output.with_name(output.stem + ".instructions.md")
    if output.is_relative_to(root) or notes.is_relative_to(root):
        raise ValueError("Annotation export must stay outside target source")
    if output.exists() or notes.exists():
        raise FileExistsError("Annotation export already exists")
    _check_scope(root, workspace_data_dir, value["workspace"])
    draft = {
        "schema_version": 1, "kind": "navigation-annotation-draft", "status": "draft_unknown",
        "human_labels_approved": False, "source_snapshot_revalidated": False,
        "formal_acceptance": {"passed": False, "reason": "仅为待填写草稿，缺少独立人工标签和正式源码重验"},
        "source_binding": {"snapshot_kind": "frozen_manifest_snapshot", "manifest_path": str(manifest_path),
                           "manifest_sha256": digest, "input_snapshot_sha256": value["input_snapshot_sha256"],
                           "project_id": value["project_id"], "workspace": value["workspace"],
                           "algorithm_scope": value["algorithm_scope"]},
        "task": {"id": None, "prompt": None, "reading_key_definition": None,
                 "deployment_context": None, "annotation_unit": "file",
                 "application_entry_metric_roles": ["process", "mount"],
                 "entry_ontology": {"process": "进程启动/外部加载目标", "mount": "界面挂载",
                                    "bridge": "桥接上下文", "assembly": "应用装配/注册",
                                    "candidate": "待证实线索"}},
        "reviewer": {"id": None, "reviewed_at": None, "method": None, "disagreements": None},
        "privacy": {"local_only": True, "model_calls": False, "source_content_included": False,
                    "operator_managed_export": True, "auto_removed_on_workspace_revoke": False},
        "files": [{"file": row["path"], "source_sha256": row["sha256"],
                   "ranking_scope": row["ranking_scope"], "reading_key": None,
                   "entry_roles": None, "evidence": [], "note": None}
                  for row in sorted(value["inputs"]["source_inventory"], key=lambda row: row["path"])],
        "instructions_zh": INSTRUCTIONS,
    }
    summary = validate_draft_structure(draft)
    created = []
    try:
        _check_scope(root, workspace_data_dir, value["workspace"])
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.parent.resolve() != output.parent or output.is_relative_to(root):
            raise ValueError("Export destination changed")
        for destination, content in ((output, json.dumps(draft, ensure_ascii=False, indent=2) + "\n"),
                                     (notes, INSTRUCTIONS)):
            with destination.open("x", encoding="utf-8") as stream:
                created.append(destination)
                stream.write(content)
        _, after_digest = _manifest(manifest_path)
        if after_digest != digest:
            raise ValueError("Manifest changed during annotation export")
        _check_scope(root, workspace_data_dir, value["workspace"])
    except BaseException:
        for destination in created:
            destination.unlink(missing_ok=True)
        raise
    return summary | {"status": "draft_unknown", "source_snapshot_revalidated": False,
                      "human_labels_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--workspace-data-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = create_annotation_draft(args.manifest, args.workspace_data_dir, output=args.output)
    except Exception as error:
        print(json.dumps({"status": "draft_unavailable", "error_type": type(error).__name__, "formal_passed": False}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
