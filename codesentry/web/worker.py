"""Fixed analyzer worker. Reads source as data, never runs target entry points."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import weakref

from codesentry.core.policy import Policy
from codesentry.access import AccessPolicy
from codesentry.access.registry import RegistryGuard
from codesentry.index.builder import build_index
from codesentry.output.reading_order import reading_order
from codesentry.output.report import to_dict
from codesentry.web.provenance import analysis_provenance
from codesentry.workspaces.store import IMPLEMENTATION_ERROR


class RegisteredAccessPolicy(AccessPolicy):
    """A frozen task may never override a revocation in the trusted registry."""

    def __init__(self, root: Path, data_dir: Path, workspace_id: str, snapshot: dict):
        self._registry_guard = RegistryGuard(root, data_dir, workspace_id=workspace_id, snapshot=snapshot)
        self._resource_finalizer = weakref.finalize(self, self._registry_guard.close)
        self.workspace_id = self._registry_guard.workspace_id
        self.snapshot = self._registry_guard.snapshot
        try:
            super().__init__(root, self._registry_guard.settings, confirmed=True, read_guard=self._registry_guard)
        except BaseException:
            self.close()
            raise

    def _assert_current(self) -> None:
        self._registry_guard()

    def close(self):
        self._resource_finalizer()

    def __enter__(self):
        self.check_current()
        return self

    def __exit__(self, *_):
        self.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("workspace_id")
    parser.add_argument("analysis_id")
    parser.add_argument("config")
    parser.add_argument("access_policy")
    parser.add_argument("data_dir", type=Path)
    args = parser.parse_args(argv)
    access = None
    try:
        config = json.loads(args.config)
        kind = config.get("kind", "navigation")
        if kind not in {"navigation", "review_preview", "change_scope", "gate_check", "defect_preview"}:
            raise ValueError("不支持的分析任务类型")
        snapshot = json.loads(args.access_policy)
        provenance = analysis_provenance()
        if snapshot.get("analysis_provenance") != provenance:
            raise ValueError(IMPLEMENTATION_ERROR)
        if kind == "gate_check":
            from codesentry.review.gate import gate_manifest
            if config.get("gate_policy_sha256") != gate_manifest()["policy_sha256"]:
                raise ValueError("可信必检策略已变化，旧门禁任务不得读取项目")
        if kind == "defect_preview":
            from codesentry.review.defects import defect_preview_policy
            policy_hash = hashlib.sha256(json.dumps(defect_preview_policy(), sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            if config.get("defect_policy_sha256") != policy_hash:
                raise ValueError("缺陷候选规则已变化，旧任务不得读取项目")
        access = RegisteredAccessPolicy(args.root, args.data_dir, args.workspace_id, snapshot)
        if access.fingerprint != snapshot["fingerprint"]:
            raise ValueError("文件访问规则已变化，旧分析不得开始")
        if kind == "review_preview":
            from codesentry.review.scan import scan_preview
            threshold = config.get("max_function_lines", 80)
            if type(threshold) is not int or not 1 <= threshold <= 10_000:
                raise ValueError("审查阈值不在支持范围内")
            print("读取获准Python源码并生成只报告审查预览（未运行目标代码）", flush=True)
            result = scan_preview(access, max_function_lines=threshold)
            result["analysis_mode"] = "static"
            complete = result["review_status"] in {"report_only", "not_applicable"}
        elif kind == "defect_preview":
            from codesentry.review.defects import scan_defect_preview
            print("检查获准Python源码中的缺陷候选；未确认意图，不运行目标代码", flush=True)
            result = scan_defect_preview(access)
            result["analysis_mode"] = "static"
            complete = result["review_status"] in {"report_only", "not_applicable"}
        elif kind == "change_scope":
            from codesentry.review.changes import analyze_changes
            print("比较获准文件的提交与本地快照（未运行目标代码）", flush=True)
            result = analyze_changes(access, base_ref=config["base_ref"], comparison=config["comparison"],
                                     target_ref=config.get("target_ref"), git_executable=os.environ.get("CODESENTRY_GIT"))
            result["analysis_mode"] = "static"
            complete = result["change_status"] == "report_only"
        elif kind == "gate_check":
            from codesentry.review.gate import evaluate_gate
            print("按内置可信必检清单检查；报告生成不代表门禁通过", flush=True)
            result = evaluate_gate(access)
            result["analysis_mode"] = "static"
            # This private worker protocol reports task completion. Only the
            # result's gate_status/exit_code is a gate decision or CI exit code.
            complete = True
        else:
            print("读取环境声明并解析源码（未运行目标代码）", flush=True)
            index = build_index(args.root, Policy(), use_cache=False, access=access)
            result = to_dict(index)
            result.update({
                "reading_order": [
                    {"file": file, "label": label, "depth": depth}
                    for file, label, depth in reading_order(index, max_depth=config["max_depth"], max_items=config["max_items"])
                ],
                "file_details": [meta.model_dump(mode="json") for meta in index.files],
                "symbol_details": [symbol.model_dump(mode="json", exclude={"docstring"}) for symbol in index.symbols],
                "review_status": "not_implemented",
            })
            complete = index.is_complete
        access.refresh()
        if access.fingerprint != snapshot["fingerprint"]:
            raise ValueError("文件访问规则已变化，旧分析不得保存")
        result.update({
            "workspace_id": args.workspace_id,
            "analysis_id": args.analysis_id,
            "analysis_provenance": provenance,
            "policy_version": snapshot["version"],
            "policy_fingerprint": snapshot["fingerprint"],
            "config": config,
            "kind": kind,
        })
        rendered = json.dumps(result, ensure_ascii=False)
        if len(rendered.encode("utf-8")) > 32 * 1024 * 1024:
            raise ValueError("分析结果超过32MiB上限")
        temporary = args.destination.with_suffix(".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, args.destination)
        if kind == "review_preview":
            print(f"策略债务观察{result['summary']['policy_debt_findings']}项；只报告，门禁未评估", flush=True)
        elif kind == "defect_preview":
            print(f"缺陷候选{result['summary']['candidate_findings']}项；确认行为缺陷0项；门禁未评估", flush=True)
        elif kind == "change_scope":
            print(f"变更文件{result['summary']['changed_files']}项；影响面仅供核对，门禁未评估", flush=True)
        elif kind == "gate_check":
            print(f"门禁判定：{result['gate_status']}；CI退出码{result['exit_code']}；未运行目标代码", flush=True)
        else:
            print(f"已解析 {sum(item.is_parsed for item in index.files)}/{len(index.files)} 个文件；导航报告已生成，审查需另行启动", flush=True)
        return 0 if complete else 1
    except Exception as error:
        print(f"分析失败: {type(error).__name__}: {str(error)[:1000]}", file=sys.stderr, flush=True)
        return 2
    finally:
        if access is not None:
            access.close()


if __name__ == "__main__":
    raise SystemExit(main())
