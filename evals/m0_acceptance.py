"""P1导航验收：冻结输入、P@10/Recall、独立入口标签与实际输出时延。

文档标签只表示代理命中；无独立入口金标或存在P0未决项，不能宣称P1通过。
例：python evals/m0_acceptance.py <project> --contract <json> --project-id <id> --no-cache
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import re
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codesentry.core.policy import Policy
from codesentry.access import AccessDenied, AccessPolicy
from codesentry.cli.access import resolve_access
from codesentry.core.symbol import Language
from codesentry.index.builder import IndexResult, build_index
from codesentry.index.discovery import classify, discover
from codesentry.output.reading_order import reading_order
from codesentry.output.report import render_l1, render_l2
from evals.metrics import application_entry_predictions, directory_coverage, entrypoint_metrics, ranking_metrics, resolution_summary

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
MAX_EVALUATION_FILE_BYTES = 16 * 1024 * 1024
# These are the P0 collector's exact declaration/document discovery rules.
DECLARATION_NAMES = {
    "pyproject.toml", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "tsconfig.json", ".python-version", ".nvmrc", "policy.yaml", "Dockerfile",
    "docker-compose.yml", "docker-compose.yaml",
}
DOCUMENT_NAMES = {"README.md", "项目接手指南.md", "ARCHITECTURE.md", "架构.md", "CONTRIBUTING.md", "GETTING_STARTED.md"}


@dataclass
class FrozenInputs:
    contract: dict
    project: dict
    policy: Policy
    ground_truth: Path
    path: Path
    sha256: str


def _read_bytes(path: Path, root: Path, access: AccessPolicy) -> bytes:
    """Target data always uses access; explicit external control inputs do not grant target access."""
    path = path.absolute()
    access.check_current()
    if path.is_relative_to(root):
        data = access.read_bytes(path.relative_to(root).as_posix(), limit=MAX_EVALUATION_FILE_BYTES)
    elif path.resolve().is_relative_to(root):
        data = access.read_bytes(path.resolve().relative_to(root).as_posix(), limit=MAX_EVALUATION_FILE_BYTES)
    else:
        with path.open("rb") as stream:
            data = stream.read(MAX_EVALUATION_FILE_BYTES + 1)
        if len(data) > MAX_EVALUATION_FILE_BYTES:
            raise ValueError("评测控制文件超过16MiB上限")
    access.check_current()
    return data


def _check_access(access: AccessPolicy, expected_fingerprint: str) -> None:
    access.refresh_if_changed()
    access.check_current()
    if access.fingerprint != expected_fingerprint:
        raise AccessDenied("ACCESS_SCOPE_CONFLICT：评测期间文件访问范围已变化")


def load_ground_truth(path: Path, *, root: Path, access: AccessPolicy) -> list[str]:
    raw = _read_bytes(path, root, access)
    data = json.loads(raw.decode("utf-8"))
    values = data if isinstance(data, list) else data.get("files", [])
    if not isinstance(values, list) or not all(isinstance(f, str) for f in values):
        raise ValueError("ground truth必须是文件名列表，或含files列表的对象")
    return list(dict.fromkeys(f.replace("\\", "/").removeprefix("./") for f in values))


def match_ground_truth(truth, real_files, ranked_files=None):
    """精确/唯一后缀匹配，歧义不因已匹配其他项而消失。"""
    pool = real_files if ranked_files is None else ranked_files
    matched, unmatched, seen = [], [], set()
    for raw in truth:
        item = raw.replace("\\", "/").removeprefix("./")
        if item in pool:
            candidates = [item]
        elif "/" in item:
            candidates = sorted(f for f in pool if f.endswith("/" + item))
        else:
            candidates = sorted(f for f in pool if f.rsplit("/", 1)[-1] == item)
        if len(candidates) == 1:
            if candidates[0] not in seen:
                matched.append(candidates[0])
                seen.add(candidates[0])
        else:
            unmatched.append(item)
    return matched, list(dict.fromkeys(unmatched))


def _safe_path(root: Path, value: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError(f"非法相对路径: {value!r}")
    path = root / value
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"路径越界: {value}")
    return path


def _sha256(path: Path, root: Path, access: AccessPolicy) -> str:
    return hashlib.sha256(_read_bytes(path, root, access)).hexdigest()


def load_contract(path: Path, project_id: str | None, root: Path, gt: Path | None,
                  *, access: AccessPolicy | None = None) -> FrozenInputs:
    access = access or AccessPolicy(root)
    raw = _read_bytes(path, root, access)
    contract = json.loads(raw.decode("utf-8"))
    if not isinstance(contract, dict) or contract.get("contract_version") != 1:
        raise ValueError("只支持navigation合约版本1")
    projects = contract.get("projects")
    if not isinstance(projects, list):
        raise ValueError("合约缺少projects列表")
    candidates = [p for p in projects if isinstance(p, dict) and (
        p.get("project_id") == project_id if project_id else Path(p.get("root", "")).resolve() == root
    )]
    if len(candidates) != 1:
        raise ValueError("必须通过--project-id或唯一根路径选择冻结项目")
    project = candidates[0]
    if Path(project.get("root", "")).resolve() != root:
        raise ValueError("项目根路径与P0冻结项目不一致")
    if project.get("holdout") is not False or project.get("role") != "dev-regression":
        raise ValueError("本工具只读取开发回归输入，不读取封存/holdout项目")
    scope = contract.get("frozen_scope", {})
    required = ("extensions", "not_parsed_directory_names", "not_ranked_directory_names")
    if any(not isinstance(scope.get(key), list) or not all(isinstance(x, str) for x in scope[key]) for key in required):
        raise ValueError("冻结范围字段无效")
    policy = Policy()
    policy.index.exclude.extensions = list(scope["extensions"])
    policy.index.exclude.not_parsed = list(scope["not_parsed_directory_names"])
    policy.index.exclude.not_ranked = list(scope["not_ranked_directory_names"])
    inventory = project.get("source_inventory")
    if not isinstance(inventory, list) or not inventory:
        raise ValueError("冻结源码清单为空")
    seen = set()
    for section in (inventory, project.get("environment_declarations", []), project.get("documents", [])):
        if not isinstance(section, list):
            raise ValueError("冻结清单必须是列表")
        for item in section:
            if not isinstance(item, dict) or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
                raise ValueError("清单缺少SHA256")
            _safe_path(root, item.get("path"))
    for item in inventory:
        if item["path"] in seen:
            raise ValueError("冻结源码清单存在重复路径")
        seen.add(item["path"])
    for key in ("ranking_eligible_canonical_labels", "not_ranked_canonical_labels", "unmatched_labels", "ambiguous_labels"):
        values = project.get(key, [])
        if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
            raise ValueError(f"冻结标签列表无效: {key}")
    blockers = contract.get("formal_acceptance_blockers", [])
    if not isinstance(blockers, list) or not all(isinstance(x, str) for x in blockers):
        raise ValueError("正式验收未决项必须是字符串列表")
    labels = project.get("ranking_eligible_canonical_labels", [])
    if not isinstance(labels, list) or not all(isinstance(x, str) and x in seen for x in labels):
        raise ValueError("冻结标签不在源码清单中")
    for label in labels:
        row = next(item for item in inventory if item["path"] == label)
        if row.get("ranking_scope") is not True or any(classify(label, policy.index.exclude)[1:]):
            raise ValueError(f"冻结排序标签不符合声明范围: {label}")
    legacy = project.get("legacy_gt", {})
    legacy_path = Path(legacy.get("path", ""))
    ground_truth = gt.absolute() if gt else (legacy_path if legacy_path.is_absolute() else REPOSITORY_ROOT / legacy_path).absolute()
    if not legacy.get("sha256"):
        raise ValueError("合约缺少原始GT哈希")
    task = contract.get("task", {})
    if task.get("p_at_10", {}).get("threshold") != 0.8:
        raise ValueError("冻结P@10目标必须是用户确认的0.8")
    entry_gold = project.get("entry_gold", task.get("entry_gold", {}))
    if not isinstance(entry_gold, dict):
        raise ValueError("入口标签声明必须是对象")
    latency = task.get("latency_seconds", {})
    if latency.get("l1_less_than") != 30 or latency.get("l2_less_than") != 180:
        raise ValueError("冻结时延必须采用L1<30秒、L2<180秒")
    return FrozenInputs(contract, project, policy, ground_truth, path, hashlib.sha256(raw).hexdigest())


def _current_declarations(root: Path) -> set[str]:
    found = set()
    for unit in (root, root / "frontend"):
        if not unit.is_dir() or not unit.resolve().is_relative_to(root):
            continue
        candidates = [unit / name for name in DECLARATION_NAMES]
        candidates += list(unit.glob("requirements*.txt")) + list(unit.glob("tsconfig*.json"))
        found.update(path.relative_to(root).as_posix() for path in candidates if path.is_file() and not path.is_symlink())
    return found


def contract_input_drift(frozen: FrozenInputs, root: Path, *, access: AccessPolicy | None = None) -> list[dict]:
    """只读复核所有冻结输入及新增文件；不刷新合约或修改标签。"""
    project = frozen.project
    access = access or AccessPolicy(root)
    access.refresh_if_changed()
    issues = []
    sections = (("source", project["source_inventory"]),
                ("configuration", project.get("environment_declarations", [])),
                ("document", project.get("documents", [])))
    # Resolve the declared scope before opening any source to hash it. An old
    # freeze is an identity record, never permission to read a denied file.
    for kind, manifest in sections:
        for item in manifest:
            decision = access.decision(item["path"])
            if decision["mode"] == "exclude":
                issues.append({"kind": kind, "path": item["path"], "change": "access_scope_conflict",
                               "reason": decision["reason"]})
    discovery_issues = []
    current_sources = {rel for _, rel, _ in discover(root, frozen.policy.index.exclude,
                                                   issues=discovery_issues, access=access)}
    current_configs = _current_declarations(root)
    current_docs = {name for name in DOCUMENT_NAMES if (root / name).is_file() and not (root / name).is_symlink()}
    for item in discovery_issues:
        if item.get("status", "").startswith("access_"):
            issues.append({"kind": "source", "path": item.get("file", "."),
                           "change": "access_scope_conflict", "reason": item.get("message", "范围受限")})
    for kind, candidates in (("configuration", current_configs), ("document", current_docs)):
        for relative in sorted(candidates):
            decision = access.decision(relative)
            if decision["mode"] == "exclude":
                issues.append({"kind": kind, "path": relative, "change": "access_scope_conflict", "reason": decision["reason"]})
    for item in access.to_dict().get("issues", []):
        issues.append({"kind": "access_policy", "path": item.get("file", "."),
                       "change": "access_scope_conflict", "reason": item.get("message", "权限规则受限")})
    if issues:
        return issues
    for kind, manifest in sections:
        for item in manifest:
            try:
                path = _safe_path(root, item["path"])
                actual = _sha256(path, root, access)
            except AccessDenied as error:
                issues.append({"kind": kind, "path": item["path"], "change": "access_scope_conflict", "reason": str(error)})
                continue
            except (OSError, ValueError) as error:
                issues.append({"kind": kind, "path": item["path"], "change": "unreadable_or_missing", "reason": str(error)})
                continue
            if actual != item["sha256"]:
                issues.append({"kind": kind, "path": item["path"], "change": "hash_changed", "expected": item["sha256"], "actual": actual})
    for kind, current, manifest in (
        ("source", current_sources, project["source_inventory"]),
        ("configuration", current_configs, project.get("environment_declarations", [])),
        ("document", current_docs, project.get("documents", [])),
    ):
        recorded = {item["path"] for item in manifest}
        for relative in sorted(current - recorded):
            issues.append({"kind": kind, "path": relative, "change": "added_since_freeze"})
        for relative in sorted(recorded - current):
            issues.append({"kind": kind, "path": relative, "change": "removed_or_out_of_scope"})
    try:
        actual = _sha256(frozen.ground_truth, root, access)
        if actual != project["legacy_gt"]["sha256"]:
            issues.append({"kind": "ground_truth", "path": str(frozen.ground_truth), "change": "hash_changed"})
    except AccessDenied as error:
        issues.append({"kind": "ground_truth", "path": str(frozen.ground_truth), "change": "access_scope_conflict", "reason": str(error)})
    except OSError as error:
        issues.append({"kind": "ground_truth", "path": str(frozen.ground_truth), "change": "unreadable_or_missing", "reason": str(error)})
    try:
        if _sha256(frozen.path, root, access) != frozen.sha256:
            issues.append({"kind": "contract", "path": str(frozen.path), "change": "changed_during_evaluation"})
    except AccessDenied as error:
        issues.append({"kind": "contract", "path": str(frozen.path), "change": "access_scope_conflict", "reason": str(error)})
    except OSError as error:
        issues.append({"kind": "contract", "path": str(frozen.path), "change": "unreadable_or_missing", "reason": str(error)})
    return issues


def _percent(value):
    return "N/A" if value is None else f"{value * 100:.1f}%"


def _report_ranking(title, files, truth):
    print(f"\n{title}（文档标注口径）")
    for k in (5, 10, 15, 20, 30, 50):
        score = ranking_metrics(files, truth, k)
        print(f"    P@{k}={score.hits}/{score.recommended} ({_percent(score.precision)})；Recall@{k}={score.hits}/{score.truth_count} ({_percent(score.recall)})")
    print(f"    前10项未命中文档标注（未知，未人工判错）: {list(ranking_metrics(files, truth, 10).unlabelled)}")


def output_location_errors(root: Path, result: IndexResult, order_files: list[str],
                           *, access: AccessPolicy | None = None) -> list[str]:
    """独立核验已输出文件和行号；不把位置正确解释为语义正确。"""
    root = root.resolve()
    access = access or AccessPolicy(root)
    errors = []
    indexed = {f.path for f in result.files}
    claims = {f for f, _ in result.top_files(60)} | set(order_files) | {e.file for e in result.entrypoints}
    qmap = {s.qname: s for s in result.symbols}
    if len(qmap) != len(result.symbols):
        errors.append("符号身份冲突: qname不唯一")
    symbol_claims = set(sorted(result.symbol_pr, key=result.symbol_pr.get, reverse=True)[:30])
    longest = max((s for s in result.symbols if s.is_production), key=lambda s: s.length, default=None)
    if longest:
        symbol_claims.add(longest.qname)
    for qname in sorted(symbol_claims):
        symbol = qmap.get(qname)
        if symbol is None:
            errors.append(f"符号不在索引中: {qname}")
            continue
        claims.add(symbol.file)
        try:
            _safe_path(root, symbol.file)
            count = len(access.read_text(symbol.file).splitlines())
        except (OSError, ValueError):
            errors.append(f"符号文件不可读或越界: {symbol.file}")
            continue
        if symbol.line < 1 or symbol.line > count or not symbol.line <= (symbol.end_line or symbol.line) <= count:
            errors.append(f"符号行号越界: {qname}:{symbol.line}-{symbol.end_line}")
    for relative in sorted(claims):
        if relative not in indexed:
            errors.append(f"输出文件不在索引中: {relative}")
        try:
            _safe_path(root, relative)
            file = access.resolve(relative)
            if not file.is_file():
                raise OSError("missing file")
        except (OSError, ValueError):
            errors.append(f"输出位置不可访问或越界: {relative}")
    for entry in result.entrypoints:
        line = getattr(entry, "line", None)
        if line is not None:
            try:
                _safe_path(root, entry.file)
                count = len(access.read_text(entry.file).splitlines())
                if not 1 <= line <= count:
                    errors.append(f"入口行号越界: {entry.file}:{line}")
            except (OSError, ValueError):
                errors.append(f"入口文件不可读: {entry.file}")
        for evidence in getattr(entry, "evidence", []):
            if not isinstance(evidence, dict):
                errors.append(f"入口证据格式无效: {entry.file}")
                continue
            relative = evidence.get("file")
            number = evidence.get("line")
            try:
                _safe_path(root, relative)
            except (OSError, ValueError):
                errors.append(f"入口证据文件不可读或越界: {relative}")
                continue
            startup_inputs = getattr(result, "startup_inputs", {})
            if relative not in indexed and relative not in startup_inputs:
                errors.append(f"入口证据文件未冻结在源码或启动输入中: {relative}")
                continue
            try:
                access.resolve(relative)
                expected = startup_inputs.get(relative)
                if relative in startup_inputs and not (isinstance(expected, str) and re.fullmatch(r"[0-9a-fA-F]{64}", expected)):
                    errors.append(f"入口证据启动输入未成功冻结: {relative}")
                    continue
                if number is not None and type(number) is not int:
                    errors.append(f"入口证据行号无效: {relative}:{number}")
                    continue
                # Unknown lines remain unknown, including for an empty file.
                # Config declarations are outside the source index, but their
                # exact bytes must belong to the builder's startup snapshot.
                if expected is not None:
                    raw = access.read_bytes(relative)
                    if hashlib.sha256(raw).hexdigest() != expected.lower():
                        errors.append(f"入口证据启动输入摘要不一致: {relative}")
                    count = len(raw.decode("utf-8-sig").splitlines()) if number is not None else None
                elif number is not None:
                    count = len(access.read_text(relative).splitlines())
                else:
                    access.read_bytes(relative)
                    count = None
                if number is not None and not 1 <= number <= count:
                    errors.append(f"入口证据行号越界: {relative}:{number}")
            except (OSError, ValueError, UnicodeError):
                errors.append(f"入口证据文件不可读或越界: {relative}")
    return errors


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_root", type=Path)
    parser.add_argument("ground_truth", type=Path, nargs="?")
    parser.add_argument("--contract", type=Path, help="P0冻结navigation_v1.json")
    parser.add_argument("--project-id", help="冻结项目ID；未指定时按根路径唯一匹配")
    parser.add_argument("--min-p10", type=float, default=0.8)
    parser.add_argument("--l1-max-seconds", "--max-seconds", type=float, dest="l1_max_seconds", default=30.0, help="L1实际输出上限，旧max-seconds为此参数别名")
    parser.add_argument("--l2-max-seconds", type=float, default=180.0)
    parser.add_argument("--no-cache", action="store_true", help="禁用解析缓存读取和写入")
    parser.add_argument("--workspace-data-dir", help="与网页一致的可信工作空间状态目录")
    parser.add_argument("--confirm-access", action="store_true", help="确认未注册项目按默认忽略规则仅在本地评测")
    parser.add_argument("--access-policy", help="目标目录之外的可信访问策略JSON")
    parser.add_argument("--exclude", action="append", default=[], help="额外完全排除路径/模式，可重复")
    parser.add_argument("--local-only", action="append", default=[], help="仅限本地路径/模式，可重复")
    args = parser.parse_args(argv)
    if not math.isfinite(args.min_p10) or not 0 <= args.min_p10 <= 1:
        parser.error("--min-p10必须在0到1之间")
    if any(not math.isfinite(value) or value <= 0 for value in (args.l1_max_seconds, args.l2_max_seconds)):
        parser.error("耗时上限必须大于0")
    if args.project_id and not args.contract:
        parser.error("--project-id必须与--contract一起使用")
    if args.ground_truth is None and args.contract is None:
        parser.error("必须提供ground_truth或--contract")
    return args


def main(argv=None):
    args = _arguments(argv)
    started = time.perf_counter()
    root = args.project_root.resolve()
    if not root.is_dir():
        print(f"项目目录不存在: {root}")
        return 2
    frozen = None
    try:
        access = resolve_access(args, root)
        initial_access_fingerprint = access.fingerprint
        if args.contract:
            frozen = load_contract(args.contract.absolute(), args.project_id, root, args.ground_truth, access=access)
            drift = contract_input_drift(frozen, root, access=access)
            if drift:
                if any(item.get("change") == "access_scope_conflict" for item in drift):
                    print("ACCESS_SCOPE_CONFLICT：当前权限与P0冻结范围不兼容，not_evaluable；未读取禁读内容，不缩减旧GT或验收分母")
                else:
                    print("INPUT_DRIFT：P0输入已漂移，不运行可比性验收，不刷新冻结文件或标签")
                print(json.dumps(drift, ensure_ascii=False, indent=2))
                return 1
            policy, gt_path = frozen.policy, frozen.ground_truth
        else:
            policy, gt_path = Policy(), args.ground_truth
        truth = load_ground_truth(gt_path, root=root, access=access)
        _check_access(access, initial_access_fingerprint)
    except AccessDenied as error:
        print(f"ACCESS_SCOPE_CONFLICT：not_evaluable，{error}")
        return 1
    except (OSError, ValueError, AttributeError, KeyError, TypeError) as error:
        print(f"验收输入无效: {error}")
        return 2
    build_started = time.perf_counter()
    try:
        result = build_index(root, policy, use_cache=not args.no_cache, access=access)
        build_elapsed = time.perf_counter() - build_started
        _check_access(access, initial_access_fingerprint)
        # 与onboard --level 2一致：同一快照先输出L1，再输出L2。
        l1 = render_l1(result)
        print(l1, flush=True)
        l1_elapsed = time.perf_counter() - started
        l2 = render_l2(result)
        print(l2, flush=True)
        l2_elapsed = time.perf_counter() - started
    except AccessDenied as error:
        print(f"ACCESS_SCOPE_CONFLICT：not_evaluable，{error}")
        return 1
    except Exception as error:
        print(f"索引/输出失败，不能宣称通过: {type(error).__name__}: {error}")
        return 2
    order_files = [item[0] for item in reading_order(result, max_items=30)]
    print("=" * 66)
    print(f"P1导航验收 · {root.name} · static；动态验证未执行")
    print(f"构建 {build_elapsed:.2f}s；L1端到端 {l1_elapsed:.2f}s；L2端到端 {l2_elapsed:.2f}s（含准备校验、构建与实际输出）")
    print(f"缓存: {'禁用读写' if args.no_cache else '使用本地缓存'}；L1/L2输出字符数: {len(l1)}/{len(l2)}")
    print(f"当前已确认访问策略 SHA256={initial_access_fingerprint}；遵守.gitignore={access.settings['respect_gitignore']}；模型未启用")
    if frozen:
        project = frozen.project
        expected = {item["path"] for item in project["source_inventory"]}
        present = list(project["ranking_eligible_canonical_labels"])
        excluded = list(project.get("not_ranked_canonical_labels", []))
        unmatched = list(project.get("unmatched_labels", [])) + list(project.get("ambiguous_labels", []))
        print(f"合约 {frozen.contract.get('contract_id')} SHA256={frozen.sha256}")
        print(f"项目 {project['project_id']} · dev-regression · 非holdout；源快照={project.get('snapshot_sha256')}")
        print(f"GT SHA256={project['legacy_gt']['sha256']}；源码/配置/文档/GT按冻结清单核验")
    else:
        expected = {rel for _, rel, _ in discover(root, policy.index.exclude, access=access)}
        matched, unmatched = match_ground_truth(truth, expected)
        present = [f for f in matched if not any(classify(f, policy.index.exclude)[2:])]
        excluded = [f for f in matched if f not in present]
        print("未使用P0冻结合约：只作探索测量，不能宣称P1正式通过")
    print(f"GT {len(truth)}项 → 唯一范围内{len(present)}；排除{len(excluded)}；未知/歧义{len(unmatched)}")
    print(f"    排除项: {excluded}；未匹配/歧义: {unmatched}")
    print("未标注推荐保持未知，P@K仅表示文档标注命中比例，不是人工真实准确率。")
    print("少于K项仅报告实际前N项比例；不足10项不能声明P@10达标。")
    _report_ranking("[1] PageRank排序（仅报告）", [f for f, _ in result.top_files(80)], present)
    _report_ranking("[1b] 阅读顺序（P@10对象）", order_files, present)
    directories = directory_coverage(present, order_files)
    print("\n[1c] 文件GT父目录覆盖（不是独立架构金标）")
    for coverage in directories:
        print(f"    {coverage.directory}: {coverage.covered}/{coverage.expected}")
    entry_gold = (frozen.project.get("entry_gold", frozen.contract.get("task", {}).get("entry_gold", {})) if frozen else {})
    independent = entry_gold.get("status") in {"independently_adjudicated", "independently_annotated"}
    entry_truth = entry_gold.get("files") if independent else None
    if not isinstance(entry_truth, list) or not all(isinstance(x, str) and x in expected for x in entry_truth):
        entry_truth, independent = None, False
    predictions = application_entry_predictions(result.entrypoints)
    entries = entrypoint_metrics(predictions, entry_truth, independently_annotated=independent)
    print(f"\n[2] 应用入口（process+mount文件集合）: {entries.predicted}；precision={_percent(entries.precision)}；recall={_percent(entries.recall)}")
    counts = {kind: sum(getattr(entry, "kind", "candidate") == kind for entry in result.entrypoints)
              for kind in ("process", "mount", "bridge", "assembly", "candidate")}
    print(f"    启动角色观察数: {counts}；仅非脚本、static/declared的process/mount计入应用入口预测，桥接/装配/候选不混算。")
    print("    按角色precision/recall=N/A：当前入口金标只提供文件集合，不推造分组答案。")
    if not independent:
        print("    无独立入口金标，入口指标N/A，不能宣称P1全通过。")
    location_errors = output_location_errors(root, result, order_files, access=access)
    print(f"\n[3] 索引自洽与磁盘位置错误 {len(location_errors)}（不证明语义正确）")
    for error in location_errors:
        print(f"    {error}")
    missing = sorted(expected - {f.path for f in result.files})
    unknown = sorted(f.path for f in result.files if not f.is_parsed or f.language == Language.UNKNOWN)
    parse_issues = getattr(result, "parse_issues", [])
    builder_complete = getattr(result, "is_complete", None)
    complete = bool(expected) and not missing and not unknown and not result.parse_failures and not parse_issues and builder_complete is not False
    print(f"\n[4] 发现{len(expected)}；索引{len(result.files)}；解析异常{result.parse_failures}；完整={complete}")
    print(f"    缺失文件: {missing}；未解析/未知语言文件: {unknown}")
    for issue in parse_issues:
        print(f"    解析问题: {issue}")
    resolution = resolution_summary(result.call_stats)
    print(f"    项目内候选确定绑定 {resolution.resolved}/{resolution.denominator} ({_percent(resolution.rate)})；heuristic={resolution.heuristic}；分类={result.call_stats}")
    try:
        drift = contract_input_drift(frozen, root, access=access) if frozen else []
        _check_access(access, initial_access_fingerprint)
    except AccessDenied as error:
        drift = [{"kind": "access_policy", "path": ".", "change": "access_scope_conflict", "reason": str(error)}]
    if drift:
        print("ACCESS_SCOPE_CONFLICT：运行期间权限变化，not_evaluable，不能作为冻结验收" if any(item.get("change") == "access_scope_conflict" for item in drift)
              else "INPUT_DRIFT：运行期间输入发生变化，所有测量不能作为冻结验收")
        print(json.dumps(drift, ensure_ascii=False, indent=2))
    formal_blockers = list(frozen.contract.get("formal_acceptance_blockers", [])) if frozen else ["未使用P0冻结合约"]
    if formal_blockers:
        print(f"\nP0正式验收未决项: {formal_blockers}")
    p10 = ranking_metrics(order_files, present, 10)
    effective_p10 = max(0.8, args.min_p10)
    checks = {
        f"阅读顺序文档标注P@10 >= {effective_p10:.0%}": p10.precision is not None and p10.precision >= effective_p10,
        "标签与输出适用（无未知标注、至少8个标签及10项输出）": not unmatched and len(set(present)) >= 8 and len(order_files) >= 10,
        "解析完整": complete,
        "磁盘位置错误0": not location_errors,
        f"L1端到端 < {args.l1_max_seconds:g}s": l1_elapsed < args.l1_max_seconds,
        f"L2端到端 < {args.l2_max_seconds:g}s": l2_elapsed < args.l2_max_seconds,
        "独立入口precision>=90%、recall=100%": entries.precision is not None and entries.precision >= 0.9 and entries.recall == 1.0,
        "P0冻结输入无漂移": frozen is not None and not drift,
        "P0正式验收未决项已解决": not formal_blockers,
        "阈值未放宽已确认目标": args.min_p10 >= 0.8 and args.l1_max_seconds <= 30 and args.l2_max_seconds <= 180,
    }
    print("\n" + "=" * 66)
    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {name}")
    passed = all(checks.values())
    not_evaluable = not frozen or bool(formal_blockers or drift or unmatched) or not independent or not complete or len(set(present)) < 8 or len(order_files) < 10
    print("P1验收通过（仅声明范围；非泛化证明）" if passed else ("P1无法验收：未知、不完整或证据不足，不能宣称通过" if not_evaluable else "P1验收失败：未达到冻结门槛"))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
