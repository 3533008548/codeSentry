"""CLI 入口。

v0.2 决策 12：多子命令结构。

    codesentry onboard <path> [--level 1|2] [--json]   # 场景 A：理解
    codesentry scan <path> --preview [--json]          # 场景 B：只报告策略债务，非门禁
    codesentry index <path> --refresh                  # 显式重建索引
    codesentry init [path]                             # 生成 policy.yaml

**为什么现在定多子命令**：scan 与 onboard 的输出形态根本不同（finding 列表
vs 导航图），用单命令 + flag 实现会长出 15-flag 的上帝函数。而底层数据模型
（Symbol/Edge/Finding）现在就要定——它们是两个场景共用的地基。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path

from codesentry.core.policy import (
    Policy,
    default_policy_text,
    load_policy,
)
from codesentry.environment import get_toolchain, inspect_environment
from codesentry.index.builder import build_index
from codesentry.index.store import IndexStore
from codesentry.output.report import render_json, render_l1, render_l2
from codesentry.cli.access import default_workspace_data_dir, resolve_access


def _resolve_policy(explicit: str | None, root: Path) -> tuple[Path | None, object]:
    """找policy：显式指定 > 项目根 > 当前目录。"""
    if explicit:
        return Path(explicit), None
    for candidate in (root / "policy.yaml", Path("policy.yaml")):
        if candidate.exists():
            return candidate, None
    return None, None


def _analysis_policy(args, root: Path, access) -> Policy:
    """Repository analysis settings never grant file access."""
    path = Path(args.policy).expanduser().resolve() if args.policy else root / 'policy.yaml'
    if not path.exists():
        return Policy()
    if not path.is_relative_to(root):
        return load_policy(path) if args.policy else Policy()
    relative = path.relative_to(root).as_posix()
    if access.decision(relative)['mode'] == 'exclude':
        print('算法配置在排除范围内，使用默认分析设置。', file=sys.stderr)
        return Policy()
    import yaml
    data = yaml.safe_load(access.read_text(relative, limit=2 * 1024 * 1024))
    if data is None:
        return Policy()
    if not isinstance(data, dict):
        raise ValueError('算法配置顶层必须是映射')
    return Policy.model_validate(data)


def cmd_onboard(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"路径不存在: {root}", file=sys.stderr)
        return 2

    access = resolve_access(args, root)
    policy = _analysis_policy(args, root, access)

    result = build_index(root, policy, refresh=args.refresh,
                         use_cache=False if args.no_cache else None, access=access)
    access.check_current()

    if args.json:
        print(render_json(result))
        return 0 if result.is_complete else 1

    print(render_l1(result))
    if args.level >= 2:
        print()
        print(render_l2(result))
    return 0 if result.is_complete else 1


def cmd_scan(args: argparse.Namespace) -> int:
    """Preview, defect candidates and gate checks are explicit."""
    if args.gate:
        return cmd_gate(args)
    if args.defects:
        return cmd_defects(args)
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"路径不存在: {root}", file=sys.stderr)
        return 2
    if args.preview:
        if args.policy:
            raise ValueError("请通过 --max-function-lines 设置预览阈值，此模式尚未支持 --policy")
        from codesentry.review.scan import scan_preview
        access = resolve_access(args, root)
        report = scan_preview(access, max_function_lines=80 if args.max_function_lines is None else args.max_function_lines)
        access.check_current()
        if args.json:
            print(json.dumps(report, ensure_ascii=False))
        else:
            print("只报告审查预览；门禁未评估，不能作为CI通过依据。")
            print(f"Python文件：{report['coverage']['analyzed_python']}；策略债务：{report['summary']['policy_debt_findings']}")
            for item in report['findings']:
                finding = item['finding']
                print(f"  {finding['file']}:{finding['line']}  {finding['reason']}")
            print(f"预览状态：{report['review_status']}；问题/限制：{len(report['issues'])}")
        return 1 if report['review_status'] == 'incomplete' else 3
    if args.json:
        print(json.dumps({'review_status': 'not_implemented', 'root': str(root),
                          'message': '正式门禁尚未开放；可用scan --preview查看Python策略债务预览'}, ensure_ascii=False))
    else:
        print('正式门禁尚未开放。可用 scan --preview 查看Python策略债务预览。')
    return 2


def cmd_gate(args: argparse.Namespace) -> int:
    from codesentry.review.gate import evaluate_gate, gate_error
    try:
        if args.policy or args.max_function_lines is not None:
            raise ValueError("门禁仅使用内置可信必检策略，不接受本次扫描覆盖规则或阈值")
        root = Path(args.path).resolve()
        if not root.is_dir():
            raise ValueError("项目目录不存在或不是目录")
        access = resolve_access(args, root)
        report = evaluate_gate(access)
        access.check_current()
    except Exception as error:
        report = gate_error(str(error)[:500])
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        print(f"门禁判定：{report['gate_status']}；退出码：{report['exit_code']}")
        for issue in report.get("issues", []):
            print(f"  {issue.get('message', issue.get('status', '检查未完成'))}")
        for row in report.get("findings", []):
            finding = row["finding"]
            print(f"  {finding['file']}:{finding['line']}  {finding['reason']}")
    return report["exit_code"]


def cmd_defects(args: argparse.Namespace) -> int:
    from codesentry.review.defects import scan_defect_preview
    try:
        if args.policy or args.max_function_lines is not None:
            raise ValueError("缺陷候选使用固定规则，不接受仓库算法策略或函数行数覆盖")
        root = Path(args.path).resolve()
        if not root.is_dir():
            raise ValueError("项目目录不存在或不是目录")
        access = resolve_access(args, root)
        report = scan_defect_preview(access)
        access.check_current()
        exit_code = 1 if report["review_status"] == "incomplete" else 3
    except Exception as error:
        report = {"schema_version": 1, "mode": "defect_preview", "review_status": "error",
            "gate_status": "not_evaluated", "findings": [], "source_sha256": {},
            "issues": [{"file": ".", "status": "input_or_permission_error", "message": str(error)[:500]}],
            "summary": {"candidate_findings": 0, "confirmed_behavior_bug_findings": 0, "blocking_findings": 0},
            "formal_acceptance": {"passed": False, "reason": "candidate input or permissions unavailable"}}
        exit_code = 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        print(f"缺陷候选：{report['summary']['candidate_findings']}项；已确认行为缺陷0项；门禁未评估")
        for row in report["findings"]:
            finding = row["finding"]
            print(f"  {finding['file']}:{finding['line']}  {finding['reason']}")
        for issue in report["issues"]:
            print(f"  未完成：{issue.get('message', issue.get('status'))}")
    return exit_code


def cmd_crap(args: argparse.Namespace) -> int:
    from codesentry.review.crap import scan_crap

    if args.policy:
        raise ValueError("CRAP 报告使用固定复杂度口径，参考线由 --reference 指定")
    root = Path(args.path).resolve()
    if not root.is_dir():
        raise ValueError("项目目录不存在或不是目录")
    access = resolve_access(args, root)
    coverage_path = None
    if args.coverage_json is not None:
        report_path = Path(args.coverage_json).expanduser()
        if report_path.is_absolute():
            report_path = report_path.relative_to(root)
        coverage_path = report_path.as_posix()
    report = scan_crap(access, coverage_path=coverage_path, reference=args.reference)
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        summary = report["summary"]
        print(f"CRAP 维护风险报告 · Python · 参考目标 < {report['reference']:g}")
        print(f"函数 {summary['functions']} 个，已评分 {summary['scored']} 个，"
              f"待覆盖率证据 {summary['unscored']} 个，达到或超过参考线 {summary['at_or_above_reference']} 个")
        if args.coverage_json is None:
            print("可用 --coverage-json 导入同一源码版本的 coverage.py 报告以计算分数。")
        for row in report["functions"]:
            measurement = row["coverage"]
            coverage = "N/A"
            score = "N/A"
            if measurement is not None:
                basis = "分支" if measurement["basis"] == "branches" else "语句"
                coverage = f"{measurement['ratio']:.1%}（{basis}）"
                score = f"{row['crap']:.2f}"
            print(f"  {row['file']}:{row['line']}  {row['function']}  "
                  f"CC {row['complexity']}  覆盖率 {coverage}  CRAP {score}")
            print(f"    {row['suggestion']}")
        for issue in report["issues"]:
            print(f"  扫描未完成  {issue['file']}  {issue['status']}")
    return int(report["scan_status"] == "incomplete")


def cmd_review_plan(args: argparse.Namespace) -> int:
    from codesentry.review.coverage_plan import build_coverage_plan

    if args.policy:
        raise ValueError("审阅计划采用固定分段口径，请用文件访问选项限定范围")
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("项目目录不存在或不是目录")
    access = resolve_access(args, root)
    data_dir = Path(args.workspace_data_dir).expanduser() if args.workspace_data_dir else default_workspace_data_dir()
    report = build_coverage_plan(access, data_dir=data_dir)
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        summary = report["summary"]
        status = "已就绪" if report["plan_status"] == "ready" else "不完整"
        print(f"本地审阅计划 · {status} · 模型审阅尚未开始")
        print(f"本地范围 {summary['eligible_local_files']} 个文件，已规划 {summary['planned_lines']} 行、"
              f"{summary['planned_ranges']} 个行段，有缺口或未规划的文件 {summary['unplanned_or_partial_files']} 个")
        print(f"已知排除文件 {summary['excluded_files_seen']} 个、目录 {summary['excluded_directories_seen']} 个，"
              f"不支持的文件 {summary['unsupported_files']} 个")
        print("用 --json 查看各文件的行段、缺口和源码摘要。")
    return int(report["plan_status"] == "incomplete")


def _review_access(args):
    if args.policy:
        raise ValueError("审阅批次使用已确认的文件访问范围和固定分段口径")
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("项目目录不存在或不是目录")
    access = resolve_access(args, root)
    if access.workspace_id is None:
        raise ValueError("请先在工作台登记项目、确认模型候选范围并启用 DeepSeek")
    data_dir = Path(args.workspace_data_dir).expanduser() if args.workspace_data_dir else default_workspace_data_dir()
    return root, access, data_dir.resolve()


def _review_semantic(args, root, data_dir, *, enabled):
    from codesentry.semantic.credentials import load_deepseek_credentials
    from codesentry.semantic.service import SemanticService

    if not enabled:
        return SemanticService(data_dir)
    env_file = Path(args.env_file).expanduser().resolve() if args.env_file else None
    if env_file is not None and env_file.is_relative_to(root):
        raise ValueError("显式密钥文件须位于被审项目目录之外")
    credentials = load_deepseek_credentials(env_file)
    if not credentials.api_key:
        raise ValueError("请先在 CodeSentry 的 .env 或环境变量配置 DeepSeek 启动密钥")
    return SemanticService(data_dir, configured_api_key=credentials.api_key, configured_key_source=credentials.source)


def cmd_review_run(args: argparse.Namespace) -> int:
    from codesentry.review.batch_review import run_batch_review

    root, access, data_dir = _review_access(args)
    semantic = _review_semantic(args, root, data_dir, enabled=True)
    try:
        report = run_batch_review(access, semantic, access.workspace_id, data_dir=data_dir,
                                  approved_plan=args.approve_plan, question=args.question, model=args.model,
                                  first_batch=args.first_batch, max_batches=args.max_batches,
                                  retry_requests=args.retry_requests,
                                  progress=lambda number, total: print(f"已处理审阅批次 {number}/{total}",
                                                                      file=sys.stderr, flush=True))
    finally:
        semantic.close()
    print(json.dumps(report, ensure_ascii=True))
    if report.get("stop_reason") == "cancelled":
        return 130
    return int(report["review_status"] != "model_scope_complete")


def cmd_review_merge(args: argparse.Namespace) -> int:
    from codesentry.review.review_merge import merge_reviews, read_reports
    from codesentry.semantic.service import MAX_REVIEW_BATCHES

    if not 0 <= args.summary_requests <= MAX_REVIEW_BATCHES:
        raise ValueError("汇总请求上限必须在 0 至 100 之间")
    if args.summary_source_evidence and not args.summary_requests:
        raise ValueError("源码复核需要显式指定正数 --summary-requests")
    root, access, data_dir = _review_access(args)
    reports = read_reports(args.report, root)
    semantic = _review_semantic(args, root, data_dir, enabled=bool(args.summary_requests))
    try:
        result = merge_reviews(access, semantic, reports, data_dir=data_dir, approved_plan=args.approve_plan,
                               question=args.question, model=args.model, summary_requests=args.summary_requests,
                               summary_source_evidence=args.summary_source_evidence)
    finally:
        semantic.close()
    print(json.dumps(result, ensure_ascii=True))
    if result.get("summary", {}).get("status") == "interrupted":
        return 130
    return int(result["review_status"] != "model_scope_complete"
               or bool(args.summary_requests and result.get("summary", {}).get("status") != "completed"))


def cmd_status(args: argparse.Namespace) -> int:
    """报告索引状态与陈旧程度。

    回答 v0.2 §4.5 提的问题：「索引是快照，代码改了索引不知道，
    直到下次重建」——本命令让这个状态显式可见。
    """
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"路径不存在: {root}", file=sys.stderr)
        return 2
    access = resolve_access(args, root)
    policy = _analysis_policy(args, root, access)

    store = IndexStore(root, access=access)
    saved = store.load()
    if saved is None:
        print("索引不存在。需要先运行：codesentry index <path>")
        return 1

    # 重建一次以比对（走缓存，很快）
    result = build_index(root, policy, use_cache=False, access=access)
    info = store.check_stale(result)
    access.check_current()
    print(store.stale_report(info))
    print(f"索引文件: {store.index_file}")
    print(f"构建于:   {info.built_at}（{info.age_seconds / 3600:.1f} 小时前）")
    print(f"规模:     {saved.get('file_count')} 文件 · "
          f"{saved.get('symbol_count')} 符号 · "
          f"{saved.get('edge_count')} 边")
    return 1 if info.stale else 0


def cmd_index(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f'项目目录不存在或不是目录: {root}', file=sys.stderr)
        return 2
    access = resolve_access(args, root)
    policy = _analysis_policy(args, root, access)
    result = build_index(root, policy, verbose=not args.json, refresh=True,
                         use_cache=False if args.no_cache else None, access=access)
    store = IndexStore(root, save_to_project=args.save_to_project, access=access)
    saved = store.save(result)
    access.check_current()
    if args.json:
        payload = json.loads(render_json(result))
        payload['index_saved'] = saved
        payload['index_file'] = str(store.index_file)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif saved:
        print(f'索引已保存: {store.index_file}')
    if not saved:
        print(f'索引保存失败: {store.index_file}', file=sys.stderr)
        return 2
    return 0 if result.is_complete else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f'项目目录不存在或不是目录: {root}', file=sys.stderr)
        return 2
    access = resolve_access(args, root)
    toolchain = get_toolchain(root)
    profile = inspect_environment(root, toolchain=toolchain, access=access)
    access.check_current()
    payload = profile.to_dict()
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print('环境诊断（只读，未安装或运行目标依赖）')
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
        from codesentry.web.app import create_app
    except ImportError as error:
        print('网页依赖尚未安装。请安装 codesentry[web] 后再启动。', file=sys.stderr)
        return 2
    frontend = (Path(args.frontend_dir).expanduser().resolve() if args.frontend_dir
                else Path(__file__).resolve().parents[2] / 'frontend' / 'dist')
    if not (frontend / 'index.html').is_file():
        print('网页资源尚未构建。请在 frontend 目录安装依赖并运行 npm run build。', file=sys.stderr)
        return 2
    if args.data_dir:
        data_dir = Path(args.data_dir).expanduser().resolve()
    else:
        data_dir = default_workspace_data_dir()
    from codesentry.semantic.credentials import load_deepseek_credentials
    try:
        credentials = load_deepseek_credentials(Path(args.env_file) if args.env_file else None)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    app = create_app(data_dir=data_dir, frontend_dir=frontend,
                     allowed_dev_origins=set(args.dev_origin),
                     configured_api_key=credentials.api_key,
                     configured_key_source=credentials.source if credentials.api_key else None)
    url = f'http://{args.host}:{args.port}'
    print(f'CodeSentry 工作空间: {url}', flush=True)
    if args.open_browser:
        import threading
        import time
        import webbrowser
        config = uvicorn.Config(app, host=args.host, port=args.port, log_level='warning')
        server = uvicorn.Server(config)
        def open_when_ready():
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not server.should_exit:
                if server.started:
                    webbrowser.open(url)
                    return
                time.sleep(0.1)
        threading.Thread(target=open_when_ready, daemon=True).start()
        server.run()
    else:
        uvicorn.run(app, host=args.host, port=args.port, log_level='warning')
    return 0


def _local_port(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError('端口须在1到65535之间')
    return number


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path or ".").resolve() / "policy.yaml"
    if target.exists() and not args.force:
        print(f"已存在，不覆盖: {target}", file=sys.stderr)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(default_policy_text(), encoding="utf-8")
    print(f"已写入 {target}")
    return 0


def cmd_runner(args: argparse.Namespace) -> int:
    from codesentry.execution.commands import main as execution_main
    arguments = ['doctor', '--json']
    if args.docker_executable:
        arguments += ['--docker-executable', args.docker_executable]
    if args.endpoint:
        arguments += ['--endpoint', args.endpoint]
    return execution_main(arguments)


def cmd_changes(args: argparse.Namespace) -> int:
    from codesentry.review.changes import analyze_changes
    if args.policy:
        raise ValueError("变更范围预览不加载仓库算法策略；文件权限请使用访问范围参数")
    if (args.comparison == "commit") != (args.target is not None):
        raise ValueError("两提交比较必须指定--target；其他模式不接受--target")
    root = Path(args.path).resolve()
    if not root.is_dir():
        raise ValueError("项目目录不存在或不是目录")
    access = resolve_access(args, root)
    result = analyze_changes(access, base_ref=args.base, comparison=args.comparison, target_ref=args.target)
    access.check_current()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"变更范围：{result['change_status']}；门禁未评估")
        print(f"变更文件 {result['summary']['changed_files']}；可能影响文件 {result['summary']['affected_files']}")
        for item in result["changes"]:
            print(f"  {item['layer']} / {item['status']}: {item['old_path'] or ''} -> {item['new_path'] or ''}")
        for issue in result["issues"]:
            print(f"  未完成：{issue['message']}")
    return 3 if result["change_status"] == "report_only" else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codesentry",
        description="CodeSentry · 本地优先的代码理解与审查 Agent",
    )
    p.add_argument("--policy", help="policy.yaml 路径（默认找项目根）")
    sub = p.add_subparsers(dest="command", required=True)

    def access_options(command):
        command.add_argument('--workspace-data-dir', help='已确认权限所在的工作空间数据目录')
        command.add_argument('--confirm-access', action='store_true', help='对未注册项目确认按默认忽略规则仅在本地分析')
        command.add_argument('--access-policy', help='项目目录之外的可信访问策略JSON')
        command.add_argument('--exclude', action='append', default=[], help='额外完全排除路径或模式，可重复')
        command.add_argument('--local-only', action='append', default=[], help='仅允许本地分析的路径或模式，可重复')

    # onboard
    ob = sub.add_parser("onboard", help="理解陌生项目：入口点与骨架")
    ob.add_argument("path", help="项目根目录")
    ob.add_argument("--level", type=int, choices=[1, 2], default=2,
                    help="输出档位：1=定位 2=骨架")
    ob.add_argument("--json", action="store_true", help="输出 JSON")
    ob.add_argument("--no-cache", action="store_true", help="不读写解析缓存")
    ob.add_argument("--refresh", action="store_true",
                    help="清空缓存，全量重建索引")
    ob.set_defaults(func=cmd_onboard)
    access_options(ob)

    # scan
    sc = sub.add_parser("scan", help="审查预览、缺陷候选与门禁检查（生产阻断未准入）")
    sc.add_argument("path", help="项目根目录")
    sc.add_argument("--json", action="store_true", help="输出 JSON")
    sc.add_argument("--refresh", action="store_true",
                    help="清空缓存，全量重建索引")
    scan_mode = sc.add_mutually_exclusive_group()
    scan_mode.add_argument('--preview', action='store_true', help='只报告Python策略债务，门禁未评估（完成返回3）')
    scan_mode.add_argument('--gate', action='store_true', help='按内置可信必检清单判定门禁，未准入不通过')
    scan_mode.add_argument('--defects', action='store_true', help='检查Python缺陷候选，仅报告，尚未确认行为缺陷')
    sc.add_argument('--max-function-lines', type=int, default=None, help='仅预览的函数物理行数阈值（默认80），门禁禁止覆盖')
    sc.set_defaults(func=cmd_scan)
    access_options(sc)

    crap = sub.add_parser('crap', help='计算 Python 函数维护风险分数，读取已有覆盖率报告')
    crap.add_argument('path', help='项目根目录')
    crap.add_argument('--coverage-json', help='项目内的 coverage.py JSON 报告路径，省略时只计算复杂度')
    crap.add_argument('--reference', type=float, default=10, help='报告参考线（默认 10）')
    crap.add_argument('--json', action='store_true', help='输出 JSON')
    crap.set_defaults(func=cmd_crap)
    access_options(crap)

    plan = sub.add_parser("review-plan", help="在本地规划项目审阅的文件、行段和覆盖缺口")
    plan.add_argument("path", help="项目根目录")
    plan.add_argument("--json", action="store_true", help="输出逐文件行段和摘要")
    plan.set_defaults(func=cmd_review_plan)
    access_options(plan)

    run = sub.add_parser("review-run", help="授权按计划向 DeepSeek 提交审阅批次，输出覆盖报告")
    run.add_argument("path", help="已登记的项目根目录")
    run.add_argument("--approve-plan", required=True, help="本次批准的 review-plan 摘要")
    run.add_argument("--question", required=True, help="本次审阅问题")
    run.add_argument("--model", required=True, help="本次批准使用的工作空间 DeepSeek 模型")
    run.add_argument("--first-batch", type=int, default=1, help="起始批次（从 1 开始）")
    run.add_argument("--max-batches", type=int, required=True, help="本次最多处理的批次")
    run.add_argument("--retry-requests", type=int, default=0, help="额外授权补跑失败行段的次数，默认为 0")
    run.add_argument("--env-file", help="CodeSentry 启动密钥文件")
    run.set_defaults(func=cmd_review_run)
    access_options(run)

    merge = sub.add_parser("review-merge", help="合并同一计划的本机批次报告，可显式授权跨文件汇总")
    merge.add_argument("path", help="已登记的项目根目录")
    merge.add_argument("--approve-plan", required=True, help="原审阅的计划摘要")
    merge.add_argument("--question", required=True, help="原审阅问题")
    merge.add_argument("--model", required=True, help="原审阅使用的工作空间模型")
    merge.add_argument("--report", required=True, action="append", help="已导出的批次 JSON，可重复指定")
    merge.add_argument("--summary-requests", type=int, default=0, help="授权跨文件汇总的请求上限，默认为 0")
    merge.add_argument("--summary-source-evidence", action="store_true",
                       help="允许汇总请求重发已引用行段的源码，并逐条核对引用")
    merge.add_argument("--env-file", help="CodeSentry 启动密钥文件，仅用于授权汇总")
    merge.set_defaults(func=cmd_review_merge)
    access_options(merge)

    changes = sub.add_parser('changes', help='只读比较提交/工作树与Python导入影响范围，门禁未评估')
    changes.add_argument('path', help='项目根目录')
    changes.add_argument('--base', default='HEAD', help='HEAD或完整提交SHA，默认HEAD')
    changes.add_argument('--comparison', choices=['working_tree', 'staged', 'commit'], default='working_tree')
    changes.add_argument('--target', help='两提交模式的完整目标SHA；不自动选择merge-base')
    changes.add_argument('--json', action='store_true')
    changes.set_defaults(func=cmd_changes)
    access_options(changes)

    # index
    ix = sub.add_parser("index", help="显式重建索引")
    ix.add_argument("path", help="项目根目录")
    ix.add_argument("--json", action="store_true", help="输出 JSON")
    ix.add_argument("--no-cache", action="store_true", help="不读写解析缓存")
    ix.add_argument("--save-to-project", action="store_true",
                    help="把索引写到项目根（默认写用户缓存目录，不污染项目）")
    ix.set_defaults(func=cmd_index)
    access_options(ix)

    # status
    st = sub.add_parser("status", help="报告索引状态与陈旧程度")
    st.add_argument("path", help="项目根目录")
    st.set_defaults(func=cmd_status)
    access_options(st)

    doctor = sub.add_parser('doctor', help='只读环境与工具链诊断')
    doctor.add_argument('path', help='项目根目录')
    doctor.add_argument('--json', action='store_true', help='输出 JSON')
    doctor.set_defaults(func=cmd_doctor)
    access_options(doctor)

    serve = sub.add_parser('serve', help='启动本地网页工作空间')
    serve.add_argument('--host', choices=['127.0.0.1', 'localhost'], default='127.0.0.1')
    serve.add_argument('--port', type=_local_port, default=8765)
    serve.add_argument('--data-dir', help='本地工作空间状态目录（不写源代码）')
    serve.add_argument('--env-file', help='可信的CodeSentry环境文件；默认读取CodeSentry安装目录的.env，不读取被审项目的.env')
    serve.add_argument('--frontend-dir', help='已构建网页资源目录')
    serve.add_argument('--open-browser', action='store_true', help='启动完成后打开浏览器')
    serve.add_argument('--dev-origin', action='append', default=[], help='显式允许的本地前端开发源（生产默认关闭）')
    serve.set_defaults(func=cmd_serve)

    runner = sub.add_parser('runner', help='执行后端准备（仅诊断，不运行项目）')
    runner.add_argument('action', choices=['doctor'])
    runner.add_argument('--json', action='store_true')
    runner.add_argument('--docker-executable', help='可信Docker程序的绝对路径')
    runner.add_argument('--endpoint', help='已支持的本地Docker端点')
    runner.set_defaults(func=cmd_runner)

    # init
    it = sub.add_parser("init", help="生成 policy.yaml")
    it.add_argument("path", nargs="?", help="项目根目录（默认当前目录）")
    it.add_argument("--force", action="store_true", help="覆盖已有文件")
    it.set_defaults(func=cmd_init)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        with ExitStack() as args._access_stack:
            return args.func(args)
    except (OSError, ValueError) as error:
        print(f'执行失败: {error}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
