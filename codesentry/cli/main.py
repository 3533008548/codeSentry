"""CLI 入口。

v0.2 决策 12：多子命令结构。

    codesentry onboard <path> [--level 1|2] [--json]   # 场景 A：理解
    codesentry scan <path> [--json]                    # 场景 B：审查（M3 起）
    codesentry index <path> --refresh                  # 显式重建索引
    codesentry init [path]                             # 生成 policy.yaml

**为什么现在定多子命令**：scan 与 onboard 的输出形态根本不同（finding 列表
vs 导航图），用单命令 + flag 实现会长出 15-flag 的上帝函数。而底层数据模型
（Symbol/Edge/Finding）现在就要定——它们是两个场景共用的地基。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from codesentry.core.policy import (
    default_policy_text,
    load_policy,
)
from codesentry.index.builder import build_index
from codesentry.index.store import IndexStore
from codesentry.output.report import render_json, render_l1, render_l2


def _resolve_policy(explicit: str | None, root: Path) -> tuple[Path | None, object]:
    """找policy：显式指定 > 项目根 > 当前目录。"""
    if explicit:
        return Path(explicit), None
    for candidate in (root / "policy.yaml", Path("policy.yaml")):
        if candidate.exists():
            return candidate, None
    return None, None


def cmd_onboard(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"路径不存在: {root}", file=sys.stderr)
        return 2

    policy_path, _ = _resolve_policy(args.policy, root)
    policy = load_policy(policy_path)

    result = build_index(root, policy, refresh=args.refresh)

    if args.json:
        print(render_json(result))
        return 0

    print(render_l1(result))
    if args.level >= 2:
        print()
        print(render_l2(result))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """场景 B 的入口。M3 之前只做索引与占位说明。"""
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"路径不存在: {root}", file=sys.stderr)
        return 2
    policy_path, _ = _resolve_policy(args.policy, root)
    policy = load_policy(policy_path)
    result = build_index(root, policy)
    if args.json:
        print(render_json(result))
        return 0
    print("scan 尚未实现检查器（M1 完成）。当前仅索引可用：")
    print(render_l1(result))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """报告索引状态与陈旧程度。

    回答 v0.2 §4.5 提的问题：「索引是快照，代码改了索引不知道，
    直到下次重建」——本命令让这个状态显式可见。
    """
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"路径不存在: {root}", file=sys.stderr)
        return 2
    policy_path, _ = _resolve_policy(args.policy, root)
    policy = load_policy(policy_path)

    store = IndexStore(root)
    saved = store.load()
    if saved is None:
        print("索引不存在。需要先运行：codesentry index <path>")
        return 1

    # 重建一次以比对（走缓存，很快）
    result = build_index(root, policy)
    info = store.check_stale(result)
    print(store.stale_report(info))
    print(f"索引文件: {store.index_file}")
    print(f"构建于:   {info.built_at}（{info.age_seconds / 3600:.1f} 小时前）")
    print(f"规模:     {saved.get('file_count')} 文件 · "
          f"{saved.get('symbol_count')} 符号 · "
          f"{saved.get('edge_count')} 边")
    return 0 if not info.stale else 0


def cmd_index(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    policy_path, _ = _resolve_policy(args.policy, root)
    policy = load_policy(policy_path)
    result = build_index(root, policy, verbose=True, refresh=True)
    store = IndexStore(root, save_to_project=args.save_to_project)
    store.save(result)
    print(f"索引已保存: {store.index_file}")
    if args.json:
        print(render_json(result))
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path or ".").resolve() / "policy.yaml"
    if target.exists() and not args.force:
        print(f"已存在，不覆盖: {target}", file=sys.stderr)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(default_policy_text(), encoding="utf-8")
    print(f"已写入 {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codesentry",
        description="CodeSentry · 本地优先的代码理解与审查 Agent",
    )
    p.add_argument("--policy", help="policy.yaml 路径（默认找项目根）")
    sub = p.add_subparsers(dest="command", required=True)

    # onboard
    ob = sub.add_parser("onboard", help="理解陌生项目：入口点与骨架")
    ob.add_argument("path", help="项目根目录")
    ob.add_argument("--level", type=int, choices=[1, 2], default=2,
                    help="输出档位：1=定位 2=骨架")
    ob.add_argument("--json", action="store_true", help="输出 JSON")
    ob.add_argument("--refresh", action="store_true",
                    help="清空缓存，全量重建索引")
    ob.set_defaults(func=cmd_onboard)

    # scan
    sc = sub.add_parser("scan", help="审查改动（M3 起）")
    sc.add_argument("path", help="项目根目录")
    sc.add_argument("--json", action="store_true", help="输出 JSON")
    sc.add_argument("--refresh", action="store_true",
                    help="清空缓存，全量重建索引")
    sc.set_defaults(func=cmd_scan)

    # index
    ix = sub.add_parser("index", help="显式重建索引")
    ix.add_argument("path", help="项目根目录")
    ix.add_argument("--json", action="store_true", help="输出 JSON")
    ix.add_argument("--save-to-project", action="store_true",
                    help="把索引写到项目根（默认写用户缓存目录，不污染项目）")
    ix.set_defaults(func=cmd_index)

    # status
    st = sub.add_parser("status", help="报告索引状态与陈旧程度")
    st.add_argument("path", help="项目根目录")
    st.set_defaults(func=cmd_status)

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
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
