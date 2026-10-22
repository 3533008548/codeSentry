"""M0 验收：在两个真实项目上做定量验证。

验证项（依据 docs/CodeSentry_技术选型定稿_v0.2.md §5.5）：
  1. 关键文件 Top-K 命中 —— ground truth 用项目自带文档的**全量**清单
  2. 入口点两级分类 —— 应用入口 vs 脚本入口
  3. 幻觉符号率 —— 输出中的符号/文件是否都真实存在（目标 0）
  4. 性能 —— L1+L2 端到端耗时

**方法论红线**：ground truth 必须是文档里的全量清单，不能手工挑样本
（v0.2 §4.3.2 的循环论证教训）。

用法: python evals/m0_acceptance.py <project> <ground_truth.json>
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codesentry.core.policy import Policy
from codesentry.index.builder import build_index


def load_ground_truth(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return list(data.get("files", []))


def match_ground_truth(
    truth: list[str], real_files: set[str]
) -> tuple[list[str], list[str]]:
    """把 ground truth 匹配到实际存在的文件。

    文档里可能只写文件名（`App.tsx`）而实际路径是
    `frontend/src/App.tsx`。按「完整路径优先，basename 唯一时兜底」匹配。

    **basename 兜底只在唯一时生效**：实测 Knowledge Loop 里
    `desktop-answer-loop.ts` 在接手指南中出现了两种写法（带路径与不带），
    若不严格会导致同一文件被计入两次，分母虚高。

    Returns:
        (匹配上的文件, 未能匹配的文件)
    """
    matched: list[str] = []
    unmatched: list[str] = []
    seen: set[str] = set()
    by_base: dict[str, list[str]] = {}
    for f in real_files:
        by_base.setdefault(f.rsplit("/", 1)[-1], []).append(f)

    for t in truth:
        if t in seen:
            continue
        if t in real_files:
            if t not in seen:
                matched.append(t)
                seen.add(t)
            continue
        base = t.rsplit("/", 1)[-1]
        cands = by_base.get(base, [])
        # 兜底匹配前先排除已匹配过的文件，避免同一真实文件被计入两次
        cands = [c for c in cands if c not in seen]
        if len(cands) == 1:
            matched.append(cands[0])
            seen.add(cands[0])
        elif len(cands) > 1:
            hit = next(
                (c for c in cands if t.split("/")[-2:-1] and
                 t.split("/")[-2] in c), None)
            if hit:
                matched.append(hit)
                seen.add(hit)
            else:
                unmatched.append(t)
        else:
            unmatched.append(t)
    return matched, unmatched


def main() -> int:
    if len(sys.argv) < 3:
        print("用法: python m0_acceptance.py <project_root> <ground_truth.json>")
        return 2

    root = Path(sys.argv[1]).resolve()
    gt_path = Path(sys.argv[2])
    truth = load_ground_truth(gt_path)

    t0 = time.perf_counter()
    result = build_index(root, Policy())
    elapsed = time.perf_counter() - t0

    print("=" * 66)
    print(f"M0 验收 · {root.name}")
    print("=" * 66)
    print(f"文件 {len(result.files)} · 符号 {len(result.symbols)} · "
          f"边 {len(result.edges)}")
    print(f"端到端耗时 {elapsed:.2f}s")
    print(f"阶段耗时 {({k: round(v, 3) for k, v in result.timings.items()})}")

    # ---- 1. 关键文件 Top-K 命中 ----
    ranked = result.top_files(80)
    rank_of = {f: i + 1 for i, (f, _) in enumerate(ranked)}
    real_files = {f.path for f in result.files}
    present, unmatched = match_ground_truth(truth, real_files)

    print(f"\n[1] 关键文件 Top-K 命中（ground truth: {gt_path.name}，"
          f"{len(truth)} 项）")
    print(f"    匹配上 {len(present)} 项，未匹配 {len(unmatched)} 项")
    if unmatched:
        print(f"    未匹配: {unmatched[:8]}")
    for k in (5, 10, 15, 20, 30, 50):
        hit = sum(1 for f in present if rank_of.get(f, 10**9) <= k)
        if present:
            print(f"    Top{k:<3} {hit:>3}/{len(present)}  "
                  f"({hit / len(present) * 100:.1f}%)")

    print("\n    排名明细:")
    for f in sorted(present, key=lambda x: rank_of.get(x, 10**9)):
        r = rank_of.get(f)
        print(f"      {str(r) if r else '未进榜':>8}. {f}")

    # ---- 1b. 阅读顺序命中（L2 的真实产出质量）----
    # L2 输出的是「从入口出发沿依赖 BFS 展开的推荐阅读顺序」，
    # 不是纯 PageRank 排名。入口/编排类文件在 PageRank 里天然排不上去
    # （被引用少），但它们恰恰是"读懂项目"最该先读的。
    from codesentry.output.reading_order import reading_order
    order = reading_order(result, max_items=30)
    order_files = [f for f, _, _ in order]
    order_rank = {f: i + 1 for i, f in enumerate(order_files)}
    depth_of = {f: d for f, _, d in order}

    print(f"\n[1b] 阅读顺序命中（L2 实际产出，从入口沿依赖 BFS）")
    for k in (5, 10, 15, 20, 30):
        hit = sum(1 for f in present if order_rank.get(f, 10**9) <= k)
        if present:
            print(f"    Top{k:<3} {hit:>3}/{len(present)}  "
                  f"({hit / len(present) * 100:.1f}%)")

    # 深度分布：入口类应在浅层，底层实现应在深层
    shallow = sum(1 for f in present if depth_of.get(f, 99) <= 1)
    print(f"    浅层(深度≤1)命中: {shallow}/{len(present)} "
          f"({shallow / len(present) * 100:.1f}%)")

    print("\n    阅读顺序前 12:")
    for i, (f, label, d) in enumerate(order[:12], 1):
        mark = "✓" if f in present else " "
        print(f"      {i:>3}. {mark} L{d if d >= 0 else '·'} {f}")

    # ---- 2. 入口点 ----
    print(f"\n[2] 入口点")
    print(f"    应用入口 {len(result.entrypoints)} 个")
    for e in result.entrypoints:
        print(f"      {e.file:<44} {e.reason}")
    print(f"    脚本入口 {len(result.script_entrypoints)} 个（折叠）")

    # ---- 3. 幻觉符号率 ----
    # 检查输出的 top_files 与 top_symbols 里的每个文件/符号是否真实存在
    real_files = {f.path for f in result.files}
    real_qnames = {s.qname for s in result.symbols}

    hallucinated_files = [
        f for f, _ in result.top_files(60) if f not in real_files
    ]
    top_syms = sorted(result.symbol_pr.items(), key=lambda kv: -kv[1])[:30]
    hallucinated_syms = [
        q for q, _ in top_syms if q not in real_qnames
    ]

    total_claims = len(result.top_files(60)) + len(top_syms)
    total_halluc = len(hallucinated_files) + len(hallucinated_syms)
    rate = total_halluc / total_claims * 100 if total_claims else 0.0
    print(f"\n[3] 幻觉符号率")
    print(f"    输出声明 {total_claims} 项，幻觉 {total_halluc} 项 "
          f"→ {rate:.2f}%")
    if hallucinated_files:
        print(f"    幻觉文件: {hallucinated_files[:5]}")
    if hallucinated_syms:
        print(f"    幻觉符号: {hallucinated_syms[:5]}")

    # ---- 4. 解析率 ----
    total_calls = sum(result.call_stats.values())
    internal = result.call_stats.get("local", 0) + \
        result.call_stats.get("cross_file", 0)
    print(f"\n[4] 符号解析率")
    print(f"    项目内 {internal:,}/{total_calls:,} "
          f"({internal / total_calls * 100:.1f}%)")
    print(f"    分类: {result.call_stats}")

    # ---- 汇总 ----
    ok = rate == 0.0
    print("\n" + "=" * 66)
    print(f"幻觉符号率 = {rate:.2f}%  {'✅ 达标（硬门槛 0）' if ok else '❌ 未达标'}")
    print(f"L1+L2 端到端 {elapsed:.2f}s  "
          f"{'✅ 达标（<30s）' if elapsed < 30 else '❌ 超时'}")
    print("=" * 66)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
