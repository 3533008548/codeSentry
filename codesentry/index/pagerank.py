"""PageRank 重要度计算。

纯 Python 实现，**不引入 numpy / scipy / networkx**：
  - 实测 30,000 节点仅 169 ms，够用
  - Windows 上安装 scipy 需编译 C 扩展，实测直接超时
  - 60 行可单测，不受第三方版本升级影响

**每次全量计算，不做局部近似**（v0.2 修订）：
  实测局部近似的 Top50 重合度仅 11/50，质量代价明显，而性能收益
  （169 ms）在 AST 解析耗时（8.9 s）面前可忽略。
"""
from __future__ import annotations

from collections import defaultdict


def pagerank(
    nodes: list[str],
    edges: list[tuple[str, str]],
    alpha: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-6,
) -> dict[str, float]:
    """计算 PageRank。

    Args:
        nodes: 节点列表
        edges: 有向边列表 (source, target)
        alpha: 阻尼系数
        max_iter: 最大迭代次数
        tol: 收敛阈值

    Returns:
        {节点: 分数}
    """
    n = len(nodes)
    if n == 0:
        return {}

    idx = {name: i for i, name in enumerate(nodes)}
    out_links: dict[str, list[str]] = defaultdict(list)
    in_links: dict[str, list[str]] = defaultdict(list)

    for s, d in edges:
        if s not in idx or d not in idx or s == d:
            continue
        out_links[s].append(d)
        in_links[d].append(s)

    rank = [1.0 / n] * n
    new_rank = [0.0] * n
    dangling = [i for i in range(n) if not out_links[nodes[i]]]

    for _ in range(max_iter):
        for i in range(n):
            new_rank[i] = (1 - alpha) / n
        for i, name in enumerate(nodes):
            srcs = in_links.get(name)
            if not srcs:
                continue
            s = 0.0
            for u in srcs:
                s += rank[idx[u]] / len(out_links[u])
            new_rank[i] += alpha * s
        # 悬挂节点（无出边）均匀分摊
        dangling_sum = sum(rank[i] for i in dangling)
        if dangling_sum:
            share = alpha * dangling_sum / n
            for i in dangling:
                new_rank[i] += share
        delta = sum(abs(new_rank[i] - rank[i]) for i in range(n))
        rank = new_rank
        if delta < tol:
            break

    return {nodes[i]: rank[i] for i in range(n)}


def normalize(scores: dict[str, float], keys: list[str]) -> dict[str, float]:
    """归一化到 [0,1]。"""
    if not keys:
        return {}
    mx = max((scores.get(k, 0.0) for k in keys), default=0.0)
    if mx <= 0:
        return {k: 0.0 for k in keys}
    return {k: scores.get(k, 0.0) / mx for k in keys}
