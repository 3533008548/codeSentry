"""推荐阅读顺序的推导。

**这是场景 A 最值钱的产出。** 用户的痛点不是"信息缺失"，而是
"不知道从哪开始读、读到哪算够"。

## 为什么不用纯 PageRank 排序

实测（v0.2 §4.3.3，M0 验收报告 §四）：PageRank 对入口/编排类文件
没有系统性偏好——

| 项目 | 入口类排名中位 | 全部文件中位 | 编排类中位 |
|---|---|---|---|
| research_agent | 70 | 60 | 77 |
| Knowledge Loop | 33 | 21 | 64 |

**原因**：PageRank 衡量"被引用的中心性"，而入口与编排器是"引用别人"
的一方。`research_agent.py` import 了 30 个模块却几乎不被 import，
PageRank 给它 0.003，排第 66。

**但入口恰恰是"读懂项目"最该先看的文件。**

## 做法：从入口出发沿依赖边 BFS

```
第 0 层：应用入口
第 1 层：入口直接依赖的模块
第 2 层：第 1 层依赖的模块（尚未出现的）
...
```

层内按 PageRank 降序（同层的重要性差异小，用 PR 区分合理）。

**为什么 BFS 而不是 DFS**：DFS 会顺着一条链走到底（入口 → A → A 的
依赖 → ...），中途跳到很深的叶子。**BFS 保证"先读 breadth 层的骨架，
再深入细节"**，这符合"先建立全局印象"的需求。

**兜底**：BFS 覆盖不到的文件（孤立模块、叶子层 UI 文件）按 PageRank
补在末尾——它们可能不在依赖图上（如 `api/app.py` 路由层），但仍是
必读文件。
"""
from __future__ import annotations

from collections import defaultdict, deque

from codesentry.index.builder import IndexResult


def _role_of(result: IndexResult, f: str) -> str:
    r = result.roles.get(f)
    return r.role if r and r.role != "-" else "core"


def _has_contract_shape(result: IndexResult, f: str) -> bool:
    """判断一个文件是否是「契约形态」。

    判据：含 interface / type / 协议类定义，且实现型符号很少。
    这样能区分「真正的契约层」（只定义接口）与
    「普通工具模块」（有实现但被依赖多）。
    """
    syms = result.symbols_of(f)
    if not syms:
        return False
    from codesentry.core.symbol import SymbolKind

    contract_kinds = {
        SymbolKind.INTERFACE, SymbolKind.TYPE_ALIAS, SymbolKind.ENUM,
    }
    contracts = sum(1 for s in syms if s.kind in contract_kinds)
    impls = sum(
        1 for s in syms
        if s.kind in (SymbolKind.FUNCTION, SymbolKind.METHOD)
    )
    # 有契约定义，且实现不多（允许少量简单实现）
    return contracts > 0 and impls <= contracts + 2


def reading_order(
    result: IndexResult,
    max_depth: int = 4,
    max_items: int = 30,
) -> list[tuple[str, str, int]]:
    """推导推荐阅读顺序。

    Returns:
        [(文件, 标签, 深度)]，深度 0 = 入口
    """
    # 层内排序键：PageRank 降序，同层内用 PR 区分
    pr = result.file_pr

    # ---- 第 0 层：应用入口 ----
    # 排序用**出度**（组装了多少模块），不用 PageRank。
    # 实测：src/main.ts（1796 行，装配 30+ 模块）出度 92，
    # 而 src/preload.ts（18 行）出度 0。若按 PageRank 排，
    # preload 会因为"被引用少"而排到 main 前面——但它显然不是
    # "读懂项目"的起点。
    #
    # **只把「出度 > 0」的入口作为阅读起点**（其余作为辅助入口列出）：
    # 实测 src/preload.ts / App.tsx / main.tsx 出度都是 0——它们是
    # 渲染层叶子，不组装任何东西，从它们读起会走进死胡同。
    # research_agent 侧 api/app.py 出度 11、api/routes.py 53、
    # research_agent.py 65，才是真正的起点。
    all_entries = sorted(
        result.entrypoints,
        key=lambda e: (-e.out_degree, -result.file_pr.get(e.file, 0.0), e.file),
    )
    main_entries = [e for e in all_entries if e.out_degree > 0]
    leaf_entries = [e for e in all_entries if e.out_degree == 0]

    entries = main_entries or all_entries
    # ---- 契约层：紧跟入口之后 ----
    # 实测 Knowledge Loop：core/core/knowledge-repository.ts（只读接口）、
    # src/shared/desktop-api.ts（类型契约）在向下 BFS 里到不了——
    # 它们不是入口的依赖，而是「被依赖方」，方向相反。
    #
    # 判据（两条同时满足，避免把普通工具模块误判为契约层）：
    #   1. 向下依赖为 0（自己不依赖别人）
    #   2. 向上依赖 ≥ 2（被多个模块依赖）
    #   3. 文件里有 interface / type 声明（真正的契约形态）
    #
    # **位置很重要**：契约层是理解架构的骨架（"这个项目有哪些接口"），
    # 必须在细节之前。若放到末尾，30 个位置早已被 BFS 占满。
    contract_layer = [
        f for f in result.dependents
        if not result.dependencies.get(f)
        and len(result.dependents.get(f, ())) >= 2
        and _has_contract_shape(result, f)
    ]
    contract_sorted = sorted(
        contract_layer,
        key=lambda x: (-len(result.dependents.get(x, ())), -pr.get(x, 0.0), x),
    )

    ordered: list[tuple[str, str, int]] = []
    seen: set[str] = set()

    # 第 0 层：应用入口
    for e in entries:
        if e.file in seen:
            continue
        seen.add(e.file)
        role = _role_of(result, e.file)
        ordered.append((e.file, f"入口·{role}" if role != "core" else "入口", 0))

    # 第 1 层：契约层（接口 / 类型契约）
    for f in contract_sorted:
        if f in seen or len(ordered) >= max_items:
            continue
        seen.add(f)
        ordered.append((f, f"契约层·{_role_of(result, f)}", 1))

    # ---- BFS 展开依赖 ----
    # 同一层内先收集所有候选，再统一按 PR 排序入队
    frontier = deque(seen)
    depth = 0
    while frontier and depth < max_depth and len(ordered) < max_items:
        depth += 1
        layer_candidates: set[str] = set()
        for f in list(frontier):
            for dep in result.dependencies.get(f, ()):
                if dep not in seen:
                    layer_candidates.add(dep)
        # 层内按 PR 降序
        for dep in sorted(
            layer_candidates,
            key=lambda x: (-pr.get(x, 0.0), x),
        ):
            if dep in seen or len(ordered) >= max_items:
                continue
            seen.add(dep)
            role = _role_of(result, dep)
            ordered.append((dep, role, depth))
            frontier.append(dep)

    # ---- 兜底：BFS 覆盖不到的（孤立模块 / 叶子层 UI）----
    # 这些文件可能既不 import 也不被 import（PageRank 给分极低），
    # 但常常是必读的（路由层、UI 入口）。按 PR 补在末尾。
    for f, _ in result.top_files(max_items * 2):
        if f in seen or len(ordered) >= max_items:
            continue
        seen.add(f)
        ordered.append((f, _role_of(result, f), -1))

    # 叶子层入口（出度 0）单独放在最后——它们是"界面侧"的起点，
    # 不是"内核"的起点，但读懂了内核后确实要看它们。
    for e in leaf_entries:
        if e.file in seen:
            continue
        seen.add(e.file)
        ordered.append((e.file, f"界面入口·{_role_of(result, e.file)}", -1))

    return ordered[:max_items]


def render_reading_order(
    result: IndexResult, max_depth: int = 4, max_items: int = 30
) -> str:
    """渲染阅读顺序为可读文本。"""
    lines = ["推荐阅读顺序（从入口沿依赖展开）:"]
    for i, (f, label, depth) in enumerate(
        reading_order(result, max_depth, max_items), 1
    ):
        indent = "  " + "  " * max(depth, 0)
        if depth < 0:
            marker = "·"
        else:
            marker = f"L{depth}"
        lines.append(f"  {i:>2}. {indent}{marker} {f}  [{label}]")
    return "\n".join(lines)
