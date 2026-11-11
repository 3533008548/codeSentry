"""A complete reading route with evidenced roots and honest graph distances.

Breadth-first search computes distances independently of presentation. A
priority window never turns a factory or familiar filename into a startup root.
"""
from __future__ import annotations

from collections import deque

from codesentry.core.symbol import Language, SymbolKind
from codesentry.index.builder import IndexResult


def _role_of(result: IndexResult, file: str) -> str:
    role = result.roles.get(file)
    return role.role if role and role.role != '-' else 'core'


def _has_contract_shape(result: IndexResult, file: str) -> bool:
    symbols = result.symbols_of(file)
    contracts = sum(symbol.kind in {SymbolKind.INTERFACE, SymbolKind.TYPE_ALIAS, SymbolKind.ENUM}
                    for symbol in symbols)
    implementations = sum(symbol.kind in {SymbolKind.FUNCTION, SymbolKind.METHOD} for symbol in symbols)
    return contracts > 0 and implementations <= contracts + 2


def reading_order(result: IndexResult, max_depth: int = 4,
                  max_items: int = 30) -> list[tuple[str, str, int]]:
    """Return every eligible production file once.

    max_items is a priority-window budget, not complete-list truncation.
    Depth is the shortest dependency distance from a declared/static process or
    mount. -1 means not reached within max_depth. Zero depth is valid.
    """
    if type(max_depth) is not int or max_depth < 0:
        raise ValueError('阅读展开深度必须是非负整数')
    if type(max_items) is not int or max_items <= 0:
        raise ValueError('优先阅读数量必须是正整数')
    available = {meta.path for meta in result.files
                 if meta.is_production and not meta.is_data and meta.language is not Language.UNKNOWN}
    if not available:
        return []
    pr = result.file_pr
    graph = {file: (set(result.dependencies.get(file, ())) & available) - {file}
             for file in available}
    by_score = lambda file: (-pr.get(file, 0.0), file)
    entries = [entry for entry in result.entrypoints if entry.file in available and entry.level != 'script']
    kind_order = {'process': 0, 'mount': 1}
    strong = sorted(
        (entry for entry in entries
         if getattr(entry, 'kind', 'candidate') in kind_order
         and getattr(entry, 'confidence', 'heuristic') in {'declared', 'static'}),
        key=lambda entry: (kind_order[entry.kind], entry.confidence != 'declared',
                           -len(graph[entry.file]), *by_score(entry.file)),
    )
    roots = list(dict.fromkeys(entry.file for entry in strong))
    root_kinds = {}
    for entry in strong:
        root_kinds.setdefault(entry.file, entry.kind)

    # Discovery and display have separate visited sets. Deferring a file must
    # not cause a direct dependency to acquire depth 2 or 3.
    distances = {file: 0 for file in roots}
    queue = deque(roots)
    while queue:
        file = queue.popleft()
        if distances[file] >= max_depth:
            continue
        for dependency in sorted(graph[file]):
            if dependency not in distances:
                distances[dependency] = distances[file] + 1
                queue.append(dependency)

    hints = {}
    hint_order = {'assembly': 0, 'bridge': 1, 'candidate': 2}
    for entry in sorted(entries, key=lambda item: (hint_order.get(getattr(item, 'kind', 'candidate'), 3), item.file)):
        hints.setdefault(entry.file, getattr(entry, 'kind', 'candidate'))

    def reachable(start, limit=None):
        seen = {start: 0}
        pending = deque([start])
        while pending:
            current = pending.popleft()
            if limit is not None and seen[current] >= limit:
                continue
            for dependency in sorted(graph[current]):
                if dependency not in seen:
                    seen[dependency] = seen[current] + 1
                    pending.append(dependency)
        return seen

    # A missing launch declaration must not hide another application branch.
    # These are presentation anchors only: they never contribute root distance.
    # Directed coverage matters; two branches can share a contract without one
    # being reachable from the other's mount.
    covered = set().union(*(set(reachable(root)) for root in roots)) if roots else set()
    candidates = sorted(
        {entry.file for entry in entries
         if entry.kind in {'assembly', 'bridge'}
         and entry.confidence in {'declared', 'static'}
         and entry.file not in covered},
        key=lambda file: (hint_order.get(hints[file], 3), -len(graph[file]), *by_score(file)),
    )
    reach = {file: set(reachable(file)) for file in candidates}
    anchors = []
    for file in candidates:
        # Select a source component in the anchor reachability graph. Downstream
        # factories are explored from its upstream factory, while cycles have
        # one deterministic representative. A high rank cannot reverse this.
        if any(file in reach[other] and other not in reach[file]
               for other in candidates if other != file):
            continue
        if any(file in reach[chosen] for chosen in anchors):
            continue
        anchors.append(file)
    ordered = []
    displayed = set()

    def append(file, label=None):
        if file in displayed:
            return
        role = _role_of(result, file)
        if label is None:
            if file in root_kinds:
                label = '进程入口' if root_kinds[file] == 'process' else '界面挂载'
            elif file in hints:
                label = {'assembly': '应用装配', 'bridge': '桥接上下文'}.get(hints[file], '入口候选')
            else:
                label = role
        if label != role and role != 'core':
            label += f'·{role}'
        ordered.append((file, label, distances.get(file, -1)))
        displayed.add(file)

    for file in roots:
        append(file)
    for file in anchors:
        append(file)

    branch_distances = [reachable(file, max_depth) for file in roots + anchors]
    direct_branches = sum(any(value == 1 and file not in displayed
                              for file, value in branch.items())
                          for branch in branch_distances)

    # Shared contracts may precede detail, but cannot consume the entire
    # remaining priority window or become fictitious BFS roots.
    contracts = [file for file in available - displayed
                 if not graph[file]
                 and len(set(result.dependents.get(file, ())) & available) >= 2
                 and _has_contract_shape(result, file)]
    contracts.sort(key=lambda file: (-len(set(result.dependents.get(file, ())) & available), *by_score(file)))
    contract_budget = max(0, (max_items - len(ordered) - direct_branches) // 3)
    for file in contracts[:contract_budget]:
        append(file, '契约层')

    layers = {
        depth: [deque(sorted((file for file, value in branch.items()
                              if value == depth and file not in displayed), key=by_score))
                for branch in branch_distances]
        for depth in range(1, max_depth + 1)
    }
    for depth in range(1, max_depth + 1):
        remaining = max(0, max_items - len(ordered))
        if not remaining:
            break
        branches = layers[depth]
        future = any(any(layers[later]) for later in range(depth + 1, max_depth + 1))
        quota = max(1, (remaining * 2) // 3) if future else remaining
        # Give each represented branch its first turn when capacity permits;
        # a depth quota or an early contract must not consume those seats.
        quota = min(remaining, max(quota, sum(bool(branch) for branch in branches)))
        taken = 0
        while taken < quota and any(branches):
            for branch in branches:
                while branch and branch[0] in displayed:
                    branch.popleft()
                if branch:
                    append(branch.popleft())
                    taken += 1
                if taken >= quota:
                    break

    # Complete means complete, including disconnected and low-rank files.
    for file in sorted(available - displayed, key=by_score):
        append(file)
    return ordered


def render_reading_order(result: IndexResult, max_depth: int = 4,
                         max_items: int = 30) -> str:
    lines = ['推荐阅读顺序（入口与装配线索优先，沿各分支静态依赖展开）:',
             '层级为距入口的最短依赖距离；·表示未在展开深度内到达，优先窗口不截断完整清单。']
    for index, (file, label, depth) in enumerate(reading_order(result, max_depth, max_items), 1):
        marker = f'L{depth}' if depth >= 0 else '·'
        indent = '  ' + '  ' * max(depth, 0)
        lines.append(f'  {index:>2}. {indent}{marker} {file}  [{label}]')
    return '\n'.join(lines)
