"""阅读顺序推导的单测。

这是场景 A 最值钱的产出，逻辑必须可测。
"""
from codesentry.core.policy import Policy
from codesentry.core.symbol import (
    FileMeta,
    Language,
    Symbol,
    SymbolKind,
)
from codesentry.index.builder import IndexResult
from codesentry.index.entrypoint import EntryPoint
from codesentry.index.roles import RoleLabel
from codesentry.output.reading_order import reading_order


def _sym(name: str, file: str, kind=SymbolKind.FUNCTION) -> Symbol:
    return Symbol(qname=f"{file}::{name}", name=name, kind=kind,
                  file=file, line=1, end_line=10)


def _meta(path: str) -> FileMeta:
    return FileMeta(path=path, language=Language.PYTHON, lines=100)


def _build() -> IndexResult:
    """构造一个小项目：
        main.py        （入口）→ core.py, api.py
        core.py        （核心）→ base.py
        api.py         （路由，无向下依赖）
        base.py        （底层）
        contract.ts    （接口，被 api 依赖）
    """
    r = IndexResult(root="/tmp/proj")
    files = [
        "main.py", "core.py", "api.py", "base.py", "contract.ts",
        "orphan.py",
    ]
    for f in files:
        r.files.append(_meta(f))
        r.roles[f] = RoleLabel("core", 0.2)

    r.symbols = [
        _sym("main", "main.py"),
        _sym("core_fn", "core.py"),
        _sym("api_handler", "api.py"),
        _sym("base_fn", "base.py"),
        _sym("Contract", "contract.ts", SymbolKind.INTERFACE),
    ]

    r.entrypoints = [EntryPoint("main.py", "app", "测试", out_degree=2)]
    r.dependencies = {
        "main.py": {"core.py", "api.py"},
        "core.py": {"base.py"},
        "api.py": set(),
        "base.py": set(),
        "contract.ts": set(),
    }
    r.dependents = {
        "core.py": {"main.py"},
        "api.py": {"main.py"},
        "base.py": {"core.py"},
        # 契约层判据要求「向上依赖 ≥ 2」，所以让两个模块依赖它
        "contract.ts": {"api.py", "core.py"},
    }
    r.file_pr = {
        "main.py": 0.02, "core.py": 0.05, "api.py": 0.03,
        "base.py": 0.01, "contract.ts": 0.005, "orphan.py": 0.04,
    }
    r.reverse_refs = {"core.py": {"main.py"}, "api.py": {"main.py"}}
    return r


def test_入口排在最前():
    r = _build()
    order = reading_order(r, max_items=10)
    assert order[0][0] == "main.py"
    assert order[0][2] == 0


def test_依赖按层展开():
    r = _build()
    order = reading_order(r, max_items=10)
    depth = {f: d for f, _, d in order}
    # core.py 是 main.py 的直接依赖 → 深度 1
    assert depth["core.py"] == 1
    # base.py 是 core.py 的依赖 → 深度 2
    assert depth["base.py"] == 2


def test_契约层紧跟入口():
    """契约层（无向下依赖、有向上依赖、含 interface）应排在 BFS 细节之前。"""
    r = _build()
    order = reading_order(r, max_items=10)
    files = [f for f, _, _ in order]
    assert "contract.ts" in files
    # 契约层应在 base.py（深度 2 的实现细节）之前
    assert files.index("contract.ts") < files.index("base.py")


def test_孤立模块兜底进榜():
    r = _build()
    order = reading_order(r, max_items=10)
    files = [f for f, _, _ in order]
    assert "orphan.py" in files, "BFS 到不了的模块应按 PR 兜底补入"


def test_深度为负表示兜底():
    r = _build()
    order = reading_order(r, max_items=10)
    depth = {f: d for f, _, d in order}
    assert depth["orphan.py"] == -1


def test_不重复():
    r = _build()
    order = reading_order(r, max_items=20)
    files = [f for f, _, _ in order]
    assert len(files) == len(set(files))


def test_出度为0的入口不进第0层():
    """叶子入口（渲染层）不应作为阅读起点。"""
    r = _build()
    r.entrypoints = [
        EntryPoint("main.py", "app", "测试", out_degree=2),
        EntryPoint("api.py", "app", "测试", out_degree=0),
    ]
    order = reading_order(r, max_items=10)
    depth = {f: d for f, _, d in order}
    assert depth["api.py"] != 0, "出度 0 的入口不应占第 0 层"


def test_空项目不崩():
    r = IndexResult(root="/tmp/empty")
    order = reading_order(r, max_items=10)
    assert order == []
