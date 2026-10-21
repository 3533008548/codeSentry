"""PageRank 的单测。"""
from codesentry.index.pagerank import normalize, pagerank


def test_空图():
    assert pagerank([], []) == {}


def test_单节点():
    r = pagerank(["a"], [])
    assert set(r) == {"a"}
    assert 0 < r["a"] <= 1


def test_被引用的节点排名更高():
    # a 被 b、c 引用；b、c 不被引用
    r = pagerank(
        ["a", "b", "c"],
        [("b", "a"), ("c", "a")],
    )
    assert r["a"] > r["b"], "被引用的节点应排名更高"
    assert r["a"] > r["c"]


def test_重要性沿调用链传播():
    """边 s→d 表示「s 引用 d」，被引用方（更底层）更重要。

    链 x→y→z：x 调 y，y 调 z。z 是最底层、被依赖最多的，应最高。
    """
    r = pagerank(["x", "y", "z"], [("x", "y"), ("y", "z")])
    assert r["z"] > r["y"] > r["x"], "越底层（被引用越多）应越重要"


def test_自环被忽略():
    r = pagerank(["a", "b"], [("a", "a"), ("b", "a")])
    assert r["a"] > r["b"]


def test_悬挂节点不崩溃():
    # c 没有出边（悬挂节点）
    r = pagerank(["a", "b", "c"], [("a", "b")])
    assert len(r) == 3
    assert all(v > 0 for v in r.values())


def test_收敛稳定():
    edges = [("a", "b"), ("b", "c"), ("c", "a"), ("x", "b")]
    r1 = pagerank(["a", "b", "c", "x"], edges)
    r2 = pagerank(["a", "b", "c", "x"], edges)
    assert r1 == r2, "同样输入必须产出同样结果（可复现）"


def test_normalize():
    out = normalize({"a": 10.0, "b": 5.0, "c": 0.0}, ["a", "b", "c"])
    assert out["a"] == 1.0
    assert out["b"] == 0.5
    assert out["c"] == 0.0


def test_normalize_全零():
    out = normalize({"a": 0.0}, ["a"])
    assert out["a"] == 0.0
