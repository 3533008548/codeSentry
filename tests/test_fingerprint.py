"""内容指纹的单测。

v0.1 决策 5 的核心保证：插入行、改注释、调格式都不应让基线失效。
"""
from codesentry.core.fingerprint import (
    compute_fingerprint,
    content_hash,
    normalize_snippet,
)


def test_插入行不改变指纹():
    """符号片段内容不变时，指纹必须不变——无论文件前面多了什么。

    这正是它能抵抗"文件头加 import"这类变更的原因：
    指纹只吃符号自身的片段，不吃文件位置或行号。
    """
    fragment = "def f():\n    return 1\n"
    a = compute_fingerprint("complexity.function_length", "f.py::f", fragment)
    b = compute_fingerprint("complexity.function_length", "f.py::f", fragment)
    assert a == b, "相同片段必须产出相同指纹"

    # 片段前的内容被切掉后，指纹不受行号位移影响
    file_before = "import json\ndef f():\n    return 1\n"
    file_after = "import json\nimport os\nimport sys\ndef f():\n    return 1\n"
    fa = compute_fingerprint(
        "complexity.function_length", "f.py::f",
        file_before[file_before.index("def f()"):])
    fb = compute_fingerprint(
        "complexity.function_length", "f.py::f",
        file_after[file_after.index("def f()"):])
    assert fa == fb, "文件头插入 import 后，符号片段的指纹必须不变"


def test_符号内部插入行改变指纹():
    """片段内部插入代码，指纹必须变。"""
    a = compute_fingerprint("r", "f.py::f", "def f():\n    return 1\n")
    b = compute_fingerprint("r", "f.py::f", "def f():\n    x = 1\n    return 1\n")
    assert a != b, "符号内部新增代码必须改变指纹"


def test_改注释不改变指纹():
    a = compute_fingerprint("r", "f.py::f", "def f():\n    return 1\n")
    b = compute_fingerprint("r", "f.py::f", "def f():\n    # 改个注释\n    return 1\n")
    assert a == b, "整行注释变化不应改变指纹"


def test_改逻辑改变指纹():
    a = compute_fingerprint("r", "f.py::f", "def f():\n    return 1\n")
    b = compute_fingerprint("r", "f.py::f", "def f():\n    return 2\n")
    assert a != b, "逻辑变化必须改变指纹"


def test_改缩进不改变指纹():
    a = compute_fingerprint("r", "f.py::f", "def f():\n    return 1\n")
    b = compute_fingerprint("r", "f.py::f", "def f():\n        return 1\n")
    assert a == b, "缩进变化不应改变指纹"


def test_不同规则指纹不同():
    a = compute_fingerprint("rule_a", "f.py::f", "x = 1\n")
    b = compute_fingerprint("rule_b", "f.py::f", "x = 1\n")
    assert a != b, "不同规则必须产出不同指纹"


def test_不同符号指纹不同():
    a = compute_fingerprint("r", "f.py::a", "x = 1\n")
    b = compute_fingerprint("r", "f.py::b", "x = 1\n")
    assert a != b, "不同符号必须产出不同指纹"


def test_指纹格式():
    fp = compute_fingerprint("r", "s", "x = 1\n")
    assert fp.startswith("sha1:")
    assert len(fp) == len("sha1:") + 40


def test_normalize_丢弃空行与块注释():
    text = "# 头部注释\n\ndef f():\n    return 1\n"
    out = normalize_snippet(text)
    assert "头部注释" not in out
    assert "return 1" in out
    assert "\n\n" not in out


def test_content_hash_稳定():
    assert content_hash("abc") == content_hash("abc")
    assert content_hash("abc") != content_hash("abd")
