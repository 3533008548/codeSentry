"""V2 keeps complete raw evidence; cache content_hash stays compatible."""
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


def test_改注释改变完整证据指纹():
    a = compute_fingerprint("r", "f.py::f", "def f():\n    return 1\n")
    b = compute_fingerprint("r", "f.py::f", "def f():\n    # 改个注释\n    return 1\n")
    assert a != b, "未证明注释等价时保留完整原文"


def test_改逻辑改变指纹():
    a = compute_fingerprint("r", "f.py::f", "def f():\n    return 1\n")
    b = compute_fingerprint("r", "f.py::f", "def f():\n    return 2\n")
    assert a != b, "逻辑变化必须改变指纹"


def test_改缩进改变完整证据指纹():
    a = compute_fingerprint("r", "f.py::f", "def f():\n    return 1\n")
    b = compute_fingerprint("r", "f.py::f", "def f():\n        return 1\n")
    assert a != b, "raw证据不忽略缩进变化"


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
    assert fp.startswith("v2:sha256:")
    assert len(fp) == len("v2:sha256:") + 64


def test_normalize_保留全部原文():
    text = "# 头部注释\n\ndef f():\n    return 1\n"
    out = normalize_snippet(text)
    assert out == text


def test_content_hash_稳定():
    assert content_hash("abc") == content_hash("abc")
    assert content_hash("abc") != content_hash("abd")
