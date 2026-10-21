"""排除规则与发现逻辑的单测。

v0.2 修订：排除分两类，用途不同。
"""
from codesentry.core.policy import ExcludeConfig
from codesentry.index.discovery import _parts, classify


def test_parts_统一分隔符():
    """Windows 陷阱：先 replace 再 split(os.sep) 永远切不开。"""
    assert _parts("a\\b\\c.py") == ["a", "b", "c.py"]
    assert _parts("a/b/c.py") == ["a", "b", "c.py"]


def test_数据目录不解析():
    cfg = ExcludeConfig()
    is_data, not_parsed, _, _ = classify("runtime/primary/papers/x.py", cfg)
    assert is_data and not_parsed, "runtime/ 应被判定为数据目录"


def test_脚本目录参与解析但不参与排序():
    cfg = ExcludeConfig()
    is_data, not_parsed, is_script, is_test = classify("scripts/run_eval.py", cfg)
    assert not not_parsed, "scripts/ 应参与解析"
    assert is_script, "scripts/ 应标记为脚本"


def test_测试目录判定独立于not_ranked():
    """tests/ 在 not_ranked 里，但 is_test 必须能独立判定。"""
    cfg = ExcludeConfig()
    _, not_parsed, is_script, is_test = classify("tests/test_core.py", cfg)
    assert not not_parsed
    assert is_script
    assert is_test, "tests/ 下的文件必须被判定为测试"


def test_测试文件命名模式():
    cfg = ExcludeConfig()
    _, _, _, is_test = classify("src/test_helper.py", cfg)
    assert is_test
    _, _, _, is_test2 = classify("src/foo_test.py", cfg)
    assert is_test2


def test_普通生产文件():
    cfg = ExcludeConfig()
    is_data, not_parsed, is_script, is_test = classify("core/knowledge/x.py", cfg)
    assert not is_data and not not_parsed and not is_script and not is_test


def test_嵌套目录判定():
    cfg = ExcludeConfig()
    _, not_parsed, _, _ = classify("a/b/runtime/primary/x.py", cfg)
    assert not_parsed, "任意层级的 runtime/ 都应被排除"
