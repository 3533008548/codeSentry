"""增量缓存的单测。"""
import json
from pathlib import Path

from codesentry.core.symbol import (
    CallSite,
    FileMeta,
    Language,
    Symbol,
    SymbolKind,
)
from codesentry.index.cache import (
    CACHE_VERSION,
    FileCacheEntry,
    ParseCache,
    default_cache_dir,
    hash_content,
)


def _entry(path: str, h: str) -> FileCacheEntry:
    return FileCacheEntry(
        path=path,
        content_hash=h,
        mtime=1.0,
        symbols=[Symbol(qname=f"{path}::f", name="f", kind=SymbolKind.FUNCTION,
                       file=path, line=1, end_line=5)],
        calls=[CallSite(caller_qname=f"{path}::f", callee_name="g",
                        file=path, line=3)],
        imports={"os": ["getenv"]},
        meta=FileMeta(path=path, language=Language.PYTHON).model_dump(),
    )


def test_内容哈希一致时命中(tmp_path: Path):
    c = ParseCache(tmp_path)
    c.put(_entry("a.py", "h1"))
    got = c.get("a.py", "h1")
    assert got is not None, "哈希一致应命中"
    assert c.stats["hits"] == 1


def test_内容哈希不一致时不命中(tmp_path: Path):
    c = ParseCache(tmp_path)
    c.put(_entry("a.py", "h1"))
    got = c.get("a.py", "h2")
    assert got is None, "哈希不一致必须重解析"
    assert c.stats["misses"] == 1


def test_未缓存的文件不命中(tmp_path: Path):
    c = ParseCache(tmp_path)
    assert c.get("new.py", "h1") is None


def test_禁用缓存时不命中(tmp_path: Path):
    c = ParseCache(tmp_path, enabled=False)
    c.put(_entry("a.py", "h1"))
    assert c.get("a.py", "h1") is None


def test_存盘后能读回(tmp_path: Path):
    c = ParseCache(tmp_path, cache_dir=tmp_path / "cache")
    c.put(_entry("a.py", "h1"))
    assert c.save()

    c2 = ParseCache(tmp_path, cache_dir=tmp_path / "cache")
    c2.load()
    got = c2.get("a.py", "h1")
    assert got is not None
    assert got.symbols[0].qname == "a.py::f"
    assert got.imports["os"] == {"getenv"}


def test_版本不匹配时缓存作废(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "parse_cache.json").write_text(
        json.dumps({"version": CACHE_VERSION + 1, "files": [
            _entry("a.py", "h1").to_dict()
        ]}),
        encoding="utf-8",
    )
    c = ParseCache(tmp_path, cache_dir=cache_dir)
    c.load()
    assert c.get("a.py", "h1") is None, "版本不匹配必须整体作废"


def test_损坏的缓存文件不报错(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "parse_cache.json").write_text("{ 坏文件", encoding="utf-8")
    c = ParseCache(tmp_path, cache_dir=cache_dir)
    c.load()  # 不应抛异常
    assert c.get("a.py", "h1") is None


def test_清理已删除文件的条目(tmp_path: Path):
    c = ParseCache(tmp_path, cache_dir=tmp_path / "cache")
    c.put(_entry("a.py", "h1"))
    c.put(_entry("b.py", "h2"))
    removed = c.prune({"a.py"})
    assert removed == 1
    assert c.get("b.py", "h2") is None
    assert c.get("a.py", "h1") is not None


def test_默认缓存目录不在项目内(tmp_path: Path):
    """工具不该在被审查项目里留垃圾。"""
    d = default_cache_dir(tmp_path)
    assert tmp_path not in d.parents or d.is_relative_to(tmp_path) is False
    assert "codesentry" in str(d)


def test_hash_content_稳定():
    assert hash_content("abc") == hash_content("abc")
    assert hash_content("abc") != hash_content("abd")
