"""增量缓存的验证脚本。

关键验证点：
  1. 二次扫描命中缓存，耗时显著下降
  2. 改动一个文件 → 只重解析该文件（其余命中缓存）
  3. 增量结果与全量重建**完全一致**
  4. 缓存不写进被审查项目

用法: python evals/verify_cache.py <project_root> [--keep]
"""
from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codesentry.core.policy import Policy
from codesentry.index.builder import build_index
from codesentry.index.cache import ParseCache, default_cache_dir


def snapshot(r) -> dict:
    """提取可比较的结果快照。"""
    return {
        "files": len(r.files),
        "symbols": len(r.symbols),
        "edges": len(r.edges),
        "file_pr": {k: round(v, 10) for k, v in sorted(r.file_pr.items())},
        "entrypoints": sorted(e.file for e in r.entrypoints),
        "call_stats": dict(sorted(r.call_stats.items())),
    }


def diff(a: dict, b: dict) -> list[str]:
    """比较两个快照的差异。"""
    out = []
    for key in ("files", "symbols", "edges"):
        if a[key] != b[key]:
            out.append(f"{key}: {a[key]} vs {b[key]}")
    if a["file_pr"] != b["file_pr"]:
        diffs = [
            k for k in set(a["file_pr"]) | set(b["file_pr"])
            if a["file_pr"].get(k) != b["file_pr"].get(k)
        ]
        out.append(f"file_pr 差异 {len(diffs)} 个: {diffs[:5]}")
    if a["entrypoints"] != b["entrypoints"]:
        out.append(f"entrypoints: {a['entrypoints']} vs {b['entrypoints']}")
    if a["call_stats"] != b["call_stats"]:
        out.append(f"call_stats: {a['call_stats']} vs {b['call_stats']}")
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python verify_cache.py <project_root>")
        return 2
    src_root = Path(sys.argv[1]).resolve()
    policy = Policy()

    print("=" * 66)
    print(f"增量缓存验证 · {src_root.name}")
    print("=" * 66)

    # ---- 复制到临时目录做改动实验 ----
    #
    # **绝不原地修改被审查项目的文件**。第一版脚本直接写原文件，
    # 结果把用户的 api_server.py 改成了 CRLF/LF 差异（git status 显示 M
    # 但 git diff 为空）。更严重的是：脚本中途崩溃就会把测试代码
    # 留在用户文件里。
    #
    # 复制到临时目录 → 原项目全程只读。
    import shutil
    import tempfile

    workdir = Path(tempfile.mkdtemp(prefix="codesentry_verify_"))
    root = workdir / src_root.name
    shutil.copytree(
        src_root, root,
        ignore=shutil.ignore_patterns(
            ".git", "node_modules", "__pycache__", "runtime", "dist",
            "build", ".venv", "venv", "*.egg-info",
        ),
    )
    print(f"实验副本: {root}")
    print("（原项目只读，绝不修改）")

    # 找一个可写的源文件做改动实验
    target = None
    for p in sorted(root.glob("*.py")):
        if p.stat().st_size > 100:
            target = p
            break
    if target is None:
        print("找不到可测试的 .py 文件")
        shutil.rmtree(workdir, ignore_errors=True)
        return 2

    # **用二进制读写保留原始行尾符**——第一版用 text 模式写回，
    # 把用户的 CRLF 文件改成了 LF，git status 显示 M 但 git diff 为空。
    backup_bytes = target.read_bytes()

    # ---- 1. 冷启动 ----
    t0 = time.perf_counter()
    r1 = build_index(root, policy, refresh=True)
    cold = time.perf_counter() - t0
    print(f"\n[1] 冷启动（refresh）  {cold:.3f}s  "
          f"parse {r1.timings['parse']:.3f}s  缓存 {r1.cache_stats}")

    # ---- 2. 热缓存 ----
    t0 = time.perf_counter()
    r2 = build_index(root, policy)
    warm = time.perf_counter() - t0
    print(f"[2] 热缓存            {warm:.3f}s  "
          f"parse {r2.timings['parse']:.3f}s  缓存 {r2.cache_stats}")
    print(f"    加速比 {cold / warm:.2f}x")

    d = diff(snapshot(r1), snapshot(r2))
    print(f"    冷热一致性: {'✅ 完全一致' if not d else '❌ ' + '; '.join(d)}")

    # ---- 3. 改一个文件 ----
    print(f"\n[3] 改动一个文件: {target.name}")
    try:
        # 二进制追加，保留原始行尾符风格
        nl = b"\r\n" if b"\r\n" in backup_bytes else b"\n"
        target.write_bytes(
            backup_bytes
            + nl + nl
            + b"def _codesentry_probe():" + nl
            + b"    return 1" + nl
        )
        t0 = time.perf_counter()
        r3 = build_index(root, policy)
        incr = time.perf_counter() - t0
        print(f"    增量扫描          {incr:.3f}s  "
              f"parse {r3.timings['parse']:.3f}s  缓存 {r3.cache_stats}")
        expect_hits = len(r2.files) - 1
        ok = r3.cache_stats["hits"] == expect_hits
        print(f"    命中 {r3.cache_stats['hits']} / 期望 {expect_hits}  "
              f"{'✅ 只重解析改动的文件' if ok else '❌'}")

        # ---- 4. 与全量重建对比 ----
        t0 = time.perf_counter()
        r4 = build_index(root, policy, refresh=True)
        full = time.perf_counter() - t0
        print(f"\n[4] 全量重建          {full:.3f}s")
        d = diff(snapshot(r3), snapshot(r4))
        print(f"    增量 vs 全量: {'✅ 完全一致' if not d else '❌ ' + '; '.join(d)}")

        # 新符号是否被检出
        probe = f"{target.name}::_codesentry_probe"
        found = any(s.qname == probe for s in r3.symbols)
        print(f"    新增符号被检出: {'✅' if found else '❌'} ({probe})")
    finally:
        target.write_bytes(backup_bytes)

    # ---- 5. 缓存位置 ----
    print("\n[5] 缓存位置")
    cache_dir = default_cache_dir(root)
    in_project = (root / ".codesentry").exists()
    print(f"    用户缓存目录: {cache_dir}")
    print(f"    项目内缓存:   {'❌ 存在（污染了被审查项目）' if in_project else '✅ 不存在'}")
    print(f"    缓存文件大小: {(cache_dir / 'parse_cache.json').stat().st_size / 1024:.0f} KB"
          if (cache_dir / "parse_cache.json").exists() else "    缓存文件: 无")

    print("\n" + "=" * 66)
    shutil.rmtree(workdir, ignore_errors=True)
    print("实验副本已清理")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
