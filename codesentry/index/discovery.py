"""文件发现与排除规则。

v0.2 修订：**两类排除，用途不同，不可混为一谈**。

  ① 不解析（not_parsed）           —— 不是源码，解析即浪费
  ② 不参与重要度排序（not_ranked） —— 是源码但不是产品架构的一部分

实测依据：
  - research_agent 的 runtime/ 含 465 个 .py、175,589 行，占全仓 Python
    行数 80%，但一行都不是项目代码（论文库、实验产物、临时文件）
  - scripts/ evals/ 是源码，但它们的 __main__ 守卫会命中 entry 角色规则，
    把重要度排序搅乱
"""
from __future__ import annotations

import os
from pathlib import Path

from codesentry.core.policy import ExcludeConfig
from codesentry.access import AccessPolicy


def _parts(rel_path: str) -> list[str]:
    """拆路径片段。

    注意：必须先统一分隔符再 split。Windows 上 os.sep 是 "\\"，
    而 relpath 返回的也是 "\\"，若先 replace 成 "/" 再 split(os.sep)
    永远切不开（v0.2 已记录的 Windows 专属陷阱）。
    """
    return rel_path.replace("\\", "/").split("/")


def classify(
    rel_path: str, cfg: ExcludeConfig
) -> tuple[bool, bool, bool, bool]:
    """判定一个文件。

    Returns:
        (is_data, is_not_parsed, is_script, is_test)
    """
    parts = _parts(rel_path)
    dirs = parts[:-1]
    name = parts[-1]

    is_data = any(d in cfg.not_parsed for d in dirs)
    is_not_parsed = is_data

    is_script = any(d in cfg.not_ranked for d in dirs)
    # 测试判定独立于 not_ranked —— tests/ 目录在 not_ranked 里，
    # 但「是否测试」需要单独判断，否则统计里测试符号会显示为 0。
    is_test = (
        "tests" in dirs or "test" in dirs
        or name.startswith("test_") or name.endswith("_test.py")
        or name.endswith(".test.ts") or name.endswith(".test.tsx")
        or name.endswith(".spec.ts") or name.endswith(".spec.tsx")
        or name.startswith("conftest")
    )
    return is_data, is_not_parsed, is_script, is_test


def discover(
    root: Path, cfg: ExcludeConfig, issues: list[dict] | None = None,
    access: AccessPolicy | None = None,
) -> list[tuple[Path, str, str]]:
    """扫描项目，返回 [(绝对路径, 相对路径, 后缀)]。

    相对路径统一用 "/" 分隔（跨平台一致）。
    """
    out: list[tuple[Path, str, str]] = []
    exts = tuple(cfg.extensions)

    root = root.resolve()
    access = access or AccessPolicy(root)
    if access.root != root:
        raise ValueError('访问策略不属于当前项目')
    def on_error(error: OSError) -> None:
        if issues is not None:
            issues.append({'file': str(error.filename), 'status': 'discovery_failed',
                           'message': str(error)[:500]})

    def is_link(path: Path) -> bool:
        return path.is_symlink() or getattr(path, 'is_junction', lambda: False)()

    for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
        if issues is not None:
            for directory_name in dirnames:
                directory_relative = (Path(dirpath) / directory_name).relative_to(root).as_posix()
                if (directory_name not in cfg.not_parsed and not directory_name.startswith('.')
                        and access.decision(directory_relative, is_dir=True)['mode'] == 'exclude'):
                    issue = {'file': directory_relative, 'status': 'access_scope_limited',
                             'message': '该目录受文件访问范围限制，未读取内容'}
                    if issue not in issues:
                        issues.append(issue)
        # 原地裁剪，避免走进不解析的目录
        dirnames[:] = sorted([
            d for d in dirnames
            if d not in cfg.not_parsed and not d.startswith(".")
            and not is_link(Path(dirpath) / d)
            and access.decision((Path(dirpath) / d).relative_to(root).as_posix(), is_dir=True)['mode'] != 'exclude'
        ])
        for fn in sorted(filenames):
            if not fn.endswith(exts):
                continue
            abs_path = Path(dirpath) / fn
            if is_link(abs_path):
                if issues is not None:
                    issues.append({'file': str(abs_path.relative_to(root)),
                                   'status': 'source_link_skipped',
                                   'message': '链接源文件不属于已支持的普通文件范围'})
                continue
            rel = os.path.relpath(abs_path, root).replace("\\", "/")
            decision = access.decision(rel)
            if decision['mode'] == 'exclude':
                if issues is not None and not rel.split('/')[0].startswith('.'):
                    issue = {'file': rel, 'status': 'access_scope_limited', 'message': decision['reason']}
                    if issue not in issues:
                        issues.append(issue)
                continue
            suffix = os.path.splitext(fn)[1]
            out.append((abs_path, rel, suffix))
    return out
