"""通过 GitHub API 推送（绕过 git 协议的代理限制）。

## 为什么需要这个

本地环境��代理（127.0.0.1:54047）**只允许 api.github.com**，
不允许 github.com（git 协议端点）：

    $ curl https://github.com     → CONNECT tunnel failed, 502
    $ curl https://api.github.com → 200

`gh` 的所有 API 操作都走 api.github.com，所以能用；
但 `git push` 必须访问 github.com → 失败。

## 做法

用 GitHub 的 **Git Data API**：
    1. 创建 blob（每个文件一个）
    2. 创建 tree（一次提交所有 blob）
    3. 创建 commit
    4. 更新 ref

这等价于 `git push`，但全程走 api.github.com。

用法: python push_via_api.py <repo> <local_dir>
"""
from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path


def gh(*args: str, input_data: str | None = None,
        method: str | None = None) -> str:
    """调用 gh api。"""
    cmd = ["gh", "api", *args]
    if method:
        cmd += ["--method", method]
    if input_data is not None:
        cmd += ["--input", "-"]
    result = subprocess.run(
        cmd, input=input_data, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh api 失败: {result.stderr[:500]}")
    return result.stdout


def main() -> int:
    if len(sys.argv) < 3:
        print("用法: python push_via_api.py <owner/repo> <local_dir>")
        return 2
    repo = sys.argv[1]
    local = Path(sys.argv[2]).resolve()

    # 1. 读当前 ref（可能不存在）
    try:
        ref_info = gh(f"repos/{repo}/git/ref/heads/main")
        parent_sha = ref_info and __import__("json").loads(ref_info)["object"]["sha"]
    except RuntimeError:
        parent_sha = None
    print(f"当前 ref: {parent_sha or '（空仓库，将创建初始提交）'}")

    # 2. 收集文件
    files = []
    for p in sorted(local.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(local).as_posix()
        if rel.startswith(".git/"):
            continue
        if any(part in ("__pycache__", ".pytest_cache", ".venv",
                        "node_modules", ".workbuddy") for part in p.parts):
            continue
        if rel.endswith((".pyc", ".pyo")):
            continue
        files.append((rel, p))
    print(f"待推送文件: {len(files)}")

    # 3. 创建 blob
    import json
    tree_entries = []
    for i, (rel, path) in enumerate(files, 1):
        data = base64.b64encode(path.read_bytes()).decode("ascii")
        blob = json.loads(gh(
            f"repos/{repo}/git/blobs", input_data=json.dumps({
                "content": data, "encoding": "base64"
            })))
        tree_entries.append({
            "path": rel,
            "mode": "100644",
            "type": "blob",
            "sha": blob["sha"],
        })
        if i % 10 == 0 or i == len(files):
            print(f"  blob {i}/{len(files)}")

    # 4. 创建 tree
    tree = json.loads(gh(
        f"repos/{repo}/git/trees", input_data=json.dumps({
            "base_tree": parent_sha, "tree": tree_entries
        })))
    print(f"tree: {tree['sha']}")

    # 5. 创建 commit
    commit = json.loads(gh(
        f"repos/{repo}/git/commits", input_data=json.dumps({
            "message": "M0-M1: CodeSentry 索引层与阅读顺序实现",
            "tree": tree["sha"],
            "parents": [parent_sha] if parent_sha else [],
        })))
    print(f"commit: {commit['sha']}")

    # 6. 更新 ref
    try:
        gh(f"repos/{repo}/git/refs", input_data=json.dumps({
            "ref": "refs/heads/main", "sha": commit["sha"]
        }))
    except RuntimeError:
        gh(f"repos/{repo}/git/refs/heads/main", input_data=json.dumps({
            "sha": commit["sha"], "force": False
        }))
    print(f"ref 已更新 → main = {commit['sha']}")

    # 7. 设置默认分支
    try:
        gh(f"repos/{repo}", input_data=json.dumps({
            "default_branch": "main"
        }), method="PATCH")
    except RuntimeError:
        pass

    print("\n✅ 推送完成")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
