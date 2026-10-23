"""用 GitHub API 重建本地提交历史（高效版）。

## 为什么需要

本地 `git push` 走不通（代理只允许 api.github.com），用 Git Data API
只能创建**单个快照提交**——本地 8 个提交的开发过程丢失了。

对求职项目来说，**提交历史本身就是叙事**：它展示"怎么一步步想清楚
并推翻错误方案"，比最终代码更有说服力。

## 关键技巧：tree API 支持内联 content

GitHub 的 `POST /git/trees` 接受 tree 条目里直接带 `content`
（不必先建 blob）：

    {"tree": [{"path": "a.py", "mode": "100644", "type": "blob",
               "content": "..."}]}

于是每个提交只需 **2 次 API 调用**（tree + commit），
而不是「N 个 blob + 1 个 tree + 1 个 commit」。

第一版脚本逐个 GET 探测 blob 是否存在，376 次调用直接超时。

## 注意

commit sha 会与本地不同（GitHub 重算 sha 时会加签名等元数据），
但**提交内容、顺序、消息、作者、时间完全一致**。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def run(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"命令失败: {' '.join(args)}\n{result.stderr[:300]}")
    return result.stdout


def gh(*args: str, input_data: str | None = None,
       method: str | None = None) -> str:
    cmd = ["gh", "api", *args]
    if method:
        cmd += ["--method", method]
    if input_data is not None:
        cmd += ["--input", "-"]
    result = subprocess.run(cmd, input=input_data,
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"gh api 失败: {result.stderr[:500]}")
    return result.stdout


def read_tree_inline(local: Path, sha: str) -> list[dict]:
    """读本地提交的 tree，条目内联文件内容。

    **用 `git archive` 一次导出整个 tree**（0.31s / 47 文件），
    而不是逐个 `git cat-file`（8.4s，因为每次起进程要 180ms）。

    实测踩坑：`git cat-file --batch` 在 Windows 上会挂起等 EOF
    （管道未正常关闭），第一版脚本因此超时。
    """
    import io
    import tarfile

    proc = subprocess.run(
        ["git", "-C", str(local), "archive", "--format=tar", sha],
        capture_output=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git archive 失败: {proc.stderr[:300]}")

    entries: list[dict] = []
    with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            content = fh.read()
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                # 二进制文件：tree API 的 content 不支持 base64，
                # 本项目全是文本文件，跳过即可
                continue
            mode = "100755" if (member.mode & 0o111) else "100644"
            entries.append({
                "path": member.name, "mode": mode, "type": "blob",
                "content": text,
            })
    return entries


def main() -> int:
    repo = sys.argv[1] if len(sys.argv) > 1 else "3533008548/codeSentry"
    local = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else Path.cwd()

    # 1. 本地提交（旧 → 新）
    records = run("git", "-C", str(local), "log", "--reverse",
                  "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%B%x1e")
    commits = []
    for rec in records.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, author, email, date, body = rec.split("\x1f", 4)
        commits.append((sha, author, email, date, body.rstrip("\n")))

    print(f"本地提交 {len(commits)} 个")
    for sha, _, _, _, body in commits:
        print(f"  {sha[:8]} {body.splitlines()[0] if body else ''}")
    print()

    # --fresh：从零开始建链（丢弃之前 API 生成的冗余提交）
    fresh = "--fresh" in sys.argv
    parent: str | None = None
    if not fresh:
        try:
            ref = json.loads(gh(f"repos/{repo}/git/ref/heads/main"))
            parent = ref["object"]["sha"]
            print(f"远程当前: {parent[:8]}")
        except RuntimeError:
            print("远程无 main 分支")
    else:
        print("--fresh：从零建链（丢弃冗余提交）")

    for sha, author, email, date, body in commits:
        entries = read_tree_inline(local, sha)
        tree = json.loads(gh(
            f"repos/{repo}/git/trees",
            input_data=json.dumps({"tree": entries}),
        ))
        payload = {
            "message": body,
            "tree": tree["sha"],
            "author": {"name": author, "email": email, "date": date},
            "committer": {"name": author, "email": email, "date": date},
        }
        if parent:
            payload["parents"] = [parent]
        commit = json.loads(gh(
            f"repos/{repo}/git/commits", input_data=json.dumps(payload)))
        parent = commit["sha"]
        first = body.splitlines()[0] if body else ""
        print(f"  {sha[:8]} → {parent[:8]}  {first}  ({len(entries)} 文件)")

    gh(f"repos/{repo}/git/refs/heads/main",
       input_data=json.dumps({"sha": parent, "force": True}),
       method="PATCH")
    print(f"\n✅ main → {parent[:8]}")

    remote = json.loads(gh(f"repos/{repo}/commits?per_page=30"))
    print(f"\n远程提交数: {len(remote)}")
    for c in reversed(remote):
        msg = c["commit"]["message"].splitlines()[0]
        print(f"  {c['sha'][:8]} {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
