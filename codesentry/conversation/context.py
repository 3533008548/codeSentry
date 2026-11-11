"""Bounded local retrieval. Only model-eligible sources enter cloud context."""
from __future__ import annotations

import hashlib
import io
import re
import tokenize
from pathlib import PurePosixPath

from codesentry.access import AccessDenied
from codesentry.workspaces.files import list_files


MAX_SOURCES = 4
MAX_SOURCE_BYTES = 12288
MAX_SCAN_BYTES = 512 * 1024
MAX_FILE_BYTES = 128 * 1024
MAX_EXCERPT_LINES = 100
MAX_EXCERPT_BYTES = 3000


class FunctionContextError(ValueError):
    pass


def source_lines(text):
    # Match Python source positions, including CRLF. A form feed or Unicode
    # separator inside a string is not a physical source line.
    return list(io.StringIO(text, newline=""))


def bounded_excerpt(lines):
    selected, size = [], 0
    for line in lines[:MAX_EXCERPT_LINES]:
        line_bytes = len(line.encode("utf-8"))
        if size + line_bytes > MAX_EXCERPT_BYTES:
            break
        selected.append(line)
        size += line_bytes
    return "".join(selected), len(selected), size


def select_function_context(access, target, *, check_text):
    """Use only the report's verified function span in a focused request."""
    path = target["path"]
    if access.decision(path)["mode"] != "model_eligible":
        raise FunctionContextError("这个函数不在当前模型候选范围内")
    try:
        raw = access.read_bytes(path, limit=MAX_FILE_BYTES)
    except (OSError, ValueError):
        raise FunctionContextError("目标文件无法读取或超过对话取材上限。请核对源码后重新生成 CRAP 报告") from None
    digest = hashlib.sha256(raw).hexdigest()
    if digest != target["sha256"]:
        raise FunctionContextError("目标文件已变化，请重新生成 CRAP 报告后再讨论")
    try:
        encoding = tokenize.detect_encoding(io.BytesIO(raw).readline)[0]
        text = raw.decode(encoding)
        check_text(path + "\n" + text)
    except (OSError, ValueError, SyntaxError, LookupError):
        raise FunctionContextError("目标文件无法安全用于对话，请在源码预览中核对") from None
    lines = source_lines(text)
    start, end = target["start_line"], target["end_line"]
    if not 1 <= start <= end <= len(lines):
        raise FunctionContextError("函数位置无法核对，请重新生成 CRAP 报告")
    excerpt, line_count, size = bounded_excerpt(lines[start - 1:end])
    if not excerpt.strip():
        raise FunctionContextError("目标函数开头超出对话取材上限，请在源码预览中核对")
    last = start + line_count - 1
    return {"files": [path], "sources": [{"path": path, "start_line": start, "end_line": last,
                "source": excerpt, "sha256": digest, "source_id": "S1"}],
            "focus": {"source_id": "S1", "function_end_line": end, "complete": last == end},
            "coverage": {"eligible_files": 1, "scanned_files": 1, "selected_files": 1,
                         "source_bytes": size, "partial": last < end}}


def terms(question):
    words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", question.lower()))
    for chinese, english in (("启动", "main app server cli package pyproject"),
                             ("入口", "main app routes index"), ("结构", "readme main app"),
                             ("任务", "task job queue"), ("保存", "save store repository"),
                             ("权限", "access policy auth"), ("模型", "semantic model chat"),
                             ("测试", "test spec"), ("环境", "config package pyproject requirements")):
        if chinese in question:
            words.update(english.split())
    return words


def select_context(access, data_dir, question, *, selected_path=None, check_text):
    """No target imports, shells or model-directed tools. Report partial coverage."""
    listing = list_files(access.root, access=access, data_dir=data_dir)
    files = [item for item in listing["files"] if item["access_mode"] == "model_eligible"]
    if selected_path and selected_path not in {item["path"] for item in files}:
        raise AccessDenied("当前引用文件不在模型候选范围内，请先调整文件访问范围")
    tokens = terms(question)

    def priority(item):
        path = item["path"].lower()
        name = PurePosixPath(path).name
        score = sum(8 for token in tokens if token in path)
        score += 5 if name in {"readme.md", "pyproject.toml", "package.json", "main.py", "app.py", "main.ts", "main.tsx"} else 0
        score += 1000 if item["path"] == selected_path else 0
        return -score, len(path.split("/")), path

    ranked = sorted(files, key=priority)
    candidates, scanned, skipped = [], 0, 0
    for item in ranked[:64]:
        if item["size"] > MAX_FILE_BYTES or scanned + item["size"] > MAX_SCAN_BYTES:
            skipped += 1
            continue
        path = item["path"]
        try:
            raw = access.read_bytes(path, limit=MAX_FILE_BYTES)
            scanned += len(raw)
            if b"\0" in raw:
                continue
            encoding = tokenize.detect_encoding(io.BytesIO(raw).readline)[0] if path.endswith((".py", ".pyi")) else "utf-8-sig"
            text = raw.decode(encoding)
            check_text(path + "\n" + text)
        except (OSError, ValueError, SyntaxError, UnicodeError, LookupError):
            skipped += 1
            continue
        lines = source_lines(text)
        if not lines:
            continue
        scores = [sum(1 for token in tokens if token in line.lower()) for line in lines]
        anchor = max(range(len(lines)), key=lambda index: scores[index]) if tokens else 0
        start = max(0, anchor - 12) if max(scores, default=0) else 0
        excerpt, line_count, _size = bounded_excerpt(lines[start:start + MAX_EXCERPT_LINES])
        if not excerpt.strip():
            skipped += 1
            continue
        score = -priority(item)[0] + sum(sorted(scores, reverse=True)[:5])
        candidates.append((score, {"path": path, "start_line": start + 1, "end_line": start + line_count,
                                   "source": excerpt, "sha256": hashlib.sha256(raw).hexdigest()}, len(lines)))
    sources, used, partial_excerpt = [], 0, False
    for _score, source, file_lines in sorted(candidates, key=lambda pair: (-pair[0], pair[1]["path"])):
        size = len(source["source"].encode("utf-8"))
        if len(sources) == MAX_SOURCES or used + size > MAX_SOURCE_BYTES:
            break
        sources.append(source | {"source_id": f"S{len(sources) + 1}"})
        used += size
        partial_excerpt |= source["start_line"] != 1 or source["end_line"] != file_lines
    # Filenames are data too. Never include a locally restricted filename in
    # cloud context just to make the repository map look more complete.
    names, name_bytes = [], 0
    for item in ranked[:120]:
        try:
            check_text(item["path"])
            if name_bytes + len(item["path"].encode("utf-8")) > 4096:
                break
            names.append(item["path"])
            name_bytes += len(item["path"].encode("utf-8"))
        except AccessDenied:
            skipped += 1
    return {"files": names, "sources": sources,
            "coverage": {"eligible_files": len(files), "scanned_files": len(candidates),
                         "selected_files": len(sources), "source_bytes": used,
                         "partial": bool(listing["truncated"] or skipped or len(files) > len(sources) or partial_excerpt)}}


def source_digest(access, path):
    if access.decision(path)["mode"] != "model_eligible":
        return None
    try:
        raw = access.read_bytes(path, limit=MAX_FILE_BYTES)
    except (OSError, ValueError):
        return None
    return hashlib.sha256(raw).hexdigest()


def sources_current(access, sources):
    return all(source_digest(access, source["path"]) == source["sha256"] for source in sources)


def answer_dependencies(evidence, *, has_prior_answers):
    """Recover old evidence only when the turn could not have reused history."""
    if "dependencies" in evidence:
        return evidence["dependencies"]
    if evidence.get("crap_target") or not has_prior_answers:
        return evidence.get("sources", [])
    return None
