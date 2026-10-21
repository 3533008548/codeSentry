"""内容指纹计算。

v0.1 决策 5：**基线必须用内容指纹，禁用行号**。

为什么：
    用 file:line 做 key，在文件头插入 3 行 import 后，基线里全部问题
    都会变成"新增"，门禁疯狂误报，一周内必然被关掉。

    指纹 = sha1(rule_id + normalized_symbol + normalized_snippet)
    行号只作为展示信息，不参与匹配。
"""
from __future__ import annotations

import hashlib
import re

# 归一化：折叠空白、去掉注释行
_COMMENT_RE = re.compile(r"(?m)^\s*(#|//|/\*|\*).*$")
_BLANK_RE = re.compile(r"\n\s*\n")
_WS_RE = re.compile(r"[ \t]+")


def normalize_snippet(snippet: str, max_lines: int = 12) -> str:
    """归一化代码片段。

    去掉整行注释、折叠空白、丢弃空行、截断到前 N 行。
    目的是让"格式变化"与"注释变化"不改变指纹。
    """
    if not snippet:
        return ""
    text = _COMMENT_RE.sub("", snippet)
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    text = "\n".join(lines[:max_lines])
    text = _WS_RE.sub(" ", text)
    return text


def compute_fingerprint(
    rule_id: str,
    symbol_name: str | None,
    snippet: str,
    max_lines: int = 12,
) -> str:
    """计算内容指纹。

    Args:
        rule_id: 规则标识，决定"哪条规则触发"
        symbol_name: 符号名（限定名或裸名）
        snippet: 该符号的代码片段
        max_lines: 参与哈希的最大行数

    Returns:
        `sha1:xxxxxxxx` 形式的指纹
    """
    norm_sym = (symbol_name or "").strip()
    norm_snip = normalize_snippet(snippet, max_lines)
    payload = f"{rule_id}\x00{norm_sym}\x00{norm_snip}".encode("utf-8")
    return "sha1:" + hashlib.sha1(payload).hexdigest()


def content_hash(text: str) -> str:
    """文件内容哈希，用于增量缓存失效判断。"""
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()
