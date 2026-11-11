"""A local-only, testable future model-input boundary. No network transport."""
from __future__ import annotations

import re
from codesentry.access.policy import AccessDenied, AccessPolicy

SECRET = re.compile(r"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:api[_-]?key|secret|access[_-]?token|password)\b\s*[:=]\s*['\"]?[^\s'\"]{8,}|\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})\b)", re.I)


def prepare_model_input(policy: AccessPolicy, paths: list[str], *, service: str,
                        purpose: str, authorized: bool = False, derived: list[dict] | None = None) -> dict:
    """Read permitted sources afresh; refuse mixed/unknown historical provenance."""
    if authorized is not True or not isinstance(service, str) or not isinstance(purpose, str) or not service.strip() or not purpose.strip():
        raise AccessDenied("模型服务、用途及范围尚未授权")
    policy.refresh()
    fingerprint = policy.fingerprint
    if not paths or len(paths) > 64 or len(set(paths)) != len(paths):
        raise ValueError("模型输入需要1到64个明确且不重复的来源文件")
    for path in paths:
        if policy.decision(path)["mode"] != "model_eligible":
            raise AccessDenied("模型输入包含完全排除或仅限本地来源")
    if derived:
        # A raw dictionary cannot prove its own provenance. Until trusted
        # derived producers exist, only freshly read eligible source is sent.
        raise AccessDenied("衍生信息尚无可信来源凭据，不能通过自报来源进入模型")
    sources = []
    total_bytes = 0
    for path in paths:
        text = policy.read_text(path, limit=2 * 1024 * 1024)
        total_bytes += len(text.encode('utf-8'))
        if total_bytes > 8 * 1024 * 1024:
            raise ValueError('模型输入超过8MiB上限')
        if SECRET.search(text):
            raise AccessDenied("候选内容包含疑似秘密，模型发送已阻止")
        sources.append({"path": path, "content": text})
    for item in derived or []:
        if SECRET.search(str(item.get("content", ""))):
            raise AccessDenied("衍生信息包含疑似秘密，模型发送已阻止")
    if fingerprint != policy.fingerprint:
        raise AccessDenied("构建模型输入期间权限已变化")
    return {"service": service, "purpose": purpose, "sources": sources,
            "derived": list(derived or []), "access_fingerprint": fingerprint,
            "transport": "not_implemented"}
