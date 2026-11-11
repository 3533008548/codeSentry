"""Strict warning data from an untrusted model; never Finding credentials."""
from __future__ import annotations

import json


class InvalidOutput(ValueError):
    def __init__(self, code="invalid_model_output"):
        self.code = code
        super().__init__(code)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise InvalidOutput()
        result[key] = value
    return result


def strict_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _value: (_ for _ in ()).throw(InvalidOutput()))
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise InvalidOutput() from None


def provider_usage(body):
    try:
        value = strict_json(body)
        usage = value.get("usage") if type(value) is dict else None
        if (type(usage) is dict and all(type(usage.get(key)) is int and 0 <= usage[key] <= 1_000_000
                                      for key in ("prompt_tokens", "completion_tokens", "total_tokens"))
                and usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"]):
            return {key: usage[key] for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
    except InvalidOutput:
        pass
    return None


def parse_completion(body: bytes, *, excerpt: str, start_line: int, end_line: int):
    """Validate the provider envelope and the exact five-field warning schema."""
    value = strict_json(body)
    if (type(value) is not dict or type(value.get("choices")) is not list or len(value["choices"]) != 1):
        raise InvalidOutput("invalid_provider_response")
    choice = value["choices"][0]
    if type(choice) is not dict or choice.get("finish_reason") != "stop":
        raise InvalidOutput("incomplete_model_response")
    message = choice.get("message")
    if (type(message) is not dict or message.get("role") != "assistant" or message.get("tool_calls")
            or "function_call" in message or type(message.get("content")) is not str
            or not message["content"].strip()):
        raise InvalidOutput("incomplete_model_response")
    content = strict_json(message["content"])
    if (type(content) is not dict or set(content) != {"warnings"} or type(content["warnings"]) is not list
            or len(content["warnings"]) > 20):
        raise InvalidOutput()
    warnings, issues = [], []
    lines = excerpt.splitlines(keepends=True)
    for item in content["warnings"]:
        if (type(item) is not dict or set(item) != {"line", "end_line", "reason", "evidence_quote", "suggestion"}
                or type(item["line"]) is not int or type(item["end_line"]) is not int
                or not start_line <= item["line"] <= item["end_line"] <= end_line
                or any(type(item[key]) is not str or len(item[key].encode("utf-8")) > 4096
                       for key in ("reason", "evidence_quote", "suggestion"))
                or not item["reason"].strip() or not item["evidence_quote"]):
            raise InvalidOutput()
        quoted_lines = "".join(lines[item["line"] - start_line:item["end_line"] - start_line + 1])
        checked = item["evidence_quote"] in quoted_lines
        warnings.append({**item, "source": "llm", "verified": False, "can_block": False,
                         "confirmed_behavior_bug": False, "evidence_checked": checked})
        if not checked:
            issues.append({"status": "evidence_quote_not_matched"})
    usage = provider_usage(body)
    if usage is None:
        issues.append({"status": "usage_unavailable"})
    return warnings, usage, issues
