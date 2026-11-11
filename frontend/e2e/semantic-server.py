"""Browser acceptance server with a synthetic, in-process model transport.

This test launcher never calls a provider, accepts no endpoint option, and
refuses every key except the documented fake browser-fixture key. Production
CodeSentry entry points do not import this file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY))

from codesentry.semantic.transport import DeepSeekTransport, SemanticTransportError, TransportResponse
from codesentry.web.app import create_app
from fastapi.staticfiles import StaticFiles


SYNTHETIC_KEY = "sk-E2E_SYNTHETIC_ONLY_NOT_A_REAL_KEY"
WARNING = "SYNTHETIC_MODEL_WARNING_CHECK_INTENT"


def _deny_provider_transport(*_args, **_kwargs):
    raise SemanticTransportError("external_provider_disabled_in_e2e")


class SyntheticTransport:
    """Return one quoted warning, without sockets, SDKs, subprocesses or eval."""

    def __init__(self):
        self._lock = threading.Lock()
        self._request_hashes = []

    def send(self, body, *, api_key, timeout_seconds, cancel_event, live_guard):
        live_guard()
        if cancel_event.is_set():
            raise SemanticTransportError("cancelled")
        if api_key != SYNTHETIC_KEY:
            raise SemanticTransportError("synthetic_key_required")
        try:
            request = json.loads(body)
            payload = json.loads(request["messages"][-1]["content"])
            if "question" in payload and "context" in payload:
                sources = payload["context"]["sources"]
                citations = [{"source_id": item["source_id"]} for item in sources[:3]]
                content = {"answer": "## 先看一条线：接收请求 → 处理业务 → 保存结果\n\n我们从“创建任务”开始。本步先弄清入口负责什么、业务规则在哪里，以及结果何时写入。可以随时停下来追问。\n\n入口将请求交给 `TaskService`，服务创建任务并调用存储。点击文件引用就能在旁边对照源码。\n\n## 值得进一步核对的重构线索\n\n**名称规则在入口和服务各有一份。** 我们需要先核对它们是否表达同一条约束；若职责不同，保留两处可能更清楚。\n\n如果规则相同，可以集中表达，减少后续修改时遗漏一处的风险。代价是需要统一错误行为并做兼容验证。\n\n性能建议暂不下结论：当前还缺吞吐目标与内存峰值的依据。\n\n合成验收响应，仅用于验证交互，不代表模型真实效果。",
                           "citations": citations, "followups": ["解释这两处校验", "继续看保存过程", "讲得再细一点"]}
                envelope = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(content, ensure_ascii=False)}}],
                            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}}
                live_guard()
                with self._lock:
                    self._request_hashes.append(hashlib.sha256(body).hexdigest())
                return TransportResponse(200, json.dumps(envelope, ensure_ascii=False).encode())
            source = json.loads(request["messages"][1]["content"])
            if (request["model"] != "deepseek-flash" or request["stream"] is not False
                    or request["thinking"] != {"type": "disabled"}
                    or request["response_format"] != {"type": "json_object"}
                    or request["max_tokens"] != 1024 or "tools" in request
                    or source["path"] != "main.py" or source["start_line"] != source["end_line"]
                    or type(source["source"]) is not str or not source["source"].strip()):
                raise ValueError()
            quote = source["source"].rstrip("\r\n")
            content = {"warnings": [{"line": source["start_line"], "end_line": source["end_line"],
                "reason": WARNING, "evidence_quote": quote,
                "suggestion": "请人工核对断言条件；本条为合成测试响应，尚未确认行为缺陷。"}]}
            envelope = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant",
                "content": json.dumps(content, ensure_ascii=False)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}}
        except (ValueError, KeyError, TypeError, IndexError):
            raise SemanticTransportError("synthetic_fixture_mismatch") from None
        live_guard()
        if cancel_event.is_set():
            raise SemanticTransportError("cancelled")
        with self._lock:
            self._request_hashes.append(hashlib.sha256(body).hexdigest())
        return TransportResponse(200, json.dumps(envelope, ensure_ascii=False).encode("utf-8"))

    def diagnostics(self):
        with self._lock:
            return {"transport": "synthetic_no_network", "requests": len(self._request_hashes),
                "request_sha256": list(self._request_hashes), "provider_http_disabled": True}


def make_app(data_dir, frontend_dir):
    # Defence against an accidental fallback introduced by a later refactor.
    DeepSeekTransport.send = _deny_provider_transport
    transport = SyntheticTransport()
    # Inject the fixed fake credential directly. Never load the developer's
    # real .env or inherited credential environment in the browser test host.
    app = create_app(Path(data_dir), semantic_transport=transport,
                     configured_api_key=SYNTHETIC_KEY, configured_key_source="env_file")

    @app.get("/api/e2e/semantic-transport")
    def diagnostic():
        # Existing loopback/origin/session middleware still protects this route.
        # Return hashes/counts only, never headers, keys, source or provider data.
        return transport.diagnostics()

    # Register test API before the catch-all page mount, matching production's
    # own route ordering; otherwise StaticFiles consumes the diagnostic path.
    fallback = [route for route in app.router.routes
                if getattr(route, "path", None) == "/" and getattr(route, "name", None) == "frontend_not_built"]
    if len(fallback) != 1:
        raise RuntimeError("synthetic_harness_frontend_route_changed")
    app.router.routes.remove(fallback[0])
    app.mount("/", StaticFiles(directory=Path(frontend_dir), html=True), name="frontend")
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--frontend-dir", type=Path, required=True)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(make_app(args.data_dir, args.frontend_dir), host="127.0.0.1", port=8766,
                log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
