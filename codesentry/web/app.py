"""Same-origin, loopback-only workbench API with workspace-scoped file access."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
import secrets
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StringConstraints, model_validator

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.review.approvals import BaselineConflict
from codesentry.web.jobs import AnalysisManager, PolicyConflict
from codesentry.workspaces.files import checked_root, list_files, read_file
from codesentry.workspaces.store import WorkspaceStore, policy_metadata, unconfirmed_policy

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
SourcePath = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4096)]
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class AccessSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    respect_gitignore: StrictBool = True
    exclude: list[str] = Field(default_factory=list, max_length=256)
    local_only: list[str] = Field(default_factory=list, max_length=256)
    model_scope: list[str] = Field(default_factory=list, max_length=256)


class AccessConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]
    settings: AccessSettings
    fingerprint: str | None = Field(default=None, min_length=1, max_length=128)
    expected_version: int | None = Field(default=None, ge=0, strict=True)


class AccessPreview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: SourcePath
    settings: AccessSettings = Field(default_factory=AccessSettings)


class WorkspaceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: SourcePath
    name: Name | None = None
    access_policy: AccessConfirmation | None = None


class ConfigPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_depth: int | None = Field(default=None, ge=1, le=8, strict=True)
    max_items: int | None = Field(default=None, ge=10, le=100, strict=True)


class WorkspacePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Name | None = None
    config: ConfigPatch | None = None
    access_policy: AccessConfirmation | None = None


class AnalysisCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["static"] = "static"
    kind: Literal["navigation", "review_preview", "change_scope", "gate_check", "defect_preview"] = "navigation"
    max_function_lines: int | None = Field(default=None, ge=1, le=10_000, strict=True)
    base_ref: str | None = Field(default=None, min_length=1, max_length=256)
    comparison: Literal["working_tree", "staged", "commit"] | None = None
    target_ref: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def _review_options(self):
        if self.kind != "review_preview" and self.max_function_lines is not None:
            raise ValueError("函数行数阈值只适用于审查预览")
        if self.kind != "change_scope" and any(value is not None for value in (self.base_ref, self.comparison, self.target_ref)):
            raise ValueError("变更比较参数只适用于变更范围任务")
        if self.kind == "change_scope":
            if ((self.comparison or "working_tree") == "commit") != (self.target_ref is not None):
                raise ValueError("两提交比较必须指定目标提交；其他模式不接受目标提交")
            for reference in (self.base_ref, self.target_ref):
                if reference is not None and (not reference.strip() or reference.startswith("-")
                        or any(ord(char) < 32 for char in reference)):
                    raise ValueError("提交引用格式不合法")
        return self


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.path or parsed.query or parsed.fragment:
            return None
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def create_app(data_dir: Path, frontend_dir: Path | None = None, *, allowed_dev_origins: set[str] | None = None,
               semantic_transport=None, configured_api_key: str | None = None,
               configured_key_source: str | None = None) -> FastAPI:
    store = WorkspaceStore(Path(data_dir))
    token = secrets.token_urlsafe(32)
    dev_origins = set()
    for value in allowed_dev_origins or set():
        origin = _origin(value)
        if not origin or origin[1] not in LOOPBACK_HOSTS:
            raise ValueError("开发源必须是显式的loopback地址")
        dev_origins.add(origin)

    @asynccontextmanager
    async def lifespan(app):
        app.state.manager = AnalysisManager(store, semantic_transport=semantic_transport,
            configured_api_key=configured_api_key, configured_key_source=configured_key_source)
        try:
            yield
        finally:
            app.state.manager.close()

    app = FastAPI(title="CodeSentry Local Workbench", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store = store
    app.state.session_token = token
    app.state.manager = None

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        host = request.headers.get("host", "")
        effective = _origin(f"{request.url.scheme}://{host}")
        if effective is None or effective[1] not in LOOPBACK_HOSTS:
            return JSONResponse({"detail": "仅允许本地工作台地址"}, status_code=400)
        supplied = request.headers.get("origin")
        if supplied is not None and _origin(supplied) not in ({effective} | dev_origins):
            return JSONResponse({"detail": "拒绝其他网站访问本地工作台"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "拒绝跨站请求"}, status_code=403)
        if request.url.path.startswith("/api/") and request.url.path != "/api/session":
            candidate = request.headers.get("x-codesentry-token", "")
            if not secrets.compare_digest(candidate, token):
                return JSONResponse({"detail": "工作台会话已失效，请刷新页面"}, status_code=401)
        if request.method in {"POST", "PATCH", "PUT", "DELETE"}:
            if request.headers.get("content-type", "").split(";", 1)[0].lower() not in {"application/json", ""}:
                return JSONResponse({"detail": "只接受JSON请求"}, status_code=415)
            try:
                if int(request.headers.get("content-length", "0")) > 16384:
                    return JSONResponse({"detail": "请求超过上限"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "无效请求长度"}, status_code=400)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "font-src 'self' data:; img-src 'self' data:; worker-src 'self' blob:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.exception_handler(KeyError)
    async def missing(_request, error):
        return JSONResponse({"detail": str(error).strip("'")}, status_code=404)

    @app.exception_handler(ValueError)
    async def invalid(_request, error):
        return JSONResponse({"detail": str(error)[:500]}, status_code=400)

    @app.exception_handler(PolicyConflict)
    async def policy_conflict(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=409)

    @app.exception_handler(BaselineConflict)
    async def baseline_conflict(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=409)

    @app.exception_handler(FileNotFoundError)
    async def no_file(_request, _error):
        return JSONResponse({"detail": "代码目录或文件不存在，请刷新工作空间"}, status_code=404)

    @app.exception_handler(PermissionError)
    @app.exception_handler(AccessDenied)
    async def denied(_request, error):
        return JSONResponse({"detail": str(error)[:500] or "无法读取这个目录或文件"}, status_code=403)

    @app.get("/api/session")
    def session():
        return {"token": token, "api_version": "1", "capabilities": {"analysis": True, "review": True, "chat": True},
                "review_mode": "preview", "change_scope": True, "baseline_review": True, "gate_check": True,
                "defect_preview": True, "semantic_review": True, "model_provider": "deepseek"}

    @app.get("/api/gate-policy")
    def gate_policy():
        from codesentry.review.gate import gate_manifest
        return gate_manifest()

    @app.get("/api/workspaces")
    def workspaces():
        return {"workspaces": [app.state.manager.synchronize(item["id"]) for item in store.list_workspaces()]}

    @app.post("/api/access/preview")
    def access_preview(body: AccessPreview):
        root = checked_root(Path(body.path).expanduser().resolve(strict=True))
        existing = store.find_workspace_by_path(root)
        version = (app.state.manager.synchronize(existing["id"])["access_policy"]["version"]
                   if existing is not None else 0)
        policy = AccessPolicy(root, body.settings.model_dump(), confirmed=True)
        entries, truncated = [], False
        for relative, _path, is_dir, decision in policy.walk():
            entries.append({"path": relative, "is_dir": is_dir, **decision})
            if len(entries) >= 5000:
                truncated = True
                break
        metadata = unconfirmed_policy() | policy_metadata(policy)
        metadata.update(confirmed=False, version=version)
        return {"path": str(root), "expected_version": version,
                "access_policy": metadata, "entries": entries, "truncated": truncated}

    @app.post("/api/workspaces", status_code=201)
    def open_workspace(body: WorkspaceCreate):
        existing = store.find_workspace_by_path(Path(body.path))
        if existing is not None:
            if body.access_policy is not None:
                return app.state.manager.confirm_policy(existing["id"], body.access_policy.settings.model_dump(),
                                                         fingerprint=body.access_policy.fingerprint,
                                                         expected_version=body.access_policy.expected_version)
            return app.state.manager.synchronize(existing["id"])
        created = store.create_workspace(body.path, body.name)
        if body.access_policy is not None:
            return app.state.manager.confirm_policy(created["id"], body.access_policy.settings.model_dump(),
                                                     fingerprint=body.access_policy.fingerprint,
                                                     expected_version=body.access_policy.expected_version)
        return created

    @app.get("/api/workspaces/{workspace_id}")
    def workspace(workspace_id: str):
        return app.state.manager.synchronize(workspace_id)

    @app.patch("/api/workspaces/{workspace_id}")
    def change_workspace(workspace_id: str, body: WorkspacePatch):
        if body.access_policy is not None:
            app.state.manager.confirm_policy(workspace_id, body.access_policy.settings.model_dump(),
                                             fingerprint=body.access_policy.fingerprint,
                                             expected_version=body.access_policy.expected_version)
        else:
            app.state.manager.synchronize(workspace_id)
        config = body.config.model_dump(exclude_none=True) if body.config is not None else None
        return store.update_workspace(workspace_id, name=body.name, config=config)

    @app.get("/api/workspaces/{workspace_id}/files")
    def files(workspace_id: str):
        with app.state.manager.authorized(workspace_id) as (selected, policy):
            access = selected["access_policy"]
            return JSONResponse({"workspace_id": workspace_id, "policy_version": access["version"],
                                 "policy_fingerprint": access["fingerprint"],
                                 **list_files(Path(selected["path"]), access=policy, data_dir=store.data_dir)})

    @app.get("/api/workspaces/{workspace_id}/file")
    def file(workspace_id: str, path: str, analysis_id: str | None = None):
        with app.state.manager.authorized(workspace_id) as (selected, policy):
            access = selected["access_policy"]
            analysis = store.get_analysis(workspace_id, analysis_id, include_result=True) if analysis_id else None
            if analysis is not None and analysis["status"] == "invalidated":
                raise HTTPException(409, "所选分析结果已失效，请重新分析；仍可直接打开当前文件")
            payload = {"workspace_id": workspace_id, "policy_version": access["version"],
                       "policy_fingerprint": access["fingerprint"],
                       **read_file(Path(selected["path"]), path, access=policy, data_dir=store.data_dir)}
            expected = None
            expected_algorithm = None
            actual = payload["content_hash"]
            if analysis is not None:
                if analysis["result"]:
                    if analysis["kind"] in {"review_preview", "change_scope", "gate_check", "defect_preview", "semantic_review"}:
                        hashes = analysis["result"].get("source_sha256", {})
                        expected = hashes.get(payload["path"]) if isinstance(hashes, dict) else None
                        expected_algorithm, actual = "sha256-raw-bytes", payload["sha256"]
                    else:
                        expected = next((item.get("content_hash") for item in analysis["result"].get("file_details", [])
                                         if item.get("path") == payload["path"]), None)
                        expected_algorithm = "sha1-decoded-text"
            payload.update({"analysis_id": analysis_id, "snapshot_content_hash": expected,
                            "snapshot_content_hash_algorithm": expected_algorithm,
                            "is_stale": actual != expected if expected is not None else None})
            return JSONResponse(payload)

    @app.get("/api/workspaces/{workspace_id}/analyses")
    def analyses(workspace_id: str):
        app.state.manager.synchronize(workspace_id)
        return {"workspace_id": workspace_id, "analyses": store.list_analyses(workspace_id, metadata_only=True)}

    @app.post("/api/workspaces/{workspace_id}/analyses", status_code=202)
    def analyze(workspace_id: str, body: AnalysisCreate | None = Body(default=None)):
        if app.state.manager is None:
            raise HTTPException(503, "分析服务尚未启动")
        options = body or AnalysisCreate()
        return app.state.manager.submit(workspace_id, kind=options.kind, max_function_lines=options.max_function_lines,
                                        base_ref=options.base_ref, comparison=options.comparison, target_ref=options.target_ref)

    @app.get("/api/workspaces/{workspace_id}/analyses/{analysis_id}")
    def analysis(workspace_id: str, analysis_id: str):
        with app.state.manager.authorized(workspace_id) as (workspace, _access):
            job = store.get_analysis(workspace_id, analysis_id, include_result=True)
            if (job["kind"] == "review_preview" and job.get("result")
                    and job["result"].get("review_status") == "report_only"):
                from codesentry.web.baselines import review_context
                context = review_context(store, workspace, job["result"]["policy_sha256"])
                job["result"] = app.state.manager.baselines.annotate(workspace_id, context, job["result"])
            return JSONResponse(job)

    @app.post("/api/workspaces/{workspace_id}/analyses/{analysis_id}/cancel")
    def cancel(workspace_id: str, analysis_id: str):
        if app.state.manager is None:
            raise HTTPException(503, "分析服务尚未启动")
        return app.state.manager.cancel(workspace_id, analysis_id)

    from codesentry.web.baselines import install_baseline_routes
    install_baseline_routes(app, store)
    from codesentry.web.semantic import install_semantic_routes
    install_semantic_routes(app)
    from codesentry.web.conversations import install_conversation_routes
    install_conversation_routes(app)

    if frontend_dir is not None and Path(frontend_dir).is_dir():
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    else:
        @app.get("/")
        def frontend_not_built():
            return HTMLResponse("<h1>CodeSentry</h1><p>本地服务已启动。请先构建frontend，再重新启动工作台。</p>", status_code=503)
    return app
