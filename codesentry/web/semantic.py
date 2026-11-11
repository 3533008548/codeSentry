"""Workspace-scoped, explicit preview/confirm model-review routes."""
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool
from typing import Literal

from codesentry.semantic.service import SemanticBudgetExceeded, SemanticConflict


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool
    model: Literal["deepseek-flash", "deepseek-v4-pro"]


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=1, strict=True)
    settings: Settings
    api_key: SecretStr | None = None
    clear_key: StrictBool = False
    use_configured_key: StrictBool | None = None


class Preview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=4096)
    start_line: int = Field(ge=1, strict=True)
    end_line: int = Field(ge=1, strict=True)
    expected_profile_revision: int = Field(ge=1, strict=True)


class Send(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: StrictBool
    expected_request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_profile_revision: int = Field(ge=1, strict=True)


def _identity(workspace):
    access = workspace["access_policy"]
    return {"workspace_id": workspace["id"], "policy_version": access["version"],
            "policy_fingerprint": access["fingerprint"]}


def install_semantic_routes(app):
    # Never return Pydantic's input or ctx: a malformed body may contain a key
    # even in an unknown field. Existing endpoints benefit from the same rule.
    @app.exception_handler(RequestValidationError)
    async def validation_error(_request, error):
        return JSONResponse({"detail": "请求字段无效，请检查后重试"}, status_code=422)

    @app.exception_handler(SemanticConflict)
    async def conflict(_request, _error):
        return JSONResponse({"detail": "模型设置、访问范围或片段已变化，请重新生成发送预览"}, status_code=409)

    @app.exception_handler(SemanticBudgetExceeded)
    async def budget(_request, _error):
        return JSONResponse({"detail": "模型审查已达到本次服务的请求或用量上限"}, status_code=409)

    @app.get("/api/workspaces/{workspace_id}/semantic-profile")
    def profile(workspace_id: str, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            return manager.semantic.read_profile(workspace_id) | _identity(workspace)

    @app.put("/api/workspaces/{workspace_id}/semantic-profile")
    def update_profile(workspace_id: str, body: ProfileUpdate, request: Request):
        manager = request.app.state.manager
        profile = manager.update_semantic_profile(workspace_id, body.settings.model_dump(),
            expected_revision=body.expected_revision,
            api_key=None if body.api_key is None else body.api_key.get_secret_value(), clear_key=body.clear_key,
            use_configured_key=body.use_configured_key)
        with manager.authorized(workspace_id) as (workspace, _access):
            return profile | _identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/semantic-previews")
    def preview(workspace_id: str, body: Preview, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, access):
            result = manager.semantic.preview(workspace_id, access, **body.model_dump(),
                                              access_version=workspace["access_policy"]["version"])
            return result | _identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/semantic-previews/{preview_id}/send", status_code=202)
    def send(workspace_id: str, preview_id: str, body: Send, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, access):
            reservation = manager.semantic.reserve(workspace_id, access, preview_id=preview_id,
                **body.model_dump(), access_version=workspace["access_policy"]["version"])
            return manager.submit_semantic(workspace_id, reservation)
