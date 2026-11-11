"""Same-origin project conversation endpoints; no client-supplied model context."""
from typing import Literal

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from codesentry.conversation.insights import InsightConflict
from codesentry.conversation.service import ConversationConflict


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    consent: StrictBool
    context: str = Field(max_length=4000)
    expected_revision: int = Field(ge=0, strict=True)
    expected_policy_version: int = Field(ge=1, strict=True)
    expected_profile_revision: int = Field(ge=1, strict=True)


class Topic(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="新话题", min_length=1, max_length=120)


class CrapTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    turn_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    file: str = Field(min_length=1, max_length=4096)
    line: int = Field(ge=1, strict=True)


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=4000)
    selected_path: str | None = Field(default=None, min_length=1, max_length=4096)
    crap_target: CrapTarget | None = None
    expected_settings_revision: int = Field(ge=0, strict=True)


class Feedback(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(max_length=1000)


class InsightDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    statement: str = Field(min_length=1, max_length=1200)
    kind: Literal["observation", "hypothesis"]
    scope: Literal["project", "topic"]
    track_environment: StrictBool = False
    expected_policy_version: int = Field(ge=1, strict=True)


class InsightChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cid: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    action: Literal["retire", "delete"]
    expected_policy_version: int = Field(ge=1, strict=True)


def identity(workspace):
    return {"workspace_id": workspace["id"], "policy_version": workspace["access_policy"]["version"],
            "policy_fingerprint": workspace["access_policy"]["fingerprint"]}


def install_conversation_routes(app):
    @app.exception_handler(ConversationConflict)
    @app.exception_handler(InsightConflict)
    async def conflict(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=409)

    @app.get("/api/workspaces/{workspace_id}/chat-settings")
    def settings(workspace_id: str, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            return manager.conversations.settings(workspace) | identity(workspace)

    @app.put("/api/workspaces/{workspace_id}/chat-settings")
    def save_settings(workspace_id: str, body: Settings, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            return manager.conversations.save_settings(workspace, **body.model_dump()) | identity(workspace)

    @app.get("/api/workspaces/{workspace_id}/conversations")
    def conversations(workspace_id: str, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            return {"conversations": manager.conversations.list(workspace_id)} | identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/conversations", status_code=201)
    def create(workspace_id: str, body: Topic, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            return manager.conversations.create(workspace_id, body.title) | identity(workspace)

    @app.get("/api/workspaces/{workspace_id}/conversations/{conversation_id}")
    def read(workspace_id: str, conversation_id: str, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            return manager.conversations.read(workspace_id, conversation_id) | identity(workspace)

    @app.delete("/api/workspaces/{workspace_id}/conversations/{conversation_id}")
    def delete(workspace_id: str, conversation_id: str, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            manager.conversations.delete(workspace_id, conversation_id)
            return {"deleted": True} | identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/conversations/{conversation_id}/messages", status_code=202)
    def send(workspace_id: str, conversation_id: str, body: Message, request: Request):
        if not body.question.strip():
            raise ValueError("请输入问题")
        if body.selected_path is not None and body.crap_target is not None:
            raise ValueError("请选择一种源码引用")
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            return manager.conversations.submit(workspace, conversation_id, body.question, body.selected_path,
                                                body.expected_settings_revision,
                                                crap_target=body.crap_target.model_dump() if body.crap_target else None) | identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/conversations/{conversation_id}/cancel")
    def cancel(workspace_id: str, conversation_id: str, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            manager.conversations.cancel(workspace_id, conversation_id)
            return manager.conversations.read(workspace_id, conversation_id) | identity(workspace)

    @app.put("/api/workspaces/{workspace_id}/conversations/{conversation_id}/turns/{turn_id}/feedback")
    def feedback(workspace_id: str, conversation_id: str, turn_id: str, body: Feedback, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, _access):
            manager.conversations.feedback(workspace_id, conversation_id, turn_id, body.text)
            return manager.conversations.read(workspace_id, conversation_id) | identity(workspace)

    @app.get("/api/workspaces/{workspace_id}/insights")
    def list_insights(workspace_id: str, request: Request, conversation_id: str | None = None):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, access):
            notes = manager.conversations.insights.list(workspace, access, conversation_id)
            return {"insights": notes} | identity(workspace)

    @app.post("/api/workspaces/{workspace_id}/conversations/{conversation_id}/turns/{turn_id}/insights", status_code=201)
    def create_insight(workspace_id: str, conversation_id: str, turn_id: str, body: InsightDraft, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, access):
            manager.semantic.check_chat_text(workspace_id, body.statement)
            note = manager.conversations.insights.create(workspace, access, conversation_id, turn_id, **body.model_dump())
            return {"insight": note} | identity(workspace)

    @app.patch("/api/workspaces/{workspace_id}/insights/{insight_id}")
    def change_insight(workspace_id: str, insight_id: str, body: InsightChange, request: Request):
        manager = request.app.state.manager
        with manager.authorized(workspace_id) as (workspace, access):
            manager.conversations.insights.change(workspace, access, insight_id, **body.model_dump())
            return {"updated": True} | identity(workspace)
