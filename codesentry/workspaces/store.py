"""Small SQLite registry for one local user's workspaces and analysis history."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import re
import os
from pathlib import Path
import sqlite3
import threading
import uuid

from codesentry.access import AccessPolicy, validate_settings
from codesentry.environment.toolchain import is_link
from codesentry.web.provenance import analysis_provenance
from codesentry.workspaces.lease import DirectoryLease


DEFAULT_CONFIG = {"max_depth": 4, "max_items": 30}
TERMINAL = {"succeeded", "incomplete", "failed", "cancelled", "interrupted", "invalidated"}
RESULT_ERROR = "保存的分析结果已失效（文件缺失、不可读或身份不匹配），请重新分析"
IMPLEMENTATION_ERROR = "分析工具或结果格式已更新，旧结果不可作为当前证据，请重新分析；更新后请重启服务"
ACCESS_ERROR = "文件访问范围已改变，旧分析及日志已失效，请重新分析"
JOB_METADATA = ("id,workspace_id,status,created_at,started_at,finished_at,elapsed_seconds,"
                "NULL AS error,'[]' AS logs,config,result_path,access_policy")


def unconfirmed_policy() -> dict:
    return {"confirmed": False, "version": 0, "settings": validate_settings({}),
            "fingerprint": None, "cleanup_pending": False, "cleanup_error": None,
            "issues": [], "restricted": True}


def policy_metadata(policy: AccessPolicy) -> dict:
    result = policy.to_dict()
    result["issues"] = [f"{item.get('file', '.')}: {item.get('message', item.get('status', '访问受限'))}"
                        if isinstance(item, dict) else str(item) for item in result["issues"]]
    return result


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WorkspaceStore:
    def __init__(self, data_dir: Path):
        self.analysis_provenance = analysis_provenance()
        self.data_dir = data_dir.expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database = self.data_dir / "workspaces.sqlite3"
        self.lock = threading.RLock()
        with self.connection() as connection:
            connection.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS workspaces (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, path TEXT NOT NULL,
                    canonical_key TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, config TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    status TEXT NOT NULL, created_at TEXT NOT NULL,
                    started_at TEXT, finished_at TEXT, elapsed_seconds REAL,
                    error TEXT, logs TEXT NOT NULL, config TEXT NOT NULL,
                    result_path TEXT
                );
                CREATE INDEX IF NOT EXISTS analysis_workspace
                    ON analyses(workspace_id, created_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_analysis
                    ON analyses(workspace_id) WHERE status IN ('queued','running');
            """)
            # Existing registries are deliberately unconfirmed. Migration must
            # never infer permission from historical successful reads.
            migrations = []
            for table in ("workspaces", "analyses"):
                columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
                if "access_policy" not in columns:
                    migrations.append(table)
            if migrations:
                # An older running binary may use INSERT ... VALUES with the
                # old column count. Refuse upgrade before altering its schema.
                lease = DirectoryLease(self.data_dir)
                try:
                    for table in migrations:
                        connection.execute(f"ALTER TABLE {table} ADD COLUMN access_policy TEXT")
                    connection.execute("UPDATE workspaces SET access_policy=? WHERE access_policy IS NULL",
                                       (json.dumps(unconfirmed_policy()),))
                    connection.commit()
                finally:
                    lease.close()

    @contextmanager
    def connection(self):
        with self.lock:
            connection = sqlite3.connect(self.database, timeout=10)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            try:
                with connection:
                    yield connection
            finally:
                connection.close()

    def create_workspace(self, path: str, name: str | None = None, *, access_policy: dict | None = None) -> dict:
        root = Path(path).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("请选择存在的代码目录")
        canonical_key = os.path.normcase(str(root))
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM workspaces WHERE canonical_key=?", (canonical_key,)).fetchone()
            if row:
                return self._workspace(row)
            identity, created = uuid.uuid4().hex, now()
            access = unconfirmed_policy()
            if access_policy is not None and access_policy.get("confirmed") is True:
                policy = AccessPolicy(root, access_policy.get("settings", {}), confirmed=True)
                supplied = access_policy.get("fingerprint")
                if supplied is not None and supplied != policy.fingerprint:
                    raise ValueError("访问范围预览已改变，请重新预览并确认")
                access.update(policy_metadata(policy), confirmed=True, version=1)
            connection.execute(
                "INSERT INTO workspaces(id,name,path,canonical_key,created_at,updated_at,config,access_policy) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (identity, (name or root.name or str(root)).strip(), str(root), canonical_key,
                 created, created, json.dumps(DEFAULT_CONFIG), json.dumps(access)),
            )
        return self.get_workspace(identity)

    def _workspace(self, row: sqlite3.Row) -> dict:
        return {key: row[key] for key in ("id", "name", "path", "created_at", "updated_at")} | {
            "config": json.loads(row["config"]),
            "access_policy": json.loads(row["access_policy"]),
            "last_analysis": self.latest_analysis(row["id"]),
        }

    def find_workspace_by_path(self, root: Path) -> dict | None:
        canonical_key = os.path.normcase(str(Path(root).expanduser().resolve()))
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM workspaces WHERE canonical_key=?", (canonical_key,)).fetchone()
        return self._workspace(row) if row else None

    def workspace_policy(self, identity: str) -> dict:
        with self.connection() as connection:
            row = connection.execute("SELECT access_policy FROM workspaces WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise KeyError("工作空间不存在")
        return json.loads(row["access_policy"])

    def begin_policy_change(self, identity: str, policy: AccessPolicy) -> dict:
        access = self.workspace_policy(identity)
        access.update(policy_metadata(policy), confirmed=True, version=access["version"] + 1,
                      cleanup_pending=True, cleanup_error=None)
        with self.connection() as connection:
            connection.execute("UPDATE workspaces SET access_policy=?,updated_at=? WHERE id=?",
                               (json.dumps(access, ensure_ascii=False), now(), identity))
            # Persist denial before signalling workers or touching old files.
            connection.execute(
                "UPDATE analyses SET status='invalidated',error=?,logs='[]',result_path=NULL "
                "WHERE workspace_id=?", (ACCESS_ERROR, identity))
        return access

    def finish_policy_change(self, identity: str, *, error: str | None = None) -> None:
        access = self.workspace_policy(identity)
        access.update(cleanup_pending=error is not None, cleanup_error=error)
        with self.connection() as connection:
            connection.execute("UPDATE workspaces SET access_policy=? WHERE id=?",
                               (json.dumps(access, ensure_ascii=False), identity))

    def analysis_policy(self, workspace_id: str, identity: str) -> dict | None:
        with self.connection() as connection:
            row = connection.execute("SELECT access_policy FROM analyses WHERE workspace_id=? AND id=?",
                                     (workspace_id, identity)).fetchone()
        if row is None:
            raise KeyError("分析任务不存在于这个工作空间")
        return json.loads(row["access_policy"]) if row["access_policy"] else None

    def invalidate_analysis(self, workspace_id: str, identity: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE analyses SET status='invalidated',error=?,logs='[]',result_path=NULL,"
                "finished_at=COALESCE(finished_at,?) WHERE workspace_id=? AND id=?",
                (ACCESS_ERROR, now(), workspace_id, identity))

    def policy_matches(self, workspace_id: str, snapshot: dict | None) -> bool:
        access = self.workspace_policy(workspace_id)
        return bool(snapshot and access["confirmed"] and not access["cleanup_pending"]
                    and access["version"] == snapshot.get("version")
                    and access["fingerprint"] == snapshot.get("fingerprint"))

    def list_workspaces(self) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute("SELECT * FROM workspaces ORDER BY updated_at DESC, id").fetchall()
        return [self._workspace(row) for row in rows]

    def get_workspace(self, identity: str) -> dict:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM workspaces WHERE id=?", (identity,)).fetchone()
        if not row:
            raise KeyError("工作空间不存在")
        return self._workspace(row)

    def update_workspace(self, identity: str, *, name: str | None = None, config: dict | None = None) -> dict:
        workspace = self.get_workspace(identity)
        selected = dict(workspace["config"])
        if config is not None:
            selected.update(config)
        with self.connection() as connection:
            connection.execute("UPDATE workspaces SET name=?,config=?,updated_at=? WHERE id=?",
                               (name if name is not None else workspace["name"], json.dumps(selected), now(), identity))
        return self.get_workspace(identity)

    def _invalidate_result(self, job: dict, *, error: str = RESULT_ERROR) -> dict:
        with self.connection() as connection:
            connection.execute(
                "UPDATE analyses SET status='invalidated',error=?,result_path=NULL "
                "WHERE id=? AND workspace_id=? AND status IN ('succeeded','incomplete')",
                (error, job["id"], job["workspace_id"]),
            )
        job.update(status="invalidated", error=error, result=None, result_state="unavailable")
        return job

    def _result_location(self, workspace_id: str, identity: str) -> Path:
        return self.data_dir / "workspaces" / workspace_id / "analyses" / identity / "result.json"

    def _job(self, row: sqlite3.Row) -> dict:
        snapshot = json.loads(row["access_policy"]) if row["access_policy"] else None
        permitted = self.policy_matches(row["workspace_id"], snapshot)
        config = json.loads(row["config"])
        job = {key: row[key] for key in (
            "id", "workspace_id", "status", "created_at", "started_at", "finished_at",
            "elapsed_seconds", "error",
        )} | {"logs": [], "config": config, "kind": config.get("kind", "navigation"),
              "result": None, "result_state": "not_ready",
              "policy_version": snapshot.get("version") if snapshot else None,
              "policy_fingerprint": snapshot.get("fingerprint") if snapshot else None}
        if not permitted:
            job.update(logs=[], result_state="unavailable",
                       error=ACCESS_ERROR if row["status"] == "invalidated" else "访问范围待确认或已改变，旧输出不可用")
            return job
        job["logs"] = json.loads(row["logs"])
        if row["status"] == "invalidated":
            job["result_state"] = "unavailable"
        elif row["status"] in {"succeeded", "incomplete"}:
            # This metadata check also covers legacy results and list views,
            # without opening historical payloads or scanning target source.
            if snapshot.get("analysis_provenance") != self.analysis_provenance:
                return self._invalidate_result(job, error=IMPLEMENTATION_ERROR)
            destination = self._result_location(row["workspace_id"], row["id"])
            try:
                expected = str(destination.relative_to(self.data_dir))
                components = [destination, *destination.parents]
                if (row["result_path"] != expected or not destination.is_file()
                        or destination.stat().st_size > 32 * 1024 * 1024
                        or any(is_link(part) for part in components if part.is_relative_to(self.data_dir))):
                    return self._invalidate_result(job)
                job["result_state"] = "available"
            except OSError:
                return self._invalidate_result(job)
        return job

    def latest_analysis(self, workspace_id: str) -> dict | None:
        with self.connection() as connection:
            row = connection.execute(
                f"SELECT {JOB_METADATA} FROM analyses WHERE workspace_id=? ORDER BY created_at DESC,id DESC LIMIT 1",
                (workspace_id,),
            ).fetchone()
        return self._job(row) if row else None

    def list_analyses(self, workspace_id: str, *, metadata_only: bool = False) -> list[dict]:
        self.get_workspace(workspace_id)
        with self.connection() as connection:
            rows = connection.execute(
                f"SELECT {JOB_METADATA if metadata_only else '*'} FROM analyses "
                "WHERE workspace_id=? ORDER BY created_at DESC,id DESC LIMIT 100",
                (workspace_id,),
            ).fetchall()
        return [self._job(row) for row in rows]

    def create_analysis(self, workspace_id: str, *, kind: str = "navigation",
                        max_function_lines: int | None = None, base_ref: str | None = None,
                        comparison: str | None = None, target_ref: str | None = None,
                        semantic_config: dict | None = None) -> dict:
        if kind not in {"navigation", "review_preview", "change_scope", "gate_check", "defect_preview", "semantic_review"}:
            raise ValueError("不支持的分析任务类型")
        if kind == "semantic_review":
            expected = {"kind", "provider", "model", "profile_revision", "request_sha256", "source_digest", "request_id"}
            if (not isinstance(semantic_config, dict) or set(semantic_config) != expected
                    or semantic_config.get("kind") != kind or semantic_config.get("provider") != "deepseek"
                    or semantic_config.get("model") not in {"deepseek-flash", "deepseek-v4-pro"}
                    or type(semantic_config.get("profile_revision")) is not int or semantic_config["profile_revision"] < 1
                    or any(not isinstance(semantic_config.get(key), str)
                           or not re.fullmatch(r"[a-f0-9]{64}", semantic_config[key])
                           for key in ("request_sha256", "source_digest"))
                    or not isinstance(semantic_config.get("request_id"), str)
                    or not re.fullmatch(r"[a-f0-9]{32}", semantic_config["request_id"])):
                raise ValueError("模型任务必须来自已确认的发送预览")
        elif semantic_config is not None:
            raise ValueError("模型配置只适用于模型审查")
        if max_function_lines is not None and (kind != "review_preview" or type(max_function_lines) is not int
                                               or not 1 <= max_function_lines <= 10_000):
            raise ValueError("审查预览的函数行数阈值必须为1到10000的整数")
        workspace = self.get_workspace(workspace_id)
        config = workspace["config"] | {"kind": kind}
        if kind == "semantic_review":
            config.update(semantic_config)
        if kind == "review_preview":
            config["max_function_lines"] = 80 if max_function_lines is None else max_function_lines
        if kind == "gate_check":
            from codesentry.review.gate import gate_manifest
            config["gate_policy_sha256"] = gate_manifest()["policy_sha256"]
        if kind == "defect_preview":
            from codesentry.review.defects import defect_preview_policy
            config["defect_policy_sha256"] = hashlib.sha256(json.dumps(defect_preview_policy(),
                sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        if kind != "change_scope" and any(value is not None for value in (base_ref, comparison, target_ref)):
            raise ValueError("变更比较参数只适用于变更范围任务")
        if kind == "change_scope":
            base_ref = "HEAD" if base_ref is None else base_ref
            comparison = "working_tree" if comparison is None else comparison
            if comparison not in {"working_tree", "staged", "commit"}:
                raise ValueError("不支持的变更比较模式")
            for reference in (base_ref, target_ref):
                if reference is not None and (not isinstance(reference, str) or not reference.strip()
                        or len(reference) > 256 or reference.startswith("-")
                        or any(ord(char) < 32 for char in reference)):
                    raise ValueError("提交引用格式不合法")
            if (comparison == "commit") != (target_ref is not None):
                raise ValueError("两提交比较必须指定目标提交；其他模式不接受目标提交")
            config.update(base_ref=base_ref, comparison=comparison, target_ref=target_ref)
        access = workspace["access_policy"]
        if not access["confirmed"] or access["cleanup_pending"]:
            raise PermissionError("请先确认文件访问范围并完成旧数据清理")
        identity, created = uuid.uuid4().hex, now()
        with self.connection() as connection:
            active = connection.execute(
                "SELECT id FROM analyses WHERE workspace_id=? AND status IN ('queued','running')", (workspace_id,),
            ).fetchone()
            if active:
                raise ValueError("这个工作空间已有进行中的分析")
            connection.execute(
                "INSERT INTO analyses(id,workspace_id,status,created_at,started_at,finished_at,elapsed_seconds,"
                "error,logs,config,result_path,access_policy) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (identity, workspace_id, "queued", created, None, None, None, None,
                 json.dumps([{"review_preview": "审查预览已排队", "change_scope": "变更范围任务已排队", "gate_check": "门禁检查已排队", "defect_preview": "缺陷候选检查已排队"}.get(kind, "分析已排队")], ensure_ascii=False), json.dumps(config), None,
                 json.dumps(access | {"analysis_provenance": self.analysis_provenance})),
            )
            connection.execute("UPDATE workspaces SET updated_at=? WHERE id=?", (created, workspace_id))
        return self.get_analysis(workspace_id, identity)

    def get_analysis(self, workspace_id: str, identity: str, *, include_result: bool = False) -> dict:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM analyses WHERE id=? AND workspace_id=?",
                                     (identity, workspace_id)).fetchone()
        if not row:
            raise KeyError("分析任务不存在于这个工作空间")
        job = self._job(row)
        if include_result and job["result_state"] == "available":
            destination = self._result_location(workspace_id, identity)
            try:
                result = json.loads(destination.read_text(encoding="utf-8"))
                if (not isinstance(result, dict) or result.get("workspace_id") != workspace_id
                        or result.get("analysis_id") != identity
                        or result.get("policy_version") != job["policy_version"]
                        or result.get("policy_fingerprint") != job["policy_fingerprint"]):
                    raise ValueError("分析结果身份不匹配")
                if result.get("analysis_provenance") != self.analysis_provenance:
                    return self._invalidate_result(job, error=IMPLEMENTATION_ERROR)
                if (result.get("kind", "navigation") != job["kind"]
                        or json.dumps(result.get("config"), sort_keys=True) != json.dumps(job["config"], sort_keys=True)):
                    raise ValueError("分析任务类型或冻结配置不匹配")
                job["result"] = result
            except (OSError, UnicodeError, ValueError):
                return self._invalidate_result(job)
        return job

    def analysis_config(self, workspace_id: str, identity: str) -> dict:
        with self.connection() as connection:
            row = connection.execute("SELECT config FROM analyses WHERE workspace_id=? AND id=?",
                                     (workspace_id, identity)).fetchone()
        if not row:
            raise KeyError("分析任务不存在")
        return json.loads(row["config"])

    def update_analysis(self, workspace_id: str, identity: str, **changes) -> dict:
        allowed = {"status", "started_at", "finished_at", "elapsed_seconds", "error", "result_path"}
        if not changes or not set(changes) <= allowed:
            raise ValueError("无效任务更新")
        assignments = ",".join(f"{key}=?" for key in changes)
        with self.connection() as connection:
            row = connection.execute("SELECT status FROM analyses WHERE id=? AND workspace_id=?",
                                     (identity, workspace_id)).fetchone()
            if row and row["status"] == "invalidated":
                return self.get_analysis(workspace_id, identity)
            cursor = connection.execute(f"UPDATE analyses SET {assignments} WHERE id=? AND workspace_id=?",
                                        (*changes.values(), identity, workspace_id))
            if not cursor.rowcount:
                raise KeyError("分析任务不存在")
        return self.get_analysis(workspace_id, identity)

    def append_log(self, workspace_id: str, identity: str, message: str) -> None:
        job = self.get_analysis(workspace_id, identity)
        if job["status"] == "invalidated" or not self.policy_matches(workspace_id, self.analysis_policy(workspace_id, identity)):
            return
        logs = (job["logs"] + [message[:2000]])[-64:]
        with self.connection() as connection:
            connection.execute("UPDATE analyses SET logs=? WHERE id=? AND workspace_id=?",
                               (json.dumps(logs, ensure_ascii=False), identity, workspace_id))

    def mark_interrupted(self) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE analyses SET status='interrupted',finished_at=?,error=? WHERE status IN ('queued','running')",
                (now(), "上次服务中断，分析未被记作完成；可以重新运行"),
            )

    def result_file(self, workspace_id: str, identity: str) -> Path:
        self.get_analysis(workspace_id, identity)
        directory = self._result_location(workspace_id, identity).parent
        directory.mkdir(parents=True, exist_ok=True)
        return directory / "result.json"
