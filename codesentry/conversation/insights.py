"""User-written, local project notes with evidence snapshots and a one-way lifecycle."""
from __future__ import annotations

import hashlib
import json
import uuid

from codesentry.access import AccessDenied
from codesentry.conversation.context import answer_dependencies, source_digest, sources_current
from codesentry.environment.inspect import DECLARATION_NAMES, LOCK_NAMES
from codesentry.workspaces.store import now


ENVIRONMENT_PATHS = sorted(DECLARATION_NAMES | LOCK_NAMES | {"tsconfig.json", "jsconfig.json"})
MAX_ENVIRONMENT_BYTES = 4 * 1024 * 1024
MAX_INSIGHTS = 100


class InsightConflict(ValueError):
    pass


def declared_environment(access):
    """Snapshot permitted root declarations, without probing installed runtimes."""
    observed = {}
    for path in ENVIRONMENT_PATHS:
        if access.decision(path)["mode"] == "exclude":
            continue
        try:
            data = access.read_bytes(path, limit=MAX_ENVIRONMENT_BYTES)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            return None
        observed[path] = hashlib.sha256(data).hexdigest()
    return observed


def _check_policy(workspace, access, expected_version=None):
    policy = workspace["access_policy"]
    if expected_version is not None and policy["version"] != expected_version:
        raise InsightConflict("文件访问范围已变化，请刷新后重试")
    access.refresh_if_changed()
    if access.fingerprint != policy["fingerprint"]:
        raise AccessDenied("文件访问范围已变化，请刷新后重试")


def _public(row):
    result = {key: row[key] for key in ("id", "statement", "kind", "status", "drift_reason", "created_at",
                                       "last_checked_at", "origin_conversation_id", "origin_turn_id")}
    return result | {"scope": "topic" if row["topic_id"] else "project", "tracks_environment": row["environment"] is not None,
                     "citations": json.loads(row["evidence"])["citations"]}


def _answer_record(db, wid, cid, tid):
    return db.execute("SELECT t.evidence,t.citations,EXISTS(SELECT 1 FROM conversation_turns p "
                      "WHERE p.conversation_id=t.conversation_id AND p.rowid<t.rowid "
                      "AND p.status='completed' AND p.answer<>'') AS has_prior_answers "
                      "FROM conversation_turns t JOIN conversations c ON c.id=t.conversation_id "
                      "WHERE c.workspace_id=? AND c.id=? AND t.id=? AND t.status='completed' AND t.answer<>''",
                      (wid, cid, tid)).fetchone()


def _dependencies(record):
    return answer_dependencies(json.loads(record["evidence"]), has_prior_answers=record["has_prior_answers"])


class InsightStore:
    def __init__(self, store):
        self.store = store
        with store.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS conversation_insights(
                    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    topic_id TEXT REFERENCES conversations(id) ON DELETE CASCADE,
                    origin_conversation_id TEXT NOT NULL, origin_turn_id TEXT NOT NULL,
                    statement TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('observation','hypothesis')),
                    evidence TEXT NOT NULL, environment TEXT,
                    status TEXT NOT NULL CHECK(status IN ('active','stale','retired')),
                    drift_reason TEXT, created_at TEXT NOT NULL, last_checked_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS insight_workspace ON conversation_insights(workspace_id,topic_id);
            """)

    def create(self, workspace, access, cid, tid, *, statement, kind, scope, track_environment, expected_policy_version):
        statement = statement.strip()
        if not statement:
            raise ValueError("请输入要保存的笔记")
        _check_policy(workspace, access, expected_policy_version)
        wid, topic_id = workspace["id"], cid if scope == "topic" else None
        with self.store.connection() as db:
            turn = _answer_record(db, wid, cid, tid)
            if turn is None:
                raise KeyError("当前话题中没有这条已完成的回答")
            dependencies = _dependencies(turn)
            if dependencies is None:
                raise InsightConflict("旧回答缺少历史取材记录，请根据当前源码重新提问后保存")
            citations = [{key: citation[key] for key in ("path", "line", "end_line", "sha256")}
                         for citation in json.loads(turn["citations"]) if citation.get("quote_checked")]
            if not dependencies or not citations:
                raise InsightConflict("这条回答没有可核对的源码引用")
            environment = declared_environment(access) if track_environment else None
            if track_environment and environment is None:
                raise InsightConflict("无法核对根目录中的依赖或版本声明")
            if not sources_current(access, dependencies):
                raise InsightConflict("原回答用到的源码已变化，请根据当前源码重新提问后保存")
            _check_policy(workspace, access, expected_policy_version)
            existing = db.execute("SELECT * FROM conversation_insights WHERE workspace_id=? AND origin_turn_id=? "
                                  "AND topic_id IS ? AND kind=? AND statement=? AND (environment IS NOT NULL)=?",
                                  (wid, tid, topic_id, kind, statement, track_environment)).fetchone()
            if existing:
                # An identical retry never reactivates an older record.
                result = _public(self._refresh(db, [existing], access)[0])
                _check_policy(workspace, access, expected_policy_version)
                return result
            if db.execute("SELECT count(*) FROM conversation_insights WHERE workspace_id=?", (wid,)).fetchone()[0] >= MAX_INSIGHTS:
                raise InsightConflict("本项目的笔记已达到 100 条，请先删除不再需要的记录")
            identity, stamp = uuid.uuid4().hex, now()
            evidence = json.dumps({"dependencies": dependencies, "citations": citations}, ensure_ascii=False)
            db.execute("INSERT INTO conversation_insights VALUES(?,?,?,?,?,?,?,?,?,'active',NULL,?,?)",
                       (identity, wid, topic_id, cid, tid, statement, kind, evidence,
                        json.dumps(environment) if track_environment else None, stamp, stamp))
            return _public(db.execute("SELECT * FROM conversation_insights WHERE id=?", (identity,)).fetchone())

    @staticmethod
    def _refresh(db, rows, access):
        environment = (declared_environment(access) if any(row["status"] == "active" and row["environment"] is not None
                                                           for row in rows) else None)
        digests, updated = {}, []
        stamp = now()
        for row in rows:
            row = dict(row)
            if row["status"] == "active":
                reason = None
                evidence = json.loads(row["evidence"])
                upgraded = None
                dependencies = evidence.get("dependencies")
                if dependencies is None:
                    origin = _answer_record(db, row["workspace_id"], row["origin_conversation_id"], row["origin_turn_id"])
                    dependencies = _dependencies(origin) if origin else None
                    if not dependencies:
                        reason = "history"
                    else:
                        upgraded = json.dumps({"dependencies": dependencies, "citations": evidence["citations"]}, ensure_ascii=False)
                for source in dependencies or []:
                    path = source["path"]
                    if path not in digests:
                        digests[path] = source_digest(access, path)
                    if digests[path] != source["sha256"]:
                        reason = "source"
                        break
                if reason is None and row["environment"] is not None and environment != json.loads(row["environment"]):
                    reason = "environment"
                row.update(status="stale" if reason else "active", drift_reason=reason, last_checked_at=stamp)
                db.execute("UPDATE conversation_insights SET status=?,drift_reason=?,last_checked_at=?,"
                           "evidence=COALESCE(?,evidence) WHERE id=?", (row["status"], reason, stamp, upgraded, row["id"]))
            updated.append(row)
        return updated

    def list(self, workspace, access, cid):
        with self.store.connection() as db:
            if cid is not None and not db.execute("SELECT 1 FROM conversations WHERE id=? AND workspace_id=?",
                                                   (cid, workspace["id"])).fetchone():
                raise KeyError("对话不存在")
            rows = db.execute("SELECT * FROM conversation_insights WHERE workspace_id=? "
                              "AND (topic_id IS NULL OR topic_id=?) ORDER BY created_at DESC,id",
                              (workspace["id"], cid)).fetchall()
            result = [_public(row) for row in self._refresh(db, rows, access)]
            _check_policy(workspace, access)
            return result

    def change(self, workspace, access, identity, *, cid, action, expected_policy_version):
        _check_policy(workspace, access, expected_policy_version)
        with self.store.connection() as db:
            row = db.execute("SELECT * FROM conversation_insights WHERE id=? AND workspace_id=? "
                             "AND (topic_id IS NULL OR topic_id=?)", (identity, workspace["id"], cid)).fetchone()
            if row is None:
                raise KeyError("当前范围中没有这条笔记")
            if action == "retire":
                db.execute("UPDATE conversation_insights SET status='retired' WHERE id=?", (identity,))
            elif row["status"] == "retired":
                db.execute("DELETE FROM conversation_insights WHERE id=?", (identity,))
            else:
                raise InsightConflict("请先归档这条笔记")
