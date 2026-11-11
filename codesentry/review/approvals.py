"""Explicit local-user baseline decisions in trusted external application state.

Snapshot dictionaries and v2 hashes are data, not credentials. Trusted adapters
must authorise the workspace and recompute/compare scan_preview before proposal
creation or approval. This module checks that data's shape, completeness and
binding, then records explicit decisions; it never imports repository baselines,
hides findings, authenticates an independent OS identity, or evaluates a gate.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from codesentry.access.policy import is_link
from codesentry.core.finding import Finding, Source
from codesentry.core.fingerprint import FingerprintV2


MAX_ISSUES = 10_000
MAX_SELECTED = 2000
SCHEMA_VERSION = 1


class BaselineConflict(ValueError):
    """A stale revision, source snapshot, or selected issue needs a new review."""


def _text(value, label):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or "\0" in value:
        raise ValueError(f"Invalid baseline {label}")
    return value


def _sha(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"Invalid baseline {label}")
    return value


def _reason(value):
    value = _text(value, "decision reason").strip()
    if len(value) > 2000:
        raise ValueError("Baseline decision reasons must not exceed 2000 characters")
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _name(value):
    _text(value, "source name")
    if ("\\" in value or ":" in value or value.startswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ValueError("Baseline source names must be workspace-relative")
    return value


def _safe(path):
    if any(is_link(part) for part in (path, *path.parents)):
        raise ValueError("Baseline application state is redirected")


@dataclass(frozen=True)
class BaselineContext:
    root: Path
    access_fingerprint: str
    access_version: int
    analysis_provenance: str
    policy_sha256: str

    def __post_init__(self):
        root = Path(self.root).expanduser().absolute()
        _safe(root)
        if root.resolve() != root or not root.is_dir():
            raise ValueError("Baseline needs a current canonical project directory")
        object.__setattr__(self, "root", root)
        _sha(self.access_fingerprint, "access fingerprint")
        _sha(self.policy_sha256, "policy identity")
        _text(self.analysis_provenance, "tool provenance")
        if type(self.access_version) is not int or self.access_version < 1:
            raise ValueError("Baseline needs a confirmed access revision")

    def to_dict(self):
        return asdict(self) | {"root": str(self.root)}

    @property
    def key(self):
        return _digest(self.to_dict())

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("Invalid baseline context fields")
        return cls(**value)


def _current(workspace_id, context, current, *, require_v2=True):
    """Validate a host-supplied complete preview without treating JSON as authority."""
    if type(context) is not BaselineContext or not isinstance(current, dict):
        raise TypeError("A trusted host context and preview are required")
    _text(workspace_id, "workspace identity")
    if (type(current.get("schema_version")) is not int or current["schema_version"] != 1
            or current.get("review_status") != "report_only" or current.get("gate_status") != "not_evaluated"
            or current.get("mode") != "preview" or current.get("issues") != []
            or current.get("language_scope") != "permitted_python_files_only"
            or current.get("access_fingerprint") != context.access_fingerprint
            or current.get("policy_sha256") != context.policy_sha256):
        raise ValueError("Only a complete, current in-scope preview can be reviewed")
    for field, expected in (("workspace_id", workspace_id), ("kind", "review_preview"),
                            ("policy_fingerprint", context.access_fingerprint), ("policy_version", context.access_version),
                            ("analysis_provenance", context.analysis_provenance)):
        if field in current and (type(current[field]) is not type(expected) or current[field] != expected):
            raise ValueError("Preview metadata belongs to another workspace or context")
    policy, coverage, hashes, rows = (current.get(key) for key in ("policy", "coverage", "source_sha256", "findings"))
    if not isinstance(policy, dict) or _digest(policy) != context.policy_sha256:
        raise ValueError("Preview policy hash does not match its complete configuration")
    if (not isinstance(coverage, dict) or coverage.get("within_scope_complete") is not True
            or coverage.get("whole_repository_evaluated") is not False or not isinstance(hashes, dict)
            or not hashes or not isinstance(rows, list) or len(rows) > MAX_ISSUES):
        raise ValueError("Preview coverage or issue collection is incomplete")
    for field in ("discovered_python", "analyzed_python", "attempted_python"):
        if type(coverage.get(field)) is not int or coverage[field] != len(hashes):
            raise ValueError("Preview source inventory is not completely accounted for")
    for path, digest in hashes.items():
        _name(path)
        _sha(digest, "source digest")
    declared = current.get("rules")
    if (not isinstance(declared, list) or not declared
            or any(not isinstance(rule, dict) or rule.get("approved_for_blocking") is not False for rule in declared)):
        raise ValueError("Only the declared report-only rules are supported")
    rules = {(rule.get("rule_id"), rule.get("rule_version")) for rule in declared}
    normalised, issues = [], []
    for index, row in enumerate(rows):
        if (not isinstance(row, dict) or row.get("mode") != "report_only"
                or row.get("classification") != "policy_debt" or row.get("can_block") is not False):
            raise ValueError("Invalid report-only issue wrapper")
        finding = Finding.model_validate(row.get("finding"))
        if (finding.source is not Source.DETERMINISTIC or finding.verified is not True
                or finding.file not in hashes or row.get("file") != finding.file
                or (finding.rule_id, finding.rule_version) not in rules
                or not finding.anchor or not finding.symbol):
            raise ValueError("Issue is not bound to the declared current source and rule")
        fingerprint = None
        try:
            fingerprint = FingerprintV2(finding.identity_digest, finding.evidence_digest, finding.combined_digest)
            if finding.fingerprint != fingerprint.combined_digest:
                raise ValueError("Legacy or inconsistent fingerprint")
        except ValueError:
            fingerprint = None
            if require_v2:
                raise ValueError("Baseline approval requires exact valid v2 fingerprints") from None
        value = finding.model_dump(mode="json", exclude={"created_at"})
        normalised.append({"finding": value, "mode": row["mode"], "classification": row["classification"],
                           "can_block": False, "file": row["file"]})
        issues.append({"ordinal": index, "file": finding.file, "line": finding.line, "end_line": finding.end_line,
                       "symbol": finding.symbol, "reason": finding.reason, "rule_id": finding.rule_id,
                       "rule_version": finding.rule_version, "anchor": finding.anchor, "occurrence": finding.occurrence,
                       "fingerprint": fingerprint.to_dict() if fingerprint is not None else None})
    summary = current.get("summary")
    if (not isinstance(summary, dict) or type(summary.get("policy_debt_findings")) is not int
            or summary["policy_debt_findings"] != len(rows) or summary.get("blocking_findings") != 0
            or summary.get("behavior_bug_findings") != 0):
        raise ValueError("Preview summary does not account for every issue occurrence")
    snapshot = {"policy": policy, "policy_sha256": context.policy_sha256,
                "source_sha256": hashes, "coverage": coverage, "rules": declared, "findings": normalised}
    return _digest(snapshot), issues


class BaselineStore:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir).expanduser().absolute()
        _safe(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        _safe(self.data_dir)
        self.database = self.data_dir / "baselines.sqlite3"
        _safe(self.database)
        if self.database.exists():
            self._identity_now()  # Refuse aliases before opening or writing state.
        connection = sqlite3.connect(self.database, isolation_level=None)
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS baseline_metadata(version INTEGER NOT NULL);
                INSERT INTO baseline_metadata(version) SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM baseline_metadata);
                CREATE TABLE IF NOT EXISTS baseline_workspaces(workspace_id TEXT PRIMARY KEY,revision INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS baseline_proposals(
                    id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,context_key TEXT NOT NULL,context_json TEXT NOT NULL,
                    source_analysis_id TEXT NOT NULL,snapshot_sha256 TEXT NOT NULL,created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS baseline_issues(
                    id TEXT PRIMARY KEY,proposal_id TEXT NOT NULL,ordinal INTEGER NOT NULL,issue_json TEXT NOT NULL,
                    UNIQUE(proposal_id,ordinal),FOREIGN KEY(proposal_id) REFERENCES baseline_proposals(id) ON DELETE CASCADE);
                CREATE TABLE IF NOT EXISTS baseline_records(
                    id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,proposal_id TEXT NOT NULL,issue_id TEXT NOT NULL UNIQUE,
                    context_key TEXT NOT NULL,identity_digest TEXT NOT NULL,evidence_digest TEXT NOT NULL,combined_digest TEXT NOT NULL,
                    status TEXT NOT NULL,approved_at TEXT NOT NULL,approval_reason TEXT NOT NULL,
                    revoked_at TEXT,revocation_reason TEXT,
                    FOREIGN KEY(proposal_id) REFERENCES baseline_proposals(id) ON DELETE CASCADE,
                    FOREIGN KEY(issue_id) REFERENCES baseline_issues(id) ON DELETE CASCADE);
                CREATE UNIQUE INDEX IF NOT EXISTS one_current_baseline_identity
                    ON baseline_records(workspace_id,context_key,identity_digest) WHERE status='approved';
                CREATE TABLE IF NOT EXISTS baseline_audit(
                    id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,revision INTEGER NOT NULL,action TEXT NOT NULL,
                    actor TEXT NOT NULL,created_at TEXT NOT NULL,proposal_id TEXT,record_id TEXT,
                    selection_count INTEGER NOT NULL,reason_sha256 TEXT);
            """)
            if connection.execute("SELECT version FROM baseline_metadata").fetchall() != [(SCHEMA_VERSION,)]:
                raise ValueError("Unsupported baseline state schema")
        finally:
            connection.close()
        self._identity = self._identity_now()

    def _identity_now(self):
        _safe(self.database)
        info = self.database.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_ino:
            raise ValueError("Baseline state must be a regular, unshared application file")
        return info.st_dev, info.st_ino

    def _context(self, context):
        if type(context) is not BaselineContext:
            raise TypeError("Typed baseline context is required; hashes alone do not authorise approval")
        if self.database.resolve().is_relative_to(context.root):
            raise ValueError("Baseline decisions must be stored outside the reviewed project")

    @contextmanager
    def _connection(self):
        if self._identity_now() != self._identity:
            raise ValueError("Baseline application state identity changed")
        connection = sqlite3.connect(self.database.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            if self._identity_now() != self._identity:
                raise ValueError("Baseline state changed during the transaction")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _revision(self, connection, workspace_id):
        row = connection.execute("SELECT revision FROM baseline_workspaces WHERE workspace_id=?", (workspace_id,)).fetchone()
        return row[0] if row else 0

    def _bump(self, connection, workspace_id, *, expected=None):
        revision = self._revision(connection, workspace_id)
        if expected is not None and (type(expected) is not int or expected < 0 or expected != revision):
            raise BaselineConflict("Baseline revision changed; refresh and review again")
        connection.execute("INSERT INTO baseline_workspaces(workspace_id,revision) VALUES(?,?) "
                           "ON CONFLICT(workspace_id) DO UPDATE SET revision=excluded.revision", (workspace_id, revision + 1))
        return revision + 1

    def _audit(self, connection, workspace_id, revision, action, *, proposal_id=None, record_id=None, count=0, reason=None):
        connection.execute("INSERT INTO baseline_audit VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (uuid.uuid4().hex, workspace_id, revision, action, "local_user", datetime.now(timezone.utc).isoformat(),
                            proposal_id, record_id, count, hashlib.sha256(reason.encode()).hexdigest() if reason is not None else None))

    def _proposal(self, connection, workspace_id, proposal_id):
        proposal = connection.execute("SELECT * FROM baseline_proposals WHERE workspace_id=? AND id=?",
                                      (workspace_id, proposal_id)).fetchone()
        if proposal is None:
            raise KeyError("Baseline proposal does not belong to this workspace")
        rows = connection.execute("SELECT id,issue_json FROM baseline_issues WHERE proposal_id=? ORDER BY ordinal", (proposal_id,)).fetchall()
        issues = [json.loads(row["issue_json"]) | {"id": row["id"]} for row in rows]
        counts = Counter(issue["fingerprint"]["identity_digest"] for issue in issues)
        for issue in issues:
            matches = connection.execute("SELECT id,status,evidence_digest FROM baseline_records WHERE workspace_id=? "
                                         "AND context_key=? AND identity_digest=? ORDER BY approved_at DESC",
                                         (workspace_id, proposal["context_key"], issue["fingerprint"]["identity_digest"])).fetchall()
            active = [row for row in matches if row["status"] == "approved"]
            direct = connection.execute("SELECT id,status FROM baseline_records WHERE issue_id=?", (issue["id"],)).fetchone()
            exact = len(active) == 1 and active[0]["evidence_digest"] == issue["fingerprint"]["evidence_digest"] and counts[issue["fingerprint"]["identity_digest"]] == 1
            issue["status"] = "approved" if exact else "revoked" if direct is not None and direct["status"] == "revoked" else "pending"
            issue["ambiguous"] = counts[issue["fingerprint"]["identity_digest"]] > 1
            if exact:
                issue["record_id"] = active[0]["id"]
        pending = sum(issue["status"] == "pending" for issue in issues)
        approved = sum(issue["status"] == "approved" for issue in issues)
        status = "pending" if pending == len(issues) else "partially_approved" if pending else "approved" if approved == len(issues) else "reviewed"
        return {"id": proposal["id"], "workspace_id": workspace_id, "revision": self._revision(connection, workspace_id),
                "status": status, "created_at": proposal["created_at"], "context": json.loads(proposal["context_json"]),
                "source_analysis_id": proposal["source_analysis_id"], "snapshot_sha256": proposal["snapshot_sha256"], "issues": issues}

    def _record(self, connection, workspace_id, record_id):
        row = connection.execute("SELECT r.*,i.issue_json,p.context_json,p.source_analysis_id FROM baseline_records r "
                                 "JOIN baseline_issues i ON i.id=r.issue_id JOIN baseline_proposals p ON p.id=r.proposal_id "
                                 "WHERE r.workspace_id=? AND r.id=?", (workspace_id, record_id)).fetchone()
        if row is None:
            raise KeyError("Baseline record does not belong to this workspace")
        result = dict(row)
        issue, context = json.loads(result.pop("issue_json")), json.loads(result.pop("context_json"))
        return issue | result | {"context": context, "actor": "local_user"}

    def create_proposal(self, workspace_id, context, current):
        self._context(context)
        snapshot_hash, issues = _current(workspace_id, context, current)
        analysis_id = _text(current.get("analysis_id"), "source analysis identity")
        proposal_id = uuid.uuid4().hex
        with self._connection() as connection:
            revision = self._bump(connection, workspace_id)
            connection.execute("INSERT INTO baseline_proposals VALUES(?,?,?,?,?,?,?)",
                               (proposal_id, workspace_id, context.key, _canonical(context.to_dict()), analysis_id,
                                snapshot_hash, datetime.now(timezone.utc).isoformat()))
            for issue in issues:
                connection.execute("INSERT INTO baseline_issues VALUES(?,?,?,?)",
                                   (uuid.uuid4().hex, proposal_id, issue["ordinal"], _canonical(issue)))
            self._audit(connection, workspace_id, revision, "proposal_created", proposal_id=proposal_id, count=len(issues))
            return self._proposal(connection, workspace_id, proposal_id)

    def approve(self, workspace_id, proposal_id, context, current, selected_ids, reason, expected_revision):
        self._context(context)
        reason = _reason(reason)
        try:
            snapshot_hash, _ = _current(workspace_id, context, current)
        except (ValueError, TypeError) as error:
            raise BaselineConflict("Preview or context is no longer complete and current") from error
        if (not isinstance(selected_ids, list) or not selected_ids or len(selected_ids) > MAX_SELECTED
                or any(not isinstance(value, str) for value in selected_ids) or len(set(selected_ids)) != len(selected_ids)):
            raise ValueError("Explicit unique issue IDs are required")
        with self._connection() as connection:
            proposal = self._proposal(connection, workspace_id, proposal_id)
            if (proposal["context"] != context.to_dict() or proposal["snapshot_sha256"] != snapshot_hash
                    or proposal["source_analysis_id"] != current.get("analysis_id")):
                raise BaselineConflict("Source, policy, tool, access or reviewed snapshot changed")
            issues = {issue["id"]: issue for issue in proposal["issues"]}
            if any(value not in issues or issues[value]["status"] != "pending" or issues[value]["ambiguous"] for value in selected_ids):
                raise BaselineConflict("Selected issue is absent, already reviewed, or ambiguous")
            revision = self._bump(connection, workspace_id, expected=expected_revision)
            record_ids = []
            for identity in selected_ids:
                issue, record_id = issues[identity], uuid.uuid4().hex
                fingerprint = issue["fingerprint"]
                if connection.execute("SELECT 1 FROM baseline_records WHERE workspace_id=? AND context_key=? "
                                      "AND identity_digest=? AND status='approved'", (workspace_id, context.key, fingerprint["identity_digest"])).fetchone():
                    raise BaselineConflict("Revoke the prior decision before approving changed evidence")
                connection.execute("INSERT INTO baseline_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (record_id, workspace_id, proposal_id, identity, context.key, fingerprint["identity_digest"],
                     fingerprint["evidence_digest"], fingerprint["combined_digest"], "approved",
                     datetime.now(timezone.utc).isoformat(), reason, None, None))
                record_ids.append(record_id)
            self._audit(connection, workspace_id, revision, "issues_approved", proposal_id=proposal_id, count=len(record_ids), reason=reason)
            return self._snapshot(connection, workspace_id, context) | {"approved_record_ids": record_ids}

    def revoke(self, workspace_id, record_id, context, reason, expected_revision):
        self._context(context)
        reason = _reason(reason)
        with self._connection() as connection:
            record = self._record(connection, workspace_id, record_id)
            if record["context"] != context.to_dict() or record["status"] != "approved":
                raise BaselineConflict("Record context changed or the decision was already revoked")
            revision = self._bump(connection, workspace_id, expected=expected_revision)
            connection.execute("UPDATE baseline_records SET status='revoked',revoked_at=?,revocation_reason=? WHERE id=?",
                               (datetime.now(timezone.utc).isoformat(), reason, record_id))
            self._audit(connection, workspace_id, revision, "approval_revoked", record_id=record_id, count=1, reason=reason)
            return self._snapshot(connection, workspace_id, context) | {"revoked_record_id": record_id}

    def _snapshot(self, connection, workspace_id, context):
        proposals = [self._proposal(connection, workspace_id, row[0]) for row in connection.execute(
            "SELECT id FROM baseline_proposals WHERE workspace_id=? AND context_key=? ORDER BY created_at,id", (workspace_id, context.key))]
        records = [self._record(connection, workspace_id, row[0]) for row in connection.execute(
            "SELECT id FROM baseline_records WHERE workspace_id=? AND context_key=? ORDER BY approved_at,id", (workspace_id, context.key))]
        audit = [dict(row) for row in connection.execute("SELECT * FROM baseline_audit WHERE workspace_id=? ORDER BY revision,id", (workspace_id,))]
        return {"workspace_id": workspace_id, "revision": self._revision(connection, workspace_id), "context": context.to_dict(),
                "proposals": proposals, "records": records, "audit": audit, "gate_status": "not_evaluated",
                "local_user_decisions": True, "independent_identity_verified": False, "findings_hidden": 0}

    def snapshot(self, workspace_id, context):
        _text(workspace_id, "workspace identity")
        self._context(context)
        with self._connection() as connection:
            return self._snapshot(connection, workspace_id, context)

    def get_proposal(self, workspace_id, proposal_id):
        with self._connection() as connection:
            return self._proposal(connection, workspace_id, proposal_id)

    def get_record(self, workspace_id, record_id):
        with self._connection() as connection:
            return self._record(connection, workspace_id, record_id)

    def annotate(self, workspace_id, context, current):
        self._context(context)
        _, issues = _current(workspace_id, context, current, require_v2=False)
        result = json.loads(_canonical(current))
        counts = Counter(issue["fingerprint"]["identity_digest"] for issue in issues if issue["fingerprint"] is not None)
        with self._connection() as connection:
            revision = self._revision(connection, workspace_id)
            for row, issue in zip(result["findings"], issues):
                fingerprint = issue["fingerprint"]
                annotation = {"status": "new", "exemption_applied": False}
                if fingerprint is None:
                    annotation["status"] = "unsupported_fingerprint"
                elif counts[fingerprint["identity_digest"]] > 1:
                    annotation["status"] = "ambiguous"
                else:
                    matches = connection.execute("SELECT id,status,evidence_digest,combined_digest,context_key FROM baseline_records "
                        "WHERE workspace_id=? AND identity_digest=?", (workspace_id, fingerprint["identity_digest"])).fetchall()
                    scoped = [record for record in matches if record["context_key"] == context.key]
                    active = [record for record in scoped if record["status"] == "approved"]
                    if len(active) > 1:
                        annotation["status"] = "ambiguous"
                    elif active:
                        record = active[0]
                        if (record["evidence_digest"] == fingerprint["evidence_digest"]
                                and record["combined_digest"] == fingerprint["combined_digest"]):
                            annotation.update(status="approved", record_id=record["id"])
                        else:
                            annotation["status"] = "evidence_changed"
                    elif scoped:
                        annotation["status"] = "revoked"
                    elif matches:
                        annotation["status"] = "context_changed"
                row["baseline"] = annotation
        result["baseline"] = {"revision": revision, "approved_exact_matches": sum(
            row["baseline"]["status"] == "approved" for row in result["findings"]),
            "findings_hidden": 0, "gate_exemptions_applied": False, "gate_status": "not_evaluated"}
        return result

    def invalidate_workspace(self, workspace_id):
        _text(workspace_id, "workspace identity")
        with self._connection() as connection:
            revision = self._bump(connection, workspace_id)
            count = connection.execute("SELECT COUNT(*) FROM baseline_proposals WHERE workspace_id=?", (workspace_id,)).fetchone()[0]
            connection.execute("DELETE FROM baseline_proposals WHERE workspace_id=?", (workspace_id,))
            self._audit(connection, workspace_id, revision, "workspace_invalidated", count=count)
        return {"workspace_id": workspace_id, "revision": revision, "content_cleared": True, "minimal_audit_preserved": True}
