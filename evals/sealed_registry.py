"""Operator-declared evaluation metadata and feedback history, not access control.

The SQLite event chain detects accidental edits, replay, and state conflicts.
An owner able to rewrite this database can rebuild its chain or restore an old
copy. No gold is opened, no candidate runs, and no operating-system isolation or
actual holdout evaluation eligibility is established by these declarations.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from codesentry.access.policy import is_link


SCHEMA_VERSION = 1
MAX_PAYLOAD_BYTES = 256 * 1024
MAX_EVENTS = 100_000
PARTITIONS = {"train", "dev", "holdout"}
OUTCOMES = {"passed", "failed", "incomplete", "error", "cancelled"}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_KNOWN_DEV = {"researchagent", "knowledgeloop", "agentforobsidian", "codesentry"}


def _text(value, name):
    if (not isinstance(value, str) or not value or len(value) > 512 or value != value.strip()
            or any(ord(char) < 32 for char in value)):
        raise ValueError(f"invalid {name}")
    return value


def _hash(value, name):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


def _groups(values, name):
    if (not isinstance(values, tuple) or not 0 < len(values) <= 128
            or any(not isinstance(value, str) for value in values)):
        raise ValueError(f"invalid {name}")
    for value in values:
        _text(value, name)
    if len({value.casefold() for value in values}) != len(values):
        raise ValueError(f"duplicate {name}")


def _known_dev(group):
    leaf = group.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for prefix in ("repo:", "repository:"):
        if leaf.startswith(prefix):
            leaf = leaf[len(prefix):]
    return re.sub(r"[^a-z0-9]", "", leaf) in _KNOWN_DEV


@dataclass(frozen=True)
class BatchSpec:
    batch_id: str
    dataset_id: str
    dataset_version: str
    source_groups: tuple[str, ...]
    defect_families: tuple[str, ...]
    partition: str
    frozen_input_hash: str
    scorer_hash: str
    preregistration_hash: str

    def __post_init__(self):
        for name in ("batch_id", "dataset_id", "dataset_version"):
            _text(getattr(self, name), name)
        _groups(self.source_groups, "source groups")
        _groups(self.defect_families, "defect families")
        if not isinstance(self.partition, str) or self.partition not in PARTITIONS:
            raise ValueError("invalid partition")
        for name in ("frozen_input_hash", "scorer_hash", "preregistration_hash"):
            _hash(getattr(self, name), name)

    def to_dict(self):
        return asdict(self) | {"source_groups": sorted(self.source_groups), "defect_families": sorted(self.defect_families)}


def _tokens(batch):
    return {("source", value.casefold()) for value in batch["source_groups"]} | {
        ("family", value.casefold()) for value in batch["defect_families"]}


def _connected(batches, batch_id):
    selected, tokens = {batch_id}, _tokens(batches[batch_id])
    changed = True
    while changed:
        changed = False
        for identity, batch in batches.items():
            if identity not in selected and tokens & _tokens(batch):
                selected.add(identity)
                tokens |= _tokens(batch)
                changed = True
    return selected


def _fields(payload, keys):
    if not isinstance(payload, dict) or set(payload) != keys:
        raise ValueError("invalid event payload fields")


def _apply(state, kind, payload, event_id):
    """Revalidate transitions both before insertion and when replaying history."""
    batches, evaluations = state["batches"], state["evaluations"]
    if kind == "batch_registered":
        _fields(payload, set(BatchSpec.__dataclass_fields__))
        if not isinstance(payload["source_groups"], list) or not isinstance(payload["defect_families"], list):
            raise ValueError("group metadata must be lists")
        spec = BatchSpec(**(payload | {"source_groups": tuple(payload["source_groups"]),
                                     "defect_families": tuple(payload["defect_families"])}))
        if spec.batch_id in batches:
            raise ValueError("batch identity is already frozen")
        if spec.partition == "holdout" and any(_known_dev(group) for group in spec.source_groups):
            raise ValueError("known development groups cannot become holdout")
        for batch in batches.values():
            if _tokens(payload) & _tokens(batch) and spec.partition != batch["effective_partition"]:
                raise ValueError("related source or defect groups cannot cross partitions or regain holdout")
        batches[spec.batch_id] = payload | {"effective_partition": spec.partition,
                                          "registered_event": event_id, "demoted_by": []}
        return
    if kind == "evaluation_started":
        _fields(payload, {"batch_id", "evaluation_id", "candidate_id", "candidate_version", "candidate_hash"})
        for key in ("batch_id", "evaluation_id", "candidate_id", "candidate_version"):
            _text(payload[key], key)
        _hash(payload["candidate_hash"], "candidate hash")
        if payload["batch_id"] not in batches or payload["evaluation_id"] in evaluations:
            raise ValueError("unknown batch or replayed evaluation identity")
        for prior in evaluations.values():
            same = all(prior[key] == payload[key] for key in ("candidate_id", "candidate_version"))
            if same and prior["candidate_hash"] != payload["candidate_hash"]:
                raise ValueError("a frozen candidate version cannot change bytes")
            if (prior["state"] == "started" and prior["batch_id"] == payload["batch_id"]
                    and prior["candidate_hash"] == payload["candidate_hash"]):
                raise ValueError("the same batch and candidate already have an active evaluation")
        evaluations[payload["evaluation_id"]] = payload | {
            "state": "started", "start_event": event_id, "outcome": None, "report_hash": None,
            "released_to": [], "feedback_accesses": [], "feedback_uses": []}
        return
    if kind == "evaluation_finished":
        _fields(payload, {"evaluation_id", "outcome", "report_hash"})
        _text(payload["evaluation_id"], "evaluation identity")
        evaluation = evaluations.get(payload["evaluation_id"])
        if evaluation is None or evaluation["state"] != "started":
            raise ValueError("evaluation must start once before finishing once")
        if not isinstance(payload["outcome"], str) or payload["outcome"] not in OUTCOMES:
            raise ValueError("invalid evaluation outcome")
        _hash(payload["report_hash"], "report hash")
        evaluation.update(state="finished", outcome=payload["outcome"], report_hash=payload["report_hash"],
                          finish_event=event_id)
        return
    expected = {"feedback_released": {"evaluation_id", "recipient"},
                "feedback_accessed": {"evaluation_id", "actor"},
                "feedback_used": {"evaluation_id", "modification_id", "note"}}
    if kind not in expected:
        raise ValueError("unknown registry event")
    _fields(payload, expected[kind])
    for key, value in payload.items():
        _text(value, key)
    evaluation = evaluations.get(payload["evaluation_id"])
    if evaluation is None or evaluation["state"] != "finished":
        raise ValueError("feedback requires a finished evaluation")
    if kind == "feedback_released":
        if payload["recipient"] in evaluation["released_to"]:
            raise ValueError("feedback has already been released to this recipient")
        evaluation["released_to"].append(payload["recipient"])
    elif kind == "feedback_accessed":
        if payload["actor"] not in evaluation["released_to"]:
            raise ValueError("record release to this declared actor before recording access")
        evaluation["feedback_accesses"].append(payload | {"event_id": event_id})
    else:
        if not evaluation["feedback_accesses"]:
            raise ValueError("feedback use requires prior recorded release and access")
        if any(item["modification_id"] == payload["modification_id"] for item in evaluation["feedback_uses"]):
            raise ValueError("feedback use for this modification was already recorded")
        evaluation["feedback_uses"].append(payload | {"event_id": event_id})
        for identity in _connected(batches, evaluation["batch_id"]):
            batch = batches[identity]
            if batch["effective_partition"] == "holdout":
                batch["effective_partition"] = "dev"
                batch["demoted_by"].append(event_id)


def _path_identity(path):
    if any(is_link(part) for part in (path, *path.parents)):
        raise ValueError("registry path is redirected")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or not metadata.st_ino:
        raise ValueError("registry must be a direct, unshared regular file")
    return metadata.st_dev, metadata.st_ino


class SealedRegistry:
    def __init__(self, path: Path):
        self.path = Path(path).expanduser().absolute()
        self._identity = _path_identity(self.path)
        self.inspect()

    @classmethod
    def create(cls, path: Path, *, operator_id: str):
        _text(operator_id, "declared operator")
        path = Path(path).expanduser().absolute()
        if any(is_link(part) for part in (path.parent, *path.parent.parents)):
            raise ValueError("registry parent is redirected")
        with path.open("xb"):
            pass
        header = {"schema_version": str(SCHEMA_VERSION), "registry_id": uuid.uuid4().hex,
                  "created_at": datetime.now(timezone.utc).isoformat(), "operator_id": operator_id}
        connection = sqlite3.connect(path)
        try:
            connection.executescript("""
                PRAGMA user_version=1;
                CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE events(
                    sequence INTEGER PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,created_at TEXT NOT NULL,payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);
            """)
            connection.executemany("INSERT INTO metadata(key,value) VALUES(?,?)", [*header.items(),
                                   ("event_count", "0"), ("head_hash", _digest(header))])
            connection.commit()
        finally:
            connection.close()
        return cls(path)

    @contextmanager
    def _connection(self, *, write=False):
        if _path_identity(self.path) != self._identity:
            raise ValueError("registry file identity changed")
        connection = sqlite3.connect(self.path.as_uri() + ("?mode=rw" if write else "?mode=ro"),
                                     uri=True, isolation_level=None, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            if _path_identity(self.path) != self._identity:
                raise ValueError("registry path changed during the transaction")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _read(self, connection):
        if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise ValueError("unsupported registry schema")
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        if set(metadata) != {"schema_version", "registry_id", "created_at", "operator_id", "event_count", "head_hash"}:
            raise ValueError("invalid registry metadata")
        header = {key: metadata[key] for key in ("schema_version", "registry_id", "created_at", "operator_id")}
        if header["schema_version"] != str(SCHEMA_VERSION):
            raise ValueError("registry schema identity changed")
        for key in ("registry_id", "created_at", "operator_id"):
            _text(header[key], key)
        state = {"batches": {}, "evaluations": {}}
        previous, event_ids, events = _digest(header), set(), []
        rows = connection.execute("SELECT * FROM events ORDER BY sequence")
        for sequence, row in enumerate(rows, 1):
            if sequence > MAX_EVENTS or row["sequence"] != sequence or row["event_id"] in event_ids:
                raise ValueError("registry event order or replay is invalid")
            _text(row["event_id"], "event identity")
            _text(row["created_at"], "event timestamp")
            if len(row["payload"].encode()) > MAX_PAYLOAD_BYTES:
                raise ValueError("registry payload exceeds limit")
            payload = json.loads(row["payload"], object_pairs_hook=_unique)
            if _canonical(payload) != row["payload"]:
                raise ValueError("registry payload encoding changed")
            body = {"sequence": sequence, "event_id": row["event_id"], "kind": row["kind"],
                    "created_at": row["created_at"], "payload": payload, "previous_hash": previous}
            calculated = _digest(body)
            if row["previous_hash"] != previous or row["event_hash"] != calculated:
                raise ValueError("registry event chain is invalid")
            _apply(state, row["kind"], payload, row["event_id"])
            previous = calculated
            event_ids.add(row["event_id"])
            events.append(body | {"event_hash": calculated})
        if metadata["event_count"] != str(len(events)) or metadata["head_hash"] != previous:
            raise ValueError("registry event tail or head checkpoint changed")
        return header, state, events, previous, event_ids

    def _append(self, kind, payload, *, event_id):
        _text(event_id, "event identity")
        encoded = _canonical(payload)
        if len(encoded.encode()) > MAX_PAYLOAD_BYTES:
            raise ValueError("event payload exceeds limit")
        # Normalise tuples to the fixed event JSON representation before replay.
        payload = json.loads(encoded)
        with self._connection(write=True) as connection:
            _, state, events, previous, event_ids = self._read(connection)
            if event_id in event_ids or len(events) >= MAX_EVENTS:
                raise ValueError("event identity was already used or the ledger is full")
            _apply(state, kind, payload, event_id)
            created = datetime.now(timezone.utc).isoformat()
            body = {"sequence": len(events) + 1, "event_id": event_id, "kind": kind,
                    "created_at": created, "payload": payload, "previous_hash": previous}
            digest = _digest(body)
            connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                               (body["sequence"], event_id, kind, created, encoded, previous, digest))
            connection.execute("UPDATE metadata SET value=? WHERE key='event_count'", (str(body["sequence"]),))
            connection.execute("UPDATE metadata SET value=? WHERE key='head_hash'", (digest,))
        return {"event_id": event_id, "sequence": body["sequence"], "event_hash": digest,
                "operator_declaration_only": True, "os_isolation_verified": False,
                "holdout_evaluation_ready": False}

    def register_batch(self, spec: BatchSpec, *, event_id: str):
        if type(spec) is not BatchSpec:
            raise TypeError("typed batch metadata is required")
        return self._append("batch_registered", spec.to_dict(), event_id=event_id)

    def start_evaluation(self, batch_id, evaluation_id, candidate_id, candidate_version, candidate_hash, *, event_id):
        return self._append("evaluation_started", {"batch_id": batch_id, "evaluation_id": evaluation_id,
                            "candidate_id": candidate_id, "candidate_version": candidate_version,
                            "candidate_hash": candidate_hash}, event_id=event_id)

    def finish_evaluation(self, evaluation_id, outcome, report_hash, *, event_id):
        return self._append("evaluation_finished", {"evaluation_id": evaluation_id, "outcome": outcome,
                                                   "report_hash": report_hash}, event_id=event_id)

    def release_feedback(self, evaluation_id, recipient, *, event_id):
        return self._append("feedback_released", {"evaluation_id": evaluation_id, "recipient": recipient}, event_id=event_id)

    def access_feedback(self, evaluation_id, actor, *, event_id):
        return self._append("feedback_accessed", {"evaluation_id": evaluation_id, "actor": actor}, event_id=event_id)

    def use_feedback(self, evaluation_id, modification_id, note, *, event_id):
        return self._append("feedback_used", {"evaluation_id": evaluation_id, "modification_id": modification_id,
                                              "note": note}, event_id=event_id)

    def inspect(self):
        with self._connection() as connection:
            header, state, events, head, _ = self._read(connection)
        return {"schema_version": SCHEMA_VERSION, "kind": "sealed-metadata-registry", "registry_id": header["registry_id"],
                "declared_operator": header["operator_id"], "event_count": len(events), "head_hash": head,
                "chain_valid": True, "batches": list(state["batches"].values()),
                "evaluations": list(state["evaluations"].values()), "events": events,
                "operator_declaration_only": True, "os_isolation_verified": False,
                "holdout_evaluation_ready": False, "gold_read": False, "candidate_executed": False,
                "formal_acceptance": {"passed": False},
                "limitations": ["Same-permission owners can rewrite the ledger or restore an older complete copy.",
                                "Group declarations do not discover undeclared renames, copies, or related defects.",
                                "This metadata workflow never authorizes holdout scoring or supplies OS isolation."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Operator-declared evaluation metadata; never gold access or execution")
    parser.add_argument("operation", choices=("init", "register", "inspect"))
    parser.add_argument("database", type=Path)
    parser.add_argument("--operator")
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--event-id")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == "init":
            registry = SealedRegistry.create(args.database, operator_id=args.operator)
        else:
            registry = SealedRegistry(args.database)
        if args.operation == "register":
            if args.metadata is None:
                raise ValueError("explicit batch metadata is required")
            with args.metadata.open("rb") as stream:
                data = stream.read(MAX_PAYLOAD_BYTES + 1)
            if len(data) > MAX_PAYLOAD_BYTES:
                raise ValueError("batch metadata exceeds limit")
            payload = json.loads(data, object_pairs_hook=_unique)
            _fields(payload, set(BatchSpec.__dataclass_fields__))
            if not isinstance(payload["source_groups"], list) or not isinstance(payload["defect_families"], list):
                raise ValueError("explicit group lists are required")
            spec = BatchSpec(**(payload | {"source_groups": tuple(payload["source_groups"]),
                                         "defect_families": tuple(payload["defect_families"])}))
            registry.register_batch(spec, event_id=args.event_id)
        report = registry.inspect()
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
        print(json.dumps({key: report[key] for key in ("registry_id", "event_count", "head_hash", "chain_valid",
                         "operator_declaration_only", "os_isolation_verified", "holdout_evaluation_ready")}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        print("Registry unavailable: invalid metadata, replay, integrity error, or output conflict; no eligibility granted")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
