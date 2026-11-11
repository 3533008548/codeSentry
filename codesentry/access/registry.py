"""A live permission guard over one pinned, read-only workspace registry.

Connections are reused; authorizations are never cached. Every check executes a
fresh autocommit query and verifies the database pathname before and afterwards.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import weakref

from codesentry.access.policy import AccessDenied, is_link, validate_settings


DENIED = '工作空间文件权限已变化或注册表不可用；请在工作台重新确认范围'
MAX_POLICY_CHARACTERS = 8 * 1024 * 1024


class RegistryGuard:
    """Serialize fresh checks on a pinned SQLite identity, including absence.

    The lock protects this guard's connection, not an entire AccessPolicy.
    Replacement or any failed check permanently invalidates this guard; callers
    must obtain a new confirmed policy rather than reconnect an old snapshot.
    """

    def __init__(self, root: Path, data_dir: Path, *, workspace_id: str | None = None,
                 snapshot: dict | None = None):
        self.root = Path(root).expanduser().resolve()
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.database = self.data_dir / 'workspaces.sqlite3'
        self._key = os.path.normcase(str(self.root))
        self._pid = os.getpid()
        self._lock = threading.RLock()
        self._connection = None
        self._finalizer = None
        self._closed = False
        self._failed = False
        self._expected = None
        self._snapshot = None
        try:
            self._identity = self._database_identity()
            if self._identity is not None:
                self._connection = sqlite3.connect(
                    self.database.as_uri() + '?mode=ro', uri=True,
                    isolation_level=None, check_same_thread=False, timeout=0.5,
                )
                self._finalizer = weakref.finalize(self, self._connection.close)
                self._connection.row_factory = sqlite3.Row
            if self._database_identity() != self._identity:
                raise AccessDenied(DENIED)
            row = self._read_row()
            if row is not None:
                policy = self._parse_policy(row['access_policy'], validate=True)
                self._expected = self._row_identity(row, policy)
                self._snapshot = copy.deepcopy(policy)
            if workspace_id is not None or snapshot is not None:
                if (self._expected is None or workspace_id != self._expected[0]
                        or self._policy_identity(snapshot, validate=True) != self._expected[3:]):
                    raise AccessDenied(DENIED)
            self.check_current()
        except BaseException as error:
            self.close()
            if isinstance(error, (OSError, ValueError, TypeError, KeyError, sqlite3.Error)):
                raise AccessDenied(DENIED) from error
            raise

    def _database_identity(self):
        # A data-directory redirect must not make an existing SQLite handle an
        # authority over a different registry now exposed at the same pathname.
        if self.data_dir.resolve() != self.data_dir:
            raise AccessDenied(DENIED)
        try:
            metadata = self.database.lstat()
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(metadata.st_mode) or is_link(self.database)
                or metadata.st_nlink != 1 or not metadata.st_ino
                or self.database.resolve() != self.database):
            raise AccessDenied(DENIED)
        return metadata.st_dev, metadata.st_ino

    def _read_row(self):
        if self._connection is None:
            return None
        # Fixed columns intentionally reject old schemas rather than dropping
        # workspace identity checks to accommodate unconfirmed migrations.
        cursor = self._connection.execute(
            'SELECT id,path,canonical_key,CASE WHEN length(access_policy)<=? '
            'THEN access_policy ELSE NULL END AS access_policy '
            'FROM workspaces WHERE canonical_key=? LIMIT 2',
            (MAX_POLICY_CHARACTERS, self._key),
        )
        try:
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if len(rows) > 1:
            raise AccessDenied(DENIED)
        return rows[0] if rows else None

    @staticmethod
    def _policy_identity(policy, *, validate=False):
        if (not isinstance(policy, dict) or policy.get('confirmed') is not True
                or policy.get('cleanup_pending') is not False
                or type(policy.get('version')) is not int or policy['version'] < 1
                or not isinstance(policy.get('fingerprint'), str)
                or re.fullmatch(r'[0-9a-f]{64}', policy['fingerprint']) is None
                or not isinstance(policy.get('settings'), dict)):
            raise AccessDenied(DENIED)
        settings = policy['settings']
        # Python considers True == 1; typed permission data must not gain
        # equality with a validated snapshot through that numeric coercion.
        if (set(settings) != {'respect_gitignore', 'exclude', 'local_only', 'model_scope'}
                or type(settings['respect_gitignore']) is not bool
                or any(not isinstance(settings[key], list)
                       or any(not isinstance(value, str) for value in settings[key])
                       for key in ('exclude', 'local_only', 'model_scope'))):
            raise AccessDenied(DENIED)
        if validate:
            validated = validate_settings(settings)
            if settings != validated:
                raise AccessDenied(DENIED)
            settings = validated
        return policy['version'], policy['fingerprint'], settings

    @classmethod
    def _parse_policy(cls, raw, *, validate=False):
        if not isinstance(raw, str) or len(raw) > MAX_POLICY_CHARACTERS:
            raise AccessDenied(DENIED)
        policy = json.loads(raw)
        cls._policy_identity(policy, validate=validate)
        return policy

    def _row_identity(self, row, policy):
        if (not isinstance(row['id'], str) or not row['id']
                or row['canonical_key'] != self._key
                or not isinstance(row['path'], str)
                or os.path.normcase(row['path']) != self._key):
            raise AccessDenied(DENIED)
        return row['id'], row['path'], row['canonical_key'], *self._policy_identity(policy)

    def check_current(self):
        with self._lock:
            if self._closed or self._failed or os.getpid() != self._pid:
                raise AccessDenied(DENIED)
            try:
                if self._database_identity() != self._identity:
                    raise AccessDenied(DENIED)
                row = self._read_row()
                current = None if row is None else self._row_identity(row, self._parse_policy(row['access_policy']))
                if current != self._expected or self._database_identity() != self._identity:
                    raise AccessDenied(DENIED)
            except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
                self._failed = True
                raise AccessDenied(DENIED) from error

    __call__ = check_current

    @property
    def settings(self):
        return None if self._snapshot is None else copy.deepcopy(self._snapshot['settings'])

    @property
    def snapshot(self):
        return copy.deepcopy(self._snapshot)

    @property
    def workspace_id(self):
        return None if self._expected is None else self._expected[0]

    @property
    def closed(self):
        return self._closed

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._finalizer is not None:
                self._finalizer()
            self._connection = None

    def __enter__(self):
        self.check_current()
        return self

    def __exit__(self, *_):
        self.close()
