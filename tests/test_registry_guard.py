"""Frozen synthetic revocation cases for a reusable read-only registry guard.

No inspected repository is opened; all projects and databases are fixtures.
"""
import copy
import gc
import json
import os
from pathlib import Path
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import weakref

import pytest

from codesentry.access import AccessDenied, validate_settings
from codesentry.access.registry import RegistryGuard


IDENTITY = 'a' * 32


@contextmanager
def database_connection(path):
    connection = sqlite3.connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def create_registry(directory, root, *, insert=True):
    directory.mkdir(parents=True, exist_ok=True)
    database = directory / 'workspaces.sqlite3'
    with database_connection(database) as connection:
        connection.execute('CREATE TABLE workspaces(id TEXT,path TEXT,canonical_key TEXT,access_policy TEXT)')
        policy = {'confirmed': True, 'cleanup_pending': False, 'version': 1,
                  'fingerprint': 'b' * 64, 'settings': validate_settings({})}
        if insert:
            connection.execute('INSERT INTO workspaces VALUES(?,?,?,?)',
                               (IDENTITY, str(root), os.path.normcase(str(root)), json.dumps(policy)))
    return database, policy


@pytest.fixture
def registered(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    directory = tmp_path / 'state'
    database, policy = create_registry(directory, root)
    return root, directory, database, policy


def update_policy(database, transform):
    with database_connection(database) as connection:
        policy = json.loads(connection.execute('SELECT access_policy FROM workspaces').fetchone()[0])
        transform(policy)
        connection.execute('UPDATE workspaces SET access_policy=?', (json.dumps(policy),))


def test_reuses_one_readonly_autocommit_connection_but_rechecks_each_time(registered, monkeypatch):
    root, directory, _, _ = registered
    original = sqlite3.connect
    opened = []

    def connect(*args, **kwargs):
        connection = original(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, 'connect', connect)
    with RegistryGuard(root, directory) as guard:
        for _ in range(50):
            guard()
        assert len(opened) == 1
        assert not opened[0].in_transaction
        with pytest.raises(sqlite3.OperationalError):
            opened[0].execute('DELETE FROM workspaces')
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute('SELECT 1')


@pytest.mark.parametrize('field,value', [
    ('confirmed', False), ('confirmed', 1), ('cleanup_pending', True),
    ('version', 2), ('version', True), ('fingerprint', 'c' * 64),
    ('settings', validate_settings({'exclude': ['private.py']})),
    ('settings', validate_settings({'local_only': ['main.py']})),
    ('settings', validate_settings({'model_scope': ['main.py']})),
    ('settings', {'respect_gitignore': 1, 'exclude': [], 'local_only': [], 'model_scope': []}),
])
def test_every_permission_identity_field_revokes_without_waiting_for_new_connection(registered, field, value):
    root, directory, database, _ = registered
    with RegistryGuard(root, directory) as guard:
        update_policy(database, lambda policy: policy.__setitem__(field, value))
        with pytest.raises(AccessDenied):
            guard()


@pytest.mark.parametrize('column,value', [('id', 'd' * 32), ('path', 'another-project'),
                                         ('canonical_key', 'another-key')])
def test_workspace_row_identity_is_pinned(registered, column, value):
    root, directory, database, _ = registered
    with RegistryGuard(root, directory) as guard:
        with database_connection(database) as connection:
            connection.execute(f'UPDATE workspaces SET {column}=?', (value,))
        with pytest.raises(AccessDenied):
            guard()


def test_deleted_or_duplicated_row_is_not_an_absence_authorization(registered):
    root, directory, database, _ = registered
    with RegistryGuard(root, directory) as guard:
        with database_connection(database) as connection:
            connection.execute('INSERT INTO workspaces SELECT * FROM workspaces')
        with pytest.raises(AccessDenied):
            guard()
    with database_connection(database) as connection:
        connection.execute('DELETE FROM workspaces')
    with RegistryGuard(root, directory) as absent:
        assert absent.settings is None
        absent()


@pytest.mark.parametrize('initial_database', [False, True])
def test_initial_absence_is_observed_until_new_registration(tmp_path, initial_database):
    root = tmp_path / 'project'
    root.mkdir()
    directory = tmp_path / 'state'
    if initial_database:
        database, policy = create_registry(directory, root, insert=False)
    with RegistryGuard(root, directory) as guard:
        assert guard.settings is None
        guard()
        if initial_database:
            with database_connection(database) as connection:
                connection.execute('INSERT INTO workspaces VALUES(?,?,?,?)',
                                   (IDENTITY, str(root), os.path.normcase(str(root)), json.dumps(policy)))
        else:
            create_registry(directory, root)
        with pytest.raises(AccessDenied):
            guard()


def test_replacement_and_deletion_fail_before_querying_old_connection(registered, tmp_path, monkeypatch):
    root, directory, database, _ = registered
    replacement, _ = create_registry(tmp_path / 'replacement', root)
    guard = RegistryGuard(root, directory)
    try:
        # Windows can refuse replacing an open SQLite database. Release only the
        # raw SQLite handle in that case, preserving the guard's pinned identity.
        try:
            os.replace(replacement, database)
        except PermissionError:
            guard._connection.close()
            os.replace(replacement, database)
        monkeypatch.setattr(guard, '_read_row', lambda: pytest.fail('Old connection queried after path replacement'))
        with pytest.raises(AccessDenied):
            guard()
    finally:
        guard.close()
    guard = RegistryGuard(root, directory)
    try:
        try:
            database.unlink()
        except PermissionError:
            guard._connection.close()
            database.unlink()
        monkeypatch.setattr(guard, '_read_row', lambda: pytest.fail('Deleted database queried'))
        with pytest.raises(AccessDenied):
            guard()
    finally:
        guard.close()


def test_identity_is_rechecked_after_query_and_failure_is_sticky(registered, monkeypatch):
    root, directory, _, _ = registered
    with RegistryGuard(root, directory) as guard:
        original = guard._database_identity
        identity = original()
        calls = 0

        def identity_after_query():
            nonlocal calls
            calls += 1
            return identity if calls == 1 else ('different', 'file')

        monkeypatch.setattr(guard, '_database_identity', identity_after_query)
        with pytest.raises(AccessDenied):
            guard()
        monkeypatch.setattr(guard, '_database_identity', original)
        with pytest.raises(AccessDenied):
            guard()


def test_expected_policy_is_not_mutable_through_snapshot_or_settings(registered):
    root, directory, _, policy = registered
    supplied = copy.deepcopy(policy)
    with RegistryGuard(root, directory, workspace_id=IDENTITY, snapshot=supplied) as guard:
        supplied['settings']['exclude'].append('mutation.py')
        guard.settings['exclude'].append('another.py')
        guard.snapshot['settings']['exclude'].append('third.py')
        guard()
        assert guard.settings['exclude'] == []


def test_worker_snapshot_must_match_live_root_identity_and_settings(registered):
    root, directory, _, policy = registered
    with pytest.raises(AccessDenied):
        RegistryGuard(root, directory, workspace_id='wrong', snapshot=policy)
    changed = copy.deepcopy(policy)
    changed['settings']['exclude'] = ['private.py']
    with pytest.raises(AccessDenied):
        RegistryGuard(root, directory, workspace_id=IDENTITY, snapshot=changed)


def test_connection_is_serialized_for_other_threads_and_close_is_idempotent(registered):
    root, directory, _, _ = registered
    guard = RegistryGuard(root, directory)
    with ThreadPoolExecutor(max_workers=4) as executor:
        assert list(executor.map(lambda _: guard(), range(20))) == [None] * 20
        executor.submit(guard.close).result()
    guard.close()
    assert guard.closed
    with pytest.raises(AccessDenied):
        guard()


def test_unclosed_guard_finalizer_releases_connection(registered):
    root, directory, _, _ = registered
    guard = RegistryGuard(root, directory)
    connection = guard._connection
    reference = weakref.ref(guard)
    del guard
    gc.collect()
    assert reference() is None
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute('SELECT 1')


def test_missing_schema_columns_cannot_downgrade_identity_checks(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    directory = tmp_path / 'state'
    directory.mkdir()
    with database_connection(directory / 'workspaces.sqlite3') as connection:
        connection.execute('CREATE TABLE workspaces(canonical_key TEXT,access_policy TEXT)')
    with pytest.raises(AccessDenied):
        RegistryGuard(root, directory)


@pytest.mark.parametrize('raw', ['not-json', '[]', '{"confirmed":true}',
                                 '{"confirmed":true,"cleanup_pending":false,"version":true}'])
def test_malformed_authorization_fails_closed(registered, raw):
    root, directory, database, _ = registered
    with database_connection(database) as connection:
        connection.execute('UPDATE workspaces SET access_policy=?', (raw,))
    with pytest.raises(AccessDenied):
        RegistryGuard(root, directory)
