"""Local snapshot tests use invented sources and never execute their code."""
import json
import os
from pathlib import Path

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.execution.snapshot import (SnapshotCleanupPending, prepare_snapshot,
                                          validate_snapshot)


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_text("raise RuntimeError('MUST_NOT_EXECUTE')\n", encoding="utf-8")
    (root / "module").mkdir()
    (root / "module/helper.py").write_text("VALUE=1\n", encoding="utf-8")
    return root


def export(source, tmp_path, *, access=None, paths=("main.py", "module/helper.py"), **limits):
    return prepare_snapshot(access or AccessPolicy(source), tmp_path / "export",
        paths=paths, **({"max_files": 10, "max_bytes": 4096, "max_file_bytes": 1024} | limits))


def test_exact_copy_and_local_manifest_are_separate_from_mounted_input(source, tmp_path):
    with export(source, tmp_path) as snapshot:
        assert snapshot.file_count == 2
        assert (snapshot.directory / "main.py").read_bytes() == (source / "main.py").read_bytes()
        manifest = json.loads(snapshot.manifest_path.read_text(encoding="utf-8"))
        assert manifest["content_sha256"] == snapshot.digest
        assert not manifest["model_use_authorized"]
        assert not snapshot.manifest_path.is_relative_to(snapshot.directory)
        assert manifest["source_freshness_after_export"] == "not_asserted"
        validate_snapshot(snapshot.directory, snapshot.digest)
    assert not (tmp_path / "export").exists()
    assert (source / "main.py").is_file()


@pytest.mark.parametrize("relative,settings", [
    (".env", {}), ("ignored.py", {}), ("private.py", {"exclude": ["private.py"]}),
])
def test_denied_inputs_are_not_opened_or_silently_dropped(source, tmp_path, monkeypatch, relative, settings):
    (source / relative).write_text("private sentinel", encoding="utf-8")
    (source / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    access = AccessPolicy(source, settings)
    original = Path.open
    def checked(path, *args, **kwargs):
        if path == source / relative:
            pytest.fail("excluded bytes were opened")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", checked)
    with pytest.raises(AccessDenied):
        export(source, tmp_path, access=access, paths=("main.py", relative))
    assert not (tmp_path / "export").exists()


def test_unconfirmed_has_no_output(source, tmp_path):
    with pytest.raises(AccessDenied):
        export(source, tmp_path, access=AccessPolicy(source, confirmed=False))
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("paths", [(), ("main.py", "main.py"), ("main.py", "MAIN.py"),
    ("../main.py",), ("module\\helper.py",), ("/main.py",), ("nul",), ("name. ",)])
def test_portable_names_and_nonempty_unique_list(source, tmp_path, paths):
    with pytest.raises(ValueError):
        export(source, tmp_path, paths=paths)
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("limits", [{"max_files": 1}, {"max_bytes": 1}, {"max_file_bytes": 1},
                                    {"max_files": True}, {"max_bytes": 0}])
def test_explicit_task_budgets_enforced_without_partial_export(source, tmp_path, limits):
    with pytest.raises(ValueError):
        export(source, tmp_path, **limits)
    assert not (tmp_path / "export").exists()


def test_export_refuses_existing_or_in_source_destination(source, tmp_path):
    existing = tmp_path / "export"
    existing.mkdir()
    marker = existing / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError):
        export(source, tmp_path)
    with pytest.raises(ValueError):
        prepare_snapshot(AccessPolicy(source), source / "export", paths=["main.py"],
                         max_files=1, max_bytes=1024, max_file_bytes=1024)
    assert marker.read_text(encoding="utf-8") == "keep"


def test_source_drift_during_copy_cleans_partial_export(source, tmp_path, monkeypatch):
    access = AccessPolicy(source)
    read, calls = access.read_bytes, 0
    def changing(relative, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            (source / "main.py").write_text("CHANGED=2\n", encoding="utf-8")
        return read(relative, **kwargs)
    monkeypatch.setattr(access, "read_bytes", changing)
    with pytest.raises(AccessDenied):
        export(source, tmp_path, access=access)
    assert not (tmp_path / "export").exists()


def test_revocation_cannot_use_prepared_snapshot(source, tmp_path):
    permitted = True
    def guard():
        if not permitted:
            raise AccessDenied("revoked")
    snapshot = export(source, tmp_path, access=AccessPolicy(source, read_guard=guard))
    permitted = False
    with pytest.raises(AccessDenied):
        snapshot.check()
    snapshot.close()
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("tamper", ["change", "add", "empty_directory"])
def test_snapshot_tampering_cannot_run(source, tmp_path, tamper):
    snapshot = export(source, tmp_path)
    if tamper == "change":
        (snapshot.directory / "main.py").write_text("CHANGED=3", encoding="utf-8")
    elif tamper == "add":
        (snapshot.directory / "extra.py").write_text("EXTRA=4", encoding="utf-8")
    else:
        (snapshot.directory / "extra").mkdir()
    with pytest.raises((AccessDenied, ValueError)):
        snapshot.check()
    # Unknown artifacts are deliberately not recursively removed.
    if tamper != "change":
        with pytest.raises(SnapshotCleanupPending):
            snapshot.close()
    else:
        snapshot.close()


def test_permission_rule_change_invalidates_export(source, tmp_path):
    snapshot = export(source, tmp_path)
    (source / ".gitignore").write_text("main.py\n", encoding="utf-8")
    with pytest.raises(AccessDenied):
        snapshot.check()
    snapshot.close()


def test_actual_multilink_source_rejected(source, tmp_path):
    os.link(source / "main.py", source / "alias.py")
    with pytest.raises(AccessDenied):
        export(source, tmp_path, paths=("main.py",))
    assert not (tmp_path / "export").exists()


def test_actual_multilink_snapshot_rejected_and_cleanup_is_explicit(source, tmp_path):
    snapshot = export(source, tmp_path)
    os.link(snapshot.directory / "main.py", tmp_path / "outside-alias.py")
    with pytest.raises(AccessDenied):
        snapshot.check()
    with pytest.raises(SnapshotCleanupPending):
        snapshot.close()
    assert (tmp_path / "outside-alias.py").is_file()


def test_cleanup_failure_is_not_hidden(source, tmp_path, monkeypatch):
    snapshot = export(source, tmp_path)
    original = Path.unlink
    def failing(path, *args, **kwargs):
        if path == snapshot.directory / "main.py":
            raise PermissionError("locked")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", failing)
    with pytest.raises(SnapshotCleanupPending):
        snapshot.close()
    assert (snapshot.directory / "main.py").is_file()


def test_later_source_edits_do_not_redefine_the_fixed_snapshot(source, tmp_path):
    with export(source, tmp_path) as snapshot:
        original = snapshot.digest
        (source / "main.py").write_text("LATER=4", encoding="utf-8")
        snapshot.check()
        assert snapshot.digest == original
