"""Redirect checks reuse one no-follow metadata snapshot, never a cached permission."""
from pathlib import Path
from types import SimpleNamespace
import stat

import pytest

from codesentry.access.policy import is_link

REPARSE_POINT = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)

@pytest.mark.parametrize('mode,attributes,expected', [
    (stat.S_IFREG | 0o600, 0, False),
    (stat.S_IFLNK | 0o777, 0, True),
    (stat.S_IFDIR | 0o700, REPARSE_POINT, True),
    (stat.S_IFREG | 0o600, REPARSE_POINT, True),
])
def test_redirect_types_are_determined_from_no_follow_metadata(mode, attributes, expected):
    class MetadataPath:
        calls = 0

        def lstat(self):
            self.calls += 1
            return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)

        def is_symlink(self):
            return stat.S_ISLNK(mode)

        def is_junction(self):
            return stat.S_ISDIR(mode) and bool(attributes & REPARSE_POINT)

    path = MetadataPath()
    assert is_link(path) is expected


def test_one_redirect_check_uses_one_metadata_read(tmp_path, monkeypatch):
    file = tmp_path / 'ordinary.py'
    file.write_text('pass\n', encoding='utf-8')
    original = Path.lstat
    observed = []

    def record(path, *args, **kwargs):
        if path == file:
            observed.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'lstat', record)
    assert is_link(file) is False
    assert len(observed) == 1


def test_missing_path_is_not_a_redirect(tmp_path):
    assert is_link(tmp_path / 'absent.py') is False


def test_unreadable_metadata_cannot_authorize_a_path():
    class Unreadable:
        def lstat(self):
            raise PermissionError('metadata denied')

    with pytest.raises(PermissionError):
        is_link(Unreadable())
