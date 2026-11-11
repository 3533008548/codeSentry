"""Analyzer identity changes do not require opening the inspected project."""
import json

import pytest

from codesentry.web import provenance, worker


@pytest.mark.parametrize("name", ["parsers/_ts_extract.js", "output/reading_order.py", "output/report.py"])
def test_implementation_identity_covers_parser_and_navigation_output(tmp_path, name):
    source = tmp_path / name
    source.parent.mkdir(parents=True)
    source.write_text("first implementation", encoding="utf-8")
    original = provenance._implementation_identity(tmp_path)
    assert provenance._implementation_identity(tmp_path) == original
    source.write_text("second implementation", encoding="utf-8")
    assert provenance._implementation_identity(tmp_path) != original


def test_worker_with_another_implementation_does_not_open_target(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("a worker with an outdated implementation accessed the project")
    monkeypatch.setattr(worker, "RegisteredAccessPolicy", forbidden)
    destination = tmp_path / "result.json"
    result = worker.main([str(tmp_path / "unread-target"), str(destination), "workspace", "analysis", "{}",
                          json.dumps({"analysis_provenance": "outdated"}), str(tmp_path / "state")])
    assert result == 2
    assert "格式已更新" in capsys.readouterr().err
    assert not destination.exists()
