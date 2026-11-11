"""Historical CLIs must fail before enumerating or copying a restricted project."""
import importlib
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('name', ['extract_groundtruth', 'verify_cache'])
def test_retired_helper_refuses_before_any_project_filesystem_access(monkeypatch, name):
    helper = importlib.import_module(f'evals.{name}')
    monkeypatch.setattr(sys, 'argv', [name, 'restricted-project', '--out', 'must-not-exist.json'])

    def forbidden(*args, **kwargs):
        raise AssertionError('Retired helper touched the filesystem')

    for method in ('resolve', 'read_text', 'read_bytes', 'exists', 'glob', 'write_text'):
        monkeypatch.setattr(Path, method, forbidden)
    assert helper.main() == 2


@pytest.mark.parametrize('name', ['extract_groundtruth', 'verify_cache'])
def test_retired_script_exit_is_non_success_without_output_artifact(tmp_path, name):
    repository = Path(__file__).resolve().parents[1]
    output = tmp_path / 'forbidden-output.json'
    result = subprocess.run([sys.executable, str(repository / 'evals' / f'{name}.py'),
                             str(tmp_path / 'missing-project'), '--out', str(output)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'Historical helper disabled' in result.stdout
    assert not output.exists()
