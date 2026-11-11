"""The web entry remains local and optional for CLI users."""
import importlib
from pathlib import Path

import pytest

from codesentry.cli.main import build_parser, main

cli = importlib.import_module('codesentry.cli.main')


def test_serve_defaults_to_loopback():
    args = build_parser().parse_args(['serve'])
    assert args.host == '127.0.0.1' and args.port == 8765
    assert args.dev_origin == []


@pytest.mark.parametrize('arguments', [['--host','0.0.0.0'], ['--port','0'], ['--port','65536']])
def test_serve_rejects_nonlocal_or_invalid_endpoint(arguments):
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(['serve', *arguments])
    assert error.value.code == 2


def test_serve_missing_assets_fails_before_server(tmp_path, monkeypatch, capsys):
    uvicorn = pytest.importorskip('uvicorn')
    monkeypatch.setattr(uvicorn, 'run', lambda *args, **kwargs: pytest.fail('must not start without UI'))
    assert main(['serve','--frontend-dir',str(tmp_path/'missing')]) == 2
    assert '尚未构建' in capsys.readouterr().err


def test_serve_uses_separate_state_and_explicit_development_origin(tmp_path, monkeypatch):
    uvicorn = pytest.importorskip('uvicorn')
    web = importlib.import_module('codesentry.web.app')
    frontend = tmp_path/'dist'
    frontend.mkdir()
    (frontend/'index.html').write_text('<div id="root"></div>',encoding='utf-8')
    state = tmp_path/'app-data'
    seen = {}
    app = object()
    def factory(**kwargs):
        seen.update(kwargs)
        return app
    def serve(selected, **kwargs):
        assert selected is app
        assert kwargs['host'] == '127.0.0.1'
        assert kwargs['port'] == 8765
    monkeypatch.setattr(web,'create_app',factory)
    monkeypatch.setattr(uvicorn,'run',serve)
    assert main(['serve','--frontend-dir',str(frontend),'--data-dir',str(state),
                 '--dev-origin','http://127.0.0.1:5173']) == 0
    assert seen['data_dir'] == state.resolve()
    assert seen['frontend_dir'] == frontend.resolve()
    assert seen['allowed_dev_origins'] == {'http://127.0.0.1:5173'}
