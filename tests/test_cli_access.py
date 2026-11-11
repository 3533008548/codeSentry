"""CLI content reads require confirmed scope and cannot bypass workspace denies."""
import json
import importlib
import os
from pathlib import Path
import sqlite3

import pytest

from codesentry.cli.main import main
from codesentry.cli.main import build_parser
from codesentry.cli.access import resolve_access
from codesentry.access import AccessDenied
from codesentry.access import AccessPolicy
from codesentry.access.registry import RegistryGuard


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'main.py').write_text('def main():\n    return 1\n', encoding='utf-8')
    return root


def block_content_reads(monkeypatch, forbidden):
    original = Path.open
    touched = []
    def checked(path, *args, **kwargs):
        if path.resolve() in forbidden:
            touched.append(path)
            pytest.fail(f'excluded target content was opened: {path.name}')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', checked)
    return touched


def test_unconfirmed_command_reads_no_target_content(repo, monkeypatch, capsys):
    block_content_reads(monkeypatch, {repo / 'main.py'})
    assert main(['onboard', str(repo), '--json', '--no-cache']) == 2
    assert '确认' in capsys.readouterr().err


def test_explicit_local_confirmation_still_respects_git_and_user_denies(repo, monkeypatch, capsys):
    hidden = repo / 'private.py'
    ignored = repo / 'ignored.py'
    hidden.write_text("SENSITIVE = 'USER_DENIED_CONTENT'\n", encoding='utf-8')
    ignored.write_text("SECRET = 'IGNORED_CONTENT'\n", encoding='utf-8')
    (repo / '.gitignore').write_text('ignored.py\n', encoding='utf-8')
    block_content_reads(monkeypatch, {hidden, ignored})
    assert main(['onboard', str(repo), '--json', '--no-cache', '--confirm-access', '--exclude', 'private.py']) == 1
    output = capsys.readouterr().out
    assert 'USER_DENIED_CONTENT' not in output and 'IGNORED_CONTENT' not in output
    assert json.loads(output)['files'] == 1
    assert json.loads(output)['access_scope_limited'] is True


def test_excluded_algorithm_config_cannot_be_read_to_expand_permissions(repo, monkeypatch, capsys):
    config = repo / 'policy.yaml'
    config.write_text('index:\n  exclude:\n    not_parsed: []\n', encoding='utf-8')
    block_content_reads(monkeypatch, {config})
    assert main(['onboard', str(repo), '--json', '--no-cache', '--confirm-access', '--exclude', 'policy.yaml']) == 1
    assert '默认分析设置' in capsys.readouterr().err


def test_access_configuration_inside_repository_is_not_trusted(repo, monkeypatch, capsys):
    config = repo / 'access.json'
    config.write_text('{}', encoding='utf-8')
    block_content_reads(monkeypatch, {config, repo / 'main.py'})
    assert main(['onboard', str(repo), '--access-policy', str(config)]) == 2
    assert '项目目录之外' in capsys.readouterr().err


def registry(data_dir, root, *, confirmed=True, cleanup_pending=False):
    data_dir.mkdir()
    settings = {'respect_gitignore':True,'exclude':['private.py'],'local_only':[],'model_scope':[]}
    connection = sqlite3.connect(data_dir/'workspaces.sqlite3')
    try:
        with connection:
            connection.execute('CREATE TABLE workspaces(id TEXT PRIMARY KEY,path TEXT,canonical_key TEXT UNIQUE,access_policy TEXT)')
            connection.execute('INSERT INTO workspaces VALUES(?,?,?,?)', ('a'*32,str(root),os.path.normcase(str(root)),json.dumps({
                'confirmed':confirmed,'cleanup_pending':cleanup_pending,'settings':settings,
                'version':1,'fingerprint':AccessPolicy(root,settings).fingerprint})))
    finally:
        connection.close()


@pytest.mark.parametrize('confirmed,cleanup_pending', [(False,False),(True,True)])
def test_cli_confirmation_cannot_bypass_pending_workspace_migration(repo, tmp_path, monkeypatch, capsys, confirmed, cleanup_pending):
    state = tmp_path/'state'
    registry(state,repo,confirmed=confirmed,cleanup_pending=cleanup_pending)
    block_content_reads(monkeypatch, {repo/'main.py'})
    assert main(['onboard',str(repo),'--workspace-data-dir',str(state),'--confirm-access']) == 2
    assert '工作台' in capsys.readouterr().err


def test_existing_workspace_deny_survives_more_permissive_cli_file(repo, tmp_path, monkeypatch, capsys):
    hidden = repo/'private.py'
    hidden.write_text("SECRET='WORKSPACE_ONLY_SECRET'",encoding='utf-8')
    state=tmp_path/'state'
    registry(state,repo)
    config=tmp_path/'trusted-access.json'
    config.write_text(json.dumps({'root':str(repo),'settings':{'respect_gitignore':False,'exclude':[],'local_only':[],'model_scope':['**']}}),encoding='utf-8')
    block_content_reads(monkeypatch,{hidden})
    assert main(['onboard',str(repo),'--json','--no-cache','--workspace-data-dir',str(state),'--access-policy',str(config)]) == 1
    assert 'WORKSPACE_ONLY_SECRET' not in capsys.readouterr().out


def test_running_cli_cannot_read_after_workspace_permissions_change(repo, tmp_path, monkeypatch):
    state=tmp_path/'state'
    registry(state,repo)
    args=build_parser().parse_args(['onboard',str(repo),'--workspace-data-dir',str(state)])
    access=resolve_access(args,repo)
    with sqlite3.connect(state/'workspaces.sqlite3') as connection:
        row=connection.execute('SELECT access_policy FROM workspaces').fetchone()
        changed=json.loads(row[0]);changed['version']=2
        changed['settings']['exclude'].append('main.py')
        connection.execute('UPDATE workspaces SET access_policy=?',(json.dumps(changed),))
    block_content_reads(monkeypatch,{repo/'main.py'})
    with pytest.raises(AccessDenied):
        access.read_text('main.py')


def test_cli_does_not_publish_old_result_after_mid_analysis_revoke(repo, tmp_path, monkeypatch, capsys):
    state=tmp_path/'state'
    registry(state,repo)
    cli=importlib.import_module('codesentry.cli.main')
    from codesentry.index.builder import IndexResult
    def analyze(*args,**kwargs):
        with sqlite3.connect(state/'workspaces.sqlite3') as connection:
            row=connection.execute('SELECT access_policy FROM workspaces').fetchone()
            changed=json.loads(row[0]);changed['cleanup_pending']=True
            connection.execute('UPDATE workspaces SET access_policy=?',(json.dumps(changed),))
        return IndexResult(root=str(repo))
    monkeypatch.setattr(cli,'build_index',analyze)
    assert main(['onboard',str(repo),'--json','--workspace-data-dir',str(state)]) == 2
    output=capsys.readouterr()
    assert output.out == ''
    assert '权限已变化' in output.err


def test_cli_main_closes_owned_guard_on_success_and_error(repo, tmp_path, monkeypatch, capsys):
    state=tmp_path/'state'
    registry(state,repo)
    opened=[]
    original=RegistryGuard.__init__
    def tracked(self,*args,**kwargs):
        original(self,*args,**kwargs)
        opened.append(self)
    monkeypatch.setattr(RegistryGuard,'__init__',tracked)
    assert main(['doctor',str(repo),'--json','--workspace-data-dir',str(state)]) in {0,1}
    capsys.readouterr()
    assert opened and all(guard.closed for guard in opened)
    config=repo/'not-trusted.json'
    config.write_text('{}',encoding='utf-8')
    assert main(['onboard',str(repo),'--workspace-data-dir',str(state),'--access-policy',str(config)])==2
    assert all(guard.closed for guard in opened)


def test_unregistered_cli_scope_cannot_survive_later_workspace_registration(repo,tmp_path,monkeypatch):
    state=tmp_path/'state'
    args=build_parser().parse_args(['onboard',str(repo),'--workspace-data-dir',str(state),'--confirm-access'])
    with resolve_access(args,repo) as access:
        registry(state,repo)
        block_content_reads(monkeypatch,{repo/'main.py'})
        with pytest.raises(AccessDenied):
            access.read_text('main.py')
