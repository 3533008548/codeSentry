"""Launch evidence comes from declarations and bound calls, not familiar names."""
import json
from pathlib import Path

import pytest

from codesentry.access import AccessPolicy
from codesentry.core.policy import Policy
from codesentry.index.builder import build_index
from codesentry.index.entrypoint import detect
from codesentry.index.startup import collect_startup_inputs


def project(tmp_path, files):
    root = tmp_path / 'project'
    root.mkdir()
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    return root


def analyze(root, **kwargs):
    return build_index(root, Policy(), use_cache=False, **kwargs)


def entries(result):
    return {entry.file: entry for entry in result.entrypoints + result.script_entrypoints}


def test_name_and_framework_strings_do_not_prove_an_application_entry(tmp_path):
    root = project(tmp_path, {'app.py': '# FastAPI()\ntext = "createRoot()"\ndef helper():\n    return 1\n',
                              'other.py': 'def FastAPI():\n    return None\napp = FastAPI()\n'})
    found = entries(analyze(root))
    assert found['app.py'].kind == 'candidate'
    assert found['app.py'].confidence == 'heuristic'
    assert found['app.py'].line is None
    assert 'other.py' not in found


def test_python_guard_is_parsed_as_syntax_and_does_not_alone_prove_application_role(tmp_path):
    root = project(tmp_path, {'main.py': '# if __name__ == "__main__":\ntext="__name__ == \'__main__\'"\n',
                              'task.py': 'if "__main__" == __name__:\n    print("run")\n'})
    found = entries(analyze(root))
    assert found['main.py'].confidence == 'heuristic'
    assert found['task.py'].kind == 'candidate' and found['task.py'].confidence == 'static'
    assert found['task.py'].line == 1


def test_console_and_gui_scripts_have_declaration_and_source_location(tmp_path):
    root = project(tmp_path, {'pyproject.toml':'[project]\nname="fixture"\n[project.scripts]\nstart="runner:launch"\n[project.gui-scripts]\nwindow="ui:open_window"\n',
                              'runner.py':'# not executed\ndef launch():\n    raise RuntimeError("must not run")\n',
                              'ui.py':'def open_window():\n    return None\n'})
    result = analyze(root)
    found = entries(result)
    assert found['runner.py'].kind == found['ui.py'].kind == 'process'
    assert found['runner.py'].confidence == 'declared' and found['runner.py'].line == 2
    assert {'file':'pyproject.toml','line':4,'type':'python_console_script'} in found['runner.py'].evidence
    assert 'pyproject.toml' in result.startup_inputs


def test_missing_console_attribute_is_unknown_not_a_confirmed_process(tmp_path):
    root=project(tmp_path, {'pyproject.toml':'[project.scripts]\nstart="runner:missing"\n',
                            'runner.py':'def helper():\n    return 1\n'})
    result=analyze(root)
    assert not any(entry.kind=='process' for entry in result.entrypoints)
    assert any(issue['status']=='startup_attribute_unresolved' for issue in result.entry_evidence_issues)


def test_src_layout_requires_explicit_package_directory_mapping(tmp_path):
    root=project(tmp_path, {'pyproject.toml':'[project.scripts]\nstart="pkg.runner:launch"\n[tool.setuptools.package-dir]\n""="src"\n',
                            'src/pkg/runner.py':'def launch():\n    return 1\n'})
    assert entries(analyze(root))['src/pkg/runner.py'].confidence=='declared'


def test_fastapi_factory_and_router_are_assembly_not_process(tmp_path):
    root=project(tmp_path, {'factory.py':'from fastapi import FastAPI, APIRouter\nrouter=APIRouter()\ndef create_app():\n    return FastAPI()\n'})
    found=entries(analyze(root))
    assert found['factory.py'].kind=='assembly' and found['factory.py'].confidence=='static'
    assert found['factory.py'].line in {2,4}


def test_package_main_library_is_not_an_application_process(tmp_path):
    root=project(tmp_path, {'package.json':json.dumps({'main':'src/library.ts'}),
                            'src/library.ts':'export function helper(){return 1;}\n'})
    found=entries(analyze(root))
    assert found['src/library.ts'].kind=='assembly' and found['src/library.ts'].confidence=='declared'


def test_explicit_build_mapping_and_launch_declaration_select_electron_process(tmp_path):
    root=project(tmp_path, {'package.json':json.dumps({'main':'dist/boot.cjs','scripts':{
      'build':'esbuild src/boot.ts --bundle --outfile=dist/boot.cjs','start':'electron .'}}),
      'src/boot.ts':'import { app } from "electron";\napp.whenReady();\n',
      'src/App.tsx':'export function App(){ return <div/>; }\n'})
    found=entries(analyze(root))
    assert found['src/boot.ts'].kind=='process' and found['src/boot.ts'].confidence=='declared'
    assert any(item['type']=='explicit_build_mapping' for item in found['src/boot.ts'].evidence)
    assert found['src/App.tsx'].kind=='candidate'


def test_dist_to_source_is_not_guessed_from_filename(tmp_path):
    root=project(tmp_path, {'package.json':json.dumps({'main':'dist/main.cjs','scripts':{'start':'electron .'}}),
                            'src/main.ts':'export const unrelated = 1;\n'})
    result=analyze(root)
    assert entries(result)['src/main.ts'].confidence=='heuristic'
    assert result.entry_evidence_issues


def test_html_mount_preserves_dependency_free_bootstrap_and_ignores_remote_script(tmp_path):
    root=project(tmp_path, {'frontend/index.html':'<html>\n<script type="module" src="/src/launch.tsx"></script>\n<script src="https://example.invalid/main.tsx"></script></html>',
                            'frontend/src/launch.tsx':'export const render = 1;\n'})
    found=entries(analyze(root))
    assert found['frontend/src/launch.tsx'].kind=='mount'
    assert {'file':'frontend/index.html','line':2,'type':'html_script_source'} in found['frontend/src/launch.tsx'].evidence


def test_react_bound_call_is_a_mount_but_import_shadowing_and_text_are_not(tmp_path):
    root=project(tmp_path, {'mount.tsx':'import {createRoot as mount} from "react-dom/client";\nmount(document.getElementById("root"));\n',
      'decoy.tsx':'const text="createRoot()";\nfunction createRoot(){return 1;}\ncreateRoot();\n',
      'nested.tsx':'import {createRoot} from "react-dom/client";\nfunction helper(createRoot:any){createRoot();}\n'})
    found=entries(analyze(root))
    assert found['mount.tsx'].kind=='mount' and found['mount.tsx'].line==2
    assert 'decoy.tsx' not in found and 'nested.tsx' not in found


def test_docker_literal_copy_and_command_prove_loader_target_not_factory(tmp_path):
    root=project(tmp_path, {'Dockerfile':'FROM python:3\nWORKDIR /app\nCOPY . .\nENTRYPOINT []\nCMD ["uvicorn", "service:app"]\n',
                            'service.py':'from factory import create_app\napp=create_app()\n',
                            'factory.py':'from fastapi import FastAPI\ndef create_app():\n    return FastAPI()\n'})
    found=entries(analyze(root))
    assert found['service.py'].kind=='process' and found['service.py'].confidence=='declared'
    assert found['service.py'].line==2
    assert found['factory.py'].kind=='assembly'


def test_compose_external_image_without_source_mapping_does_not_guess_host_entry(tmp_path):
    root=project(tmp_path, {'compose.yml':'services:\n  web:\n    image: external/image\n    command: [python, runner.py]\n',
                            'runner.py':'def helper():\n    return 1\n'})
    result=analyze(root)
    assert 'runner.py' not in entries(result)
    assert any(issue['status']=='startup_container_mapping_unknown' for issue in result.entry_evidence_issues)


def test_compose_explicit_source_bind_and_working_dir_map_to_host_source(tmp_path):
    root=project(tmp_path, {'compose.yml':'services:\n  worker:\n    working_dir: /app\n    volumes: [".:/app"]\n    entrypoint: []\n    command: [python, consumer.py]\n',
                            'consumer.py':'print("not executed")\n'})
    assert entries(analyze(root))['consumer.py'].kind=='process'


def test_shell_commands_and_unmatched_build_outputs_are_unknown_not_executed(tmp_path):
    root=project(tmp_path, {'package.json':json.dumps({'scripts':{'start':'python target.py && touch SIDE_EFFECT'}}),
                            'target.py':'raise RuntimeError("not executed")\n'})
    result=analyze(root)
    assert not (root/'SIDE_EFFECT').exists()
    assert not any(entry.confidence=='declared' for entry in result.entrypoints)
    assert any(issue['status']=='startup_command_unsupported' for issue in result.entry_evidence_issues)


def test_excluded_startup_configuration_is_not_opened(tmp_path,monkeypatch):
    root=project(tmp_path, {'package.json':json.dumps({'scripts':{'start':'python runner.py'}}),
                            'runner.py':'print("not executed")\n'})
    access=AccessPolicy(root,{'exclude':['package.json']})
    original=Path.open
    def checked(path,*args,**kwargs):
        if path==root/'package.json':
            pytest.fail('excluded launch configuration was opened')
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',checked)
    result=analyze(root,access=access)
    assert result.startup_inputs['package.json']=='unread:access-policy'
    assert any(issue['status']=='startup_config_excluded' for issue in result.entry_evidence_issues)


def test_startup_only_configuration_changes_invalidate_input_identity(tmp_path):
    root=project(tmp_path, {'index.html':'<script type="module" src="a.ts"></script>',
                            'a.ts':'export const a = 1;','b.ts':'export const b = 2;'})
    first=analyze(root)
    (root/'index.html').write_text('<script type="module" src="b.ts"></script>',encoding='utf-8')
    second=analyze(root)
    assert first.input_fingerprint!=second.input_fingerprint
    assert first.startup_inputs!=second.startup_inputs
    assert entries(second)['b.ts'].kind=='mount'


def test_inflight_startup_declaration_change_discards_old_entries(tmp_path,monkeypatch):
    root=project(tmp_path, {'index.html':'<script type="module" src="a.ts"></script>',
                            'a.ts':'export const a = 1;','b.ts':'export const b = 2;'})
    import codesentry.index.builder as builder
    original=builder.detect_entrypoints
    def changed(*args,**kwargs):
        result=original(*args,**kwargs)
        (root/'index.html').write_text('<script type="module" src="b.ts"></script>',encoding='utf-8')
        return result
    monkeypatch.setattr(builder,'detect_entrypoints',changed)
    result=analyze(root)
    assert not result.is_complete and result.entrypoints==[]
    assert any(issue['status']=='startup_configuration_changed' for issue in result.parse_issues)


def test_test_or_data_declaration_cannot_promote_production_component(tmp_path):
    root=project(tmp_path, {'tests/index.html':'<script src="../App.tsx"></script>',
      'runtime/package.json':json.dumps({'bin':'../App.tsx'}),
      'App.tsx':'export function App(){return <div/>;}'})
    result=analyze(root)
    assert entries(result)['App.tsx'].confidence=='heuristic'
    assert not any(path.startswith(('tests/','runtime/')) for path in result.startup_inputs)


def test_explicit_preload_host_and_build_mapping_create_separate_bridge_role(tmp_path):
    root=project(tmp_path, {'package.json':json.dumps({'main':'dist/boot.cjs','scripts':{
      'build:main':'esbuild src/boot.ts --outfile=dist/boot.cjs',
      'build:bridge':'esbuild src/bridge.ts --outfile=dist/bridge.cjs','start':'electron .'}}),
      'src/boot.ts':'import {app, BrowserWindow} from "electron";\nimport path from "node:path";\nconst PRELOAD = path.join(__dirname,"bridge.cjs");\napp.whenReady();\nnew BrowserWindow({webPreferences:{preload:PRELOAD}});\n',
      'src/bridge.ts':'import {contextBridge} from "electron";\ncontextBridge.exposeInMainWorld("api",{});\n'})
    result=analyze(root)
    found=entries(result)
    assert found['src/boot.ts'].kind=='process'
    assert found['src/bridge.ts'].kind=='bridge'
    assert found['src/bridge.ts'].confidence=='declared'
    assert any(item['type']=='electron_preload_load' and item['file']=='src/boot.ts' and item['line']==5 for item in found['src/bridge.ts'].evidence)


def test_preload_text_and_object_spread_do_not_prove_host_loading(tmp_path):
    root=project(tmp_path, {'package.json':'{}',
      'boot.ts':'import {BrowserWindow} from "electron";\nconst text="preload: \'bridge.ts\'";\nnew BrowserWindow({webPreferences:{...options,preload:"bridge.ts"}});\n',
      'bridge.ts':'export const api = 1;\n'})
    assert 'bridge.ts' not in entries(analyze(root))


def test_console_script_reexport_is_located_without_importing_the_package(tmp_path):
    root=project(tmp_path, {'pyproject.toml':'[project.scripts]\nrun="pkg:main"\n',
      'pkg/__init__.py':'from .cli import main\n',
      'pkg/cli.py':'def main():\n    raise RuntimeError("never run")\n'})
    found=entries(analyze(root))
    assert found['pkg/__init__.py'].kind=='process' and found['pkg/__init__.py'].line==1


def test_build_lifecycle_is_not_reported_as_a_missing_application_command(tmp_path):
    root=project(tmp_path, {'package.json':json.dumps({'scripts':{'build':'tsc -b && vite build'}}),
                            'helper.ts':'export const value=1;'})
    assert not analyze(root).entry_evidence_issues


def test_inline_script_and_nested_runner_are_explicit_unknowns(tmp_path):
    root=project(tmp_path, {'package.json':json.dumps({'scripts':{'start':'npm run nested'}}),
      'index.html':'<script type="module">import "./main.ts"</script>',
      'main.ts':'export const value=1;'})
    statuses={issue['status'] for issue in analyze(root).entry_evidence_issues}
    assert {'startup_inline_script_unsupported','startup_command_unsupported'} <= statuses


def test_malformed_python_console_target_is_not_promoted(tmp_path):
    root=project(tmp_path, {'pyproject.toml':'[project.scripts]\nstart="runner"\n',
                            'runner.py':'def run():\n    return 1\n'})
    result=analyze(root)
    assert not any(entry.kind=='process' for entry in result.entrypoints)
    assert result.entry_evidence_issues


def test_startup_declaration_truncation_is_visible(tmp_path):
    root=project(tmp_path, {'package.json':json.dumps({'scripts':{f'build:{i}':'tsc' for i in range(130)}}),
                            'helper.ts':'export const value=1;'})
    result=analyze(root)
    assert any(issue['status']=='startup_declaration_limit' for issue in result.entry_evidence_issues)


def test_container_command_arguments_do_not_override_explicit_entrypoint(tmp_path):
    root=project(tmp_path, {'compose.yml':'services:\n  worker:\n    working_dir: /app\n    volumes: [".:/app"]\n    entrypoint: [echo]\n    command: [python, consumer.py]\n',
                            'consumer.py':'print("never run")'})
    assert 'consumer.py' not in entries(analyze(root))


def test_inherited_container_entrypoint_keeps_cmd_only_as_candidate(tmp_path):
    root=project(tmp_path, {'Dockerfile':'FROM unknown/image\nWORKDIR /app\nCOPY . .\nCMD ["python", "consumer.py"]\n',
                            'consumer.py':'print("never run")'})
    result=analyze(root)
    assert entries(result)['consumer.py'].kind=='candidate'
    assert any(issue['status']=='startup_container_entrypoint_unknown' for issue in result.entry_evidence_issues)


def test_inert_html_template_script_does_not_become_mount(tmp_path):
    root=project(tmp_path, {'index.html':'<template><script type="module" src="component.tsx"></script></template>',
                            'component.tsx':'export const Component = () => <div/>;'})
    assert 'component.tsx' not in entries(analyze(root))


def test_anonymous_callbacks_unused_arrows_and_class_initializers_are_not_module_roots(tmp_path):
    root=project(tmp_path, {
      'callback.tsx':'import {createRoot} from "react-dom/client";\nsetTimeout(()=>createRoot(document.getElementById("root")),1000);',
      'unused.tsx':'import {createRoot} from "react-dom/client";\nconst unused=()=>createRoot(document.getElementById("root"));',
      'member.tsx':'import {createRoot} from "react-dom/client";\nclass Component { field = createRoot(document.getElementById("root")); }',
      'lifecycle.ts':'import {app} from "electron";\nsetTimeout(()=>app.whenReady(),1000);',
      'lazy.py':'import uvicorn\nf=lambda: uvicorn.run("service:app")\n',
      'direct.tsx':'import {createRoot} from "react-dom/client";\ncreateRoot(document.getElementById("root"));',
    })
    found=entries(analyze(root))
    assert all(file not in found or found[file].kind not in {'process','mount'} for file in ('callback.tsx','unused.tsx','member.tsx','lifecycle.ts','lazy.py'))
    assert found['direct.tsx'].kind=='mount'
