"""Reported binding rates must distinguish definite bindings from guesses."""
from codesentry.index.builder import IndexResult
from codesentry.output.report import render_l1, render_l2, to_dict
from codesentry.core.symbol import FileMeta, Language


def test_binding_rate_does_not_count_builtins_or_heuristics_as_success():
    result = IndexResult(root=".", call_stats={
        "local": 2, "cross_file": 1, "heuristic": 2, "ambiguous": 1,
        "unresolved": 2, "builtin": 100, "external": 50, "test_helper": 20,
    })
    output = render_l1(result)
    assert "3/8" in output
    assert "37.5%" in output


def test_no_internal_candidates_is_not_a_perfect_binding_rate():
    output = render_l1(IndexResult(root=".", call_stats={"builtin": 4}))
    assert "N/A" in output


def test_reports_show_static_scope_environment_and_visible_failures():
    result = IndexResult(root=".")
    result.files = [FileMeta(path="good.py", language=Language.PYTHON),
                    FileMeta(path="bad.ts", language=Language.TYPESCRIPT, is_parsed=False)]
    result.is_complete = False
    result.environment = {"project_units": [{"path": "."}, {"path": "frontend"}],
                          "observed": {"python": "fixture", "typescript": "fixture"},
                          "unknowns": ["target dependencies were not executed"]}
    result.environment_fingerprint = "environment-fixture"
    result.input_fingerprint = "source-fixture"
    result.parse_failures = 1
    result.parse_issues = [{"path": "bad.ts", "reason": "tool unavailable"}]
    for render in (render_l1, render_l2):
        output = render(result)
        assert "static（静态分析）" in output
        assert "目标运行验证未执行" in output
        assert "成功1/2个已记录文件" in output
        assert "不完整" in output and "tool unavailable" in output
        assert "声明项目单元2" in output and "未知项1" in output
        assert "不代表目标依赖已安装或业务可运行" in output
    data = to_dict(result)
    assert data["analysis_mode"] == "static" and data["dynamic_verification"] == "not_run"
    assert data["environment_fingerprint"] == "environment-fixture"
    assert data["input_fingerprint"] == "source-fixture"
    assert data["is_complete"] is False
    assert data["parsing"]["unparsed_files"] == ["bad.ts"]
    assert data["parse_issues"] == result.parse_issues


def test_missing_profile_is_explicit_unknown_not_ready():
    output = render_l1(IndexResult(root="."))
    assert "画像未提供" in output
    assert "不推定目标环境已就绪" in output


def test_startup_declaration_and_assembly_are_not_presented_as_running_or_adjudicated():
    from codesentry.index.entrypoint import EntryPoint
    result = IndexResult(root='.')
    result.entrypoints = [
        EntryPoint('launch.py','app','package declaration',kind='process',confidence='declared',line=3,
                   evidence=[{'file':'pyproject.toml','line':8,'kind':'project_script'}]),
        EntryPoint('factory.py','app','application factory',kind='assembly',confidence='static',line=5),
    ]
    result.entry_evidence_issues = [{'file':'package.json','status':'unsupported_launch','message':'complex command remains unknown'}]
    output = render_l1(result)
    assert '进程入口 · 启动声明' in output and '应用装配 · 静态证据' in output
    assert 'pyproject.toml:8' in output and '不等于已运行或人工标签' in output
    data = to_dict(result)
    assert data['entrypoints'][0]['kind'] == 'process'
    assert data['entrypoints'][1]['kind'] == 'assembly'
    assert data['entry_evidence_complete'] is False
    assert data['parse_failures'] == 0 and data['is_complete'] is True
