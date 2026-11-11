"""P1验收的冻结输入、计分、真实输出时延与证据不足状态。"""
import hashlib
import json
from types import SimpleNamespace

import pytest

from codesentry.core.symbol import FileMeta, Language, Symbol, SymbolKind
from codesentry.index.builder import IndexResult
from codesentry.index.entrypoint import EntryPoint
from evals import m0_acceptance as acceptance


def read_contract(project):
    return json.loads(project.contract.read_text(encoding="utf-8"))


def write_contract(project, contract):
    project.contract.write_text(json.dumps(contract), encoding="utf-8")


@pytest.fixture
def project(tmp_path, monkeypatch):
    files = [f"module{i}.py" for i in range(12)]
    result = IndexResult(root=str(tmp_path))
    result.is_complete = True
    result.parse_issues = []
    for i, name in enumerate(files):
        (tmp_path / name).write_text("value = 1\n", encoding="utf-8")
        result.files.append(FileMeta(path=name, language=Language.PYTHON))
        result.file_pr[name] = 1 / (i + 1)
    result.entrypoints = [EntryPoint(file=files[0], level="app", reason="fixture", kind="process", confidence="static")]
    (tmp_path / "README.md").write_text("fixture documentation\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    value = SimpleNamespace(root=tmp_path, gt=tmp_path / "gt.json", contract=tmp_path / "contract.json", result=result, files=files)

    def freeze(truth=None, unmatched=()):
        truth = files[:8] if truth is None else truth
        value.gt.write_text(json.dumps(truth), encoding="utf-8")
        def row(name):
            data = (tmp_path / name).read_bytes()
            return {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "ranking_scope": True}
        contract = {
            "contract_version": 1, "contract_id": "unit-fixture",
            "task": {"p_at_10": {"threshold": 0.8}, "latency_seconds": {"l1_less_than": 30, "l2_less_than": 180},
                     "entry_gold": {"status": "independently_adjudicated", "files": [files[0]], "fixture_only": True}},
            "frozen_scope": {"extensions": [".py"], "not_parsed_directory_names": [".git", ".venv"], "not_ranked_directory_names": ["tests"]},
            "formal_acceptance_blockers": [],
            "projects": [{"project_id": "fixture", "root": str(tmp_path), "role": "dev-regression", "holdout": False,
                          "source_inventory": [row(name) for name in files],
                          "environment_declarations": [row("pyproject.toml")], "documents": [row("README.md")],
                          "legacy_gt": {"path": str(value.gt), "sha256": hashlib.sha256(value.gt.read_bytes()).hexdigest()},
                          "ranking_eligible_canonical_labels": [name for name in truth if name in files],
                          "not_ranked_canonical_labels": [], "unmatched_labels": list(unmatched), "ambiguous_labels": []}],
        }
        write_contract(value, contract)
    value.freeze = freeze
    freeze()
    monkeypatch.setattr(acceptance, "build_index", lambda *args, **kwargs: result)
    monkeypatch.setattr(acceptance, "render_l1", lambda _: "L1 rendered")
    monkeypatch.setattr(acceptance, "render_l2", lambda _: "L2 rendered")
    monkeypatch.setattr(acceptance, "reading_order", lambda *args, **kwargs: [(name, "core", 0) for name in files])
    return value


def run(project, *extra):
    return acceptance.main([str(project.root), str(project.gt), "--contract", str(project.contract), "--project-id", "fixture", "--no-cache", "--confirm-access", *extra])


def test_exact_eight_out_of_ten_and_independent_entry_fixture_pass(project, capsys):
    assert run(project) == 0
    output = capsys.readouterr().out
    assert "P@10=8/10 (80.0%)" in output
    assert "Recall@10=8/8 (100.0%)" in output
    assert "dev-regression · 非holdout" in output
    assert "P1验收通过" in output
    assert "L1 rendered" in output and "L2 rendered" in output


def test_ranking_failure_is_not_ignored_with_valid_positions(project, capsys):
    project.freeze(project.files[:7] + [project.files[-1]])
    assert run(project) == 1
    assert "P1验收失败" in capsys.readouterr().out
    project.freeze()
    assert run(project, "--min-p10", "0.9") == 1


def test_relaxing_confirmed_thresholds_cannot_manufacture_acceptance(project, capsys):
    assert run(project, "--min-p10", "0.7", "--l1-max-seconds", "90", "--l2-max-seconds", "300") == 1
    assert "FAIL 阈值未放宽已确认目标" in capsys.readouterr().out


def test_empty_gt_is_na_and_not_accepted(project, capsys):
    project.freeze([])
    assert run(project) == 1
    output = capsys.readouterr().out
    assert "P@10=0/10 (N/A)" in output
    assert "无法验收" in output


def test_missing_entry_gold_is_na_even_when_document_proxy_passes(project, capsys):
    contract = read_contract(project)
    contract["task"]["entry_gold"] = {"status": "not_yet_independently_annotated"}
    write_contract(project, contract)
    assert run(project) == 1
    output = capsys.readouterr().out
    assert "precision=N/A；recall=N/A" in output
    assert "不能宣称P1全通过" in output


def test_unresolved_p0_blockers_are_preserved(project, capsys):
    contract = read_contract(project)
    contract["formal_acceptance_blockers"] = ["fixture awaiting adjudication"]
    write_contract(project, contract)
    assert run(project) == 1
    assert "fixture awaiting adjudication" in capsys.readouterr().out


def test_raw_gt_without_contract_is_exploration_not_formal_pass(project, capsys):
    assert acceptance.main([str(project.root), str(project.gt), "--no-cache", "--confirm-access"]) == 1
    assert "未使用P0冻结合约" in capsys.readouterr().out


def test_short_output_is_not_a_p10_pass(project, monkeypatch, capsys):
    monkeypatch.setattr(acceptance, "reading_order", lambda *args, **kwargs: [(f, "core", 0) for f in project.files[:8]])
    assert run(project) == 1
    assert "无法验收" in capsys.readouterr().out


def test_missing_or_unknown_parse_cannot_pass(project, capsys):
    project.result.files.pop()
    assert run(project) == 1
    assert "缺失文件: ['module11.py']" in capsys.readouterr().out
    project.result.files.append(FileMeta(path="module11.py", language=Language.UNKNOWN))
    assert run(project) == 1
    assert "未解析/未知语言文件: ['module11.py']" in capsys.readouterr().out


def test_structured_parse_issues_prevent_false_complete(project, capsys):
    project.result.parse_issues = [{"path": "module0.py", "reason": "source changed during indexing"}]
    assert run(project) == 1
    assert "source changed during indexing" in capsys.readouterr().out


def test_unmatched_or_ambiguous_gt_is_not_removed_from_eligibility(project, capsys):
    project.freeze(project.files[:8] + ["missing/key.py"], unmatched=["missing/key.py"])
    assert run(project) == 1
    assert "missing/key.py" in capsys.readouterr().out


def test_l1_and_l2_are_measured_against_distinct_limits(project, monkeypatch, capsys):
    counter = iter([100.0, 100.05, 100.1, 131.0, 151.0])
    monkeypatch.setattr(acceptance.time, "perf_counter", lambda: next(counter))
    assert run(project) == 1
    output = capsys.readouterr().out
    assert "L1端到端 31.00s；L2端到端 51.00s" in output
    assert "FAIL L1端到端 < 30s" in output
    assert "PASS L2端到端 < 180s" in output


def test_slow_l2_is_not_hidden_by_fast_l1(project, monkeypatch, capsys):
    counter = iter([100.0, 100.05, 100.1, 100.2, 281.0])
    monkeypatch.setattr(acceptance.time, "perf_counter", lambda: next(counter))
    assert run(project) == 1
    output = capsys.readouterr().out
    assert "PASS L1端到端 < 30s" in output
    assert "FAIL L2端到端 < 180s" in output


def test_cache_disabled_is_forwarded(project, monkeypatch):
    flags = []
    def build(*args, **kwargs):
        flags.append(kwargs["use_cache"])
        return project.result
    monkeypatch.setattr(acceptance, "build_index", build)
    run(project)
    assert flags == [False]


@pytest.mark.parametrize(("name", "kind"), [("module0.py", "source"), ("pyproject.toml", "configuration"), ("README.md", "document"), ("gt.json", "ground_truth")])
def test_frozen_input_hash_drift_fails_before_build(project, monkeypatch, capsys, name, kind):
    (project.root / name).write_text("modified input", encoding="utf-8")
    def forbidden(*args, **kwargs):
        pytest.fail("drifting inputs must not reach parser")
    monkeypatch.setattr(acceptance, "build_index", forbidden)
    assert run(project) == 1
    output = capsys.readouterr().out
    assert "INPUT_DRIFT" in output and kind in output


@pytest.mark.parametrize("name", ["new_module.py", "requirements-extra.txt", "ARCHITECTURE.md"])
def test_new_input_files_cannot_silently_change_frozen_scope(project, capsys, name):
    (project.root / name).write_text("new input", encoding="utf-8")
    assert run(project) == 1
    assert "added_since_freeze" in capsys.readouterr().out


def test_input_mutation_during_build_invalidates_result(project, monkeypatch, capsys):
    def build(*args, **kwargs):
        (project.root / "module0.py").write_text("changed = 2", encoding="utf-8")
        return project.result
    monkeypatch.setattr(acceptance, "build_index", build)
    assert run(project) == 1
    assert "运行期间输入发生变化" in capsys.readouterr().out


def test_holdout_is_rejected_before_execution(project, monkeypatch, capsys):
    contract = read_contract(project)
    contract["projects"][0]["holdout"] = True
    write_contract(project, contract)
    monkeypatch.setattr(acceptance, "build_index", lambda *args, **kwargs: pytest.fail("must not execute holdout"))
    assert run(project) == 2
    assert "不读取封存" in capsys.readouterr().out


def test_contract_cannot_read_source_outside_project(project, capsys):
    contract = read_contract(project)
    contract["projects"][0]["source_inventory"][0]["path"] = "../outside.py"
    write_contract(project, contract)
    assert run(project) == 2
    assert "路径越界" in capsys.readouterr().out


def test_ambiguous_basename_remains_unknown_after_exact_match():
    matched, unmatched = acceptance.match_ground_truth(["a/main.py", "main.py"], {"a/main.py", "b/main.py"})
    assert matched == ["a/main.py"] and unmatched == ["main.py"]
    assert acceptance.match_ground_truth(["a/main.py", "main.py"], {"a/main.py"}) == (["a/main.py"], [])


def test_disk_positions_and_symbol_identity_are_independently_checked(project):
    bad = Symbol(qname="module0.py::fake", name="fake", kind=SymbolKind.FUNCTION, file="module0.py", line=2)
    project.result.symbols = [bad, bad]
    project.result.symbol_pr = {bad.qname: 1.0, "missing.py::fake": 0.5}
    errors = acceptance.output_location_errors(project.root, project.result, project.files + ["missing.py"])
    assert any("符号身份冲突" in error for error in errors)
    assert any("符号行号越界" in error for error in errors)
    assert any("符号不在索引中" in error for error in errors)
    assert any("输出位置不可访问" in error for error in errors)


def test_deleted_contract_during_build_is_explicit_drift(project, monkeypatch, capsys):
    def build(*args, **kwargs):
        project.contract.unlink()
        return project.result
    monkeypatch.setattr(acceptance, "build_index", build)
    assert run(project) == 1
    output = capsys.readouterr().out
    assert "INPUT_DRIFT" in output and "unreadable_or_missing" in output


def test_malformed_entry_declaration_is_rejected_before_build(project, capsys):
    contract = read_contract(project)
    contract["task"]["entry_gold"] = ["main.py"]
    write_contract(project, contract)
    assert run(project) == 2
    assert "入口标签声明必须是对象" in capsys.readouterr().out


def test_out_of_scope_label_is_not_a_formal_positive(project, capsys):
    contract = read_contract(project)
    contract["projects"][0]["source_inventory"][0]["ranking_scope"] = False
    write_contract(project, contract)
    assert run(project) == 2
    assert "冻结排序标签不符合声明范围" in capsys.readouterr().out


def test_wrong_entry_prediction_fails_even_when_p10_passes(project, capsys):
    project.result.entrypoints = [EntryPoint(file=project.files[1], level="app", reason="wrong fixture", kind="process", confidence="static")]
    assert run(project) == 1
    assert "precision=0.0%；recall=0.0%" in capsys.readouterr().out


def test_entry_hints_do_not_become_application_false_positives(project, capsys):
    project.result.entrypoints.extend([
        EntryPoint(project.files[1], "app", "factory", kind="assembly", confidence="static"),
        EntryPoint(project.files[2], "app", "bridge", kind="bridge", confidence="declared"),
        EntryPoint(project.files[3], "app", "name", kind="candidate", confidence="heuristic"),
        EntryPoint(project.files[4], "app", "guess", kind="process", confidence="heuristic"),
    ])
    assert run(project) == 0
    output = capsys.readouterr().out
    assert "precision=100.0%；recall=100.0%" in output
    assert "'bridge': 1, 'assembly': 1, 'candidate': 1" in output
    assert "按角色precision/recall=N/A" in output
