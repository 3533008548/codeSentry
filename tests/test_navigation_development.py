"""Allowed run manifests are frozen before scores and never restore revoked scope."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

from codesentry.access import AccessPolicy
from evals import navigation_development as development


@pytest.fixture
def sample(tmp_path):
    root=tmp_path/"source"
    root.mkdir()
    names=[f"module{i}.py" for i in range(12)]
    for index,name in enumerate(names):
        (root/name).write_text(f"def main():\n    return {index}\n",encoding="utf-8")
    (root/"pyproject.toml").write_text("[project]\nname='fixture'\n[project.scripts]\napp='module0:main'\n",encoding="utf-8")
    (root/"README.md").write_text("fixture documentation\n",encoding="utf-8")
    (root/"index.html").write_text('<div id="root"></div><script type="module" src="/module0.py"></script>',encoding="utf-8")
    truth=tmp_path/"gold.json"
    truth.write_text(json.dumps(names[:8]),encoding="utf-8")
    def row(name):
        raw=(root/name).read_bytes()
        return {"path":name,"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw),"ranking_scope":True}
    contract=tmp_path/"contract.json"
    contract.write_text(json.dumps({
        "contract_version":1,"contract_id":"fixture-parent-v1",
        "label_policy":{"human_adjudication":"not_performed","unmentioned_files":"unknown_not_negative"},
        "task":{"p_at_10":{"threshold":0.8},"latency_seconds":{"l1_less_than":30,"l2_less_than":180},
                "entry_gold":{"status":"not_yet_independently_annotated"}},
        "frozen_scope":{"extensions":[".py"],"not_parsed_directory_names":[".git",".venv"],"not_ranked_directory_names":["tests"]},
        "formal_acceptance_blockers":["fixture labels are not human adjudicated"],
        "projects":[{"project_id":"fixture","root":str(root),"role":"dev-regression","holdout":False,
                     "source_inventory":[row(name) for name in names],"environment_declarations":[row("pyproject.toml")],
                     "documents":[row("README.md")],"legacy_gt":{"path":str(truth),"sha256":hashlib.sha256(truth.read_bytes()).hexdigest()},
                     "ranking_eligible_canonical_labels":names[:8],"not_ranked_canonical_labels":[],"unmatched_labels":["missing.py"],"ambiguous_labels":[]}],
    }),encoding="utf-8")
    state=tmp_path/"state"
    state.mkdir()
    with sqlite3.connect(state/"workspaces.sqlite3") as connection:
        connection.execute("CREATE TABLE workspaces(id TEXT,path TEXT,canonical_key TEXT,access_policy TEXT)")
    return {"base":tmp_path,"root":root,"state":state,"contract":contract,"truth":truth,"names":names}


def register(sample, settings=None, version=1):
    policy=AccessPolicy(sample["root"],settings)
    access=policy.to_dict()|{"version":version,"cleanup_pending":False}
    with sqlite3.connect(sample["state"]/"workspaces.sqlite3") as connection:
        connection.execute("DELETE FROM workspaces")
        connection.execute("INSERT INTO workspaces VALUES(?,?,?,?)",("a"*32,str(sample["root"]),
                           os.path.normcase(str(sample["root"])),json.dumps(access)))


def freeze(sample,run_id="run1"):
    return development.freeze_development_manifest(sample["contract"],"fixture",sample["state"],sample["base"]/"output",run_id)


def forbid_open(monkeypatch,paths):
    original=Path.open
    denied={path.absolute() for path in paths}
    def checked(path,*args,**kwargs):
        if path.absolute() in denied:
            pytest.fail("forbidden source content was opened")
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,"open",checked)


def test_manifest_is_dev_only_and_exclusive_before_any_score(sample):
    register(sample)
    report=freeze(sample)
    path=Path(report["manifest_path"])
    raw=path.read_bytes();manifest=json.loads(raw)
    assert manifest["constraints"]["scoring_started"] is False
    assert manifest["constraints"]["human_labels_approved"] is False
    assert manifest["constraints"]["formal_contract_v2"] is False
    assert manifest["label_provenance"]["unmatched_labels"]==["missing.py"]
    assert len(manifest["label_provenance"]["ranking_eligible_canonical_labels"])==8
    assert "texts" not in manifest["inputs"]
    assert b"def main():" not in raw and b"fixture documentation" not in raw
    assert manifest["inputs"]["startup_input_hashes"]["index.html"]
    assert report["compatibility"]["change_counts"]["startup_input_not_frozen_in_v1"]==1
    assert development.validate_run_manifest(path,sample["state"])["valid"] is True
    with pytest.raises(FileExistsError):
        freeze(sample)
    assert path.read_bytes()==raw


def test_denied_old_source_is_never_hashed_and_old_labels_are_not_shrunk(sample,monkeypatch):
    register(sample,{"exclude":["module0.py"]})
    forbid_open(monkeypatch,[sample["root"]/"module0.py"])
    report=freeze(sample)
    manifest=json.loads(Path(report["manifest_path"]).read_bytes())
    assert report["compatibility"]["comparable_to_v1"] is False
    assert report["compatibility"]["change_counts"]["access_scope_conflict"]>=1
    assert report["summary"]["source_files"]==11
    assert "module0.py" in manifest["label_provenance"]["ranking_eligible_canonical_labels"]
    assert len(manifest["label_provenance"]["ranking_eligible_canonical_labels"])==8


def test_source_change_invalidates_frozen_manifest_without_overwriting_it(sample):
    register(sample)
    report=freeze(sample)
    path=Path(report["manifest_path"]);before=path.read_bytes()
    (sample["root"]/"module1.py").write_text("def changed():\n    return 999\n",encoding="utf-8")
    result=development.validate_run_manifest(path,sample["state"])
    assert result["valid"] is False and result["reason"]=="input_snapshot_changed"
    assert path.read_bytes()==before


def test_policy_revoke_is_checked_before_any_further_source_read(sample,monkeypatch):
    register(sample)
    report=freeze(sample)
    register(sample,{"exclude":["module0.py"]},version=2)
    forbid_open(monkeypatch,[sample["root"]/name for name in sample["names"]])
    result=development.validate_run_manifest(Path(report["manifest_path"]),sample["state"])
    assert result=={"valid":False,"reason":"workspace_policy_changed"}


def test_startup_inputs_use_same_collector_and_html_change_is_detected(sample,monkeypatch):
    register(sample)
    calls=[]
    original=development.collect_startup_inputs
    def collected(access,*,exclude):
        calls.append(exclude)
        return original(access,exclude=exclude)
    monkeypatch.setattr(development,"collect_startup_inputs",collected)
    report=freeze(sample)
    assert calls and all(config.extensions==[".py"] for config in calls)
    (sample["root"]/"index.html").write_text('<script type="module" src="changed.py"></script>',encoding="utf-8")
    assert development.validate_run_manifest(Path(report["manifest_path"]),sample["state"])["valid"] is False


def test_console_prints_aggregates_only_and_does_not_spawn_target_tools(sample,monkeypatch,capsys):
    register(sample)
    import subprocess
    monkeypatch.setattr(subprocess,"Popen",lambda *a,**k: pytest.fail("preflight must not launch target or Node tools"))
    assert development.main(["--contract",str(sample["contract"]),"--project-id","fixture",
                             "--workspace-data-dir",str(sample["state"]),"--output-dir",str(sample["base"]/"output"),"--run-id","console"])==0
    output=capsys.readouterr().out
    assert "module0.py" not in output and "index.html" not in output and str(sample["root"]) not in output
    assert '"source_files": 12' in output
    assert '"manifest_sha256"' not in output and '"input_snapshot_sha256"' not in output


def test_source_budget_does_not_open_files_larger_than_remaining_allowance(sample,monkeypatch):
    register(sample)
    monkeypatch.setattr(development,"MAX_TOTAL_SOURCE_BYTES",8)
    # Skip the legacy preflight here: inspect the permitted collector itself,
    # whose source-byte budget is independent of metadata/control reads.
    access,identity=development._confirmed_access(sample["root"],sample["state"])
    frozen=development.load_contract(sample["contract"],"fixture",sample["root"],None,access=access)
    forbid_open(monkeypatch,[sample["root"]/name for name in sample["names"]])
    result=development.collect_current_inputs(access,frozen)
    assert result["source_inventory"]==[]
    assert len(result["unread_source_inventory"])==12


def test_new_git_restrictions_return_invalid_without_reading_revoked_source(sample,monkeypatch):
    register(sample)
    report=freeze(sample)
    (sample["root"]/".gitignore").write_text("module0.py\n",encoding="utf-8")
    forbid_open(monkeypatch,[sample["root"]/name for name in sample["names"]])
    result=development.validate_run_manifest(Path(report["manifest_path"]),sample["state"])
    assert result=={"valid":False,"reason":"workspace_scope_unavailable"}
