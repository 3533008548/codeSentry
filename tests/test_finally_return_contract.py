"""Check that developer candidate artifacts cannot stand in for admission."""
import json

import pytest

from codesentry.access import AccessPolicy
from codesentry.review.gate import evaluate_gate, gate_manifest
from evals import finally_return_contract as contract
from evals import finally_return_isolation as isolation


def test_dev_contract_refuses_changed_material_and_keeps_existing_report(tmp_path, monkeypatch):
    source_root = contract.ROOT
    for name in (contract.PROPOSAL, contract.DATASET, contract.IMPLEMENTATION, contract.SCORER):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((source_root / name).read_bytes())
    monkeypatch.setattr(contract, "ROOT", tmp_path)
    registration, report_path = tmp_path / "registered.json", tmp_path / "report.json"
    contract.register(registration)
    report = contract.evaluate(registration, report_path)
    assert report["contract_consistent"] and not report["formal_acceptance"]
    original = report_path.read_bytes()
    with pytest.raises(FileExistsError):
        contract.evaluate(registration, report_path)
    assert report_path.read_bytes() == original

    path = tmp_path / contract.DATASET
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="registration differs"):
        contract.evaluate(registration, tmp_path / "changed.json")
    assert not (tmp_path / "changed.json").exists()


@pytest.mark.filterwarnings("ignore:'return' in a 'finally' block:SyntaxWarning")
def test_project_cannot_promote_the_proposal_by_forging_an_active_record(tmp_path):
    path = tmp_path / "rules" / "active" / "python.finally_return.json"
    path.parent.mkdir(parents=True)
    proposal = json.loads((contract.ROOT / contract.PROPOSAL).read_bytes())
    path.write_text(json.dumps(proposal | {"status": "active", "production_admission": True}), encoding="utf-8")
    (tmp_path / "example.py").write_text("def f():\n    try:\n        work()\n    finally:\n        return 0\n", encoding="utf-8")
    manifest = gate_manifest()
    assert not manifest["admission_ready"]
    assert [entry["rule_id"] for entry in manifest["required_rules"]] == ["python.function_length"]
    report = evaluate_gate(AccessPolicy(tmp_path, confirmed=True))
    assert report["gate_status"] == "incomplete"
    assert report["summary"]["blocking_findings"] == 0


def test_isolated_replay_mounts_only_unlabeled_inputs_and_refuses_a_replaced_registration(tmp_path, monkeypatch):
    binding, cases, files = isolation._inputs()
    projected = json.loads(files["input.txt"])
    assert projected == [{key: case[key] for key in ("id", "source")} for case in cases]
    assert binding["partition"] == "dev" and binding["formal_acceptance"] is False
    original = json.loads(isolation.ORIGINAL.read_bytes())
    original["sha256"]["../outside.py"] = "0" * 64
    replaced = tmp_path / "replacement.json"
    replaced.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(isolation, "ORIGINAL", replaced)
    with pytest.raises(ValueError, match="original development registration was changed"):
        isolation._inputs()
