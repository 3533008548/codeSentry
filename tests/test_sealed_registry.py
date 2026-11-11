"""Synthetic metadata exercises audit transactions; it never runs candidates."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import threading

import pytest

from evals.sealed_registry import BatchSpec, SealedRegistry, main


HASH = "a" * 64
OTHER = "b" * 64


def spec(batch_id="batch-v1", *, partition="dev", source="independent-repo-a", family="concrete-lineage-a"):
    return BatchSpec(batch_id, "synthetic-metadata", "v1", (source,), (family,), partition, HASH, HASH, HASH)


@pytest.fixture
def registry(tmp_path):
    return SealedRegistry.create(tmp_path / "registry.sqlite3", operator_id="declared-operator")


def register(registry, batch=None, event="register-v1"):
    registry.register_batch(batch or spec(), event_id=event)


def start(registry, *, evaluation="evaluation-1", event="start-1", batch="batch-v1", candidate_hash=HASH):
    return registry.start_evaluation(batch, evaluation, "candidate-a", "v1", candidate_hash, event_id=event)


def finished(registry, *, outcome="failed"):
    start(registry)
    registry.finish_evaluation("evaluation-1", outcome, OTHER, event_id="finish-1")


def release_and_access(registry):
    registry.release_feedback("evaluation-1", "developer-a", event_id="release-1")
    registry.access_feedback("evaluation-1", "developer-a", event_id="access-1")


def batch_rows(registry):
    return {row["batch_id"]: row for row in registry.inspect()["batches"]}


def test_operator_metadata_lifecycle_never_grants_os_or_holdout_eligibility(registry):
    register(registry, spec(source="CodeSentry"))
    finished(registry, outcome="passed")
    release_and_access(registry)
    registry.use_feedback("evaluation-1", "declared-modification-v2", "feedback informed this operator-declared change",
                          event_id="use-1")
    report = registry.inspect()
    assert report["chain_valid"] and report["event_count"] == 6
    assert not report["os_isolation_verified"] and not report["holdout_evaluation_ready"]
    assert not report["gold_read"] and not report["candidate_executed"] and not report["formal_acceptance"]["passed"]
    assert report["operator_declaration_only"] and report["batches"][0]["effective_partition"] == "dev"
    evaluation = report["evaluations"][0]
    assert evaluation["candidate_hash"] == HASH and evaluation["report_hash"] == OTHER
    assert evaluation["outcome"] == "passed" and len(evaluation["feedback_accesses"]) == 1


@pytest.mark.parametrize("outcome", ["passed", "failed", "incomplete", "error", "cancelled"])
def test_any_released_feedback_used_for_modification_demotes_holdout(registry, outcome):
    register(registry, spec(partition="holdout"))
    finished(registry, outcome=outcome)
    release_and_access(registry)
    assert batch_rows(registry)["batch-v1"]["effective_partition"] == "holdout"
    registry.use_feedback("evaluation-1", "change-2", "operator declares feedback was used", event_id="use-1")
    batch = batch_rows(registry)["batch-v1"]
    assert batch["partition"] == "holdout" and batch["effective_partition"] == "dev"
    assert batch["demoted_by"] == ["use-1"]
    assert not registry.inspect()["holdout_evaluation_ready"]


def test_demotion_spreads_across_transitive_source_and_defect_groups(registry):
    register(registry, spec(partition="holdout"))
    register(registry, spec("batch-b", partition="holdout", family="concrete-lineage-b"), "register-b")
    register(registry, spec("batch-c", partition="holdout", source="independent-repo-c", family="concrete-lineage-b"),
             "register-c")
    register(registry, spec("independent", partition="holdout", source="independent-repo-d", family="lineage-d"),
             "register-d")
    finished(registry)
    release_and_access(registry)
    registry.use_feedback("evaluation-1", "modification", "declared feedback use", event_id="use-1")
    batches = batch_rows(registry)
    assert all(batches[name]["effective_partition"] == "dev" for name in ("batch-v1", "batch-b", "batch-c"))
    assert batches["independent"]["effective_partition"] == "holdout"
    for new in (spec("reuse-source", partition="holdout", source="independent-repo-c", family="new-family"),
                spec("reuse-family", partition="holdout", source="new-repo", family="concrete-lineage-b")):
        with pytest.raises(ValueError, match="regain holdout"):
            register(registry, new, "new-" + new.batch_id)
    # Reopening does not reset the demotion or permit a newly named holdout.
    reopened = SealedRegistry(registry.path)
    assert batch_rows(reopened)["batch-c"]["effective_partition"] == "dev"


@pytest.mark.parametrize("group", ["research_agent", "Research Agent", "knowledge_loop", "Knowledge Loop",
                                  "agent for obsidian", "CodeSentry", "repo:codesentry", "repository:Research_Agent",
                                  "D:/develop/project/CodeSentry"])
def test_known_exposed_projects_cannot_be_registered_as_holdout(registry, group):
    with pytest.raises(ValueError, match="known development"):
        register(registry, spec(partition="holdout", source=group))
    assert registry.inspect()["event_count"] == 0


@pytest.mark.parametrize("change", [{"source_groups": ("independent-repo-a",)},
                                     {"defect_families": ("concrete-lineage-a",)}])
def test_related_groups_cannot_cross_train_dev_holdout_partitions(registry, change):
    register(registry, spec(partition="train"))
    candidate = replace(spec("new", source="other-repo", family="other-family"), **change)
    with pytest.raises(ValueError, match="cross partitions"):
        register(registry, candidate, "new-register")
    assert registry.inspect()["event_count"] == 1


def test_feedback_cannot_be_used_without_finish_release_and_access(registry):
    register(registry)
    with pytest.raises(ValueError, match="finished"):
        registry.release_feedback("evaluation-1", "developer-a", event_id="too-early")
    start(registry)
    with pytest.raises(ValueError, match="finished"):
        registry.release_feedback("evaluation-1", "developer-a", event_id="too-early-again")
    registry.finish_evaluation("evaluation-1", "failed", OTHER, event_id="finish-1")
    with pytest.raises(ValueError, match="prior recorded"):
        registry.use_feedback("evaluation-1", "change", "unavailable feedback", event_id="bad-use")
    with pytest.raises(ValueError, match="release"):
        registry.access_feedback("evaluation-1", "developer-a", event_id="bad-access")
    registry.release_feedback("evaluation-1", "developer-a", event_id="release-1")
    with pytest.raises(ValueError, match="prior recorded"):
        registry.use_feedback("evaluation-1", "change", "not yet accessed", event_id="bad-use-again")
    assert registry.inspect()["event_count"] == 4


def test_unique_event_batch_evaluation_and_feedback_identities_prevent_replay(registry):
    register(registry)
    for batch, event in ((spec("other-batch"), "register-v1"), (spec(), "new-register")):
        with pytest.raises(ValueError):
            register(registry, batch, event)
    start(registry)
    with pytest.raises(ValueError):
        start(registry, event="duplicate-evaluation")
    registry.finish_evaluation("evaluation-1", "failed", OTHER, event_id="finish-1")
    with pytest.raises(ValueError):
        registry.finish_evaluation("evaluation-1", "passed", HASH, event_id="new-finish")
    release_and_access(registry)
    with pytest.raises(ValueError, match="already been released"):
        registry.release_feedback("evaluation-1", "developer-a", event_id="new-release")
    registry.use_feedback("evaluation-1", "change-1", "feedback used", event_id="use-1")
    with pytest.raises(ValueError, match="already recorded"):
        registry.use_feedback("evaluation-1", "change-1", "replay", event_id="new-use")
    assert registry.inspect()["event_count"] == 6


def test_candidate_version_bytes_are_frozen_across_evaluations(registry):
    register(registry)
    finished(registry)
    with pytest.raises(ValueError, match="cannot change bytes"):
        start(registry, evaluation="evaluation-2", event="start-2", candidate_hash=OTHER)
    start(registry, evaluation="evaluation-2", event="start-2")
    report = registry.inspect()
    assert len(report["evaluations"]) == 2  # Genuine reruns remain visible.


def test_same_candidate_cannot_have_two_active_evaluations_for_one_batch(registry):
    register(registry)
    start(registry)
    with pytest.raises(ValueError, match="active evaluation"):
        start(registry, evaluation="evaluation-2", event="start-2")
    assert registry.inspect()["event_count"] == 2


def test_finish_unknown_evaluation_is_rejected_without_an_event(registry):
    with pytest.raises(ValueError):
        registry.finish_evaluation("unknown", "passed", HASH, event_id="bad-finish")
    assert registry.inspect()["event_count"] == 0


@pytest.mark.parametrize("sql,parameters", [
    ("UPDATE events SET event_hash=? WHERE sequence=1", ("0" * 64,)),
    ("UPDATE events SET previous_hash=? WHERE sequence=1", ("0" * 64,)),
    ("UPDATE events SET created_at=? WHERE sequence=1", ("edited-time",)),
    ("UPDATE events SET payload=? WHERE sequence=1", ('{"edited":true}',)),
    ("DELETE FROM events WHERE sequence=2", ()),
    ("DELETE FROM events WHERE sequence=1", ()),
    ("UPDATE metadata SET value=? WHERE key='head_hash'", ("0" * 64,)),
    ("UPDATE metadata SET value=? WHERE key='operator_id'", ("someone-else",)),
])
def test_event_chain_and_tail_checkpoint_detect_accidental_edits(registry, sql, parameters):
    register(registry)
    start(registry)
    connection = sqlite3.connect(registry.path)
    with connection:
        connection.execute(sql, parameters)
    connection.close()
    with pytest.raises(ValueError):
        registry.inspect()
    with pytest.raises(ValueError):
        registry.finish_evaluation("evaluation-1", "failed", OTHER, event_id="must-not-append")


def test_event_replay_survives_process_style_reopen(registry):
    register(registry)
    finished(registry)
    before = registry.inspect()
    after = SealedRegistry(registry.path).inspect()
    assert before == after and before["event_count"] == 3
    assert before["events"][1]["previous_hash"] == before["events"][0]["event_hash"]


def test_concurrent_replayed_event_is_committed_exactly_once(registry):
    barrier = threading.Barrier(2)
    def contender(index):
        instance = SealedRegistry(registry.path)
        barrier.wait()
        try:
            instance.register_batch(spec(f"batch-{index}"), event_id="same-request-id")
            return "committed"
        except ValueError:
            return "rejected"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(contender, range(2)))
    assert sorted(results) == ["committed", "rejected"]
    assert registry.inspect()["event_count"] == 1


def test_concurrent_same_candidate_start_is_serialized(registry):
    register(registry)
    barrier = threading.Barrier(2)
    def contender(index):
        instance = SealedRegistry(registry.path)
        barrier.wait()
        try:
            start(instance, evaluation=f"evaluation-{index}", event=f"start-{index}")
            return "committed"
        except ValueError:
            return "rejected"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(contender, range(2)))
    assert sorted(results) == ["committed", "rejected"]
    assert registry.inspect()["event_count"] == 2


def test_concurrent_feedback_use_and_related_new_holdout_cannot_restore_sealing(registry):
    register(registry, spec(partition="holdout"))
    finished(registry)
    release_and_access(registry)
    barrier = threading.Barrier(2)
    def use():
        instance = SealedRegistry(registry.path)
        barrier.wait()
        instance.use_feedback("evaluation-1", "change-2", "declared used feedback", event_id="use-1")
    def another():
        instance = SealedRegistry(registry.path)
        barrier.wait()
        try:
            register(instance, spec("new-name", partition="holdout"), "register-new-name")
        except ValueError:
            pass
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(use), pool.submit(another)]
        for future in futures:
            future.result()
    assert all(batch["effective_partition"] == "dev" for batch in batch_rows(registry).values())


@pytest.mark.parametrize("changes", [{"source_groups": ()}, {"defect_families": ()}, {"source_groups": ("a", "A")},
                                      {"partition": "approved"}, {"frozen_input_hash": "not-a-hash"},
                                      {"scorer_hash": True}, {"dataset_version": ""}])
def test_batch_metadata_is_versioned_and_strict(changes):
    with pytest.raises(ValueError):
        replace(spec(), **changes)


def test_init_never_overwrites_existing_database(registry):
    before = registry.path.read_bytes()
    with pytest.raises(FileExistsError):
        SealedRegistry.create(registry.path, operator_id="new-operator")
    assert registry.path.read_bytes() == before


def test_no_gold_read_or_candidate_execution_is_hidden_in_metadata_workflow(registry, tmp_path, monkeypatch):
    import subprocess
    gold = tmp_path / "gold.json"
    candidate = tmp_path / "candidate.py"
    gold.write_text("private label contents", encoding="utf-8")
    candidate.write_text("raise RuntimeError('must not execute')", encoding="utf-8")
    original = Path.open
    def forbid(path, *args, **kwargs):
        if path in {gold, candidate}:
            pytest.fail("metadata ledger opened gold or candidate bytes")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", forbid)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("metadata ledger executed a process"))
    register(registry)
    finished(registry)
    release_and_access(registry)
    registry.use_feedback("evaluation-1", "new-candidate", "declared modification", event_id="use-1")
    assert registry.inspect()["candidate_executed"] is False


def test_cli_register_inspect_and_exclusive_output(tmp_path, capsys):
    database, metadata, output = tmp_path / "ledger.db", tmp_path / "batch.json", tmp_path / "report.json"
    metadata.write_text(json.dumps(spec(source="CodeSentry").to_dict()), encoding="utf-8")
    assert main(["init", str(database), "--operator", "declared-operator"]) == 0
    assert main(["register", str(database), "--metadata", str(metadata), "--event-id", "register-v1"]) == 0
    assert main(["inspect", str(database), "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["event_count"] == 1 and report["batches"][0]["partition"] == "dev"
    before = output.read_bytes()
    assert main(["inspect", str(database), "--output", str(output)]) == 2
    assert output.read_bytes() == before
    assert "source_groups" not in capsys.readouterr().out


def test_cli_rejects_group_string_and_extra_trust_fields(registry, tmp_path):
    path = tmp_path / "invalid.json"
    payload = spec().to_dict() | {"source_groups": "one-group"}
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["register", str(registry.path), "--metadata", str(path), "--event-id", "bad-request"]) == 2
    payload = spec().to_dict() | {"role": "independent-approved-owner", "os_isolation_verified": True}
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["register", str(registry.path), "--metadata", str(path), "--event-id", "bad-request-2"]) == 2
    assert registry.inspect()["event_count"] == 0
