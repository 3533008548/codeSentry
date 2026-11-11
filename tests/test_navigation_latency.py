"""End-to-end navigation clocks include preparation and actual local flushes."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codesentry.access import AccessDenied
from evals import navigation_latency as latency


@pytest.fixture
def sample(tmp_path, monkeypatch):
    root = tmp_path / "target"
    root.mkdir()
    (root / "main.py").write_text("SOURCE_MUST_NOT_BE_EXECUTED\n", encoding="utf-8")
    private = tmp_path / "private_artifacts"
    output = private / "measurement"
    report = tmp_path / "aggregate.json"
    path = tmp_path / "frozen.manifest.json"
    identity = {"workspace_id": "a" * 32, "policy_version": 1,
                "policy_fingerprint": "c" * 64, "settings": {"exclude": []}}
    manifest = {"schema_version": 1, "manifest_kind": "navigation-development-allowed-run",
                "role": "dev-regression", "holdout": False, "root": str(root),
                "project_id": "fixture", "workspace": identity,
                "parent_contract_path": str(tmp_path / "contract.json"),
                "parent_contract_sha256": "b" * 64}
    path.write_text(json.dumps(manifest), encoding="utf-8")
    clock = SimpleNamespace(value=0.0)
    state = SimpleNamespace(root=root, path=path, output=output, report=report,
                            manifest=manifest, identity=identity, clock=clock,
                            pre_seconds=10.0, post_seconds=100.0,
                            validation_calls=[], access_objects=[], build_calls=[])

    class Access:
        def __init__(self):
            self.fingerprint = identity["policy_fingerprint"]
            self.closed = False
        def check_current(self):
            assert not self.closed
        def refresh_if_changed(self):
            assert not self.closed
        def close(self):
            self.closed_after_report_exists = report.exists()
            self.closed = True

    def validate(*args):
        state.validation_calls.append(True)
        clock.value += state.pre_seconds if len(state.validation_calls) == 1 else state.post_seconds
        return {"valid": True, "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "input_snapshot_sha256": "d" * 64}

    def access(*args):
        selected = Access()
        state.access_objects.append(selected)
        return selected, copy.deepcopy(identity)

    def build(*args, **kwargs):
        state.build_calls.append((args, kwargs))
        clock.value += 5
        return SimpleNamespace(is_complete=True, parse_failures=0,
                               files=[SimpleNamespace(path="main.py", is_parsed=True)])

    def render(text, seconds):
        def emit(result):
            clock.value += seconds
            return text
        return emit

    original_write = latency._write_utf8
    def write(path, content, created):
        original_write(path, content, created)
        if path.suffix == ".txt":
            clock.value += 2

    monkeypatch.setattr(latency, "LOCAL_ARTIFACT_ROOT", private)
    monkeypatch.setattr(latency.time, "perf_counter", lambda: clock.value)
    monkeypatch.setattr(latency, "_implementation", lambda: {"trusted_analyzer": "e" * 64})
    monkeypatch.setattr(latency, "validate_run_manifest", validate)
    monkeypatch.setattr(latency, "_confirmed_access", access)
    monkeypatch.setattr(latency, "load_contract", lambda *args, **kwargs: SimpleNamespace(policy="fixed-policy", sha256="b" * 64))
    monkeypatch.setattr(latency, "build_index", build)
    monkeypatch.setattr(latency, "render_l1", render("L1 中文私有报告 SYNTHETIC_CONTENT_SENTINEL\n", 1))
    monkeypatch.setattr(latency, "render_l2", render("L2 中文私有报告 SYNTHETIC_CONTENT_SENTINEL\n", 2))
    monkeypatch.setattr(latency, "_write_utf8", write)
    return state


def run(sample):
    return latency.measure_navigation_latency(sample.path, sample.root.parent / "state",
                                              output_dir=sample.output, report_path=sample.report)


def test_preparation_and_utf8_flushes_are_inside_end_to_end_clocks(sample):
    sample.pre_seconds = 40
    report = run(sample)
    # precheck 40 + build 5 + render 1 + actual write/flush 2.
    assert report["latency"]["l1_end_to_end_seconds"] == 48
    assert report["latency"]["l2_end_to_end_seconds"] == 52
    assert report["latency"]["l1_below_limit"] is False
    assert report["latency"]["preparation_seconds"] == 40
    assert report["latency"]["uncached_build_seconds"] == 5
    assert report["latency"]["l1_delivery_seconds"] == 3
    assert report["latency"]["l2_below_limit"] is True
    assert sample.build_calls[0][1]["use_cache"] is False
    assert report["formal_acceptance"]["passed"] is False


def test_post_output_validation_is_reported_separately_and_guards_close(sample):
    report = run(sample)
    assert report["latency"]["l1_end_to_end_seconds"] == 18
    assert report["latency"]["l2_end_to_end_seconds"] == 22
    assert report["latency"]["post_output_validation_seconds"] == 100
    assert report["latency"]["validated_outputs_ready_seconds"] == 122
    assert "m0_acceptance.py:main" in report["latency"]["timing_definition_reference"]
    assert len(sample.validation_calls) == 2
    assert len(sample.access_objects) == 2 and all(access.closed for access in sample.access_objects)
    assert all(access.closed_after_report_exists for access in sample.access_objects)


def test_local_files_contain_real_utf8_output_but_json_has_only_aggregates(sample, capsys):
    report = run(sample)
    first = sample.output / "l1.txt"
    assert first.read_text(encoding="utf-8").startswith("L1 中文私有报告")
    assert report["local_outputs"]["l1"]["sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()
    raw = sample.report.read_text(encoding="utf-8")
    assert "SYNTHETIC_CONTENT_SENTINEL" not in raw and "main.py" not in raw
    assert json.loads(raw) == report
    assert report["conditions"]["local_plaintext_report_written"] is True
    assert report["conditions"]["plaintext_console_output"] is False
    assert report["conditions"]["source_or_derived_content_sent_to_model"] is False
    assert report["conditions"]["operator_managed_export"] is True
    assert report["conditions"]["auto_removed_on_workspace_revoke"] is False
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("phase", ["pre", "post"])
def test_invalid_manifest_never_leaves_success_report_or_plaintext(sample, monkeypatch, phase):
    original = latency.validate_run_manifest
    def validate(*args):
        result = original(*args)
        if (phase == "pre" and len(sample.validation_calls) == 1
                or phase == "post" and len(sample.validation_calls) == 2):
            return {"valid": False, "reason": "synthetic_input_drift"}
        return result
    monkeypatch.setattr(latency, "validate_run_manifest", validate)
    with pytest.raises(ValueError):
        run(sample)
    assert not sample.report.exists()
    assert not (sample.output / "l1.txt").exists()
    assert not (sample.output / "l2.txt").exists()
    assert all(access.closed for access in sample.access_objects)
    if phase == "pre":
        assert not sample.build_calls


def test_implementation_drift_discards_only_this_runs_outputs(sample, monkeypatch):
    sample.output.mkdir(parents=True)
    keep = sample.output / "keep.txt"
    keep.write_text("KEEP_EXISTING_FILE", encoding="utf-8")
    versions = iter([{"trusted_analyzer": "a"}, {"trusted_analyzer": "b"}])
    monkeypatch.setattr(latency, "_implementation", lambda: next(versions))
    with pytest.raises(ValueError, match="implementation changed"):
        run(sample)
    assert not sample.report.exists() and not (sample.output / "l1.txt").exists()
    assert keep.read_text(encoding="utf-8") == "KEEP_EXISTING_FILE"
    assert all(access.closed for access in sample.access_objects)


@pytest.mark.parametrize("name", ["l1.txt", "l2.txt", "aggregate.json"])
def test_existing_artifacts_are_never_overwritten(sample, name):
    sample.output.mkdir(parents=True)
    existing = sample.report if name == "aggregate.json" else sample.output / name
    existing.write_text("KEEP_EXISTING_ARTIFACT", encoding="utf-8")
    with pytest.raises(FileExistsError):
        run(sample)
    assert existing.read_text(encoding="utf-8") == "KEEP_EXISTING_ARTIFACT"
    assert not sample.validation_calls


@pytest.mark.parametrize("which", ["plaintext", "json"])
def test_outputs_inside_target_source_are_refused_before_full_validation(sample, which):
    if which == "plaintext":
        sample.output = sample.root / "reports"
    else:
        sample.report = sample.root / "aggregate.json"
    with pytest.raises(ValueError, match="outside target"):
        run(sample)
    assert not sample.validation_calls


def test_plaintext_outside_ignored_artifact_root_is_refused(sample):
    sample.output = sample.root.parent / "public_reports"
    with pytest.raises(ValueError, match="analyzer .venv"):
        run(sample)
    assert not sample.validation_calls


def test_linked_output_parent_is_refused(sample, monkeypatch):
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == sample.output or original(path))
    with pytest.raises(ValueError, match="links or junctions"):
        run(sample)
    assert not sample.validation_calls


def test_permission_failure_does_not_render_or_leave_outputs(sample, monkeypatch):
    def denied(*args, **kwargs):
        raise AccessDenied("SYNTHETIC_PRIVATE_ERROR_DETAILS")
    monkeypatch.setattr(latency, "build_index", denied)
    with pytest.raises(AccessDenied):
        run(sample)
    assert not sample.report.exists() and not (sample.output / "l1.txt").exists()
    assert all(access.closed for access in sample.access_objects)


def test_post_output_workspace_identity_change_is_not_a_valid_measurement(sample, monkeypatch):
    original = latency._confirmed_access
    def changed(*args):
        access, identity = original(*args)
        if len(sample.access_objects) == 2:
            identity["policy_version"] = 2
        return access, identity
    monkeypatch.setattr(latency, "_confirmed_access", changed)
    with pytest.raises(AccessDenied):
        run(sample)
    assert not sample.report.exists() and not (sample.output / "l1.txt").exists()
    assert not (sample.output / "l2.txt").exists()
    assert all(access.closed for access in sample.access_objects)


def test_partial_write_failure_removes_created_files_and_closes_guard(sample, monkeypatch):
    original = latency._write_utf8
    def broken(path, text, created):
        original(path, text, created)
        if path.name == "l2.txt":
            raise OSError("Synthetic flush failure")
    monkeypatch.setattr(latency, "_write_utf8", broken)
    with pytest.raises(OSError):
        run(sample)
    assert not sample.report.exists() and not (sample.output / "l1.txt").exists()
    assert not (sample.output / "l2.txt").exists()
    assert all(access.closed for access in sample.access_objects)


def revoke_during_record_write(sample, monkeypatch):
    original = latency._write_utf8
    def write(path, text, created):
        original(path, text, created)
        if path == sample.report:
            access = sample.access_objects[0]
            assert not access.closed
            def denied():
                raise AccessDenied("Synthetic revocation while persisting record")
            access.check_current = denied
    monkeypatch.setattr(latency, "_write_utf8", write)


def test_revocation_during_record_persistence_is_checked_before_publication(sample, monkeypatch):
    revoke_during_record_write(sample, monkeypatch)
    with pytest.raises(AccessDenied):
        run(sample)
    assert not sample.report.exists()
    assert not (sample.output / "l1.txt").exists()
    assert not (sample.output / "l2.txt").exists()
    assert all(access.closed for access in sample.access_objects)


def test_cleanup_failure_explicitly_reports_pending_invalid_artifacts(sample, monkeypatch, capsys):
    original_validate = latency.validate_run_manifest
    def drift(*args):
        result = original_validate(*args)
        return {"valid": False} if len(sample.validation_calls) == 2 else result
    monkeypatch.setattr(latency, "validate_run_manifest", drift)
    original_unlink = Path.unlink
    def deny_one(path, *args, **kwargs):
        if path == sample.output / "l1.txt":
            raise PermissionError("Synthetic locked artifact")
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", deny_one)
    assert latency.main([str(sample.path), "--workspace-data-dir", str(sample.root.parent / "state"),
                         "--output-dir", str(sample.output), "--report", str(sample.report)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "not_evaluable" and result["artifacts_valid"] is False
    assert result["cleanup_pending"] is True and result["pending_artifact_count"] == 1
    assert result["original_error_type"] == "ValueError"
    assert (sample.output / "l1.txt").exists() and not (sample.output / "l2.txt").exists()
    assert not sample.report.exists()
    assert all(access.closed for access in sample.access_objects)


def test_failed_publication_receipt_invalidates_any_locked_residual_record(sample, monkeypatch, capsys):
    revoke_during_record_write(sample, monkeypatch)
    original_unlink = Path.unlink
    def locked_record(path, *args, **kwargs):
        if path == sample.report:
            raise PermissionError("Synthetic locked measurement record")
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", locked_record)
    assert latency.main([str(sample.path), "--workspace-data-dir", str(sample.root.parent / "state"),
                         "--output-dir", str(sample.output), "--report", str(sample.report)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["artifacts_valid"] is False and result["cleanup_pending"] is True
    assert result["original_error_type"] == "AccessDenied"
    residual = json.loads(sample.report.read_bytes())
    assert residual["conditions"]["measurement_requires_successful_command_receipt"] is True
    assert all(access.closed for access in sample.access_objects)


def test_console_emits_only_aggregate_latencies(sample, capsys):
    assert latency.main([str(sample.path), "--workspace-data-dir", str(sample.root.parent / "state"),
                         "--output-dir", str(sample.output), "--report", str(sample.report)]) == 0
    output = capsys.readouterr().out
    assert '"l1_end_to_end_seconds": 18.0' in output
    assert "SYNTHETIC_CONTENT_SENTINEL" not in output and "main.py" not in output
    assert str(sample.root) not in output
    measured = json.loads(output)
    assert measured["measured_command_seconds"] == 122
    assert measured["artifacts_valid"] is True and measured["cleanup_pending"] is False


def test_failed_console_measurement_cannot_leak_private_exception_text(sample, monkeypatch, capsys):
    monkeypatch.setattr(latency, "build_index", lambda *a, **k: (_ for _ in ()).throw(AccessDenied("SYNTHETIC_PRIVATE_ERROR_DETAILS")))
    assert latency.main([str(sample.path), "--workspace-data-dir", str(sample.root.parent / "state"),
                         "--output-dir", str(sample.output), "--report", str(sample.report)]) == 1
    output = capsys.readouterr().out
    assert '"status": "not_evaluable"' in output and '"formal_passed": false' in output
    assert "SYNTHETIC_PRIVATE_ERROR_DETAILS" not in output
