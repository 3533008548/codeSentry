"""Reproduction attribution must not mistake generic execution failure for a bug."""
from copy import deepcopy
import hashlib
import json

import pytest

from evals import fingerprint_verification as reproduction


def verified_variants():
    ids = ["after_line_12_changes_fingerprint", "string_internal_whitespace_changes_fingerprint",
           "identical_snippet_is_stable"]
    variants = {}
    for variant in ("before", "fix_candidate"):
        cases = []
        for index, identity in enumerate(ids):
            value = variant != "before" or index == 2
            raw = (json.dumps({"case_id": identity, "actual": value}, sort_keys=True,
                              separators=(",", ":")) + "\n").encode()
            cases.append({"case_id": identity, "status": "passed" if value else "failed",
                "execution": {"exit_code": 0, "status": "not_verified", "architecture": "amd64",
                              "output_sha256": hashlib.sha256(raw).hexdigest()}})
        variants[variant] = {"verification": {"status": "failed" if variant == "before" else "passed",
            "plan_digest": "a" * 64, "image_reference": reproduction.IMAGE_REFERENCE,
            "image_id": reproduction.IMAGE_ID, "limits": {}, "evidence_valid": True,
            "cleanup_pending": False, "planned_cases": 3, "executed_cases": 3,
            "completed_cases": 3, "host_behavior_checks_evaluated": 6, "cases": cases}}
    return variants


def test_fixed_legacy_false_observations_and_same_success_plan_are_reproduced():
    assert reproduction._comparison_valid(verified_variants())


@pytest.mark.parametrize("field,value", [("plan_digest", "b" * 64), ("image_id", "sha256:" + "b" * 64),
    ("limits", {"different": True}), ("evidence_valid", False), ("cleanup_pending", True),
    ("completed_cases", 2), ("host_behavior_checks_evaluated", 5)])
def test_different_environment_or_incomplete_checks_do_not_reproduce(field, value):
    variants = verified_variants()
    variants["fix_candidate"]["verification"][field] = value
    assert not reproduction._comparison_valid(variants)


@pytest.mark.parametrize("tamper", ["warning", "crash", "missing_digest", "wrong_arch"])
def test_arbitrary_before_failure_is_not_fingerprint_collision_evidence(tamper):
    variants = verified_variants()
    execution = variants["before"]["verification"]["cases"][0]["execution"]
    if tamper == "warning":
        execution["output_sha256"] = hashlib.sha256(b"warning: unrelated\n").hexdigest()
    elif tamper == "crash":
        execution["exit_code"], execution["status"] = 3, "failed"
    elif tamper == "missing_digest":
        execution["output_sha256"] = None
    else:
        execution["architecture"] = "arm64"
    assert not reproduction._comparison_valid(variants)


def test_original_code_already_passing_would_not_prove_the_specific_reproduction():
    variants = verified_variants()
    variants["before"] = deepcopy(variants["fix_candidate"])
    assert not reproduction._comparison_valid(variants)


def test_cli_refuses_overwrite_before_execution(tmp_path, monkeypatch, capsys):
    output = tmp_path / "report.json"
    output.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(reproduction, "reproduce", lambda **kwargs: pytest.fail("refused run executed"))
    assert reproduction.main(["--output", str(output)]) == 2
    assert output.read_text(encoding="utf-8") == "keep"
    assert json.loads(capsys.readouterr().out)["comparison_verified"] is False


def test_runtime_image_override_cannot_widen_fixed_policy(tmp_path):
    with pytest.raises(ValueError):
        reproduction.reproduce(executable=tmp_path / "docker", endpoint="unix:///var/run/docker.sock",
                               image_reference="python:latest")
