"""Replay one fixed development batch without mounting its answers in Docker."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tempfile

from codesentry.access import AccessPolicy
from codesentry.execution import commands, runner, snapshot
from evals import sealed_registry


ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "evals/reports/p6_finally_return_registration_20261110.json"
ORIGINAL_SHA256 = "4832214c51b733cb04e72296e53c08f525bdc3d52546790307e300923b5a7c24"
CANDIDATE = "evals/finally_return_candidate.py"
DATASET = "evals/datasets/p6_finally_return_dev_v1.json"
IMAGES = {
    "3.11": "sha256:3c35dbe0205e9428cdd671c078cc6c824fc20c86591646eb91c0cdc6c86fb8bd",
    "3.14": "sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c",
}
LIMITS = runner.ResourceLimits(256 * 1024 * 1024, 1, 32, 20, 16 * 1024, 8 * 1024 * 1024)

PREDICT_SOURCE = '''import ast
import importlib.util
import json
from pathlib import Path
import sys
import warnings

def compiler(source):
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        try:
            tree = ast.parse(source, filename="<synthetic>")
            compile(tree, "<synthetic>", "exec", dont_inherit=True)
        except SyntaxError:
            return {"status": "invalid_source", "lines": []}
    lines = {item.lineno for item in observed if item.category is SyntaxWarning
             and str(item.message) == "'return' in a 'finally' block"}
    return {"status": "checked", "lines": sorted(lines)}

mode, = sys.argv[1:]
if mode == "candidate":
    spec = importlib.util.spec_from_file_location("candidate", "/work/candidate.py")
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    predict = candidate.detect
elif mode == "compiler":
    predict = compiler
else:
    raise ValueError("unexpected prediction mode")

assert sorted(path.name for path in Path("/input").iterdir()) == ["boundary.py", "candidate.py", "input.txt", "predict.py"]
inputs = json.loads(Path("/input/input.txt").read_bytes())
assert all(set(item) == {"id", "source"} for item in inputs)
print(json.dumps({"version": list(sys.version_info[:3]),
    "rows": [{"id": item["id"], **predict(item["source"])} for item in inputs]}, sort_keys=True))
'''


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _inputs():
    original = ORIGINAL.read_bytes()
    if _hash(original) != ORIGINAL_SHA256:
        raise ValueError("original development registration was changed")
    registered = json.loads(original)
    if registered["partition"] != "dev" or (registered["rule_id"], registered["rule_version"]) != ("python.finally_return", "1"):
        raise ValueError("expected the frozen development candidate")
    for name, digest in registered["sha256"].items():
        if _hash((ROOT / name).read_bytes()) != digest:
            raise ValueError("original development registration no longer matches")
    dataset = json.loads((ROOT / DATASET).read_bytes())
    cases = dataset["cases"]
    if dataset["partition"] != "dev" or [case["id"] for case in cases] != registered["case_ids"]:
        raise ValueError("development cases changed")
    files = {
        "boundary.py": commands.BOUNDARY_SOURCE.encode(), "predict.py": PREDICT_SOURCE.encode(),
        "candidate.py": (ROOT / CANDIDATE).read_bytes(),
        "input.txt": json.dumps([{key: case[key] for key in ("id", "source")} for case in cases]).encode(),
    }
    binding = {"schema_version": 1, "partition": "dev", "registration_sha256": _hash(original),
        "dataset_id": dataset["dataset_id"], "dataset_sha256": registered["sha256"][DATASET],
        "images": IMAGES, "platform": "linux/amd64", "limits": asdict(LIMITS),
        "snapshot_files": {name: _hash(raw) for name, raw in files.items()},
        "host_tools": {module.__name__: _hash(Path(module.__file__).read_bytes())
                       for module in (commands, runner, snapshot, sealed_registry)} | {"scorer": _hash(Path(__file__).read_bytes())},
        "comparison": "Exact return span, owning try line and case status for contract; paired warning line sets per valid case.",
        "formal_acceptance": False}
    return binding, cases, files


def _predictions(result, version, cases, field):
    if (not result.executed or result.exit_code != 0 or result.cleanup_pending or result.log_truncated
            or result.status != "not_verified" or result.image_id != IMAGES[version]
            or (result.platform, result.architecture) != ("linux", "amd64")
            or _hash(result.logs.encode()) != result.output_sha256):
        raise ValueError("missing complete prediction output or execution evidence")
    decoded = json.loads(result.logs)
    if decoded["version"][:2] != list(map(int, version.split("."))):
        raise ValueError("runtime version does not match the preregistration")
    rows = decoded["rows"]
    if [row["id"] for row in rows] != [case["id"] for case in cases]:
        raise ValueError("incomplete or reordered prediction rows")
    for row in rows:
        if set(row) != {"id", "status", field} or row["status"] not in {"checked", "invalid_source", "source_limit"}:
            raise ValueError("unexpected prediction fields")
        if not isinstance(row[field], list) or (row["status"] != "checked" and row[field]):
            raise ValueError("invalid prediction positions")
        for hit in row[field]:
            positions = [hit] if field == "lines" else hit
            if (not isinstance(positions, list) or len(positions) != (1 if field == "lines" else 3)
                    or any(type(line) is not int or line < 1 for line in positions)):
                raise ValueError("invalid prediction line number")
    return decoded


def _score(cases, candidate, compiler):
    counts = Counter(matched=0, missed=0, unexpected=0, status_mismatches=0, compiler_status_mismatches=0,
                     valid_cases=0, invalid_cases=0, overlap=0, candidate_only=0, compiler_only=0)
    for case, proposed, native in zip(cases, candidate["rows"], compiler["rows"], strict=True):
        expected = Counter(tuple(hit) for hit in case["expected_hits"])
        actual = Counter(tuple(hit) for hit in proposed["hits"])
        counts.update(matched=sum((expected & actual).values()), missed=sum((expected - actual).values()),
                      unexpected=sum((actual - expected).values()),
                      status_mismatches=int(proposed["status"] != case["expected_status"]),
                      compiler_status_mismatches=int(native["status"] != case["expected_status"]))
        if case["expected_status"] != "checked":
            counts["invalid_cases"] += 1
            continue
        candidate_lines = {hit[0] for hit in actual}
        compiler_lines = set(native["lines"])
        counts.update(valid_cases=1, overlap=len(candidate_lines & compiler_lines),
                      candidate_only=len(candidate_lines - compiler_lines), compiler_only=len(compiler_lines - candidate_lines))
    return dict(counts)


def _write_new(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def replay(registration, output, ledger_path):
    frozen = registration.read_bytes()
    binding, cases, files = _inputs()
    if json.loads(frozen) != binding:
        raise ValueError("isolation registration no longer matches")
    if output.exists() or ledger_path.exists() or output.resolve() == ledger_path.resolve():
        raise ValueError("distinct new output and ledger paths are required")
    expected = (json.dumps(dict.fromkeys(commands.BOUNDARY_KEYS, True), sort_keys=True) + "\n").encode()
    versions = {}
    with tempfile.TemporaryDirectory(prefix="codesentry-finally-dev-") as temporary:
        base = Path(temporary).resolve(strict=True)
        source = base / "source"
        source.mkdir()
        for name, raw in files.items():
            (source / name).write_bytes(raw)
        ledger = sealed_registry.SealedRegistry.create(base / "dev.sqlite3", operator_id="local-developer-replay")
        ledger.register_batch(sealed_registry.BatchSpec(
            "finally-return-isolated-dev", binding["dataset_id"], "1", ("tool-owned-synthetic-finally-v1",),
            ("python.finally_return",), "dev", binding["dataset_sha256"], binding["host_tools"]["scorer"], _hash(frozen)),
            event_id="dev-register")
        ledger.start_evaluation("finally-return-isolated-dev", "paired-python-run", "python.finally_return", "1",
                                binding["snapshot_files"]["candidate.py"], event_id="dev-start")
        with snapshot.prepare_snapshot(AccessPolicy(source, confirmed=True), base / "snapshot", paths=list(files),
                max_files=len(files), max_bytes=256 * 1024, max_file_bytes=128 * 1024) as exported:
            for version, image_id in IMAGES.items():
                backend = runner.DockerRunner(commands.default_executable(), endpoint=commands.default_endpoint(),
                    image_ref=f"docker.io/library/python@{image_id}", expected_image_id=image_id, limits=LIMITS)
                boundary = runner.ExecutionTask("boundary", "probe", ("/usr/local/bin/python", "-I", "/work/boundary.py"),
                                                expected_output_sha256=_hash(expected))
                probe = backend.run(boundary, exported.directory, exported.digest, snapshot_check=exported.check)
                record = versions[version] = {"boundary": probe.to_dict()}
                if probe.status != "passed" or probe.cleanup_pending or (probe.platform, probe.architecture) != ("linux", "amd64"):
                    continue
                try:
                    for mode, field in (("compiler", "lines"), ("candidate", "hits")):
                        task = runner.ExecutionTask(mode, "probe", ("/usr/local/bin/python", "-I", "/work/predict.py", mode))
                        result = backend.run(task, exported.directory, exported.digest, snapshot_check=exported.check)
                        record[f"{mode}_execution"] = result.to_dict() | {"logs": None}
                        record[mode] = _predictions(result, version, cases, field)
                    record["summary"] = _score(cases, record["candidate"], record["compiler"])
                except (KeyError, TypeError, ValueError) as error:
                    record["output_rejected"] = type(error).__name__
        if _inputs()[0] != binding or registration.read_bytes() != frozen:
            raise ValueError("frozen development inputs drifted")
        complete = all("summary" in record for record in versions.values())
        passed = complete and all(not any(record["summary"][name] for name in (
            "missed", "unexpected", "status_mismatches", "compiler_status_mismatches")) for record in versions.values())
        report = {"schema_version": 1, "partition": "dev", "registration_sha256": _hash(frozen),
                  "input_snapshot_sha256": exported.digest, "answers_mounted": False,
                  "independent_labels": False, "formal_acceptance": False,
                  "complete": complete, "contract_passed": passed, "versions": versions}
        _write_new(output, report)
        ledger.finish_evaluation("paired-python-run", "passed" if passed else "failed" if complete else "incomplete",
                                 _hash(output.read_bytes()), event_id="dev-finish")
        audit = ledger.inspect()
        _write_new(ledger_path, {key: audit[key] for key in ("registry_id", "chain_valid", "head_hash", "events",
            "operator_declaration_only", "holdout_evaluation_ready")})
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("register").add_argument("--output", type=Path, required=True)
    run = actions.add_parser("run")
    for name in ("registration", "output", "ledger"):
        run.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "register":
            _write_new(args.output, _inputs()[0])
            return 0
        report = replay(args.registration, args.output, args.ledger)
    except (KeyError, OSError, TypeError, ValueError) as error:
        parser.exit(2, f"isolated development run refused: {error}\n")
    print(json.dumps({version: data.get("summary") for version, data in report["versions"].items()}))
    return 0 if report["contract_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
