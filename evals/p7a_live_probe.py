"""Compare the two review-merge modes on the fixed synthetic P7A projects."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tempfile
import time
from unittest.mock import patch

from codesentry.cli.main import main as cli
from codesentry.conversation.context import MAX_SOURCES, source_lines
from codesentry.semantic import service
from codesentry.semantic.credentials import load_deepseek_credentials
from codesentry.semantic.output import provider_usage
from codesentry.semantic.transport import DeepSeekTransport, SemanticTransportError
from codesentry.workspaces.store import WorkspaceStore


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evals/datasets/p7a_fresh_projects_v1.json"
CANDIDATE = ("codesentry/review/batch_review.py", "codesentry/review/review_merge.py",
             "codesentry/cli/main.py", "codesentry/semantic/service.py")
MODEL = "deepseek-flash"
MODES = ("observations", "source")
STOP_REASONS = {"http_401", "http_403", "http_429", "provider_unauthorized"}


def _cli(arguments):
    with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()):
        status = cli(arguments)
    output = stdout.getvalue()
    if not output:
        raise RuntimeError(f"CLI returned {status} without a report")
    return json.loads(output)


class _ProbeTransport:
    def __init__(self, files, question):
        self.transport = DeepSeekTransport()
        self.question = question
        self.numbered_sources = {
            name: "".join(f"{line} | {text}" for line, text in enumerate(source_lines(source), 1))
            for name, source in files.items()
        }
        self.phase = "batch"
        self.calls = []

    def send(self, body, **kwargs):
        request = json.loads(body)
        payload = json.loads(request["messages"][-1]["content"])
        batch = self.phase == "batch"
        expected = {"question", "sources", "required_ids"} if batch else {"question", "observations"}
        if request["model"] != MODEL or payload.get("question") != self.question or set(payload) != expected:
            raise ValueError("Unexpected outbound request for the fixed probe")
        rows = payload["sources"] if batch else payload["observations"]
        source_ids = []
        for row in rows:
            path = row["path"]
            if path not in self.numbered_sources:
                raise ValueError("Unexpected outbound path")
            if "source" in row:
                if self.phase == "observations" or row["source"] != self.numbered_sources[path]:
                    raise ValueError("Unexpected outbound source")
                source_ids.append(row["id"])
        call = {"phase": self.phase, "source_range_ids": source_ids, "range_count": len(rows)}
        self.calls.append(call)
        started = time.perf_counter()
        try:
            response = self.transport.send(body, **kwargs)
        except SemanticTransportError as error:
            call["status"] = error.code
            raise
        else:
            call.update(status=response.status, usage=provider_usage(response.body))
            return response
        finally:
            call["seconds"] = round(time.perf_counter() - started, 3)


def _run_project(project, scratch, credentials, results):
    root = scratch / project["id"]
    target, data = root / "source", root / "state"
    target.mkdir(parents=True)
    files = project["files"]
    for name, source in files.items():
        if Path(name).name != name or not name.endswith(".py"):
            raise ValueError("The fixed fixture must use flat Python files")
        (target / name).write_bytes(source.encode())
    workspace = WorkspaceStore(data).create_workspace(
        str(target), access_policy={"confirmed": True, "settings": {"model_scope": list(files)}})
    semantic = service.SemanticService(data, configured_api_key=credentials.api_key,
                                       configured_key_source=credentials.source)
    try:
        profile = semantic.read_profile(workspace["id"])
        semantic.update_profile(workspace["id"], {"enabled": True, "model": MODEL},
                                expected_revision=profile["revision"])
    finally:
        semantic.close()
    common = [str(target), "--workspace-data-dir", str(data)]
    plan = _cli(["review-plan", *common, "--json"])
    if plan["plan_status"] != "ready" or plan["summary"]["planned_ranges"] != len(files):
        raise ValueError("Fixture plan differs from the registered one-range-per-file scope")
    for case in project["cases"]:
        modes = MODES if len(results) % 2 == 0 else MODES[::-1]
        started = time.perf_counter()
        meter = _ProbeTransport(files, case["question"])
        scope = [*common, "--approve-plan", plan["plan_sha256"], "--model", MODEL, "--question", case["question"]]
        batches = (len(files) + MAX_SOURCES - 1) // MAX_SOURCES
        summaries = {mode: {"status": "batch_incomplete"} for mode in modes}
        with patch.object(service, "DeepSeekTransport", return_value=meter):
            report = _cli(["review-run", *scope, "--max-batches", str(batches)])
            if report["review_status"] == "model_scope_complete":
                report_path = root / "batch.json"
                report_path.write_text(json.dumps(report), encoding="utf-8")
                for mode in modes:
                    meter.phase = mode
                    flags = ["--summary-source-evidence"] if mode == "source" else []
                    merged = _cli(["review-merge", *scope, "--report", str(report_path),
                                   "--summary-requests", "1", *flags])
                    summaries[mode] = merged.get("summary", {"status": merged["review_status"]})
        results.append({"id": case["id"], "project": project["id"], "batch_status": report["review_status"],
                        "batch_ranges": report.get("ranges", []), "summaries": summaries,
                        "requests": meter.calls, "seconds": round(time.perf_counter() - started, 3)})
        print(case["id"], report["review_status"], *(summaries[mode]["status"] for mode in MODES), flush=True)
        if any(call["status"] in STOP_REASONS for call in meter.calls):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raw = DATASET.read_bytes()
    dataset = json.loads(raw)
    candidate = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in CANDIDATE}
    # Match the local workbench startup without exposing the credential in arguments or output.
    os.environ.pop("DEEPSEEK_API_KEY", None)
    credentials = load_deepseek_credentials()
    if not credentials.api_key or credentials.source != "env_file":
        raise SystemExit("Configure the CodeSentry workbench .env before the synthetic probe")
    results = []
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        with tempfile.TemporaryDirectory(prefix="codesentry-p7a-") as directory:
            for project in dataset["projects"]:
                if not _run_project(project, Path(directory), credentials, results):
                    break
        if candidate != {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in CANDIDATE}:
            raise RuntimeError("Candidate changed during evaluation")
        json.dump({"schema_version": 1, "dataset_id": dataset["dataset_id"], "synthetic_only": True,
                   "dataset_sha256": sha256(raw).hexdigest(), "candidate_sha256": candidate,
                   "model": MODEL, "results": results}, output, indent=2, ensure_ascii=False)
        output.write("\n")


if __name__ == "__main__":
    main()
