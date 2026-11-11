"""Container-only observations; expected answers are outside this snapshot."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


def load_target():
    module_path = Path(__file__).with_name("fingerprint.py")
    spec = importlib.util.spec_from_file_location("fingerprint_target", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("target module unavailable")
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)
    return target


def observe(case_id: str, target) -> bool:
    if case_id == "after_line_12_changes_fingerprint":
        prefix = "".join(f"field_{index:02d} = {index}\n" for index in range(1, 13))
        left, right = prefix + "result = 1\n", prefix + "result = 2\n"
        return target.compute_fingerprint("repro.rule", "sample.py::sample", left) != target.compute_fingerprint("repro.rule", "sample.py::sample", right)
    if case_id == "string_internal_whitespace_changes_fingerprint":
        left, right = 'value = "two  words"\n', 'value = "two words"\n'
        return target.compute_fingerprint("repro.rule", "sample.py::sample", left) != target.compute_fingerprint("repro.rule", "sample.py::sample", right)
    if case_id == "identical_snippet_is_stable":
        snippet = "def sample():\n    return 1\n"
        return target.compute_fingerprint("repro.rule", "sample.py::sample", snippet) == target.compute_fingerprint("repro.rule", "sample.py::sample", snippet)
    raise ValueError("unknown observation case")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    actual = observe(sys.argv[1], load_target())
    print(json.dumps({"case_id": sys.argv[1], "actual": actual}, sort_keys=True, separators=(",", ":")))
