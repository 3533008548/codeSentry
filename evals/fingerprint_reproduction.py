"""Hash-check a fixed dev reproduction fixture without importing its target.

Only the two source-only variant directories are candidate inputs. The plan,
provenance and unadjudicated data card stay outside those directories. Running
the target or driver is reserved for the separately controlled Docker adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from codesentry.access.policy import is_link


FIXTURE = Path(__file__).parent / "fixtures" / "fingerprint_reproduction_v1"
FROZEN_SHA256 = {
    "before/behavior_driver.py": "6042bf33c6e521ed88d7c19c3eb85b7c9f1dec27e77cacee80c9054a93c53673",
    "before/fingerprint.py": "b524329828545334e69ed645eac016917acc951c73d228e06f48dbbe6d15a989",
    "data_card.json": "945d143b7f888c60dca90c1472188483b8663dd2c02dc67f25979d4a84880882",
    "descriptor.json": "96f1b3e6623ea1c4255447ae59a224451930d5825b55d4ed9d55339a3fc2266c",
    "fix_candidate/behavior_driver.py": "6042bf33c6e521ed88d7c19c3eb85b7c9f1dec27e77cacee80c9054a93c53673",
    "fix_candidate/fingerprint.py": "45a062a05ab3e904cff0fe9bc80bafdac8fb7f9c3cbb5f109dc85d47b5f55638",
    "plan.json": "0f19c918b9b52e6c925a9d26abdcfebf5f1cc6127b047d7ecaf2653aabe05b41",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _checked_metadata(path: Path, *, directory: bool = False):
    root = Path(os.path.abspath(FIXTURE))
    target = Path(os.path.abspath(path))
    _require(target.is_relative_to(root), "fixture path leaves the fixed root")
    for ancestor in reversed(target.parents):
        _require(not is_link(ancestor) and stat.S_ISDIR(ancestor.lstat().st_mode),
                 "fixture ancestor cannot be a link or reparse point")
    _require(not is_link(target), "fixture path cannot be a link or reparse point")
    metadata = target.lstat()
    _require(stat.S_ISDIR(metadata.st_mode) if directory else
             stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
             "fixture files must be regular files with one hard link")
    return metadata


def _read_checked(path: Path) -> bytes:
    before = _checked_metadata(path)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                 and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                 "fixture opened file identity changed")
        raw = stream.read(64 * 1024 + 1)
    after = _checked_metadata(path)
    _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "fixture file identity changed")
    return raw


def load_fixture() -> dict:
    """Return a fresh descriptor after checking the frozen local fixture bytes.

    This establishes neither current production state nor label truth. It does
    not execute source, contact Git, or reinterpret a recorded commit as approval.
    """
    contents = {}
    for relative, expected in FROZEN_SHA256.items():
        path = FIXTURE / relative
        raw = _read_checked(path)
        _require(len(raw) <= 64 * 1024 and hashlib.sha256(raw).hexdigest() == expected,
                 "frozen reproduction fixture changed")
        contents[relative] = raw
    descriptor = json.loads(contents["descriptor.json"])
    _require(descriptor["schema_version"] == 1 and descriptor["reproduction_id"] == "fingerprint-reproduction-v1",
             "unexpected reproduction descriptor")
    _require(descriptor["plan"] == {"path": "plan.json", "sha256": FROZEN_SHA256["plan.json"]}, "plan binding mismatch")
    _require(descriptor["data_card"] == {"path": "data_card.json", "sha256": FROZEN_SHA256["data_card.json"]},
             "data card binding mismatch")
    _require(descriptor["source_roots"] == {"before": "before", "fix_candidate": "fix_candidate"}, "unexpected source roots")
    for variant in ("before", "fix_candidate"):
        folder = FIXTURE / variant
        _checked_metadata(folder, directory=True)
        _require({path.name for path in folder.iterdir()}
                 == {"fingerprint.py", "behavior_driver.py"}, "candidate snapshot must contain only module and driver")
        _checked_metadata(folder, directory=True)
        expected_files = [{"path": name, "sha256": FROZEN_SHA256[f"{variant}/{name}"]}
                          for name in ("fingerprint.py", "behavior_driver.py")]
        _require(descriptor["variant_files"][variant] == expected_files, "source file binding mismatch")
    return descriptor


def load_plan() -> dict:
    """Read the trusted expected-output plan only after fixture validation."""
    load_fixture()
    raw = _read_checked(FIXTURE / "plan.json")
    _require(len(raw) <= 64 * 1024 and hashlib.sha256(raw).hexdigest() == FROZEN_SHA256["plan.json"],
             "frozen reproduction plan changed")
    return json.loads(raw)
