"""Audit declared evaluation groups without reading source or running candidates.

This checks a trusted operator's manifest. It cannot discover undeclared copies,
establish label truth, or isolate holdout files from another operating-system user.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SCHEMA_VERSION = 1
MAX_BYTES = 8 * 1024 * 1024
MAX_SAMPLES = 10_000
SPLITS = frozenset({"train", "dev", "holdout"})
# These projects have already informed CodeSentry development. Renaming a
# repository_group cannot establish independence; grouping requires human review.
DEVELOPMENT_REPOSITORIES = frozenset({"research_agent", "knowledge_loop"})


def _text(value: object, field: str) -> str:
    if (not isinstance(value, str) or not value or value != value.strip() or len(value) > 512
            or any(ord(char) < 32 for char in value)):
        raise ValueError(f"Invalid {field}")
    return value


def _keys(value: object, keys: set[str], field: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"Invalid {field} fields")
    return value


def audit_splits(manifest: dict) -> dict:
    """Check transitive repository/family/derivation groups and feedback reuse.

    defect_family identifies a concrete related-defect lineage, not a broad
    category such as CWE. A missing lineage keeps the audit incomplete.
    """
    _keys(manifest, {"schema_version", "dataset_id", "samples"}, "manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Unsupported split schema")
    _text(manifest["dataset_id"], "dataset_id")
    samples = manifest["samples"]
    if not isinstance(samples, list) or len(samples) > MAX_SAMPLES:
        raise ValueError("Invalid sample collection")

    rows = {}
    for row in samples:
        _keys(row, {"id", "split", "repository_group", "defect_family",
                    "derived_from", "feedback_used"}, "sample")
        identity = _text(row["id"], "sample id")
        if identity in rows:
            raise ValueError("Duplicate sample id")
        if not isinstance(row["split"], str) or row["split"] not in SPLITS:
            raise ValueError("Invalid split")
        _text(row["repository_group"], "repository_group")
        if row["defect_family"] is not None:
            _text(row["defect_family"], "defect_family")
        relations = row["derived_from"]
        if (not isinstance(relations, list) or len(relations) > MAX_SAMPLES
                or any(not isinstance(item, str) for item in relations)):
            raise ValueError("Invalid derived_from")
        for relation in relations:
            _text(relation, "derived_from id")
        if len(set(relations)) != len(relations) or identity in relations:
            raise ValueError("Duplicate or self derivation")
        if type(row["feedback_used"]) is not bool:
            raise ValueError("feedback_used must be boolean")
        rows[identity] = row

    parent = {identity: identity for identity in rows}

    def find(identity):
        while parent[identity] != identity:
            parent[identity] = parent[parent[identity]]
            identity = parent[identity]
        return identity

    def join(left, right):
        left, right = find(left), find(right)
        if left != right:
            parent[max(left, right)] = min(left, right)

    issues = []
    repositories, families = {}, {}
    for identity, row in sorted(rows.items()):
        repository = row["repository_group"]
        if repository in repositories:
            join(identity, repositories[repository])
        else:
            repositories[repository] = identity
        family = row["defect_family"]
        if family is None:
            issues.append({"kind": "unknown_defect_family", "sample_ids": [identity]})
        elif family in families:
            join(identity, families[family])
        else:
            families[family] = identity
        for origin in row["derived_from"]:
            if origin not in rows:
                issues.append({"kind": "missing_derivation", "sample_ids": [identity, origin]})
            else:
                join(identity, origin)

    groups = {}
    for identity in sorted(rows):
        groups.setdefault(find(identity), []).append(identity)
    for identities in groups.values():
        splits = sorted({rows[identity]["split"] for identity in identities})
        if len(splits) > 1:
            issues.append({"kind": "cross_split_group", "sample_ids": identities, "splits": splits})
        holdout = [identity for identity in identities if rows[identity]["split"] == "holdout"]
        if holdout and any(rows[identity]["feedback_used"] for identity in identities):
            issues.append({"kind": "feedback_exposed_holdout", "sample_ids": identities})
        if holdout and any(rows[identity]["repository_group"] in DEVELOPMENT_REPOSITORIES
                           for identity in identities):
            issues.append({"kind": "development_project_in_holdout", "sample_ids": identities})
    if not rows:
        issues.append({"kind": "empty_dataset", "sample_ids": []})

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "review-split-audit",
        "dataset_id": manifest["dataset_id"],
        "manifest_sha256": hashlib.sha256(json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest(),
        "sample_count": len(rows),
        "group_count": len(groups),
        "split_counts": {split: sum(row["split"] == split for row in rows.values())
                         for split in sorted(SPLITS)},
        "split_assignment_valid": not issues,
        "issues": issues,
        "isolation_verified": False,
        "label_truth_verified": False,
        "formal_acceptance": {"passed": False},
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Audit trusted evaluation split metadata only")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        with args.manifest.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Manifest exceeds limit")
        report = audit_splits(json.loads(raw, object_pairs_hook=_unique_object))
        # Exclusive creation also prevents accidentally replacing the manifest.
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print(json.dumps({key: report[key] for key in (
            "sample_count", "group_count", "split_assignment_valid", "isolation_verified"
        )}))
        return 0 if report["split_assignment_valid"] else 1
    except (ValueError, TypeError, KeyError, OSError):
        print("Split audit unavailable: invalid input or output; no acceptance granted")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
