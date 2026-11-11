"""Local inventory and source ranges for a bounded review, without sending source."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.conversation.context import MAX_EXCERPT_BYTES, MAX_EXCERPT_LINES, source_lines
from codesentry.review.scan import PreviewLimits
from codesentry.workspaces.files import decode_source, supported_text


MAX_RANGES = 10_000


def _hash(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def _inventory(access, data_dir):
    def outside_state(relative):
        return data_dir is None or not (access.root / relative).is_relative_to(data_dir)

    permitted = {}
    outside = {"excluded_files_seen": 0, "excluded_directories_seen": 0, "unsupported_files": 0}
    for relative, path, directory, decision in access.walk(descend_filter=outside_state):
        mode = decision["mode"]
        if mode == "exclude" or not outside_state(relative):
            key = "excluded_directories_seen" if directory else "excluded_files_seen"
            outside[key] += 1
        elif not directory:
            if supported_text(path):
                permitted[relative] = mode
            else:
                outside["unsupported_files"] += 1
    return permitted, outside


def _ranges(lines):
    start, block = 1, bytearray()
    for number, line in enumerate(lines, 1):
        data = line.encode("utf-8")
        if block and (len(block) + len(data) > MAX_EXCERPT_BYTES or number - start == MAX_EXCERPT_LINES):
            yield {"start_line": start, "end_line": number - 1, "status": "planned",
                   "utf8_bytes": len(block), "text_sha256": _hash(block)}
            start, block = number, bytearray()
        if len(data) > MAX_EXCERPT_BYTES:
            yield {"start_line": number, "end_line": number, "status": "line_limit", "utf8_bytes": len(data)}
            start = number + 1
        else:
            block.extend(data)
    if block:
        yield {"start_line": start, "end_line": len(lines), "status": "planned",
               "utf8_bytes": len(block), "text_sha256": _hash(block)}


def build_coverage_plan(access: AccessPolicy, *, data_dir: Path | None = None, limits: PreviewLimits | None = None,
                        max_ranges: int = MAX_RANGES) -> dict:
    """Record planned ranges and gaps, then recheck the readable snapshot before publishing."""
    if not access.confirmed:
        raise AccessDenied("请先确认文件访问范围")
    if type(max_ranges) is not int or not 1 <= max_ranges <= MAX_RANGES:
        raise ValueError("行段预算超出上限")
    limits = PreviewLimits() if limits is None else limits
    if data_dir is not None:
        data_dir = data_dir.resolve()
        if data_dir == access.root:
            raise ValueError("工作空间数据目录不能作为审阅源码目录")
        if not data_dir.is_relative_to(access.root):
            data_dir = None
    access.refresh_if_changed()
    fingerprint = access.fingerprint

    def check_scope():
        access.refresh_if_changed()
        access.check_current()
        if access.fingerprint != fingerprint:
            raise AccessDenied("访问范围已变化，请重新生成审阅计划")

    permitted, outside = _inventory(access, data_dir)
    paths = sorted(permitted)
    rows, snapshots = [], {}
    remaining_bytes, remaining_ranges = limits.max_total_bytes, max_ranges
    for path in paths[:limits.max_files]:
        row = {"path": path, "access_mode": permitted[path], "status": "unavailable", "ranges": []}
        rows.append(row)
        if not remaining_ranges:
            row["status"] = "range_limit"
            continue
        try:
            size = access.resolve(path).stat().st_size
            if size > limits.max_file_bytes:
                row["status"] = "file_byte_limit"
                continue
            reservation = max(1, size)
            if reservation > remaining_bytes:
                row["status"] = "total_byte_limit"
                continue
            remaining_bytes -= reservation
            raw = access.read_bytes(path, limit=reservation)
            remaining_bytes += reservation - len(raw)
        except AccessDenied:
            raise
        except (OSError, ValueError):
            continue
        digest = _hash(raw)
        snapshots[path] = (len(raw), digest)
        row.update(raw_bytes=len(raw), source_sha256=digest)
        try:
            text = decode_source(raw, Path(path))
            text.encode("utf-8")
        except ValueError:
            row["status"] = "unsupported_content"
            continue
        lines = source_lines(text)
        row.update(lines=len(lines), status="planned" if lines else "empty")
        for item in _ranges(lines):
            if not remaining_ranges:
                row["ranges"].append({"start_line": item["start_line"], "end_line": len(lines), "status": "range_limit"})
                row["status"] = "partial"
                break
            remaining_ranges -= 1
            row["ranges"].append(item)
            if item["status"] != "planned":
                row["status"] = "partial"

    check_scope()
    for row in rows:
        path = row["path"]
        if path not in snapshots:
            continue
        size, digest = snapshots[path]
        try:
            current = _hash(access.read_bytes(path, limit=max(1, size)))
        except AccessDenied:
            raise
        except (OSError, ValueError):
            current = None
        if current != digest:
            row.update(status="source_changed", ranges=[])
    latest, _ = _inventory(access, data_dir)
    check_scope()
    issues = sorted({item["status"] for item in access.to_dict()["issues"]})
    if latest != permitted:
        issues.append("inventory_changed")

    omitted = len(paths) - len(rows)
    planned = [span for row in rows for span in row["ranges"] if span["status"] == "planned"]
    planned_lines = sum(span["end_line"] - span["start_line"] + 1 for span in planned)
    unplanned_files = sum(row["status"] not in {"planned", "empty"} for row in rows) + omitted
    if not planned:
        issues.append("no_plannable_source")
    report = {"schema_version": 1, "mode": "local_review_plan", "review_status": "not_started",
              "plan_status": "ready" if not unplanned_files and not issues else "incomplete",
              "access_fingerprint": fingerprint,
              "limits": asdict(limits) | {"max_ranges": max_ranges, "max_lines_per_range": MAX_EXCERPT_LINES,
                                          "max_utf8_bytes_per_range": MAX_EXCERPT_BYTES},
              "summary": outside | {"eligible_local_files": len(paths), "files_omitted_by_limit": omitted,
                                    "unplanned_or_partial_files": unplanned_files, "planned_ranges": len(planned),
                                    "planned_lines": planned_lines,
                                    "model_candidate_files": sum(mode == "model_eligible" for mode in permitted.values())},
              "issues": issues, "files": rows}
    return report | {"plan_sha256": _hash(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())}
