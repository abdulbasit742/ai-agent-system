#!/usr/bin/env python3
"""Atomic audit-log segment rotation and offline continuity verification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import agent_system
from agent_audit import (
    AUDIT_VERSION,
    ZERO_HASH,
    _canonical_line,
    _exclusive_lock,
    _record_hash,
    _validate_record,
)
from agent_audit_events import EVENT_SCHEMA_VERSION, SCHEMA_FIELD, prepare_event

SEGMENT_VERSION = 1
SEGMENT_FILE = "segment.jsonl"
MANIFEST_FILE = "manifest.json"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_FIELDS = {
    "manifest_version",
    "segment_index",
    "previous_segment_id",
    "file",
    "records",
    "typed_records",
    "untyped_records",
    "privacy_safe",
    "bytes",
    "head_hash",
    "sha256",
    "event_schema_version",
    "segment_id",
}
START_FIELDS = {
    SCHEMA_FIELD,
    "segment_index",
    "previous_segment_id",
    "previous_segment_sha256",
    "previous_head_hash",
    "previous_records",
    "previous_bytes",
}


class AuditSegmentError(ValueError):
    """Raised when segment rotation or verification cannot proceed safely."""

    def __init__(self, message: str, *, rule_id: str = "AUS003") -> None:
        super().__init__(message)
        self.rule_id = rule_id


class _DuplicateKeyError(ValueError):
    pass


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _segment_id(core: dict[str, Any]) -> str:
    encoded = json.dumps(
        core,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"audit-segment-manifest-v1\0" + encoded).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _non_negative(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < int(positive):
        qualifier = "positive" if positive else "non-negative"
        raise AuditSegmentError(f"{label} must be a {qualifier} integer")
    return value


def _lower_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditSegmentError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_file(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise AuditSegmentError("segment output produced a partial write", rule_id="AUS001")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise AuditSegmentError("segment manifest must be a regular non-symlink file", rule_id="AUS001")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, _DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
        raise AuditSegmentError(f"segment manifest is not strict JSON: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != MANIFEST_FIELDS:
        raise AuditSegmentError("segment manifest fields do not match the reviewed schema")
    if raw != _canonical_json(payload):
        raise AuditSegmentError("segment manifest is not canonically serialized")
    if payload["manifest_version"] != SEGMENT_VERSION:
        raise AuditSegmentError(f"segment manifest version must be {SEGMENT_VERSION}")
    if payload["file"] != SEGMENT_FILE:
        raise AuditSegmentError(f"segment manifest file must be {SEGMENT_FILE}")
    _non_negative(payload["segment_index"], "segment_index", positive=True)
    _lower_hash(payload["previous_segment_id"], "previous_segment_id")
    _non_negative(payload["records"], "records", positive=True)
    _non_negative(payload["typed_records"], "typed_records")
    _non_negative(payload["untyped_records"], "untyped_records")
    if not isinstance(payload["privacy_safe"], bool):
        raise AuditSegmentError("privacy_safe must be a boolean")
    _non_negative(payload["bytes"], "bytes", positive=True)
    _lower_hash(payload["head_hash"], "head_hash")
    _lower_hash(payload["sha256"], "sha256")
    if payload["event_schema_version"] != EVENT_SCHEMA_VERSION:
        raise AuditSegmentError("segment event schema version is unsupported")
    stored_id = _lower_hash(payload["segment_id"], "segment_id")
    core = dict(payload)
    core.pop("segment_id")
    if stored_id != _segment_id(core):
        raise AuditSegmentError("segment manifest ID does not match its canonical payload")
    return payload, raw


def _first_record(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        raw_line = handle.readline()
    if not raw_line:
        raise AuditSegmentError("audit log is empty", rule_id="AUS008")
    try:
        record = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise AuditSegmentError("audit log first record is not JSON", rule_id="AUS002") from exc
    if not isinstance(record, dict):
        raise AuditSegmentError("audit log first record must be an object", rule_id="AUS002")
    return record


def _validate_start_details(details: Any) -> dict[str, Any]:
    if not isinstance(details, dict) or set(details) != START_FIELDS:
        raise AuditSegmentError("audit segment start fields do not match the reviewed schema", rule_id="AUS005")
    if details[SCHEMA_FIELD] != EVENT_SCHEMA_VERSION:
        raise AuditSegmentError("audit segment start event schema is unsupported", rule_id="AUS005")
    output = {
        SCHEMA_FIELD: EVENT_SCHEMA_VERSION,
        "segment_index": _non_negative(details["segment_index"], "segment_index", positive=True),
        "previous_segment_id": _lower_hash(details["previous_segment_id"], "previous_segment_id"),
        "previous_segment_sha256": _lower_hash(
            details["previous_segment_sha256"], "previous_segment_sha256"
        ),
        "previous_head_hash": _lower_hash(details["previous_head_hash"], "previous_head_hash"),
        "previous_records": _non_negative(details["previous_records"], "previous_records", positive=True),
        "previous_bytes": _non_negative(details["previous_bytes"], "previous_bytes", positive=True),
    }
    if output != details:
        raise AuditSegmentError("audit segment start details are not canonical", rule_id="AUS005")
    return output


def _start_link(path: Path) -> dict[str, Any] | None:
    first = _first_record(path)
    if first.get("event") != "audit-segment-start":
        return None
    return _validate_start_details(first.get("details"))


def _new_active_bytes(manifest: dict[str, Any]) -> bytes:
    raw_details = {
        "segment_index": manifest["segment_index"],
        "previous_segment_id": manifest["segment_id"],
        "previous_segment_sha256": manifest["sha256"],
        "previous_head_hash": manifest["head_hash"],
        "previous_records": manifest["records"],
        "previous_bytes": manifest["bytes"],
    }
    event, details = prepare_event("audit-segment-start", raw_details)
    _validate_start_details(details)
    core = {
        "audit_version": AUDIT_VERSION,
        "sequence": 1,
        "time": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "event": event,
        "details": details,
        "previous_hash": ZERO_HASH,
    }
    record = {**core, "hash": _record_hash(ZERO_HASH, core)}
    _validate_record(record, line_number=1, previous_hash=ZERO_HASH)
    return _canonical_line(record)


def inspect_segment_directory(directory: Path) -> dict[str, Any]:
    """Verify one immutable segment directory independently."""
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise AuditSegmentError("segment directory must be a regular non-symlink directory", rule_id="AUS001")
    manifest, _ = _load_manifest(directory / MANIFEST_FILE)
    segment = directory / SEGMENT_FILE
    if segment.is_symlink() or not segment.is_file():
        raise AuditSegmentError("segment data must be a regular non-symlink file", rule_id="AUS001")
    raw = segment.read_bytes()
    if len(raw) != manifest["bytes"] or _sha256(raw) != manifest["sha256"]:
        raise AuditSegmentError("segment bytes do not match the manifest", rule_id="AUS004")
    report = agent_system.inspect_audit(segment, require_typed=True)
    if not report["valid"]:
        error = report.get("error") or {}
        raise AuditSegmentError(
            f"segment audit validation failed: {error.get('rule_id', 'unknown')} {error.get('message', '')}",
            rule_id="AUS004",
        )
    comparisons = {
        "records": report["records"],
        "typed_records": report["typed_records"],
        "untyped_records": report["untyped_records"],
        "privacy_safe": report["privacy_safe"],
        "head_hash": report["head_hash"],
        "event_schema_version": report["event_schema_version"],
    }
    for key, actual in comparisons.items():
        if manifest[key] != actual:
            raise AuditSegmentError(f"segment {key} does not match the manifest", rule_id="AUS004")
    return {
        "directory": str(directory),
        "segment_id": manifest["segment_id"],
        "segment_index": manifest["segment_index"],
        "previous_segment_id": manifest["previous_segment_id"],
        "sha256": manifest["sha256"],
        "head_hash": manifest["head_hash"],
        "records": manifest["records"],
        "bytes": manifest["bytes"],
        "manifest": manifest,
    }


def _verify_link_to_previous(current: dict[str, Any], previous: dict[str, Any]) -> None:
    if current["previous_segment_id"] != previous["segment_id"]:
        raise AuditSegmentError("segment manifest continuity ID does not match", rule_id="AUS005")
    segment_path = Path(current["directory"]) / SEGMENT_FILE
    link = _start_link(segment_path)
    if link is None:
        raise AuditSegmentError("non-initial segment does not begin with a continuity record", rule_id="AUS005")
    expected = {
        SCHEMA_FIELD: EVENT_SCHEMA_VERSION,
        "segment_index": previous["segment_index"],
        "previous_segment_id": previous["segment_id"],
        "previous_segment_sha256": previous["sha256"],
        "previous_head_hash": previous["head_hash"],
        "previous_records": previous["records"],
        "previous_bytes": previous["bytes"],
    }
    if link != expected:
        raise AuditSegmentError("segment continuity record does not match the previous manifest", rule_id="AUS005")


def verify_segment_chain(
    directories: list[Path],
    *,
    active_path: Path | None = None,
    expected_latest_segment_id: str | None = None,
) -> dict[str, Any]:
    """Verify a complete ordered segment chain and optional active log."""
    if not directories:
        raise AuditSegmentError("at least one segment directory is required")
    segments = [inspect_segment_directory(Path(directory)) for directory in directories]
    for position, segment in enumerate(segments, 1):
        if segment["segment_index"] != position:
            raise AuditSegmentError("segment indexes must form a complete sequence from one", rule_id="AUS005")
        if position == 1:
            if segment["previous_segment_id"] != ZERO_HASH:
                raise AuditSegmentError("first segment must use the zero previous segment ID", rule_id="AUS005")
        else:
            _verify_link_to_previous(segment, segments[position - 2])
    latest = segments[-1]
    if expected_latest_segment_id is not None:
        expected = _lower_hash(expected_latest_segment_id.lower(), "expected_latest_segment_id")
        if latest["segment_id"] != expected:
            raise AuditSegmentError("latest segment ID differs from the externally retained pin", rule_id="AUS007")
    active_summary = None
    if active_path is not None:
        active = Path(active_path)
        report = agent_system.inspect_audit(active, require_typed=True)
        if not report["valid"]:
            raise AuditSegmentError("active audit log is invalid or not fully typed", rule_id="AUS006")
        link = _start_link(active)
        expected_link = {
            SCHEMA_FIELD: EVENT_SCHEMA_VERSION,
            "segment_index": latest["segment_index"],
            "previous_segment_id": latest["segment_id"],
            "previous_segment_sha256": latest["sha256"],
            "previous_head_hash": latest["head_hash"],
            "previous_records": latest["records"],
            "previous_bytes": latest["bytes"],
        }
        if link != expected_link:
            raise AuditSegmentError("active log does not continue from the latest segment", rule_id="AUS006")
        active_summary = {
            "path": str(active),
            "records": report["records"],
            "head_hash": report["head_hash"],
            "typed_records": report["typed_records"],
            "privacy_safe": report["privacy_safe"],
        }
    return {
        "report_version": 1,
        "valid": True,
        "segments": [{key: value for key, value in segment.items() if key != "manifest"} for segment in segments],
        "segment_count": len(segments),
        "total_records": sum(segment["records"] for segment in segments),
        "total_bytes": sum(segment["bytes"] for segment in segments),
        "latest_segment_id": latest["segment_id"],
        "expected_latest_segment_id": expected_latest_segment_id.lower() if expected_latest_segment_id else None,
        "active": active_summary,
    }


def rotate_audit(
    path: Path,
    output_dir: Path,
    *,
    expected_head: str | None = None,
    expected_records: int | None = None,
) -> dict[str, Any]:
    """Seal the current typed log and atomically replace it with a linked active log."""
    path = Path(path)
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or output_dir.exists():
        raise AuditSegmentError("rotation output directory must not already exist", rule_id="AUS001")
    if path.absolute() == output_dir.absolute() or path.parent.absolute() == output_dir.absolute():
        raise AuditSegmentError("rotation output directory must not replace or contain the active log", rule_id="AUS001")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with _exclusive_lock(lock_path):
        report = agent_system.inspect_audit(
            path,
            expected_head=expected_head,
            expected_records=expected_records,
            require_typed=True,
        )
        if not report["valid"]:
            error = report.get("error") or {}
            raise AuditSegmentError(
                f"source audit log is invalid: {error.get('rule_id', 'unknown')} {error.get('message', '')}",
                rule_id="AUS002",
            )
        if report["records"] == 0:
            raise AuditSegmentError("rotation requires a non-empty typed audit log", rule_id="AUS008")
        raw = path.read_bytes()
        prior_link = _start_link(path)
        segment_index = 1 if prior_link is None else prior_link["segment_index"] + 1
        previous_segment_id = ZERO_HASH if prior_link is None else prior_link["previous_segment_id"]
        core = {
            "manifest_version": SEGMENT_VERSION,
            "segment_index": segment_index,
            "previous_segment_id": previous_segment_id,
            "file": SEGMENT_FILE,
            "records": report["records"],
            "typed_records": report["typed_records"],
            "untyped_records": report["untyped_records"],
            "privacy_safe": report["privacy_safe"],
            "bytes": len(raw),
            "head_hash": report["head_hash"],
            "sha256": _sha256(raw),
            "event_schema_version": report["event_schema_version"],
        }
        manifest = {**core, "segment_id": _segment_id(core)}
        active_bytes = _new_active_bytes(manifest)

        temporary_directory = Path(
            tempfile.mkdtemp(prefix=f".{output_dir.name}.", suffix=".tmp", dir=output_dir.parent)
        )
        active_descriptor, active_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".rotate", dir=path.parent
        )
        active_temporary = Path(active_name)
        try:
            os.fchmod(active_descriptor, 0o600)
            with os.fdopen(active_descriptor, "wb", closefd=True) as handle:
                handle.write(active_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            _write_file(temporary_directory / SEGMENT_FILE, raw)
            _write_file(temporary_directory / MANIFEST_FILE, _canonical_json(manifest))
            _fsync_directory(temporary_directory)
            inspected = inspect_segment_directory(temporary_directory)
            if inspected["segment_id"] != manifest["segment_id"]:
                raise AuditSegmentError("staged segment failed independent verification", rule_id="AUS004")
            try:
                os.rename(temporary_directory, output_dir)
            except FileExistsError as exc:
                raise AuditSegmentError("rotation output directory already exists", rule_id="AUS001") from exc
            _fsync_directory(output_dir.parent)
            os.replace(active_temporary, path)
            _fsync_directory(path.parent)
        finally:
            if active_temporary.exists():
                active_temporary.unlink()
            if temporary_directory.exists():
                shutil.rmtree(temporary_directory)

    active_report = agent_system.inspect_audit(path, require_typed=True)
    if not active_report["valid"] or active_report["records"] != 1:
        raise AuditSegmentError("new active log failed independent verification", rule_id="AUS006")
    return {
        "report_version": 1,
        "rotated": True,
        "active_path": str(path),
        "output_directory": str(output_dir),
        "segment_index": manifest["segment_index"],
        "segment_id": manifest["segment_id"],
        "previous_segment_id": manifest["previous_segment_id"],
        "segment_sha256": manifest["sha256"],
        "sealed_records": manifest["records"],
        "sealed_bytes": manifest["bytes"],
        "sealed_head_hash": manifest["head_hash"],
        "active_records": active_report["records"],
        "active_head_hash": active_report["head_hash"],
    }


def _text_report(payload: dict[str, Any]) -> str:
    if payload.get("rotated"):
        return "\n".join([
            f"ROTATED segment={payload['segment_index']} id={payload['segment_id']}",
            f"sealed: records={payload['sealed_records']} bytes={payload['sealed_bytes']} head={payload['sealed_head_hash']}",
            f"active: records={payload['active_records']} head={payload['active_head_hash']}",
            f"archive: {payload['output_directory']}",
        ])
    return "\n".join([
        f"VALID {payload['segment_count']} segment(s)",
        f"latest: {payload['latest_segment_id']}",
        f"sealed: records={payload['total_records']} bytes={payload['total_bytes']}",
        f"active: {'verified' if payload.get('active') else 'not supplied'}",
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-audit-segments")
    subparsers = parser.add_subparsers(dest="command", required=True)

    rotate = subparsers.add_parser("rotate")
    rotate.add_argument("--path", type=Path, default=Path(".agent-system/audit.jsonl"))
    rotate.add_argument("--output-dir", type=Path, required=True)
    rotate.add_argument("--expected-head")
    rotate.add_argument("--expected-records", type=int)
    rotate.add_argument("--format", choices=("text", "json"), default="text")

    verify = subparsers.add_parser("verify")
    verify.add_argument("directories", nargs="+", type=Path)
    verify.add_argument("--active", type=Path)
    verify.add_argument("--expected-latest-segment-id")
    verify.add_argument("--format", choices=("text", "json"), default="text")

    args = parser.parse_args(argv)
    try:
        if args.command == "rotate":
            result = rotate_audit(
                args.path,
                args.output_dir,
                expected_head=args.expected_head,
                expected_records=args.expected_records,
            )
        else:
            result = verify_segment_chain(
                args.directories,
                active_path=args.active,
                expected_latest_segment_id=args.expected_latest_segment_id,
            )
    except (AuditSegmentError, OSError) as exc:
        rule_id = exc.rule_id if isinstance(exc, AuditSegmentError) else "AUS001"
        print(f"Audit segment error: {rule_id}: {exc}", file=__import__("sys").stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(_text_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
