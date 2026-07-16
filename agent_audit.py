#!/usr/bin/env python3
"""Strict tamper-evident audit-log validation, appending, and recovery copies."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

AUDIT_VERSION = 1
ZERO_HASH = "0" * 64
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00$"
)
MAX_AUDIT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_EVENT_LENGTH = 128
MAX_JSON_DEPTH = 32
LEGACY_FIELDS = {"time", "event", "details", "previous_hash", "hash"}
VERSIONED_FIELDS = LEGACY_FIELDS | {"audit_version", "sequence"}


class AuditError(ValueError):
    """Raised when an audit operation cannot be completed safely."""


class _DuplicateKeyError(ValueError):
    pass


def _canonical_core(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_line(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _record_hash(previous_hash: str, core: dict[str, Any]) -> str:
    return hashlib.sha256(previous_hash.encode("ascii") + _canonical_core(core)).hexdigest()


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _validate_json(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise AuditError("audit details exceed the reviewed nesting limit")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise AuditError("audit details contain a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuditError("audit detail object keys must be strings")
            _validate_json(item, depth=depth + 1)
        return
    raise AuditError(f"audit details contain unsupported type: {type(value).__name__}")


def _issue(
    rule_id: str,
    message: str,
    *,
    line: int | None,
    byte_offset: int,
    recoverable: bool = True,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "message": message,
        "line": line,
        "byte_offset": byte_offset,
        "recoverable": recoverable,
    }


def _base_report(path: Path, exists: bool, file_bytes: int) -> dict[str, Any]:
    return {
        "report_version": 1,
        "valid": True,
        "path": str(path),
        "exists": exists,
        "file_bytes": file_bytes,
        "records": 0,
        "legacy_records": 0,
        "versioned_records": 0,
        "head_hash": ZERO_HASH,
        "recoverable_prefix": {
            "records": 0,
            "bytes": 0,
            "head_hash": ZERO_HASH,
        },
        "expected": {"records": None, "head_hash": None},
        "error": None,
    }


def _failed(report: dict[str, Any], issue: dict[str, Any]) -> dict[str, Any]:
    report["valid"] = False
    report["error"] = issue
    if not issue["recoverable"]:
        report["recoverable_prefix"] = None
    return report


def _validate_record(
    payload: Any,
    *,
    line_number: int,
    previous_hash: str,
) -> tuple[dict[str, Any], bool]:
    if not isinstance(payload, dict):
        raise AuditError("audit record must be a JSON object")
    fields = set(payload)
    legacy = fields == LEGACY_FIELDS
    if not legacy and fields != VERSIONED_FIELDS:
        raise AuditError("audit record fields do not match a reviewed schema")
    if not legacy:
        if payload["audit_version"] != AUDIT_VERSION:
            raise AuditError(f"audit record version must be {AUDIT_VERSION}")
        if isinstance(payload["sequence"], bool) or payload["sequence"] != line_number:
            raise AuditError("audit record sequence does not match its line number")

    timestamp = payload["time"]
    if not isinstance(timestamp, str) or not UTC_TIMESTAMP.fullmatch(timestamp):
        raise AuditError("audit time must be a canonical UTC ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise AuditError("audit time is not a valid timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise AuditError("audit time must use UTC")

    event = payload["event"]
    if (
        not isinstance(event, str)
        or not event
        or event != event.strip()
        or len(event) > MAX_EVENT_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in event)
    ):
        raise AuditError("audit event must be a canonical printable non-empty string")

    details = payload["details"]
    if not isinstance(details, dict):
        raise AuditError("audit details must be a JSON object")
    _validate_json(details)

    stored_previous = payload["previous_hash"]
    stored_hash = payload["hash"]
    if not isinstance(stored_previous, str) or not HEX_64.fullmatch(stored_previous):
        raise AuditError("audit previous hash is malformed")
    if not isinstance(stored_hash, str) or not HEX_64.fullmatch(stored_hash):
        raise AuditError("audit record hash is malformed")
    if stored_previous != previous_hash:
        raise AuditError("audit previous hash does not match the verified chain head")

    core = dict(payload)
    core.pop("hash")
    if stored_hash != _record_hash(previous_hash, core):
        raise AuditError("audit record hash does not match its canonical payload")
    return payload, legacy


def inspect_audit(
    path: Path,
    *,
    expected_head: str | None = None,
    expected_records: int | None = None,
) -> dict[str, Any]:
    path = Path(path)
    if expected_head is not None:
        expected_head = expected_head.lower()
        if not HEX_64.fullmatch(expected_head):
            raise AuditError("expected audit head must be 64 lowercase hexadecimal characters")
    if expected_records is not None and (
        isinstance(expected_records, bool) or not isinstance(expected_records, int) or expected_records < 0
    ):
        raise AuditError("expected audit record count must be a non-negative integer")

    if path.is_symlink():
        report = _base_report(path, True, 0)
        report["expected"] = {"records": expected_records, "head_hash": expected_head}
        return _failed(
            report,
            _issue("AUD001", "audit log must not be a symlink", line=None, byte_offset=0, recoverable=False),
        )
    if not path.exists():
        report = _base_report(path, False, 0)
        report["expected"] = {"records": expected_records, "head_hash": expected_head}
        if expected_records not in (None, 0):
            return _failed(
                report,
                _issue("AUD020", "audit record count differs from the externally pinned count", line=None, byte_offset=0, recoverable=False),
            )
        if expected_head not in (None, ZERO_HASH):
            return _failed(
                report,
                _issue("AUD021", "audit head differs from the externally pinned hash", line=None, byte_offset=0, recoverable=False),
            )
        return report

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AuditError(f"unable to read audit log: {path}") from exc
    report = _base_report(path, True, len(raw))
    report["expected"] = {"records": expected_records, "head_hash": expected_head}
    if len(raw) > MAX_AUDIT_BYTES:
        return _failed(
            report,
            _issue("AUD002", "audit log exceeds the reviewed size limit", line=None, byte_offset=0, recoverable=False),
        )
    if not raw:
        if expected_records not in (None, 0):
            return _failed(
                report,
                _issue("AUD020", "audit record count differs from the externally pinned count", line=None, byte_offset=0, recoverable=False),
            )
        if expected_head not in (None, ZERO_HASH):
            return _failed(
                report,
                _issue("AUD021", "audit head differs from the externally pinned hash", line=None, byte_offset=0, recoverable=False),
            )
        return report

    complete_end = len(raw) if raw.endswith(b"\n") else raw.rfind(b"\n") + 1
    previous_hash = ZERO_HASH
    offset = 0
    line_number = 0
    for raw_line in raw[:complete_end].splitlines(keepends=True):
        line_number += 1
        line_start = offset
        offset += len(raw_line)
        if len(raw_line) > MAX_LINE_BYTES:
            return _failed(
                report,
                _issue("AUD004", "audit record exceeds the reviewed line-size limit", line=line_number, byte_offset=line_start),
            )
        body = raw_line[:-1]
        if body.endswith(b"\r"):
            return _failed(
                report,
                _issue("AUD017", "audit records must use canonical LF line endings", line=line_number, byte_offset=line_start),
            )
        if not body:
            return _failed(
                report,
                _issue("AUD005", "blank audit records are not allowed", line=line_number, byte_offset=line_start),
            )
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return _failed(
                report,
                _issue("AUD006", "audit record is not valid UTF-8", line=line_number, byte_offset=line_start),
            )
        try:
            payload = json.loads(
                text,
                object_pairs_hook=_json_object,
                parse_constant=_reject_constant,
            )
        except (_DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
            return _failed(
                report,
                _issue("AUD007", f"audit record is not strict JSON: {exc}", line=line_number, byte_offset=line_start),
            )
        try:
            normalized, legacy = _validate_record(
                payload,
                line_number=line_number,
                previous_hash=previous_hash,
            )
        except AuditError as exc:
            message = str(exc)
            if "fields" in message or "JSON object" in message or "version" in message:
                rule_id = "AUD008"
            elif "sequence" in message:
                rule_id = "AUD010"
            elif "time" in message or "timestamp" in message or "UTC" in message:
                rule_id = "AUD011"
            elif "event" in message:
                rule_id = "AUD012"
            elif "details" in message or "detail" in message:
                rule_id = "AUD013"
            elif "malformed" in message:
                rule_id = "AUD014"
            elif "previous hash does not match" in message:
                rule_id = "AUD015"
            else:
                rule_id = "AUD016"
            return _failed(
                report,
                _issue(rule_id, message, line=line_number, byte_offset=line_start),
            )
        if raw_line != _canonical_line(normalized):
            return _failed(
                report,
                _issue("AUD017", "audit record is not canonically serialized", line=line_number, byte_offset=line_start),
            )
        previous_hash = normalized["hash"]
        report["records"] += 1
        report["legacy_records"] += int(legacy)
        report["versioned_records"] += int(not legacy)
        report["head_hash"] = previous_hash
        report["recoverable_prefix"] = {
            "records": report["records"],
            "bytes": offset,
            "head_hash": previous_hash,
        }

    if complete_end != len(raw):
        return _failed(
            report,
            _issue(
                "AUD003",
                "audit log ends with a partial record and no final newline",
                line=line_number + 1,
                byte_offset=complete_end,
            ),
        )
    if expected_records is not None and report["records"] != expected_records:
        return _failed(
            report,
            _issue("AUD020", "audit record count differs from the externally pinned count", line=None, byte_offset=len(raw), recoverable=False),
        )
    if expected_head is not None and report["head_hash"] != expected_head:
        return _failed(
            report,
            _issue("AUD021", "audit head differs from the externally pinned hash", line=None, byte_offset=len(raw), recoverable=False),
        )
    return report


def verify_audit(path: Path) -> tuple[bool, int]:
    """Compatibility wrapper returning validity and record/error line count."""
    report = inspect_audit(path)
    if report["valid"]:
        return True, report["records"]
    line = report["error"]["line"] if report["error"] else None
    return False, line or report["records"]


@contextlib.contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    if lock_path.is_symlink():
        raise AuditError("audit lock file must not be a symlink")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def append_audit(
    path: Path,
    event: str,
    details: dict[str, Any],
    *,
    timestamp: str | None = None,
) -> dict[str, Any]:
    path = Path(path)
    lock_path = path.with_name(path.name + ".lock")
    with _exclusive_lock(lock_path):
        report = inspect_audit(path)
        if not report["valid"]:
            error = report["error"]
            raise AuditError(
                f"refusing to extend invalid audit log ({error['rule_id']} at line {error['line']}): {error['message']}"
            )
        if path.is_symlink():
            raise AuditError("audit log must not be a symlink")
        if not isinstance(event, str):
            raise AuditError("audit event must be a string")
        if not isinstance(details, dict):
            raise AuditError("audit details must be a JSON object")
        _validate_json(details)
        current_time = timestamp or datetime.now(timezone.utc).isoformat()
        core = {
            "audit_version": AUDIT_VERSION,
            "sequence": report["records"] + 1,
            "time": current_time,
            "event": event,
            "details": details,
            "previous_hash": report["head_hash"],
        }
        record = {**core, "hash": _record_hash(report["head_hash"], core)}
        _validate_record(record, line_number=core["sequence"], previous_hash=report["head_hash"])
        encoded = _canonical_line(record)
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        descriptor = os.open(path, flags, 0o600)
        try:
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise AuditError("audit append produced a partial write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return record


def _write_new_bytes(path: Path, data: bytes, label: str) -> None:
    if path.is_symlink():
        raise AuditError(f"{label} output must not be a symlink")
    if path.exists():
        raise AuditError(f"refusing to overwrite existing {label}: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise AuditError(f"refusing to overwrite existing {label}: {path}") from exc
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def recover_audit(path: Path, output: Path, report: dict[str, Any] | None = None) -> dict[str, Any]:
    path = Path(path)
    output = Path(output)
    report = report or inspect_audit(path)
    prefix = report.get("recoverable_prefix")
    if prefix is None:
        raise AuditError("audit failure is not safely recoverable without resolving the external pin mismatch")
    if path.absolute() == output.absolute():
        raise AuditError("recovery output must differ from the source audit log")
    raw = b"" if not path.exists() else path.read_bytes()
    data = raw[: prefix["bytes"]]
    _write_new_bytes(output, data, "audit recovery copy")
    recovered = inspect_audit(output)
    if not recovered["valid"] or recovered["records"] != prefix["records"]:
        raise AuditError("recovery copy failed independent verification")
    return {
        "created": str(output),
        "records": recovered["records"],
        "head_hash": recovered["head_hash"],
        "source_valid": report["valid"],
        "source_error": report["error"],
    }
