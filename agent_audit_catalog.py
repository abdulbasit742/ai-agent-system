#!/usr/bin/env python3
"""Canonical audit-segment catalog discovery, synchronization, and verification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from agent_audit import ZERO_HASH, _exclusive_lock
from agent_audit_segments import (
    MANIFEST_FILE,
    SEGMENT_FILE,
    AuditSegmentError,
    inspect_segment_directory,
    verify_segment_chain,
)

CATALOG_VERSION = 1
MAX_CATALOG_BYTES = 8 * 1024 * 1024
MAX_SEGMENTS = 100_000
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
CATALOG_FIELDS = {
    "catalog_version",
    "generation",
    "previous_catalog_id",
    "segments",
    "segment_count",
    "total_records",
    "total_bytes",
    "latest_segment_id",
    "catalog_id",
}
ENTRY_FIELDS = {
    "segment_index",
    "directory",
    "segment_id",
    "previous_segment_id",
    "manifest_sha256",
    "segment_sha256",
    "head_hash",
    "records",
    "bytes",
}


class AuditCatalogError(ValueError):
    """Raised when a segment catalog operation cannot proceed safely."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "AUC002",
        denied: bool = False,
    ) -> None:
        super().__init__(message)
        self.rule_id = rule_id
        self.denied = denied


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


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _catalog_id(core: dict[str, Any]) -> str:
    encoded = json.dumps(
        core,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"audit-segment-catalog-v1\0" + encoded).hexdigest()


def _lower_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditCatalogError(
            f"{label} must be 64 lowercase hexadecimal characters",
            rule_id="AUC002",
        )
    return value


def _positive(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "non-negative" if allow_zero else "positive"
        raise AuditCatalogError(
            f"{label} must be a {qualifier} integer",
            rule_id="AUC002",
        )
    return value


def _safe_directory_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 255
        or value in {".", ".."}
        or value.startswith(".")
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or Path(value).name != value
    ):
        raise AuditCatalogError(
            "catalog segment directory must be one safe immediate-child name",
            rule_id="AUC001",
        )
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


def _write_new(path: Path, data: bytes) -> None:
    if path.is_symlink() or path.exists():
        raise AuditCatalogError(
            "catalog output must not already exist or be a symlink",
            rule_id="AUC008",
        )
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
            raise AuditCatalogError(
                "catalog output appeared during creation",
                rule_id="AUC008",
            ) from exc
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _replace(path: Path, data: bytes) -> None:
    if path.is_symlink() or not path.is_file():
        raise AuditCatalogError(
            "catalog update target must be a regular non-symlink file",
            rule_id="AUC001",
        )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".sync", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _segment_error(exc: AuditSegmentError, context: str) -> AuditCatalogError:
    if exc.rule_id == "AUS006":
        return AuditCatalogError(
            f"{context}: {exc}",
            rule_id="AUC006",
            denied=True,
        )
    if exc.rule_id == "AUS005":
        return AuditCatalogError(
            f"{context}: {exc}",
            rule_id="AUC005",
            denied=True,
        )
    return AuditCatalogError(f"{context}: {exc}", rule_id="AUC004")


def _entry_for_directory(root: Path, directory: Path) -> dict[str, Any]:
    root = Path(root)
    directory = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise AuditCatalogError(
            "catalog archive root must be a regular non-symlink directory",
            rule_id="AUC001",
        )
    if directory.parent.absolute() != root.absolute():
        raise AuditCatalogError(
            "catalog segments must be immediate children of the archive root",
            rule_id="AUC001",
        )
    name = _safe_directory_name(directory.name)
    try:
        inspected = inspect_segment_directory(directory)
    except AuditSegmentError as exc:
        raise _segment_error(exc, f"segment {name} failed verification") from exc
    manifest_path = directory / MANIFEST_FILE
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise AuditCatalogError(
            f"segment {name} manifest is unsafe",
            rule_id="AUC001",
        )
    return {
        "segment_index": inspected["segment_index"],
        "directory": name,
        "segment_id": inspected["segment_id"],
        "previous_segment_id": inspected["previous_segment_id"],
        "manifest_sha256": _sha256(manifest_path.read_bytes()),
        "segment_sha256": inspected["sha256"],
        "head_hash": inspected["head_hash"],
        "records": inspected["records"],
        "bytes": inspected["bytes"],
    }


def discover_segments(root: Path) -> tuple[list[dict[str, Any]], list[Path]]:
    """Discover, verify, and order every immediate segment directory in one archive root."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise AuditCatalogError(
            "catalog archive root must be a regular non-symlink directory",
            rule_id="AUC001",
        )
    candidates: list[Path] = []
    for child in root.iterdir():
        if child.is_symlink():
            raise AuditCatalogError(
                f"archive root contains symlink entry: {child.name}",
                rule_id="AUC001",
            )
        if not child.is_dir():
            continue
        manifest = child / MANIFEST_FILE
        segment = child / SEGMENT_FILE
        has_manifest = manifest.exists() or manifest.is_symlink()
        has_segment = segment.exists() or segment.is_symlink()
        if has_manifest != has_segment:
            raise AuditCatalogError(
                f"archive child {child.name} is an incomplete segment directory",
                rule_id="AUC004",
            )
        if not has_manifest:
            raise AuditCatalogError(
                f"archive root contains unreviewed directory: {child.name}",
                rule_id="AUC001",
            )
        candidates.append(child)
    if not candidates:
        raise AuditCatalogError(
            "catalog initialization requires at least one sealed segment",
            rule_id="AUC010",
        )
    entries = [_entry_for_directory(root, directory) for directory in candidates]
    paired = sorted(zip(entries, candidates), key=lambda item: item[0]["segment_index"])
    entries = [item[0] for item in paired]
    directories = [item[1] for item in paired]
    if len(entries) > MAX_SEGMENTS:
        raise AuditCatalogError(
            "archive exceeds the reviewed segment-count boundary",
            rule_id="AUC003",
        )
    names = [entry["directory"] for entry in entries]
    identifiers = [entry["segment_id"] for entry in entries]
    if len(names) != len(set(names)) or len(identifiers) != len(set(identifiers)):
        raise AuditCatalogError(
            "archive contains duplicate segment directories or IDs",
            rule_id="AUC005",
            denied=True,
        )
    try:
        verify_segment_chain(directories)
    except AuditSegmentError as exc:
        raise _segment_error(exc, "discovered segment chain is invalid") from exc
    return entries, directories


def _validate_entry(entry: Any, position: int) -> dict[str, Any]:
    if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
        raise AuditCatalogError(
            "catalog segment entry fields do not match the reviewed schema",
            rule_id="AUC002",
        )
    normalized = {
        "segment_index": _positive(entry["segment_index"], "segment_index"),
        "directory": _safe_directory_name(entry["directory"]),
        "segment_id": _lower_hash(entry["segment_id"], "segment_id"),
        "previous_segment_id": _lower_hash(
            entry["previous_segment_id"], "previous_segment_id"
        ),
        "manifest_sha256": _lower_hash(
            entry["manifest_sha256"], "manifest_sha256"
        ),
        "segment_sha256": _lower_hash(
            entry["segment_sha256"], "segment_sha256"
        ),
        "head_hash": _lower_hash(entry["head_hash"], "head_hash"),
        "records": _positive(entry["records"], "records"),
        "bytes": _positive(entry["bytes"], "bytes"),
    }
    if normalized != entry:
        raise AuditCatalogError(
            "catalog segment entry is not canonical",
            rule_id="AUC002",
        )
    if normalized["segment_index"] != position:
        raise AuditCatalogError(
            "catalog segment indexes must form a complete sequence from one",
            rule_id="AUC005",
            denied=True,
        )
    return normalized


def _build_catalog(
    entries: list[dict[str, Any]],
    *,
    generation: int,
    previous_catalog_id: str,
) -> dict[str, Any]:
    core = {
        "catalog_version": CATALOG_VERSION,
        "generation": generation,
        "previous_catalog_id": previous_catalog_id,
        "segments": entries,
        "segment_count": len(entries),
        "total_records": sum(entry["records"] for entry in entries),
        "total_bytes": sum(entry["bytes"] for entry in entries),
        "latest_segment_id": entries[-1]["segment_id"],
    }
    return {**core, "catalog_id": _catalog_id(core)}


def _validate_catalog(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != CATALOG_FIELDS:
        raise AuditCatalogError(
            "catalog fields do not match the reviewed schema",
            rule_id="AUC002",
        )
    if payload["catalog_version"] != CATALOG_VERSION:
        raise AuditCatalogError(
            f"catalog version must be {CATALOG_VERSION}",
            rule_id="AUC002",
        )
    generation = _positive(payload["generation"], "generation")
    previous_catalog_id = _lower_hash(
        payload["previous_catalog_id"], "previous_catalog_id"
    )
    entries_value = payload["segments"]
    if (
        not isinstance(entries_value, list)
        or not entries_value
        or len(entries_value) > MAX_SEGMENTS
    ):
        raise AuditCatalogError(
            "catalog segments must be a non-empty bounded array",
            rule_id="AUC002",
        )
    entries = [
        _validate_entry(entry, position)
        for position, entry in enumerate(entries_value, 1)
    ]
    if entries[0]["previous_segment_id"] != ZERO_HASH:
        raise AuditCatalogError(
            "catalog first segment must use the zero previous segment ID",
            rule_id="AUC005",
            denied=True,
        )
    for previous, current in zip(entries, entries[1:]):
        if current["previous_segment_id"] != previous["segment_id"]:
            raise AuditCatalogError(
                "catalog segment IDs do not form one append-only chain",
                rule_id="AUC005",
                denied=True,
            )
    if generation == 1 and previous_catalog_id != ZERO_HASH:
        raise AuditCatalogError(
            "initial catalog must use the zero previous catalog ID",
            rule_id="AUC003",
        )
    if generation > 1 and previous_catalog_id == ZERO_HASH:
        raise AuditCatalogError(
            "advanced catalog must retain its previous catalog ID",
            rule_id="AUC003",
        )
    expected_count = len(entries)
    expected_records = sum(entry["records"] for entry in entries)
    expected_bytes = sum(entry["bytes"] for entry in entries)
    expected_latest = entries[-1]["segment_id"]
    comparisons = {
        "segment_count": expected_count,
        "total_records": expected_records,
        "total_bytes": expected_bytes,
        "latest_segment_id": expected_latest,
    }
    for key, expected in comparisons.items():
        if payload[key] != expected:
            raise AuditCatalogError(
                f"catalog {key} does not match its segment entries",
                rule_id="AUC003",
            )
    names = [entry["directory"] for entry in entries]
    identifiers = [entry["segment_id"] for entry in entries]
    if len(names) != len(set(names)) or len(identifiers) != len(set(identifiers)):
        raise AuditCatalogError(
            "catalog contains duplicate directory names or segment IDs",
            rule_id="AUC005",
            denied=True,
        )
    stored_id = _lower_hash(payload["catalog_id"], "catalog_id")
    core = dict(payload)
    core.pop("catalog_id")
    if stored_id != _catalog_id(core):
        raise AuditCatalogError(
            "catalog ID does not match its canonical payload",
            rule_id="AUC003",
        )
    return payload


def load_catalog(
    path: Path,
    *,
    expected_catalog_id: str | None = None,
) -> dict[str, Any]:
    """Load and structurally validate one canonical catalog file."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditCatalogError(
            "catalog must be a regular non-symlink file",
            rule_id="AUC001",
        )
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_CATALOG_BYTES:
        raise AuditCatalogError(
            "catalog size is outside the reviewed boundary",
            rule_id="AUC002",
        )
    try:
        text = raw.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        _DuplicateKeyError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise AuditCatalogError(
            f"catalog is not strict JSON: {exc}",
            rule_id="AUC002",
        ) from exc
    if not isinstance(payload, dict) or raw != _canonical_bytes(payload):
        raise AuditCatalogError(
            "catalog is not canonically serialized",
            rule_id="AUC002",
        )
    payload = _validate_catalog(payload)
    if expected_catalog_id is not None:
        expected = _lower_hash(
            expected_catalog_id.lower(), "expected_catalog_id"
        )
        if payload["catalog_id"] != expected:
            raise AuditCatalogError(
                "catalog ID differs from the externally retained pin",
                rule_id="AUC007",
                denied=True,
            )
    return payload


def _listed_directories(
    path: Path,
    payload: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[Path]]:
    root = path.parent
    entries: list[dict[str, Any]] = []
    directories: list[Path] = []
    for stored in payload["segments"]:
        directory = root / _safe_directory_name(stored["directory"])
        actual = _entry_for_directory(root, directory)
        if actual != stored:
            raise AuditCatalogError(
                f"catalog entry for {stored['directory']} does not match sealed evidence",
                rule_id="AUC004",
            )
        entries.append(actual)
        directories.append(directory)
    try:
        verify_segment_chain(
            directories,
            expected_latest_segment_id=payload["latest_segment_id"],
        )
    except AuditSegmentError as exc:
        raise _segment_error(exc, "catalog segment chain is invalid") from exc
    return entries, directories


def _verify_active(
    directories: list[Path],
    latest_segment_id: str,
    active_path: Path | None,
) -> dict[str, Any] | None:
    if active_path is None:
        return None
    try:
        report = verify_segment_chain(
            directories,
            active_path=Path(active_path),
            expected_latest_segment_id=latest_segment_id,
        )
    except AuditSegmentError as exc:
        raise _segment_error(exc, "active audit log does not match the catalog") from exc
    return report["active"]


def verify_catalog(
    path: Path,
    *,
    expected_catalog_id: str | None = None,
    active_path: Path | None = None,
    require_complete_discovery: bool = True,
) -> dict[str, Any]:
    """Verify catalog bytes, every indexed segment, discovery completeness, and active continuity."""
    path = Path(path)
    payload = load_catalog(path, expected_catalog_id=expected_catalog_id)
    entries, directories = _listed_directories(path, payload)
    if require_complete_discovery:
        discovered, discovered_directories = discover_segments(path.parent)
        if discovered != entries:
            raise AuditCatalogError(
                "catalog does not exactly cover the discovered segment set",
                rule_id="AUC005",
                denied=True,
            )
        directories = discovered_directories
    active = _verify_active(
        directories,
        payload["latest_segment_id"],
        active_path,
    )
    return {
        "report_version": 1,
        "valid": True,
        "catalog_path": str(path),
        "catalog_id": payload["catalog_id"],
        "expected_catalog_id": (
            expected_catalog_id.lower() if expected_catalog_id else None
        ),
        "generation": payload["generation"],
        "previous_catalog_id": payload["previous_catalog_id"],
        "segment_count": payload["segment_count"],
        "total_records": payload["total_records"],
        "total_bytes": payload["total_bytes"],
        "latest_segment_id": payload["latest_segment_id"],
        "segments": entries,
        "active": active,
    }


def initialize_catalog(
    path: Path,
    *,
    active_path: Path | None = None,
    expected_latest_segment_id: str | None = None,
) -> dict[str, Any]:
    """Discover all sealed segments in the catalog directory and create generation one."""
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise AuditCatalogError(
            "catalog initialization refuses to overwrite an existing path",
            rule_id="AUC008",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    entries, directories = discover_segments(path.parent)
    if expected_latest_segment_id is not None:
        expected = _lower_hash(
            expected_latest_segment_id.lower(), "expected_latest_segment_id"
        )
        if entries[-1]["segment_id"] != expected:
            raise AuditCatalogError(
                "discovered latest segment differs from the external pin",
                rule_id="AUC007",
                denied=True,
            )
    _verify_active(directories, entries[-1]["segment_id"], active_path)
    payload = _build_catalog(
        entries,
        generation=1,
        previous_catalog_id=ZERO_HASH,
    )
    _write_new(path, _canonical_bytes(payload))
    report = verify_catalog(
        path,
        expected_catalog_id=payload["catalog_id"],
        active_path=active_path,
    )
    report.update({"created": True, "updated": False, "added_segments": len(entries)})
    return report


def synchronize_catalog(
    path: Path,
    *,
    expected_catalog_id: str,
    active_path: Path | None = None,
) -> dict[str, Any]:
    """Atomically append every newly discovered right-descendant segment to a pinned catalog."""
    path = Path(path)
    lock_path = path.with_name(path.name + ".lock")
    with _exclusive_lock(lock_path):
        current = load_catalog(path, expected_catalog_id=expected_catalog_id)
        current_entries, _ = _listed_directories(path, current)
        discovered, discovered_directories = discover_segments(path.parent)
        if len(discovered) < len(current_entries):
            raise AuditCatalogError(
                "discovered archive is missing cataloged segments",
                rule_id="AUC005",
                denied=True,
            )
        if discovered[: len(current_entries)] != current_entries:
            raise AuditCatalogError(
                "discovered archive does not retain the catalog as an exact prefix",
                rule_id="AUC005",
                denied=True,
            )
        active = _verify_active(
            discovered_directories,
            discovered[-1]["segment_id"],
            active_path,
        )
        added = len(discovered) - len(current_entries)
        if added == 0:
            report = verify_catalog(
                path,
                expected_catalog_id=current["catalog_id"],
                active_path=active_path,
            )
            report.update({"created": False, "updated": False, "added_segments": 0})
            return report
        payload = _build_catalog(
            discovered,
            generation=current["generation"] + 1,
            previous_catalog_id=current["catalog_id"],
        )
        _replace(path, _canonical_bytes(payload))
    report = verify_catalog(
        path,
        expected_catalog_id=payload["catalog_id"],
        active_path=active_path,
    )
    report.update(
        {
            "created": False,
            "updated": True,
            "added_segments": added,
            "previous_catalog_id": current["catalog_id"],
            "active": active,
        }
    )
    return report


def _text_report(payload: dict[str, Any]) -> str:
    action = "CREATED" if payload.get("created") else "UPDATED" if payload.get("updated") else "VALID"
    return "\n".join(
        [
            f"{action} catalog={payload['catalog_id']} generation={payload['generation']}",
            f"segments: count={payload['segment_count']} added={payload.get('added_segments', 0)} latest={payload['latest_segment_id']}",
            f"sealed: records={payload['total_records']} bytes={payload['total_bytes']}",
            f"active: {'verified' if payload.get('active') else 'not supplied'}",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-audit-catalog")
    subparsers = parser.add_subparsers(dest="command", required=True)

    initialize = subparsers.add_parser("init")
    initialize.add_argument("catalog", type=Path)
    initialize.add_argument("--active", type=Path)
    initialize.add_argument("--expected-latest-segment-id")
    initialize.add_argument("--format", choices=("text", "json"), default="text")

    verify = subparsers.add_parser("verify")
    verify.add_argument("catalog", type=Path)
    verify.add_argument("--expected-catalog-id", required=True)
    verify.add_argument("--active", type=Path)
    verify.add_argument("--format", choices=("text", "json"), default="text")

    synchronize = subparsers.add_parser("sync")
    synchronize.add_argument("catalog", type=Path)
    synchronize.add_argument("--expected-catalog-id", required=True)
    synchronize.add_argument("--active", type=Path)
    synchronize.add_argument("--format", choices=("text", "json"), default="text")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = initialize_catalog(
                args.catalog,
                active_path=args.active,
                expected_latest_segment_id=args.expected_latest_segment_id,
            )
        elif args.command == "verify":
            result = verify_catalog(
                args.catalog,
                expected_catalog_id=args.expected_catalog_id,
                active_path=args.active,
            )
        else:
            result = synchronize_catalog(
                args.catalog,
                expected_catalog_id=args.expected_catalog_id,
                active_path=args.active,
            )
    except (AuditCatalogError, OSError) as exc:
        rule_id = exc.rule_id if isinstance(exc, AuditCatalogError) else "AUC001"
        print(f"Audit catalog error: {rule_id}: {exc}", file=__import__("sys").stderr)
        return 1 if isinstance(exc, AuditCatalogError) and exc.denied else 2
    if args.format == "json":
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(_text_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
