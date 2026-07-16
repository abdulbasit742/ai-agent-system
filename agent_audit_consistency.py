#!/usr/bin/env python3
"""Compact append-only consistency proofs between audit catalog checkpoints."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable

from agent_audit_catalog import AuditCatalogError, _validate_catalog, load_catalog, verify_catalog
from agent_audit_checkpoint import (
    AuditCatalogCheckpointError,
    MERKLE_ALGORITHM,
    _canonical_bytes,
    _identifier,
    _leaf_hash,
    _merkle_root,
    _node_hash,
    checkpoint_matches_catalog,
    load_checkpoint,
    validate_checkpoint,
)

CONSISTENCY_VERSION = 1
CONSISTENCY_ALGORITHM = "sha256-rfc6962-compact-range-v1"
MAX_CONSISTENCY_BYTES = 1_000_000
MAX_FRONTIER_SEGMENTS = 256
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
CONSISTENCY_FIELDS = {
    "consistency_version",
    "algorithm",
    "relation",
    "direct_predecessor_verified",
    "previous",
    "candidate",
    "previous_frontier",
    "append_frontier",
    "consistency_id",
}
CHECKPOINT_REFERENCE_FIELDS = {
    "checkpoint_id",
    "catalog_id",
    "generation",
    "previous_catalog_id",
    "segment_count",
    "total_records",
    "total_bytes",
    "latest_segment_id",
    "merkle_root",
}
FRONTIER_FIELDS = {"start", "size", "hash"}


class AuditCatalogConsistencyError(ValueError):
    """Raised when catalog consistency evidence cannot be processed safely."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "AUK002",
        denied: bool = False,
    ) -> None:
        super().__init__(message)
        self.rule_id = rule_id
        self.denied = denied


class AuditCatalogConsistencyDenied(AuditCatalogConsistencyError):
    """Raised when valid catalogs are related by rollback, fork, or generation regression."""

    def __init__(self, report: dict[str, Any]) -> None:
        violation = report["violations"][0]
        super().__init__(
            violation["message"],
            rule_id=violation["rule_id"],
            denied=True,
        )
        self.report = report


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


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditCatalogConsistencyError(
            f"{label} must be 64 lowercase hexadecimal characters",
            rule_id="AUK002",
        )
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditCatalogConsistencyError(
            f"{label} must be an integer greater than or equal to {minimum}",
            rule_id="AUK002",
        )
    return value


def _exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditCatalogConsistencyError(
            f"{label} fields do not match the reviewed schema",
            rule_id="AUK002",
        )
    return value


def _checkpoint_reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_checkpoint(checkpoint)
    catalog = normalized["catalog"]
    return {
        "checkpoint_id": normalized["checkpoint_id"],
        "catalog_id": catalog["catalog_id"],
        "generation": catalog["generation"],
        "previous_catalog_id": catalog["previous_catalog_id"],
        "segment_count": catalog["segment_count"],
        "total_records": catalog["total_records"],
        "total_bytes": catalog["total_bytes"],
        "latest_segment_id": catalog["latest_segment_id"],
        "merkle_root": normalized["merkle"]["root"],
    }


def _validate_checkpoint_reference(value: Any, label: str) -> dict[str, Any]:
    reference = _exact_fields(value, CHECKPOINT_REFERENCE_FIELDS, label)
    normalized = {
        "checkpoint_id": _hash(reference["checkpoint_id"], f"{label} checkpoint id"),
        "catalog_id": _hash(reference["catalog_id"], f"{label} catalog id"),
        "generation": _integer(reference["generation"], f"{label} generation", 1),
        "previous_catalog_id": _hash(
            reference["previous_catalog_id"], f"{label} previous catalog id"
        ),
        "segment_count": _integer(
            reference["segment_count"], f"{label} segment count", 1
        ),
        "total_records": _integer(
            reference["total_records"], f"{label} total records", 1
        ),
        "total_bytes": _integer(reference["total_bytes"], f"{label} total bytes", 1),
        "latest_segment_id": _hash(
            reference["latest_segment_id"], f"{label} latest segment id"
        ),
        "merkle_root": _hash(reference["merkle_root"], f"{label} Merkle root"),
    }
    if normalized != reference:
        raise AuditCatalogConsistencyError(
            f"{label} is not canonical",
            rule_id="AUK002",
        )
    return normalized


def _largest_power_at_most(value: int) -> int:
    if value < 1:
        raise AuditCatalogConsistencyError(
            "compact range requires a positive size",
            rule_id="AUK005",
        )
    return 1 << (value.bit_length() - 1)


def range_layout(start: int, end: int) -> list[tuple[int, int]]:
    """Return the canonical maximal aligned power-of-two cover of [start, end)."""
    _integer(start, "range start")
    _integer(end, "range end")
    if end < start:
        raise AuditCatalogConsistencyError(
            "range end must not precede range start",
            rule_id="AUK005",
        )
    layout: list[tuple[int, int]] = []
    cursor = start
    while cursor < end:
        remaining = end - cursor
        if cursor == 0:
            size = _largest_power_at_most(remaining)
        else:
            size = cursor & -cursor
            while size > remaining:
                size >>= 1
        layout.append((cursor, size))
        cursor += size
    return layout


def _frontier_segment(start: int, size: int, digest: bytes) -> dict[str, Any]:
    return {"start": start, "size": size, "hash": digest.hex()}


def _segments_for_entries(
    entries: list[dict[str, Any]], start: int, end: int
) -> list[dict[str, Any]]:
    leaves = [_leaf_hash(entry) for entry in entries]
    result: list[dict[str, Any]] = []
    for offset, size in range_layout(start, end):
        result.append(
            _frontier_segment(offset, size, _merkle_root(leaves[offset : offset + size]))
        )
    return result


def _validate_frontier(
    value: Any,
    start: int,
    end: int,
    label: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_FRONTIER_SEGMENTS:
        raise AuditCatalogConsistencyError(
            f"{label} is malformed or exceeds the reviewed limit",
            rule_id="AUK005",
        )
    expected = range_layout(start, end)
    if len(value) != len(expected):
        raise AuditCatalogConsistencyError(
            f"{label} does not use the canonical compact-range layout",
            rule_id="AUK005",
        )
    normalized: list[dict[str, Any]] = []
    for position, (raw, (expected_start, expected_size)) in enumerate(
        zip(value, expected), 1
    ):
        item = _exact_fields(raw, FRONTIER_FIELDS, f"{label} segment {position}")
        segment_start = _integer(item["start"], f"{label} segment start")
        segment_size = _integer(item["size"], f"{label} segment size", 1)
        if segment_start != expected_start or segment_size != expected_size:
            raise AuditCatalogConsistencyError(
                f"{label} does not use the canonical compact-range layout",
                rule_id="AUK005",
            )
        if segment_size & (segment_size - 1) or segment_start % segment_size:
            raise AuditCatalogConsistencyError(
                f"{label} contains a non-aligned range",
                rule_id="AUK005",
            )
        normalized.append(
            {
                "start": segment_start,
                "size": segment_size,
                "hash": _hash(item["hash"], f"{label} segment hash"),
            }
        )
    return normalized


def _forest_root(frontier: list[dict[str, Any]]) -> bytes:
    if not frontier:
        raise AuditCatalogConsistencyError(
            "compact frontier must contain at least one segment",
            rule_id="AUK005",
        )
    end = frontier[-1]["start"] + frontier[-1]["size"]
    if [(item["start"], item["size"]) for item in frontier] != range_layout(0, end):
        raise AuditCatalogConsistencyError(
            "compact frontier does not match the canonical prefix layout",
            rule_id="AUK005",
        )
    root = bytes.fromhex(frontier[-1]["hash"])
    for item in reversed(frontier[:-1]):
        root = _node_hash(bytes.fromhex(item["hash"]), root)
    return root


def _append_segment(forest: list[dict[str, Any]], segment: dict[str, Any]) -> None:
    if forest:
        expected_start = forest[-1]["start"] + forest[-1]["size"]
        if segment["start"] != expected_start:
            raise AuditCatalogConsistencyError(
                "compact consistency segments are not contiguous",
                rule_id="AUK005",
            )
    elif segment["start"] != 0:
        raise AuditCatalogConsistencyError(
            "compact consistency frontier must begin at zero",
            rule_id="AUK005",
        )
    forest.append(dict(segment))
    while len(forest) >= 2:
        left, right = forest[-2], forest[-1]
        size = left["size"]
        if (
            right["size"] != size
            or left["start"] + size != right["start"]
            or left["start"] % (2 * size)
        ):
            break
        forest[-2:] = [
            _frontier_segment(
                left["start"],
                size * 2,
                _node_hash(bytes.fromhex(left["hash"]), bytes.fromhex(right["hash"])),
            )
        ]


def _reconstruct_roots(
    previous_frontier: list[dict[str, Any]],
    append_frontier: list[dict[str, Any]],
    previous_count: int,
    candidate_count: int,
) -> tuple[str, str]:
    previous_root = _forest_root(previous_frontier).hex()
    if previous_frontier[-1]["start"] + previous_frontier[-1]["size"] != previous_count:
        raise AuditCatalogConsistencyError(
            "previous frontier does not cover the previous checkpoint",
            rule_id="AUK005",
        )
    forest = [dict(item) for item in previous_frontier]
    for item in append_frontier:
        _append_segment(forest, item)
    if [(item["start"], item["size"]) for item in forest] != range_layout(
        0, candidate_count
    ):
        raise AuditCatalogConsistencyError(
            "proof does not reconstruct the canonical candidate frontier",
            rule_id="AUK005",
        )
    return previous_root, _forest_root(forest).hex()


def catalog_lineage(
    previous_catalog: dict[str, Any], candidate_catalog: dict[str, Any]
) -> dict[str, Any]:
    """Classify two validated catalogs by exact segment-entry prefix relation."""
    previous = _validate_catalog(previous_catalog)
    candidate = _validate_catalog(candidate_catalog)
    left_entries = previous["segments"]
    right_entries = candidate["segments"]
    common = 0
    for left, right in zip(left_entries, right_entries):
        if left != right:
            break
        common += 1

    direct = False
    if previous == candidate:
        relation = "same"
        accepted = True
        violation = None
    elif common == len(left_entries) == len(right_entries):
        relation = "fork"
        accepted = False
        violation = {
            "rule_id": "AUK010",
            "message": "same-size catalogs differ despite identical segment entries",
        }
    elif common == len(left_entries):
        if candidate["generation"] <= previous["generation"]:
            relation = "generation-regression"
            accepted = False
            violation = {
                "rule_id": "AUK011",
                "message": "candidate catalog extends segments without increasing generation",
            }
        elif (
            candidate["generation"] == previous["generation"] + 1
            and candidate["previous_catalog_id"] != previous["catalog_id"]
        ):
            relation = "fork"
            accepted = False
            violation = {
                "rule_id": "AUK010",
                "message": "direct candidate generation does not retain the previous catalog ID",
            }
        else:
            relation = "right-descendant"
            accepted = True
            direct = (
                candidate["generation"] == previous["generation"] + 1
                and candidate["previous_catalog_id"] == previous["catalog_id"]
            )
            violation = None
    elif common == len(right_entries):
        relation = "rollback"
        accepted = False
        violation = {
            "rule_id": "AUK009",
            "message": "candidate catalog is an older prefix of the retained catalog",
        }
    else:
        relation = "fork"
        accepted = False
        violation = {
            "rule_id": "AUK010",
            "message": "candidate catalog diverges from the retained segment history",
        }

    core = {
        "lineage_version": 1,
        "accepted": accepted,
        "relation": relation,
        "direct_predecessor_verified": direct,
        "previous": {
            "catalog_id": previous["catalog_id"],
            "generation": previous["generation"],
            "segment_count": previous["segment_count"],
            "latest_segment_id": previous["latest_segment_id"],
        },
        "candidate": {
            "catalog_id": candidate["catalog_id"],
            "generation": candidate["generation"],
            "segment_count": candidate["segment_count"],
            "latest_segment_id": candidate["latest_segment_id"],
        },
        "common": {
            "segment_count": common,
            "latest_segment_id": (
                left_entries[common - 1]["segment_id"] if common else None
            ),
        },
        "violations": [violation] if violation else [],
    }
    return {
        **core,
        "lineage_id": _identifier(b"audit-catalog-lineage-v1", core),
    }


def _denial_report(
    lineage_report: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    violation = lineage_report["violations"][0]
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "accepted": False,
        "relation": lineage_report["relation"],
        "direct_predecessor_verified": False,
        "previous": _checkpoint_reference(previous_checkpoint),
        "candidate": _checkpoint_reference(candidate_checkpoint),
        "common": lineage_report["common"],
        "violations": [violation],
    }
    return {
        **core,
        "decision_id": _identifier(b"audit-catalog-consistency-decision-v1", core),
    }


def _checkpoint_matches_catalog(
    checkpoint: dict[str, Any], catalog: dict[str, Any], label: str
) -> dict[str, Any]:
    try:
        return checkpoint_matches_catalog(checkpoint, catalog)
    except AuditCatalogCheckpointError as exc:
        raise AuditCatalogConsistencyError(
            f"{label} checkpoint does not match its catalog: {exc}",
            rule_id="AUK004",
            denied=exc.denied,
        ) from exc


def create_consistency_proof(
    previous_catalog: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_catalog: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    """Create compact evidence for identical or append-only descendant catalogs."""
    previous = _validate_catalog(previous_catalog)
    candidate = _validate_catalog(candidate_catalog)
    previous_cp = _checkpoint_matches_catalog(
        previous_checkpoint, previous, "previous"
    )
    candidate_cp = _checkpoint_matches_catalog(
        candidate_checkpoint, candidate, "candidate"
    )
    lineage_report = catalog_lineage(previous, candidate)
    if not lineage_report["accepted"]:
        raise AuditCatalogConsistencyDenied(
            _denial_report(lineage_report, previous_cp, candidate_cp)
        )

    previous_count = previous["segment_count"]
    candidate_count = candidate["segment_count"]
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "algorithm": CONSISTENCY_ALGORITHM,
        "relation": lineage_report["relation"],
        "direct_predecessor_verified": lineage_report[
            "direct_predecessor_verified"
        ],
        "previous": _checkpoint_reference(previous_cp),
        "candidate": _checkpoint_reference(candidate_cp),
        "previous_frontier": _segments_for_entries(
            previous["segments"], 0, previous_count
        ),
        "append_frontier": _segments_for_entries(
            candidate["segments"], previous_count, candidate_count
        ),
    }
    return {
        **core,
        "consistency_id": _identifier(b"audit-catalog-consistency-proof-v1", core),
    }


def validate_consistency_proof(value: Any) -> dict[str, Any]:
    root = _exact_fields(value, CONSISTENCY_FIELDS, "catalog consistency proof")
    if root["consistency_version"] != CONSISTENCY_VERSION:
        raise AuditCatalogConsistencyError(
            f"consistency proof version must be {CONSISTENCY_VERSION}",
            rule_id="AUK002",
        )
    if root["algorithm"] != CONSISTENCY_ALGORITHM:
        raise AuditCatalogConsistencyError(
            "consistency proof algorithm is unsupported",
            rule_id="AUK002",
        )
    previous = _validate_checkpoint_reference(root["previous"], "previous checkpoint")
    candidate = _validate_checkpoint_reference(root["candidate"], "candidate checkpoint")
    previous_count = previous["segment_count"]
    candidate_count = candidate["segment_count"]
    if previous_count > candidate_count:
        raise AuditCatalogConsistencyError(
            "consistency proof attempts to move to an older checkpoint",
            rule_id="AUK009",
            denied=True,
        )
    expected_relation = "same" if previous_count == candidate_count else "right-descendant"
    if root["relation"] != expected_relation:
        raise AuditCatalogConsistencyError(
            "consistency relation does not match checkpoint sizes",
            rule_id="AUK005",
        )
    if expected_relation == "same" and previous != candidate:
        raise AuditCatalogConsistencyError(
            "same-size consistency proof requires identical checkpoints",
            rule_id="AUK010",
            denied=True,
        )
    if expected_relation == "right-descendant" and candidate["generation"] <= previous[
        "generation"
    ]:
        raise AuditCatalogConsistencyError(
            "candidate generation does not increase with its segment count",
            rule_id="AUK011",
            denied=True,
        )
    expected_direct = (
        expected_relation == "right-descendant"
        and candidate["generation"] == previous["generation"] + 1
        and candidate["previous_catalog_id"] == previous["catalog_id"]
    )
    if root["direct_predecessor_verified"] is not expected_direct:
        raise AuditCatalogConsistencyError(
            "direct predecessor marker does not match checkpoint lineage",
            rule_id="AUK005",
        )
    if (
        expected_relation == "right-descendant"
        and candidate["generation"] == previous["generation"] + 1
        and not expected_direct
    ):
        raise AuditCatalogConsistencyError(
            "direct candidate generation does not retain the previous catalog ID",
            rule_id="AUK010",
            denied=True,
        )

    previous_frontier = _validate_frontier(
        root["previous_frontier"], 0, previous_count, "previous frontier"
    )
    append_frontier = _validate_frontier(
        root["append_frontier"], previous_count, candidate_count, "append frontier"
    )
    previous_root, candidate_root = _reconstruct_roots(
        previous_frontier,
        append_frontier,
        previous_count,
        candidate_count,
    )
    if previous_root != previous["merkle_root"]:
        raise AuditCatalogConsistencyError(
            "proof does not reconstruct the previous Merkle root",
            rule_id="AUK006",
        )
    if candidate_root != candidate["merkle_root"]:
        raise AuditCatalogConsistencyError(
            "proof does not reconstruct the candidate Merkle root",
            rule_id="AUK006",
        )
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "algorithm": CONSISTENCY_ALGORITHM,
        "relation": expected_relation,
        "direct_predecessor_verified": expected_direct,
        "previous": previous,
        "candidate": candidate,
        "previous_frontier": previous_frontier,
        "append_frontier": append_frontier,
    }
    consistency_id = _hash(root["consistency_id"], "consistency id")
    if consistency_id != _identifier(b"audit-catalog-consistency-proof-v1", core):
        raise AuditCatalogConsistencyError(
            "consistency ID does not match its canonical payload",
            rule_id="AUK003",
        )
    return {**core, "consistency_id": consistency_id}


def proof_matches_checkpoints(
    proof: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    normalized = validate_consistency_proof(proof)
    try:
        previous = _checkpoint_reference(validate_checkpoint(previous_checkpoint))
        candidate = _checkpoint_reference(validate_checkpoint(candidate_checkpoint))
    except AuditCatalogCheckpointError as exc:
        raise AuditCatalogConsistencyError(
            f"checkpoint validation failed: {exc}",
            rule_id="AUK004",
            denied=exc.denied,
        ) from exc
    if normalized["previous"] != previous or normalized["candidate"] != candidate:
        raise AuditCatalogConsistencyError(
            "consistency proof checkpoint references do not match supplied checkpoints",
            rule_id="AUK004",
            denied=True,
        )
    return normalized


def _safe_parent(path: Path) -> Path:
    parent = path.parent
    cursor = parent
    missing: list[Path] = []
    while not cursor.exists():
        missing.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    if cursor.is_symlink() or not cursor.is_dir():
        raise AuditCatalogConsistencyError(
            "output parent must be a regular non-symlink directory",
            rule_id="AUK001",
        )
    for directory in reversed(missing):
        directory.mkdir()
    if parent.is_symlink() or not parent.is_dir():
        raise AuditCatalogConsistencyError(
            "output parent must be a regular non-symlink directory",
            rule_id="AUK001",
        )
    return parent


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, payload: dict[str, Any]) -> None:
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise AuditCatalogConsistencyError(
            "consistency proof output must not already exist or be a symlink",
            rule_id="AUK008",
        )
    parent = _safe_parent(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(_canonical_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise AuditCatalogConsistencyError(
                "consistency proof output appeared during creation",
                rule_id="AUK008",
            ) from exc
        _fsync_directory(parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_canonical(
    path: Path,
    validator: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditCatalogConsistencyError(
            "consistency proof must be a regular non-symlink file",
            rule_id="AUK001",
        )
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_CONSISTENCY_BYTES:
        raise AuditCatalogConsistencyError(
            "consistency proof size is outside the reviewed boundary",
            rule_id="AUK002",
        )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        _DuplicateKeyError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise AuditCatalogConsistencyError(
            f"consistency proof is not strict JSON: {exc}",
            rule_id="AUK002",
        ) from exc
    normalized = validator(payload)
    if raw != _canonical_bytes(normalized):
        raise AuditCatalogConsistencyError(
            "consistency proof is not canonically serialized",
            rule_id="AUK002",
        )
    return normalized


def load_consistency_proof(path: Path) -> dict[str, Any]:
    return _load_canonical(path, validate_consistency_proof)


def _pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuditCatalogConsistencyError(
            f"{label} must be a string",
            rule_id="AUK002",
        )
    return _hash(value.lower(), label)


def _verified_catalog(
    path: Path,
    expected_catalog_id: str,
    active_path: Path | None,
    label: str,
) -> dict[str, Any]:
    expected = _pin(expected_catalog_id, f"expected {label} catalog id")
    try:
        verify_catalog(
            path,
            expected_catalog_id=expected,
            active_path=active_path,
            require_complete_discovery=False,
        )
        return load_catalog(path, expected_catalog_id=expected)
    except AuditCatalogError as exc:
        rule = "AUK007" if exc.rule_id == "AUC007" else "AUK004"
        raise AuditCatalogConsistencyError(
            f"{label} catalog verification failed: {exc}",
            rule_id=rule,
            denied=exc.denied,
        ) from exc


def _pinned_checkpoint(path: Path, expected_id: str, label: str) -> dict[str, Any]:
    expected = _pin(expected_id, f"expected {label} checkpoint id")
    try:
        checkpoint = load_checkpoint(path)
    except AuditCatalogCheckpointError as exc:
        raise AuditCatalogConsistencyError(
            f"{label} checkpoint verification failed: {exc}",
            rule_id="AUK004",
            denied=exc.denied,
        ) from exc
    if checkpoint["checkpoint_id"] != expected:
        raise AuditCatalogConsistencyError(
            f"{label} checkpoint differs from the externally retained pin",
            rule_id="AUK007",
            denied=True,
        )
    return checkpoint


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    if stream is None:
        import sys

        stream = sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
        return
    lines: list[str] = []
    for key in (
        "accepted",
        "valid",
        "created",
        "relation",
        "direct_predecessor_verified",
        "consistency_id",
        "lineage_id",
        "decision_id",
    ):
        if key in payload:
            lines.append(f"{key}: {payload[key]}")
    for violation in payload.get("violations", []):
        lines.append(f"- {violation['rule_id']}: {violation['message']}")
    print("\n".join(lines), file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prove = subparsers.add_parser("prove")
    prove.add_argument("previous_catalog", type=Path)
    prove.add_argument("previous_checkpoint", type=Path)
    prove.add_argument("candidate_catalog", type=Path)
    prove.add_argument("candidate_checkpoint", type=Path)
    prove.add_argument("output", type=Path)
    prove.add_argument("--expected-previous-catalog-id", required=True)
    prove.add_argument("--expected-previous-checkpoint-id", required=True)
    prove.add_argument("--expected-candidate-catalog-id", required=True)
    prove.add_argument("--expected-candidate-checkpoint-id", required=True)
    prove.add_argument("--previous-active", type=Path)
    prove.add_argument("--candidate-active", type=Path)
    prove.add_argument("--format", choices=("json", "text"), default="json")

    verify = subparsers.add_parser("verify")
    verify.add_argument("proof", type=Path)
    verify.add_argument("previous_checkpoint", type=Path)
    verify.add_argument("candidate_checkpoint", type=Path)
    verify.add_argument("--expected-previous-catalog-id", required=True)
    verify.add_argument("--expected-previous-checkpoint-id", required=True)
    verify.add_argument("--expected-candidate-catalog-id", required=True)
    verify.add_argument("--expected-candidate-checkpoint-id", required=True)
    verify.add_argument("--format", choices=("json", "text"), default="json")

    lineage_parser = subparsers.add_parser("lineage")
    lineage_parser.add_argument("previous_catalog", type=Path)
    lineage_parser.add_argument("previous_checkpoint", type=Path)
    lineage_parser.add_argument("candidate_catalog", type=Path)
    lineage_parser.add_argument("candidate_checkpoint", type=Path)
    lineage_parser.add_argument("--expected-previous-catalog-id", required=True)
    lineage_parser.add_argument("--expected-previous-checkpoint-id", required=True)
    lineage_parser.add_argument("--expected-candidate-catalog-id", required=True)
    lineage_parser.add_argument("--expected-candidate-checkpoint-id", required=True)
    lineage_parser.add_argument("--previous-active", type=Path)
    lineage_parser.add_argument("--candidate-active", type=Path)
    lineage_parser.add_argument("--format", choices=("json", "text"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command in {"prove", "lineage"}:
            previous_catalog = _verified_catalog(
                args.previous_catalog,
                args.expected_previous_catalog_id,
                args.previous_active,
                "previous",
            )
            candidate_catalog = _verified_catalog(
                args.candidate_catalog,
                args.expected_candidate_catalog_id,
                args.candidate_active,
                "candidate",
            )
            previous_checkpoint = _pinned_checkpoint(
                args.previous_checkpoint,
                args.expected_previous_checkpoint_id,
                "previous",
            )
            candidate_checkpoint = _pinned_checkpoint(
                args.candidate_checkpoint,
                args.expected_candidate_checkpoint_id,
                "candidate",
            )
            _checkpoint_matches_catalog(
                previous_checkpoint, previous_catalog, "previous"
            )
            _checkpoint_matches_catalog(
                candidate_checkpoint, candidate_catalog, "candidate"
            )
            if args.command == "lineage":
                result = catalog_lineage(previous_catalog, candidate_catalog)
                _emit(result, args.format)
                return 0 if result["accepted"] else 1
            proof = create_consistency_proof(
                previous_catalog,
                previous_checkpoint,
                candidate_catalog,
                candidate_checkpoint,
            )
            _write_new(args.output, proof)
            _emit(
                {
                    "created": str(args.output),
                    "accepted": True,
                    "relation": proof["relation"],
                    "direct_predecessor_verified": proof[
                        "direct_predecessor_verified"
                    ],
                    "consistency_id": proof["consistency_id"],
                    "previous": proof["previous"],
                    "candidate": proof["candidate"],
                    "frontier_hashes": len(proof["previous_frontier"])
                    + len(proof["append_frontier"]),
                },
                args.format,
            )
            return 0

        proof = load_consistency_proof(args.proof)
        previous_checkpoint = _pinned_checkpoint(
            args.previous_checkpoint,
            args.expected_previous_checkpoint_id,
            "previous",
        )
        candidate_checkpoint = _pinned_checkpoint(
            args.candidate_checkpoint,
            args.expected_candidate_checkpoint_id,
            "candidate",
        )
        if previous_checkpoint["catalog"]["catalog_id"] != _pin(
            args.expected_previous_catalog_id, "expected previous catalog id"
        ):
            raise AuditCatalogConsistencyError(
                "previous checkpoint catalog differs from the external pin",
                rule_id="AUK007",
                denied=True,
            )
        if candidate_checkpoint["catalog"]["catalog_id"] != _pin(
            args.expected_candidate_catalog_id, "expected candidate catalog id"
        ):
            raise AuditCatalogConsistencyError(
                "candidate checkpoint catalog differs from the external pin",
                rule_id="AUK007",
                denied=True,
            )
        normalized = proof_matches_checkpoints(
            proof, previous_checkpoint, candidate_checkpoint
        )
        _emit(
            {
                "valid": True,
                "accepted": True,
                "relation": normalized["relation"],
                "direct_predecessor_verified": normalized[
                    "direct_predecessor_verified"
                ],
                "consistency_id": normalized["consistency_id"],
                "previous": normalized["previous"],
                "candidate": normalized["candidate"],
                "frontier_hashes": len(normalized["previous_frontier"])
                + len(normalized["append_frontier"]),
            },
            args.format,
        )
        return 0
    except AuditCatalogConsistencyDenied as exc:
        _emit(exc.report, args.format)
        return 1
    except AuditCatalogConsistencyError as exc:
        import sys

        _emit(
            {
                "valid": False,
                "accepted": False,
                "rule_id": exc.rule_id,
                "error": str(exc),
            },
            args.format,
            stream=sys.stderr,
        )
        return 1 if exc.denied else 2


if __name__ == "__main__":
    raise SystemExit(main())
