#!/usr/bin/env python3
"""Create and verify compact append-only proofs between audit trust checkpoints."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from agent_audit_trust import AuditBundleTrustError, canonical_json, load_state, validate_state
from agent_audit_trust_checkpoint import (
    AuditTrustCheckpointError,
    MERKLE_ALGORITHM,
    _entry,
    _head,
    _leaf_hash,
    _merkle_root,
    _node_hash,
    checkpoint_matches_state,
    lineage,
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
    "previous",
    "candidate",
    "previous_frontier",
    "append_frontier",
    "boundary_entry",
    "consistency_id",
}
CHECKPOINT_REFERENCE_FIELDS = {
    "checkpoint_id",
    "state_id",
    "entry_count",
    "head",
    "merkle_root",
}
FRONTIER_FIELDS = {"start", "size", "hash"}


class AuditTrustConsistencyError(ValueError):
    """Raised when audit trust consistency evidence cannot be processed safely."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "ATK002",
        denied: bool = False,
    ) -> None:
        super().__init__(message)
        self.rule_id = rule_id
        self.denied = denied


class AuditTrustConsistencyDenied(AuditTrustConsistencyError):
    """Raised when valid trust states are related by rollback or fork."""

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


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditTrustConsistencyError(
            f"{label} fields do not match the reviewed schema",
            rule_id="ATK002",
        )
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditTrustConsistencyError(
            f"{label} must be 64 lowercase hexadecimal characters",
            rule_id="ATK002",
        )
    return value


def _pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuditTrustConsistencyError(f"{label} must be a string", rule_id="ATK003")
    lowered = value.lower()
    if not HEX_64.fullmatch(lowered):
        raise AuditTrustConsistencyError(
            f"{label} must be 64 hexadecimal characters",
            rule_id="ATK003",
        )
    return lowered


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditTrustConsistencyError(
            f"{label} must be an integer greater than or equal to {minimum}",
            rule_id="ATK002",
        )
    return value


def _identifier(domain: bytes, payload: dict[str, Any]) -> str:
    return hashlib.sha256(domain + b"\x00" + canonical_json(payload)).hexdigest()


def _checkpoint_reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    try:
        normalized = validate_checkpoint(checkpoint)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustConsistencyError(
            f"checkpoint validation failed: {exc}",
            rule_id="ATK004",
            denied=exc.denied,
        ) from exc
    return {
        "checkpoint_id": normalized["checkpoint_id"],
        "state_id": normalized["state_id"],
        "entry_count": normalized["entry_count"],
        "head": normalized["head"],
        "merkle_root": normalized["merkle"]["root"],
    }


def _validate_checkpoint_reference(value: Any, label: str) -> dict[str, Any]:
    raw = _exact(value, CHECKPOINT_REFERENCE_FIELDS, label)
    try:
        head = _head(raw["head"])
    except AuditTrustCheckpointError as exc:
        raise AuditTrustConsistencyError(
            f"{label} head is invalid: {exc}", rule_id="ATK002"
        ) from exc
    normalized = {
        "checkpoint_id": _hash(raw["checkpoint_id"], f"{label} checkpoint id"),
        "state_id": _hash(raw["state_id"], f"{label} state id"),
        "entry_count": _integer(raw["entry_count"], f"{label} entry count", 1),
        "head": head,
        "merkle_root": _hash(raw["merkle_root"], f"{label} Merkle root"),
    }
    if normalized["head"]["sequence"] != normalized["entry_count"]:
        raise AuditTrustConsistencyError(
            f"{label} head sequence differs from its entry count",
            rule_id="ATK002",
        )
    if normalized != raw:
        raise AuditTrustConsistencyError(f"{label} is not canonical", rule_id="ATK002")
    return normalized


def _largest_power_at_most(value: int) -> int:
    if value < 1:
        raise AuditTrustConsistencyError(
            "compact range requires a positive size", rule_id="ATK005"
        )
    return 1 << (value.bit_length() - 1)


def range_layout(start: int, end: int) -> list[tuple[int, int]]:
    """Return the canonical maximal aligned power-of-two cover of [start, end)."""
    _integer(start, "range start")
    _integer(end, "range end")
    if end < start:
        raise AuditTrustConsistencyError(
            "range end must not precede range start", rule_id="ATK005"
        )
    result: list[tuple[int, int]] = []
    cursor = start
    while cursor < end:
        remaining = end - cursor
        if cursor == 0:
            size = _largest_power_at_most(remaining)
        else:
            size = cursor & -cursor
            while size > remaining:
                size >>= 1
        result.append((cursor, size))
        cursor += size
    return result


def append_layout(start: int, end: int) -> list[tuple[int, int]]:
    """Return a compact append cover with the first appended leaf exposed."""
    _integer(start, "append start")
    _integer(end, "append end")
    if end < start:
        raise AuditTrustConsistencyError(
            "append end must not precede append start", rule_id="ATK005"
        )
    if start == end:
        return []
    return [(start, 1), *range_layout(start + 1, end)]


def _frontier_segment(start: int, size: int, digest: bytes) -> dict[str, Any]:
    return {"start": start, "size": size, "hash": digest.hex()}


def _segments_for_layout(
    entries: list[dict[str, Any]], layout: list[tuple[int, int]]
) -> list[dict[str, Any]]:
    leaves = [_leaf_hash(entry) for entry in entries]
    return [
        _frontier_segment(start, size, _merkle_root(leaves[start : start + size]))
        for start, size in layout
    ]


def _validate_frontier(
    value: Any,
    expected: list[tuple[int, int]],
    label: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_FRONTIER_SEGMENTS:
        raise AuditTrustConsistencyError(
            f"{label} is malformed or exceeds the reviewed limit",
            rule_id="ATK005",
        )
    if len(value) != len(expected):
        raise AuditTrustConsistencyError(
            f"{label} does not use the canonical compact-range layout",
            rule_id="ATK005",
        )
    normalized: list[dict[str, Any]] = []
    for position, (raw, (expected_start, expected_size)) in enumerate(
        zip(value, expected), 1
    ):
        item = _exact(raw, FRONTIER_FIELDS, f"{label} segment {position}")
        start = _integer(item["start"], f"{label} segment start")
        size = _integer(item["size"], f"{label} segment size", 1)
        if start != expected_start or size != expected_size:
            raise AuditTrustConsistencyError(
                f"{label} does not use the canonical compact-range layout",
                rule_id="ATK005",
            )
        if size & (size - 1) or start % size:
            raise AuditTrustConsistencyError(
                f"{label} contains a non-aligned range", rule_id="ATK005"
            )
        normalized.append(
            {"start": start, "size": size, "hash": _hash(item["hash"], f"{label} hash")}
        )
    return normalized


def _forest_root(frontier: list[dict[str, Any]]) -> bytes:
    if not frontier:
        raise AuditTrustConsistencyError(
            "compact frontier must contain at least one segment", rule_id="ATK005"
        )
    end = frontier[-1]["start"] + frontier[-1]["size"]
    if [(item["start"], item["size"]) for item in frontier] != range_layout(0, end):
        raise AuditTrustConsistencyError(
            "compact frontier does not match the canonical prefix layout",
            rule_id="ATK005",
        )
    root = bytes.fromhex(frontier[-1]["hash"])
    for item in reversed(frontier[:-1]):
        root = _node_hash(bytes.fromhex(item["hash"]), root)
    return root


def _append_segment(forest: list[dict[str, Any]], segment: dict[str, Any]) -> None:
    if forest:
        expected_start = forest[-1]["start"] + forest[-1]["size"]
        if segment["start"] != expected_start:
            raise AuditTrustConsistencyError(
                "compact consistency segments are not contiguous", rule_id="ATK005"
            )
    elif segment["start"] != 0:
        raise AuditTrustConsistencyError(
            "compact consistency frontier must begin at zero", rule_id="ATK005"
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
        raise AuditTrustConsistencyError(
            "previous frontier does not cover the previous checkpoint",
            rule_id="ATK005",
        )
    forest = [dict(item) for item in previous_frontier]
    for item in append_frontier:
        _append_segment(forest, item)
    if [(item["start"], item["size"]) for item in forest] != range_layout(
        0, candidate_count
    ):
        raise AuditTrustConsistencyError(
            "proof does not reconstruct the canonical candidate frontier",
            rule_id="ATK005",
        )
    return previous_root, _forest_root(forest).hex()


def _denial_report(
    relation_report: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    relation = relation_report["relation"]
    if relation == "rollback":
        violation = {
            "rule_id": "ATK009",
            "message": "candidate audit trust state is an older prefix of the retained state",
        }
    else:
        violation = {
            "rule_id": "ATK010",
            "message": "candidate audit trust state diverges from the retained history",
        }
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "accepted": False,
        "relation": relation,
        "previous": _checkpoint_reference(previous_checkpoint),
        "candidate": _checkpoint_reference(candidate_checkpoint),
        "common": relation_report["common"],
        "violations": [violation],
    }
    return {
        **core,
        "decision_id": _identifier(b"audit-trust-consistency-decision-v1", core),
    }


def _checkpoint_matches_state(
    checkpoint: dict[str, Any], state: dict[str, Any], label: str
) -> dict[str, Any]:
    try:
        return checkpoint_matches_state(checkpoint, state)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustConsistencyError(
            f"{label} checkpoint does not match its trust state: {exc}",
            rule_id="ATK004",
            denied=exc.denied,
        ) from exc


def create_consistency_proof(
    previous_state: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_state: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    """Create compact evidence for identical or append-only descendant trust states."""
    try:
        previous = validate_state(previous_state)
        candidate = validate_state(candidate_state)
    except AuditBundleTrustError as exc:
        raise AuditTrustConsistencyError(str(exc), rule_id="ATK002") from exc
    previous_cp = _checkpoint_matches_state(previous_checkpoint, previous, "previous")
    candidate_cp = _checkpoint_matches_state(candidate_checkpoint, candidate, "candidate")
    try:
        relation_report = lineage(previous, candidate)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustConsistencyError(str(exc), rule_id="ATK002") from exc
    if not relation_report["accepted"]:
        raise AuditTrustConsistencyDenied(
            _denial_report(relation_report, previous_cp, candidate_cp)
        )

    previous_count = len(previous["entries"])
    candidate_count = len(candidate["entries"])
    relation = relation_report["relation"]
    boundary_entry = (
        candidate["entries"][previous_count] if relation == "right-descendant" else None
    )
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "algorithm": CONSISTENCY_ALGORITHM,
        "relation": relation,
        "previous": _checkpoint_reference(previous_cp),
        "candidate": _checkpoint_reference(candidate_cp),
        "previous_frontier": _segments_for_layout(
            previous["entries"], range_layout(0, previous_count)
        ),
        "append_frontier": _segments_for_layout(
            candidate["entries"], append_layout(previous_count, candidate_count)
        ),
        "boundary_entry": boundary_entry,
    }
    return {
        **core,
        "consistency_id": _identifier(b"audit-trust-consistency-proof-v1", core),
    }


def _validate_boundary(
    value: Any,
    relation: str,
    previous: dict[str, Any],
    candidate: dict[str, Any],
    append_frontier: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if relation == "same":
        if value is not None or append_frontier:
            raise AuditTrustConsistencyError(
                "same-state proof must not contain append evidence", rule_id="ATK005"
            )
        return None
    if value is None:
        raise AuditTrustConsistencyError(
            "descendant proof is missing its first appended trust entry",
            rule_id="ATK011",
        )
    try:
        entry = _entry(value)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustConsistencyError(
            f"boundary trust entry is invalid: {exc}", rule_id="ATK011"
        ) from exc
    expected_sequence = previous["entry_count"] + 1
    if entry["sequence"] != expected_sequence or entry["kind"] != "transition":
        raise AuditTrustConsistencyError(
            "boundary trust entry sequence or kind is inconsistent",
            rule_id="ATK011",
        )
    if entry["previous_entry_hash"] != previous["head"]["entry_hash"]:
        raise AuditTrustConsistencyError(
            "boundary trust entry does not retain the previous head hash",
            rule_id="ATK011",
        )
    transition = entry["transition"]
    if (
        transition["previous_checkpoint_id"] != previous["head"]["checkpoint_id"]
        or transition["previous_catalog_id"] != previous["head"]["catalog_id"]
    ):
        raise AuditTrustConsistencyError(
            "boundary trust entry does not retain previous checkpoint/catalog evidence",
            rule_id="ATK011",
        )
    generation_delta = entry["evidence"]["generation"] - previous["head"]["generation"]
    if generation_delta < 1 or transition["generation_delta"] != generation_delta:
        raise AuditTrustConsistencyError(
            "boundary trust entry generation transition is inconsistent",
            rule_id="ATK011",
        )
    if not append_frontier or append_frontier[0]["start"] != previous["entry_count"]:
        raise AuditTrustConsistencyError(
            "append frontier does not begin at the trust boundary", rule_id="ATK005"
        )
    if append_frontier[0]["size"] != 1 or append_frontier[0]["hash"] != _leaf_hash(entry).hex():
        raise AuditTrustConsistencyError(
            "boundary trust entry is not authenticated by the append frontier",
            rule_id="ATK011",
        )
    if candidate["head"]["generation"] <= previous["head"]["generation"]:
        raise AuditTrustConsistencyError(
            "candidate checkpoint head does not advance generation",
            rule_id="ATK011",
        )
    return entry


def validate_consistency_proof(value: Any) -> dict[str, Any]:
    root = _exact(value, CONSISTENCY_FIELDS, "audit trust consistency proof")
    if root["consistency_version"] != CONSISTENCY_VERSION:
        raise AuditTrustConsistencyError(
            f"consistency proof version must be {CONSISTENCY_VERSION}",
            rule_id="ATK002",
        )
    if root["algorithm"] != CONSISTENCY_ALGORITHM:
        raise AuditTrustConsistencyError(
            "consistency proof algorithm is unsupported", rule_id="ATK002"
        )
    previous = _validate_checkpoint_reference(root["previous"], "previous checkpoint")
    candidate = _validate_checkpoint_reference(root["candidate"], "candidate checkpoint")
    previous_count = previous["entry_count"]
    candidate_count = candidate["entry_count"]
    if previous_count > candidate_count:
        raise AuditTrustConsistencyError(
            "consistency proof attempts to move to an older checkpoint",
            rule_id="ATK009",
            denied=True,
        )
    expected_relation = "same" if previous_count == candidate_count else "right-descendant"
    if root["relation"] != expected_relation:
        raise AuditTrustConsistencyError(
            "consistency relation does not match checkpoint sizes", rule_id="ATK005"
        )
    if expected_relation == "same" and previous != candidate:
        raise AuditTrustConsistencyError(
            "same-size consistency proof requires identical checkpoints",
            rule_id="ATK010",
            denied=True,
        )

    previous_frontier = _validate_frontier(
        root["previous_frontier"], range_layout(0, previous_count), "previous frontier"
    )
    append_frontier = _validate_frontier(
        root["append_frontier"],
        append_layout(previous_count, candidate_count),
        "append frontier",
    )
    previous_root, candidate_root = _reconstruct_roots(
        previous_frontier, append_frontier, previous_count, candidate_count
    )
    if previous_root != previous["merkle_root"]:
        raise AuditTrustConsistencyError(
            "proof does not reconstruct the previous Merkle root", rule_id="ATK006"
        )
    if candidate_root != candidate["merkle_root"]:
        raise AuditTrustConsistencyError(
            "proof does not reconstruct the candidate Merkle root", rule_id="ATK006"
        )
    boundary_entry = _validate_boundary(
        root["boundary_entry"], expected_relation, previous, candidate, append_frontier
    )
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "algorithm": CONSISTENCY_ALGORITHM,
        "relation": expected_relation,
        "previous": previous,
        "candidate": candidate,
        "previous_frontier": previous_frontier,
        "append_frontier": append_frontier,
        "boundary_entry": boundary_entry,
    }
    consistency_id = _hash(root["consistency_id"], "consistency id")
    if consistency_id != _identifier(b"audit-trust-consistency-proof-v1", core):
        raise AuditTrustConsistencyError(
            "consistency ID does not match its canonical payload", rule_id="ATK007"
        )
    return {**core, "consistency_id": consistency_id}


def proof_matches_checkpoints(
    proof: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    normalized = validate_consistency_proof(proof)
    previous = _checkpoint_reference(previous_checkpoint)
    candidate = _checkpoint_reference(candidate_checkpoint)
    if normalized["previous"] != previous or normalized["candidate"] != candidate:
        raise AuditTrustConsistencyError(
            "consistency proof checkpoint references do not match supplied checkpoints",
            rule_id="ATK004",
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
        raise AuditTrustConsistencyError(
            "output parent must be a regular non-symlink directory", rule_id="ATK001"
        )
    for directory in reversed(missing):
        directory.mkdir()
    if parent.is_symlink() or not parent.is_dir():
        raise AuditTrustConsistencyError(
            "output parent must be a regular non-symlink directory", rule_id="ATK001"
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
        raise AuditTrustConsistencyError(
            "consistency proof output must not already exist or be a symlink",
            rule_id="ATK008",
        )
    parent = _safe_parent(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(canonical_json(payload))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise AuditTrustConsistencyError(
                "consistency proof output appeared during creation", rule_id="ATK008"
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
        raise AuditTrustConsistencyError(
            "consistency proof must be a regular non-symlink file", rule_id="ATK001"
        )
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_CONSISTENCY_BYTES:
        raise AuditTrustConsistencyError(
            "consistency proof size is outside the reviewed boundary", rule_id="ATK002"
        )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, _DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
        raise AuditTrustConsistencyError(
            f"consistency proof is not strict JSON: {exc}", rule_id="ATK002"
        ) from exc
    normalized = validator(payload)
    if raw != canonical_json(normalized):
        raise AuditTrustConsistencyError(
            "consistency proof is not canonically serialized", rule_id="ATK002"
        )
    return normalized


def load_consistency_proof(path: Path) -> dict[str, Any]:
    return _load_canonical(path, validate_consistency_proof)


def _pinned_state(path: Path, expected_id: str, label: str) -> dict[str, Any]:
    expected = _pin(expected_id, f"expected {label} state id")
    try:
        state = load_state(path)
    except AuditBundleTrustError as exc:
        raise AuditTrustConsistencyError(
            f"{label} state verification failed: {exc}", rule_id="ATK004"
        ) from exc
    if state["state_id"] != expected:
        raise AuditTrustConsistencyError(
            f"{label} state differs from the externally retained pin",
            rule_id="ATK003",
            denied=True,
        )
    return state


def _pinned_checkpoint(path: Path, expected_id: str, label: str) -> dict[str, Any]:
    expected = _pin(expected_id, f"expected {label} checkpoint id")
    try:
        checkpoint = load_checkpoint(path)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustConsistencyError(
            f"{label} checkpoint verification failed: {exc}",
            rule_id="ATK004",
            denied=exc.denied,
        ) from exc
    if checkpoint["checkpoint_id"] != expected:
        raise AuditTrustConsistencyError(
            f"{label} checkpoint differs from the externally retained pin",
            rule_id="ATK003",
            denied=True,
        )
    return checkpoint


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    if stream is None:
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
        "consistency_id",
        "decision_id",
        "frontier_hashes",
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
    prove.add_argument("previous_state", type=Path)
    prove.add_argument("previous_checkpoint", type=Path)
    prove.add_argument("candidate_state", type=Path)
    prove.add_argument("candidate_checkpoint", type=Path)
    prove.add_argument("output", type=Path)
    prove.add_argument("--expected-previous-state-id", required=True)
    prove.add_argument("--expected-previous-checkpoint-id", required=True)
    prove.add_argument("--expected-candidate-state-id", required=True)
    prove.add_argument("--expected-candidate-checkpoint-id", required=True)
    prove.add_argument("--format", choices=("json", "text"), default="json")

    verify = subparsers.add_parser("verify")
    verify.add_argument("proof", type=Path)
    verify.add_argument("previous_checkpoint", type=Path)
    verify.add_argument("candidate_checkpoint", type=Path)
    verify.add_argument("--expected-previous-checkpoint-id", required=True)
    verify.add_argument("--expected-candidate-checkpoint-id", required=True)
    verify.add_argument("--format", choices=("json", "text"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command == "prove":
            previous_state = _pinned_state(
                args.previous_state, args.expected_previous_state_id, "previous"
            )
            candidate_state = _pinned_state(
                args.candidate_state, args.expected_candidate_state_id, "candidate"
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
            proof = create_consistency_proof(
                previous_state,
                previous_checkpoint,
                candidate_state,
                candidate_checkpoint,
            )
            _write_new(args.output, proof)
            _emit(
                {
                    "accepted": True,
                    "valid": True,
                    "created": str(args.output),
                    "relation": proof["relation"],
                    "consistency_id": proof["consistency_id"],
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
        normalized = proof_matches_checkpoints(
            proof, previous_checkpoint, candidate_checkpoint
        )
        _emit(
            {
                "accepted": True,
                "valid": True,
                "relation": normalized["relation"],
                "consistency_id": normalized["consistency_id"],
                "frontier_hashes": len(normalized["previous_frontier"])
                + len(normalized["append_frontier"]),
            },
            args.format,
        )
        return 0
    except AuditTrustConsistencyDenied as exc:
        _emit(exc.report, args.format, stream=sys.stderr)
        return 1
    except AuditTrustConsistencyError as exc:
        _emit(
            {
                "accepted": False,
                "valid": False,
                "rule_id": exc.rule_id,
                "error": str(exc),
            },
            args.format,
            stream=sys.stderr,
        )
        return 1 if exc.denied else 2


if __name__ == "__main__":
    raise SystemExit(main())
