#!/usr/bin/env python3
"""Create and verify compact append-only consistency proofs between release checkpoints."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

try:
    from scripts.release_checkpoint import (
        CheckpointError,
        _checkpoint_reference,
        _leaf_hash,
        _merkle_root,
        _node_hash,
        _write_new,
        canonical_json,
        checkpoint_matches_state,
        lineage,
        load_checkpoint,
    )
    from scripts.release_trust import TrustStateError, load_state, validate_state
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from release_checkpoint import (
        CheckpointError,
        _checkpoint_reference,
        _leaf_hash,
        _merkle_root,
        _node_hash,
        _write_new,
        canonical_json,
        checkpoint_matches_state,
        lineage,
        load_checkpoint,
    )
    from release_trust import TrustStateError, load_state, validate_state

CONSISTENCY_VERSION = 1
CONSISTENCY_ALGORITHM = "sha256-rfc6962-compact-range-v1"
MAX_CONSISTENCY_BYTES = 1_000_000
MAX_SEGMENTS = 256
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class ConsistencyError(ValueError):
    """Raised when compact consistency evidence or pinned input is invalid."""


class ConsistencyDenied(ConsistencyError):
    """Raised when valid trust states are related by rollback or fork."""

    def __init__(self, report: dict[str, Any]):
        super().__init__(report["violations"][0]["message"])
        self.report = report


def _sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _exact_fields(payload: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ConsistencyError(f"{label} fields do not match the reviewed schema")
    return payload


def _hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ConsistencyError(f"{label} is malformed")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConsistencyError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def _checkpoint_ref(payload: Any, label: str) -> dict[str, Any]:
    raw = _exact_fields(
        payload,
        {"checkpoint_id", "project", "state_id", "entry_count", "merkle_root"},
        label,
    )
    project = raw["project"]
    if not isinstance(project, str) or not project or project != project.strip():
        raise ConsistencyError(f"{label} project must be a canonical non-empty string")
    return {
        "checkpoint_id": _hex(raw["checkpoint_id"], f"{label} checkpoint id"),
        "project": project,
        "state_id": _hex(raw["state_id"], f"{label} state id"),
        "entry_count": _integer(raw["entry_count"], f"{label} entry count", 1),
        "merkle_root": _hex(raw["merkle_root"], f"{label} Merkle root"),
    }


def _largest_power_at_most(value: int) -> int:
    if value < 1:
        raise ConsistencyError("compact range requires a positive size")
    return 1 << (value.bit_length() - 1)


def range_layout(start: int, end: int) -> list[tuple[int, int]]:
    """Return the canonical maximal aligned power-of-two cover of [start, end)."""
    _integer(start, "range start")
    _integer(end, "range end")
    if end < start:
        raise ConsistencyError("range end must not precede range start")
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


def _segment(start: int, size: int, digest: bytes) -> dict[str, Any]:
    return {"start": start, "size": size, "hash": digest.hex()}


def _segments_for_entries(entries: list[dict[str, Any]], start: int, end: int) -> list[dict[str, Any]]:
    leaves = [_leaf_hash(entry) for entry in entries]
    result: list[dict[str, Any]] = []
    for offset, size in range_layout(start, end):
        result.append(_segment(offset, size, _merkle_root(leaves[offset : offset + size])))
    return result


def _validate_segments(
    payload: Any, start: int, end: int, label: str
) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or len(payload) > MAX_SEGMENTS:
        raise ConsistencyError(f"{label} is malformed or exceeds the reviewed limit")
    expected = range_layout(start, end)
    if len(payload) != len(expected):
        raise ConsistencyError(f"{label} does not use the canonical compact-range layout")
    normalized: list[dict[str, Any]] = []
    for index, (raw, (expected_start, expected_size)) in enumerate(zip(payload, expected), 1):
        item = _exact_fields(raw, {"start", "size", "hash"}, f"{label} segment {index}")
        segment_start = _integer(item["start"], f"{label} segment {index} start")
        segment_size = _integer(item["size"], f"{label} segment {index} size", 1)
        if segment_start != expected_start or segment_size != expected_size:
            raise ConsistencyError(f"{label} does not use the canonical compact-range layout")
        if segment_size & (segment_size - 1) or segment_start % segment_size:
            raise ConsistencyError(f"{label} segment {index} is not an aligned power-of-two range")
        normalized.append(
            {"start": segment_start, "size": segment_size, "hash": _hex(item["hash"], f"{label} segment hash")}
        )
    return normalized


def _forest_root(segments: list[dict[str, Any]]) -> bytes:
    if not segments:
        raise ConsistencyError("compact forest must contain at least one segment")
    end = segments[-1]["start"] + segments[-1]["size"]
    if [(item["start"], item["size"]) for item in segments] != range_layout(0, end):
        raise ConsistencyError("compact forest does not match the canonical prefix layout")
    root = bytes.fromhex(segments[-1]["hash"])
    for item in reversed(segments[:-1]):
        root = _node_hash(bytes.fromhex(item["hash"]), root)
    return root


def _append_segment(forest: list[dict[str, Any]], segment: dict[str, Any]) -> None:
    if forest:
        expected_start = forest[-1]["start"] + forest[-1]["size"]
        if segment["start"] != expected_start:
            raise ConsistencyError("compact consistency segments are not contiguous")
    elif segment["start"] != 0:
        raise ConsistencyError("compact consistency forest must begin at zero")
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
        merged = _segment(
            left["start"],
            size * 2,
            _node_hash(bytes.fromhex(left["hash"]), bytes.fromhex(right["hash"])),
        )
        forest[-2:] = [merged]


def _reconstruct_roots(
    previous_frontier: list[dict[str, Any]], append_frontier: list[dict[str, Any]],
    previous_count: int, candidate_count: int,
) -> tuple[str, str]:
    if not previous_frontier:
        raise ConsistencyError("previous compact frontier must not be empty")
    previous_root = _forest_root(previous_frontier).hex()
    forest = [dict(item) for item in previous_frontier]
    for item in append_frontier:
        _append_segment(forest, item)
    if [(item["start"], item["size"]) for item in forest] != range_layout(0, candidate_count):
        raise ConsistencyError("consistency proof does not reconstruct the canonical candidate forest")
    if previous_frontier[-1]["start"] + previous_frontier[-1]["size"] != previous_count:
        raise ConsistencyError("previous compact frontier does not cover the previous checkpoint")
    return previous_root, _forest_root(forest).hex()


def _denial_report(relation_report: dict[str, Any]) -> dict[str, Any]:
    relation = relation_report["relation"]
    if relation == "rollback":
        violation = {"rule_id": "CNS010", "message": "candidate trust state is older than the retained state"}
    elif relation == "fork":
        violation = {"rule_id": "CNS011", "message": "candidate trust state diverges from the retained history"}
    else:
        raise ConsistencyError("consistency proof requires identical or right-descendant trust states")
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "accepted": False,
        "relation": relation,
        "project": relation_report["project"],
        "previous": relation_report["left"],
        "candidate": relation_report["right"],
        "common": relation_report["common"],
        "violations": [violation],
    }
    return {**core, "decision_id": _sha256(core)}


def create_consistency_proof(
    previous_state: dict[str, Any], previous_checkpoint: dict[str, Any],
    candidate_state: dict[str, Any], candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    previous = validate_state(previous_state)
    candidate = validate_state(candidate_state)
    previous_cp = checkpoint_matches_state(previous_checkpoint, previous)
    candidate_cp = checkpoint_matches_state(candidate_checkpoint, candidate)
    try:
        relation_report = lineage(previous, candidate)
    except CheckpointError as exc:
        raise ConsistencyError(str(exc)) from exc
    if not relation_report["accepted"]:
        raise ConsistencyDenied(_denial_report(relation_report))
    previous_count = len(previous["entries"])
    candidate_count = len(candidate["entries"])
    previous_frontier = _segments_for_entries(previous["entries"], 0, previous_count)
    append_frontier = _segments_for_entries(candidate["entries"], previous_count, candidate_count)
    relation = "same" if previous_count == candidate_count else "right-descendant"
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "algorithm": CONSISTENCY_ALGORITHM,
        "relation": relation,
        "previous": _checkpoint_reference(previous_cp),
        "candidate": _checkpoint_reference(candidate_cp),
        "previous_frontier": previous_frontier,
        "append_frontier": append_frontier,
    }
    return {**core, "consistency_id": _sha256(core)}


def validate_consistency_proof(payload: Any) -> dict[str, Any]:
    root = _exact_fields(
        payload,
        {
            "consistency_version", "algorithm", "relation", "previous", "candidate",
            "previous_frontier", "append_frontier", "consistency_id",
        },
        "consistency proof",
    )
    if root["consistency_version"] != CONSISTENCY_VERSION:
        raise ConsistencyError(f"consistency proof version must be {CONSISTENCY_VERSION}")
    if root["algorithm"] != CONSISTENCY_ALGORITHM:
        raise ConsistencyError("consistency proof algorithm is unsupported")
    previous = _checkpoint_ref(root["previous"], "previous checkpoint reference")
    candidate = _checkpoint_ref(root["candidate"], "candidate checkpoint reference")
    if previous["project"] != candidate["project"]:
        raise ConsistencyError("consistency checkpoints belong to different projects")
    if previous["entry_count"] > candidate["entry_count"]:
        raise ConsistencyError("consistency proof attempts to move to an older checkpoint")
    relation = root["relation"]
    expected_relation = "same" if previous["entry_count"] == candidate["entry_count"] else "right-descendant"
    if relation != expected_relation:
        raise ConsistencyError("consistency relation does not match checkpoint sizes")
    if relation == "same" and previous != candidate:
        raise ConsistencyError("same-size consistency proof requires identical checkpoints")
    previous_frontier = _validate_segments(
        root["previous_frontier"], 0, previous["entry_count"], "previous frontier"
    )
    append_frontier = _validate_segments(
        root["append_frontier"], previous["entry_count"], candidate["entry_count"], "append frontier"
    )
    previous_root, candidate_root = _reconstruct_roots(
        previous_frontier, append_frontier, previous["entry_count"], candidate["entry_count"]
    )
    if previous_root != previous["merkle_root"]:
        raise ConsistencyError("consistency proof does not reconstruct the previous Merkle root")
    if candidate_root != candidate["merkle_root"]:
        raise ConsistencyError("consistency proof does not reconstruct the candidate Merkle root")
    core = {
        "consistency_version": CONSISTENCY_VERSION,
        "algorithm": CONSISTENCY_ALGORITHM,
        "relation": relation,
        "previous": previous,
        "candidate": candidate,
        "previous_frontier": previous_frontier,
        "append_frontier": append_frontier,
    }
    consistency_id = _hex(root["consistency_id"], "consistency id")
    if consistency_id != _sha256(core):
        raise ConsistencyError("consistency id does not match its canonical payload")
    return {**core, "consistency_id": consistency_id}


def _load_canonical(
    path: Path, validator: Callable[[Any], dict[str, Any]], label: str, limit: int
) -> dict[str, Any]:
    if path.is_symlink():
        raise ConsistencyError(f"{label} must not be a symlink")
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ConsistencyError(f"{label} not found: {path}") from exc
    except OSError as exc:
        raise ConsistencyError(f"unable to read {label}: {path}") from exc
    if len(raw) > limit:
        raise ConsistencyError(f"{label} exceeds the reviewed size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConsistencyError(f"{label} is not valid UTF-8 canonical JSON") from exc
    normalized = validator(payload)
    if raw != canonical_json(normalized):
        raise ConsistencyError(f"{label} is not canonically serialized")
    return normalized


def load_consistency_proof(path: Path) -> dict[str, Any]:
    return _load_canonical(
        path, validate_consistency_proof, "consistency proof", MAX_CONSISTENCY_BYTES
    )


def _pin(value: str, label: str) -> str:
    return _hex(value.lower(), label)


def _text(payload: dict[str, Any]) -> str:
    lines = []
    for key in ("valid", "created", "accepted", "relation", "consistency_id", "decision_id"):
        if key in payload:
            lines.append(f"{key}: {payload[key]}")
    previous = payload.get("previous")
    candidate = payload.get("candidate")
    if isinstance(previous, dict):
        lines.append(f"previous: entries={previous.get('entry_count', previous.get('entries'))}")
    if isinstance(candidate, dict):
        lines.append(f"candidate: entries={candidate.get('entry_count', candidate.get('entries'))}")
    for violation in payload.get("violations", []):
        lines.append(f"- {violation['rule_id']}: {violation['message']}")
    return "\n".join(lines)


def _emit(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        print(_text(payload))


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
    prove.add_argument("--expected-candidate-state-id", required=True)
    prove.add_argument("--expected-previous-checkpoint-id", required=True)
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
        previous_checkpoint = load_checkpoint(args.previous_checkpoint)
        candidate_checkpoint = load_checkpoint(args.candidate_checkpoint)
        expected_previous_checkpoint = _pin(
            args.expected_previous_checkpoint_id, "expected previous checkpoint id"
        )
        expected_candidate_checkpoint = _pin(
            args.expected_candidate_checkpoint_id, "expected candidate checkpoint id"
        )
        if previous_checkpoint["checkpoint_id"] != expected_previous_checkpoint:
            raise ConsistencyError("previous checkpoint does not match its externally pinned id")
        if candidate_checkpoint["checkpoint_id"] != expected_candidate_checkpoint:
            raise ConsistencyError("candidate checkpoint does not match its externally pinned id")

        if args.command == "verify":
            proof = load_consistency_proof(args.proof)
            if proof["previous"] != _checkpoint_reference(previous_checkpoint):
                raise ConsistencyError("consistency proof references a different previous checkpoint")
            if proof["candidate"] != _checkpoint_reference(candidate_checkpoint):
                raise ConsistencyError("consistency proof references a different candidate checkpoint")
            _emit(
                {
                    "valid": True,
                    "accepted": True,
                    "relation": proof["relation"],
                    "consistency_id": proof["consistency_id"],
                    "previous": proof["previous"],
                    "candidate": proof["candidate"],
                    "proof_hashes": len(proof["previous_frontier"]) + len(proof["append_frontier"]),
                },
                args.format,
            )
            return 0

        previous_state = load_state(args.previous_state)
        candidate_state = load_state(args.candidate_state)
        if previous_state["state_id"] != _pin(
            args.expected_previous_state_id, "expected previous state id"
        ):
            raise ConsistencyError("previous trust state does not match its externally pinned id")
        if candidate_state["state_id"] != _pin(
            args.expected_candidate_state_id, "expected candidate state id"
        ):
            raise ConsistencyError("candidate trust state does not match its externally pinned id")
        proof = create_consistency_proof(
            previous_state, previous_checkpoint, candidate_state, candidate_checkpoint
        )
        _write_new(args.output, proof, "consistency proof")
        _emit(
            {
                "created": str(args.output),
                "accepted": True,
                "relation": proof["relation"],
                "consistency_id": proof["consistency_id"],
                "previous": proof["previous"],
                "candidate": proof["candidate"],
                "proof_hashes": len(proof["previous_frontier"]) + len(proof["append_frontier"]),
            },
            args.format,
        )
        return 0
    except ConsistencyDenied as exc:
        _emit(exc.report, args.format)
        return 1
    except (OSError, TrustStateError, CheckpointError, ConsistencyError) as exc:
        print(f"Release consistency error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
