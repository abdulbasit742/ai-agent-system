#!/usr/bin/env python3
"""Create and verify portable Merkle checkpoints for release trust states."""
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

try:
    from scripts.release_trust import TrustStateError, load_state, validate_state
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from release_trust import TrustStateError, load_state, validate_state

CHECKPOINT_VERSION = 1
PROOF_VERSION = 1
MERKLE_ALGORITHM = "sha256-rfc6962-v1"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
NUMERIC_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
ZERO_HASH = "0" * 64
MAX_CHECKPOINT_BYTES = 1_000_000
MAX_PROOF_BYTES = 1_000_000


class CheckpointError(ValueError):
    """Raised when checkpoint, proof, lineage, or pinned input is invalid."""


def canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _exact_fields(payload: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise CheckpointError(f"{label} fields do not match the reviewed schema")
    return payload


def _hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CheckpointError(f"{label} is malformed")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CheckpointError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def _project(value: Any, label: str = "project") -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CheckpointError(f"{label} must be a canonical non-empty string")
    return value


def _version(value: Any, label: str = "version") -> str:
    if not isinstance(value, str) or not NUMERIC_VERSION.fullmatch(value):
        raise CheckpointError(f"{label} must be a canonical numeric dot-separated version")
    if any(len(part) > 1 and part.startswith("0") for part in value.split(".")):
        raise CheckpointError(f"{label} must not contain leading-zero numeric segments")
    return value


def _head(payload: Any) -> dict[str, Any]:
    head = _exact_fields(
        payload,
        {"sequence", "entry_hash", "release_id", "source_commit", "version"},
        "checkpoint head",
    )
    return {
        "sequence": _integer(head["sequence"], "checkpoint head sequence", 1),
        "entry_hash": _hex(head["entry_hash"], HEX_64, "checkpoint head entry hash"),
        "release_id": _hex(head["release_id"], HEX_64, "checkpoint head release id"),
        "source_commit": _hex(head["source_commit"], HEX_40, "checkpoint head source commit"),
        "version": _version(head["version"], "checkpoint head version"),
    }


def _entry(payload: Any) -> dict[str, Any]:
    entry = _exact_fields(
        payload,
        {
            "entry_version",
            "sequence",
            "kind",
            "previous_entry_hash",
            "release",
            "transition",
            "entry_hash",
        },
        "proof entry",
    )
    if entry["entry_version"] != 1:
        raise CheckpointError("proof entry version is unsupported")
    sequence = _integer(entry["sequence"], "proof entry sequence", 1)
    kind = entry["kind"]
    if kind not in {"anchor", "transition"} or (sequence == 1) != (kind == "anchor"):
        raise CheckpointError("proof entry kind is inconsistent with its sequence")
    previous_hash = _hex(entry["previous_entry_hash"], HEX_64, "proof previous entry hash")
    if sequence == 1 and previous_hash != ZERO_HASH:
        raise CheckpointError("anchor proof entry must use the zero previous hash")

    release_raw = _exact_fields(
        entry["release"],
        {"project", "version", "release_id", "source_commit", "source_date_epoch"},
        "proof release",
    )
    release = {
        "project": _project(release_raw["project"], "proof release project"),
        "version": _version(release_raw["version"], "proof release version"),
        "release_id": _hex(release_raw["release_id"], HEX_64, "proof release id"),
        "source_commit": _hex(release_raw["source_commit"], HEX_40, "proof source commit"),
        "source_date_epoch": _integer(
            release_raw["source_date_epoch"], "proof source date epoch"
        ),
    }

    transition = entry["transition"]
    if sequence == 1:
        if transition is not None:
            raise CheckpointError("anchor proof entry must not contain transition evidence")
    else:
        transition_raw = _exact_fields(
            transition,
            {"previous_release_id", "transition_id", "policy_sha256"},
            "proof transition",
        )
        transition = {
            "previous_release_id": _hex(
                transition_raw["previous_release_id"], HEX_64, "proof previous release id"
            ),
            "transition_id": _hex(
                transition_raw["transition_id"], HEX_64, "proof transition id"
            ),
            "policy_sha256": _hex(
                transition_raw["policy_sha256"], HEX_64, "proof policy sha256"
            ),
        }

    core = {
        "entry_version": 1,
        "sequence": sequence,
        "kind": kind,
        "previous_entry_hash": previous_hash,
        "release": release,
        "transition": transition,
    }
    entry_hash = _hex(entry["entry_hash"], HEX_64, "proof entry hash")
    if entry_hash != _sha256(core):
        raise CheckpointError("proof entry hash does not match its canonical payload")
    return {**core, "entry_hash": entry_hash}


def _leaf_hash(entry: dict[str, Any]) -> bytes:
    return hashlib.sha256(b"\x00" + canonical_json(entry)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(size: int) -> int:
    if size < 2:
        raise CheckpointError("Merkle split requires at least two leaves")
    return 1 << ((size - 1).bit_length() - 1)


def _merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise CheckpointError("Merkle tree requires at least one leaf")
    if len(leaves) == 1:
        return leaves[0]
    split = _largest_power_of_two_less_than(len(leaves))
    return _node_hash(_merkle_root(leaves[:split]), _merkle_root(leaves[split:]))


def _audit_path(leaves: list[bytes], index: int) -> list[bytes]:
    if index < 0 or index >= len(leaves):
        raise CheckpointError("proof index is outside the Merkle tree")
    if len(leaves) == 1:
        return []
    split = _largest_power_of_two_less_than(len(leaves))
    if index < split:
        return _audit_path(leaves[:split], index) + [_merkle_root(leaves[split:])]
    return _audit_path(leaves[split:], index - split) + [_merkle_root(leaves[:split])]


def _rebuild_root(
    leaf: bytes, index: int, size: int, siblings: list[bytes], position: list[int]
) -> bytes:
    if size == 1:
        return leaf
    split = _largest_power_of_two_less_than(size)
    if index < split:
        left = _rebuild_root(leaf, index, split, siblings, position)
        if position[0] >= len(siblings):
            raise CheckpointError("inclusion proof audit path is too short")
        right = siblings[position[0]]
    else:
        right = _rebuild_root(leaf, index - split, size - split, siblings, position)
        if position[0] >= len(siblings):
            raise CheckpointError("inclusion proof audit path is too short")
        left = siblings[position[0]]
    position[0] += 1
    return _node_hash(left, right)


def _verify_inclusion(entry: dict[str, Any], sequence: int, size: int, audit_path: list[str]) -> str:
    if sequence < 1 or sequence > size:
        raise CheckpointError("proof sequence is outside the checkpoint entry range")
    siblings = [bytes.fromhex(_hex(item, HEX_64, "audit path hash")) for item in audit_path]
    position = [0]
    root = _rebuild_root(_leaf_hash(entry), sequence - 1, size, siblings, position)
    if position[0] != len(siblings):
        raise CheckpointError("inclusion proof audit path contains extra hashes")
    return root.hex()


def create_checkpoint(state: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_state(state)
    leaves = [_leaf_hash(entry) for entry in normalized["entries"]]
    payload = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "project": normalized["project"],
        "state_id": normalized["state_id"],
        "entry_count": len(normalized["entries"]),
        "head": normalized["head"],
        "merkle": {
            "algorithm": MERKLE_ALGORITHM,
            "root": _merkle_root(leaves).hex(),
        },
    }
    return {**payload, "checkpoint_id": _sha256(payload)}


def validate_checkpoint(payload: Any) -> dict[str, Any]:
    root = _exact_fields(
        payload,
        {
            "checkpoint_version",
            "project",
            "state_id",
            "entry_count",
            "head",
            "merkle",
            "checkpoint_id",
        },
        "checkpoint",
    )
    if root["checkpoint_version"] != CHECKPOINT_VERSION:
        raise CheckpointError(f"checkpoint version must be {CHECKPOINT_VERSION}")
    project = _project(root["project"], "checkpoint project")
    state_id = _hex(root["state_id"], HEX_64, "checkpoint state id")
    entry_count = _integer(root["entry_count"], "checkpoint entry count", 1)
    head = _head(root["head"])
    if head["sequence"] != entry_count:
        raise CheckpointError("checkpoint head sequence differs from entry count")
    merkle_raw = _exact_fields(root["merkle"], {"algorithm", "root"}, "checkpoint Merkle data")
    if merkle_raw["algorithm"] != MERKLE_ALGORITHM:
        raise CheckpointError("checkpoint Merkle algorithm is unsupported")
    merkle = {
        "algorithm": MERKLE_ALGORITHM,
        "root": _hex(merkle_raw["root"], HEX_64, "checkpoint Merkle root"),
    }
    core = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "project": project,
        "state_id": state_id,
        "entry_count": entry_count,
        "head": head,
        "merkle": merkle,
    }
    checkpoint_id = _hex(root["checkpoint_id"], HEX_64, "checkpoint id")
    if checkpoint_id != _sha256(core):
        raise CheckpointError("checkpoint id does not match its canonical payload")
    return {**core, "checkpoint_id": checkpoint_id}


def _checkpoint_reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "checkpoint_id": checkpoint["checkpoint_id"],
        "project": checkpoint["project"],
        "state_id": checkpoint["state_id"],
        "entry_count": checkpoint["entry_count"],
        "merkle_root": checkpoint["merkle"]["root"],
    }


def checkpoint_matches_state(checkpoint: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    normalized_checkpoint = validate_checkpoint(checkpoint)
    expected = create_checkpoint(validate_state(state))
    if normalized_checkpoint != expected:
        raise CheckpointError("checkpoint does not match the canonical trust state")
    return normalized_checkpoint


def create_proof(
    state: dict[str, Any], checkpoint: dict[str, Any], *, sequence: int | None = None,
    release_id: str | None = None,
) -> dict[str, Any]:
    normalized_state = validate_state(state)
    normalized_checkpoint = checkpoint_matches_state(checkpoint, normalized_state)
    if (sequence is None) == (release_id is None):
        raise CheckpointError("select exactly one proof entry by sequence or release id")
    selected: dict[str, Any] | None = None
    if sequence is not None:
        _integer(sequence, "proof sequence", 1)
        if sequence <= len(normalized_state["entries"]):
            selected = normalized_state["entries"][sequence - 1]
    else:
        wanted = _hex(str(release_id).lower(), HEX_64, "proof release id")
        for entry in normalized_state["entries"]:
            if entry["release"]["release_id"] == wanted:
                selected = entry
                break
    if selected is None:
        raise CheckpointError("requested release entry is not present in trust state")
    leaves = [_leaf_hash(entry) for entry in normalized_state["entries"]]
    audit_path = [item.hex() for item in _audit_path(leaves, selected["sequence"] - 1)]
    core = {
        "proof_version": PROOF_VERSION,
        "checkpoint": _checkpoint_reference(normalized_checkpoint),
        "entry": selected,
        "audit_path": audit_path,
    }
    return {**core, "proof_id": _sha256(core)}


def validate_proof(payload: Any) -> dict[str, Any]:
    root = _exact_fields(
        payload,
        {"proof_version", "checkpoint", "entry", "audit_path", "proof_id"},
        "inclusion proof",
    )
    if root["proof_version"] != PROOF_VERSION:
        raise CheckpointError(f"inclusion proof version must be {PROOF_VERSION}")
    reference_raw = _exact_fields(
        root["checkpoint"],
        {"checkpoint_id", "project", "state_id", "entry_count", "merkle_root"},
        "proof checkpoint reference",
    )
    reference = {
        "checkpoint_id": _hex(reference_raw["checkpoint_id"], HEX_64, "proof checkpoint id"),
        "project": _project(reference_raw["project"], "proof checkpoint project"),
        "state_id": _hex(reference_raw["state_id"], HEX_64, "proof state id"),
        "entry_count": _integer(reference_raw["entry_count"], "proof entry count", 1),
        "merkle_root": _hex(reference_raw["merkle_root"], HEX_64, "proof Merkle root"),
    }
    entry = _entry(root["entry"])
    if entry["release"]["project"] != reference["project"]:
        raise CheckpointError("proof entry project differs from checkpoint project")
    audit_path = root["audit_path"]
    if not isinstance(audit_path, list) or len(audit_path) > 64:
        raise CheckpointError("proof audit path is malformed or exceeds the reviewed limit")
    audit_path = [_hex(item, HEX_64, "proof audit path hash") for item in audit_path]
    rebuilt = _verify_inclusion(entry, entry["sequence"], reference["entry_count"], audit_path)
    if rebuilt != reference["merkle_root"]:
        raise CheckpointError("inclusion proof does not reconstruct the checkpoint Merkle root")
    core = {
        "proof_version": PROOF_VERSION,
        "checkpoint": reference,
        "entry": entry,
        "audit_path": audit_path,
    }
    proof_id = _hex(root["proof_id"], HEX_64, "proof id")
    if proof_id != _sha256(core):
        raise CheckpointError("proof id does not match its canonical payload")
    return {**core, "proof_id": proof_id}


def lineage(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_state = validate_state(left)
    right_state = validate_state(right)
    if left_state["project"] != right_state["project"]:
        raise CheckpointError("trust states belong to different projects")
    left_hashes = [entry["entry_hash"] for entry in left_state["entries"]]
    right_hashes = [entry["entry_hash"] for entry in right_state["entries"]]
    common = 0
    for left_hash, right_hash in zip(left_hashes, right_hashes):
        if left_hash != right_hash:
            break
        common += 1
    if common == len(left_hashes) == len(right_hashes):
        relation = "same"
    elif common == len(left_hashes):
        relation = "right-descendant"
    elif common == len(right_hashes):
        relation = "rollback"
    else:
        relation = "fork"
    violations: list[dict[str, str]] = []
    if relation == "rollback":
        violations.append({"rule_id": "CHK010", "message": "right trust state is older than left"})
    elif relation == "fork":
        violations.append({"rule_id": "CHK011", "message": "trust states diverge after a common prefix"})
    common_entry = left_state["entries"][common - 1] if common else None
    core = {
        "lineage_version": 1,
        "accepted": not violations,
        "relation": relation,
        "project": left_state["project"],
        "left": {
            "state_id": left_state["state_id"],
            "entries": len(left_state["entries"]),
            "head": left_state["head"],
        },
        "right": {
            "state_id": right_state["state_id"],
            "entries": len(right_state["entries"]),
            "head": right_state["head"],
        },
        "common": {
            "entries": common,
            "entry_hash": common_entry["entry_hash"] if common_entry else ZERO_HASH,
            "release_id": common_entry["release"]["release_id"] if common_entry else None,
        },
        "violations": violations,
    }
    return {**core, "lineage_id": _sha256(core)}


def _load_canonical(
    path: Path, validator: Callable[[Any], dict[str, Any]], label: str, limit: int
) -> dict[str, Any]:
    if path.is_symlink():
        raise CheckpointError(f"{label} must not be a symlink")
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise CheckpointError(f"{label} not found: {path}") from exc
    except OSError as exc:
        raise CheckpointError(f"unable to read {label}: {path}") from exc
    if len(raw) > limit:
        raise CheckpointError(f"{label} exceeds the reviewed size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckpointError(f"{label} is not valid UTF-8 canonical JSON") from exc
    normalized = validator(payload)
    if raw != canonical_json(normalized):
        raise CheckpointError(f"{label} is not canonically serialized")
    return normalized


def load_checkpoint(path: Path) -> dict[str, Any]:
    return _load_canonical(path, validate_checkpoint, "checkpoint", MAX_CHECKPOINT_BYTES)


def load_proof(path: Path) -> dict[str, Any]:
    return _load_canonical(path, validate_proof, "inclusion proof", MAX_PROOF_BYTES)


def _write_new(path: Path, payload: dict[str, Any], label: str) -> None:
    if path.is_symlink():
        raise CheckpointError(f"{label} output must not be a symlink")
    if path.exists():
        raise CheckpointError(f"refusing to overwrite existing {label}: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
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
            raise CheckpointError(f"refusing to overwrite existing {label}: {path}") from exc
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


def _pin(value: str, pattern: re.Pattern[str], label: str) -> str:
    return _hex(value.lower(), pattern, label)


def _text(payload: dict[str, Any]) -> str:
    lines = []
    for key in (
        "valid",
        "created",
        "checkpoint_id",
        "proof_id",
        "state_id",
        "lineage_id",
        "accepted",
        "relation",
    ):
        if key in payload:
            lines.append(f"{key}: {payload[key]}")
    head = payload.get("head")
    if isinstance(head, dict):
        lines.append(
            f"head: sequence={head['sequence']} version={head['version']} release_id={head['release_id']}"
        )
    entry = payload.get("entry")
    if isinstance(entry, dict):
        lines.append(
            f"entry: sequence={entry['sequence']} release_id={entry['release']['release_id']}"
        )
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

    create = subparsers.add_parser("create")
    create.add_argument("state", type=Path)
    create.add_argument("output", type=Path)
    create.add_argument("--expected-state-id", required=True)
    create.add_argument("--format", choices=("json", "text"), default="json")

    verify = subparsers.add_parser("verify")
    verify.add_argument("checkpoint", type=Path)
    verify.add_argument("--expected-checkpoint-id", required=True)
    verify.add_argument("--state", type=Path)
    verify.add_argument("--expected-state-id")
    verify.add_argument("--format", choices=("json", "text"), default="json")

    prove = subparsers.add_parser("prove")
    prove.add_argument("state", type=Path)
    prove.add_argument("checkpoint", type=Path)
    prove.add_argument("output", type=Path)
    prove.add_argument("--expected-state-id", required=True)
    prove.add_argument("--expected-checkpoint-id", required=True)
    selector = prove.add_mutually_exclusive_group(required=True)
    selector.add_argument("--sequence", type=int)
    selector.add_argument("--release-id")
    prove.add_argument("--format", choices=("json", "text"), default="json")

    verify_proof = subparsers.add_parser("verify-proof")
    verify_proof.add_argument("proof", type=Path)
    verify_proof.add_argument("checkpoint", type=Path)
    verify_proof.add_argument("--expected-checkpoint-id", required=True)
    verify_proof.add_argument("--format", choices=("json", "text"), default="json")

    lineage_parser = subparsers.add_parser("lineage")
    lineage_parser.add_argument("left", type=Path)
    lineage_parser.add_argument("right", type=Path)
    lineage_parser.add_argument("--expected-left-state-id", required=True)
    lineage_parser.add_argument("--expected-right-state-id", required=True)
    lineage_parser.add_argument("--format", choices=("json", "text"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            state = load_state(args.state)
            expected_state_id = _pin(args.expected_state_id, HEX_64, "expected state id")
            if state["state_id"] != expected_state_id:
                raise CheckpointError("trust state does not match the externally pinned state id")
            checkpoint = create_checkpoint(state)
            _write_new(args.output, checkpoint, "checkpoint")
            _emit(
                {
                    "created": str(args.output),
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "state_id": checkpoint["state_id"],
                    "head": checkpoint["head"],
                },
                args.format,
            )
            return 0

        if args.command == "verify":
            checkpoint = load_checkpoint(args.checkpoint)
            expected_checkpoint_id = _pin(
                args.expected_checkpoint_id, HEX_64, "expected checkpoint id"
            )
            if checkpoint["checkpoint_id"] != expected_checkpoint_id:
                raise CheckpointError("checkpoint does not match the externally pinned checkpoint id")
            if args.state is not None:
                if args.expected_state_id is None:
                    raise CheckpointError("--expected-state-id is required when --state is supplied")
                state = load_state(args.state)
                expected_state_id = _pin(args.expected_state_id, HEX_64, "expected state id")
                if state["state_id"] != expected_state_id:
                    raise CheckpointError("trust state does not match the externally pinned state id")
                checkpoint_matches_state(checkpoint, state)
            _emit(
                {
                    "valid": True,
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "state_id": checkpoint["state_id"],
                    "head": checkpoint["head"],
                    "entry_count": checkpoint["entry_count"],
                    "merkle_root": checkpoint["merkle"]["root"],
                },
                args.format,
            )
            return 0

        if args.command == "prove":
            state = load_state(args.state)
            checkpoint = load_checkpoint(args.checkpoint)
            if state["state_id"] != _pin(args.expected_state_id, HEX_64, "expected state id"):
                raise CheckpointError("trust state does not match the externally pinned state id")
            if checkpoint["checkpoint_id"] != _pin(
                args.expected_checkpoint_id, HEX_64, "expected checkpoint id"
            ):
                raise CheckpointError("checkpoint does not match the externally pinned checkpoint id")
            proof = create_proof(
                state,
                checkpoint,
                sequence=args.sequence,
                release_id=args.release_id,
            )
            _write_new(args.output, proof, "inclusion proof")
            _emit(
                {
                    "created": str(args.output),
                    "proof_id": proof["proof_id"],
                    "checkpoint_id": proof["checkpoint"]["checkpoint_id"],
                    "entry": proof["entry"],
                },
                args.format,
            )
            return 0

        if args.command == "verify-proof":
            checkpoint = load_checkpoint(args.checkpoint)
            if checkpoint["checkpoint_id"] != _pin(
                args.expected_checkpoint_id, HEX_64, "expected checkpoint id"
            ):
                raise CheckpointError("checkpoint does not match the externally pinned checkpoint id")
            proof = load_proof(args.proof)
            if proof["checkpoint"] != _checkpoint_reference(checkpoint):
                raise CheckpointError("inclusion proof references a different checkpoint")
            _emit(
                {
                    "valid": True,
                    "proof_id": proof["proof_id"],
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "entry": proof["entry"],
                },
                args.format,
            )
            return 0

        left = load_state(args.left)
        right = load_state(args.right)
        if left["state_id"] != _pin(args.expected_left_state_id, HEX_64, "expected left state id"):
            raise CheckpointError("left trust state does not match its externally pinned state id")
        if right["state_id"] != _pin(
            args.expected_right_state_id, HEX_64, "expected right state id"
        ):
            raise CheckpointError("right trust state does not match its externally pinned state id")
        report = lineage(left, right)
        _emit(report, args.format)
        return 0 if report["accepted"] else 1
    except (OSError, TrustStateError, CheckpointError) as exc:
        print(f"Release checkpoint error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
