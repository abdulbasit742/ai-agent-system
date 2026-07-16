#!/usr/bin/env python3
"""Create and verify portable Merkle checkpoints for audit bundle trust states."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from agent_audit_bundle import AuditEvidenceBundleError, verify_bundle
from agent_audit_trust import (
    ADMISSION_FIELDS,
    ENTRY_FIELDS,
    ENTRY_VERSION,
    EVIDENCE_FIELDS,
    HEAD_FIELDS,
    TRANSITION_FIELDS,
    ZERO_HASH,
    AuditBundleTrustError,
    _admission,
    _entry_payload,
    _evidence,
    _identifier as trust_identifier,
    _transition,
    canonical_json,
    load_state,
    validate_state,
)

CHECKPOINT_VERSION = 1
PROOF_VERSION = 1
LINEAGE_VERSION = 1
MERKLE_ALGORITHM = "sha256-rfc6962-v1"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_CHECKPOINT_BYTES = 1_000_000
MAX_PROOF_BYTES = 2_000_000
MAX_AUDIT_PATH = 64

CHECKPOINT_FIELDS = {
    "checkpoint_version",
    "state_id",
    "entry_count",
    "head",
    "merkle",
    "checkpoint_id",
}
CHECKPOINT_REFERENCE_FIELDS = {
    "checkpoint_id",
    "state_id",
    "entry_count",
    "merkle_root",
}
PROOF_FIELDS = {"proof_version", "checkpoint", "entry", "audit_path", "proof_id"}
MERKLE_FIELDS = {"algorithm", "root"}


class AuditTrustCheckpointError(ValueError):
    """Raised when checkpoint, proof, lineage, or pinned input is invalid."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "ATC002",
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


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditTrustCheckpointError(
            f"{label} fields do not match the reviewed schema",
            rule_id="ATC002",
        )
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditTrustCheckpointError(
            f"{label} must be 64 lowercase hexadecimal characters",
            rule_id="ATC002",
        )
    return value


def _pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuditTrustCheckpointError(f"{label} must be a string", rule_id="ATC003")
    lowered = value.lower()
    if not HEX_64.fullmatch(lowered):
        raise AuditTrustCheckpointError(
            f"{label} must be 64 hexadecimal characters",
            rule_id="ATC003",
        )
    return lowered


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditTrustCheckpointError(
            f"{label} must be an integer greater than or equal to {minimum}",
            rule_id="ATC002",
        )
    return value


def _checkpoint_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"audit-bundle-trust-checkpoint-v1\x00" + canonical_json(payload)
    ).hexdigest()


def _proof_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"audit-bundle-trust-inclusion-proof-v1\x00" + canonical_json(payload)
    ).hexdigest()


def _lineage_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"audit-bundle-trust-lineage-v1\x00" + canonical_json(payload)
    ).hexdigest()


def _head(value: Any) -> dict[str, Any]:
    raw = _exact(value, HEAD_FIELDS, "checkpoint head")
    return {
        "sequence": _integer(raw["sequence"], "checkpoint head sequence", 1),
        "entry_hash": _hash(raw["entry_hash"], "checkpoint head entry hash"),
        "bundle_id": _hash(raw["bundle_id"], "checkpoint head bundle id"),
        "checkpoint_id": _hash(raw["checkpoint_id"], "checkpoint head evidence checkpoint id"),
        "catalog_id": _hash(raw["catalog_id"], "checkpoint head catalog id"),
        "generation": _integer(raw["generation"], "checkpoint head generation", 1),
        "segment_count": _integer(raw["segment_count"], "checkpoint head segment count", 1),
    }


def _entry(value: Any) -> dict[str, Any]:
    raw = _exact(value, ENTRY_FIELDS, "proof trust entry")
    if raw["entry_version"] != ENTRY_VERSION:
        raise AuditTrustCheckpointError("proof trust entry version is unsupported")
    sequence = _integer(raw["sequence"], "proof trust entry sequence", 1)
    kind = raw["kind"]
    if kind not in {"anchor", "transition"} or (sequence == 1) != (kind == "anchor"):
        raise AuditTrustCheckpointError("proof trust entry kind is inconsistent with sequence")
    previous_entry_hash = _hash(raw["previous_entry_hash"], "proof previous entry hash")
    if sequence == 1 and previous_entry_hash != ZERO_HASH:
        raise AuditTrustCheckpointError("anchor proof entry must use the zero previous hash")
    try:
        evidence = _evidence(_exact(raw["evidence"], EVIDENCE_FIELDS, "proof evidence"))
        admission = _admission(_exact(raw["admission"], ADMISSION_FIELDS, "proof admission"))
        if sequence == 1:
            if raw["transition"] is not None:
                raise AuditTrustCheckpointError(
                    "anchor proof entry must not contain transition evidence"
                )
            transition = None
        else:
            transition = _transition(
                _exact(raw["transition"], TRANSITION_FIELDS, "proof transition")
            )
    except AuditBundleTrustError as exc:
        raise AuditTrustCheckpointError(str(exc), rule_id="ATC002") from exc
    core = _entry_payload(
        sequence,
        kind,
        previous_entry_hash,
        evidence,
        admission,
        transition,
    )
    entry_hash = _hash(raw["entry_hash"], "proof trust entry hash")
    expected = trust_identifier(b"audit-bundle-trust-entry-v1", core)
    if entry_hash != expected:
        raise AuditTrustCheckpointError(
            "proof trust entry hash does not match its canonical payload",
            rule_id="ATC006",
        )
    return {**core, "entry_hash": entry_hash}


def _leaf_hash(entry: dict[str, Any]) -> bytes:
    return hashlib.sha256(b"\x00" + canonical_json(entry)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(size: int) -> int:
    if size < 2:
        raise AuditTrustCheckpointError("Merkle split requires at least two leaves")
    return 1 << ((size - 1).bit_length() - 1)


def _merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise AuditTrustCheckpointError("Merkle tree requires at least one leaf")
    if len(leaves) == 1:
        return leaves[0]
    split = _largest_power_of_two_less_than(len(leaves))
    return _node_hash(_merkle_root(leaves[:split]), _merkle_root(leaves[split:]))


def _audit_path(leaves: list[bytes], index: int) -> list[bytes]:
    if index < 0 or index >= len(leaves):
        raise AuditTrustCheckpointError("proof index is outside the Merkle tree")
    if len(leaves) == 1:
        return []
    split = _largest_power_of_two_less_than(len(leaves))
    if index < split:
        return _audit_path(leaves[:split], index) + [_merkle_root(leaves[split:])]
    return _audit_path(leaves[split:], index - split) + [_merkle_root(leaves[:split])]


def _rebuild_root(
    leaf: bytes,
    index: int,
    size: int,
    siblings: list[bytes],
    position: list[int],
) -> bytes:
    if size == 1:
        return leaf
    split = _largest_power_of_two_less_than(size)
    if index < split:
        left = _rebuild_root(leaf, index, split, siblings, position)
        if position[0] >= len(siblings):
            raise AuditTrustCheckpointError(
                "inclusion proof audit path is too short", rule_id="ATC006"
            )
        right = siblings[position[0]]
    else:
        right = _rebuild_root(
            leaf, index - split, size - split, siblings, position
        )
        if position[0] >= len(siblings):
            raise AuditTrustCheckpointError(
                "inclusion proof audit path is too short", rule_id="ATC006"
            )
        left = siblings[position[0]]
    position[0] += 1
    return _node_hash(left, right)


def _verify_inclusion(
    entry: dict[str, Any], sequence: int, size: int, audit_path: list[str]
) -> str:
    if sequence < 1 or sequence > size:
        raise AuditTrustCheckpointError(
            "proof sequence is outside the checkpoint entry range", rule_id="ATC006"
        )
    siblings = [bytes.fromhex(_hash(item, "proof audit path hash")) for item in audit_path]
    position = [0]
    root = _rebuild_root(_leaf_hash(entry), sequence - 1, size, siblings, position)
    if position[0] != len(siblings):
        raise AuditTrustCheckpointError(
            "inclusion proof audit path contains extra hashes", rule_id="ATC006"
        )
    return root.hex()


def create_checkpoint(state: dict[str, Any]) -> dict[str, Any]:
    try:
        normalized = validate_state(state)
    except AuditBundleTrustError as exc:
        raise AuditTrustCheckpointError(str(exc), rule_id="ATC002") from exc
    leaves = [_leaf_hash(entry) for entry in normalized["entries"]]
    payload = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "state_id": normalized["state_id"],
        "entry_count": len(normalized["entries"]),
        "head": normalized["head"],
        "merkle": {
            "algorithm": MERKLE_ALGORITHM,
            "root": _merkle_root(leaves).hex(),
        },
    }
    return {**payload, "checkpoint_id": _checkpoint_identifier(payload)}


def validate_checkpoint(value: Any) -> dict[str, Any]:
    raw = _exact(value, CHECKPOINT_FIELDS, "audit trust checkpoint")
    if raw["checkpoint_version"] != CHECKPOINT_VERSION:
        raise AuditTrustCheckpointError(
            f"checkpoint version must be {CHECKPOINT_VERSION}"
        )
    state_id = _hash(raw["state_id"], "checkpoint state id")
    entry_count = _integer(raw["entry_count"], "checkpoint entry count", 1)
    head = _head(raw["head"])
    if head["sequence"] != entry_count:
        raise AuditTrustCheckpointError(
            "checkpoint head sequence differs from entry count", rule_id="ATC002"
        )
    merkle_raw = _exact(raw["merkle"], MERKLE_FIELDS, "checkpoint Merkle data")
    if merkle_raw["algorithm"] != MERKLE_ALGORITHM:
        raise AuditTrustCheckpointError("checkpoint Merkle algorithm is unsupported")
    merkle = {
        "algorithm": MERKLE_ALGORITHM,
        "root": _hash(merkle_raw["root"], "checkpoint Merkle root"),
    }
    core = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "state_id": state_id,
        "entry_count": entry_count,
        "head": head,
        "merkle": merkle,
    }
    checkpoint_id = _hash(raw["checkpoint_id"], "checkpoint id")
    if checkpoint_id != _checkpoint_identifier(core):
        raise AuditTrustCheckpointError(
            "checkpoint id does not match its canonical payload", rule_id="ATC002"
        )
    return {**core, "checkpoint_id": checkpoint_id}


def _checkpoint_reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "checkpoint_id": checkpoint["checkpoint_id"],
        "state_id": checkpoint["state_id"],
        "entry_count": checkpoint["entry_count"],
        "merkle_root": checkpoint["merkle"]["root"],
    }


def checkpoint_matches_state(
    checkpoint: dict[str, Any], state: dict[str, Any]
) -> dict[str, Any]:
    normalized_checkpoint = validate_checkpoint(checkpoint)
    expected = create_checkpoint(state)
    if normalized_checkpoint != expected:
        raise AuditTrustCheckpointError(
            "checkpoint does not match the canonical audit trust state",
            rule_id="ATC004",
        )
    return normalized_checkpoint


def create_proof(
    state: dict[str, Any],
    checkpoint: dict[str, Any],
    *,
    sequence: int | None = None,
    bundle_id: str | None = None,
) -> dict[str, Any]:
    try:
        normalized_state = validate_state(state)
    except AuditBundleTrustError as exc:
        raise AuditTrustCheckpointError(str(exc), rule_id="ATC002") from exc
    normalized_checkpoint = checkpoint_matches_state(checkpoint, normalized_state)
    if (sequence is None) == (bundle_id is None):
        raise AuditTrustCheckpointError(
            "select exactly one proof entry by sequence or bundle id",
            rule_id="ATC005",
        )
    selected: dict[str, Any] | None = None
    if sequence is not None:
        _integer(sequence, "proof sequence", 1)
        if sequence <= len(normalized_state["entries"]):
            selected = normalized_state["entries"][sequence - 1]
    else:
        wanted = _pin(bundle_id, "proof bundle id")
        for entry in normalized_state["entries"]:
            if entry["evidence"]["bundle_id"] == wanted:
                selected = entry
                break
    if selected is None:
        raise AuditTrustCheckpointError(
            "requested audit bundle entry is not present in trust state",
            rule_id="ATC005",
        )
    leaves = [_leaf_hash(entry) for entry in normalized_state["entries"]]
    audit_path = [
        item.hex() for item in _audit_path(leaves, selected["sequence"] - 1)
    ]
    core = {
        "proof_version": PROOF_VERSION,
        "checkpoint": _checkpoint_reference(normalized_checkpoint),
        "entry": selected,
        "audit_path": audit_path,
    }
    return {**core, "proof_id": _proof_identifier(core)}


def validate_proof(value: Any) -> dict[str, Any]:
    raw = _exact(value, PROOF_FIELDS, "audit trust inclusion proof")
    if raw["proof_version"] != PROOF_VERSION:
        raise AuditTrustCheckpointError(
            f"inclusion proof version must be {PROOF_VERSION}"
        )
    reference_raw = _exact(
        raw["checkpoint"], CHECKPOINT_REFERENCE_FIELDS, "proof checkpoint reference"
    )
    reference = {
        "checkpoint_id": _hash(reference_raw["checkpoint_id"], "proof checkpoint id"),
        "state_id": _hash(reference_raw["state_id"], "proof state id"),
        "entry_count": _integer(reference_raw["entry_count"], "proof entry count", 1),
        "merkle_root": _hash(reference_raw["merkle_root"], "proof Merkle root"),
    }
    entry = _entry(raw["entry"])
    audit_path_raw = raw["audit_path"]
    if not isinstance(audit_path_raw, list) or len(audit_path_raw) > MAX_AUDIT_PATH:
        raise AuditTrustCheckpointError(
            "proof audit path is malformed or exceeds the reviewed limit",
            rule_id="ATC006",
        )
    audit_path = [_hash(item, "proof audit path hash") for item in audit_path_raw]
    rebuilt = _verify_inclusion(
        entry, entry["sequence"], reference["entry_count"], audit_path
    )
    if rebuilt != reference["merkle_root"]:
        raise AuditTrustCheckpointError(
            "inclusion proof does not reconstruct the checkpoint Merkle root",
            rule_id="ATC006",
        )
    core = {
        "proof_version": PROOF_VERSION,
        "checkpoint": reference,
        "entry": entry,
        "audit_path": audit_path,
    }
    proof_id = _hash(raw["proof_id"], "proof id")
    if proof_id != _proof_identifier(core):
        raise AuditTrustCheckpointError(
            "proof id does not match its canonical payload", rule_id="ATC006"
        )
    return {**core, "proof_id": proof_id}


def proof_matches_checkpoint(
    proof: dict[str, Any], checkpoint: dict[str, Any]
) -> dict[str, Any]:
    normalized_proof = validate_proof(proof)
    normalized_checkpoint = validate_checkpoint(checkpoint)
    if normalized_proof["checkpoint"] != _checkpoint_reference(normalized_checkpoint):
        raise AuditTrustCheckpointError(
            "proof checkpoint reference does not match the supplied checkpoint",
            rule_id="ATC007",
        )
    return normalized_proof


def proof_matches_bundle(proof: dict[str, Any], bundle: Path) -> dict[str, Any]:
    normalized = validate_proof(proof)
    entry = normalized["entry"]
    evidence = entry["evidence"]
    expected_previous = None
    if entry["kind"] == "transition":
        expected_previous = entry["transition"]["previous_checkpoint_id"]
    try:
        verified = verify_bundle(
            Path(bundle),
            expected_bundle_id=evidence["bundle_id"],
            expected_candidate_checkpoint_id=evidence["checkpoint_id"],
            expected_previous_checkpoint_id=expected_previous,
        )
    except AuditEvidenceBundleError as exc:
        raise AuditTrustCheckpointError(
            f"audit bundle verification failed ({exc.rule_id}): {exc}",
            rule_id="ATC008",
        ) from exc
    expected_type = "snapshot" if entry["kind"] == "anchor" else "transition"
    candidate = verified.get("candidate")
    if not isinstance(candidate, dict):
        raise AuditTrustCheckpointError(
            "verified bundle candidate evidence is malformed", rule_id="ATC008"
        )
    actual = {
        "bundle_id": verified.get("bundle_id"),
        "checkpoint_id": candidate.get("checkpoint_id"),
        "catalog_id": candidate.get("catalog_id"),
        "generation": candidate.get("generation"),
        "segment_count": candidate.get("segment_count"),
        "merkle_root": candidate.get("merkle_root"),
    }
    if verified.get("bundle_type") != expected_type or actual != evidence:
        raise AuditTrustCheckpointError(
            "verified bundle does not match the authenticated trust entry",
            rule_id="ATC008",
        )
    return verified


def lineage(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    try:
        left_state = validate_state(left)
        right_state = validate_state(right)
    except AuditBundleTrustError as exc:
        raise AuditTrustCheckpointError(str(exc), rule_id="ATC002") from exc
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
        violations.append(
            {
                "rule_id": "ATC010",
                "message": "right audit trust state is older than left",
            }
        )
    elif relation == "fork":
        violations.append(
            {
                "rule_id": "ATC011",
                "message": "audit trust states diverge after a common prefix",
            }
        )
    common_entry = left_state["entries"][common - 1] if common else None
    core = {
        "lineage_version": LINEAGE_VERSION,
        "accepted": not violations,
        "relation": relation,
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
            "bundle_id": (
                common_entry["evidence"]["bundle_id"] if common_entry else None
            ),
        },
        "violations": violations,
    }
    return {**core, "lineage_id": _lineage_identifier(core)}


def _load_canonical(
    path: Path,
    validator: Callable[[Any], dict[str, Any]],
    label: str,
    limit: int,
) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditTrustCheckpointError(
            f"{label} must be a regular non-symlink file", rule_id="ATC001"
        )
    raw = path.read_bytes()
    if not raw or len(raw) > limit:
        raise AuditTrustCheckpointError(
            f"{label} size is outside the reviewed boundary", rule_id="ATC002"
        )
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, _DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
        raise AuditTrustCheckpointError(
            f"{label} is not strict JSON: {exc}", rule_id="ATC002"
        ) from exc
    normalized = validator(value)
    if raw != canonical_json(normalized):
        raise AuditTrustCheckpointError(
            f"{label} is not canonically serialized", rule_id="ATC002"
        )
    return normalized


def load_checkpoint(path: Path) -> dict[str, Any]:
    return _load_canonical(
        path, validate_checkpoint, "audit trust checkpoint", MAX_CHECKPOINT_BYTES
    )


def load_proof(path: Path) -> dict[str, Any]:
    return _load_canonical(
        path, validate_proof, "audit trust inclusion proof", MAX_PROOF_BYTES
    )


def _safe_parent(path: Path) -> Path:
    parent = Path(path).parent
    cursor = parent
    missing: list[Path] = []
    while not cursor.exists():
        missing.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    if cursor.is_symlink() or not cursor.is_dir():
        raise AuditTrustCheckpointError(
            "checkpoint output parent must be a regular non-symlink directory",
            rule_id="ATC001",
        )
    for directory in reversed(missing):
        directory.mkdir()
    if parent.is_symlink() or not parent.is_dir():
        raise AuditTrustCheckpointError(
            "checkpoint output parent must be a regular non-symlink directory",
            rule_id="ATC001",
        )
    return parent


def _write_new(path: Path, payload: dict[str, Any], label: str) -> None:
    path = Path(path)
    parent = _safe_parent(path)
    if path.is_symlink() or path.exists():
        raise AuditTrustCheckpointError(
            f"refusing to overwrite existing {label}", rule_id="ATC009"
        )
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
            raise AuditTrustCheckpointError(
                f"refusing to overwrite existing {label}", rule_id="ATC009"
            ) from exc
        try:
            output_stat = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise AuditTrustCheckpointError(
                f"unable to inspect created {label}", rule_id="ATC001"
            ) from exc
        if not stat.S_ISREG(output_stat.st_mode):
            raise AuditTrustCheckpointError(
                f"created {label} is not a regular file", rule_id="ATC001"
            )
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
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


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    if stream is None:
        stream = sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
        return
    for key in (
        "valid",
        "created",
        "checkpoint_id",
        "proof_id",
        "state_id",
        "lineage_id",
        "accepted",
        "relation",
        "rule_id",
        "error",
    ):
        if key in payload:
            print(f"{key}: {payload[key]}", file=stream)
    head = payload.get("head")
    if isinstance(head, dict):
        print(
            "head: "
            f"sequence={head['sequence']} generation={head['generation']} "
            f"bundle_id={head['bundle_id']}",
            file=stream,
        )
    entry = payload.get("entry")
    if isinstance(entry, dict):
        print(
            "entry: "
            f"sequence={entry['sequence']} bundle_id={entry['evidence']['bundle_id']}",
            file=stream,
        )
    for violation in payload.get("violations", []):
        print(f"- {violation['rule_id']}: {violation['message']}", file=stream)


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
    selector.add_argument("--bundle-id")
    prove.add_argument("--format", choices=("json", "text"), default="json")

    verify_proof = subparsers.add_parser("verify-proof")
    verify_proof.add_argument("proof", type=Path)
    verify_proof.add_argument("checkpoint", type=Path)
    verify_proof.add_argument("--expected-checkpoint-id", required=True)
    verify_proof.add_argument("--bundle", type=Path)
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
            expected_state_id = _pin(args.expected_state_id, "expected state id")
            if state["state_id"] != expected_state_id:
                raise AuditTrustCheckpointError(
                    "audit trust state does not match the externally pinned state id",
                    rule_id="ATC003",
                )
            checkpoint = create_checkpoint(state)
            _write_new(args.output, checkpoint, "audit trust checkpoint")
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
                args.expected_checkpoint_id, "expected checkpoint id"
            )
            if checkpoint["checkpoint_id"] != expected_checkpoint_id:
                raise AuditTrustCheckpointError(
                    "checkpoint does not match the externally pinned checkpoint id",
                    rule_id="ATC003",
                )
            if (args.state is None) != (args.expected_state_id is None):
                raise AuditTrustCheckpointError(
                    "state verification requires both --state and --expected-state-id"
                )
            if args.state is not None:
                state = load_state(args.state)
                expected_state_id = _pin(args.expected_state_id, "expected state id")
                if state["state_id"] != expected_state_id:
                    raise AuditTrustCheckpointError(
                        "audit trust state does not match the externally pinned state id",
                        rule_id="ATC003",
                    )
                checkpoint_matches_state(checkpoint, state)
            _emit(
                {
                    "valid": True,
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "state_id": checkpoint["state_id"],
                    "head": checkpoint["head"],
                    "entries": checkpoint["entry_count"],
                },
                args.format,
            )
            return 0

        if args.command == "prove":
            state = load_state(args.state)
            expected_state_id = _pin(args.expected_state_id, "expected state id")
            if state["state_id"] != expected_state_id:
                raise AuditTrustCheckpointError(
                    "audit trust state does not match the externally pinned state id",
                    rule_id="ATC003",
                )
            checkpoint = load_checkpoint(args.checkpoint)
            expected_checkpoint_id = _pin(
                args.expected_checkpoint_id, "expected checkpoint id"
            )
            if checkpoint["checkpoint_id"] != expected_checkpoint_id:
                raise AuditTrustCheckpointError(
                    "checkpoint does not match the externally pinned checkpoint id",
                    rule_id="ATC003",
                )
            proof = create_proof(
                state,
                checkpoint,
                sequence=args.sequence,
                bundle_id=args.bundle_id,
            )
            _write_new(args.output, proof, "audit trust inclusion proof")
            _emit(
                {
                    "created": str(args.output),
                    "proof_id": proof["proof_id"],
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "entry": proof["entry"],
                },
                args.format,
            )
            return 0

        if args.command == "verify-proof":
            proof = load_proof(args.proof)
            checkpoint = load_checkpoint(args.checkpoint)
            expected_checkpoint_id = _pin(
                args.expected_checkpoint_id, "expected checkpoint id"
            )
            if checkpoint["checkpoint_id"] != expected_checkpoint_id:
                raise AuditTrustCheckpointError(
                    "checkpoint does not match the externally pinned checkpoint id",
                    rule_id="ATC003",
                )
            proof = proof_matches_checkpoint(proof, checkpoint)
            bundle_verified = False
            if args.bundle is not None:
                proof_matches_bundle(proof, args.bundle)
                bundle_verified = True
            _emit(
                {
                    "valid": True,
                    "proof_id": proof["proof_id"],
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "entry": proof["entry"],
                    "bundle_verified": bundle_verified,
                },
                args.format,
            )
            return 0

        left = load_state(args.left)
        right = load_state(args.right)
        if left["state_id"] != _pin(
            args.expected_left_state_id, "expected left state id"
        ):
            raise AuditTrustCheckpointError(
                "left state does not match the externally pinned state id",
                rule_id="ATC003",
            )
        if right["state_id"] != _pin(
            args.expected_right_state_id, "expected right state id"
        ):
            raise AuditTrustCheckpointError(
                "right state does not match the externally pinned state id",
                rule_id="ATC003",
            )
        report = lineage(left, right)
        _emit(report, args.format)
        return 0 if report["accepted"] else 1
    except (AuditBundleTrustError, AuditTrustCheckpointError, OSError) as exc:
        if isinstance(exc, AuditTrustCheckpointError):
            error = exc
        else:
            error = AuditTrustCheckpointError(str(exc))
        _emit(
            {
                "valid": False,
                "rule_id": error.rule_id,
                "error": str(error),
            },
            getattr(args, "format", "json"),
            stream=sys.stderr,
        )
        return 1 if error.denied else 2


if __name__ == "__main__":
    raise SystemExit(main())
