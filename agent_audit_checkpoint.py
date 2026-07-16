#!/usr/bin/env python3
"""Portable Merkle checkpoints and inclusion proofs for audit segment catalogs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable

from agent_audit_catalog import (
    AuditCatalogError,
    _safe_directory_name,
    _validate_catalog,
    _validate_entry,
    load_catalog,
    verify_catalog,
)
from agent_audit_segments import MANIFEST_FILE, AuditSegmentError, inspect_segment_directory

CHECKPOINT_VERSION = 1
PROOF_VERSION = 1
MERKLE_ALGORITHM = "sha256-rfc6962-v1"
MAX_CHECKPOINT_BYTES = 1_000_000
MAX_PROOF_BYTES = 1_000_000
MAX_AUDIT_PATH = 64
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
CHECKPOINT_FIELDS = {"checkpoint_version", "catalog", "merkle", "checkpoint_id"}
CATALOG_REFERENCE_FIELDS = {
    "catalog_id",
    "generation",
    "previous_catalog_id",
    "segment_count",
    "total_records",
    "total_bytes",
    "latest_segment_id",
}
MERKLE_FIELDS = {"algorithm", "root"}
PROOF_FIELDS = {"proof_version", "checkpoint", "entry", "audit_path", "proof_id"}
PROOF_REFERENCE_FIELDS = {
    "checkpoint_id",
    "catalog_id",
    "generation",
    "segment_count",
    "merkle_root",
}


class AuditCatalogCheckpointError(ValueError):
    """Raised when checkpoint or proof evidence cannot be processed safely."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "AUP002",
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


def _encoded(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return _encoded(payload) + b"\n"


def _identifier(domain: bytes, payload: dict[str, Any]) -> str:
    return hashlib.sha256(domain + b"\0" + _encoded(payload)).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditCatalogCheckpointError(
            f"{label} must be 64 lowercase hexadecimal characters",
            rule_id="AUP002",
        )
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditCatalogCheckpointError(
            f"{label} must be an integer greater than or equal to {minimum}",
            rule_id="AUP002",
        )
    return value


def _exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditCatalogCheckpointError(
            f"{label} fields do not match the reviewed schema",
            rule_id="AUP002",
        )
    return value


def _catalog_reference(catalog: dict[str, Any]) -> dict[str, Any]:
    return {
        "catalog_id": catalog["catalog_id"],
        "generation": catalog["generation"],
        "previous_catalog_id": catalog["previous_catalog_id"],
        "segment_count": catalog["segment_count"],
        "total_records": catalog["total_records"],
        "total_bytes": catalog["total_bytes"],
        "latest_segment_id": catalog["latest_segment_id"],
    }


def _validate_catalog_reference(value: Any) -> dict[str, Any]:
    reference = _exact_fields(value, CATALOG_REFERENCE_FIELDS, "checkpoint catalog reference")
    normalized = {
        "catalog_id": _hash(reference["catalog_id"], "checkpoint catalog id"),
        "generation": _integer(reference["generation"], "checkpoint catalog generation", 1),
        "previous_catalog_id": _hash(
            reference["previous_catalog_id"], "checkpoint previous catalog id"
        ),
        "segment_count": _integer(
            reference["segment_count"], "checkpoint segment count", 1
        ),
        "total_records": _integer(
            reference["total_records"], "checkpoint total records", 1
        ),
        "total_bytes": _integer(reference["total_bytes"], "checkpoint total bytes", 1),
        "latest_segment_id": _hash(
            reference["latest_segment_id"], "checkpoint latest segment id"
        ),
    }
    if normalized != reference:
        raise AuditCatalogCheckpointError(
            "checkpoint catalog reference is not canonical",
            rule_id="AUP002",
        )
    return normalized


def _leaf_hash(entry: dict[str, Any]) -> bytes:
    return hashlib.sha256(b"\x00" + _encoded(entry)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(size: int) -> int:
    if size < 2:
        raise AuditCatalogCheckpointError(
            "Merkle split requires at least two leaves",
            rule_id="AUP003",
        )
    return 1 << ((size - 1).bit_length() - 1)


def _merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise AuditCatalogCheckpointError(
            "checkpoint requires at least one catalog entry",
            rule_id="AUP003",
        )
    if len(leaves) == 1:
        return leaves[0]
    split = _largest_power_of_two_less_than(len(leaves))
    return _node_hash(_merkle_root(leaves[:split]), _merkle_root(leaves[split:]))


def _audit_path(leaves: list[bytes], index: int) -> list[bytes]:
    if index < 0 or index >= len(leaves):
        raise AuditCatalogCheckpointError(
            "proof index is outside the checkpoint tree",
            rule_id="AUP008",
            denied=True,
        )
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
            raise AuditCatalogCheckpointError(
                "inclusion proof audit path is too short",
                rule_id="AUP006",
            )
        right = siblings[position[0]]
    else:
        right = _rebuild_root(leaf, index - split, size - split, siblings, position)
        if position[0] >= len(siblings):
            raise AuditCatalogCheckpointError(
                "inclusion proof audit path is too short",
                rule_id="AUP006",
            )
        left = siblings[position[0]]
    position[0] += 1
    return _node_hash(left, right)


def _verify_inclusion(
    entry: dict[str, Any],
    size: int,
    audit_path: list[str],
) -> str:
    index = entry["segment_index"] - 1
    if index < 0 or index >= size:
        raise AuditCatalogCheckpointError(
            "proof segment index is outside the checkpoint range",
            rule_id="AUP006",
        )
    siblings = [bytes.fromhex(_hash(item, "proof audit path hash")) for item in audit_path]
    position = [0]
    root = _rebuild_root(_leaf_hash(entry), index, size, siblings, position)
    if position[0] != len(siblings):
        raise AuditCatalogCheckpointError(
            "inclusion proof audit path contains extra hashes",
            rule_id="AUP006",
        )
    return root.hex()


def create_checkpoint(catalog: dict[str, Any]) -> dict[str, Any]:
    """Create one deterministic Merkle checkpoint from a validated catalog."""
    normalized = _validate_catalog(catalog)
    leaves = [_leaf_hash(entry) for entry in normalized["segments"]]
    core = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "catalog": _catalog_reference(normalized),
        "merkle": {
            "algorithm": MERKLE_ALGORITHM,
            "root": _merkle_root(leaves).hex(),
        },
    }
    return {
        **core,
        "checkpoint_id": _identifier(b"audit-catalog-checkpoint-v1", core),
    }


def validate_checkpoint(value: Any) -> dict[str, Any]:
    root = _exact_fields(value, CHECKPOINT_FIELDS, "catalog checkpoint")
    if root["checkpoint_version"] != CHECKPOINT_VERSION:
        raise AuditCatalogCheckpointError(
            f"checkpoint version must be {CHECKPOINT_VERSION}",
            rule_id="AUP002",
        )
    catalog = _validate_catalog_reference(root["catalog"])
    merkle_raw = _exact_fields(root["merkle"], MERKLE_FIELDS, "checkpoint Merkle data")
    if merkle_raw["algorithm"] != MERKLE_ALGORITHM:
        raise AuditCatalogCheckpointError(
            "checkpoint Merkle algorithm is unsupported",
            rule_id="AUP002",
        )
    merkle = {
        "algorithm": MERKLE_ALGORITHM,
        "root": _hash(merkle_raw["root"], "checkpoint Merkle root"),
    }
    core = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "catalog": catalog,
        "merkle": merkle,
    }
    checkpoint_id = _hash(root["checkpoint_id"], "checkpoint id")
    if checkpoint_id != _identifier(b"audit-catalog-checkpoint-v1", core):
        raise AuditCatalogCheckpointError(
            "checkpoint ID does not match its canonical payload",
            rule_id="AUP003",
        )
    return {**core, "checkpoint_id": checkpoint_id}


def checkpoint_matches_catalog(
    checkpoint: dict[str, Any], catalog: dict[str, Any]
) -> dict[str, Any]:
    normalized = validate_checkpoint(checkpoint)
    expected = create_checkpoint(_validate_catalog(catalog))
    if normalized != expected:
        raise AuditCatalogCheckpointError(
            "checkpoint does not match the canonical catalog",
            rule_id="AUP004",
            denied=True,
        )
    return normalized


def _proof_checkpoint_reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    catalog = checkpoint["catalog"]
    return {
        "checkpoint_id": checkpoint["checkpoint_id"],
        "catalog_id": catalog["catalog_id"],
        "generation": catalog["generation"],
        "segment_count": catalog["segment_count"],
        "merkle_root": checkpoint["merkle"]["root"],
    }


def _validate_proof_reference(value: Any) -> dict[str, Any]:
    reference = _exact_fields(value, PROOF_REFERENCE_FIELDS, "proof checkpoint reference")
    normalized = {
        "checkpoint_id": _hash(reference["checkpoint_id"], "proof checkpoint id"),
        "catalog_id": _hash(reference["catalog_id"], "proof catalog id"),
        "generation": _integer(reference["generation"], "proof catalog generation", 1),
        "segment_count": _integer(reference["segment_count"], "proof segment count", 1),
        "merkle_root": _hash(reference["merkle_root"], "proof Merkle root"),
    }
    if normalized != reference:
        raise AuditCatalogCheckpointError(
            "proof checkpoint reference is not canonical",
            rule_id="AUP005",
        )
    return normalized


def create_proof(
    catalog: dict[str, Any],
    checkpoint: dict[str, Any],
    *,
    segment_index: int | None = None,
    segment_id: str | None = None,
) -> dict[str, Any]:
    """Create a compact membership proof for one catalog segment entry."""
    normalized_catalog = _validate_catalog(catalog)
    normalized_checkpoint = checkpoint_matches_catalog(checkpoint, normalized_catalog)
    if (segment_index is None) == (segment_id is None):
        raise AuditCatalogCheckpointError(
            "select exactly one segment by index or ID",
            rule_id="AUP008",
            denied=True,
        )
    selected: dict[str, Any] | None = None
    if segment_index is not None:
        _integer(segment_index, "requested segment index", 1)
        if segment_index <= normalized_catalog["segment_count"]:
            selected = normalized_catalog["segments"][segment_index - 1]
    else:
        wanted = _hash(str(segment_id).lower(), "requested segment id")
        for entry in normalized_catalog["segments"]:
            if entry["segment_id"] == wanted:
                selected = entry
                break
    if selected is None:
        raise AuditCatalogCheckpointError(
            "requested segment is not present in the catalog",
            rule_id="AUP008",
            denied=True,
        )
    leaves = [_leaf_hash(entry) for entry in normalized_catalog["segments"]]
    core = {
        "proof_version": PROOF_VERSION,
        "checkpoint": _proof_checkpoint_reference(normalized_checkpoint),
        "entry": selected,
        "audit_path": [item.hex() for item in _audit_path(leaves, selected["segment_index"] - 1)],
    }
    return {
        **core,
        "proof_id": _identifier(b"audit-catalog-inclusion-proof-v1", core),
    }


def validate_proof(value: Any) -> dict[str, Any]:
    root = _exact_fields(value, PROOF_FIELDS, "catalog inclusion proof")
    if root["proof_version"] != PROOF_VERSION:
        raise AuditCatalogCheckpointError(
            f"proof version must be {PROOF_VERSION}",
            rule_id="AUP005",
        )
    reference = _validate_proof_reference(root["checkpoint"])
    entry_raw = root["entry"]
    if not isinstance(entry_raw, dict) or isinstance(entry_raw.get("segment_index"), bool):
        raise AuditCatalogCheckpointError("proof entry is malformed", rule_id="AUP005")
    entry = _validate_entry(entry_raw, entry_raw.get("segment_index"))
    if entry["segment_index"] > reference["segment_count"]:
        raise AuditCatalogCheckpointError(
            "proof entry lies outside the checkpoint segment range",
            rule_id="AUP006",
        )
    audit_path_raw = root["audit_path"]
    if not isinstance(audit_path_raw, list) or len(audit_path_raw) > MAX_AUDIT_PATH:
        raise AuditCatalogCheckpointError(
            "proof audit path is malformed or exceeds the reviewed limit",
            rule_id="AUP005",
        )
    audit_path = [_hash(item, "proof audit path hash") for item in audit_path_raw]
    rebuilt = _verify_inclusion(entry, reference["segment_count"], audit_path)
    if rebuilt != reference["merkle_root"]:
        raise AuditCatalogCheckpointError(
            "inclusion proof does not reconstruct the checkpoint Merkle root",
            rule_id="AUP006",
        )
    core = {
        "proof_version": PROOF_VERSION,
        "checkpoint": reference,
        "entry": entry,
        "audit_path": audit_path,
    }
    proof_id = _hash(root["proof_id"], "proof id")
    if proof_id != _identifier(b"audit-catalog-inclusion-proof-v1", core):
        raise AuditCatalogCheckpointError(
            "proof ID does not match its canonical payload",
            rule_id="AUP005",
        )
    return {**core, "proof_id": proof_id}


def proof_matches_checkpoint(
    proof: dict[str, Any], checkpoint: dict[str, Any]
) -> dict[str, Any]:
    normalized_proof = validate_proof(proof)
    normalized_checkpoint = validate_checkpoint(checkpoint)
    expected_reference = _proof_checkpoint_reference(normalized_checkpoint)
    if normalized_proof["checkpoint"] != expected_reference:
        raise AuditCatalogCheckpointError(
            "proof checkpoint reference does not match the supplied checkpoint",
            rule_id="AUP006",
            denied=True,
        )
    return normalized_proof


def proof_matches_segment_directory(
    proof: dict[str, Any], directory: Path
) -> dict[str, Any]:
    """Verify optional sealed segment bytes against the entry carried by a proof."""
    normalized = validate_proof(proof)
    directory = Path(directory)
    try:
        safe_name = _safe_directory_name(directory.name)
    except AuditCatalogError as exc:
        raise AuditCatalogCheckpointError(str(exc), rule_id="AUP001") from exc
    if safe_name != normalized["entry"]["directory"]:
        raise AuditCatalogCheckpointError(
            "segment directory name differs from the proof entry",
            rule_id="AUP009",
            denied=True,
        )
    try:
        inspected = inspect_segment_directory(directory)
    except AuditSegmentError as exc:
        raise AuditCatalogCheckpointError(
            f"segment directory failed independent verification: {exc}",
            rule_id="AUP009",
            denied=True,
        ) from exc
    manifest = directory / MANIFEST_FILE
    if manifest.is_symlink() or not manifest.is_file():
        raise AuditCatalogCheckpointError(
            "segment manifest must be a regular non-symlink file",
            rule_id="AUP001",
        )
    expected = normalized["entry"]
    actual = {
        "segment_index": inspected["segment_index"],
        "directory": safe_name,
        "segment_id": inspected["segment_id"],
        "previous_segment_id": inspected["previous_segment_id"],
        "manifest_sha256": _sha256_bytes(manifest.read_bytes()),
        "segment_sha256": inspected["sha256"],
        "head_hash": inspected["head_hash"],
        "records": inspected["records"],
        "bytes": inspected["bytes"],
    }
    if actual != expected:
        raise AuditCatalogCheckpointError(
            "sealed segment evidence does not match the proof entry",
            rule_id="AUP009",
            denied=True,
        )
    return actual


def _load_canonical(
    path: Path,
    validator: Callable[[Any], dict[str, Any]],
    label: str,
    limit: int,
) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditCatalogCheckpointError(
            f"{label} must be a regular non-symlink file",
            rule_id="AUP001",
        )
    raw = path.read_bytes()
    if not raw or len(raw) > limit:
        raise AuditCatalogCheckpointError(
            f"{label} size is outside the reviewed boundary",
            rule_id="AUP010",
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
        raise AuditCatalogCheckpointError(
            f"{label} is not strict JSON: {exc}",
            rule_id="AUP002",
        ) from exc
    normalized = validator(payload)
    if raw != _canonical_bytes(normalized):
        raise AuditCatalogCheckpointError(
            f"{label} is not canonically serialized",
            rule_id="AUP002",
        )
    return normalized


def load_checkpoint(path: Path) -> dict[str, Any]:
    return _load_canonical(path, validate_checkpoint, "checkpoint", MAX_CHECKPOINT_BYTES)


def load_proof(path: Path) -> dict[str, Any]:
    return _load_canonical(path, validate_proof, "inclusion proof", MAX_PROOF_BYTES)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, payload: dict[str, Any], label: str) -> None:
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise AuditCatalogCheckpointError(
            f"refusing to overwrite existing {label}",
            rule_id="AUP001",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
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
            raise AuditCatalogCheckpointError(
                f"refusing to overwrite existing {label}",
                rule_id="AUP001",
            ) from exc
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuditCatalogCheckpointError(
            f"{label} must be a string",
            rule_id="AUP002",
        )
    return _hash(value.lower(), label)


def _verified_catalog(
    path: Path,
    *,
    expected_catalog_id: str,
    active_path: Path | None,
) -> dict[str, Any]:
    try:
        verify_catalog(
            path,
            expected_catalog_id=expected_catalog_id,
            active_path=active_path,
            require_complete_discovery=True,
        )
        return load_catalog(path, expected_catalog_id=expected_catalog_id)
    except AuditCatalogError as exc:
        raise AuditCatalogCheckpointError(
            f"catalog verification failed: {exc}",
            rule_id="AUP004",
            denied=exc.denied,
        ) from exc


def _text(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    for key in (
        "valid",
        "created",
        "checkpoint_id",
        "proof_id",
        "catalog_id",
        "generation",
        "segment_count",
        "merkle_root",
    ):
        if key in payload:
            lines.append(f"{key}: {payload[key]}")
    entry = payload.get("entry")
    if isinstance(entry, dict):
        lines.append(
            f"entry: index={entry['segment_index']} segment_id={entry['segment_id']} directory={entry['directory']}"
        )
    if payload.get("segment_verified"):
        lines.append("segment_verified: true")
    return "\n".join(lines)


def _emit(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        print(_text(payload))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-audit-catalog-checkpoint")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("catalog", type=Path)
    create.add_argument("output", type=Path)
    create.add_argument("--expected-catalog-id", required=True)
    create.add_argument("--active", type=Path)
    create.add_argument("--format", choices=("text", "json"), default="json")

    verify = subparsers.add_parser("verify")
    verify.add_argument("checkpoint", type=Path)
    verify.add_argument("--expected-checkpoint-id", required=True)
    verify.add_argument("--catalog", type=Path)
    verify.add_argument("--expected-catalog-id")
    verify.add_argument("--active", type=Path)
    verify.add_argument("--format", choices=("text", "json"), default="json")

    prove = subparsers.add_parser("prove")
    prove.add_argument("catalog", type=Path)
    prove.add_argument("checkpoint", type=Path)
    prove.add_argument("output", type=Path)
    prove.add_argument("--expected-catalog-id", required=True)
    prove.add_argument("--expected-checkpoint-id", required=True)
    prove.add_argument("--active", type=Path)
    selector = prove.add_mutually_exclusive_group(required=True)
    selector.add_argument("--segment-index", type=int)
    selector.add_argument("--segment-id")
    prove.add_argument("--format", choices=("text", "json"), default="json")

    verify_proof = subparsers.add_parser("verify-proof")
    verify_proof.add_argument("proof", type=Path)
    verify_proof.add_argument("checkpoint", type=Path)
    verify_proof.add_argument("--expected-checkpoint-id", required=True)
    verify_proof.add_argument("--segment-dir", type=Path)
    verify_proof.add_argument("--format", choices=("text", "json"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            catalog_pin = _pin(args.expected_catalog_id, "expected catalog id")
            catalog = _verified_catalog(
                args.catalog,
                expected_catalog_id=catalog_pin,
                active_path=args.active,
            )
            checkpoint = create_checkpoint(catalog)
            _write_new(args.output, checkpoint, "checkpoint")
            _emit(
                {
                    "created": str(args.output),
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "catalog_id": checkpoint["catalog"]["catalog_id"],
                    "generation": checkpoint["catalog"]["generation"],
                    "segment_count": checkpoint["catalog"]["segment_count"],
                    "merkle_root": checkpoint["merkle"]["root"],
                },
                args.format,
            )
            return 0

        if args.command == "verify":
            checkpoint = load_checkpoint(args.checkpoint)
            checkpoint_pin = _pin(args.expected_checkpoint_id, "expected checkpoint id")
            if checkpoint["checkpoint_id"] != checkpoint_pin:
                raise AuditCatalogCheckpointError(
                    "checkpoint differs from the externally retained pin",
                    rule_id="AUP007",
                    denied=True,
                )
            if args.catalog is not None:
                if args.expected_catalog_id is None:
                    raise AuditCatalogCheckpointError(
                        "--expected-catalog-id is required when --catalog is supplied",
                        rule_id="AUP002",
                    )
                catalog_pin = _pin(args.expected_catalog_id, "expected catalog id")
                catalog = _verified_catalog(
                    args.catalog,
                    expected_catalog_id=catalog_pin,
                    active_path=args.active,
                )
                checkpoint_matches_catalog(checkpoint, catalog)
            elif args.expected_catalog_id is not None or args.active is not None:
                raise AuditCatalogCheckpointError(
                    "--expected-catalog-id and --active require --catalog",
                    rule_id="AUP002",
                )
            _emit(
                {
                    "valid": True,
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "catalog_id": checkpoint["catalog"]["catalog_id"],
                    "generation": checkpoint["catalog"]["generation"],
                    "segment_count": checkpoint["catalog"]["segment_count"],
                    "merkle_root": checkpoint["merkle"]["root"],
                },
                args.format,
            )
            return 0

        if args.command == "prove":
            catalog_pin = _pin(args.expected_catalog_id, "expected catalog id")
            checkpoint_pin = _pin(args.expected_checkpoint_id, "expected checkpoint id")
            catalog = _verified_catalog(
                args.catalog,
                expected_catalog_id=catalog_pin,
                active_path=args.active,
            )
            checkpoint = load_checkpoint(args.checkpoint)
            if checkpoint["checkpoint_id"] != checkpoint_pin:
                raise AuditCatalogCheckpointError(
                    "checkpoint differs from the externally retained pin",
                    rule_id="AUP007",
                    denied=True,
                )
            proof = create_proof(
                catalog,
                checkpoint,
                segment_index=args.segment_index,
                segment_id=args.segment_id,
            )
            _write_new(args.output, proof, "inclusion proof")
            _emit(
                {
                    "created": str(args.output),
                    "proof_id": proof["proof_id"],
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "catalog_id": catalog["catalog_id"],
                    "entry": proof["entry"],
                },
                args.format,
            )
            return 0

        proof = load_proof(args.proof)
        checkpoint = load_checkpoint(args.checkpoint)
        checkpoint_pin = _pin(args.expected_checkpoint_id, "expected checkpoint id")
        if checkpoint["checkpoint_id"] != checkpoint_pin:
            raise AuditCatalogCheckpointError(
                "checkpoint differs from the externally retained pin",
                rule_id="AUP007",
                denied=True,
            )
        proof = proof_matches_checkpoint(proof, checkpoint)
        segment_verified = False
        if args.segment_dir is not None:
            proof_matches_segment_directory(proof, args.segment_dir)
            segment_verified = True
        _emit(
            {
                "valid": True,
                "proof_id": proof["proof_id"],
                "checkpoint_id": checkpoint["checkpoint_id"],
                "catalog_id": proof["checkpoint"]["catalog_id"],
                "entry": proof["entry"],
                "segment_verified": segment_verified,
            },
            args.format,
        )
        return 0
    except (AuditCatalogCheckpointError, OSError) as exc:
        error = exc if isinstance(exc, AuditCatalogCheckpointError) else AuditCatalogCheckpointError(
            str(exc), rule_id="AUP001"
        )
        print(
            f"Audit catalog checkpoint error: {error.rule_id}: {error}",
            file=__import__("sys").stderr,
        )
        return 1 if error.denied else 2


if __name__ == "__main__":
    raise SystemExit(main())
