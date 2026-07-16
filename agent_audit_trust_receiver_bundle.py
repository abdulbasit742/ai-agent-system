#!/usr/bin/env python3
"""Create and verify exact-boundary audit trust receiver handoff bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from agent_audit_trust_receiver import canonical_json as receiver_json
from agent_audit_trust_receiver_checkpoint import (
    AuditTrustReceiverCheckpointError,
    load_checkpoint,
    load_proof,
    proof_matches_checkpoint,
    validate_checkpoint,
    validate_proof,
)
from agent_audit_trust_receiver_consistency import (
    AuditTrustReceiverConsistencyError,
    load_consistency_proof,
    proof_matches_checkpoints,
    validate_consistency_proof,
)

BUNDLE_VERSION = 1
MANIFEST_NAME = "audit-trust-receiver-bundle-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
CANDIDATE_CHECKPOINT_NAME = "candidate-receiver-checkpoint.json"
PREVIOUS_CHECKPOINT_NAME = "previous-receiver-checkpoint.json"
CONSISTENCY_NAME = "receiver-consistency-proof.json"
MAX_MANIFEST_BYTES = 2_000_000
MAX_BUNDLE_FILES = 260
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_PROOFS = 128
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

MANIFEST_FIELDS = {
    "bundle_version", "bundle_type", "candidate", "previous", "consistency",
    "entries", "files", "bundle_id",
}
CHECKPOINT_REFERENCE_FIELDS = {
    "checkpoint_id", "state_id", "entry_count", "head", "merkle_root",
}
CONSISTENCY_REFERENCE_FIELDS = {
    "consistency_id", "relation", "previous_checkpoint_id", "candidate_checkpoint_id",
}
ENTRY_FIELDS = {
    "sequence", "kind", "handoff_bundle_id", "proof_id", "proof_path", "is_head",
}
FILE_FIELDS = {"path", "role", "sha256", "size"}
FILE_ROLES = {
    "candidate-receiver-checkpoint", "previous-receiver-checkpoint",
    "receiver-consistency-proof", "receiver-inclusion-proof",
}


class AuditTrustReceiverBundleError(ValueError):
    """Raised when portable receiver evidence cannot be handled safely."""

    def __init__(self, message: str, *, rule_id: str = "ARB002", denied: bool = False) -> None:
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


def _manifest_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditTrustReceiverBundleError(
            f"{label} must be 64 lowercase hexadecimal characters", rule_id="ARB002"
        )
    return value


def _pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuditTrustReceiverBundleError(f"{label} must be a string", rule_id="ARB003")
    lowered = value.lower()
    if not HEX_64.fullmatch(lowered):
        raise AuditTrustReceiverBundleError(
            f"{label} must be 64 hexadecimal characters", rule_id="ARB003"
        )
    return lowered


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditTrustReceiverBundleError(
            f"{label} must be an integer greater than or equal to {minimum}", rule_id="ARB002"
        )
    return value


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditTrustReceiverBundleError(
            f"{label} fields do not match the reviewed schema", rule_id="ARB002"
        )
    return value


def _safe_relative(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AuditTrustReceiverBundleError(f"{label} is unsafe", rule_id="ARB001")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or not path.parts:
        raise AuditTrustReceiverBundleError(f"{label} is unsafe", rule_id="ARB001")
    if any(part in {".", ".."} or not SAFE_COMPONENT.fullmatch(part) for part in path.parts):
        raise AuditTrustReceiverBundleError(f"{label} is unsafe", rule_id="ARB001")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"audit-trust-receiver-evidence-bundle-v1\x00" + _manifest_bytes(payload)
    ).hexdigest()


def _checkpoint_reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    try:
        normalized = validate_checkpoint(checkpoint)
    except AuditTrustReceiverCheckpointError as exc:
        raise AuditTrustReceiverBundleError(
            f"receiver checkpoint validation failed: {exc}", rule_id="ARB004", denied=exc.denied
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
    checkpoint = {
        "checkpoint_version": 1,
        "state_id": raw["state_id"],
        "entry_count": raw["entry_count"],
        "head": raw["head"],
        "merkle": {"algorithm": "sha256-rfc6962-v1", "root": raw["merkle_root"]},
        "checkpoint_id": raw["checkpoint_id"],
    }
    normalized = _checkpoint_reference(checkpoint)
    if normalized != raw:
        raise AuditTrustReceiverBundleError(f"{label} is not canonical", rule_id="ARB002")
    return normalized


def _consistency_reference(proof: dict[str, Any]) -> dict[str, Any]:
    try:
        normalized = validate_consistency_proof(proof)
    except AuditTrustReceiverConsistencyError as exc:
        raise AuditTrustReceiverBundleError(
            f"receiver consistency proof validation failed: {exc}",
            rule_id="ARB005", denied=exc.denied,
        ) from exc
    return {
        "consistency_id": normalized["consistency_id"],
        "relation": normalized["relation"],
        "previous_checkpoint_id": normalized["previous"]["checkpoint_id"],
        "candidate_checkpoint_id": normalized["candidate"]["checkpoint_id"],
    }


def _validate_consistency_reference(value: Any) -> dict[str, Any]:
    raw = _exact(value, CONSISTENCY_REFERENCE_FIELDS, "receiver consistency reference")
    if raw["relation"] != "right-descendant":
        raise AuditTrustReceiverBundleError(
            "transition bundle requires right-descendant receiver continuity",
            rule_id="ARB006", denied=True,
        )
    normalized = {
        "consistency_id": _hash(raw["consistency_id"], "receiver consistency id"),
        "relation": raw["relation"],
        "previous_checkpoint_id": _hash(
            raw["previous_checkpoint_id"], "receiver consistency previous checkpoint id"
        ),
        "candidate_checkpoint_id": _hash(
            raw["candidate_checkpoint_id"], "receiver consistency candidate checkpoint id"
        ),
    }
    if normalized != raw:
        raise AuditTrustReceiverBundleError(
            "receiver consistency reference is not canonical", rule_id="ARB002"
        )
    return normalized


def _entry_record(proof: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    try:
        normalized = validate_proof(proof)
    except AuditTrustReceiverCheckpointError as exc:
        raise AuditTrustReceiverBundleError(
            f"receiver inclusion proof validation failed: {exc}",
            rule_id="ARB004", denied=exc.denied,
        ) from exc
    entry = normalized["entry"]
    sequence = entry["sequence"]
    return {
        "sequence": sequence,
        "kind": entry["kind"],
        "handoff_bundle_id": entry["evidence"]["handoff_bundle_id"],
        "proof_id": normalized["proof_id"],
        "proof_path": f"proofs/receiver-entry-{sequence:08d}.json",
        "is_head": sequence == candidate["entry_count"],
    }


def _validate_entry(value: Any, candidate: dict[str, Any]) -> dict[str, Any]:
    raw = _exact(value, ENTRY_FIELDS, "receiver bundle entry")
    sequence = _integer(raw["sequence"], "receiver bundle entry sequence", 1)
    kind = raw["kind"]
    if kind not in {"anchor", "transition"} or (sequence == 1) != (kind == "anchor"):
        raise AuditTrustReceiverBundleError(
            "receiver bundle entry kind is inconsistent with sequence", rule_id="ARB002"
        )
    if not isinstance(raw["is_head"], bool):
        raise AuditTrustReceiverBundleError(
            "receiver bundle entry head marker must be boolean", rule_id="ARB002"
        )
    normalized = {
        "sequence": sequence,
        "kind": kind,
        "handoff_bundle_id": _hash(
            raw["handoff_bundle_id"], "receiver bundle entry handoff bundle id"
        ),
        "proof_id": _hash(raw["proof_id"], "receiver bundle entry proof id"),
        "proof_path": _safe_relative(raw["proof_path"], "receiver bundle proof path"),
        "is_head": raw["is_head"],
    }
    if normalized["proof_path"] != f"proofs/receiver-entry-{sequence:08d}.json":
        raise AuditTrustReceiverBundleError(
            "receiver bundle proof path is not canonical", rule_id="ARB002"
        )
    if sequence > candidate["entry_count"]:
        raise AuditTrustReceiverBundleError(
            "receiver bundle entry exceeds candidate checkpoint range",
            rule_id="ARB004", denied=True,
        )
    if normalized["is_head"] != (sequence == candidate["entry_count"]):
        raise AuditTrustReceiverBundleError(
            "receiver bundle entry head marker is inconsistent", rule_id="ARB012"
        )
    if normalized != raw:
        raise AuditTrustReceiverBundleError(
            "receiver bundle entry is not canonical", rule_id="ARB002"
        )
    return normalized


def _file_record(path: Path, relative: str, role: str) -> dict[str, Any]:
    if role not in FILE_ROLES:
        raise AuditTrustReceiverBundleError(
            "unsupported receiver bundle file role", rule_id="ARB002"
        )
    return {
        "path": _safe_relative(relative, "receiver bundle file path"),
        "role": role,
        "sha256": _sha256_file(path),
        "size": path.stat().st_size,
    }


def _validate_file(value: Any) -> dict[str, Any]:
    raw = _exact(value, FILE_FIELDS, "receiver bundle file record")
    if raw["role"] not in FILE_ROLES:
        raise AuditTrustReceiverBundleError(
            "receiver bundle file role is unsupported", rule_id="ARB002"
        )
    normalized = {
        "path": _safe_relative(raw["path"], "receiver bundle file path"),
        "role": raw["role"],
        "sha256": _hash(raw["sha256"], "receiver bundle file digest"),
        "size": _integer(raw["size"], "receiver bundle file size"),
    }
    if normalized != raw:
        raise AuditTrustReceiverBundleError(
            "receiver bundle file record is not canonical", rule_id="ARB002"
        )
    return normalized


def _bundle_id(payload: dict[str, Any]) -> str:
    core = dict(payload)
    core.pop("bundle_id", None)
    return _identifier(core)


def validate_manifest(value: Any) -> dict[str, Any]:
    root = _exact(value, MANIFEST_FIELDS, "audit trust receiver bundle manifest")
    if root["bundle_version"] != BUNDLE_VERSION:
        raise AuditTrustReceiverBundleError(
            f"bundle version must be {BUNDLE_VERSION}", rule_id="ARB002"
        )
    bundle_type = root["bundle_type"]
    if bundle_type not in {"snapshot", "transition"}:
        raise AuditTrustReceiverBundleError("bundle type is unsupported", rule_id="ARB005")
    candidate = _validate_checkpoint_reference(root["candidate"], "candidate receiver checkpoint")
    if bundle_type == "snapshot":
        if root["previous"] is not None or root["consistency"] is not None:
            raise AuditTrustReceiverBundleError(
                "snapshot receiver bundle must not contain transition evidence", rule_id="ARB005"
            )
        previous = consistency = None
    else:
        if root["previous"] is None or root["consistency"] is None:
            raise AuditTrustReceiverBundleError(
                "transition receiver bundle requires previous checkpoint and consistency evidence",
                rule_id="ARB005",
            )
        previous = _validate_checkpoint_reference(
            root["previous"], "previous receiver checkpoint"
        )
        consistency = _validate_consistency_reference(root["consistency"])
        if previous["entry_count"] >= candidate["entry_count"]:
            raise AuditTrustReceiverBundleError(
                "transition receiver candidate must extend the previous checkpoint",
                rule_id="ARB006", denied=True,
            )
        if (
            consistency["previous_checkpoint_id"] != previous["checkpoint_id"]
            or consistency["candidate_checkpoint_id"] != candidate["checkpoint_id"]
        ):
            raise AuditTrustReceiverBundleError(
                "receiver consistency reference does not bind both checkpoints",
                rule_id="ARB005", denied=True,
            )

    entries_raw = root["entries"]
    if not isinstance(entries_raw, list) or not entries_raw or len(entries_raw) > MAX_PROOFS:
        raise AuditTrustReceiverBundleError(
            "receiver bundle entries are missing or exceed the reviewed limit", rule_id="ARB010"
        )
    entries = [_validate_entry(item, candidate) for item in entries_raw]
    if entries != sorted(entries, key=lambda item: item["sequence"]):
        raise AuditTrustReceiverBundleError(
            "receiver bundle entries are not canonically ordered", rule_id="ARB002"
        )
    for key in ("sequence", "handoff_bundle_id", "proof_id", "proof_path"):
        values = [entry[key] for entry in entries]
        if len(values) != len(set(values)):
            raise AuditTrustReceiverBundleError(
                f"receiver bundle entries contain duplicate {key}", rule_id="ARB007"
            )
    if sum(1 for entry in entries if entry["is_head"]) != 1:
        raise AuditTrustReceiverBundleError(
            "receiver bundle must contain exactly one candidate-head inclusion proof",
            rule_id="ARB012",
        )

    files_raw = root["files"]
    if not isinstance(files_raw, list) or not files_raw or len(files_raw) > MAX_BUNDLE_FILES:
        raise AuditTrustReceiverBundleError(
            "receiver bundle file records are missing or exceed the reviewed limit",
            rule_id="ARB010",
        )
    files = [_validate_file(item) for item in files_raw]
    if files != sorted(files, key=lambda item: item["path"]):
        raise AuditTrustReceiverBundleError(
            "receiver bundle file records are not canonically ordered", rule_id="ARB002"
        )
    paths = [record["path"] for record in files]
    if len(paths) != len(set(paths)):
        raise AuditTrustReceiverBundleError(
            "receiver bundle file records contain duplicate paths", rule_id="ARB007"
        )
    if sum(record["size"] for record in files) > MAX_BUNDLE_BYTES:
        raise AuditTrustReceiverBundleError(
            "receiver bundle exceeds the reviewed byte limit", rule_id="ARB010"
        )
    by_role = {role: [] for role in FILE_ROLES}
    for record in files:
        by_role[record["role"]].append(record["path"])
    if by_role["candidate-receiver-checkpoint"] != [CANDIDATE_CHECKPOINT_NAME]:
        raise AuditTrustReceiverBundleError(
            "candidate receiver checkpoint file boundary is invalid", rule_id="ARB008"
        )
    if bundle_type == "snapshot":
        if by_role["previous-receiver-checkpoint"] or by_role["receiver-consistency-proof"]:
            raise AuditTrustReceiverBundleError(
                "snapshot receiver bundle contains transition-only files", rule_id="ARB005"
            )
    else:
        if by_role["previous-receiver-checkpoint"] != [PREVIOUS_CHECKPOINT_NAME]:
            raise AuditTrustReceiverBundleError(
                "previous receiver checkpoint file boundary is invalid", rule_id="ARB008"
            )
        if by_role["receiver-consistency-proof"] != [CONSISTENCY_NAME]:
            raise AuditTrustReceiverBundleError(
                "receiver consistency proof file boundary is invalid", rule_id="ARB008"
            )
    if set(by_role["receiver-inclusion-proof"]) != {
        entry["proof_path"] for entry in entries
    }:
        raise AuditTrustReceiverBundleError(
            "receiver inclusion proof boundary differs from manifest entries", rule_id="ARB008"
        )
    core = {
        "bundle_version": BUNDLE_VERSION,
        "bundle_type": bundle_type,
        "candidate": candidate,
        "previous": previous,
        "consistency": consistency,
        "entries": entries,
        "files": files,
    }
    bundle_id = _hash(root["bundle_id"], "receiver bundle id")
    if bundle_id != _bundle_id(core):
        raise AuditTrustReceiverBundleError(
            "receiver bundle ID does not match its canonical manifest payload",
            rule_id="ARB003",
        )
    return {**core, "bundle_id": bundle_id}


def _load_json(
    path: Path,
    validator: Callable[[Any], dict[str, Any]],
    label: str,
    limit: int,
) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditTrustReceiverBundleError(
            f"{label} must be a regular non-symlink file", rule_id="ARB001"
        )
    raw = path.read_bytes()
    if not raw or len(raw) > limit:
        raise AuditTrustReceiverBundleError(
            f"{label} size is outside the reviewed boundary", rule_id="ARB002"
        )
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_json_object, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, _DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
        raise AuditTrustReceiverBundleError(
            f"{label} is not strict JSON: {exc}", rule_id="ARB002"
        ) from exc
    normalized = validator(value)
    if raw != _manifest_bytes(normalized):
        raise AuditTrustReceiverBundleError(
            f"{label} is not canonically serialized", rule_id="ARB002"
        )
    return normalized


def load_manifest(path: Path) -> dict[str, Any]:
    return _load_json(path, validate_manifest, "receiver bundle manifest", MAX_MANIFEST_BYTES)


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
        raise AuditTrustReceiverBundleError(
            "receiver bundle parent must be a regular non-symlink directory", rule_id="ARB001"
        )
    for directory in reversed(missing):
        directory.mkdir()
    if parent.is_symlink() or not parent.is_dir():
        raise AuditTrustReceiverBundleError(
            "receiver bundle parent must be a regular non-symlink directory", rule_id="ARB001"
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


def _write_bytes(path: Path, payload: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        raise AuditTrustReceiverBundleError(
            "receiver bundle staging file already exists or is a symlink", rule_id="ARB011"
        )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _walk_files(root: Path) -> tuple[dict[str, Path], int]:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise AuditTrustReceiverBundleError(
            "receiver bundle must be a regular non-symlink directory", rule_id="ARB001"
        )
    files: dict[str, Path] = {}
    total = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in list(dirnames):
            child = base / name
            if child.is_symlink():
                raise AuditTrustReceiverBundleError(
                    "receiver bundle contains a symlink directory", rule_id="ARB001"
                )
        for name in filenames:
            child = base / name
            if child.is_symlink():
                raise AuditTrustReceiverBundleError(
                    "receiver bundle contains a symlink file", rule_id="ARB001"
                )
            metadata = child.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise AuditTrustReceiverBundleError(
                    "receiver bundle contains a non-regular file", rule_id="ARB001"
                )
            relative = child.relative_to(root).as_posix()
            _safe_relative(relative, "receiver bundle path")
            files[relative] = child
            total += metadata.st_size
            if len(files) > MAX_BUNDLE_FILES or total > MAX_BUNDLE_BYTES:
                raise AuditTrustReceiverBundleError(
                    "receiver bundle exceeds the reviewed boundary", rule_id="ARB010"
                )
    return files, total


def _checksums_text(records: Iterable[dict[str, Any]], manifest_path: Path) -> str:
    lines = [f"{record['sha256']}  {record['path']}" for record in records]
    lines.append(f"{_sha256_file(manifest_path)}  {MANIFEST_NAME}")
    return "\n".join(sorted(lines)) + "\n"


def _load_checksums(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise AuditTrustReceiverBundleError(
            "receiver bundle checksums must be a regular file", rule_id="ARB008"
        )
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if len(raw) < 67 or raw[64:66] != "  ":
            raise AuditTrustReceiverBundleError(
                "receiver bundle checksums are malformed", rule_id="ARB008"
            )
        digest, relative = raw[:64], raw[66:]
        _hash(digest, "receiver bundle checksum")
        _safe_relative(relative, "receiver bundle checksum path")
        if relative in result:
            raise AuditTrustReceiverBundleError(
                "receiver bundle checksums contain a duplicate path", rule_id="ARB008"
            )
        result[relative] = digest
    return result


def _load_pinned_checkpoint(path: Path, expected_id: str, label: str) -> dict[str, Any]:
    try:
        checkpoint = load_checkpoint(path)
    except AuditTrustReceiverCheckpointError as exc:
        raise AuditTrustReceiverBundleError(
            f"{label} receiver checkpoint verification failed: {exc}",
            rule_id="ARB004", denied=exc.denied,
        ) from exc
    expected = _pin(expected_id, f"expected {label} receiver checkpoint id")
    if checkpoint["checkpoint_id"] != expected:
        raise AuditTrustReceiverBundleError(
            f"{label} receiver checkpoint differs from the external pin",
            rule_id="ARB003", denied=True,
        )
    return checkpoint


def _load_bound_proof(path: Path, checkpoint: dict[str, Any]) -> dict[str, Any]:
    try:
        return proof_matches_checkpoint(load_proof(path), checkpoint)
    except AuditTrustReceiverCheckpointError as exc:
        raise AuditTrustReceiverBundleError(
            f"receiver inclusion proof verification failed: {exc}",
            rule_id="ARB004", denied=exc.denied,
        ) from exc


def _load_bound_consistency(
    path: Path, previous: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    try:
        proof = proof_matches_checkpoints(load_consistency_proof(path), previous, candidate)
    except AuditTrustReceiverConsistencyError as exc:
        raise AuditTrustReceiverBundleError(
            f"receiver consistency proof verification failed: {exc}",
            rule_id="ARB005", denied=exc.denied,
        ) from exc
    if proof["relation"] != "right-descendant":
        raise AuditTrustReceiverBundleError(
            "transition receiver bundle requires right-descendant continuity",
            rule_id="ARB006", denied=True,
        )
    return proof


def create_bundle(
    output_dir: Path,
    candidate_checkpoint_path: Path,
    expected_candidate_checkpoint_id: str,
    proof_paths: Iterable[Path],
    *,
    previous_checkpoint_path: Path | None = None,
    expected_previous_checkpoint_id: str | None = None,
    consistency_path: Path | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    if output.is_symlink() or output.exists():
        raise AuditTrustReceiverBundleError(
            "receiver bundle output must not already exist or be a symlink", rule_id="ARB011"
        )
    parent = _safe_parent(output)
    candidate = _load_pinned_checkpoint(
        candidate_checkpoint_path, expected_candidate_checkpoint_id, "candidate"
    )
    proof_sources = [Path(path) for path in proof_paths]
    if not proof_sources or len(proof_sources) > MAX_PROOFS:
        raise AuditTrustReceiverBundleError(
            "at least one receiver inclusion proof is required within the limit",
            rule_id="ARB010",
        )
    proofs = [_load_bound_proof(path, candidate) for path in proof_sources]
    entries = sorted(
        (_entry_record(proof, candidate) for proof in proofs), key=lambda item: item["sequence"]
    )
    for key in ("sequence", "handoff_bundle_id", "proof_id", "proof_path"):
        values = [entry[key] for entry in entries]
        if len(values) != len(set(values)):
            raise AuditTrustReceiverBundleError(
                f"receiver inclusion proofs contain duplicate {key}", rule_id="ARB007"
            )
    if sum(1 for entry in entries if entry["is_head"]) != 1:
        raise AuditTrustReceiverBundleError(
            "candidate receiver-head inclusion proof is required", rule_id="ARB012"
        )
    transition_values = (
        previous_checkpoint_path, expected_previous_checkpoint_id, consistency_path
    )
    supplied = [value is not None for value in transition_values]
    if any(supplied) and not all(supplied):
        raise AuditTrustReceiverBundleError(
            "transition receiver bundle requires previous checkpoint, pin, and consistency proof",
            rule_id="ARB005",
        )
    previous = consistency = None
    bundle_type = "snapshot"
    if all(supplied):
        previous = _load_pinned_checkpoint(
            Path(previous_checkpoint_path), str(expected_previous_checkpoint_id), "previous"
        )
        consistency = _load_bound_consistency(Path(consistency_path), previous, candidate)
        bundle_type = "transition"

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", suffix=".tmp", dir=parent))
    os.chmod(staging, 0o700)
    try:
        records: list[dict[str, Any]] = []
        candidate_target = staging / CANDIDATE_CHECKPOINT_NAME
        _write_bytes(candidate_target, receiver_json(candidate))
        records.append(_file_record(
            candidate_target, CANDIDATE_CHECKPOINT_NAME, "candidate-receiver-checkpoint"
        ))
        if previous is not None and consistency is not None:
            previous_target = staging / PREVIOUS_CHECKPOINT_NAME
            consistency_target = staging / CONSISTENCY_NAME
            _write_bytes(previous_target, receiver_json(previous))
            _write_bytes(consistency_target, receiver_json(consistency))
            records.append(_file_record(
                previous_target, PREVIOUS_CHECKPOINT_NAME, "previous-receiver-checkpoint"
            ))
            records.append(_file_record(
                consistency_target, CONSISTENCY_NAME, "receiver-consistency-proof"
            ))
        proof_by_sequence = {proof["entry"]["sequence"]: proof for proof in proofs}
        for entry in entries:
            target = staging / entry["proof_path"]
            _write_bytes(target, receiver_json(proof_by_sequence[entry["sequence"]]))
            records.append(_file_record(
                target, entry["proof_path"], "receiver-inclusion-proof"
            ))
        records.sort(key=lambda item: item["path"])
        core = {
            "bundle_version": BUNDLE_VERSION,
            "bundle_type": bundle_type,
            "candidate": _checkpoint_reference(candidate),
            "previous": _checkpoint_reference(previous) if previous is not None else None,
            "consistency": _consistency_reference(consistency) if consistency is not None else None,
            "entries": entries,
            "files": records,
        }
        manifest = validate_manifest({**core, "bundle_id": _bundle_id(core)})
        manifest_path = staging / MANIFEST_NAME
        _write_bytes(manifest_path, _manifest_bytes(manifest))
        _write_bytes(
            staging / CHECKSUMS_NAME,
            _checksums_text(records, manifest_path).encode("utf-8"),
        )
        _fsync_directory(staging)
        verify_bundle(
            staging,
            expected_bundle_id=manifest["bundle_id"],
            expected_candidate_checkpoint_id=candidate["checkpoint_id"],
            expected_previous_checkpoint_id=(previous["checkpoint_id"] if previous else None),
        )
        if output.exists() or output.is_symlink():
            raise AuditTrustReceiverBundleError(
                "receiver bundle output appeared during creation", rule_id="ARB011"
            )
        os.rename(staging, output)
        _fsync_directory(parent)
        return manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def verify_bundle(
    bundle_dir: Path,
    *,
    expected_bundle_id: str,
    expected_candidate_checkpoint_id: str,
    expected_previous_checkpoint_id: str | None = None,
) -> dict[str, Any]:
    files, total_bytes = _walk_files(Path(bundle_dir))
    if MANIFEST_NAME not in files or CHECKSUMS_NAME not in files:
        raise AuditTrustReceiverBundleError(
            "receiver bundle is missing manifest or checksums", rule_id="ARB008"
        )
    manifest = load_manifest(files[MANIFEST_NAME])
    if manifest["bundle_id"] != _pin(expected_bundle_id, "expected receiver bundle id"):
        raise AuditTrustReceiverBundleError(
            "receiver bundle differs from the external bundle pin",
            rule_id="ARB003", denied=True,
        )
    candidate_pin = _pin(
        expected_candidate_checkpoint_id, "expected candidate receiver checkpoint id"
    )
    if manifest["candidate"]["checkpoint_id"] != candidate_pin:
        raise AuditTrustReceiverBundleError(
            "candidate receiver checkpoint differs from the external pin",
            rule_id="ARB003", denied=True,
        )
    if manifest["bundle_type"] == "transition":
        if expected_previous_checkpoint_id is None:
            raise AuditTrustReceiverBundleError(
                "transition receiver verification requires the previous checkpoint pin",
                rule_id="ARB003", denied=True,
            )
        previous_pin = _pin(
            expected_previous_checkpoint_id, "expected previous receiver checkpoint id"
        )
        if manifest["previous"]["checkpoint_id"] != previous_pin:
            raise AuditTrustReceiverBundleError(
                "previous receiver checkpoint differs from the external pin",
                rule_id="ARB003", denied=True,
            )
    elif expected_previous_checkpoint_id is not None:
        raise AuditTrustReceiverBundleError(
            "snapshot receiver verification must not supply a previous checkpoint pin",
            rule_id="ARB005",
        )

    checksums = _load_checksums(files[CHECKSUMS_NAME])
    expected_paths = {record["path"] for record in manifest["files"]} | {
        MANIFEST_NAME, CHECKSUMS_NAME
    }
    if set(files) != expected_paths:
        raise AuditTrustReceiverBundleError(
            f"receiver bundle boundary mismatch; missing={sorted(expected_paths-set(files))}, "
            f"extra={sorted(set(files)-expected_paths)}",
            rule_id="ARB008",
        )
    if set(checksums) != expected_paths - {CHECKSUMS_NAME}:
        raise AuditTrustReceiverBundleError(
            "receiver bundle checksum boundary does not match manifest", rule_id="ARB008"
        )
    for relative, digest in checksums.items():
        if _sha256_file(files[relative]) != digest:
            raise AuditTrustReceiverBundleError(
                f"receiver bundle checksum mismatch: {relative}", rule_id="ARB008"
            )
    records = {record["path"]: record for record in manifest["files"]}
    for relative, record in records.items():
        path = files[relative]
        if path.stat().st_size != record["size"] or _sha256_file(path) != record["sha256"]:
            raise AuditTrustReceiverBundleError(
                f"receiver bundle file metadata mismatch: {relative}", rule_id="ARB008"
            )

    candidate = _load_pinned_checkpoint(
        files[CANDIDATE_CHECKPOINT_NAME], candidate_pin, "candidate"
    )
    if _checkpoint_reference(candidate) != manifest["candidate"]:
        raise AuditTrustReceiverBundleError(
            "candidate receiver checkpoint does not match manifest",
            rule_id="ARB004", denied=True,
        )
    previous = consistency = None
    if manifest["bundle_type"] == "transition":
        previous = _load_pinned_checkpoint(
            files[PREVIOUS_CHECKPOINT_NAME], manifest["previous"]["checkpoint_id"], "previous"
        )
        if _checkpoint_reference(previous) != manifest["previous"]:
            raise AuditTrustReceiverBundleError(
                "previous receiver checkpoint does not match manifest",
                rule_id="ARB004", denied=True,
            )
        consistency = _load_bound_consistency(
            files[CONSISTENCY_NAME], previous, candidate
        )
        if _consistency_reference(consistency) != manifest["consistency"]:
            raise AuditTrustReceiverBundleError(
                "receiver consistency proof does not match manifest",
                rule_id="ARB005", denied=True,
            )
    for expected in manifest["entries"]:
        actual = _entry_record(
            _load_bound_proof(files[expected["proof_path"]], candidate), candidate
        )
        if actual != expected:
            raise AuditTrustReceiverBundleError(
                "receiver inclusion proof does not match manifest entry",
                rule_id="ARB004", denied=True,
            )
    head = next(entry for entry in manifest["entries"] if entry["is_head"])
    return {
        "valid": True,
        "bundle_id": manifest["bundle_id"],
        "bundle_type": manifest["bundle_type"],
        "candidate": manifest["candidate"],
        "previous": manifest["previous"],
        "consistency": manifest["consistency"],
        "proof_count": len(manifest["entries"]),
        "head_handoff_bundle_id": head["handoff_bundle_id"],
        "files": len(files),
        "bytes": total_bytes,
    }


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    stream = stream or sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
        return
    for key in (
        "valid", "created", "bundle_id", "bundle_type", "proof_count",
        "head_handoff_bundle_id", "files", "bytes", "rule_id", "error",
    ):
        if key in payload:
            print(f"{key}: {payload[key]}", file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("output", type=Path)
    create.add_argument("--candidate-checkpoint", type=Path, required=True)
    create.add_argument("--expected-candidate-checkpoint-id", required=True)
    create.add_argument("--proof", action="append", type=Path, required=True)
    create.add_argument("--previous-checkpoint", type=Path)
    create.add_argument("--expected-previous-checkpoint-id")
    create.add_argument("--consistency-proof", type=Path)
    create.add_argument("--format", choices=("json", "text"), default="json")
    verify = subparsers.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--expected-bundle-id", required=True)
    verify.add_argument("--expected-candidate-checkpoint-id", required=True)
    verify.add_argument("--expected-previous-checkpoint-id")
    verify.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            manifest = create_bundle(
                args.output,
                args.candidate_checkpoint,
                args.expected_candidate_checkpoint_id,
                args.proof,
                previous_checkpoint_path=args.previous_checkpoint,
                expected_previous_checkpoint_id=args.expected_previous_checkpoint_id,
                consistency_path=args.consistency_proof,
            )
            _emit(
                {
                    "valid": True,
                    "created": str(args.output),
                    "bundle_id": manifest["bundle_id"],
                    "bundle_type": manifest["bundle_type"],
                    "proof_count": len(manifest["entries"]),
                },
                args.format,
            )
            return 0
        report = verify_bundle(
            args.bundle,
            expected_bundle_id=args.expected_bundle_id,
            expected_candidate_checkpoint_id=args.expected_candidate_checkpoint_id,
            expected_previous_checkpoint_id=args.expected_previous_checkpoint_id,
        )
        _emit(report, args.format)
        return 0
    except AuditTrustReceiverBundleError as exc:
        _emit(
            {"valid": False, "rule_id": exc.rule_id, "error": str(exc)},
            args.format,
            stream=sys.stderr,
        )
        return 1 if exc.denied else 2


if __name__ == "__main__":
    raise SystemExit(main())
