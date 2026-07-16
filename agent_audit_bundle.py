#!/usr/bin/env python3
"""Create and verify portable exact-boundary audit evidence bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from agent_audit_checkpoint import (
    AuditCatalogCheckpointError,
    _canonical_bytes,
    _identifier,
    load_checkpoint,
    load_proof,
    proof_matches_checkpoint,
    proof_matches_segment_directory,
    validate_checkpoint,
    validate_proof,
)
from agent_audit_consistency import (
    AuditCatalogConsistencyError,
    load_consistency_proof,
    proof_matches_checkpoints,
    validate_consistency_proof,
)
from agent_audit_segments import MANIFEST_FILE as SEGMENT_MANIFEST_FILE
from agent_audit_segments import SEGMENT_FILE

BUNDLE_VERSION = 1
MANIFEST_NAME = "audit-bundle-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
CANDIDATE_CHECKPOINT_NAME = "candidate-checkpoint.json"
PREVIOUS_CHECKPOINT_NAME = "previous-checkpoint.json"
CONSISTENCY_NAME = "consistency-proof.json"
MAX_MANIFEST_BYTES = 2_000_000
MAX_BUNDLE_FILES = 1024
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_PROOFS = 128
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

MANIFEST_FIELDS = {
    "bundle_version",
    "bundle_type",
    "candidate",
    "previous",
    "consistency",
    "entries",
    "files",
    "bundle_id",
}
CHECKPOINT_REFERENCE_FIELDS = {
    "checkpoint_id",
    "catalog_id",
    "generation",
    "segment_count",
    "merkle_root",
}
CONSISTENCY_REFERENCE_FIELDS = {
    "consistency_id",
    "relation",
    "direct_predecessor_verified",
}
ENTRY_FIELDS = {
    "segment_index",
    "segment_id",
    "directory",
    "proof_id",
    "proof_path",
    "segment_included",
}
FILE_FIELDS = {"path", "role", "sha256", "size"}
FILE_ROLES = {
    "candidate-checkpoint",
    "previous-checkpoint",
    "consistency-proof",
    "segment-inclusion-proof",
    "segment-manifest",
    "segment-data",
}


class AuditEvidenceBundleError(ValueError):
    """Raised when audit evidence cannot be bundled or verified safely."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "AUB002",
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


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditEvidenceBundleError(
            f"{label} must be 64 lowercase hexadecimal characters",
            rule_id="AUB002",
        )
    return value


def _pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuditEvidenceBundleError(f"{label} must be a string", rule_id="AUB002")
    return _hash(value.lower(), label)


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditEvidenceBundleError(
            f"{label} must be an integer greater than or equal to {minimum}",
            rule_id="AUB002",
        )
    return value


def _exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditEvidenceBundleError(
            f"{label} fields do not match the reviewed schema",
            rule_id="AUB002",
        )
    return value


def _safe_component(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_COMPONENT.fullmatch(value):
        raise AuditEvidenceBundleError(f"{label} is unsafe", rule_id="AUB001")
    return value


def _safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise AuditEvidenceBundleError(f"{label} is unsafe", rule_id="AUB001")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or not path.parts:
        raise AuditEvidenceBundleError(f"{label} is unsafe", rule_id="AUB001")
    for part in path.parts:
        if part in {".", ".."} or not SAFE_COMPONENT.fullmatch(part):
            raise AuditEvidenceBundleError(f"{label} is unsafe", rule_id="AUB001")
    return value


def _checkpoint_reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_checkpoint(checkpoint)
    catalog = normalized["catalog"]
    return {
        "checkpoint_id": normalized["checkpoint_id"],
        "catalog_id": catalog["catalog_id"],
        "generation": catalog["generation"],
        "segment_count": catalog["segment_count"],
        "merkle_root": normalized["merkle"]["root"],
    }


def _validate_checkpoint_reference(value: Any, label: str) -> dict[str, Any]:
    reference = _exact_fields(value, CHECKPOINT_REFERENCE_FIELDS, label)
    normalized = {
        "checkpoint_id": _hash(reference["checkpoint_id"], f"{label} checkpoint id"),
        "catalog_id": _hash(reference["catalog_id"], f"{label} catalog id"),
        "generation": _integer(reference["generation"], f"{label} generation", 1),
        "segment_count": _integer(reference["segment_count"], f"{label} segment count", 1),
        "merkle_root": _hash(reference["merkle_root"], f"{label} Merkle root"),
    }
    if normalized != reference:
        raise AuditEvidenceBundleError(f"{label} is not canonical", rule_id="AUB002")
    return normalized


def _consistency_reference(proof: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_consistency_proof(proof)
    return {
        "consistency_id": normalized["consistency_id"],
        "relation": normalized["relation"],
        "direct_predecessor_verified": normalized["direct_predecessor_verified"],
    }


def _validate_consistency_reference(value: Any) -> dict[str, Any]:
    reference = _exact_fields(value, CONSISTENCY_REFERENCE_FIELDS, "consistency reference")
    relation = reference["relation"]
    if relation not in {"same", "right-descendant"}:
        raise AuditEvidenceBundleError(
            "consistency relation is unsupported",
            rule_id="AUB005",
            denied=True,
        )
    direct = reference["direct_predecessor_verified"]
    if not isinstance(direct, bool):
        raise AuditEvidenceBundleError(
            "consistency direct predecessor marker must be boolean",
            rule_id="AUB002",
        )
    normalized = {
        "consistency_id": _hash(reference["consistency_id"], "consistency id"),
        "relation": relation,
        "direct_predecessor_verified": direct,
    }
    if normalized != reference:
        raise AuditEvidenceBundleError(
            "consistency reference is not canonical",
            rule_id="AUB002",
        )
    return normalized


def _entry_record(proof: dict[str, Any], *, segment_included: bool) -> dict[str, Any]:
    normalized = validate_proof(proof)
    entry = normalized["entry"]
    return {
        "segment_index": entry["segment_index"],
        "segment_id": entry["segment_id"],
        "directory": entry["directory"],
        "proof_id": normalized["proof_id"],
        "proof_path": f"proofs/segment-{entry['segment_index']:08d}.json",
        "segment_included": segment_included,
    }


def _validate_entry_record(value: Any) -> dict[str, Any]:
    entry = _exact_fields(value, ENTRY_FIELDS, "bundle entry")
    index = _integer(entry["segment_index"], "bundle entry segment index", 1)
    directory = _safe_component(entry["directory"], "bundle entry directory")
    included = entry["segment_included"]
    if not isinstance(included, bool):
        raise AuditEvidenceBundleError(
            "bundle entry segment inclusion marker must be boolean",
            rule_id="AUB002",
        )
    normalized = {
        "segment_index": index,
        "segment_id": _hash(entry["segment_id"], "bundle entry segment id"),
        "directory": directory,
        "proof_id": _hash(entry["proof_id"], "bundle entry proof id"),
        "proof_path": _safe_relative(entry["proof_path"], "bundle entry proof path"),
        "segment_included": included,
    }
    if normalized["proof_path"] != f"proofs/segment-{index:08d}.json":
        raise AuditEvidenceBundleError(
            "bundle entry proof path is not canonical",
            rule_id="AUB002",
        )
    if normalized != entry:
        raise AuditEvidenceBundleError("bundle entry is not canonical", rule_id="AUB002")
    return normalized


def _file_record(path: Path, relative: str, role: str) -> dict[str, Any]:
    if role not in FILE_ROLES:
        raise AuditEvidenceBundleError("unsupported bundle file role", rule_id="AUB002")
    return {
        "path": _safe_relative(relative, "bundle file path"),
        "role": role,
        "sha256": _sha256_file(path),
        "size": path.stat().st_size,
    }


def _validate_file_record(value: Any) -> dict[str, Any]:
    record = _exact_fields(value, FILE_FIELDS, "bundle file record")
    role = record["role"]
    if role not in FILE_ROLES:
        raise AuditEvidenceBundleError("bundle file role is unsupported", rule_id="AUB002")
    normalized = {
        "path": _safe_relative(record["path"], "bundle file path"),
        "role": role,
        "sha256": _hash(record["sha256"], "bundle file digest"),
        "size": _integer(record["size"], "bundle file size"),
    }
    if normalized != record:
        raise AuditEvidenceBundleError("bundle file record is not canonical", rule_id="AUB002")
    return normalized


def _bundle_id(payload: dict[str, Any]) -> str:
    core = dict(payload)
    core.pop("bundle_id", None)
    return _identifier(b"audit-evidence-bundle-v1", core)


def validate_manifest(value: Any) -> dict[str, Any]:
    root = _exact_fields(value, MANIFEST_FIELDS, "audit evidence bundle manifest")
    if root["bundle_version"] != BUNDLE_VERSION:
        raise AuditEvidenceBundleError(
            f"bundle version must be {BUNDLE_VERSION}",
            rule_id="AUB002",
        )
    bundle_type = root["bundle_type"]
    if bundle_type not in {"snapshot", "transition"}:
        raise AuditEvidenceBundleError("bundle type is unsupported", rule_id="AUB012")
    candidate = _validate_checkpoint_reference(root["candidate"], "candidate checkpoint")
    previous_raw = root["previous"]
    consistency_raw = root["consistency"]
    if bundle_type == "snapshot":
        if previous_raw is not None or consistency_raw is not None:
            raise AuditEvidenceBundleError(
                "snapshot bundle must not contain previous or consistency evidence",
                rule_id="AUB012",
            )
        previous = None
        consistency = None
    else:
        if previous_raw is None or consistency_raw is None:
            raise AuditEvidenceBundleError(
                "transition bundle requires previous checkpoint and consistency evidence",
                rule_id="AUB012",
            )
        previous = _validate_checkpoint_reference(previous_raw, "previous checkpoint")
        consistency = _validate_consistency_reference(consistency_raw)

    entries_raw = root["entries"]
    if not isinstance(entries_raw, list) or not entries_raw or len(entries_raw) > MAX_PROOFS:
        raise AuditEvidenceBundleError(
            "bundle entries are missing or exceed the reviewed limit",
            rule_id="AUB010",
        )
    entries = [_validate_entry_record(item) for item in entries_raw]
    if entries != sorted(entries, key=lambda item: item["segment_index"]):
        raise AuditEvidenceBundleError("bundle entries are not canonically ordered", rule_id="AUB002")
    for key in ("segment_index", "segment_id", "directory", "proof_id", "proof_path"):
        values = [entry[key] for entry in entries]
        if len(values) != len(set(values)):
            raise AuditEvidenceBundleError(
                f"bundle entries contain duplicate {key}",
                rule_id="AUB009",
            )
    if any(entry["segment_index"] > candidate["segment_count"] for entry in entries):
        raise AuditEvidenceBundleError(
            "bundle entry exceeds candidate checkpoint segment range",
            rule_id="AUB006",
            denied=True,
        )

    files_raw = root["files"]
    if not isinstance(files_raw, list) or not files_raw or len(files_raw) > MAX_BUNDLE_FILES:
        raise AuditEvidenceBundleError(
            "bundle file records are missing or exceed the reviewed limit",
            rule_id="AUB010",
        )
    files = [_validate_file_record(item) for item in files_raw]
    if files != sorted(files, key=lambda item: item["path"]):
        raise AuditEvidenceBundleError("bundle file records are not canonically ordered", rule_id="AUB002")
    paths = [record["path"] for record in files]
    if len(paths) != len(set(paths)):
        raise AuditEvidenceBundleError("bundle file records contain duplicate paths", rule_id="AUB009")
    if sum(record["size"] for record in files) > MAX_BUNDLE_BYTES:
        raise AuditEvidenceBundleError("bundle exceeds the reviewed byte limit", rule_id="AUB010")

    core = {
        "bundle_version": BUNDLE_VERSION,
        "bundle_type": bundle_type,
        "candidate": candidate,
        "previous": previous,
        "consistency": consistency,
        "entries": entries,
        "files": files,
    }
    bundle_id = _hash(root["bundle_id"], "bundle id")
    if bundle_id != _bundle_id(core):
        raise AuditEvidenceBundleError(
            "bundle ID does not match its canonical manifest payload",
            rule_id="AUB003",
        )
    return {**core, "bundle_id": bundle_id}


def _load_canonical_json(
    path: Path,
    validator: Callable[[Any], dict[str, Any]],
    label: str,
    limit: int,
) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditEvidenceBundleError(
            f"{label} must be a regular non-symlink file",
            rule_id="AUB001",
        )
    raw = path.read_bytes()
    if not raw or len(raw) > limit:
        raise AuditEvidenceBundleError(
            f"{label} size is outside the reviewed boundary",
            rule_id="AUB010",
        )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, _DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
        raise AuditEvidenceBundleError(
            f"{label} is not strict JSON: {exc}",
            rule_id="AUB002",
        ) from exc
    normalized = validator(payload)
    if raw != _canonical_bytes(normalized):
        raise AuditEvidenceBundleError(
            f"{label} is not canonically serialized",
            rule_id="AUB002",
        )
    return normalized


def load_manifest(path: Path) -> dict[str, Any]:
    return _load_canonical_json(path, validate_manifest, "bundle manifest", MAX_MANIFEST_BYTES)


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
        raise AuditEvidenceBundleError(
            "bundle output parent must be a regular non-symlink directory",
            rule_id="AUB001",
        )
    for directory in reversed(missing):
        directory.mkdir()
    if parent.is_symlink() or not parent.is_dir():
        raise AuditEvidenceBundleError(
            "bundle output parent must be a regular non-symlink directory",
            rule_id="AUB001",
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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _copy_regular(source: Path, target: Path, label: str) -> None:
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise AuditEvidenceBundleError(
            f"{label} must be a regular non-symlink file",
            rule_id="AUB001",
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as reader, target.open("xb") as writer:
        shutil.copyfileobj(reader, writer, 1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())


def _load_pinned_checkpoint(path: Path, expected_id: str, label: str) -> dict[str, Any]:
    try:
        checkpoint = load_checkpoint(path)
    except AuditCatalogCheckpointError as exc:
        raise AuditEvidenceBundleError(
            f"{label} checkpoint verification failed: {exc}",
            rule_id="AUB004",
            denied=exc.denied,
        ) from exc
    expected = _pin(expected_id, f"expected {label} checkpoint id")
    if checkpoint["checkpoint_id"] != expected:
        raise AuditEvidenceBundleError(
            f"{label} checkpoint differs from the externally retained pin",
            rule_id="AUB004",
            denied=True,
        )
    return checkpoint


def _load_bound_proof(path: Path, checkpoint: dict[str, Any]) -> dict[str, Any]:
    try:
        proof = load_proof(path)
        return proof_matches_checkpoint(proof, checkpoint)
    except AuditCatalogCheckpointError as exc:
        raise AuditEvidenceBundleError(
            f"inclusion proof verification failed: {exc}",
            rule_id="AUB006",
            denied=exc.denied,
        ) from exc


def _load_bound_consistency(
    path: Path,
    previous_checkpoint: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    try:
        proof = load_consistency_proof(path)
        return proof_matches_checkpoints(proof, previous_checkpoint, candidate_checkpoint)
    except AuditCatalogConsistencyError as exc:
        raise AuditEvidenceBundleError(
            f"consistency proof verification failed: {exc}",
            rule_id="AUB005",
            denied=exc.denied,
        ) from exc


def _verify_segment(proof: dict[str, Any], directory: Path) -> dict[str, Any]:
    try:
        return proof_matches_segment_directory(proof, directory)
    except AuditCatalogCheckpointError as exc:
        raise AuditEvidenceBundleError(
            f"sealed segment verification failed: {exc}",
            rule_id="AUB007",
            denied=exc.denied,
        ) from exc


def _checksums_text(records: Iterable[dict[str, Any]], manifest_path: Path) -> str:
    lines = [f"{record['sha256']}  {record['path']}" for record in records]
    lines.append(f"{_sha256_file(manifest_path)}  {MANIFEST_NAME}")
    return "\n".join(sorted(lines)) + "\n"


def _load_checksums(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise AuditEvidenceBundleError(
            "bundle checksum file must be a regular non-symlink file",
            rule_id="AUB001",
        )
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditEvidenceBundleError("unable to read bundle checksums", rule_id="AUB008") from exc
    if not lines or lines != sorted(lines):
        raise AuditEvidenceBundleError(
            "bundle checksums are empty or not canonically ordered",
            rule_id="AUB008",
        )
    result: dict[str, str] = {}
    for line in lines:
        if "  " not in line:
            raise AuditEvidenceBundleError("bundle checksum line is malformed", rule_id="AUB008")
        digest, relative = line.split("  ", 1)
        digest = _hash(digest, "bundle checksum digest")
        relative = _safe_relative(relative, "bundle checksum path")
        if relative == CHECKSUMS_NAME or relative in result:
            raise AuditEvidenceBundleError(
                "bundle checksums contain a duplicate or recursive path",
                rule_id="AUB008",
            )
        result[relative] = digest
    return result


def _walk_files(directory: Path) -> tuple[dict[str, Path], int]:
    if directory.is_symlink() or not directory.is_dir():
        raise AuditEvidenceBundleError(
            "audit evidence bundle must be a regular non-symlink directory",
            rule_id="AUB001",
        )
    files: dict[str, Path] = {}
    total = 0
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        _safe_relative(relative, "bundle filesystem path")
        if path.is_symlink():
            raise AuditEvidenceBundleError("bundle contains a symlink", rule_id="AUB001")
        if path.is_dir():
            continue
        if not path.is_file():
            raise AuditEvidenceBundleError("bundle contains a non-regular file", rule_id="AUB001")
        files[relative] = path
        total += path.stat().st_size
        if len(files) > MAX_BUNDLE_FILES + 2 or total > MAX_BUNDLE_BYTES + MAX_MANIFEST_BYTES:
            raise AuditEvidenceBundleError("bundle exceeds reviewed limits", rule_id="AUB010")
    return files, total


def create_bundle(
    output_dir: Path,
    candidate_checkpoint_path: Path,
    expected_candidate_checkpoint_id: str,
    proof_paths: Iterable[Path],
    *,
    segment_root: Path | None = None,
    previous_checkpoint_path: Path | None = None,
    expected_previous_checkpoint_id: str | None = None,
    consistency_path: Path | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    if output.is_symlink() or output.exists():
        raise AuditEvidenceBundleError(
            "bundle output directory must not already exist or be a symlink",
            rule_id="AUB011",
        )
    parent = _safe_parent(output)
    candidate = _load_pinned_checkpoint(
        candidate_checkpoint_path,
        expected_candidate_checkpoint_id,
        "candidate",
    )
    proof_sources = [Path(path) for path in proof_paths]
    if not proof_sources or len(proof_sources) > MAX_PROOFS:
        raise AuditEvidenceBundleError(
            "at least one inclusion proof is required within the reviewed limit",
            rule_id="AUB010",
        )
    proofs = [_load_bound_proof(path, candidate) for path in proof_sources]
    entries = [_entry_record(proof, segment_included=segment_root is not None) for proof in proofs]
    entries.sort(key=lambda item: item["segment_index"])
    # Validate duplicate identities before touching the output filesystem.
    validate_manifest(
        {
            "bundle_version": BUNDLE_VERSION,
            "bundle_type": "snapshot",
            "candidate": _checkpoint_reference(candidate),
            "previous": None,
            "consistency": None,
            "entries": entries,
            "files": [{"path": CANDIDATE_CHECKPOINT_NAME, "role": "candidate-checkpoint", "sha256": "0" * 64, "size": 0}],
            "bundle_id": "0" * 64,
        }
    ) if False else None
    for key in ("segment_index", "segment_id", "directory", "proof_id"):
        values = [entry[key] for entry in entries]
        if len(values) != len(set(values)):
            raise AuditEvidenceBundleError(
                f"inclusion proofs contain duplicate {key}",
                rule_id="AUB009",
            )

    transition_values = (
        previous_checkpoint_path,
        expected_previous_checkpoint_id,
        consistency_path,
    )
    supplied = [value is not None for value in transition_values]
    if any(supplied) and not all(supplied):
        raise AuditEvidenceBundleError(
            "transition bundle requires previous checkpoint, its pin, and consistency proof",
            rule_id="AUB012",
        )
    previous: dict[str, Any] | None = None
    consistency: dict[str, Any] | None = None
    bundle_type = "snapshot"
    if all(supplied):
        previous = _load_pinned_checkpoint(
            Path(previous_checkpoint_path),
            str(expected_previous_checkpoint_id),
            "previous",
        )
        consistency = _load_bound_consistency(
            Path(consistency_path),
            previous,
            candidate,
        )
        bundle_type = "transition"

    resolved_segment_root: Path | None = None
    if segment_root is not None:
        resolved_segment_root = Path(segment_root)
        if resolved_segment_root.is_symlink() or not resolved_segment_root.is_dir():
            raise AuditEvidenceBundleError(
                "segment root must be a regular non-symlink directory",
                rule_id="AUB001",
            )
        for proof in proofs:
            _verify_segment(proof, resolved_segment_root / proof["entry"]["directory"])

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", suffix=".tmp", dir=parent))
    try:
        records: list[dict[str, Any]] = []
        candidate_target = staging / CANDIDATE_CHECKPOINT_NAME
        _write_bytes(candidate_target, _canonical_bytes(candidate))
        records.append(_file_record(candidate_target, CANDIDATE_CHECKPOINT_NAME, "candidate-checkpoint"))

        if previous is not None and consistency is not None:
            previous_target = staging / PREVIOUS_CHECKPOINT_NAME
            consistency_target = staging / CONSISTENCY_NAME
            _write_bytes(previous_target, _canonical_bytes(previous))
            _write_bytes(consistency_target, _canonical_bytes(consistency))
            records.append(_file_record(previous_target, PREVIOUS_CHECKPOINT_NAME, "previous-checkpoint"))
            records.append(_file_record(consistency_target, CONSISTENCY_NAME, "consistency-proof"))

        proof_by_index = {proof["entry"]["segment_index"]: proof for proof in proofs}
        for entry in entries:
            proof = proof_by_index[entry["segment_index"]]
            proof_target = staging / entry["proof_path"]
            _write_bytes(proof_target, _canonical_bytes(proof))
            records.append(_file_record(proof_target, entry["proof_path"], "segment-inclusion-proof"))
            if resolved_segment_root is not None:
                source_directory = resolved_segment_root / entry["directory"]
                target_directory = staging / "segments" / entry["directory"]
                manifest_target = target_directory / SEGMENT_MANIFEST_FILE
                data_target = target_directory / SEGMENT_FILE
                _copy_regular(source_directory / SEGMENT_MANIFEST_FILE, manifest_target, "segment manifest")
                _copy_regular(source_directory / SEGMENT_FILE, data_target, "segment data")
                records.append(
                    _file_record(
                        manifest_target,
                        f"segments/{entry['directory']}/{SEGMENT_MANIFEST_FILE}",
                        "segment-manifest",
                    )
                )
                records.append(
                    _file_record(
                        data_target,
                        f"segments/{entry['directory']}/{SEGMENT_FILE}",
                        "segment-data",
                    )
                )

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
        manifest = {**core, "bundle_id": _bundle_id(core)}
        manifest = validate_manifest(manifest)
        manifest_path = staging / MANIFEST_NAME
        _write_bytes(manifest_path, _canonical_bytes(manifest))
        _write_bytes(staging / CHECKSUMS_NAME, _checksums_text(records, manifest_path).encode("utf-8"))
        _fsync_directory(staging)

        verify_bundle(
            staging,
            expected_bundle_id=manifest["bundle_id"],
            expected_candidate_checkpoint_id=candidate["checkpoint_id"],
            expected_previous_checkpoint_id=(previous["checkpoint_id"] if previous is not None else None),
        )
        if output.exists() or output.is_symlink():
            raise AuditEvidenceBundleError(
                "bundle output appeared during creation",
                rule_id="AUB011",
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
    directory = Path(bundle_dir)
    files, total_bytes = _walk_files(directory)
    required_top = {MANIFEST_NAME, CHECKSUMS_NAME}
    if not required_top.issubset(files):
        raise AuditEvidenceBundleError("bundle is missing manifest or checksums", rule_id="AUB008")
    manifest = load_manifest(files[MANIFEST_NAME])
    expected_id = _pin(expected_bundle_id, "expected bundle id")
    if manifest["bundle_id"] != expected_id:
        raise AuditEvidenceBundleError(
            "bundle differs from the externally retained bundle pin",
            rule_id="AUB003",
            denied=True,
        )
    checksums = _load_checksums(files[CHECKSUMS_NAME])
    expected_paths = {record["path"] for record in manifest["files"]} | {MANIFEST_NAME, CHECKSUMS_NAME}
    if set(files) != expected_paths:
        missing = sorted(expected_paths - set(files))
        extra = sorted(set(files) - expected_paths)
        raise AuditEvidenceBundleError(
            f"bundle file boundary mismatch; missing={missing}, extra={extra}",
            rule_id="AUB008",
        )
    expected_checksum_paths = expected_paths - {CHECKSUMS_NAME}
    if set(checksums) != expected_checksum_paths:
        raise AuditEvidenceBundleError(
            "bundle checksum boundary does not match the manifest",
            rule_id="AUB008",
        )
    for relative, digest in checksums.items():
        if _sha256_file(files[relative]) != digest:
            raise AuditEvidenceBundleError(
                f"bundle checksum mismatch: {relative}",
                rule_id="AUB008",
            )
    record_by_path = {record["path"]: record for record in manifest["files"]}
    for relative, record in record_by_path.items():
        actual = files[relative]
        if actual.stat().st_size != record["size"] or _sha256_file(actual) != record["sha256"]:
            raise AuditEvidenceBundleError(
                f"bundle file metadata mismatch: {relative}",
                rule_id="AUB008",
            )

    candidate = _load_pinned_checkpoint(
        files[CANDIDATE_CHECKPOINT_NAME],
        expected_candidate_checkpoint_id,
        "candidate",
    )
    if _checkpoint_reference(candidate) != manifest["candidate"]:
        raise AuditEvidenceBundleError(
            "candidate checkpoint differs from the bundle manifest",
            rule_id="AUB004",
            denied=True,
        )

    previous: dict[str, Any] | None = None
    consistency: dict[str, Any] | None = None
    if manifest["bundle_type"] == "transition":
        if expected_previous_checkpoint_id is None:
            raise AuditEvidenceBundleError(
                "transition bundle verification requires the previous checkpoint pin",
                rule_id="AUB004",
                denied=True,
            )
        previous = _load_pinned_checkpoint(
            files[PREVIOUS_CHECKPOINT_NAME],
            expected_previous_checkpoint_id,
            "previous",
        )
        if _checkpoint_reference(previous) != manifest["previous"]:
            raise AuditEvidenceBundleError(
                "previous checkpoint differs from the bundle manifest",
                rule_id="AUB004",
                denied=True,
            )
        consistency = _load_bound_consistency(files[CONSISTENCY_NAME], previous, candidate)
        if _consistency_reference(consistency) != manifest["consistency"]:
            raise AuditEvidenceBundleError(
                "consistency proof differs from the bundle manifest",
                rule_id="AUB005",
                denied=True,
            )
    elif expected_previous_checkpoint_id is not None:
        raise AuditEvidenceBundleError(
            "snapshot bundle does not accept a previous checkpoint pin",
            rule_id="AUB012",
        )

    proof_ids: list[str] = []
    segment_ids: list[str] = []
    for entry in manifest["entries"]:
        proof = _load_bound_proof(files[entry["proof_path"]], candidate)
        actual_entry = _entry_record(proof, segment_included=entry["segment_included"])
        if actual_entry != entry:
            raise AuditEvidenceBundleError(
                "inclusion proof differs from the bundle manifest entry",
                rule_id="AUB006",
                denied=True,
            )
        proof_ids.append(proof["proof_id"])
        segment_ids.append(proof["entry"]["segment_id"])
        if entry["segment_included"]:
            segment_directory = directory / "segments" / entry["directory"]
            _verify_segment(proof, segment_directory)

    if total_bytes > MAX_BUNDLE_BYTES + MAX_MANIFEST_BYTES:
        raise AuditEvidenceBundleError("bundle exceeds the reviewed byte limit", rule_id="AUB010")
    return {
        "valid": True,
        "bundle_id": manifest["bundle_id"],
        "bundle_type": manifest["bundle_type"],
        "candidate": manifest["candidate"],
        "previous": manifest["previous"],
        "consistency": manifest["consistency"],
        "proof_count": len(proof_ids),
        "segment_count": sum(1 for entry in manifest["entries"] if entry["segment_included"]),
        "proof_ids": proof_ids,
        "segment_ids": segment_ids,
        "files": len(files),
        "bytes": total_bytes,
    }


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    if stream is None:
        import sys

        stream = sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
        return
    for key in (
        "valid",
        "created",
        "bundle_id",
        "bundle_type",
        "proof_count",
        "segment_count",
        "files",
        "bytes",
    ):
        if key in payload:
            print(f"{key}: {payload[key]}", file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("output", type=Path)
    create.add_argument("--checkpoint", type=Path, required=True)
    create.add_argument("--expected-checkpoint-id", required=True)
    create.add_argument("--proof", action="append", type=Path, required=True)
    create.add_argument("--segment-root", type=Path)
    create.add_argument("--previous-checkpoint", type=Path)
    create.add_argument("--expected-previous-checkpoint-id")
    create.add_argument("--consistency-proof", type=Path)
    create.add_argument("--format", choices=("json", "text"), default="json")

    verify = subparsers.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--expected-bundle-id", required=True)
    verify.add_argument("--expected-checkpoint-id", required=True)
    verify.add_argument("--expected-previous-checkpoint-id")
    verify.add_argument("--format", choices=("json", "text"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            manifest = create_bundle(
                args.output,
                args.checkpoint,
                args.expected_checkpoint_id,
                args.proof,
                segment_root=args.segment_root,
                previous_checkpoint_path=args.previous_checkpoint,
                expected_previous_checkpoint_id=args.expected_previous_checkpoint_id,
                consistency_path=args.consistency_proof,
            )
            _emit(
                {
                    "created": str(args.output),
                    "valid": True,
                    "bundle_id": manifest["bundle_id"],
                    "bundle_type": manifest["bundle_type"],
                    "proof_count": len(manifest["entries"]),
                    "segment_count": sum(
                        1 for entry in manifest["entries"] if entry["segment_included"]
                    ),
                    "files": len(manifest["files"]) + 2,
                },
                args.format,
            )
            return 0
        report = verify_bundle(
            args.bundle,
            expected_bundle_id=args.expected_bundle_id,
            expected_candidate_checkpoint_id=args.expected_checkpoint_id,
            expected_previous_checkpoint_id=args.expected_previous_checkpoint_id,
        )
        _emit(report, args.format)
        return 0
    except AuditEvidenceBundleError as exc:
        import sys

        _emit(
            {
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
