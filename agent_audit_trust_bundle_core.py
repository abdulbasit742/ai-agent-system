#!/usr/bin/env python3
"""Create and verify portable exact-boundary audit trust handoff bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

from agent_audit_bundle import (
    AuditEvidenceBundleError,
    _canonical_bytes,
    _checksums_text,
    _exact_fields,
    _fsync_directory,
    _hash,
    _integer,
    _load_canonical_json,
    _load_checksums,
    _pin,
    _safe_parent,
    _safe_relative,
    _sha256_file,
    _walk_files,
    _write_bytes,
)
from agent_audit_trust_checkpoint import (
    AuditTrustCheckpointError,
    load_checkpoint,
    load_proof,
    proof_matches_checkpoint,
    validate_checkpoint,
    validate_proof,
)
from agent_audit_trust_consistency import (
    AuditTrustConsistencyError,
    load_consistency_proof,
    proof_matches_checkpoints,
    validate_consistency_proof,
)

BUNDLE_VERSION = 1
MANIFEST_NAME = "audit-trust-bundle-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
CANDIDATE_CHECKPOINT_NAME = "candidate-trust-checkpoint.json"
PREVIOUS_CHECKPOINT_NAME = "previous-trust-checkpoint.json"
CONSISTENCY_NAME = "trust-consistency-proof.json"
MAX_MANIFEST_BYTES = 2_000_000
MAX_BUNDLE_FILES = 260
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_PROOFS = 128

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
ENTRY_FIELDS = {"sequence", "kind", "bundle_id", "proof_id", "proof_path", "is_head"}
FILE_FIELDS = {"path", "role", "sha256", "size"}
FILE_ROLES = {
    "candidate-trust-checkpoint", "previous-trust-checkpoint",
    "trust-consistency-proof", "trust-inclusion-proof",
}


class AuditTrustBundleError(ValueError):
    """Raised when audit trust handoff evidence cannot be processed safely."""

    def __init__(self, message: str, *, rule_id: str = "ATB002", denied: bool = False) -> None:
        super().__init__(message)
        self.rule_id = rule_id
        self.denied = denied


def _from_base(exc: AuditEvidenceBundleError, *, rule_id: str | None = None) -> AuditTrustBundleError:
    mapped = rule_id or f"ATB{exc.rule_id[-3:]}"
    return AuditTrustBundleError(str(exc), rule_id=mapped, denied=exc.denied)


def _base(function: Any, *args: Any, rule_id: str | None = None, **kwargs: Any) -> Any:
    try:
        return function(*args, **kwargs)
    except AuditEvidenceBundleError as exc:
        raise _from_base(exc, rule_id=rule_id) from exc


def _identifier(domain: bytes, payload: dict[str, Any]) -> str:
    return hashlib.sha256(domain + b"\x00" + _canonical_bytes(payload)).hexdigest()


def _checkpoint_reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    try:
        normalized = validate_checkpoint(checkpoint)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustBundleError(
            f"checkpoint validation failed: {exc}", rule_id="ATB004", denied=exc.denied
        ) from exc
    return {
        "checkpoint_id": normalized["checkpoint_id"],
        "state_id": normalized["state_id"],
        "entry_count": normalized["entry_count"],
        "head": normalized["head"],
        "merkle_root": normalized["merkle"]["root"],
    }


def _validate_checkpoint_reference(value: Any, label: str) -> dict[str, Any]:
    raw = _base(_exact_fields, value, CHECKPOINT_REFERENCE_FIELDS, label)
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
        raise AuditTrustBundleError(f"{label} is not canonical", rule_id="ATB002")
    return normalized


def _consistency_reference(proof: dict[str, Any]) -> dict[str, Any]:
    try:
        normalized = validate_consistency_proof(proof)
    except AuditTrustConsistencyError as exc:
        raise AuditTrustBundleError(
            f"consistency proof validation failed: {exc}", rule_id="ATB005", denied=exc.denied
        ) from exc
    return {
        "consistency_id": normalized["consistency_id"],
        "relation": normalized["relation"],
        "previous_checkpoint_id": normalized["previous"]["checkpoint_id"],
        "candidate_checkpoint_id": normalized["candidate"]["checkpoint_id"],
    }


def _validate_consistency_reference(value: Any) -> dict[str, Any]:
    raw = _base(_exact_fields, value, CONSISTENCY_REFERENCE_FIELDS, "consistency reference")
    if raw["relation"] != "right-descendant":
        raise AuditTrustBundleError(
            "transition bundle requires a right-descendant consistency proof",
            rule_id="ATB006", denied=True,
        )
    normalized = {
        "consistency_id": _base(_hash, raw["consistency_id"], "consistency id"),
        "relation": raw["relation"],
        "previous_checkpoint_id": _base(
            _hash, raw["previous_checkpoint_id"], "consistency previous checkpoint id"
        ),
        "candidate_checkpoint_id": _base(
            _hash, raw["candidate_checkpoint_id"], "consistency candidate checkpoint id"
        ),
    }
    if normalized != raw:
        raise AuditTrustBundleError("consistency reference is not canonical", rule_id="ATB002")
    return normalized


def _entry_record(proof: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    try:
        normalized = validate_proof(proof)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustBundleError(
            f"trust inclusion proof validation failed: {exc}", rule_id="ATB004", denied=exc.denied
        ) from exc
    entry = normalized["entry"]
    sequence = entry["sequence"]
    return {
        "sequence": sequence,
        "kind": entry["kind"],
        "bundle_id": entry["evidence"]["bundle_id"],
        "proof_id": normalized["proof_id"],
        "proof_path": f"proofs/trust-entry-{sequence:08d}.json",
        "is_head": sequence == candidate["entry_count"],
    }


def _validate_entry(value: Any, candidate: dict[str, Any]) -> dict[str, Any]:
    raw = _base(_exact_fields, value, ENTRY_FIELDS, "trust bundle entry")
    sequence = _base(_integer, raw["sequence"], "trust bundle entry sequence", 1)
    kind = raw["kind"]
    if kind not in {"anchor", "transition"} or (sequence == 1) != (kind == "anchor"):
        raise AuditTrustBundleError(
            "trust bundle entry kind is inconsistent with sequence", rule_id="ATB002"
        )
    if not isinstance(raw["is_head"], bool):
        raise AuditTrustBundleError("trust bundle entry head marker must be boolean", rule_id="ATB002")
    normalized = {
        "sequence": sequence,
        "kind": kind,
        "bundle_id": _base(_hash, raw["bundle_id"], "trust bundle entry bundle id"),
        "proof_id": _base(_hash, raw["proof_id"], "trust bundle entry proof id"),
        "proof_path": _base(_safe_relative, raw["proof_path"], "trust bundle proof path"),
        "is_head": raw["is_head"],
    }
    if normalized["proof_path"] != f"proofs/trust-entry-{sequence:08d}.json":
        raise AuditTrustBundleError("trust bundle proof path is not canonical", rule_id="ATB002")
    if sequence > candidate["entry_count"]:
        raise AuditTrustBundleError(
            "trust bundle entry exceeds candidate checkpoint range", rule_id="ATB004", denied=True
        )
    if normalized["is_head"] != (sequence == candidate["entry_count"]):
        raise AuditTrustBundleError("trust bundle entry head marker is inconsistent", rule_id="ATB012")
    if normalized != raw:
        raise AuditTrustBundleError("trust bundle entry is not canonical", rule_id="ATB002")
    return normalized


def _file_record(path: Path, relative: str, role: str) -> dict[str, Any]:
    if role not in FILE_ROLES:
        raise AuditTrustBundleError("unsupported trust bundle file role", rule_id="ATB002")
    return {
        "path": _base(_safe_relative, relative, "trust bundle file path"),
        "role": role,
        "sha256": _sha256_file(path),
        "size": path.stat().st_size,
    }


def _validate_file(value: Any) -> dict[str, Any]:
    raw = _base(_exact_fields, value, FILE_FIELDS, "trust bundle file record")
    if raw["role"] not in FILE_ROLES:
        raise AuditTrustBundleError("trust bundle file role is unsupported", rule_id="ATB002")
    normalized = {
        "path": _base(_safe_relative, raw["path"], "trust bundle file path"),
        "role": raw["role"],
        "sha256": _base(_hash, raw["sha256"], "trust bundle file digest"),
        "size": _base(_integer, raw["size"], "trust bundle file size"),
    }
    if normalized != raw:
        raise AuditTrustBundleError("trust bundle file record is not canonical", rule_id="ATB002")
    return normalized


def _bundle_id(payload: dict[str, Any]) -> str:
    core = dict(payload)
    core.pop("bundle_id", None)
    return _identifier(b"audit-trust-evidence-bundle-v1", core)


def validate_manifest(value: Any) -> dict[str, Any]:
    root = _base(_exact_fields, value, MANIFEST_FIELDS, "audit trust bundle manifest")
    if root["bundle_version"] != BUNDLE_VERSION:
        raise AuditTrustBundleError(f"bundle version must be {BUNDLE_VERSION}", rule_id="ATB002")
    bundle_type = root["bundle_type"]
    if bundle_type not in {"snapshot", "transition"}:
        raise AuditTrustBundleError("bundle type is unsupported", rule_id="ATB005")
    candidate = _validate_checkpoint_reference(root["candidate"], "candidate checkpoint")
    if bundle_type == "snapshot":
        if root["previous"] is not None or root["consistency"] is not None:
            raise AuditTrustBundleError(
                "snapshot bundle must not contain previous or consistency evidence", rule_id="ATB005"
            )
        previous = consistency = None
    else:
        if root["previous"] is None or root["consistency"] is None:
            raise AuditTrustBundleError(
                "transition bundle requires previous checkpoint and consistency evidence",
                rule_id="ATB005",
            )
        previous = _validate_checkpoint_reference(root["previous"], "previous checkpoint")
        consistency = _validate_consistency_reference(root["consistency"])
        if previous["entry_count"] >= candidate["entry_count"]:
            raise AuditTrustBundleError(
                "transition candidate must extend the previous checkpoint",
                rule_id="ATB006", denied=True,
            )
        if (
            consistency["previous_checkpoint_id"] != previous["checkpoint_id"]
            or consistency["candidate_checkpoint_id"] != candidate["checkpoint_id"]
        ):
            raise AuditTrustBundleError(
                "consistency reference does not bind both manifest checkpoints",
                rule_id="ATB005", denied=True,
            )

    entries_raw = root["entries"]
    if not isinstance(entries_raw, list) or not entries_raw or len(entries_raw) > MAX_PROOFS:
        raise AuditTrustBundleError(
            "trust bundle entries are missing or exceed the reviewed limit", rule_id="ATB010"
        )
    entries = [_validate_entry(item, candidate) for item in entries_raw]
    if entries != sorted(entries, key=lambda item: item["sequence"]):
        raise AuditTrustBundleError("trust bundle entries are not canonically ordered", rule_id="ATB002")
    for key in ("sequence", "bundle_id", "proof_id", "proof_path"):
        values = [entry[key] for entry in entries]
        if len(values) != len(set(values)):
            raise AuditTrustBundleError(
                f"trust bundle entries contain duplicate {key}", rule_id="ATB007"
            )
    if sum(1 for entry in entries if entry["is_head"]) != 1:
        raise AuditTrustBundleError(
            "trust bundle must contain exactly one candidate-head inclusion proof",
            rule_id="ATB012",
        )

    files_raw = root["files"]
    if not isinstance(files_raw, list) or not files_raw or len(files_raw) > MAX_BUNDLE_FILES:
        raise AuditTrustBundleError(
            "trust bundle file records are missing or exceed the reviewed limit", rule_id="ATB010"
        )
    files = [_validate_file(item) for item in files_raw]
    if files != sorted(files, key=lambda item: item["path"]):
        raise AuditTrustBundleError("trust bundle file records are not canonically ordered", rule_id="ATB002")
    paths = [record["path"] for record in files]
    if len(paths) != len(set(paths)):
        raise AuditTrustBundleError("trust bundle file records contain duplicate paths", rule_id="ATB007")
    if sum(record["size"] for record in files) > MAX_BUNDLE_BYTES:
        raise AuditTrustBundleError("trust bundle exceeds the reviewed byte limit", rule_id="ATB010")

    by_role = {record["role"]: [] for record in files}
    for record in files:
        by_role[record["role"]].append(record["path"])
    if by_role["candidate-trust-checkpoint"] != [CANDIDATE_CHECKPOINT_NAME]:
        raise AuditTrustBundleError("candidate checkpoint file boundary is invalid", rule_id="ATB008")
    if bundle_type == "snapshot":
        if by_role["previous-trust-checkpoint"] or by_role["trust-consistency-proof"]:
            raise AuditTrustBundleError("snapshot bundle contains transition-only files", rule_id="ATB005")
    else:
        if by_role["previous-trust-checkpoint"] != [PREVIOUS_CHECKPOINT_NAME]:
            raise AuditTrustBundleError("previous checkpoint file boundary is invalid", rule_id="ATB008")
        if by_role["trust-consistency-proof"] != [CONSISTENCY_NAME]:
            raise AuditTrustBundleError("consistency proof file boundary is invalid", rule_id="ATB008")
    if set(by_role["trust-inclusion-proof"]) != {entry["proof_path"] for entry in entries}:
        raise AuditTrustBundleError(
            "trust inclusion proof file boundary differs from manifest entries", rule_id="ATB008"
        )

    core = {
        "bundle_version": BUNDLE_VERSION, "bundle_type": bundle_type,
        "candidate": candidate, "previous": previous, "consistency": consistency,
        "entries": entries, "files": files,
    }
    bundle_id = _base(_hash, root["bundle_id"], "trust bundle id")
    if bundle_id != _bundle_id(core):
        raise AuditTrustBundleError(
            "trust bundle ID does not match its canonical manifest payload", rule_id="ATB003"
        )
    return {**core, "bundle_id": bundle_id}


def load_manifest(path: Path) -> dict[str, Any]:
    return _base(
        _load_canonical_json, path, validate_manifest, "trust bundle manifest",
        MAX_MANIFEST_BYTES,
    )


def _load_pinned_checkpoint(path: Path, expected_id: str, label: str) -> dict[str, Any]:
    try:
        checkpoint = load_checkpoint(path)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustBundleError(
            f"{label} checkpoint verification failed: {exc}", rule_id="ATB004", denied=exc.denied
        ) from exc
    expected = _base(_pin, expected_id, f"expected {label} checkpoint id", rule_id="ATB003")
    if checkpoint["checkpoint_id"] != expected:
        raise AuditTrustBundleError(
            f"{label} checkpoint differs from the externally retained pin",
            rule_id="ATB003", denied=True,
        )
    return checkpoint


def _load_bound_proof(path: Path, checkpoint: dict[str, Any]) -> dict[str, Any]:
    try:
        return proof_matches_checkpoint(load_proof(path), checkpoint)
    except AuditTrustCheckpointError as exc:
        raise AuditTrustBundleError(
            f"trust inclusion proof verification failed: {exc}",
            rule_id="ATB004", denied=exc.denied,
        ) from exc


def _load_bound_consistency(
    path: Path, previous: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    try:
        proof = proof_matches_checkpoints(load_consistency_proof(path), previous, candidate)
    except AuditTrustConsistencyError as exc:
        raise AuditTrustBundleError(
            f"trust consistency proof verification failed: {exc}",
            rule_id="ATB005", denied=exc.denied,
        ) from exc
    if proof["relation"] != "right-descendant":
        raise AuditTrustBundleError(
            "transition bundle requires right-descendant trust continuity",
            rule_id="ATB006", denied=True,
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
        raise AuditTrustBundleError(
            "trust bundle output directory must not already exist or be a symlink",
            rule_id="ATB011",
        )
    parent = _base(_safe_parent, output)
    candidate = _load_pinned_checkpoint(
        candidate_checkpoint_path, expected_candidate_checkpoint_id, "candidate"
    )
    proof_sources = [Path(path) for path in proof_paths]
    if not proof_sources or len(proof_sources) > MAX_PROOFS:
        raise AuditTrustBundleError(
            "at least one trust inclusion proof is required within the reviewed limit",
            rule_id="ATB010",
        )
    proofs = [_load_bound_proof(path, candidate) for path in proof_sources]
    entries = sorted(
        (_entry_record(proof, candidate) for proof in proofs), key=lambda item: item["sequence"]
    )
    for key in ("sequence", "bundle_id", "proof_id", "proof_path"):
        values = [entry[key] for entry in entries]
        if len(values) != len(set(values)):
            raise AuditTrustBundleError(
                f"trust inclusion proofs contain duplicate {key}", rule_id="ATB007"
            )
    if sum(1 for entry in entries if entry["is_head"]) != 1:
        raise AuditTrustBundleError("candidate-head inclusion proof is required", rule_id="ATB012")

    transition_values = (
        previous_checkpoint_path, expected_previous_checkpoint_id, consistency_path,
    )
    supplied = [value is not None for value in transition_values]
    if any(supplied) and not all(supplied):
        raise AuditTrustBundleError(
            "transition bundle requires previous checkpoint, its pin, and consistency proof",
            rule_id="ATB005",
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
        _base(_write_bytes, candidate_target, _canonical_bytes(candidate))
        records.append(_file_record(candidate_target, CANDIDATE_CHECKPOINT_NAME, "candidate-trust-checkpoint"))
        if previous is not None and consistency is not None:
            previous_target = staging / PREVIOUS_CHECKPOINT_NAME
            consistency_target = staging / CONSISTENCY_NAME
            _base(_write_bytes, previous_target, _canonical_bytes(previous))
            _base(_write_bytes, consistency_target, _canonical_bytes(consistency))
            records.append(_file_record(previous_target, PREVIOUS_CHECKPOINT_NAME, "previous-trust-checkpoint"))
            records.append(_file_record(consistency_target, CONSISTENCY_NAME, "trust-consistency-proof"))
        proof_by_sequence = {proof["entry"]["sequence"]: proof for proof in proofs}
        for entry in entries:
            target = staging / entry["proof_path"]
            _base(_write_bytes, target, _canonical_bytes(proof_by_sequence[entry["sequence"]]))
            records.append(_file_record(target, entry["proof_path"], "trust-inclusion-proof"))
        records.sort(key=lambda item: item["path"])
        core = {
            "bundle_version": BUNDLE_VERSION, "bundle_type": bundle_type,
            "candidate": _checkpoint_reference(candidate),
            "previous": _checkpoint_reference(previous) if previous is not None else None,
            "consistency": _consistency_reference(consistency) if consistency is not None else None,
            "entries": entries, "files": records,
        }
        manifest = validate_manifest({**core, "bundle_id": _bundle_id(core)})
        manifest_path = staging / MANIFEST_NAME
        _base(_write_bytes, manifest_path, _canonical_bytes(manifest))
        _base(
            _write_bytes, staging / CHECKSUMS_NAME,
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
            raise AuditTrustBundleError("trust bundle output appeared during creation", rule_id="ATB011")
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
    files, total_bytes = _base(_walk_files, Path(bundle_dir))
    if MANIFEST_NAME not in files or CHECKSUMS_NAME not in files:
        raise AuditTrustBundleError("trust bundle is missing manifest or checksums", rule_id="ATB008")
    manifest = load_manifest(files[MANIFEST_NAME])
    if manifest["bundle_id"] != _base(_pin, expected_bundle_id, "expected trust bundle id", rule_id="ATB003"):
        raise AuditTrustBundleError(
            "trust bundle differs from the externally retained bundle pin",
            rule_id="ATB003", denied=True,
        )
    candidate_pin = _base(
        _pin, expected_candidate_checkpoint_id, "expected candidate checkpoint id",
        rule_id="ATB003",
    )
    if manifest["candidate"]["checkpoint_id"] != candidate_pin:
        raise AuditTrustBundleError(
            "candidate checkpoint differs from the externally retained pin",
            rule_id="ATB003", denied=True,
        )
    if manifest["bundle_type"] == "transition":
        if expected_previous_checkpoint_id is None:
            raise AuditTrustBundleError(
                "transition verification requires the previous checkpoint pin",
                rule_id="ATB003", denied=True,
            )
        previous_pin = _base(
            _pin, expected_previous_checkpoint_id, "expected previous checkpoint id",
            rule_id="ATB003",
        )
        if manifest["previous"]["checkpoint_id"] != previous_pin:
            raise AuditTrustBundleError(
                "previous checkpoint differs from the externally retained pin",
                rule_id="ATB003", denied=True,
            )
    elif expected_previous_checkpoint_id is not None:
        raise AuditTrustBundleError(
            "snapshot verification must not supply a previous checkpoint pin", rule_id="ATB005"
        )

    checksums = _base(_load_checksums, files[CHECKSUMS_NAME], rule_id="ATB008")
    expected_paths = {record["path"] for record in manifest["files"]} | {MANIFEST_NAME, CHECKSUMS_NAME}
    if set(files) != expected_paths:
        raise AuditTrustBundleError(
            f"trust bundle file boundary mismatch; missing={sorted(expected_paths-set(files))}, extra={sorted(set(files)-expected_paths)}",
            rule_id="ATB008",
        )
    if set(checksums) != expected_paths - {CHECKSUMS_NAME}:
        raise AuditTrustBundleError("trust bundle checksum boundary does not match manifest", rule_id="ATB008")
    for relative, digest in checksums.items():
        if _sha256_file(files[relative]) != digest:
            raise AuditTrustBundleError(f"trust bundle checksum mismatch: {relative}", rule_id="ATB008")
    records = {record["path"]: record for record in manifest["files"]}
    for relative, record in records.items():
        path = files[relative]
        if path.stat().st_size != record["size"] or _sha256_file(path) != record["sha256"]:
            raise AuditTrustBundleError(f"trust bundle file metadata mismatch: {relative}", rule_id="ATB008")

    candidate = _load_pinned_checkpoint(files[CANDIDATE_CHECKPOINT_NAME], candidate_pin, "candidate")
    if _checkpoint_reference(candidate) != manifest["candidate"]:
        raise AuditTrustBundleError(
            "candidate checkpoint does not match the manifest reference", rule_id="ATB004", denied=True
        )
    previous = consistency = None
    if manifest["bundle_type"] == "transition":
        previous = _load_pinned_checkpoint(
            files[PREVIOUS_CHECKPOINT_NAME], manifest["previous"]["checkpoint_id"], "previous"
        )
        if _checkpoint_reference(previous) != manifest["previous"]:
            raise AuditTrustBundleError(
                "previous checkpoint does not match the manifest reference", rule_id="ATB004", denied=True
            )
        consistency = _load_bound_consistency(files[CONSISTENCY_NAME], previous, candidate)
        if _consistency_reference(consistency) != manifest["consistency"]:
            raise AuditTrustBundleError(
                "consistency proof does not match the manifest reference", rule_id="ATB005", denied=True
            )
    for expected in manifest["entries"]:
        actual = _entry_record(_load_bound_proof(files[expected["proof_path"]], candidate), candidate)
        if actual != expected:
            raise AuditTrustBundleError(
                "trust inclusion proof does not match its manifest entry", rule_id="ATB004", denied=True
            )
    return {
        "valid": True,
        "bundle_id": manifest["bundle_id"],
        "bundle_type": manifest["bundle_type"],
        "candidate": manifest["candidate"],
        "previous": manifest["previous"],
        "consistency": manifest["consistency"],
        "proof_count": len(manifest["entries"]),
        "head_bundle_id": next(entry["bundle_id"] for entry in manifest["entries"] if entry["is_head"]),
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
        "head_bundle_id", "rule_id", "error",
    ):
        if key in payload:
            print(f"{key}: {payload[key]}", file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("output", type=Path)
    create.add_argument("--candidate-checkpoint", type=Path, required=True)
    create.add_argument("--expected-candidate-checkpoint-id", required=True)
    create.add_argument("--proof", type=Path, action="append", required=True)
    create.add_argument("--previous-checkpoint", type=Path)
    create.add_argument("--expected-previous-checkpoint-id")
    create.add_argument("--consistency-proof", type=Path)
    create.add_argument("--format", choices=("json", "text"), default="json")
    verify = commands.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--expected-bundle-id", required=True)
    verify.add_argument("--expected-candidate-checkpoint-id", required=True)
    verify.add_argument("--expected-previous-checkpoint-id")
    verify.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            manifest = create_bundle(
                args.output, args.candidate_checkpoint,
                args.expected_candidate_checkpoint_id, args.proof,
                previous_checkpoint_path=args.previous_checkpoint,
                expected_previous_checkpoint_id=args.expected_previous_checkpoint_id,
                consistency_path=args.consistency_proof,
            )
            report = {
                "valid": True, "created": True, "bundle_id": manifest["bundle_id"],
                "bundle_type": manifest["bundle_type"], "proof_count": len(manifest["entries"]),
            }
        else:
            report = verify_bundle(
                args.bundle,
                expected_bundle_id=args.expected_bundle_id,
                expected_candidate_checkpoint_id=args.expected_candidate_checkpoint_id,
                expected_previous_checkpoint_id=args.expected_previous_checkpoint_id,
            )
        _emit(report, args.format)
        return 0
    except AuditTrustBundleError as exc:
        _emit({"valid": False, "rule_id": exc.rule_id, "error": str(exc)}, args.format, stream=sys.stderr)
        return 1 if exc.denied else 2


if __name__ == "__main__":
    raise SystemExit(main())
