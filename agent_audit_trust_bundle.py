#!/usr/bin/env python3
"""Public audit trust handoff bundle interface."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from agent_audit_trust import canonical_json
import agent_audit_trust_bundle_core as _core


def _trust_checksums_text(
    records: Iterable[dict[str, Any]], manifest_path: Path
) -> str:
    lines = [f"{record['sha256']}  {record['path']}" for record in records]
    lines.append(f"{_core._sha256_file(manifest_path)}  {_core.MANIFEST_NAME}")
    return "\n".join(sorted(lines)) + "\n"


_original_write_bytes = _core._write_bytes


def _trust_aware_write_bytes(path: Path, payload: bytes) -> None:
    path = Path(path)
    if (
        path.name
        in {
            _core.CANDIDATE_CHECKPOINT_NAME,
            _core.PREVIOUS_CHECKPOINT_NAME,
            _core.CONSISTENCY_NAME,
        }
        or "proofs" in path.parts
    ):
        payload = canonical_json(json.loads(payload.decode("utf-8")))
    _original_write_bytes(path, payload)


def _validate_manifest(value: Any) -> dict[str, Any]:
    root = _core._base(
        _core._exact_fields,
        value,
        _core.MANIFEST_FIELDS,
        "audit trust bundle manifest",
    )
    if root["bundle_version"] != _core.BUNDLE_VERSION:
        raise _core.AuditTrustBundleError(
            f"bundle version must be {_core.BUNDLE_VERSION}", rule_id="ATB002"
        )
    bundle_type = root["bundle_type"]
    if bundle_type not in {"snapshot", "transition"}:
        raise _core.AuditTrustBundleError("bundle type is unsupported", rule_id="ATB005")
    candidate = _core._validate_checkpoint_reference(
        root["candidate"], "candidate checkpoint"
    )
    if bundle_type == "snapshot":
        if root["previous"] is not None or root["consistency"] is not None:
            raise _core.AuditTrustBundleError(
                "snapshot bundle must not contain previous or consistency evidence",
                rule_id="ATB005",
            )
        previous = None
        consistency = None
    else:
        if root["previous"] is None or root["consistency"] is None:
            raise _core.AuditTrustBundleError(
                "transition bundle requires previous checkpoint and consistency evidence",
                rule_id="ATB005",
            )
        previous = _core._validate_checkpoint_reference(
            root["previous"], "previous checkpoint"
        )
        consistency = _core._validate_consistency_reference(root["consistency"])
        if previous["entry_count"] >= candidate["entry_count"]:
            raise _core.AuditTrustBundleError(
                "transition candidate must extend the previous checkpoint",
                rule_id="ATB006",
                denied=True,
            )
        if (
            consistency["previous_checkpoint_id"] != previous["checkpoint_id"]
            or consistency["candidate_checkpoint_id"] != candidate["checkpoint_id"]
        ):
            raise _core.AuditTrustBundleError(
                "consistency reference does not bind both manifest checkpoints",
                rule_id="ATB005",
                denied=True,
            )

    entries_raw = root["entries"]
    if (
        not isinstance(entries_raw, list)
        or not entries_raw
        or len(entries_raw) > _core.MAX_PROOFS
    ):
        raise _core.AuditTrustBundleError(
            "trust bundle entries are missing or exceed the reviewed limit",
            rule_id="ATB010",
        )
    entries = [_core._validate_entry(item, candidate) for item in entries_raw]
    if entries != sorted(entries, key=lambda item: item["sequence"]):
        raise _core.AuditTrustBundleError(
            "trust bundle entries are not canonically ordered", rule_id="ATB002"
        )
    for key in ("sequence", "bundle_id", "proof_id", "proof_path"):
        values = [entry[key] for entry in entries]
        if len(values) != len(set(values)):
            raise _core.AuditTrustBundleError(
                f"trust bundle entries contain duplicate {key}", rule_id="ATB007"
            )
    if sum(1 for entry in entries if entry["is_head"]) != 1:
        raise _core.AuditTrustBundleError(
            "trust bundle must contain exactly one candidate-head inclusion proof",
            rule_id="ATB012",
        )

    files_raw = root["files"]
    if (
        not isinstance(files_raw, list)
        or not files_raw
        or len(files_raw) > _core.MAX_BUNDLE_FILES
    ):
        raise _core.AuditTrustBundleError(
            "trust bundle file records are missing or exceed the reviewed limit",
            rule_id="ATB010",
        )
    files = [_core._validate_file(item) for item in files_raw]
    if files != sorted(files, key=lambda item: item["path"]):
        raise _core.AuditTrustBundleError(
            "trust bundle file records are not canonically ordered", rule_id="ATB002"
        )
    paths = [record["path"] for record in files]
    if len(paths) != len(set(paths)):
        raise _core.AuditTrustBundleError(
            "trust bundle file records contain duplicate paths", rule_id="ATB007"
        )
    if sum(record["size"] for record in files) > _core.MAX_BUNDLE_BYTES:
        raise _core.AuditTrustBundleError(
            "trust bundle exceeds the reviewed byte limit", rule_id="ATB010"
        )

    by_role = {role: [] for role in _core.FILE_ROLES}
    for record in files:
        by_role[record["role"]].append(record["path"])
    if by_role["candidate-trust-checkpoint"] != [
        _core.CANDIDATE_CHECKPOINT_NAME
    ]:
        raise _core.AuditTrustBundleError(
            "candidate checkpoint file boundary is invalid", rule_id="ATB008"
        )
    if bundle_type == "snapshot":
        if by_role["previous-trust-checkpoint"] or by_role[
            "trust-consistency-proof"
        ]:
            raise _core.AuditTrustBundleError(
                "snapshot bundle contains transition-only files", rule_id="ATB005"
            )
    else:
        if by_role["previous-trust-checkpoint"] != [
            _core.PREVIOUS_CHECKPOINT_NAME
        ]:
            raise _core.AuditTrustBundleError(
                "previous checkpoint file boundary is invalid", rule_id="ATB008"
            )
        if by_role["trust-consistency-proof"] != [_core.CONSISTENCY_NAME]:
            raise _core.AuditTrustBundleError(
                "consistency proof file boundary is invalid", rule_id="ATB008"
            )
    if set(by_role["trust-inclusion-proof"]) != {
        entry["proof_path"] for entry in entries
    }:
        raise _core.AuditTrustBundleError(
            "trust inclusion proof file boundary differs from manifest entries",
            rule_id="ATB008",
        )

    core = {
        "bundle_version": _core.BUNDLE_VERSION,
        "bundle_type": bundle_type,
        "candidate": candidate,
        "previous": previous,
        "consistency": consistency,
        "entries": entries,
        "files": files,
    }
    bundle_id = _core._base(_core._hash, root["bundle_id"], "trust bundle id")
    if bundle_id != _core._bundle_id(core):
        raise _core.AuditTrustBundleError(
            "trust bundle ID does not match its canonical manifest payload",
            rule_id="ATB003",
        )
    return {**core, "bundle_id": bundle_id}


_core._checksums_text = _trust_checksums_text
_core._write_bytes = _trust_aware_write_bytes
_core.validate_manifest = _validate_manifest

from agent_audit_trust_bundle_core import *  # noqa: F401,F403,E402

validate_manifest = _validate_manifest


if __name__ == "__main__":
    raise SystemExit(_core.main())
