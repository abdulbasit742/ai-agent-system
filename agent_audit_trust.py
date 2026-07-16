#!/usr/bin/env python3
"""Maintain a pinned consumer trust state for admitted audit evidence bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - writes fail closed off POSIX.
    fcntl = None

from agent_audit_admission import (
    AuditBundleAdmissionError,
    evaluate_bundle,
    load_policy,
)
from agent_audit_bundle import AuditEvidenceBundleError, verify_bundle

STATE_VERSION = 1
ENTRY_VERSION = 1
ZERO_HASH = "0" * 64
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_STATE_BYTES = 5_000_000
MAX_ENTRIES = 10_000

STATE_FIELDS = {"state_version", "entries", "head", "state_id"}
ENTRY_FIELDS = {
    "entry_version",
    "sequence",
    "kind",
    "previous_entry_hash",
    "evidence",
    "admission",
    "transition",
    "entry_hash",
}
EVIDENCE_FIELDS = {
    "bundle_id",
    "checkpoint_id",
    "catalog_id",
    "generation",
    "segment_count",
    "merkle_root",
}
ADMISSION_FIELDS = {"decision_id", "policy_sha256"}
TRANSITION_FIELDS = {
    "previous_checkpoint_id",
    "previous_catalog_id",
    "generation_delta",
}
HEAD_FIELDS = {
    "sequence",
    "entry_hash",
    "bundle_id",
    "checkpoint_id",
    "catalog_id",
    "generation",
    "segment_count",
}


class AuditBundleTrustError(ValueError):
    """Raised when audit-bundle trust state or its pinned inputs are invalid."""

    def __init__(self, message: str, *, rule_id: str = "ATS002", denied: bool = False) -> None:
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


def canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _identifier(domain: bytes, payload: dict[str, Any]) -> str:
    return hashlib.sha256(domain + b"\x00" + canonical_json(payload)).hexdigest()


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditBundleTrustError(f"{label} fields do not match the reviewed schema")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditBundleTrustError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuditBundleTrustError(f"{label} must be a string")
    return _hash(value.lower(), label)


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditBundleTrustError(
            f"{label} must be an integer greater than or equal to {minimum}"
        )
    return value


def _evidence(value: Any) -> dict[str, Any]:
    raw = _exact(value, EVIDENCE_FIELDS, "trust evidence")
    return {
        "bundle_id": _hash(raw["bundle_id"], "bundle id"),
        "checkpoint_id": _hash(raw["checkpoint_id"], "checkpoint id"),
        "catalog_id": _hash(raw["catalog_id"], "catalog id"),
        "generation": _integer(raw["generation"], "catalog generation", 1),
        "segment_count": _integer(raw["segment_count"], "segment count", 1),
        "merkle_root": _hash(raw["merkle_root"], "catalog merkle root"),
    }


def _admission(value: Any) -> dict[str, Any]:
    raw = _exact(value, ADMISSION_FIELDS, "admission evidence")
    return {
        "decision_id": _hash(raw["decision_id"], "admission decision id"),
        "policy_sha256": _hash(raw["policy_sha256"], "admission policy sha256"),
    }


def _transition(value: Any) -> dict[str, Any]:
    raw = _exact(value, TRANSITION_FIELDS, "transition evidence")
    return {
        "previous_checkpoint_id": _hash(
            raw["previous_checkpoint_id"], "previous checkpoint id"
        ),
        "previous_catalog_id": _hash(raw["previous_catalog_id"], "previous catalog id"),
        "generation_delta": _integer(raw["generation_delta"], "generation delta", 1),
    }


def _evidence_from_verified(verified: dict[str, Any]) -> dict[str, Any]:
    candidate = verified.get("candidate")
    if not isinstance(candidate, dict):
        raise AuditBundleTrustError("verified bundle candidate evidence is malformed")
    return _evidence(
        {
            "bundle_id": verified.get("bundle_id"),
            "checkpoint_id": candidate.get("checkpoint_id"),
            "catalog_id": candidate.get("catalog_id"),
            "generation": candidate.get("generation"),
            "segment_count": candidate.get("segment_count"),
            "merkle_root": candidate.get("merkle_root"),
        }
    )


def _evidence_from_admission(report: dict[str, Any]) -> dict[str, Any]:
    identity = report.get("identity")
    details = report.get("evidence")
    if not isinstance(identity, dict) or not isinstance(details, dict):
        raise AuditBundleTrustError("admission report identity is malformed")
    return _evidence(
        {
            "bundle_id": identity.get("bundle_id"),
            "checkpoint_id": identity.get("candidate_checkpoint_id"),
            "catalog_id": identity.get("candidate_catalog_id"),
            "generation": details.get("candidate_generation"),
            "segment_count": details.get("candidate_segment_count"),
            "merkle_root": report.get("candidate_merkle_root"),
        }
    )


def _admission_from_report(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("admitted") is not True:
        raise AuditBundleTrustError(
            "only an admitted bundle can enter trust history",
            rule_id="ATS004",
            denied=True,
        )
    return _admission(
        {
            "decision_id": report.get("decision_id"),
            "policy_sha256": report.get("policy_sha256"),
        }
    )


def _entry_payload(
    sequence: int,
    kind: str,
    previous_entry_hash: str,
    evidence: dict[str, Any],
    admission: dict[str, Any],
    transition: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "entry_version": ENTRY_VERSION,
        "sequence": sequence,
        "kind": kind,
        "previous_entry_hash": previous_entry_hash,
        "evidence": evidence,
        "admission": admission,
        "transition": transition,
    }


def _seal_entry(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "entry_hash": _identifier(b"audit-bundle-trust-entry-v1", payload)}


def _head(entries: list[dict[str, Any]]) -> dict[str, Any]:
    last = entries[-1]
    evidence = last["evidence"]
    return {
        "sequence": last["sequence"],
        "entry_hash": last["entry_hash"],
        "bundle_id": evidence["bundle_id"],
        "checkpoint_id": evidence["checkpoint_id"],
        "catalog_id": evidence["catalog_id"],
        "generation": evidence["generation"],
        "segment_count": evidence["segment_count"],
    }


def _state_payload(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {"state_version": STATE_VERSION, "entries": entries, "head": _head(entries)}


def _seal_state(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "state_id": _identifier(b"audit-bundle-trust-state-v1", payload)}


def create_state(report: dict[str, Any], verified: dict[str, Any]) -> dict[str, Any]:
    if report.get("identity", {}).get("bundle_type") != "snapshot":
        raise AuditBundleTrustError(
            "trust-state anchor must be an admitted snapshot bundle", rule_id="ATS005"
        )
    evidence = _evidence_from_verified(verified)
    report_evidence = _evidence_from_admission_with_merkle(report, evidence["merkle_root"])
    if evidence != report_evidence:
        raise AuditBundleTrustError("admission report differs from verified bundle identity")
    entry = _seal_entry(
        _entry_payload(1, "anchor", ZERO_HASH, evidence, _admission_from_report(report), None)
    )
    return _seal_state(_state_payload([entry]))


def _evidence_from_admission_with_merkle(
    report: dict[str, Any], merkle_root: str
) -> dict[str, Any]:
    identity = report.get("identity")
    details = report.get("evidence")
    if not isinstance(identity, dict) or not isinstance(details, dict):
        raise AuditBundleTrustError("admission report identity is malformed")
    return _evidence(
        {
            "bundle_id": identity.get("bundle_id"),
            "checkpoint_id": identity.get("candidate_checkpoint_id"),
            "catalog_id": identity.get("candidate_catalog_id"),
            "generation": details.get("candidate_generation"),
            "segment_count": details.get("candidate_segment_count"),
            "merkle_root": merkle_root,
        }
    )


def append_transition(
    state: dict[str, Any], report: dict[str, Any], verified: dict[str, Any]
) -> dict[str, Any]:
    normalized = validate_state(state)
    identity = report.get("identity")
    details = report.get("evidence")
    if report.get("admitted") is not True:
        raise AuditBundleTrustError(
            "candidate bundle was denied by admission policy",
            rule_id="ATS004",
            denied=True,
        )
    if not isinstance(identity, dict) or identity.get("bundle_type") != "transition":
        raise AuditBundleTrustError(
            "trust-state advancement requires an admitted transition bundle",
            rule_id="ATS005",
        )
    if not isinstance(details, dict):
        raise AuditBundleTrustError("admission report evidence is malformed")
    previous = verified.get("previous")
    if not isinstance(previous, dict):
        raise AuditBundleTrustError("transition bundle previous checkpoint is missing")
    head = normalized["head"]
    if (
        previous.get("checkpoint_id") != head["checkpoint_id"]
        or previous.get("catalog_id") != head["catalog_id"]
    ):
        raise AuditBundleTrustError(
            "transition does not start from the trust-state head",
            rule_id="ATS006",
            denied=True,
        )
    evidence = _evidence_from_verified(verified)
    report_evidence = _evidence_from_admission_with_merkle(report, evidence["merkle_root"])
    if evidence != report_evidence:
        raise AuditBundleTrustError("admission report differs from verified bundle identity")
    if evidence["generation"] <= head["generation"]:
        raise AuditBundleTrustError(
            "candidate catalog generation does not advance trust history",
            rule_id="ATS008",
            denied=True,
        )
    seen_bundle_ids = {entry["evidence"]["bundle_id"] for entry in normalized["entries"]}
    seen_checkpoint_ids = {
        entry["evidence"]["checkpoint_id"] for entry in normalized["entries"]
    }
    seen_catalog_ids = {entry["evidence"]["catalog_id"] for entry in normalized["entries"]}
    if (
        evidence["bundle_id"] in seen_bundle_ids
        or evidence["checkpoint_id"] in seen_checkpoint_ids
        or evidence["catalog_id"] in seen_catalog_ids
    ):
        raise AuditBundleTrustError(
            "candidate evidence already exists in trust history",
            rule_id="ATS007",
            denied=True,
        )
    delta = details.get("generation_delta")
    transition = _transition(
        {
            "previous_checkpoint_id": previous.get("checkpoint_id"),
            "previous_catalog_id": previous.get("catalog_id"),
            "generation_delta": delta,
        }
    )
    if transition["generation_delta"] != evidence["generation"] - head["generation"]:
        raise AuditBundleTrustError("transition generation delta is inconsistent")
    entries = list(normalized["entries"])
    entries.append(
        _seal_entry(
            _entry_payload(
                len(entries) + 1,
                "transition",
                entries[-1]["entry_hash"],
                evidence,
                _admission_from_report(report),
                transition,
            )
        )
    )
    return _seal_state(_state_payload(entries))


def validate_state(value: Any) -> dict[str, Any]:
    root = _exact(value, STATE_FIELDS, "audit bundle trust state")
    if root["state_version"] != STATE_VERSION:
        raise AuditBundleTrustError(f"trust state version must be {STATE_VERSION}")
    entries_raw = root["entries"]
    if not isinstance(entries_raw, list) or not entries_raw or len(entries_raw) > MAX_ENTRIES:
        raise AuditBundleTrustError("trust state entry count is outside the reviewed boundary")
    entries: list[dict[str, Any]] = []
    previous_entry_hash = ZERO_HASH
    seen_bundles: set[str] = set()
    seen_checkpoints: set[str] = set()
    seen_catalogs: set[str] = set()
    previous_evidence: dict[str, Any] | None = None
    for index, raw_entry in enumerate(entries_raw, 1):
        entry = _exact(raw_entry, ENTRY_FIELDS, f"trust entry {index}")
        if entry["entry_version"] != ENTRY_VERSION or entry["sequence"] != index:
            raise AuditBundleTrustError(f"trust entry {index} version or sequence is invalid")
        kind = entry["kind"]
        if kind not in {"anchor", "transition"} or (index == 1) != (kind == "anchor"):
            raise AuditBundleTrustError(f"trust entry {index} kind is invalid")
        if entry["previous_entry_hash"] != previous_entry_hash:
            raise AuditBundleTrustError(f"trust entry {index} previous hash does not match")
        evidence = _evidence(entry["evidence"])
        admission = _admission(entry["admission"])
        transition_raw = entry["transition"]
        if index == 1:
            if transition_raw is not None:
                raise AuditBundleTrustError("anchor trust entry must not contain transition evidence")
            transition = None
        else:
            transition = _transition(transition_raw)
            assert previous_evidence is not None
            if (
                transition["previous_checkpoint_id"] != previous_evidence["checkpoint_id"]
                or transition["previous_catalog_id"] != previous_evidence["catalog_id"]
            ):
                raise AuditBundleTrustError(
                    f"trust entry {index} transition does not match previous evidence"
                )
            if evidence["generation"] <= previous_evidence["generation"]:
                raise AuditBundleTrustError(f"trust entry {index} generation does not increase")
            if (
                transition["generation_delta"]
                != evidence["generation"] - previous_evidence["generation"]
            ):
                raise AuditBundleTrustError(f"trust entry {index} generation delta is invalid")
        if evidence["bundle_id"] in seen_bundles:
            raise AuditBundleTrustError("trust history contains a duplicate bundle id")
        if evidence["checkpoint_id"] in seen_checkpoints:
            raise AuditBundleTrustError("trust history contains a duplicate checkpoint id")
        if evidence["catalog_id"] in seen_catalogs:
            raise AuditBundleTrustError("trust history contains a duplicate catalog id")
        seen_bundles.add(evidence["bundle_id"])
        seen_checkpoints.add(evidence["checkpoint_id"])
        seen_catalogs.add(evidence["catalog_id"])
        payload = _entry_payload(
            index, kind, previous_entry_hash, evidence, admission, transition
        )
        entry_hash = _hash(entry["entry_hash"], "entry hash")
        if entry_hash != _identifier(b"audit-bundle-trust-entry-v1", payload):
            raise AuditBundleTrustError(f"trust entry {index} hash does not match")
        sealed = {**payload, "entry_hash": entry_hash}
        entries.append(sealed)
        previous_entry_hash = entry_hash
        previous_evidence = evidence
    payload = _state_payload(entries)
    head = _exact(root["head"], HEAD_FIELDS, "trust state head")
    if head != payload["head"]:
        raise AuditBundleTrustError("trust state head does not match final history entry")
    state_id = _hash(root["state_id"], "state id")
    if state_id != _identifier(b"audit-bundle-trust-state-v1", payload):
        raise AuditBundleTrustError("trust state id does not match canonical state")
    return {**payload, "state_id": state_id}


def load_state(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditBundleTrustError(
            "trust state must be a regular non-symlink file", rule_id="ATS001"
        )
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_STATE_BYTES:
        raise AuditBundleTrustError("trust state size is outside the reviewed boundary")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, _DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
        raise AuditBundleTrustError(f"trust state is not strict JSON: {exc}") from exc
    normalized = validate_state(value)
    if raw != canonical_json(normalized):
        raise AuditBundleTrustError("trust state is not canonically serialized")
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
        raise AuditBundleTrustError(
            "trust state parent must be a regular non-symlink directory", rule_id="ATS001"
        )
    for directory in reversed(missing):
        directory.mkdir()
    if parent.is_symlink() or not parent.is_dir():
        raise AuditBundleTrustError(
            "trust state parent must be a regular non-symlink directory", rule_id="ATS001"
        )
    return parent


def _outside_bundle(path: Path, bundle: Path, label: str) -> None:
    resolved = Path(path).resolve()
    root = Path(bundle).resolve()
    if resolved == root or root in resolved.parents:
        raise AuditBundleTrustError(
            f"{label} must be consumer-owned and outside the audit bundle",
            rule_id="ATS009",
        )


@contextmanager
def _state_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    if fcntl is None:
        raise AuditBundleTrustError(
            "trust-state locking is unavailable on this platform", rule_id="ATS010"
        )
    parent = _safe_parent(path)
    lock_path = parent / (path.name + ".lock")
    if lock_path.is_symlink():
        raise AuditBundleTrustError("trust-state lock must not be a symlink", rule_id="ATS001")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise AuditBundleTrustError("unable to open trust-state lock", rule_id="ATS010") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AuditBundleTrustError("trust-state lock is not a regular file", rule_id="ATS001")
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _atomic_write(path: Path, state: dict[str, Any], *, require_absent: bool) -> None:
    path = Path(path)
    parent = _safe_parent(path)
    if path.is_symlink():
        raise AuditBundleTrustError("trust state output must not be a symlink", rule_id="ATS001")
    if path.exists() and not path.is_file():
        raise AuditBundleTrustError("trust state output must be a regular file", rule_id="ATS001")
    if require_absent and path.exists():
        raise AuditBundleTrustError("refusing to overwrite existing trust state", rule_id="ATS001")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(canonical_json(state))
            handle.flush()
            os.fsync(handle.fileno())
        if require_absent and path.exists():
            raise AuditBundleTrustError("trust state output appeared during creation", rule_id="ATS001")
        os.replace(temporary, path)
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


def _verified_bundle(
    bundle: Path,
    *,
    expected_bundle_id: str,
    expected_candidate_checkpoint_id: str,
    expected_previous_checkpoint_id: str | None = None,
) -> dict[str, Any]:
    try:
        return verify_bundle(
            Path(bundle),
            expected_bundle_id=_pin(expected_bundle_id, "expected bundle id"),
            expected_candidate_checkpoint_id=_pin(
                expected_candidate_checkpoint_id, "expected candidate checkpoint id"
            ),
            expected_previous_checkpoint_id=(
                _pin(expected_previous_checkpoint_id, "expected previous checkpoint id")
                if expected_previous_checkpoint_id is not None
                else None
            ),
        )
    except AuditEvidenceBundleError as exc:
        raise AuditBundleTrustError(
            f"audit evidence bundle verification failed ({exc.rule_id}): {exc}"
        ) from exc


def _evaluate(
    bundle: Path,
    policy_path: Path,
    *,
    expected_bundle_id: str,
    expected_candidate_checkpoint_id: str,
    expected_previous_checkpoint_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _outside_bundle(policy_path, bundle, "admission policy")
    try:
        policy = load_policy(policy_path)
        report = evaluate_bundle(
            Path(bundle),
            policy,
            expected_bundle_id=_pin(expected_bundle_id, "expected bundle id"),
            expected_candidate_checkpoint_id=_pin(
                expected_candidate_checkpoint_id, "expected candidate checkpoint id"
            ),
            expected_previous_checkpoint_id=(
                _pin(expected_previous_checkpoint_id, "expected previous checkpoint id")
                if expected_previous_checkpoint_id is not None
                else None
            ),
        )
    except AuditBundleAdmissionError as exc:
        raise AuditBundleTrustError(f"audit bundle admission failed: {exc}") from exc
    verified = _verified_bundle(
        bundle,
        expected_bundle_id=expected_bundle_id,
        expected_candidate_checkpoint_id=expected_candidate_checkpoint_id,
        expected_previous_checkpoint_id=expected_previous_checkpoint_id,
    )
    return report, verified


def _text(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    for key in (
        "valid",
        "created",
        "advanced",
        "state_id",
        "previous_state_id",
        "rule_id",
        "error",
    ):
        if key in payload:
            lines.append(f"{key}: {payload[key]}")
    head = payload.get("head")
    if isinstance(head, dict):
        lines.append(
            "head: "
            f"sequence={head['sequence']} generation={head['generation']} "
            f"checkpoint_id={head['checkpoint_id']}"
        )
    for violation in payload.get("violations", []):
        lines.append(f"- {violation['rule_id']}: {violation['message']}")
    admission = payload.get("admission")
    if isinstance(admission, dict):
        for violation in admission.get("violations", []):
            lines.append(f"- {violation['rule_id']}: {violation['message']}")
    return "\n".join(lines)


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    if stream is None:
        stream = sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
    else:
        print(_text(payload), file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    initialize = subparsers.add_parser("init")
    initialize.add_argument("state", type=Path)
    initialize.add_argument("bundle", type=Path)
    initialize.add_argument("--policy", type=Path, required=True)
    initialize.add_argument("--expected-bundle-id", required=True)
    initialize.add_argument("--expected-candidate-checkpoint-id", required=True)
    initialize.add_argument("--format", choices=("json", "text"), default="json")

    verify = subparsers.add_parser("verify")
    verify.add_argument("state", type=Path)
    verify.add_argument("--expected-state-id", required=True)
    verify.add_argument("--bundle", type=Path)
    verify.add_argument("--format", choices=("json", "text"), default="json")

    advance = subparsers.add_parser("advance")
    advance.add_argument("state", type=Path)
    advance.add_argument("bundle", type=Path)
    advance.add_argument("--policy", type=Path, required=True)
    advance.add_argument("--expected-state-id", required=True)
    advance.add_argument("--expected-bundle-id", required=True)
    advance.add_argument("--expected-candidate-checkpoint-id", required=True)
    advance.add_argument("--format", choices=("json", "text"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            _outside_bundle(args.state, args.bundle, "trust state")
            _outside_bundle(args.policy, args.bundle, "admission policy")
            with _state_lock(args.state, exclusive=True):
                if args.state.exists() or args.state.is_symlink():
                    raise AuditBundleTrustError(
                        "refusing to overwrite existing trust state", rule_id="ATS001"
                    )
                report, verified = _evaluate(
                    args.bundle,
                    args.policy,
                    expected_bundle_id=args.expected_bundle_id,
                    expected_candidate_checkpoint_id=args.expected_candidate_checkpoint_id,
                )
                if not report["admitted"]:
                    _emit(
                        {
                            "created": False,
                            "admission": report,
                            "violations": [
                                {
                                    "rule_id": "ATS004",
                                    "message": "anchor bundle was denied by admission policy",
                                }
                            ],
                        },
                        args.format,
                    )
                    return 1
                state = create_state(report, verified)
                _atomic_write(args.state, state, require_absent=True)
            _emit(
                {
                    "created": str(args.state),
                    "state_id": state["state_id"],
                    "head": state["head"],
                    "entries": 1,
                },
                args.format,
            )
            return 0

        expected_state_id = _pin(args.expected_state_id, "expected state id")
        bundle = args.bundle if args.command == "advance" else args.bundle
        if bundle is not None:
            _outside_bundle(args.state, bundle, "trust state")
        with _state_lock(args.state, exclusive=args.command == "advance"):
            state = load_state(args.state)
            if state["state_id"] != expected_state_id:
                raise AuditBundleTrustError(
                    "trust state differs from the externally retained state pin",
                    rule_id="ATS003",
                )
            if args.command == "verify":
                if args.bundle is not None:
                    last_entry = state["entries"][-1]
                    transition = last_entry["transition"]
                    verified = _verified_bundle(
                        args.bundle,
                        expected_bundle_id=state["head"]["bundle_id"],
                        expected_candidate_checkpoint_id=state["head"]["checkpoint_id"],
                        expected_previous_checkpoint_id=(
                            transition["previous_checkpoint_id"]
                            if isinstance(transition, dict)
                            else None
                        ),
                    )
                    if _evidence_from_verified(verified) != last_entry["evidence"]:
                        raise AuditBundleTrustError(
                            "verified bundle does not match the trust-state head",
                            rule_id="ATS006",
                        )
                _emit(
                    {
                        "valid": True,
                        "state_id": state["state_id"],
                        "head": state["head"],
                        "entries": len(state["entries"]),
                    },
                    args.format,
                )
                return 0

            assert args.command == "advance"
            _outside_bundle(args.policy, args.bundle, "admission policy")
            report, verified = _evaluate(
                args.bundle,
                args.policy,
                expected_bundle_id=args.expected_bundle_id,
                expected_candidate_checkpoint_id=args.expected_candidate_checkpoint_id,
                expected_previous_checkpoint_id=state["head"]["checkpoint_id"],
            )
            if not report["admitted"]:
                _emit(
                    {
                        "advanced": False,
                        "state_id": state["state_id"],
                        "head": state["head"],
                        "admission": report,
                        "violations": [
                            {
                                "rule_id": "ATS004",
                                "message": "candidate bundle was denied by admission policy",
                            }
                        ],
                    },
                    args.format,
                )
                return 1
            try:
                updated = append_transition(state, report, verified)
            except AuditBundleTrustError as exc:
                if not exc.denied:
                    raise
                _emit(
                    {
                        "advanced": False,
                        "state_id": state["state_id"],
                        "head": state["head"],
                        "admission": report,
                        "violations": [{"rule_id": exc.rule_id, "message": str(exc)}],
                    },
                    args.format,
                )
                return 1
            _atomic_write(args.state, updated, require_absent=False)
        _emit(
            {
                "advanced": True,
                "previous_state_id": state["state_id"],
                "state_id": updated["state_id"],
                "head": updated["head"],
                "admission": {
                    "decision_id": report["decision_id"],
                    "policy_sha256": report["policy_sha256"],
                },
            },
            args.format,
        )
        return 0
    except (OSError, AuditBundleTrustError) as exc:
        rule_id = exc.rule_id if isinstance(exc, AuditBundleTrustError) else "ATS010"
        _emit(
            {"valid": False, "advanced": False, "rule_id": rule_id, "error": str(exc)},
            getattr(args, "format", "json"),
            stream=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
