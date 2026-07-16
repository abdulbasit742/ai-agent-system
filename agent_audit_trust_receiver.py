#!/usr/bin/env python3
"""Maintain a pinned receiver state for admitted audit trust handoff bundles."""
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

from agent_audit_trust_admission import (
    AuditTrustAdmissionError,
    evaluate_handoff,
    load_policy,
)
from agent_audit_trust_bundle import AuditTrustBundleError, verify_bundle

STATE_VERSION = 1
ENTRY_VERSION = 1
ZERO_HASH = "0" * 64
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_STATE_BYTES = 8_000_000
MAX_ENTRIES = 10_000

STATE_FIELDS = {"state_version", "entries", "head", "state_id"}
ENTRY_FIELDS = {
    "entry_version", "sequence", "kind", "previous_entry_hash",
    "evidence", "admission", "transition", "entry_hash",
}
EVIDENCE_FIELDS = {
    "handoff_bundle_id", "checkpoint_id", "state_id", "entry_count",
    "merkle_root", "head_entry_hash", "head_bundle_id", "head_checkpoint_id",
    "head_catalog_id", "generation", "segment_count",
}
ADMISSION_FIELDS = {"decision_id", "policy_sha256"}
TRANSITION_FIELDS = {
    "previous_checkpoint_id", "previous_state_id", "entry_delta", "generation_delta",
}
HEAD_FIELDS = {
    "sequence", "entry_hash", "handoff_bundle_id", "checkpoint_id", "state_id",
    "entry_count", "head_bundle_id", "generation", "segment_count",
}


class AuditTrustReceiverError(ValueError):
    """Raised when receiver state or its pinned handoff inputs are invalid."""

    def __init__(self, message: str, *, rule_id: str = "ATR002", denied: bool = False) -> None:
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
        raise AuditTrustReceiverError(f"{label} fields do not match the reviewed schema")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise AuditTrustReceiverError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuditTrustReceiverError(f"{label} must be a string", rule_id="ATR003")
    lowered = value.lower()
    if not HEX_64.fullmatch(lowered):
        raise AuditTrustReceiverError(
            f"{label} must be 64 hexadecimal characters", rule_id="ATR003"
        )
    return lowered


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditTrustReceiverError(
            f"{label} must be an integer greater than or equal to {minimum}"
        )
    return value


def _evidence(value: Any) -> dict[str, Any]:
    raw = _exact(value, EVIDENCE_FIELDS, "receiver evidence")
    return {
        "handoff_bundle_id": _hash(raw["handoff_bundle_id"], "handoff bundle id"),
        "checkpoint_id": _hash(raw["checkpoint_id"], "candidate checkpoint id"),
        "state_id": _hash(raw["state_id"], "candidate state id"),
        "entry_count": _integer(raw["entry_count"], "candidate entry count", 1),
        "merkle_root": _hash(raw["merkle_root"], "candidate merkle root"),
        "head_entry_hash": _hash(raw["head_entry_hash"], "candidate head entry hash"),
        "head_bundle_id": _hash(raw["head_bundle_id"], "candidate head bundle id"),
        "head_checkpoint_id": _hash(raw["head_checkpoint_id"], "candidate head checkpoint id"),
        "head_catalog_id": _hash(raw["head_catalog_id"], "candidate head catalog id"),
        "generation": _integer(raw["generation"], "candidate generation", 1),
        "segment_count": _integer(raw["segment_count"], "candidate segment count", 1),
    }


def _admission(value: Any) -> dict[str, Any]:
    raw = _exact(value, ADMISSION_FIELDS, "receiver admission")
    return {
        "decision_id": _hash(raw["decision_id"], "admission decision id"),
        "policy_sha256": _hash(raw["policy_sha256"], "admission policy sha256"),
    }


def _transition(value: Any) -> dict[str, Any]:
    raw = _exact(value, TRANSITION_FIELDS, "receiver transition")
    return {
        "previous_checkpoint_id": _hash(
            raw["previous_checkpoint_id"], "previous checkpoint id"
        ),
        "previous_state_id": _hash(raw["previous_state_id"], "previous state id"),
        "entry_delta": _integer(raw["entry_delta"], "entry delta", 1),
        "generation_delta": _integer(raw["generation_delta"], "generation delta", 1),
    }


def _evidence_from_verified(verified: dict[str, Any]) -> dict[str, Any]:
    candidate = verified.get("candidate")
    if not isinstance(candidate, dict):
        raise AuditTrustReceiverError("verified handoff candidate is malformed")
    head = candidate.get("head")
    if not isinstance(head, dict):
        raise AuditTrustReceiverError("verified handoff candidate head is malformed")
    return _evidence(
        {
            "handoff_bundle_id": verified.get("bundle_id"),
            "checkpoint_id": candidate.get("checkpoint_id"),
            "state_id": candidate.get("state_id"),
            "entry_count": candidate.get("entry_count"),
            "merkle_root": candidate.get("merkle_root"),
            "head_entry_hash": head.get("entry_hash"),
            "head_bundle_id": head.get("bundle_id"),
            "head_checkpoint_id": head.get("checkpoint_id"),
            "head_catalog_id": head.get("catalog_id"),
            "generation": head.get("generation"),
            "segment_count": head.get("segment_count"),
        }
    )


def _admission_from_report(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("admitted") is not True:
        raise AuditTrustReceiverError(
            "only an admitted handoff can enter receiver history",
            rule_id="ATR004",
            denied=True,
        )
    return _admission(
        {
            "decision_id": report.get("decision_id"),
            "policy_sha256": report.get("policy_sha256"),
        }
    )


def _report_matches_verified(report: dict[str, Any], verified: dict[str, Any]) -> None:
    identity = report.get("identity")
    details = report.get("evidence")
    candidate = verified.get("candidate")
    if not isinstance(identity, dict) or not isinstance(details, dict) or not isinstance(candidate, dict):
        raise AuditTrustReceiverError("admission report identity is malformed")
    head = candidate.get("head")
    if not isinstance(head, dict):
        raise AuditTrustReceiverError("verified handoff candidate head is malformed")
    expected = {
        "bundle_id": verified.get("bundle_id"),
        "bundle_type": verified.get("bundle_type"),
        "candidate_checkpoint_id": candidate.get("checkpoint_id"),
        "candidate_state_id": candidate.get("state_id"),
        "previous_checkpoint_id": (
            verified.get("previous", {}).get("checkpoint_id")
            if isinstance(verified.get("previous"), dict) else None
        ),
        "previous_state_id": (
            verified.get("previous", {}).get("state_id")
            if isinstance(verified.get("previous"), dict) else None
        ),
    }
    if identity != expected:
        raise AuditTrustReceiverError("admission report differs from verified handoff identity")
    checks = {
        "candidate_entry_count": candidate.get("entry_count"),
        "candidate_generation": head.get("generation"),
        "candidate_segment_count": head.get("segment_count"),
        "head_bundle_id": verified.get("head_bundle_id"),
    }
    for key, value in checks.items():
        if details.get(key) != value:
            raise AuditTrustReceiverError(
                f"admission report {key} differs from verified handoff"
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
    return {**payload, "entry_hash": _identifier(b"audit-trust-receiver-entry-v1", payload)}


def _head(entries: list[dict[str, Any]]) -> dict[str, Any]:
    last = entries[-1]
    evidence = last["evidence"]
    return {
        "sequence": last["sequence"],
        "entry_hash": last["entry_hash"],
        "handoff_bundle_id": evidence["handoff_bundle_id"],
        "checkpoint_id": evidence["checkpoint_id"],
        "state_id": evidence["state_id"],
        "entry_count": evidence["entry_count"],
        "head_bundle_id": evidence["head_bundle_id"],
        "generation": evidence["generation"],
        "segment_count": evidence["segment_count"],
    }


def _state_payload(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {"state_version": STATE_VERSION, "entries": entries, "head": _head(entries)}


def _seal_state(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "state_id": _identifier(b"audit-trust-receiver-state-v1", payload)}


def create_state(report: dict[str, Any], verified: dict[str, Any]) -> dict[str, Any]:
    if report.get("identity", {}).get("bundle_type") != "snapshot":
        raise AuditTrustReceiverError(
            "receiver anchor must be an admitted snapshot handoff", rule_id="ATR005"
        )
    _report_matches_verified(report, verified)
    evidence = _evidence_from_verified(verified)
    entry = _seal_entry(
        _entry_payload(1, "anchor", ZERO_HASH, evidence, _admission_from_report(report), None)
    )
    return _seal_state(_state_payload([entry]))


def append_transition(
    state: dict[str, Any], report: dict[str, Any], verified: dict[str, Any]
) -> dict[str, Any]:
    normalized = validate_state(state)
    identity = report.get("identity")
    details = report.get("evidence")
    if report.get("admitted") is not True:
        raise AuditTrustReceiverError(
            "candidate handoff was denied by admission policy",
            rule_id="ATR004",
            denied=True,
        )
    if not isinstance(identity, dict) or identity.get("bundle_type") != "transition":
        raise AuditTrustReceiverError(
            "receiver advancement requires an admitted transition handoff",
            rule_id="ATR005",
        )
    if not isinstance(details, dict):
        raise AuditTrustReceiverError("admission report evidence is malformed")
    previous = verified.get("previous")
    if not isinstance(previous, dict):
        raise AuditTrustReceiverError("transition handoff previous checkpoint is missing")
    head = normalized["head"]
    if (
        previous.get("checkpoint_id") != head["checkpoint_id"]
        or previous.get("state_id") != head["state_id"]
        or previous.get("entry_count") != head["entry_count"]
    ):
        raise AuditTrustReceiverError(
            "transition handoff does not start from the receiver-state head",
            rule_id="ATR006",
            denied=True,
        )
    _report_matches_verified(report, verified)
    evidence = _evidence_from_verified(verified)
    if (
        evidence["entry_count"] <= head["entry_count"]
        or evidence["generation"] <= head["generation"]
        or evidence["segment_count"] < head["segment_count"]
    ):
        raise AuditTrustReceiverError(
            "candidate trust history does not advance receiver state",
            rule_id="ATR008",
            denied=True,
        )
    seen_handoffs = {item["evidence"]["handoff_bundle_id"] for item in normalized["entries"]}
    seen_checkpoints = {item["evidence"]["checkpoint_id"] for item in normalized["entries"]}
    seen_states = {item["evidence"]["state_id"] for item in normalized["entries"]}
    if (
        evidence["handoff_bundle_id"] in seen_handoffs
        or evidence["checkpoint_id"] in seen_checkpoints
        or evidence["state_id"] in seen_states
    ):
        raise AuditTrustReceiverError(
            "candidate handoff identity already exists in receiver history",
            rule_id="ATR007",
            denied=True,
        )
    transition = _transition(
        {
            "previous_checkpoint_id": previous.get("checkpoint_id"),
            "previous_state_id": previous.get("state_id"),
            "entry_delta": details.get("entry_delta"),
            "generation_delta": details.get("generation_delta"),
        }
    )
    if transition["entry_delta"] != evidence["entry_count"] - head["entry_count"]:
        raise AuditTrustReceiverError("transition entry delta is inconsistent")
    if transition["generation_delta"] != evidence["generation"] - head["generation"]:
        raise AuditTrustReceiverError("transition generation delta is inconsistent")
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
    root = _exact(value, STATE_FIELDS, "audit trust receiver state")
    if root["state_version"] != STATE_VERSION:
        raise AuditTrustReceiverError(f"receiver state version must be {STATE_VERSION}")
    raw_entries = root["entries"]
    if not isinstance(raw_entries, list) or not raw_entries or len(raw_entries) > MAX_ENTRIES:
        raise AuditTrustReceiverError("receiver state entry count is outside the reviewed boundary")
    entries: list[dict[str, Any]] = []
    previous_hash = ZERO_HASH
    previous_evidence: dict[str, Any] | None = None
    seen_handoffs: set[str] = set()
    seen_checkpoints: set[str] = set()
    seen_states: set[str] = set()
    for index, raw_entry in enumerate(raw_entries, 1):
        entry = _exact(raw_entry, ENTRY_FIELDS, f"receiver entry {index}")
        if entry["entry_version"] != ENTRY_VERSION or entry["sequence"] != index:
            raise AuditTrustReceiverError(f"receiver entry {index} version or sequence is invalid")
        kind = entry["kind"]
        if kind not in {"anchor", "transition"} or (index == 1) != (kind == "anchor"):
            raise AuditTrustReceiverError(f"receiver entry {index} kind is invalid")
        if entry["previous_entry_hash"] != previous_hash:
            raise AuditTrustReceiverError(f"receiver entry {index} previous hash does not match")
        evidence = _evidence(entry["evidence"])
        admission = _admission(entry["admission"])
        if index == 1:
            if entry["transition"] is not None:
                raise AuditTrustReceiverError("receiver anchor must not contain transition evidence")
            transition = None
        else:
            transition = _transition(entry["transition"])
            assert previous_evidence is not None
            if (
                transition["previous_checkpoint_id"] != previous_evidence["checkpoint_id"]
                or transition["previous_state_id"] != previous_evidence["state_id"]
            ):
                raise AuditTrustReceiverError(
                    f"receiver entry {index} transition does not match previous evidence"
                )
            if evidence["entry_count"] <= previous_evidence["entry_count"]:
                raise AuditTrustReceiverError(f"receiver entry {index} entry count does not increase")
            if evidence["generation"] <= previous_evidence["generation"]:
                raise AuditTrustReceiverError(f"receiver entry {index} generation does not increase")
            if evidence["segment_count"] < previous_evidence["segment_count"]:
                raise AuditTrustReceiverError(f"receiver entry {index} segment count decreases")
            if transition["entry_delta"] != evidence["entry_count"] - previous_evidence["entry_count"]:
                raise AuditTrustReceiverError(f"receiver entry {index} entry delta is invalid")
            if transition["generation_delta"] != evidence["generation"] - previous_evidence["generation"]:
                raise AuditTrustReceiverError(f"receiver entry {index} generation delta is invalid")
        if evidence["handoff_bundle_id"] in seen_handoffs:
            raise AuditTrustReceiverError("receiver history contains a duplicate handoff bundle id")
        if evidence["checkpoint_id"] in seen_checkpoints:
            raise AuditTrustReceiverError("receiver history contains a duplicate checkpoint id")
        if evidence["state_id"] in seen_states:
            raise AuditTrustReceiverError("receiver history contains a duplicate candidate state id")
        seen_handoffs.add(evidence["handoff_bundle_id"])
        seen_checkpoints.add(evidence["checkpoint_id"])
        seen_states.add(evidence["state_id"])
        payload = _entry_payload(index, kind, previous_hash, evidence, admission, transition)
        entry_hash = _hash(entry["entry_hash"], "receiver entry hash")
        if entry_hash != _identifier(b"audit-trust-receiver-entry-v1", payload):
            raise AuditTrustReceiverError(f"receiver entry {index} hash does not match")
        sealed = {**payload, "entry_hash": entry_hash}
        entries.append(sealed)
        previous_hash = entry_hash
        previous_evidence = evidence
    payload = _state_payload(entries)
    head = _exact(root["head"], HEAD_FIELDS, "receiver state head")
    if head != payload["head"]:
        raise AuditTrustReceiverError("receiver state head does not match final history entry")
    state_id = _hash(root["state_id"], "receiver state id")
    if state_id != _identifier(b"audit-trust-receiver-state-v1", payload):
        raise AuditTrustReceiverError("receiver state id does not match canonical state")
    return {**payload, "state_id": state_id}


def load_state(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditTrustReceiverError(
            "receiver state must be a regular non-symlink file", rule_id="ATR001"
        )
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_STATE_BYTES:
        raise AuditTrustReceiverError("receiver state size is outside the reviewed boundary")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, _DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
        raise AuditTrustReceiverError(f"receiver state is not strict JSON: {exc}") from exc
    normalized = validate_state(value)
    if raw != canonical_json(normalized):
        raise AuditTrustReceiverError("receiver state is not canonically serialized")
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
        raise AuditTrustReceiverError(
            "receiver state parent must be a regular non-symlink directory", rule_id="ATR001"
        )
    for directory in reversed(missing):
        directory.mkdir()
    if parent.is_symlink() or not parent.is_dir():
        raise AuditTrustReceiverError(
            "receiver state parent must be a regular non-symlink directory", rule_id="ATR001"
        )
    return parent


def _outside_bundle(path: Path, bundle: Path, label: str) -> None:
    resolved = Path(path).resolve()
    root = Path(bundle).resolve()
    if resolved == root or root in resolved.parents:
        raise AuditTrustReceiverError(
            f"{label} must be consumer-owned and outside the handoff bundle",
            rule_id="ATR009",
        )


@contextmanager
def _state_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    if fcntl is None:
        raise AuditTrustReceiverError(
            "receiver-state locking is unavailable on this platform", rule_id="ATR010"
        )
    parent = _safe_parent(path)
    lock_path = parent / (path.name + ".lock")
    if lock_path.is_symlink():
        raise AuditTrustReceiverError("receiver-state lock must not be a symlink", rule_id="ATR001")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise AuditTrustReceiverError("unable to open receiver-state lock", rule_id="ATR010") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AuditTrustReceiverError("receiver-state lock is not a regular file", rule_id="ATR001")
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
        raise AuditTrustReceiverError("receiver state output must not be a symlink", rule_id="ATR001")
    if path.exists() and not path.is_file():
        raise AuditTrustReceiverError("receiver state output must be a regular file", rule_id="ATR001")
    if require_absent and path.exists():
        raise AuditTrustReceiverError("refusing to overwrite existing receiver state", rule_id="ATR001")
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
            raise AuditTrustReceiverError("receiver state output appeared during creation", rule_id="ATR001")
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


def _verified_handoff(
    bundle: Path,
    *,
    expected_bundle_id: str,
    expected_candidate_checkpoint_id: str,
    expected_previous_checkpoint_id: str | None = None,
) -> dict[str, Any]:
    try:
        return verify_bundle(
            Path(bundle),
            expected_bundle_id=_pin(expected_bundle_id, "expected handoff bundle id"),
            expected_candidate_checkpoint_id=_pin(
                expected_candidate_checkpoint_id, "expected candidate checkpoint id"
            ),
            expected_previous_checkpoint_id=(
                _pin(expected_previous_checkpoint_id, "expected previous checkpoint id")
                if expected_previous_checkpoint_id is not None else None
            ),
        )
    except AuditTrustBundleError as exc:
        raise AuditTrustReceiverError(
            f"audit trust handoff verification failed ({exc.rule_id}): {exc}"
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
        report = evaluate_handoff(
            Path(bundle),
            policy,
            expected_bundle_id=_pin(expected_bundle_id, "expected handoff bundle id"),
            expected_candidate_checkpoint_id=_pin(
                expected_candidate_checkpoint_id, "expected candidate checkpoint id"
            ),
            expected_previous_checkpoint_id=(
                _pin(expected_previous_checkpoint_id, "expected previous checkpoint id")
                if expected_previous_checkpoint_id is not None else None
            ),
        )
    except AuditTrustAdmissionError as exc:
        raise AuditTrustReceiverError(f"audit trust admission failed: {exc}") from exc
    verified = _verified_handoff(
        bundle,
        expected_bundle_id=expected_bundle_id,
        expected_candidate_checkpoint_id=expected_candidate_checkpoint_id,
        expected_previous_checkpoint_id=expected_previous_checkpoint_id,
    )
    return report, verified


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    stream = stream or sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
        return
    for key in (
        "valid", "created", "advanced", "state_id", "previous_state_id",
        "rule_id", "error",
    ):
        if key in payload:
            print(f"{key}: {payload[key]}", file=stream)
    head = payload.get("head")
    if isinstance(head, dict):
        print(
            "head: "
            f"sequence={head['sequence']} entry_count={head['entry_count']} "
            f"generation={head['generation']} checkpoint_id={head['checkpoint_id']}",
            file=stream,
        )
    for violation in payload.get("violations", []):
        print(f"- {violation['rule_id']}: {violation['message']}", file=stream)
    admission = payload.get("admission")
    if isinstance(admission, dict):
        for violation in admission.get("violations", []):
            print(f"- {violation['rule_id']}: {violation['message']}", file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init")
    initialize.add_argument("state", type=Path)
    initialize.add_argument("bundle", type=Path)
    initialize.add_argument("--policy", type=Path, required=True)
    initialize.add_argument("--expected-bundle-id", required=True)
    initialize.add_argument("--expected-candidate-checkpoint-id", required=True)
    initialize.add_argument("--format", choices=("json", "text"), default="json")

    verify = commands.add_parser("verify")
    verify.add_argument("state", type=Path)
    verify.add_argument("--expected-state-id", required=True)
    verify.add_argument("--bundle", type=Path)
    verify.add_argument("--format", choices=("json", "text"), default="json")

    advance = commands.add_parser("advance")
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
            _outside_bundle(args.state, args.bundle, "receiver state")
            _outside_bundle(args.policy, args.bundle, "admission policy")
            with _state_lock(args.state, exclusive=True):
                if args.state.exists() or args.state.is_symlink():
                    raise AuditTrustReceiverError(
                        "refusing to overwrite existing receiver state", rule_id="ATR001"
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
                            "violations": [{
                                "rule_id": "ATR004",
                                "message": "anchor handoff was denied by admission policy",
                            }],
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

        expected_state_id = _pin(args.expected_state_id, "expected receiver state id")
        bundle = args.bundle
        if bundle is not None:
            _outside_bundle(args.state, bundle, "receiver state")
        with _state_lock(args.state, exclusive=args.command == "advance"):
            state = load_state(args.state)
            if state["state_id"] != expected_state_id:
                raise AuditTrustReceiverError(
                    "receiver state differs from the externally retained state pin",
                    rule_id="ATR003",
                    denied=True,
                )
            if args.command == "verify":
                if args.bundle is not None:
                    last = state["entries"][-1]
                    transition = last["transition"]
                    verified = _verified_handoff(
                        args.bundle,
                        expected_bundle_id=state["head"]["handoff_bundle_id"],
                        expected_candidate_checkpoint_id=state["head"]["checkpoint_id"],
                        expected_previous_checkpoint_id=(
                            transition["previous_checkpoint_id"]
                            if isinstance(transition, dict) else None
                        ),
                    )
                    if _evidence_from_verified(verified) != last["evidence"]:
                        raise AuditTrustReceiverError(
                            "verified handoff does not match the receiver-state head",
                            rule_id="ATR006",
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
                        "violations": [{
                            "rule_id": "ATR004",
                            "message": "candidate handoff was denied by admission policy",
                        }],
                    },
                    args.format,
                )
                return 1
            try:
                updated = append_transition(state, report, verified)
            except AuditTrustReceiverError as exc:
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
    except (OSError, AuditTrustReceiverError) as exc:
        rule_id = exc.rule_id if isinstance(exc, AuditTrustReceiverError) else "ATR010"
        _emit(
            {"valid": False, "advanced": False, "rule_id": rule_id, "error": str(exc)},
            getattr(args, "format", "json"),
            stream=sys.stderr,
        )
        return 1 if isinstance(exc, AuditTrustReceiverError) and exc.denied else 2


if __name__ == "__main__":
    raise SystemExit(main())
