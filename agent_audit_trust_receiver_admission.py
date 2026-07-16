#!/usr/bin/env python3
"""Consumer-owned admission policy for verified audit trust receiver bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from agent_audit_trust_receiver_bundle import (
    AuditTrustReceiverBundleError,
    MANIFEST_NAME,
    load_manifest,
    verify_bundle,
)

POLICY_VERSION = 1
MAX_POLICY_BYTES = 1_000_000
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_BUNDLE_TYPES = frozenset({"snapshot", "transition"})
ALLOWED_RELATIONS = frozenset({"right-descendant"})

POLICY_FIELDS = {"version", "bundle", "candidate", "selection", "transition"}
BUNDLE_FIELDS = {"allowed_types", "max_files", "max_bytes", "min_proofs", "max_proofs"}
CANDIDATE_FIELDS = {
    "min_receiver_entries", "max_receiver_entries",
    "min_trust_entries", "max_trust_entries",
    "min_generation", "max_generation",
    "min_segment_count", "max_segment_count",
    "allowed_receiver_state_ids", "allowed_receiver_checkpoint_ids",
    "allowed_head_handoff_ids", "allowed_trust_state_ids",
    "allowed_trust_checkpoint_ids",
}
SELECTION_FIELDS = {
    "required_sequences", "allowed_sequences",
    "required_handoff_ids", "allowed_handoff_ids",
    "require_anchor", "require_head",
}
TRANSITION_FIELDS = {
    "allowed_relations",
    "min_receiver_entry_delta", "max_receiver_entry_delta",
    "min_trust_entry_delta", "max_trust_entry_delta",
    "min_generation_delta", "max_generation_delta",
    "allowed_previous_receiver_state_ids",
    "allowed_previous_receiver_checkpoint_ids",
    "require_single_step",
}


class AuditTrustReceiverAdmissionError(ValueError):
    """Raised when a receiver-bundle policy or evaluation is unsafe."""

    def __init__(self, message: str, *, rule_id: str = "ARA000") -> None:
        super().__init__(message)
        self.rule_id = rule_id


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


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditTrustReceiverAdmissionError(
            f"{label} fields do not match the reviewed schema"
        )
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditTrustReceiverAdmissionError(
            f"{label} must be an integer greater than or equal to {minimum}"
        )
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise AuditTrustReceiverAdmissionError(f"{label} must be a boolean")
    return value


def _strings(
    value: Any,
    label: str,
    *,
    allowed: frozenset[str] | None = None,
    hashes: bool = False,
    require_nonempty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or (require_nonempty and not value):
        qualifier = "non-empty " if require_nonempty else ""
        raise AuditTrustReceiverAdmissionError(f"{label} must be a {qualifier}array")
    if any(not isinstance(item, str) or not item for item in value):
        raise AuditTrustReceiverAdmissionError(
            f"{label} must contain only non-empty strings"
        )
    if value != sorted(value) or len(value) != len(set(value)):
        raise AuditTrustReceiverAdmissionError(
            f"{label} must be sorted and contain no duplicates"
        )
    if allowed is not None and any(item not in allowed for item in value):
        raise AuditTrustReceiverAdmissionError(f"{label} contains an unsupported value")
    if hashes and any(not HEX_64.fullmatch(item) for item in value):
        raise AuditTrustReceiverAdmissionError(
            f"{label} must contain lowercase 64-character hexadecimal IDs"
        )
    return list(value)


def _integers(value: Any, label: str) -> list[int]:
    if not isinstance(value, list):
        raise AuditTrustReceiverAdmissionError(f"{label} must be an array")
    if any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in value):
        raise AuditTrustReceiverAdmissionError(
            f"{label} must contain only positive integers"
        )
    if value != sorted(value) or len(value) != len(set(value)):
        raise AuditTrustReceiverAdmissionError(
            f"{label} must be sorted and contain no duplicates"
        )
    return list(value)


def default_policy() -> dict[str, Any]:
    return {
        "version": POLICY_VERSION,
        "bundle": {
            "allowed_types": ["snapshot", "transition"],
            "max_files": 260,
            "max_bytes": 67_108_864,
            "min_proofs": 1,
            "max_proofs": 128,
        },
        "candidate": {
            "min_receiver_entries": 1,
            "max_receiver_entries": 1_000_000,
            "min_trust_entries": 1,
            "max_trust_entries": 1_000_000,
            "min_generation": 1,
            "max_generation": 1_000_000,
            "min_segment_count": 1,
            "max_segment_count": 1_000_000,
            "allowed_receiver_state_ids": [],
            "allowed_receiver_checkpoint_ids": [],
            "allowed_head_handoff_ids": [],
            "allowed_trust_state_ids": [],
            "allowed_trust_checkpoint_ids": [],
        },
        "selection": {
            "required_sequences": [],
            "allowed_sequences": [],
            "required_handoff_ids": [],
            "allowed_handoff_ids": [],
            "require_anchor": False,
            "require_head": True,
        },
        "transition": {
            "allowed_relations": ["right-descendant"],
            "min_receiver_entry_delta": 1,
            "max_receiver_entry_delta": 1_000_000,
            "min_trust_entry_delta": 1,
            "max_trust_entry_delta": 1_000_000,
            "min_generation_delta": 1,
            "max_generation_delta": 1_000_000,
            "allowed_previous_receiver_state_ids": [],
            "allowed_previous_receiver_checkpoint_ids": [],
            "require_single_step": False,
        },
    }


def validate_policy(value: Any) -> dict[str, Any]:
    root = _exact(value, POLICY_FIELDS, "receiver admission policy")
    if root["version"] != POLICY_VERSION:
        raise AuditTrustReceiverAdmissionError(
            f"receiver admission policy version must be {POLICY_VERSION}"
        )
    bundle = _exact(root["bundle"], BUNDLE_FIELDS, "bundle policy")
    candidate = _exact(root["candidate"], CANDIDATE_FIELDS, "candidate policy")
    selection = _exact(root["selection"], SELECTION_FIELDS, "selection policy")
    transition = _exact(root["transition"], TRANSITION_FIELDS, "transition policy")
    normalized = {
        "version": POLICY_VERSION,
        "bundle": {
            "allowed_types": _strings(
                bundle["allowed_types"], "bundle.allowed_types",
                allowed=ALLOWED_BUNDLE_TYPES, require_nonempty=True,
            ),
            "max_files": _integer(bundle["max_files"], "bundle.max_files", 1),
            "max_bytes": _integer(bundle["max_bytes"], "bundle.max_bytes", 1),
            "min_proofs": _integer(bundle["min_proofs"], "bundle.min_proofs", 1),
            "max_proofs": _integer(bundle["max_proofs"], "bundle.max_proofs", 1),
        },
        "candidate": {
            "min_receiver_entries": _integer(candidate["min_receiver_entries"], "candidate.min_receiver_entries", 1),
            "max_receiver_entries": _integer(candidate["max_receiver_entries"], "candidate.max_receiver_entries", 1),
            "min_trust_entries": _integer(candidate["min_trust_entries"], "candidate.min_trust_entries", 1),
            "max_trust_entries": _integer(candidate["max_trust_entries"], "candidate.max_trust_entries", 1),
            "min_generation": _integer(candidate["min_generation"], "candidate.min_generation", 1),
            "max_generation": _integer(candidate["max_generation"], "candidate.max_generation", 1),
            "min_segment_count": _integer(candidate["min_segment_count"], "candidate.min_segment_count", 1),
            "max_segment_count": _integer(candidate["max_segment_count"], "candidate.max_segment_count", 1),
            "allowed_receiver_state_ids": _strings(candidate["allowed_receiver_state_ids"], "candidate.allowed_receiver_state_ids", hashes=True),
            "allowed_receiver_checkpoint_ids": _strings(candidate["allowed_receiver_checkpoint_ids"], "candidate.allowed_receiver_checkpoint_ids", hashes=True),
            "allowed_head_handoff_ids": _strings(candidate["allowed_head_handoff_ids"], "candidate.allowed_head_handoff_ids", hashes=True),
            "allowed_trust_state_ids": _strings(candidate["allowed_trust_state_ids"], "candidate.allowed_trust_state_ids", hashes=True),
            "allowed_trust_checkpoint_ids": _strings(candidate["allowed_trust_checkpoint_ids"], "candidate.allowed_trust_checkpoint_ids", hashes=True),
        },
        "selection": {
            "required_sequences": _integers(selection["required_sequences"], "selection.required_sequences"),
            "allowed_sequences": _integers(selection["allowed_sequences"], "selection.allowed_sequences"),
            "required_handoff_ids": _strings(selection["required_handoff_ids"], "selection.required_handoff_ids", hashes=True),
            "allowed_handoff_ids": _strings(selection["allowed_handoff_ids"], "selection.allowed_handoff_ids", hashes=True),
            "require_anchor": _boolean(selection["require_anchor"], "selection.require_anchor"),
            "require_head": _boolean(selection["require_head"], "selection.require_head"),
        },
        "transition": {
            "allowed_relations": _strings(
                transition["allowed_relations"], "transition.allowed_relations",
                allowed=ALLOWED_RELATIONS, require_nonempty=True,
            ),
            "min_receiver_entry_delta": _integer(transition["min_receiver_entry_delta"], "transition.min_receiver_entry_delta", 1),
            "max_receiver_entry_delta": _integer(transition["max_receiver_entry_delta"], "transition.max_receiver_entry_delta", 1),
            "min_trust_entry_delta": _integer(transition["min_trust_entry_delta"], "transition.min_trust_entry_delta", 1),
            "max_trust_entry_delta": _integer(transition["max_trust_entry_delta"], "transition.max_trust_entry_delta", 1),
            "min_generation_delta": _integer(transition["min_generation_delta"], "transition.min_generation_delta", 1),
            "max_generation_delta": _integer(transition["max_generation_delta"], "transition.max_generation_delta", 1),
            "allowed_previous_receiver_state_ids": _strings(transition["allowed_previous_receiver_state_ids"], "transition.allowed_previous_receiver_state_ids", hashes=True),
            "allowed_previous_receiver_checkpoint_ids": _strings(transition["allowed_previous_receiver_checkpoint_ids"], "transition.allowed_previous_receiver_checkpoint_ids", hashes=True),
            "require_single_step": _boolean(transition["require_single_step"], "transition.require_single_step"),
        },
    }
    if normalized["bundle"]["min_proofs"] > normalized["bundle"]["max_proofs"]:
        raise AuditTrustReceiverAdmissionError("bundle.min_proofs must not exceed bundle.max_proofs")
    pairs = (
        ("candidate.receiver_entries", normalized["candidate"]["min_receiver_entries"], normalized["candidate"]["max_receiver_entries"]),
        ("candidate.trust_entries", normalized["candidate"]["min_trust_entries"], normalized["candidate"]["max_trust_entries"]),
        ("candidate.generation", normalized["candidate"]["min_generation"], normalized["candidate"]["max_generation"]),
        ("candidate.segment_count", normalized["candidate"]["min_segment_count"], normalized["candidate"]["max_segment_count"]),
        ("transition.receiver_entry_delta", normalized["transition"]["min_receiver_entry_delta"], normalized["transition"]["max_receiver_entry_delta"]),
        ("transition.trust_entry_delta", normalized["transition"]["min_trust_entry_delta"], normalized["transition"]["max_trust_entry_delta"]),
        ("transition.generation_delta", normalized["transition"]["min_generation_delta"], normalized["transition"]["max_generation_delta"]),
    )
    for label, minimum, maximum in pairs:
        if minimum > maximum:
            raise AuditTrustReceiverAdmissionError(f"{label} minimum must not exceed maximum")
    required_sequences = set(normalized["selection"]["required_sequences"])
    allowed_sequences = set(normalized["selection"]["allowed_sequences"])
    if allowed_sequences and not required_sequences <= allowed_sequences:
        raise AuditTrustReceiverAdmissionError("required sequences must be a subset of allowed sequences")
    required_handoffs = set(normalized["selection"]["required_handoff_ids"])
    allowed_handoffs = set(normalized["selection"]["allowed_handoff_ids"])
    if allowed_handoffs and not required_handoffs <= allowed_handoffs:
        raise AuditTrustReceiverAdmissionError("required handoff IDs must be a subset of allowed handoff IDs")
    return normalized


def policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(validate_policy(policy))).hexdigest()


def _decision_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"audit-trust-receiver-admission-decision-v1\0" + canonical_json(payload)
    ).hexdigest()


def load_policy(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditTrustReceiverAdmissionError("receiver admission policy must be a regular non-symlink file")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_POLICY_BYTES:
        raise AuditTrustReceiverAdmissionError("receiver admission policy size is outside the reviewed boundary")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_object, parse_constant=_reject_constant)
    except (UnicodeDecodeError, _DuplicateKeyError, ValueError, json.JSONDecodeError) as exc:
        raise AuditTrustReceiverAdmissionError(f"receiver admission policy is not strict JSON: {exc}") from exc
    normalized = validate_policy(payload)
    if raw != canonical_json(normalized):
        raise AuditTrustReceiverAdmissionError("receiver admission policy is not canonically serialized")
    return normalized


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
        raise AuditTrustReceiverAdmissionError("receiver admission policy parent must be a regular non-symlink directory")
    for directory in reversed(missing):
        directory.mkdir()
    if parent.is_symlink() or not parent.is_dir():
        raise AuditTrustReceiverAdmissionError("receiver admission policy parent must be a regular non-symlink directory")
    return parent


def _write_new(path: Path, payload: dict[str, Any]) -> None:
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise AuditTrustReceiverAdmissionError("refusing to overwrite existing receiver admission policy")
    _safe_parent(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(canonical_json(payload))
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _deny(violations: list[dict[str, Any]], rule_id: str, message: str, **context: Any) -> None:
    item: dict[str, Any] = {"rule_id": rule_id, "message": message}
    for key in sorted(context):
        item[key] = context[key]
    violations.append(item)


def _allowed(actual: str, allowed: list[str]) -> bool:
    return not allowed or actual in allowed


def _policy_outside_bundle(policy_path: Path, bundle_dir: Path) -> None:
    policy = Path(policy_path).resolve(strict=False)
    bundle = Path(bundle_dir).resolve(strict=False)
    try:
        policy.relative_to(bundle)
    except ValueError:
        return
    raise AuditTrustReceiverAdmissionError("receiver admission policy must remain outside the receiver bundle")


def evaluate_bundle(
    bundle_dir: Path,
    policy: dict[str, Any],
    *,
    expected_bundle_id: str,
    expected_candidate_checkpoint_id: str,
    expected_previous_checkpoint_id: str | None = None,
) -> dict[str, Any]:
    normalized_policy = validate_policy(policy)
    try:
        verified = verify_bundle(
            Path(bundle_dir),
            expected_bundle_id=expected_bundle_id,
            expected_candidate_checkpoint_id=expected_candidate_checkpoint_id,
            expected_previous_checkpoint_id=expected_previous_checkpoint_id,
        )
        manifest = load_manifest(Path(bundle_dir) / MANIFEST_NAME)
    except AuditTrustReceiverBundleError as exc:
        raise AuditTrustReceiverAdmissionError(
            f"receiver bundle verification failed ({exc.rule_id}): {exc}"
        ) from exc
    if manifest["bundle_id"] != verified["bundle_id"]:
        raise AuditTrustReceiverAdmissionError("receiver bundle manifest identity changed after verification")

    violations: list[dict[str, Any]] = []
    bundle_policy = normalized_policy["bundle"]
    candidate_policy = normalized_policy["candidate"]
    selection_policy = normalized_policy["selection"]
    transition_policy = normalized_policy["transition"]
    candidate = verified["candidate"]
    head = candidate["head"]
    entries = manifest["entries"]
    sequences = [entry["sequence"] for entry in entries]
    handoff_ids = [entry["handoff_bundle_id"] for entry in entries]

    if verified["bundle_type"] not in bundle_policy["allowed_types"]:
        _deny(violations, "ARA001", "receiver bundle type is not allowed", bundle_type=verified["bundle_type"])
    if verified["files"] > bundle_policy["max_files"] or verified["bytes"] > bundle_policy["max_bytes"]:
        _deny(violations, "ARA002", "receiver bundle size exceeds policy", files=verified["files"], max_files=bundle_policy["max_files"], bytes=verified["bytes"], max_bytes=bundle_policy["max_bytes"])
    if not bundle_policy["min_proofs"] <= verified["proof_count"] <= bundle_policy["max_proofs"]:
        _deny(violations, "ARA003", "receiver bundle proof count is outside policy", actual=verified["proof_count"], minimum=bundle_policy["min_proofs"], maximum=bundle_policy["max_proofs"])
    if not candidate_policy["min_receiver_entries"] <= candidate["entry_count"] <= candidate_policy["max_receiver_entries"]:
        _deny(violations, "ARA004", "candidate receiver entry count is outside policy", actual=candidate["entry_count"])
    if not candidate_policy["min_trust_entries"] <= head["entry_count"] <= candidate_policy["max_trust_entries"]:
        _deny(violations, "ARA004", "candidate trust entry count is outside policy", actual=head["entry_count"])
    if not candidate_policy["min_generation"] <= head["generation"] <= candidate_policy["max_generation"]:
        _deny(violations, "ARA005", "candidate generation is outside policy", actual=head["generation"])
    if not candidate_policy["min_segment_count"] <= head["segment_count"] <= candidate_policy["max_segment_count"]:
        _deny(violations, "ARA006", "candidate segment count is outside policy", actual=head["segment_count"])
    if not _allowed(candidate["state_id"], candidate_policy["allowed_receiver_state_ids"]):
        _deny(violations, "ARA007", "candidate receiver state ID is not allowed", state_id=candidate["state_id"])
    if not _allowed(candidate["checkpoint_id"], candidate_policy["allowed_receiver_checkpoint_ids"]):
        _deny(violations, "ARA007", "candidate receiver checkpoint ID is not allowed", checkpoint_id=candidate["checkpoint_id"])
    if not _allowed(head["handoff_bundle_id"], candidate_policy["allowed_head_handoff_ids"]):
        _deny(violations, "ARA008", "candidate head handoff ID is not allowed", handoff_bundle_id=head["handoff_bundle_id"])
    if not _allowed(head["state_id"], candidate_policy["allowed_trust_state_ids"]):
        _deny(violations, "ARA008", "candidate trust state ID is not allowed", state_id=head["state_id"])
    if not _allowed(head["checkpoint_id"], candidate_policy["allowed_trust_checkpoint_ids"]):
        _deny(violations, "ARA008", "candidate trust checkpoint ID is not allowed", checkpoint_id=head["checkpoint_id"])

    selected_sequences = set(sequences)
    required_sequences = set(selection_policy["required_sequences"])
    allowed_sequences = set(selection_policy["allowed_sequences"])
    if not required_sequences <= selected_sequences:
        _deny(violations, "ARA009", "required receiver sequences are missing", missing=sorted(required_sequences - selected_sequences))
    if allowed_sequences and not selected_sequences <= allowed_sequences:
        _deny(violations, "ARA009", "selected receiver sequences exceed the allowlist", unexpected=sorted(selected_sequences - allowed_sequences))
    selected_handoffs = set(handoff_ids)
    required_handoffs = set(selection_policy["required_handoff_ids"])
    allowed_handoffs = set(selection_policy["allowed_handoff_ids"])
    if not required_handoffs <= selected_handoffs:
        _deny(violations, "ARA010", "required handoff IDs are missing", missing=sorted(required_handoffs - selected_handoffs))
    if allowed_handoffs and not selected_handoffs <= allowed_handoffs:
        _deny(violations, "ARA010", "selected handoff IDs exceed the allowlist", unexpected=sorted(selected_handoffs - allowed_handoffs))
    if selection_policy["require_anchor"] and 1 not in selected_sequences:
        _deny(violations, "ARA011", "receiver anchor proof is required")
    if selection_policy["require_head"] and candidate["entry_count"] not in selected_sequences:
        _deny(violations, "ARA011", "candidate receiver-head proof is required")

    previous = verified["previous"]
    receiver_entry_delta = trust_entry_delta = generation_delta = None
    if verified["bundle_type"] == "transition":
        relation = verified["consistency"]["relation"]
        if relation not in transition_policy["allowed_relations"]:
            _deny(violations, "ARA012", "receiver consistency relation is not allowed", relation=relation)
        receiver_entry_delta = candidate["entry_count"] - previous["entry_count"]
        if not transition_policy["min_receiver_entry_delta"] <= receiver_entry_delta <= transition_policy["max_receiver_entry_delta"]:
            _deny(violations, "ARA013", "receiver entry delta is outside policy", actual=receiver_entry_delta)
        trust_entry_delta = head["entry_count"] - previous["head"]["entry_count"]
        if not transition_policy["min_trust_entry_delta"] <= trust_entry_delta <= transition_policy["max_trust_entry_delta"]:
            _deny(violations, "ARA014", "trust entry delta is outside policy", actual=trust_entry_delta)
        generation_delta = head["generation"] - previous["head"]["generation"]
        if not transition_policy["min_generation_delta"] <= generation_delta <= transition_policy["max_generation_delta"]:
            _deny(violations, "ARA014", "generation delta is outside policy", actual=generation_delta)
        if not _allowed(previous["state_id"], transition_policy["allowed_previous_receiver_state_ids"]):
            _deny(violations, "ARA015", "previous receiver state ID is not allowed", state_id=previous["state_id"])
        if not _allowed(previous["checkpoint_id"], transition_policy["allowed_previous_receiver_checkpoint_ids"]):
            _deny(violations, "ARA015", "previous receiver checkpoint ID is not allowed", checkpoint_id=previous["checkpoint_id"])
        if transition_policy["require_single_step"] and receiver_entry_delta != 1:
            _deny(violations, "ARA016", "receiver transition must append exactly one entry", actual=receiver_entry_delta)

    policy_hash = policy_sha256(normalized_policy)
    identity = {
        "bundle_id": verified["bundle_id"],
        "bundle_type": verified["bundle_type"],
        "candidate_receiver_checkpoint_id": candidate["checkpoint_id"],
        "candidate_receiver_state_id": candidate["state_id"],
        "previous_receiver_checkpoint_id": previous["checkpoint_id"] if previous else None,
        "previous_receiver_state_id": previous["state_id"] if previous else None,
    }
    evidence = {
        "files": verified["files"],
        "bytes": verified["bytes"],
        "proof_count": verified["proof_count"],
        "selected_sequences": sequences,
        "selected_handoff_ids": handoff_ids,
        "candidate_receiver_entries": candidate["entry_count"],
        "candidate_trust_entries": head["entry_count"],
        "candidate_generation": head["generation"],
        "candidate_segment_count": head["segment_count"],
        "head_handoff_bundle_id": verified["head_handoff_bundle_id"],
        "receiver_entry_delta": receiver_entry_delta,
        "trust_entry_delta": trust_entry_delta,
        "generation_delta": generation_delta,
    }
    core = {
        "admitted": not violations,
        "policy_sha256": policy_hash,
        "identity": identity,
        "evidence": evidence,
        "violations": violations,
    }
    return {**core, "decision_id": _decision_id(core)}


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    stream = stream or sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
        return
    for key in ("valid", "created", "admitted", "policy_sha256", "decision_id", "rule_id", "error"):
        if key in payload:
            print(f"{key}: {payload[key]}", file=stream)
    for violation in payload.get("violations", []):
        print(f"{violation['rule_id']}: {violation['message']}", file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("policy", type=Path)
    init.add_argument("--format", choices=("json", "text"), default="json")
    validate = commands.add_parser("validate")
    validate.add_argument("policy", type=Path)
    validate.add_argument("--format", choices=("json", "text"), default="json")
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("bundle", type=Path)
    evaluate.add_argument("--policy", type=Path, required=True)
    evaluate.add_argument("--expected-bundle-id", required=True)
    evaluate.add_argument("--expected-candidate-checkpoint-id", required=True)
    evaluate.add_argument("--expected-previous-checkpoint-id")
    evaluate.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            policy = default_policy()
            _write_new(args.policy, policy)
            report = {"valid": True, "created": True, "policy_sha256": policy_sha256(policy)}
        elif args.command == "validate":
            policy = load_policy(args.policy)
            report = {"valid": True, "policy_sha256": policy_sha256(policy)}
        else:
            _policy_outside_bundle(args.policy, args.bundle)
            policy = load_policy(args.policy)
            report = evaluate_bundle(
                args.bundle,
                policy,
                expected_bundle_id=args.expected_bundle_id,
                expected_candidate_checkpoint_id=args.expected_candidate_checkpoint_id,
                expected_previous_checkpoint_id=args.expected_previous_checkpoint_id,
            )
        _emit(report, args.format)
        if args.command == "evaluate" and not report["admitted"]:
            return 1
        return 0
    except AuditTrustReceiverAdmissionError as exc:
        _emit({"valid": False, "rule_id": exc.rule_id, "error": str(exc)}, args.format, stream=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
