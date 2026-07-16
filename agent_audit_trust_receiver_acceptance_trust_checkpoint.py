#!/usr/bin/env python3
"""Create and verify portable Merkle checkpoints for receiver-acceptance trust states."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import agent_audit_trust_receiver_acceptance_trust as acceptance_trust
from agent_audit_trust_receiver_acceptance_bundle import (
    AuditTrustReceiverAcceptanceBundleError,
    verify_bundle,
)

RULE_PREFIX = "ABP"
CHECKPOINT_DOMAIN = b"audit-trust-receiver-acceptance-trust-checkpoint-v1"
PROOF_DOMAIN = b"audit-trust-receiver-acceptance-trust-inclusion-proof-v1"
LINEAGE_DOMAIN = b"audit-trust-receiver-acceptance-trust-lineage-v1"


class AuditTrustReceiverAcceptanceTrustCheckpointError(ValueError):
    """Raised when acceptance-trust checkpoints, proofs, lineage, or pins are invalid."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "ABP002",
        denied: bool = False,
    ) -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and rule_id.startswith("ARC") and len(rule_id) == 6:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id
        self.denied = denied


def _load_isolated_core() -> ModuleType:
    source = Path(__file__).with_name("agent_audit_trust_receiver_checkpoint.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_acceptance_trust_checkpoint_core", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceTrustCheckpointError(
            "unable to load reviewed receiver-checkpoint engine", rule_id="ABP001"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_core = _load_isolated_core()
canonical_json = acceptance_trust.canonical_json


def _checkpoint_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(CHECKPOINT_DOMAIN + b"\x00" + canonical_json(payload)).hexdigest()


def _proof_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(PROOF_DOMAIN + b"\x00" + canonical_json(payload)).hexdigest()


def _lineage_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(LINEAGE_DOMAIN + b"\x00" + canonical_json(payload)).hexdigest()


def _head(value: Any) -> dict[str, Any]:
    raw = _core._exact(value, acceptance_trust.HEAD_FIELDS, "acceptance trust checkpoint head")
    normalized = {
        "sequence": _core._integer(raw["sequence"], "acceptance trust head sequence", 1),
        "entry_hash": _core._hash(raw["entry_hash"], "acceptance trust head entry hash"),
        "handoff_bundle_id": _core._hash(
            raw["handoff_bundle_id"], "acceptance trust head bundle id"
        ),
        "checkpoint_id": _core._hash(
            raw["checkpoint_id"], "acceptance trust head acceptance checkpoint id"
        ),
        "state_id": _core._hash(raw["state_id"], "acceptance trust head acceptance state id"),
        "entry_count": _core._integer(
            raw["entry_count"], "acceptance trust head acceptance entry count", 1
        ),
        "head_receiver_bundle_id": _core._hash(
            raw["head_receiver_bundle_id"], "acceptance trust head receiver bundle id"
        ),
        "receiver_checkpoint_id": _core._hash(
            raw["receiver_checkpoint_id"], "acceptance trust head receiver checkpoint id"
        ),
        "receiver_state_id": _core._hash(
            raw["receiver_state_id"], "acceptance trust head receiver state id"
        ),
        "receiver_entry_count": _core._integer(
            raw["receiver_entry_count"], "acceptance trust head receiver entry count", 1
        ),
        "trust_handoff_id": _core._hash(
            raw["trust_handoff_id"], "acceptance trust head trust handoff id"
        ),
        "generation": _core._integer(raw["generation"], "acceptance trust head generation", 1),
        "segment_count": _core._integer(
            raw["segment_count"], "acceptance trust head segment count", 1
        ),
        "trust_checkpoint_id": _core._hash(
            raw["trust_checkpoint_id"], "acceptance trust head trust checkpoint id"
        ),
        "trust_state_id": _core._hash(
            raw["trust_state_id"], "acceptance trust head trust state id"
        ),
        "trust_entry_count": _core._integer(
            raw["trust_entry_count"], "acceptance trust head trust entry count", 1
        ),
    }
    if normalized != raw:
        raise AuditTrustReceiverAcceptanceTrustCheckpointError(
            "acceptance trust checkpoint head is not canonical", rule_id="ABP002"
        )
    return normalized


# Bind the reviewed generic receiver-checkpoint engine to acceptance-trust semantics.
_core.__doc__ = __doc__
_core.AuditTrustReceiverCheckpointError = AuditTrustReceiverAcceptanceTrustCheckpointError
_core.AuditTrustReceiverError = acceptance_trust.AuditTrustReceiverAcceptanceTrustError
_core.AuditTrustBundleError = AuditTrustReceiverAcceptanceBundleError
_core.verify_bundle = verify_bundle
_core.ADMISSION_FIELDS = acceptance_trust.ADMISSION_FIELDS
_core.ENTRY_FIELDS = acceptance_trust.ENTRY_FIELDS
_core.ENTRY_VERSION = acceptance_trust.ENTRY_VERSION
_core.EVIDENCE_FIELDS = acceptance_trust.EVIDENCE_FIELDS
_core.HEAD_FIELDS = acceptance_trust.HEAD_FIELDS
_core.TRANSITION_FIELDS = acceptance_trust.TRANSITION_FIELDS
_core.ZERO_HASH = acceptance_trust.ZERO_HASH
_core.canonical_json = canonical_json
_core.load_state = acceptance_trust.load_state
_core.validate_state = acceptance_trust.validate_state
_core._admission = acceptance_trust._engine._admission
_core._entry_payload = acceptance_trust._engine._entry_payload
_core._evidence = acceptance_trust._evidence
_core._evidence_from_verified = acceptance_trust._evidence_from_verified
_core._identifier = acceptance_trust._identifier
_core.receiver_identifier = acceptance_trust._identifier
_core._transition = acceptance_trust._transition
_core._checkpoint_identifier = _checkpoint_identifier
_core._proof_identifier = _proof_identifier
_core._lineage_identifier = _lineage_identifier
_core._head = _head

_original_lineage = _core.lineage


def lineage(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    report = _original_lineage(left, right)
    core = {key: value for key, value in report.items() if key != "lineage_id"}
    violations: list[dict[str, Any]] = []
    for violation in core.get("violations", []):
        normalized = dict(violation)
        rule_id = normalized.get("rule_id")
        if isinstance(rule_id, str) and rule_id.startswith("ARC") and len(rule_id) == 6:
            normalized["rule_id"] = RULE_PREFIX + rule_id[3:]
        violations.append(normalized)
    core["violations"] = violations
    return {**core, "lineage_id": _lineage_identifier(core)}


_core.lineage = lineage

CHECKPOINT_VERSION = _core.CHECKPOINT_VERSION
PROOF_VERSION = _core.PROOF_VERSION
LINEAGE_VERSION = _core.LINEAGE_VERSION
MERKLE_ALGORITHM = _core.MERKLE_ALGORITHM
MAX_CHECKPOINT_BYTES = _core.MAX_CHECKPOINT_BYTES
MAX_PROOF_BYTES = _core.MAX_PROOF_BYTES

create_checkpoint = _core.create_checkpoint
validate_checkpoint = _core.validate_checkpoint
checkpoint_matches_state = _core.checkpoint_matches_state
create_proof = _core.create_proof
validate_proof = _core.validate_proof
proof_matches_checkpoint = _core.proof_matches_checkpoint
proof_matches_handoff = _core.proof_matches_handoff
load_checkpoint = _core.load_checkpoint
load_proof = _core.load_proof
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
