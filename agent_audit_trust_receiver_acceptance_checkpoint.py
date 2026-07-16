#!/usr/bin/env python3
"""Create and verify portable Merkle checkpoints for receiver acceptance states."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import agent_audit_trust_receiver_acceptance as acceptance
from agent_audit_trust_receiver_bundle import (
    AuditTrustReceiverBundleError,
    verify_bundle,
)

RULE_PREFIX = "ASC"
CHECKPOINT_DOMAIN = b"audit-trust-receiver-acceptance-checkpoint-v1"
PROOF_DOMAIN = b"audit-trust-receiver-acceptance-inclusion-proof-v1"
LINEAGE_DOMAIN = b"audit-trust-receiver-acceptance-lineage-v1"


class AuditTrustReceiverAcceptanceCheckpointError(ValueError):
    """Raised when acceptance checkpoints, proofs, lineage, or pins are invalid."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "ASC002",
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
        "_agent_audit_trust_receiver_acceptance_checkpoint_core", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceCheckpointError(
            "unable to load reviewed receiver-checkpoint engine", rule_id="ASC001"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_core = _load_isolated_core()
canonical_json = acceptance.canonical_json


def _checkpoint_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(CHECKPOINT_DOMAIN + b"\x00" + canonical_json(payload)).hexdigest()


def _proof_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(PROOF_DOMAIN + b"\x00" + canonical_json(payload)).hexdigest()


def _lineage_identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(LINEAGE_DOMAIN + b"\x00" + canonical_json(payload)).hexdigest()


def _head(value: Any) -> dict[str, Any]:
    raw = _core._exact(value, acceptance.HEAD_FIELDS, "acceptance checkpoint head")
    normalized = {
        "sequence": _core._integer(raw["sequence"], "acceptance head sequence", 1),
        "entry_hash": _core._hash(raw["entry_hash"], "acceptance head entry hash"),
        "handoff_bundle_id": _core._hash(
            raw["handoff_bundle_id"], "acceptance head receiver bundle id"
        ),
        "checkpoint_id": _core._hash(
            raw["checkpoint_id"], "acceptance head receiver checkpoint id"
        ),
        "state_id": _core._hash(raw["state_id"], "acceptance head receiver state id"),
        "entry_count": _core._integer(
            raw["entry_count"], "acceptance head receiver entry count", 1
        ),
        "head_bundle_id": _core._hash(
            raw["head_bundle_id"], "acceptance head accepted handoff id"
        ),
        "generation": _core._integer(raw["generation"], "acceptance head generation", 1),
        "segment_count": _core._integer(
            raw["segment_count"], "acceptance head segment count", 1
        ),
        "trust_checkpoint_id": _core._hash(
            raw["trust_checkpoint_id"], "acceptance head trust checkpoint id"
        ),
        "trust_state_id": _core._hash(
            raw["trust_state_id"], "acceptance head trust state id"
        ),
        "trust_entry_count": _core._integer(
            raw["trust_entry_count"], "acceptance head trust entry count", 1
        ),
    }
    if normalized != raw:
        raise AuditTrustReceiverAcceptanceCheckpointError(
            "acceptance checkpoint head is not canonical", rule_id="ASC002"
        )
    return normalized


# Bind the reviewed generic receiver-checkpoint engine to acceptance-state semantics.
_core.__doc__ = __doc__
_core.AuditTrustReceiverCheckpointError = AuditTrustReceiverAcceptanceCheckpointError
_core.AuditTrustReceiverError = acceptance.AuditTrustReceiverAcceptanceError
_core.AuditTrustBundleError = AuditTrustReceiverBundleError
_core.verify_bundle = verify_bundle
_core.ADMISSION_FIELDS = acceptance.ADMISSION_FIELDS
_core.ENTRY_FIELDS = acceptance.ENTRY_FIELDS
_core.ENTRY_VERSION = acceptance.ENTRY_VERSION
_core.EVIDENCE_FIELDS = acceptance.EVIDENCE_FIELDS
_core.HEAD_FIELDS = acceptance.HEAD_FIELDS
_core.TRANSITION_FIELDS = acceptance.TRANSITION_FIELDS
_core.ZERO_HASH = acceptance.ZERO_HASH
_core.canonical_json = canonical_json
_core.load_state = acceptance.load_state
_core.validate_state = acceptance.validate_state
_core._admission = acceptance._core._admission
_core._entry_payload = acceptance._core._entry_payload
_core._evidence = acceptance._evidence
_core._evidence_from_verified = acceptance._evidence_from_verified
_core._identifier = acceptance._identifier
_core.receiver_identifier = acceptance._identifier
_core._transition = acceptance._transition
_core._checkpoint_identifier = _checkpoint_identifier
_core._proof_identifier = _proof_identifier
_core._lineage_identifier = _lineage_identifier
_core._head = _head

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
lineage = _core.lineage
load_checkpoint = _core.load_checkpoint
load_proof = _core.load_proof
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
