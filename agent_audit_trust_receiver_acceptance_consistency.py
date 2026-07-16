#!/usr/bin/env python3
"""Create and verify compact append-only proofs between acceptance checkpoints."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import agent_audit_trust_receiver_acceptance as acceptance
import agent_audit_trust_receiver_acceptance_checkpoint as checkpoint

RULE_PREFIX = "ASR"
PROOF_DOMAIN = b"audit-trust-receiver-acceptance-consistency-proof-v1"
DECISION_DOMAIN = b"audit-trust-receiver-acceptance-consistency-decision-v1"


class AuditTrustReceiverAcceptanceConsistencyError(ValueError):
    """Raised when acceptance consistency evidence cannot be processed safely."""

    def __init__(self, message: str, *, rule_id: str = "ASR002", denied: bool = False) -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and rule_id.startswith("ARR") and len(rule_id) == 6:
            rule_id = RULE_PREFIX + rule_id[3:]
        if isinstance(rule_id, str) and rule_id.startswith("ATK") and len(rule_id) == 6:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id
        self.denied = denied


class AuditTrustReceiverAcceptanceConsistencyDenied(
    AuditTrustReceiverAcceptanceConsistencyError
):
    """Raised when valid acceptance states are related by rollback or fork."""

    def __init__(self, report: dict[str, Any]) -> None:
        violation = report["violations"][0]
        super().__init__(violation["message"], rule_id=violation["rule_id"], denied=True)
        self.report = report


def _load_isolated_core() -> ModuleType:
    source = Path(__file__).with_name("agent_audit_trust_receiver_consistency.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_acceptance_consistency_adapter", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "unable to load reviewed receiver-consistency engine", rule_id="ASR001"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _identifier(domain: bytes, payload: dict[str, Any]) -> str:
    mapped = {
        b"audit-trust-consistency-proof-v1": PROOF_DOMAIN,
        b"audit-trust-consistency-decision-v1": DECISION_DOMAIN,
        b"audit-trust-receiver-consistency-proof-v1": PROOF_DOMAIN,
        b"audit-trust-receiver-consistency-decision-v1": DECISION_DOMAIN,
    }.get(domain, domain)
    return hashlib.sha256(mapped + b"\x00" + acceptance.canonical_json(payload)).hexdigest()


def _denial_report(
    relation_report: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    relation = relation_report["relation"]
    violation = {
        "rule_id": "ASR009" if relation == "rollback" else "ASR010",
        "message": (
            "candidate acceptance state is an older prefix of the retained state"
            if relation == "rollback"
            else "candidate acceptance state diverges from the retained history"
        ),
    }
    core = {
        "consistency_version": _engine.CONSISTENCY_VERSION,
        "accepted": False,
        "relation": relation,
        "previous": _engine._checkpoint_reference(previous_checkpoint),
        "candidate": _engine._checkpoint_reference(candidate_checkpoint),
        "common": relation_report["common"],
        "violations": [violation],
    }
    return {**core, "decision_id": _identifier(DECISION_DOMAIN, core)}


def _validate_boundary(
    value: Any,
    relation: str,
    previous: dict[str, Any],
    candidate: dict[str, Any],
    append_frontier: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if relation == "same":
        if value is not None or append_frontier:
            raise AuditTrustReceiverAcceptanceConsistencyError(
                "same-state proof must not contain append evidence", rule_id="ASR005"
            )
        return None
    if value is None:
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "descendant proof is missing its first appended acceptance entry",
            rule_id="ASR011",
        )
    try:
        entry = checkpoint._core._entry(value)
    except checkpoint.AuditTrustReceiverAcceptanceCheckpointError as exc:
        raise AuditTrustReceiverAcceptanceConsistencyError(
            f"boundary acceptance entry is invalid: {exc}", rule_id="ASR011"
        ) from exc
    expected_sequence = previous["entry_count"] + 1
    if entry["sequence"] != expected_sequence or entry["kind"] != "transition":
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "boundary acceptance entry sequence or kind is inconsistent",
            rule_id="ASR011",
        )
    if entry["previous_entry_hash"] != previous["head"]["entry_hash"]:
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "boundary acceptance entry does not retain the previous head hash",
            rule_id="ASR011",
        )
    transition = entry["transition"]
    previous_head = previous["head"]
    if (
        transition["previous_checkpoint_id"] != previous_head["checkpoint_id"]
        or transition["previous_state_id"] != previous_head["state_id"]
    ):
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "boundary acceptance entry does not retain previous receiver checkpoint/state",
            rule_id="ASR011",
        )
    entry_delta = entry["evidence"]["entry_count"] - previous_head["entry_count"]
    trust_entry_delta = (
        entry["evidence"]["trust_entry_count"] - previous_head["trust_entry_count"]
    )
    generation_delta = entry["evidence"]["generation"] - previous_head["generation"]
    if entry_delta < 1 or transition["entry_delta"] != entry_delta:
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "boundary receiver entry-count transition is inconsistent", rule_id="ASR011"
        )
    if trust_entry_delta < 1 or transition["trust_entry_delta"] != trust_entry_delta:
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "boundary trust entry-count transition is inconsistent", rule_id="ASR011"
        )
    if generation_delta < 1 or transition["generation_delta"] != generation_delta:
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "boundary generation transition is inconsistent", rule_id="ASR011"
        )
    if not append_frontier or append_frontier[0]["start"] != previous["entry_count"]:
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "append frontier does not begin at the acceptance boundary", rule_id="ASR005"
        )
    if (
        append_frontier[0]["size"] != 1
        or append_frontier[0]["hash"] != checkpoint._core._leaf_hash(entry).hex()
    ):
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "boundary acceptance entry is not authenticated by the append frontier",
            rule_id="ASR011",
        )
    candidate_head = candidate["head"]
    if (
        candidate_head["entry_count"] <= previous_head["entry_count"]
        or candidate_head["trust_entry_count"] <= previous_head["trust_entry_count"]
        or candidate_head["generation"] <= previous_head["generation"]
        or candidate_head["segment_count"] < previous_head["segment_count"]
    ):
        raise AuditTrustReceiverAcceptanceConsistencyError(
            "candidate acceptance checkpoint head does not advance trusted evidence",
            rule_id="ASR011",
        )
    return entry


# The receiver adapter itself wraps the generic compact-range engine. Bind the
# nested engine directly so executable function globals use acceptance schemas.
_adapter = _load_isolated_core()
_engine = _adapter._core
_engine.__doc__ = __doc__
_engine.AuditBundleTrustError = acceptance.AuditTrustReceiverAcceptanceError
_engine.AuditTrustCheckpointError = checkpoint.AuditTrustReceiverAcceptanceCheckpointError
_engine.AuditTrustConsistencyError = AuditTrustReceiverAcceptanceConsistencyError
_engine.AuditTrustConsistencyDenied = AuditTrustReceiverAcceptanceConsistencyDenied
_engine.canonical_json = acceptance.canonical_json
_engine.load_state = acceptance.load_state
_engine.validate_state = acceptance.validate_state
_engine.MERKLE_ALGORITHM = checkpoint.MERKLE_ALGORITHM
_engine._entry = checkpoint._core._entry
_engine._head = checkpoint._head
_engine._leaf_hash = checkpoint._core._leaf_hash
_engine._merkle_root = checkpoint._core._merkle_root
_engine._node_hash = checkpoint._core._node_hash
_engine.checkpoint_matches_state = checkpoint.checkpoint_matches_state
_engine.lineage = checkpoint.lineage
_engine.load_checkpoint = checkpoint.load_checkpoint
_engine.validate_checkpoint = checkpoint.validate_checkpoint
_engine._identifier = _identifier
_engine._denial_report = _denial_report
_engine._validate_boundary = _validate_boundary

CONSISTENCY_VERSION = _engine.CONSISTENCY_VERSION
CONSISTENCY_ALGORITHM = _engine.CONSISTENCY_ALGORITHM
MAX_CONSISTENCY_BYTES = _engine.MAX_CONSISTENCY_BYTES
MAX_FRONTIER_SEGMENTS = _engine.MAX_FRONTIER_SEGMENTS
CONSISTENCY_FIELDS = _engine.CONSISTENCY_FIELDS
CHECKPOINT_REFERENCE_FIELDS = _engine.CHECKPOINT_REFERENCE_FIELDS
FRONTIER_FIELDS = _engine.FRONTIER_FIELDS

range_layout = _engine.range_layout
append_layout = _engine.append_layout
create_consistency_proof = _engine.create_consistency_proof
validate_consistency_proof = _engine.validate_consistency_proof
proof_matches_checkpoints = _engine.proof_matches_checkpoints
load_consistency_proof = _engine.load_consistency_proof
_write_new = _engine._write_new
main = _engine.main


if __name__ == "__main__":
    raise SystemExit(main())
