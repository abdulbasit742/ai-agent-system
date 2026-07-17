#!/usr/bin/env python3
"""Create and verify compact append-only proofs between acceptance-trust checkpoints."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import agent_audit_trust_receiver_acceptance_trust as acceptance_trust
import agent_audit_trust_receiver_acceptance_trust_checkpoint as checkpoint

RULE_PREFIX = "ABR"
PROOF_DOMAIN = b"audit-trust-receiver-acceptance-trust-consistency-proof-v1"
DECISION_DOMAIN = b"audit-trust-receiver-acceptance-trust-consistency-decision-v1"


class AuditTrustReceiverAcceptanceTrustConsistencyError(ValueError):
    """Raised when acceptance-trust consistency evidence cannot be processed safely."""

    def __init__(self, message: str, *, rule_id: str = "ABR002", denied: bool = False) -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and len(rule_id) == 6 and rule_id[:3] in {
            "ASR", "ARR", "ATK"
        }:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id
        self.denied = denied


class AuditTrustReceiverAcceptanceTrustConsistencyDenied(
    AuditTrustReceiverAcceptanceTrustConsistencyError
):
    """Raised when valid acceptance-trust states are related by rollback or fork."""

    def __init__(self, report: dict[str, Any]) -> None:
        violation = report["violations"][0]
        super().__init__(violation["message"], rule_id=violation["rule_id"], denied=True)
        self.report = report


def _load_isolated_core() -> ModuleType:
    source = Path(__file__).with_name("agent_audit_trust_receiver_acceptance_consistency.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_acceptance_trust_consistency_adapter", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            "unable to load reviewed acceptance-consistency engine", rule_id="ABR001"
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
        b"audit-trust-receiver-acceptance-consistency-proof-v1": PROOF_DOMAIN,
        b"audit-trust-receiver-acceptance-consistency-decision-v1": DECISION_DOMAIN,
    }.get(domain, domain)
    return hashlib.sha256(
        mapped + b"\x00" + acceptance_trust.canonical_json(payload)
    ).hexdigest()


def _denial_report(
    relation_report: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    relation = relation_report["relation"]
    violation = {
        "rule_id": "ABR009" if relation == "rollback" else "ABR010",
        "message": (
            "candidate acceptance-trust state is an older prefix of the retained state"
            if relation == "rollback"
            else "candidate acceptance-trust state diverges from the retained history"
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
            raise AuditTrustReceiverAcceptanceTrustConsistencyError(
                "same-state proof must not contain append evidence", rule_id="ABR005"
            )
        return None
    if value is None:
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            "descendant proof is missing its first appended acceptance-trust entry",
            rule_id="ABR011",
        )
    try:
        entry = checkpoint._core._entry(value)
    except checkpoint.AuditTrustReceiverAcceptanceTrustCheckpointError as exc:
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            f"boundary acceptance-trust entry is invalid: {exc}", rule_id="ABR011"
        ) from exc
    expected_sequence = previous["entry_count"] + 1
    if entry["sequence"] != expected_sequence or entry["kind"] != "transition":
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            "boundary acceptance-trust entry sequence or kind is inconsistent",
            rule_id="ABR011",
        )
    if entry["previous_entry_hash"] != previous["head"]["entry_hash"]:
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            "boundary acceptance-trust entry does not retain the previous head hash",
            rule_id="ABR011",
        )
    transition = entry["transition"]
    previous_head = previous["head"]
    if (
        transition["previous_checkpoint_id"] != previous_head["checkpoint_id"]
        or transition["previous_state_id"] != previous_head["state_id"]
    ):
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            "boundary acceptance-trust entry does not retain previous acceptance checkpoint/state",
            rule_id="ABR011",
        )
    evidence = entry["evidence"]
    expected_deltas = {
        "acceptance_entry_delta": evidence["entry_count"] - previous_head["entry_count"],
        "receiver_entry_delta": (
            evidence["receiver_entry_count"] - previous_head["receiver_entry_count"]
        ),
        "trust_entry_delta": (
            evidence["trust_entry_count"] - previous_head["trust_entry_count"]
        ),
        "generation_delta": evidence["generation"] - previous_head["generation"],
        "segment_delta": evidence["segment_count"] - previous_head["segment_count"],
    }
    for key, delta in expected_deltas.items():
        minimum = 0 if key == "segment_delta" else 1
        if delta < minimum or transition[key] != delta:
            raise AuditTrustReceiverAcceptanceTrustConsistencyError(
                f"boundary acceptance-trust {key.replace('_', ' ')} is inconsistent",
                rule_id="ABR011",
            )
    if not append_frontier or append_frontier[0]["start"] != previous["entry_count"]:
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            "append frontier does not begin at the acceptance-trust boundary",
            rule_id="ABR005",
        )
    if (
        append_frontier[0]["size"] != 1
        or append_frontier[0]["hash"] != checkpoint._core._leaf_hash(entry).hex()
    ):
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            "boundary acceptance-trust entry is not authenticated by the append frontier",
            rule_id="ABR011",
        )
    candidate_head = candidate["head"]
    if (
        candidate_head["entry_count"] <= previous_head["entry_count"]
        or candidate_head["receiver_entry_count"] <= previous_head["receiver_entry_count"]
        or candidate_head["trust_entry_count"] <= previous_head["trust_entry_count"]
        or candidate_head["generation"] <= previous_head["generation"]
        or candidate_head["segment_count"] < previous_head["segment_count"]
    ):
        raise AuditTrustReceiverAcceptanceTrustConsistencyError(
            "candidate acceptance-trust checkpoint head does not advance nested evidence",
            rule_id="ABR011",
        )
    return entry


_adapter = _load_isolated_core()
_engine = _adapter._engine
_engine.__doc__ = __doc__
_engine.AuditBundleTrustError = acceptance_trust.AuditTrustReceiverAcceptanceTrustError
_engine.AuditTrustCheckpointError = (
    checkpoint.AuditTrustReceiverAcceptanceTrustCheckpointError
)
_engine.AuditTrustConsistencyError = AuditTrustReceiverAcceptanceTrustConsistencyError
_engine.AuditTrustConsistencyDenied = AuditTrustReceiverAcceptanceTrustConsistencyDenied
_engine.canonical_json = acceptance_trust.canonical_json
_engine.load_state = acceptance_trust.load_state
_engine.validate_state = acceptance_trust.validate_state
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
