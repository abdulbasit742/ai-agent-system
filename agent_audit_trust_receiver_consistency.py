#!/usr/bin/env python3
"""Create and verify compact append-only proofs between receiver checkpoints."""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from agent_audit_trust_receiver import (
    AuditTrustReceiverError,
    canonical_json,
    load_state,
    validate_state,
)
from agent_audit_trust_receiver_checkpoint import (
    AuditTrustReceiverCheckpointError,
    MERKLE_ALGORITHM,
    _entry,
    _head,
    _leaf_hash,
    _merkle_root,
    _node_hash,
    checkpoint_matches_state,
    lineage,
    load_checkpoint,
    validate_checkpoint,
)


RULE_PREFIX = "ARR"
PROOF_DOMAIN = b"audit-trust-receiver-consistency-proof-v1"
DECISION_DOMAIN = b"audit-trust-receiver-consistency-decision-v1"


class AuditTrustReceiverConsistencyError(ValueError):
    """Raised when receiver consistency evidence cannot be processed safely."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "ARR002",
        denied: bool = False,
    ) -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and rule_id.startswith("ATK") and len(rule_id) == 6:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id
        self.denied = denied


class AuditTrustReceiverConsistencyDenied(AuditTrustReceiverConsistencyError):
    """Raised when valid receiver states are related by rollback or fork."""

    def __init__(self, report: dict[str, Any]) -> None:
        violation = report["violations"][0]
        super().__init__(
            violation["message"],
            rule_id=violation["rule_id"],
            denied=True,
        )
        self.report = report


def _load_isolated_core() -> ModuleType:
    """Load the reviewed compact-range engine without mutating its public module."""
    source = Path(__file__).with_name("agent_audit_trust_consistency.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_consistency_core", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverConsistencyError(
            "unable to load the reviewed compact-range engine", rule_id="ARR001"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _identifier(domain: bytes, payload: dict[str, Any]) -> str:
    mapped = {
        b"audit-trust-consistency-proof-v1": PROOF_DOMAIN,
        b"audit-trust-consistency-decision-v1": DECISION_DOMAIN,
    }.get(domain, domain)
    return hashlib.sha256(mapped + b"\x00" + canonical_json(payload)).hexdigest()


def _denial_report(
    relation_report: dict[str, Any],
    previous_checkpoint: dict[str, Any],
    candidate_checkpoint: dict[str, Any],
) -> dict[str, Any]:
    relation = relation_report["relation"]
    if relation == "rollback":
        violation = {
            "rule_id": "ARR009",
            "message": "candidate receiver state is an older prefix of the retained state",
        }
    else:
        violation = {
            "rule_id": "ARR010",
            "message": "candidate receiver state diverges from the retained history",
        }
    core = {
        "consistency_version": _core.CONSISTENCY_VERSION,
        "accepted": False,
        "relation": relation,
        "previous": _core._checkpoint_reference(previous_checkpoint),
        "candidate": _core._checkpoint_reference(candidate_checkpoint),
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
            raise AuditTrustReceiverConsistencyError(
                "same-state proof must not contain append evidence", rule_id="ARR005"
            )
        return None
    if value is None:
        raise AuditTrustReceiverConsistencyError(
            "descendant proof is missing its first appended receiver entry",
            rule_id="ARR011",
        )
    try:
        entry = _entry(value)
    except AuditTrustReceiverCheckpointError as exc:
        raise AuditTrustReceiverConsistencyError(
            f"boundary receiver entry is invalid: {exc}", rule_id="ARR011"
        ) from exc
    expected_sequence = previous["entry_count"] + 1
    if entry["sequence"] != expected_sequence or entry["kind"] != "transition":
        raise AuditTrustReceiverConsistencyError(
            "boundary receiver entry sequence or kind is inconsistent",
            rule_id="ARR011",
        )
    if entry["previous_entry_hash"] != previous["head"]["entry_hash"]:
        raise AuditTrustReceiverConsistencyError(
            "boundary receiver entry does not retain the previous head hash",
            rule_id="ARR011",
        )
    transition = entry["transition"]
    if (
        transition["previous_checkpoint_id"] != previous["head"]["checkpoint_id"]
        or transition["previous_state_id"] != previous["head"]["state_id"]
    ):
        raise AuditTrustReceiverConsistencyError(
            "boundary receiver entry does not retain previous trust checkpoint/state evidence",
            rule_id="ARR011",
        )
    entry_delta = entry["evidence"]["entry_count"] - previous["head"]["entry_count"]
    generation_delta = entry["evidence"]["generation"] - previous["head"]["generation"]
    if entry_delta < 1 or transition["entry_delta"] != entry_delta:
        raise AuditTrustReceiverConsistencyError(
            "boundary receiver entry-count transition is inconsistent",
            rule_id="ARR011",
        )
    if generation_delta < 1 or transition["generation_delta"] != generation_delta:
        raise AuditTrustReceiverConsistencyError(
            "boundary receiver generation transition is inconsistent",
            rule_id="ARR011",
        )
    if not append_frontier or append_frontier[0]["start"] != previous["entry_count"]:
        raise AuditTrustReceiverConsistencyError(
            "append frontier does not begin at the receiver boundary", rule_id="ARR005"
        )
    if (
        append_frontier[0]["size"] != 1
        or append_frontier[0]["hash"] != _leaf_hash(entry).hex()
    ):
        raise AuditTrustReceiverConsistencyError(
            "boundary receiver entry is not authenticated by the append frontier",
            rule_id="ARR011",
        )
    previous_head = previous["head"]
    candidate_head = candidate["head"]
    if (
        candidate_head["entry_count"] <= previous_head["entry_count"]
        or candidate_head["generation"] <= previous_head["generation"]
        or candidate_head["segment_count"] < previous_head["segment_count"]
    ):
        raise AuditTrustReceiverConsistencyError(
            "candidate receiver checkpoint head does not advance trusted evidence",
            rule_id="ARR011",
        )
    return entry


_core = _load_isolated_core()
_core.__doc__ = __doc__
_core.AuditBundleTrustError = AuditTrustReceiverError
_core.AuditTrustCheckpointError = AuditTrustReceiverCheckpointError
_core.AuditTrustConsistencyError = AuditTrustReceiverConsistencyError
_core.AuditTrustConsistencyDenied = AuditTrustReceiverConsistencyDenied
_core.canonical_json = canonical_json
_core.load_state = load_state
_core.validate_state = validate_state
_core.MERKLE_ALGORITHM = MERKLE_ALGORITHM
_core._entry = _entry
_core._head = _head
_core._leaf_hash = _leaf_hash
_core._merkle_root = _merkle_root
_core._node_hash = _node_hash
_core.checkpoint_matches_state = checkpoint_matches_state
_core.lineage = lineage
_core.load_checkpoint = load_checkpoint
_core.validate_checkpoint = validate_checkpoint
_core._identifier = _identifier
_core._denial_report = _denial_report
_core._validate_boundary = _validate_boundary

CONSISTENCY_VERSION = _core.CONSISTENCY_VERSION
CONSISTENCY_ALGORITHM = _core.CONSISTENCY_ALGORITHM
MAX_CONSISTENCY_BYTES = _core.MAX_CONSISTENCY_BYTES
MAX_FRONTIER_SEGMENTS = _core.MAX_FRONTIER_SEGMENTS
CONSISTENCY_FIELDS = _core.CONSISTENCY_FIELDS
CHECKPOINT_REFERENCE_FIELDS = _core.CHECKPOINT_REFERENCE_FIELDS
FRONTIER_FIELDS = _core.FRONTIER_FIELDS

range_layout = _core.range_layout
append_layout = _core.append_layout
create_consistency_proof = _core.create_consistency_proof
validate_consistency_proof = _core.validate_consistency_proof
proof_matches_checkpoints = _core.proof_matches_checkpoints
load_consistency_proof = _core.load_consistency_proof
_write_new = _core._write_new
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
