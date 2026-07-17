#!/usr/bin/env python3
"""Maintain a pinned receiver state for admitted acceptance-trust handoff bundles."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from agent_audit_trust_receiver_acceptance_trust_admission import (
    AuditTrustReceiverAcceptanceTrustAdmissionError,
    evaluate_bundle,
    load_policy,
)
from agent_audit_trust_receiver_acceptance_trust_bundle import (
    AuditTrustReceiverAcceptanceTrustBundleError,
    verify_bundle,
)

RULE_PREFIX = "ABN"
ENTRY_DOMAIN = b"audit-trust-receiver-acceptance-trust-receiver-entry-v1"
STATE_DOMAIN = b"audit-trust-receiver-acceptance-trust-receiver-state-v1"

EVIDENCE_FIELDS = {
    "handoff_bundle_id",
    "checkpoint_id",
    "state_id",
    "entry_count",
    "merkle_root",
    "head_entry_hash",
    "head_acceptance_bundle_id",
    "acceptance_checkpoint_id",
    "acceptance_state_id",
    "acceptance_entry_count",
    "head_receiver_bundle_id",
    "receiver_checkpoint_id",
    "receiver_state_id",
    "receiver_entry_count",
    "trust_handoff_id",
    "trust_checkpoint_id",
    "trust_state_id",
    "trust_entry_count",
    "generation",
    "segment_count",
}
TRANSITION_FIELDS = {
    "previous_checkpoint_id",
    "previous_state_id",
    "acceptance_trust_entry_delta",
    "acceptance_entry_delta",
    "receiver_entry_delta",
    "trust_entry_delta",
    "generation_delta",
    "segment_delta",
}
HEAD_FIELDS = {
    "sequence",
    "entry_hash",
    "handoff_bundle_id",
    "checkpoint_id",
    "state_id",
    "entry_count",
    "merkle_root",
    "head_entry_hash",
    "head_acceptance_bundle_id",
    "acceptance_checkpoint_id",
    "acceptance_state_id",
    "acceptance_entry_count",
    "head_receiver_bundle_id",
    "receiver_checkpoint_id",
    "receiver_state_id",
    "receiver_entry_count",
    "trust_handoff_id",
    "trust_checkpoint_id",
    "trust_state_id",
    "trust_entry_count",
    "generation",
    "segment_count",
}


class AuditTrustReceiverAcceptanceTrustReceiverError(ValueError):
    """Raised when acceptance-trust receiver history or its inputs are unsafe."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "ABN002",
        denied: bool = False,
    ) -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and len(rule_id) == 6 and rule_id[:3] in {
            "ATR",
            "ARS",
            "ABT",
        }:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id
        self.denied = denied


def _load_isolated_core() -> ModuleType:
    source = Path(__file__).with_name("agent_audit_trust_receiver_acceptance_trust.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_acceptance_trust_receiver_core", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "unable to load reviewed acceptance-trust state engine",
            rule_id="ABN001",
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_adapter = _load_isolated_core()
_engine = _adapter._engine
canonical_json = _adapter.canonical_json
ZERO_HASH = _adapter.ZERO_HASH
STATE_VERSION = _adapter.STATE_VERSION
ENTRY_VERSION = _adapter.ENTRY_VERSION
STATE_FIELDS = _adapter.STATE_FIELDS
ENTRY_FIELDS = _adapter.ENTRY_FIELDS
ADMISSION_FIELDS = _adapter.ADMISSION_FIELDS
MAX_STATE_BYTES = _adapter.MAX_STATE_BYTES
MAX_ENTRIES = _adapter.MAX_ENTRIES


def _identifier(domain: bytes, payload: dict[str, Any]) -> str:
    mapped = {
        b"audit-trust-receiver-entry-v1": ENTRY_DOMAIN,
        b"audit-trust-receiver-state-v1": STATE_DOMAIN,
        getattr(_adapter, "ENTRY_DOMAIN", ENTRY_DOMAIN): ENTRY_DOMAIN,
        getattr(_adapter, "STATE_DOMAIN", STATE_DOMAIN): STATE_DOMAIN,
    }.get(domain, domain)
    return hashlib.sha256(mapped + b"\x00" + canonical_json(payload)).hexdigest()


def _evidence(value: Any) -> dict[str, Any]:
    raw = _engine._exact(value, EVIDENCE_FIELDS, "acceptance-trust receiver evidence")
    return {
        "handoff_bundle_id": _engine._hash(
            raw["handoff_bundle_id"], "acceptance-trust handoff bundle id"
        ),
        "checkpoint_id": _engine._hash(
            raw["checkpoint_id"], "acceptance-trust checkpoint id"
        ),
        "state_id": _engine._hash(raw["state_id"], "acceptance-trust state id"),
        "entry_count": _engine._integer(
            raw["entry_count"], "acceptance-trust entry count", 1
        ),
        "merkle_root": _engine._hash(
            raw["merkle_root"], "acceptance-trust Merkle root"
        ),
        "head_entry_hash": _engine._hash(
            raw["head_entry_hash"], "acceptance-trust head entry hash"
        ),
        "head_acceptance_bundle_id": _engine._hash(
            raw["head_acceptance_bundle_id"], "head acceptance bundle id"
        ),
        "acceptance_checkpoint_id": _engine._hash(
            raw["acceptance_checkpoint_id"], "acceptance checkpoint id"
        ),
        "acceptance_state_id": _engine._hash(
            raw["acceptance_state_id"], "acceptance state id"
        ),
        "acceptance_entry_count": _engine._integer(
            raw["acceptance_entry_count"], "acceptance entry count", 1
        ),
        "head_receiver_bundle_id": _engine._hash(
            raw["head_receiver_bundle_id"], "head receiver bundle id"
        ),
        "receiver_checkpoint_id": _engine._hash(
            raw["receiver_checkpoint_id"], "receiver checkpoint id"
        ),
        "receiver_state_id": _engine._hash(
            raw["receiver_state_id"], "receiver state id"
        ),
        "receiver_entry_count": _engine._integer(
            raw["receiver_entry_count"], "receiver entry count", 1
        ),
        "trust_handoff_id": _engine._hash(
            raw["trust_handoff_id"], "trust handoff id"
        ),
        "trust_checkpoint_id": _engine._hash(
            raw["trust_checkpoint_id"], "trust checkpoint id"
        ),
        "trust_state_id": _engine._hash(raw["trust_state_id"], "trust state id"),
        "trust_entry_count": _engine._integer(
            raw["trust_entry_count"], "trust entry count", 1
        ),
        "generation": _engine._integer(raw["generation"], "trusted generation", 1),
        "segment_count": _engine._integer(
            raw["segment_count"], "trusted segment count", 1
        ),
    }


def _transition(value: Any) -> dict[str, Any]:
    raw = _engine._exact(
        value, TRANSITION_FIELDS, "acceptance-trust receiver transition"
    )
    return {
        "previous_checkpoint_id": _engine._hash(
            raw["previous_checkpoint_id"],
            "previous acceptance-trust checkpoint id",
        ),
        "previous_state_id": _engine._hash(
            raw["previous_state_id"], "previous acceptance-trust state id"
        ),
        "acceptance_trust_entry_delta": _engine._integer(
            raw["acceptance_trust_entry_delta"],
            "acceptance-trust entry delta",
            1,
        ),
        "acceptance_entry_delta": _engine._integer(
            raw["acceptance_entry_delta"], "acceptance entry delta", 1
        ),
        "receiver_entry_delta": _engine._integer(
            raw["receiver_entry_delta"], "receiver entry delta", 1
        ),
        "trust_entry_delta": _engine._integer(
            raw["trust_entry_delta"], "trust entry delta", 1
        ),
        "generation_delta": _engine._integer(
            raw["generation_delta"], "generation delta", 1
        ),
        "segment_delta": _engine._integer(
            raw["segment_delta"], "segment delta", 0
        ),
    }


def _evidence_from_verified(verified: dict[str, Any]) -> dict[str, Any]:
    candidate = verified.get("candidate")
    if not isinstance(candidate, dict):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "verified acceptance-trust handoff candidate is malformed"
        )
    head = candidate.get("head")
    if not isinstance(head, dict):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "verified acceptance-trust checkpoint head is malformed"
        )
    return _evidence(
        {
            "handoff_bundle_id": verified.get("bundle_id"),
            "checkpoint_id": candidate.get("checkpoint_id"),
            "state_id": candidate.get("state_id"),
            "entry_count": candidate.get("entry_count"),
            "merkle_root": candidate.get("merkle_root"),
            "head_entry_hash": head.get("entry_hash"),
            "head_acceptance_bundle_id": head.get("handoff_bundle_id"),
            "acceptance_checkpoint_id": head.get("checkpoint_id"),
            "acceptance_state_id": head.get("state_id"),
            "acceptance_entry_count": head.get("entry_count"),
            "head_receiver_bundle_id": head.get("head_receiver_bundle_id"),
            "receiver_checkpoint_id": head.get("receiver_checkpoint_id"),
            "receiver_state_id": head.get("receiver_state_id"),
            "receiver_entry_count": head.get("receiver_entry_count"),
            "trust_handoff_id": head.get("trust_handoff_id"),
            "trust_checkpoint_id": head.get("trust_checkpoint_id"),
            "trust_state_id": head.get("trust_state_id"),
            "trust_entry_count": head.get("trust_entry_count"),
            "generation": head.get("generation"),
            "segment_count": head.get("segment_count"),
        }
    )


def _admission_from_report(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("admitted") is not True:
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "only an admitted acceptance-trust handoff can enter receiver history",
            rule_id="ABN004",
            denied=True,
        )
    return _engine._admission(
        {
            "decision_id": report.get("decision_id"),
            "policy_sha256": report.get("policy_sha256"),
        }
    )


def _report_matches_verified(report: dict[str, Any], verified: dict[str, Any]) -> None:
    identity = report.get("identity")
    details = report.get("evidence")
    candidate = verified.get("candidate")
    previous = verified.get("previous")
    if (
        not isinstance(identity, dict)
        or not isinstance(details, dict)
        or not isinstance(candidate, dict)
    ):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust admission report is malformed"
        )
    head = candidate.get("head")
    if not isinstance(head, dict):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "verified acceptance-trust checkpoint head is malformed"
        )
    expected_identity = {
        "bundle_id": verified.get("bundle_id"),
        "bundle_type": verified.get("bundle_type"),
        "candidate_acceptance_trust_checkpoint_id": candidate.get("checkpoint_id"),
        "candidate_acceptance_trust_state_id": candidate.get("state_id"),
        "previous_acceptance_trust_checkpoint_id": (
            previous.get("checkpoint_id") if isinstance(previous, dict) else None
        ),
        "previous_acceptance_trust_state_id": (
            previous.get("state_id") if isinstance(previous, dict) else None
        ),
    }
    if identity != expected_identity:
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "admission report differs from verified acceptance-trust handoff identity"
        )
    checks = {
        "candidate_acceptance_trust_entries": candidate.get("entry_count"),
        "candidate_acceptance_entries": head.get("entry_count"),
        "candidate_receiver_entries": head.get("receiver_entry_count"),
        "candidate_trust_entries": head.get("trust_entry_count"),
        "candidate_generation": head.get("generation"),
        "candidate_segment_count": head.get("segment_count"),
        "head_acceptance_bundle_id": head.get("handoff_bundle_id"),
        "head_receiver_bundle_id": head.get("head_receiver_bundle_id"),
        "head_trust_handoff_id": head.get("trust_handoff_id"),
    }
    for key, actual in checks.items():
        if details.get(key) != actual:
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                f"admission report {key} differs from verified acceptance-trust handoff"
            )


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
        "merkle_root": evidence["merkle_root"],
        "head_entry_hash": evidence["head_entry_hash"],
        "head_acceptance_bundle_id": evidence["head_acceptance_bundle_id"],
        "acceptance_checkpoint_id": evidence["acceptance_checkpoint_id"],
        "acceptance_state_id": evidence["acceptance_state_id"],
        "acceptance_entry_count": evidence["acceptance_entry_count"],
        "head_receiver_bundle_id": evidence["head_receiver_bundle_id"],
        "receiver_checkpoint_id": evidence["receiver_checkpoint_id"],
        "receiver_state_id": evidence["receiver_state_id"],
        "receiver_entry_count": evidence["receiver_entry_count"],
        "trust_handoff_id": evidence["trust_handoff_id"],
        "trust_checkpoint_id": evidence["trust_checkpoint_id"],
        "trust_state_id": evidence["trust_state_id"],
        "trust_entry_count": evidence["trust_entry_count"],
        "generation": evidence["generation"],
        "segment_count": evidence["segment_count"],
    }


def _state_payload(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {"state_version": STATE_VERSION, "entries": entries, "head": _head(entries)}


def _seal_entry(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "entry_hash": _identifier(ENTRY_DOMAIN, payload)}


def _seal_state(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "state_id": _identifier(STATE_DOMAIN, payload)}


def create_state(report: dict[str, Any], verified: dict[str, Any]) -> dict[str, Any]:
    if report.get("identity", {}).get("bundle_type") != "snapshot":
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust receiver anchor must be an admitted snapshot handoff",
            rule_id="ABN005",
        )
    _report_matches_verified(report, verified)
    evidence = _evidence_from_verified(verified)
    entry = _seal_entry(
        _engine._entry_payload(
            1,
            "anchor",
            ZERO_HASH,
            evidence,
            _admission_from_report(report),
            None,
        )
    )
    return _seal_state(_state_payload([entry]))


def _previous_matches_head(previous: dict[str, Any], head: dict[str, Any]) -> bool:
    previous_head = previous.get("head")
    return bool(
        previous.get("checkpoint_id") == head["checkpoint_id"]
        and previous.get("state_id") == head["state_id"]
        and previous.get("entry_count") == head["entry_count"]
        and previous.get("merkle_root") == head["merkle_root"]
        and isinstance(previous_head, dict)
        and previous_head.get("entry_hash") == head["head_entry_hash"]
        and previous_head.get("handoff_bundle_id") == head["head_acceptance_bundle_id"]
        and previous_head.get("checkpoint_id") == head["acceptance_checkpoint_id"]
        and previous_head.get("state_id") == head["acceptance_state_id"]
        and previous_head.get("entry_count") == head["acceptance_entry_count"]
        and previous_head.get("head_receiver_bundle_id")
        == head["head_receiver_bundle_id"]
        and previous_head.get("receiver_checkpoint_id")
        == head["receiver_checkpoint_id"]
        and previous_head.get("receiver_state_id") == head["receiver_state_id"]
        and previous_head.get("receiver_entry_count")
        == head["receiver_entry_count"]
        and previous_head.get("trust_handoff_id") == head["trust_handoff_id"]
        and previous_head.get("trust_checkpoint_id") == head["trust_checkpoint_id"]
        and previous_head.get("trust_state_id") == head["trust_state_id"]
        and previous_head.get("trust_entry_count") == head["trust_entry_count"]
        and previous_head.get("generation") == head["generation"]
        and previous_head.get("segment_count") == head["segment_count"]
    )


def append_transition(
    state: dict[str, Any],
    report: dict[str, Any],
    verified: dict[str, Any],
) -> dict[str, Any]:
    normalized = validate_state(state)
    identity = report.get("identity")
    details = report.get("evidence")
    if report.get("admitted") is not True:
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "candidate acceptance-trust handoff was denied by admission policy",
            rule_id="ABN004",
            denied=True,
        )
    if not isinstance(identity, dict) or identity.get("bundle_type") != "transition":
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust receiver advancement requires an admitted transition handoff",
            rule_id="ABN005",
        )
    if not isinstance(details, dict):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust admission evidence is malformed"
        )
    previous = verified.get("previous")
    if not isinstance(previous, dict):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust transition previous checkpoint is missing"
        )
    head = normalized["head"]
    if not _previous_matches_head(previous, head):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust transition does not start from the receiver-state head",
            rule_id="ABN006",
            denied=True,
        )
    _report_matches_verified(report, verified)
    evidence = _evidence_from_verified(verified)
    if (
        evidence["entry_count"] <= head["entry_count"]
        or evidence["acceptance_entry_count"] <= head["acceptance_entry_count"]
        or evidence["receiver_entry_count"] <= head["receiver_entry_count"]
        or evidence["trust_entry_count"] <= head["trust_entry_count"]
        or evidence["generation"] <= head["generation"]
        or evidence["segment_count"] < head["segment_count"]
    ):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "candidate acceptance-trust evidence does not advance receiver state",
            rule_id="ABN008",
            denied=True,
        )
    seen_bundles = {
        item["evidence"]["handoff_bundle_id"] for item in normalized["entries"]
    }
    seen_checkpoints = {
        item["evidence"]["checkpoint_id"] for item in normalized["entries"]
    }
    seen_states = {item["evidence"]["state_id"] for item in normalized["entries"]}
    if (
        evidence["handoff_bundle_id"] in seen_bundles
        or evidence["checkpoint_id"] in seen_checkpoints
        or evidence["state_id"] in seen_states
    ):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "candidate acceptance-trust identity already exists in receiver history",
            rule_id="ABN007",
            denied=True,
        )
    transition = _transition(
        {
            "previous_checkpoint_id": previous.get("checkpoint_id"),
            "previous_state_id": previous.get("state_id"),
            "acceptance_trust_entry_delta": details.get(
                "acceptance_trust_entry_delta"
            ),
            "acceptance_entry_delta": details.get("acceptance_entry_delta"),
            "receiver_entry_delta": details.get("receiver_entry_delta"),
            "trust_entry_delta": details.get("trust_entry_delta"),
            "generation_delta": details.get("generation_delta"),
            "segment_delta": details.get("segment_delta"),
        }
    )
    expected = {
        "acceptance_trust_entry_delta": evidence["entry_count"] - head["entry_count"],
        "acceptance_entry_delta": (
            evidence["acceptance_entry_count"] - head["acceptance_entry_count"]
        ),
        "receiver_entry_delta": (
            evidence["receiver_entry_count"] - head["receiver_entry_count"]
        ),
        "trust_entry_delta": (
            evidence["trust_entry_count"] - head["trust_entry_count"]
        ),
        "generation_delta": evidence["generation"] - head["generation"],
        "segment_delta": evidence["segment_count"] - head["segment_count"],
    }
    for key, actual in expected.items():
        if transition[key] != actual:
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                f"acceptance-trust transition {key.replace('_', ' ')} is inconsistent"
            )
    entries = list(normalized["entries"])
    entries.append(
        _seal_entry(
            _engine._entry_payload(
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
    root = _engine._exact(value, STATE_FIELDS, "acceptance-trust receiver state")
    if root["state_version"] != STATE_VERSION:
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            f"acceptance-trust receiver state version must be {STATE_VERSION}"
        )
    raw_entries = root["entries"]
    if (
        not isinstance(raw_entries, list)
        or not raw_entries
        or len(raw_entries) > MAX_ENTRIES
    ):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust receiver entry count is outside the reviewed boundary"
        )
    entries: list[dict[str, Any]] = []
    previous_hash = ZERO_HASH
    previous_evidence: dict[str, Any] | None = None
    seen_bundles: set[str] = set()
    seen_checkpoints: set[str] = set()
    seen_states: set[str] = set()
    for index, raw_entry in enumerate(raw_entries, 1):
        entry = _engine._exact(
            raw_entry, ENTRY_FIELDS, f"acceptance-trust receiver entry {index}"
        )
        if entry["entry_version"] != ENTRY_VERSION or entry["sequence"] != index:
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                f"acceptance-trust receiver entry {index} version or sequence is invalid"
            )
        kind = entry["kind"]
        if kind not in {"anchor", "transition"} or (index == 1) != (kind == "anchor"):
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                f"acceptance-trust receiver entry {index} kind is invalid"
            )
        if entry["previous_entry_hash"] != previous_hash:
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                f"acceptance-trust receiver entry {index} previous hash does not match"
            )
        evidence = _evidence(entry["evidence"])
        admission = _engine._admission(entry["admission"])
        if index == 1:
            if entry["transition"] is not None:
                raise AuditTrustReceiverAcceptanceTrustReceiverError(
                    "acceptance-trust receiver anchor must not contain transition evidence"
                )
            transition = None
        else:
            transition = _transition(entry["transition"])
            assert previous_evidence is not None
            if (
                transition["previous_checkpoint_id"]
                != previous_evidence["checkpoint_id"]
                or transition["previous_state_id"] != previous_evidence["state_id"]
            ):
                raise AuditTrustReceiverAcceptanceTrustReceiverError(
                    f"acceptance-trust receiver entry {index} transition does not match previous evidence"
                )
            expected = {
                "acceptance_trust_entry_delta": (
                    evidence["entry_count"] - previous_evidence["entry_count"]
                ),
                "acceptance_entry_delta": (
                    evidence["acceptance_entry_count"]
                    - previous_evidence["acceptance_entry_count"]
                ),
                "receiver_entry_delta": (
                    evidence["receiver_entry_count"]
                    - previous_evidence["receiver_entry_count"]
                ),
                "trust_entry_delta": (
                    evidence["trust_entry_count"]
                    - previous_evidence["trust_entry_count"]
                ),
                "generation_delta": (
                    evidence["generation"] - previous_evidence["generation"]
                ),
                "segment_delta": (
                    evidence["segment_count"] - previous_evidence["segment_count"]
                ),
            }
            if any(
                actual < (0 if key == "segment_delta" else 1)
                for key, actual in expected.items()
            ):
                raise AuditTrustReceiverAcceptanceTrustReceiverError(
                    f"acceptance-trust receiver entry {index} does not advance nested history"
                )
            for key, actual in expected.items():
                if transition[key] != actual:
                    raise AuditTrustReceiverAcceptanceTrustReceiverError(
                        f"acceptance-trust receiver entry {index} {key.replace('_', ' ')} is invalid"
                    )
        if evidence["handoff_bundle_id"] in seen_bundles:
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                "acceptance-trust receiver history contains a duplicate bundle id"
            )
        if evidence["checkpoint_id"] in seen_checkpoints:
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                "acceptance-trust receiver history contains a duplicate checkpoint id"
            )
        if evidence["state_id"] in seen_states:
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                "acceptance-trust receiver history contains a duplicate state id"
            )
        seen_bundles.add(evidence["handoff_bundle_id"])
        seen_checkpoints.add(evidence["checkpoint_id"])
        seen_states.add(evidence["state_id"])
        payload = _engine._entry_payload(
            index, kind, previous_hash, evidence, admission, transition
        )
        entry_hash = _engine._hash(
            entry["entry_hash"], "acceptance-trust receiver entry hash"
        )
        if entry_hash != _identifier(ENTRY_DOMAIN, payload):
            raise AuditTrustReceiverAcceptanceTrustReceiverError(
                f"acceptance-trust receiver entry {index} hash does not match"
            )
        sealed = {**payload, "entry_hash": entry_hash}
        entries.append(sealed)
        previous_hash = entry_hash
        previous_evidence = evidence
    payload = _state_payload(entries)
    head = _engine._exact(
        root["head"], HEAD_FIELDS, "acceptance-trust receiver head"
    )
    if head != payload["head"]:
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust receiver head does not match final history entry"
        )
    state_id = _engine._hash(
        root["state_id"], "acceptance-trust receiver state id"
    )
    if state_id != _identifier(STATE_DOMAIN, payload):
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            "acceptance-trust receiver state id does not match canonical state"
        )
    return {**payload, "state_id": state_id}


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
            expected_bundle_id=_engine._pin(
                expected_bundle_id, "expected acceptance-trust handoff id"
            ),
            expected_candidate_checkpoint_id=_engine._pin(
                expected_candidate_checkpoint_id,
                "expected acceptance-trust checkpoint id",
            ),
            expected_previous_checkpoint_id=(
                _engine._pin(
                    expected_previous_checkpoint_id,
                    "expected previous acceptance-trust checkpoint id",
                )
                if expected_previous_checkpoint_id is not None
                else None
            ),
        )
    except AuditTrustReceiverAcceptanceTrustBundleError as exc:
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            f"acceptance-trust handoff verification failed ({exc.rule_id}): {exc}"
        ) from exc


def _evaluate(
    bundle: Path,
    policy_path: Path,
    *,
    expected_bundle_id: str,
    expected_candidate_checkpoint_id: str,
    expected_previous_checkpoint_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _engine._outside_bundle(
        policy_path, bundle, "acceptance-trust admission policy"
    )
    try:
        policy = load_policy(policy_path)
        report = evaluate_bundle(
            Path(bundle),
            policy,
            expected_bundle_id=_engine._pin(
                expected_bundle_id, "expected acceptance-trust handoff id"
            ),
            expected_candidate_checkpoint_id=_engine._pin(
                expected_candidate_checkpoint_id,
                "expected acceptance-trust checkpoint id",
            ),
            expected_previous_checkpoint_id=(
                _engine._pin(
                    expected_previous_checkpoint_id,
                    "expected previous acceptance-trust checkpoint id",
                )
                if expected_previous_checkpoint_id is not None
                else None
            ),
        )
    except AuditTrustReceiverAcceptanceTrustAdmissionError as exc:
        raise AuditTrustReceiverAcceptanceTrustReceiverError(
            f"acceptance-trust admission failed ({exc.rule_id}): {exc}"
        ) from exc
    verified = _verified_handoff(
        bundle,
        expected_bundle_id=expected_bundle_id,
        expected_candidate_checkpoint_id=expected_candidate_checkpoint_id,
        expected_previous_checkpoint_id=expected_previous_checkpoint_id,
    )
    return report, verified


_engine.__doc__ = __doc__
_engine.AuditTrustReceiverError = AuditTrustReceiverAcceptanceTrustReceiverError
_engine.AuditTrustAdmissionError = AuditTrustReceiverAcceptanceTrustAdmissionError
_engine.AuditTrustBundleError = AuditTrustReceiverAcceptanceTrustBundleError
_engine.evaluate_handoff = evaluate_bundle
_engine.load_policy = load_policy
_engine.verify_bundle = verify_bundle
_engine.EVIDENCE_FIELDS = EVIDENCE_FIELDS
_engine.TRANSITION_FIELDS = TRANSITION_FIELDS
_engine.HEAD_FIELDS = HEAD_FIELDS
_engine._identifier = _identifier
_engine._evidence = _evidence
_engine._transition = _transition
_engine._evidence_from_verified = _evidence_from_verified
_engine._admission_from_report = _admission_from_report
_engine._report_matches_verified = _report_matches_verified
_engine._head = _head
_engine._state_payload = _state_payload
_engine._seal_entry = _seal_entry
_engine._seal_state = _seal_state
_engine.create_state = create_state
_engine.append_transition = append_transition
_engine.validate_state = validate_state
_engine._verified_handoff = _verified_handoff
_engine._evaluate = _evaluate

load_state = _engine.load_state
_original_main = _engine.main


def _remap_rule_ids(value: Any) -> Any:
    if isinstance(value, dict):
        result = {key: _remap_rule_ids(item) for key, item in value.items()}
        rule_id = result.get("rule_id")
        if isinstance(rule_id, str) and len(rule_id) == 6 and rule_id[:3] in {
            "ATR",
            "ARS",
            "ABT",
        }:
            result["rule_id"] = RULE_PREFIX + rule_id[3:]
        return result
    if isinstance(value, list):
        return [_remap_rule_ids(item) for item in value]
    return value


def main(argv: list[str] | None = None) -> int:
    original_emit = _engine._emit

    def remapping_emit(
        payload: dict[str, Any],
        output_format: str,
        *,
        stream: Any = None,
    ) -> None:
        original_emit(_remap_rule_ids(payload), output_format, stream=stream)

    _engine._emit = remapping_emit
    try:
        return _original_main(argv)
    finally:
        _engine._emit = original_emit


def adapter_report() -> dict[str, Any]:
    return {
        "valid": True,
        "source": "agent_audit_trust_receiver_acceptance_trust.py",
        "bundle_module": "agent_audit_trust_receiver_acceptance_trust_bundle.py",
        "admission_module": "agent_audit_trust_receiver_acceptance_trust_admission.py",
        "rule_prefix": RULE_PREFIX,
        "state_version": STATE_VERSION,
        "evidence_fields": sorted(EVIDENCE_FIELDS),
        "transition_fields": sorted(TRANSITION_FIELDS),
    }


if __name__ == "__main__":
    raise SystemExit(main())
