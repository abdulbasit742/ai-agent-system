#!/usr/bin/env python3
"""Maintain a pinned acceptance state for admitted receiver checkpoint bundles."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from agent_audit_trust_receiver_admission import (
    AuditTrustReceiverAdmissionError,
    evaluate_bundle,
    load_policy,
)
from agent_audit_trust_receiver_bundle import (
    AuditTrustReceiverBundleError,
    verify_bundle,
)

RULE_PREFIX = "ARS"
ENTRY_DOMAIN = b"audit-trust-receiver-acceptance-entry-v1"
STATE_DOMAIN = b"audit-trust-receiver-acceptance-state-v1"

EVIDENCE_FIELDS = {
    "handoff_bundle_id", "checkpoint_id", "state_id", "entry_count",
    "merkle_root", "head_entry_hash", "head_bundle_id", "generation",
    "segment_count", "trust_checkpoint_id", "trust_state_id", "trust_entry_count",
}
TRANSITION_FIELDS = {
    "previous_checkpoint_id", "previous_state_id", "entry_delta",
    "trust_entry_delta", "generation_delta",
}
HEAD_FIELDS = {
    "sequence", "entry_hash", "handoff_bundle_id", "checkpoint_id", "state_id",
    "entry_count", "head_bundle_id", "generation", "segment_count",
    "trust_checkpoint_id", "trust_state_id", "trust_entry_count",
}


class AuditTrustReceiverAcceptanceError(ValueError):
    """Raised when receiver acceptance history or its inputs are unsafe."""

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "ARS002",
        denied: bool = False,
    ) -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and rule_id.startswith("ATR") and len(rule_id) == 6:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id
        self.denied = denied


def _load_isolated_core() -> ModuleType:
    source = Path(__file__).with_name("agent_audit_trust_receiver.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_acceptance_core", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceError(
            "unable to load reviewed receiver-state engine", rule_id="ARS001"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_core = _load_isolated_core()
canonical_json = _core.canonical_json
ZERO_HASH = _core.ZERO_HASH
STATE_VERSION = _core.STATE_VERSION
ENTRY_VERSION = _core.ENTRY_VERSION
STATE_FIELDS = _core.STATE_FIELDS
ENTRY_FIELDS = _core.ENTRY_FIELDS
ADMISSION_FIELDS = _core.ADMISSION_FIELDS
MAX_STATE_BYTES = _core.MAX_STATE_BYTES
MAX_ENTRIES = _core.MAX_ENTRIES


def _identifier(domain: bytes, payload: dict[str, Any]) -> str:
    mapped = {
        b"audit-trust-receiver-entry-v1": ENTRY_DOMAIN,
        b"audit-trust-receiver-state-v1": STATE_DOMAIN,
    }.get(domain, domain)
    return hashlib.sha256(mapped + b"\x00" + canonical_json(payload)).hexdigest()


def _evidence(value: Any) -> dict[str, Any]:
    raw = _core._exact(value, EVIDENCE_FIELDS, "receiver acceptance evidence")
    return {
        "handoff_bundle_id": _core._hash(raw["handoff_bundle_id"], "receiver bundle id"),
        "checkpoint_id": _core._hash(raw["checkpoint_id"], "receiver checkpoint id"),
        "state_id": _core._hash(raw["state_id"], "receiver state id"),
        "entry_count": _core._integer(raw["entry_count"], "receiver entry count", 1),
        "merkle_root": _core._hash(raw["merkle_root"], "receiver merkle root"),
        "head_entry_hash": _core._hash(raw["head_entry_hash"], "receiver head entry hash"),
        "head_bundle_id": _core._hash(raw["head_bundle_id"], "receiver head handoff id"),
        "generation": _core._integer(raw["generation"], "trusted generation", 1),
        "segment_count": _core._integer(raw["segment_count"], "trusted segment count", 1),
        "trust_checkpoint_id": _core._hash(
            raw["trust_checkpoint_id"], "underlying trust checkpoint id"
        ),
        "trust_state_id": _core._hash(raw["trust_state_id"], "underlying trust state id"),
        "trust_entry_count": _core._integer(
            raw["trust_entry_count"], "underlying trust entry count", 1
        ),
    }


def _transition(value: Any) -> dict[str, Any]:
    raw = _core._exact(value, TRANSITION_FIELDS, "receiver acceptance transition")
    return {
        "previous_checkpoint_id": _core._hash(
            raw["previous_checkpoint_id"], "previous receiver checkpoint id"
        ),
        "previous_state_id": _core._hash(
            raw["previous_state_id"], "previous receiver state id"
        ),
        "entry_delta": _core._integer(raw["entry_delta"], "receiver entry delta", 1),
        "trust_entry_delta": _core._integer(
            raw["trust_entry_delta"], "underlying trust entry delta", 1
        ),
        "generation_delta": _core._integer(
            raw["generation_delta"], "trusted generation delta", 1
        ),
    }


def _evidence_from_verified(verified: dict[str, Any]) -> dict[str, Any]:
    candidate = verified.get("candidate")
    if not isinstance(candidate, dict):
        raise AuditTrustReceiverAcceptanceError("verified receiver bundle candidate is malformed")
    head = candidate.get("head")
    if not isinstance(head, dict):
        raise AuditTrustReceiverAcceptanceError("verified receiver checkpoint head is malformed")
    return _evidence(
        {
            "handoff_bundle_id": verified.get("bundle_id"),
            "checkpoint_id": candidate.get("checkpoint_id"),
            "state_id": candidate.get("state_id"),
            "entry_count": candidate.get("entry_count"),
            "merkle_root": candidate.get("merkle_root"),
            "head_entry_hash": head.get("entry_hash"),
            "head_bundle_id": head.get("handoff_bundle_id"),
            "generation": head.get("generation"),
            "segment_count": head.get("segment_count"),
            "trust_checkpoint_id": head.get("checkpoint_id"),
            "trust_state_id": head.get("state_id"),
            "trust_entry_count": head.get("entry_count"),
        }
    )


def _admission_from_report(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("admitted") is not True:
        raise AuditTrustReceiverAcceptanceError(
            "only an admitted receiver bundle can enter acceptance history",
            rule_id="ARS004",
            denied=True,
        )
    return _core._admission(
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
    if not isinstance(identity, dict) or not isinstance(details, dict) or not isinstance(candidate, dict):
        raise AuditTrustReceiverAcceptanceError("receiver admission report is malformed")
    head = candidate.get("head")
    if not isinstance(head, dict):
        raise AuditTrustReceiverAcceptanceError("verified receiver checkpoint head is malformed")
    expected_identity = {
        "bundle_id": verified.get("bundle_id"),
        "bundle_type": verified.get("bundle_type"),
        "candidate_receiver_checkpoint_id": candidate.get("checkpoint_id"),
        "candidate_receiver_state_id": candidate.get("state_id"),
        "previous_receiver_checkpoint_id": (
            previous.get("checkpoint_id") if isinstance(previous, dict) else None
        ),
        "previous_receiver_state_id": (
            previous.get("state_id") if isinstance(previous, dict) else None
        ),
    }
    if identity != expected_identity:
        raise AuditTrustReceiverAcceptanceError(
            "admission report differs from verified receiver bundle identity"
        )
    checks = {
        "candidate_receiver_entries": candidate.get("entry_count"),
        "candidate_trust_entries": head.get("entry_count"),
        "candidate_generation": head.get("generation"),
        "candidate_segment_count": head.get("segment_count"),
        "head_handoff_bundle_id": verified.get("head_handoff_bundle_id"),
    }
    for key, actual in checks.items():
        if details.get(key) != actual:
            raise AuditTrustReceiverAcceptanceError(
                f"admission report {key} differs from verified receiver bundle"
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
        "head_bundle_id": evidence["head_bundle_id"],
        "generation": evidence["generation"],
        "segment_count": evidence["segment_count"],
        "trust_checkpoint_id": evidence["trust_checkpoint_id"],
        "trust_state_id": evidence["trust_state_id"],
        "trust_entry_count": evidence["trust_entry_count"],
    }


def _state_payload(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {"state_version": STATE_VERSION, "entries": entries, "head": _head(entries)}


def _seal_entry(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "entry_hash": _identifier(ENTRY_DOMAIN, payload)}


def _seal_state(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "state_id": _identifier(STATE_DOMAIN, payload)}


def create_state(report: dict[str, Any], verified: dict[str, Any]) -> dict[str, Any]:
    if report.get("identity", {}).get("bundle_type") != "snapshot":
        raise AuditTrustReceiverAcceptanceError(
            "acceptance anchor must be an admitted receiver snapshot bundle",
            rule_id="ARS005",
        )
    _report_matches_verified(report, verified)
    evidence = _evidence_from_verified(verified)
    entry = _seal_entry(
        _core._entry_payload(
            1,
            "anchor",
            ZERO_HASH,
            evidence,
            _admission_from_report(report),
            None,
        )
    )
    return _seal_state(_state_payload([entry]))


def append_transition(
    state: dict[str, Any], report: dict[str, Any], verified: dict[str, Any]
) -> dict[str, Any]:
    normalized = validate_state(state)
    identity = report.get("identity")
    details = report.get("evidence")
    if report.get("admitted") is not True:
        raise AuditTrustReceiverAcceptanceError(
            "candidate receiver bundle was denied by admission policy",
            rule_id="ARS004",
            denied=True,
        )
    if not isinstance(identity, dict) or identity.get("bundle_type") != "transition":
        raise AuditTrustReceiverAcceptanceError(
            "acceptance advancement requires an admitted receiver transition bundle",
            rule_id="ARS005",
        )
    if not isinstance(details, dict):
        raise AuditTrustReceiverAcceptanceError("receiver admission evidence is malformed")
    previous = verified.get("previous")
    if not isinstance(previous, dict):
        raise AuditTrustReceiverAcceptanceError("receiver transition previous checkpoint is missing")
    head = normalized["head"]
    previous_head = previous.get("head")
    if (
        previous.get("checkpoint_id") != head["checkpoint_id"]
        or previous.get("state_id") != head["state_id"]
        or previous.get("entry_count") != head["entry_count"]
        or not isinstance(previous_head, dict)
        or previous_head.get("checkpoint_id") != head["trust_checkpoint_id"]
        or previous_head.get("state_id") != head["trust_state_id"]
        or previous_head.get("entry_count") != head["trust_entry_count"]
    ):
        raise AuditTrustReceiverAcceptanceError(
            "receiver transition does not start from the acceptance-state head",
            rule_id="ARS006",
            denied=True,
        )
    _report_matches_verified(report, verified)
    evidence = _evidence_from_verified(verified)
    if (
        evidence["entry_count"] <= head["entry_count"]
        or evidence["trust_entry_count"] <= head["trust_entry_count"]
        or evidence["generation"] <= head["generation"]
        or evidence["segment_count"] < head["segment_count"]
    ):
        raise AuditTrustReceiverAcceptanceError(
            "candidate receiver evidence does not advance acceptance state",
            rule_id="ARS008",
            denied=True,
        )
    seen_bundles = {item["evidence"]["handoff_bundle_id"] for item in normalized["entries"]}
    seen_checkpoints = {item["evidence"]["checkpoint_id"] for item in normalized["entries"]}
    seen_states = {item["evidence"]["state_id"] for item in normalized["entries"]}
    if (
        evidence["handoff_bundle_id"] in seen_bundles
        or evidence["checkpoint_id"] in seen_checkpoints
        or evidence["state_id"] in seen_states
    ):
        raise AuditTrustReceiverAcceptanceError(
            "candidate receiver identity already exists in acceptance history",
            rule_id="ARS007",
            denied=True,
        )
    transition = _transition(
        {
            "previous_checkpoint_id": previous.get("checkpoint_id"),
            "previous_state_id": previous.get("state_id"),
            "entry_delta": details.get("receiver_entry_delta"),
            "trust_entry_delta": details.get("trust_entry_delta"),
            "generation_delta": details.get("generation_delta"),
        }
    )
    if transition["entry_delta"] != evidence["entry_count"] - head["entry_count"]:
        raise AuditTrustReceiverAcceptanceError("receiver entry delta is inconsistent")
    if (
        transition["trust_entry_delta"]
        != evidence["trust_entry_count"] - head["trust_entry_count"]
    ):
        raise AuditTrustReceiverAcceptanceError("underlying trust entry delta is inconsistent")
    if transition["generation_delta"] != evidence["generation"] - head["generation"]:
        raise AuditTrustReceiverAcceptanceError("trusted generation delta is inconsistent")
    entries = list(normalized["entries"])
    entries.append(
        _seal_entry(
            _core._entry_payload(
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
    root = _core._exact(value, STATE_FIELDS, "receiver acceptance state")
    if root["state_version"] != STATE_VERSION:
        raise AuditTrustReceiverAcceptanceError(
            f"receiver acceptance state version must be {STATE_VERSION}"
        )
    raw_entries = root["entries"]
    if not isinstance(raw_entries, list) or not raw_entries or len(raw_entries) > MAX_ENTRIES:
        raise AuditTrustReceiverAcceptanceError(
            "receiver acceptance entry count is outside the reviewed boundary"
        )
    entries: list[dict[str, Any]] = []
    previous_hash = ZERO_HASH
    previous_evidence: dict[str, Any] | None = None
    seen_bundles: set[str] = set()
    seen_checkpoints: set[str] = set()
    seen_states: set[str] = set()
    for index, raw_entry in enumerate(raw_entries, 1):
        entry = _core._exact(raw_entry, ENTRY_FIELDS, f"acceptance entry {index}")
        if entry["entry_version"] != ENTRY_VERSION or entry["sequence"] != index:
            raise AuditTrustReceiverAcceptanceError(
                f"acceptance entry {index} version or sequence is invalid"
            )
        kind = entry["kind"]
        if kind not in {"anchor", "transition"} or (index == 1) != (kind == "anchor"):
            raise AuditTrustReceiverAcceptanceError(f"acceptance entry {index} kind is invalid")
        if entry["previous_entry_hash"] != previous_hash:
            raise AuditTrustReceiverAcceptanceError(
                f"acceptance entry {index} previous hash does not match"
            )
        evidence = _evidence(entry["evidence"])
        admission = _core._admission(entry["admission"])
        if index == 1:
            if entry["transition"] is not None:
                raise AuditTrustReceiverAcceptanceError(
                    "acceptance anchor must not contain transition evidence"
                )
            transition = None
        else:
            transition = _transition(entry["transition"])
            assert previous_evidence is not None
            if (
                transition["previous_checkpoint_id"] != previous_evidence["checkpoint_id"]
                or transition["previous_state_id"] != previous_evidence["state_id"]
            ):
                raise AuditTrustReceiverAcceptanceError(
                    f"acceptance entry {index} transition does not match previous evidence"
                )
            receiver_delta = evidence["entry_count"] - previous_evidence["entry_count"]
            trust_delta = evidence["trust_entry_count"] - previous_evidence["trust_entry_count"]
            generation_delta = evidence["generation"] - previous_evidence["generation"]
            if receiver_delta < 1 or transition["entry_delta"] != receiver_delta:
                raise AuditTrustReceiverAcceptanceError(
                    f"acceptance entry {index} receiver entry delta is invalid"
                )
            if trust_delta < 1 or transition["trust_entry_delta"] != trust_delta:
                raise AuditTrustReceiverAcceptanceError(
                    f"acceptance entry {index} trust entry delta is invalid"
                )
            if generation_delta < 1 or transition["generation_delta"] != generation_delta:
                raise AuditTrustReceiverAcceptanceError(
                    f"acceptance entry {index} generation delta is invalid"
                )
            if evidence["segment_count"] < previous_evidence["segment_count"]:
                raise AuditTrustReceiverAcceptanceError(
                    f"acceptance entry {index} segment count decreases"
                )
        if evidence["handoff_bundle_id"] in seen_bundles:
            raise AuditTrustReceiverAcceptanceError(
                "acceptance history contains a duplicate receiver bundle id"
            )
        if evidence["checkpoint_id"] in seen_checkpoints:
            raise AuditTrustReceiverAcceptanceError(
                "acceptance history contains a duplicate receiver checkpoint id"
            )
        if evidence["state_id"] in seen_states:
            raise AuditTrustReceiverAcceptanceError(
                "acceptance history contains a duplicate receiver state id"
            )
        seen_bundles.add(evidence["handoff_bundle_id"])
        seen_checkpoints.add(evidence["checkpoint_id"])
        seen_states.add(evidence["state_id"])
        payload = _core._entry_payload(
            index, kind, previous_hash, evidence, admission, transition
        )
        entry_hash = _core._hash(entry["entry_hash"], "acceptance entry hash")
        if entry_hash != _identifier(ENTRY_DOMAIN, payload):
            raise AuditTrustReceiverAcceptanceError(
                f"acceptance entry {index} hash does not match"
            )
        sealed = {**payload, "entry_hash": entry_hash}
        entries.append(sealed)
        previous_hash = entry_hash
        previous_evidence = evidence
    payload = _state_payload(entries)
    head = _core._exact(root["head"], HEAD_FIELDS, "receiver acceptance head")
    if head != payload["head"]:
        raise AuditTrustReceiverAcceptanceError(
            "receiver acceptance head does not match final history entry"
        )
    state_id = _core._hash(root["state_id"], "receiver acceptance state id")
    if state_id != _identifier(STATE_DOMAIN, payload):
        raise AuditTrustReceiverAcceptanceError(
            "receiver acceptance state id does not match canonical state"
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
            expected_bundle_id=_core._pin(expected_bundle_id, "expected receiver bundle id"),
            expected_candidate_checkpoint_id=_core._pin(
                expected_candidate_checkpoint_id, "expected receiver checkpoint id"
            ),
            expected_previous_checkpoint_id=(
                _core._pin(expected_previous_checkpoint_id, "expected previous receiver checkpoint id")
                if expected_previous_checkpoint_id is not None
                else None
            ),
        )
    except AuditTrustReceiverBundleError as exc:
        raise AuditTrustReceiverAcceptanceError(
            f"receiver bundle verification failed ({exc.rule_id}): {exc}"
        ) from exc


def _evaluate(
    bundle: Path,
    policy_path: Path,
    *,
    expected_bundle_id: str,
    expected_candidate_checkpoint_id: str,
    expected_previous_checkpoint_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _core._outside_bundle(policy_path, bundle, "receiver admission policy")
    try:
        policy = load_policy(policy_path)
        report = evaluate_bundle(
            Path(bundle),
            policy,
            expected_bundle_id=_core._pin(expected_bundle_id, "expected receiver bundle id"),
            expected_candidate_checkpoint_id=_core._pin(
                expected_candidate_checkpoint_id, "expected receiver checkpoint id"
            ),
            expected_previous_checkpoint_id=(
                _core._pin(expected_previous_checkpoint_id, "expected previous receiver checkpoint id")
                if expected_previous_checkpoint_id is not None
                else None
            ),
        )
    except AuditTrustReceiverAdmissionError as exc:
        raise AuditTrustReceiverAcceptanceError(
            f"receiver admission failed ({exc.rule_id}): {exc}"
        ) from exc
    verified = _verified_handoff(
        bundle,
        expected_bundle_id=expected_bundle_id,
        expected_candidate_checkpoint_id=expected_candidate_checkpoint_id,
        expected_previous_checkpoint_id=expected_previous_checkpoint_id,
    )
    return report, verified


_core.__doc__ = __doc__
_core.AuditTrustReceiverError = AuditTrustReceiverAcceptanceError
_core.AuditTrustAdmissionError = AuditTrustReceiverAdmissionError
_core.AuditTrustBundleError = AuditTrustReceiverBundleError
_core.evaluate_handoff = evaluate_bundle
_core.load_policy = load_policy
_core.verify_bundle = verify_bundle
_core.EVIDENCE_FIELDS = EVIDENCE_FIELDS
_core.TRANSITION_FIELDS = TRANSITION_FIELDS
_core.HEAD_FIELDS = HEAD_FIELDS
_core._identifier = _identifier
_core._evidence = _evidence
_core._transition = _transition
_core._evidence_from_verified = _evidence_from_verified
_core._admission_from_report = _admission_from_report
_core._report_matches_verified = _report_matches_verified
_core._head = _head
_core._state_payload = _state_payload
_core._seal_entry = _seal_entry
_core._seal_state = _seal_state
_core.create_state = create_state
_core.append_transition = append_transition
_core.validate_state = validate_state
_core._verified_handoff = _verified_handoff
_core._evaluate = _evaluate

load_state = _core.load_state
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
