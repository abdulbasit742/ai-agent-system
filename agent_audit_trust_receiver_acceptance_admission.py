#!/usr/bin/env python3
"""Consumer-owned admission policy for verified receiver-acceptance bundles."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from agent_audit_trust_receiver_acceptance_bundle import (
    AuditTrustReceiverAcceptanceBundleError,
    MANIFEST_NAME,
    load_manifest,
    verify_bundle,
)

POLICY_VERSION = 1
RULE_PREFIX = "ABA"
ALLOWED_BUNDLE_TYPES = frozenset({"snapshot", "transition"})
ALLOWED_RELATIONS = frozenset({"right-descendant"})

POLICY_FIELDS = {"version", "bundle", "candidate", "selection", "transition"}
BUNDLE_FIELDS = {"allowed_types", "max_files", "max_bytes", "min_proofs", "max_proofs"}
CANDIDATE_FIELDS = {
    "min_acceptance_entries", "max_acceptance_entries",
    "min_receiver_entries", "max_receiver_entries",
    "min_trust_entries", "max_trust_entries",
    "min_generation", "max_generation",
    "min_segment_count", "max_segment_count",
    "allowed_acceptance_state_ids", "allowed_acceptance_checkpoint_ids",
    "allowed_head_receiver_bundle_ids", "allowed_head_trust_handoff_ids",
    "allowed_receiver_state_ids", "allowed_receiver_checkpoint_ids",
    "allowed_trust_state_ids", "allowed_trust_checkpoint_ids",
}
SELECTION_FIELDS = {
    "required_sequences", "allowed_sequences",
    "required_receiver_bundle_ids", "allowed_receiver_bundle_ids",
    "require_anchor", "require_head",
}
TRANSITION_FIELDS = {
    "allowed_relations",
    "min_acceptance_entry_delta", "max_acceptance_entry_delta",
    "min_receiver_entry_delta", "max_receiver_entry_delta",
    "min_trust_entry_delta", "max_trust_entry_delta",
    "min_generation_delta", "max_generation_delta",
    "min_segment_delta", "max_segment_delta",
    "allowed_previous_acceptance_state_ids",
    "allowed_previous_acceptance_checkpoint_ids",
    "allowed_previous_receiver_state_ids",
    "allowed_previous_receiver_checkpoint_ids",
    "allowed_previous_trust_state_ids",
    "allowed_previous_trust_checkpoint_ids",
    "require_single_step",
}


class AuditTrustReceiverAcceptanceAdmissionError(ValueError):
    """Raised when an acceptance-bundle policy or evaluation is unsafe."""

    def __init__(self, message: str, *, rule_id: str = "ABA000") -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and rule_id.startswith("ARA") and len(rule_id) == 6:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id


def _load_isolated_core() -> ModuleType:
    source = Path(__file__).with_name("agent_audit_trust_receiver_admission.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_acceptance_admission_core", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceAdmissionError(
            "unable to load reviewed receiver-admission engine", rule_id="ABA000"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_core = _load_isolated_core()
_core.__doc__ = __doc__
_core.AuditTrustReceiverAdmissionError = AuditTrustReceiverAcceptanceAdmissionError
_core.AuditTrustReceiverBundleError = AuditTrustReceiverAcceptanceBundleError
_core.MANIFEST_NAME = MANIFEST_NAME
_core.load_manifest = load_manifest
_core.verify_bundle = verify_bundle
_core.POLICY_VERSION = POLICY_VERSION

canonical_json = _core.canonical_json
MAX_POLICY_BYTES = _core.MAX_POLICY_BYTES


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
            "min_acceptance_entries": 1,
            "max_acceptance_entries": 1_000_000,
            "min_receiver_entries": 1,
            "max_receiver_entries": 1_000_000,
            "min_trust_entries": 1,
            "max_trust_entries": 1_000_000,
            "min_generation": 1,
            "max_generation": 1_000_000,
            "min_segment_count": 1,
            "max_segment_count": 1_000_000,
            "allowed_acceptance_state_ids": [],
            "allowed_acceptance_checkpoint_ids": [],
            "allowed_head_receiver_bundle_ids": [],
            "allowed_head_trust_handoff_ids": [],
            "allowed_receiver_state_ids": [],
            "allowed_receiver_checkpoint_ids": [],
            "allowed_trust_state_ids": [],
            "allowed_trust_checkpoint_ids": [],
        },
        "selection": {
            "required_sequences": [],
            "allowed_sequences": [],
            "required_receiver_bundle_ids": [],
            "allowed_receiver_bundle_ids": [],
            "require_anchor": False,
            "require_head": True,
        },
        "transition": {
            "allowed_relations": ["right-descendant"],
            "min_acceptance_entry_delta": 1,
            "max_acceptance_entry_delta": 1_000_000,
            "min_receiver_entry_delta": 1,
            "max_receiver_entry_delta": 1_000_000,
            "min_trust_entry_delta": 1,
            "max_trust_entry_delta": 1_000_000,
            "min_generation_delta": 1,
            "max_generation_delta": 1_000_000,
            "min_segment_delta": 0,
            "max_segment_delta": 1_000_000,
            "allowed_previous_acceptance_state_ids": [],
            "allowed_previous_acceptance_checkpoint_ids": [],
            "allowed_previous_receiver_state_ids": [],
            "allowed_previous_receiver_checkpoint_ids": [],
            "allowed_previous_trust_state_ids": [],
            "allowed_previous_trust_checkpoint_ids": [],
            "require_single_step": False,
        },
    }


def validate_policy(value: Any) -> dict[str, Any]:
    root = _core._exact(value, POLICY_FIELDS, "acceptance admission policy")
    if root["version"] != POLICY_VERSION:
        raise AuditTrustReceiverAcceptanceAdmissionError(
            f"acceptance admission policy version must be {POLICY_VERSION}"
        )
    bundle = _core._exact(root["bundle"], BUNDLE_FIELDS, "bundle policy")
    candidate = _core._exact(root["candidate"], CANDIDATE_FIELDS, "candidate policy")
    selection = _core._exact(root["selection"], SELECTION_FIELDS, "selection policy")
    transition = _core._exact(root["transition"], TRANSITION_FIELDS, "transition policy")
    normalized = {
        "version": POLICY_VERSION,
        "bundle": {
            "allowed_types": _core._strings(
                bundle["allowed_types"], "bundle.allowed_types",
                allowed=ALLOWED_BUNDLE_TYPES, require_nonempty=True,
            ),
            "max_files": _core._integer(bundle["max_files"], "bundle.max_files", 1),
            "max_bytes": _core._integer(bundle["max_bytes"], "bundle.max_bytes", 1),
            "min_proofs": _core._integer(bundle["min_proofs"], "bundle.min_proofs", 1),
            "max_proofs": _core._integer(bundle["max_proofs"], "bundle.max_proofs", 1),
        },
        "candidate": {
            "min_acceptance_entries": _core._integer(candidate["min_acceptance_entries"], "candidate.min_acceptance_entries", 1),
            "max_acceptance_entries": _core._integer(candidate["max_acceptance_entries"], "candidate.max_acceptance_entries", 1),
            "min_receiver_entries": _core._integer(candidate["min_receiver_entries"], "candidate.min_receiver_entries", 1),
            "max_receiver_entries": _core._integer(candidate["max_receiver_entries"], "candidate.max_receiver_entries", 1),
            "min_trust_entries": _core._integer(candidate["min_trust_entries"], "candidate.min_trust_entries", 1),
            "max_trust_entries": _core._integer(candidate["max_trust_entries"], "candidate.max_trust_entries", 1),
            "min_generation": _core._integer(candidate["min_generation"], "candidate.min_generation", 1),
            "max_generation": _core._integer(candidate["max_generation"], "candidate.max_generation", 1),
            "min_segment_count": _core._integer(candidate["min_segment_count"], "candidate.min_segment_count", 1),
            "max_segment_count": _core._integer(candidate["max_segment_count"], "candidate.max_segment_count", 1),
            "allowed_acceptance_state_ids": _core._strings(candidate["allowed_acceptance_state_ids"], "candidate.allowed_acceptance_state_ids", hashes=True),
            "allowed_acceptance_checkpoint_ids": _core._strings(candidate["allowed_acceptance_checkpoint_ids"], "candidate.allowed_acceptance_checkpoint_ids", hashes=True),
            "allowed_head_receiver_bundle_ids": _core._strings(candidate["allowed_head_receiver_bundle_ids"], "candidate.allowed_head_receiver_bundle_ids", hashes=True),
            "allowed_head_trust_handoff_ids": _core._strings(candidate["allowed_head_trust_handoff_ids"], "candidate.allowed_head_trust_handoff_ids", hashes=True),
            "allowed_receiver_state_ids": _core._strings(candidate["allowed_receiver_state_ids"], "candidate.allowed_receiver_state_ids", hashes=True),
            "allowed_receiver_checkpoint_ids": _core._strings(candidate["allowed_receiver_checkpoint_ids"], "candidate.allowed_receiver_checkpoint_ids", hashes=True),
            "allowed_trust_state_ids": _core._strings(candidate["allowed_trust_state_ids"], "candidate.allowed_trust_state_ids", hashes=True),
            "allowed_trust_checkpoint_ids": _core._strings(candidate["allowed_trust_checkpoint_ids"], "candidate.allowed_trust_checkpoint_ids", hashes=True),
        },
        "selection": {
            "required_sequences": _core._integers(selection["required_sequences"], "selection.required_sequences"),
            "allowed_sequences": _core._integers(selection["allowed_sequences"], "selection.allowed_sequences"),
            "required_receiver_bundle_ids": _core._strings(selection["required_receiver_bundle_ids"], "selection.required_receiver_bundle_ids", hashes=True),
            "allowed_receiver_bundle_ids": _core._strings(selection["allowed_receiver_bundle_ids"], "selection.allowed_receiver_bundle_ids", hashes=True),
            "require_anchor": _core._boolean(selection["require_anchor"], "selection.require_anchor"),
            "require_head": _core._boolean(selection["require_head"], "selection.require_head"),
        },
        "transition": {
            "allowed_relations": _core._strings(
                transition["allowed_relations"], "transition.allowed_relations",
                allowed=ALLOWED_RELATIONS, require_nonempty=True,
            ),
            "min_acceptance_entry_delta": _core._integer(transition["min_acceptance_entry_delta"], "transition.min_acceptance_entry_delta", 1),
            "max_acceptance_entry_delta": _core._integer(transition["max_acceptance_entry_delta"], "transition.max_acceptance_entry_delta", 1),
            "min_receiver_entry_delta": _core._integer(transition["min_receiver_entry_delta"], "transition.min_receiver_entry_delta", 1),
            "max_receiver_entry_delta": _core._integer(transition["max_receiver_entry_delta"], "transition.max_receiver_entry_delta", 1),
            "min_trust_entry_delta": _core._integer(transition["min_trust_entry_delta"], "transition.min_trust_entry_delta", 1),
            "max_trust_entry_delta": _core._integer(transition["max_trust_entry_delta"], "transition.max_trust_entry_delta", 1),
            "min_generation_delta": _core._integer(transition["min_generation_delta"], "transition.min_generation_delta", 1),
            "max_generation_delta": _core._integer(transition["max_generation_delta"], "transition.max_generation_delta", 1),
            "min_segment_delta": _core._integer(transition["min_segment_delta"], "transition.min_segment_delta"),
            "max_segment_delta": _core._integer(transition["max_segment_delta"], "transition.max_segment_delta"),
            "allowed_previous_acceptance_state_ids": _core._strings(transition["allowed_previous_acceptance_state_ids"], "transition.allowed_previous_acceptance_state_ids", hashes=True),
            "allowed_previous_acceptance_checkpoint_ids": _core._strings(transition["allowed_previous_acceptance_checkpoint_ids"], "transition.allowed_previous_acceptance_checkpoint_ids", hashes=True),
            "allowed_previous_receiver_state_ids": _core._strings(transition["allowed_previous_receiver_state_ids"], "transition.allowed_previous_receiver_state_ids", hashes=True),
            "allowed_previous_receiver_checkpoint_ids": _core._strings(transition["allowed_previous_receiver_checkpoint_ids"], "transition.allowed_previous_receiver_checkpoint_ids", hashes=True),
            "allowed_previous_trust_state_ids": _core._strings(transition["allowed_previous_trust_state_ids"], "transition.allowed_previous_trust_state_ids", hashes=True),
            "allowed_previous_trust_checkpoint_ids": _core._strings(transition["allowed_previous_trust_checkpoint_ids"], "transition.allowed_previous_trust_checkpoint_ids", hashes=True),
            "require_single_step": _core._boolean(transition["require_single_step"], "transition.require_single_step"),
        },
    }
    if normalized["bundle"]["min_proofs"] > normalized["bundle"]["max_proofs"]:
        raise AuditTrustReceiverAcceptanceAdmissionError(
            "bundle.min_proofs must not exceed bundle.max_proofs"
        )
    pairs = (
        ("candidate.acceptance_entries", normalized["candidate"]["min_acceptance_entries"], normalized["candidate"]["max_acceptance_entries"]),
        ("candidate.receiver_entries", normalized["candidate"]["min_receiver_entries"], normalized["candidate"]["max_receiver_entries"]),
        ("candidate.trust_entries", normalized["candidate"]["min_trust_entries"], normalized["candidate"]["max_trust_entries"]),
        ("candidate.generation", normalized["candidate"]["min_generation"], normalized["candidate"]["max_generation"]),
        ("candidate.segment_count", normalized["candidate"]["min_segment_count"], normalized["candidate"]["max_segment_count"]),
        ("transition.acceptance_entry_delta", normalized["transition"]["min_acceptance_entry_delta"], normalized["transition"]["max_acceptance_entry_delta"]),
        ("transition.receiver_entry_delta", normalized["transition"]["min_receiver_entry_delta"], normalized["transition"]["max_receiver_entry_delta"]),
        ("transition.trust_entry_delta", normalized["transition"]["min_trust_entry_delta"], normalized["transition"]["max_trust_entry_delta"]),
        ("transition.generation_delta", normalized["transition"]["min_generation_delta"], normalized["transition"]["max_generation_delta"]),
        ("transition.segment_delta", normalized["transition"]["min_segment_delta"], normalized["transition"]["max_segment_delta"]),
    )
    for label, minimum, maximum in pairs:
        if minimum > maximum:
            raise AuditTrustReceiverAcceptanceAdmissionError(
                f"{label} minimum must not exceed maximum"
            )
    required_sequences = set(normalized["selection"]["required_sequences"])
    allowed_sequences = set(normalized["selection"]["allowed_sequences"])
    if allowed_sequences and not required_sequences <= allowed_sequences:
        raise AuditTrustReceiverAcceptanceAdmissionError(
            "required sequences must be a subset of allowed sequences"
        )
    required_bundles = set(normalized["selection"]["required_receiver_bundle_ids"])
    allowed_bundles = set(normalized["selection"]["allowed_receiver_bundle_ids"])
    if allowed_bundles and not required_bundles <= allowed_bundles:
        raise AuditTrustReceiverAcceptanceAdmissionError(
            "required receiver bundle IDs must be a subset of allowed receiver bundle IDs"
        )
    return normalized


def policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(validate_policy(policy))).hexdigest()


def _decision_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"audit-trust-receiver-acceptance-admission-decision-v1\x00"
        + canonical_json(payload)
    ).hexdigest()


def _policy_outside_bundle(policy_path: Path, bundle_dir: Path) -> None:
    policy = Path(policy_path).resolve(strict=False)
    bundle = Path(bundle_dir).resolve(strict=False)
    try:
        policy.relative_to(bundle)
    except ValueError:
        return
    raise AuditTrustReceiverAcceptanceAdmissionError(
        "acceptance admission policy must remain outside the acceptance bundle"
    )


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
    except AuditTrustReceiverAcceptanceBundleError as exc:
        raise AuditTrustReceiverAcceptanceAdmissionError(
            f"acceptance bundle verification failed ({exc.rule_id}): {exc}"
        ) from exc
    if manifest["bundle_id"] != verified["bundle_id"]:
        raise AuditTrustReceiverAcceptanceAdmissionError(
            "acceptance bundle manifest identity changed after verification"
        )

    violations: list[dict[str, Any]] = []
    bundle_policy = normalized_policy["bundle"]
    candidate_policy = normalized_policy["candidate"]
    selection_policy = normalized_policy["selection"]
    transition_policy = normalized_policy["transition"]
    candidate = verified["candidate"]
    head = candidate["head"]
    entries = manifest["entries"]
    sequences = [entry["sequence"] for entry in entries]
    receiver_bundle_ids = [entry["handoff_bundle_id"] for entry in entries]

    if verified["bundle_type"] not in bundle_policy["allowed_types"]:
        _core._deny(violations, "ABA001", "acceptance bundle type is not allowed", bundle_type=verified["bundle_type"])
    if verified["files"] > bundle_policy["max_files"] or verified["bytes"] > bundle_policy["max_bytes"]:
        _core._deny(violations, "ABA002", "acceptance bundle size exceeds policy", files=verified["files"], max_files=bundle_policy["max_files"], bytes=verified["bytes"], max_bytes=bundle_policy["max_bytes"])
    if not bundle_policy["min_proofs"] <= verified["proof_count"] <= bundle_policy["max_proofs"]:
        _core._deny(violations, "ABA003", "acceptance bundle proof count is outside policy", actual=verified["proof_count"], minimum=bundle_policy["min_proofs"], maximum=bundle_policy["max_proofs"])
    if not candidate_policy["min_acceptance_entries"] <= candidate["entry_count"] <= candidate_policy["max_acceptance_entries"]:
        _core._deny(violations, "ABA004", "candidate acceptance entry count is outside policy", actual=candidate["entry_count"])
    if not candidate_policy["min_receiver_entries"] <= head["entry_count"] <= candidate_policy["max_receiver_entries"]:
        _core._deny(violations, "ABA005", "candidate receiver entry count is outside policy", actual=head["entry_count"])
    if not candidate_policy["min_trust_entries"] <= head["trust_entry_count"] <= candidate_policy["max_trust_entries"]:
        _core._deny(violations, "ABA005", "candidate trust entry count is outside policy", actual=head["trust_entry_count"])
    if not candidate_policy["min_generation"] <= head["generation"] <= candidate_policy["max_generation"]:
        _core._deny(violations, "ABA006", "candidate generation is outside policy", actual=head["generation"])
    if not candidate_policy["min_segment_count"] <= head["segment_count"] <= candidate_policy["max_segment_count"]:
        _core._deny(violations, "ABA006", "candidate segment count is outside policy", actual=head["segment_count"])
    if not _core._allowed(candidate["state_id"], candidate_policy["allowed_acceptance_state_ids"]):
        _core._deny(violations, "ABA007", "candidate acceptance state ID is not allowed", state_id=candidate["state_id"])
    if not _core._allowed(candidate["checkpoint_id"], candidate_policy["allowed_acceptance_checkpoint_ids"]):
        _core._deny(violations, "ABA007", "candidate acceptance checkpoint ID is not allowed", checkpoint_id=candidate["checkpoint_id"])
    downstream = (
        (head["handoff_bundle_id"], candidate_policy["allowed_head_receiver_bundle_ids"], "head receiver bundle ID"),
        (head["head_bundle_id"], candidate_policy["allowed_head_trust_handoff_ids"], "head trust handoff ID"),
        (head["state_id"], candidate_policy["allowed_receiver_state_ids"], "receiver state ID"),
        (head["checkpoint_id"], candidate_policy["allowed_receiver_checkpoint_ids"], "receiver checkpoint ID"),
        (head["trust_state_id"], candidate_policy["allowed_trust_state_ids"], "trust state ID"),
        (head["trust_checkpoint_id"], candidate_policy["allowed_trust_checkpoint_ids"], "trust checkpoint ID"),
    )
    for actual, allowed, label in downstream:
        if not _core._allowed(actual, allowed):
            _core._deny(violations, "ABA008", f"candidate {label} is not allowed", identity=actual)

    selected_sequences = set(sequences)
    required_sequences = set(selection_policy["required_sequences"])
    allowed_sequences = set(selection_policy["allowed_sequences"])
    if not required_sequences <= selected_sequences:
        _core._deny(violations, "ABA009", "required acceptance sequences are missing", missing=sorted(required_sequences - selected_sequences))
    if allowed_sequences and not selected_sequences <= allowed_sequences:
        _core._deny(violations, "ABA009", "selected acceptance sequences exceed the allowlist", unexpected=sorted(selected_sequences - allowed_sequences))
    selected_bundles = set(receiver_bundle_ids)
    required_bundles = set(selection_policy["required_receiver_bundle_ids"])
    allowed_bundles = set(selection_policy["allowed_receiver_bundle_ids"])
    if not required_bundles <= selected_bundles:
        _core._deny(violations, "ABA010", "required receiver bundle IDs are missing", missing=sorted(required_bundles - selected_bundles))
    if allowed_bundles and not selected_bundles <= allowed_bundles:
        _core._deny(violations, "ABA010", "selected receiver bundle IDs exceed the allowlist", unexpected=sorted(selected_bundles - allowed_bundles))
    if selection_policy["require_anchor"] and 1 not in selected_sequences:
        _core._deny(violations, "ABA011", "acceptance anchor proof is required")
    if selection_policy["require_head"] and candidate["entry_count"] not in selected_sequences:
        _core._deny(violations, "ABA011", "candidate acceptance-head proof is required")

    previous = verified["previous"]
    acceptance_entry_delta = receiver_entry_delta = trust_entry_delta = None
    generation_delta = segment_delta = None
    if verified["bundle_type"] == "transition":
        relation = verified["consistency"]["relation"]
        if relation not in transition_policy["allowed_relations"]:
            _core._deny(violations, "ABA012", "acceptance consistency relation is not allowed", relation=relation)
        previous_head = previous["head"]
        acceptance_entry_delta = candidate["entry_count"] - previous["entry_count"]
        if not transition_policy["min_acceptance_entry_delta"] <= acceptance_entry_delta <= transition_policy["max_acceptance_entry_delta"]:
            _core._deny(violations, "ABA013", "acceptance entry delta is outside policy", actual=acceptance_entry_delta)
        receiver_entry_delta = head["entry_count"] - previous_head["entry_count"]
        trust_entry_delta = head["trust_entry_count"] - previous_head["trust_entry_count"]
        generation_delta = head["generation"] - previous_head["generation"]
        segment_delta = head["segment_count"] - previous_head["segment_count"]
        delta_checks = (
            (receiver_entry_delta, transition_policy["min_receiver_entry_delta"], transition_policy["max_receiver_entry_delta"], "receiver entry"),
            (trust_entry_delta, transition_policy["min_trust_entry_delta"], transition_policy["max_trust_entry_delta"], "trust entry"),
            (generation_delta, transition_policy["min_generation_delta"], transition_policy["max_generation_delta"], "generation"),
            (segment_delta, transition_policy["min_segment_delta"], transition_policy["max_segment_delta"], "segment"),
        )
        for actual, minimum, maximum, label in delta_checks:
            if not minimum <= actual <= maximum:
                _core._deny(violations, "ABA014", f"{label} delta is outside policy", actual=actual)
        previous_identities = (
            (previous["state_id"], transition_policy["allowed_previous_acceptance_state_ids"], "previous acceptance state ID"),
            (previous["checkpoint_id"], transition_policy["allowed_previous_acceptance_checkpoint_ids"], "previous acceptance checkpoint ID"),
            (previous_head["state_id"], transition_policy["allowed_previous_receiver_state_ids"], "previous receiver state ID"),
            (previous_head["checkpoint_id"], transition_policy["allowed_previous_receiver_checkpoint_ids"], "previous receiver checkpoint ID"),
            (previous_head["trust_state_id"], transition_policy["allowed_previous_trust_state_ids"], "previous trust state ID"),
            (previous_head["trust_checkpoint_id"], transition_policy["allowed_previous_trust_checkpoint_ids"], "previous trust checkpoint ID"),
        )
        for actual, allowed, label in previous_identities:
            if not _core._allowed(actual, allowed):
                _core._deny(violations, "ABA015", f"{label} is not allowed", identity=actual)
        if transition_policy["require_single_step"] and acceptance_entry_delta != 1:
            _core._deny(violations, "ABA016", "acceptance transition must append exactly one entry", actual=acceptance_entry_delta)

    policy_hash = policy_sha256(normalized_policy)
    identity = {
        "bundle_id": verified["bundle_id"],
        "bundle_type": verified["bundle_type"],
        "candidate_acceptance_checkpoint_id": candidate["checkpoint_id"],
        "candidate_acceptance_state_id": candidate["state_id"],
        "previous_acceptance_checkpoint_id": previous["checkpoint_id"] if previous else None,
        "previous_acceptance_state_id": previous["state_id"] if previous else None,
    }
    evidence = {
        "files": verified["files"],
        "bytes": verified["bytes"],
        "proof_count": verified["proof_count"],
        "selected_sequences": sequences,
        "selected_receiver_bundle_ids": receiver_bundle_ids,
        "candidate_acceptance_entries": candidate["entry_count"],
        "candidate_receiver_entries": head["entry_count"],
        "candidate_trust_entries": head["trust_entry_count"],
        "candidate_generation": head["generation"],
        "candidate_segment_count": head["segment_count"],
        "head_receiver_bundle_id": head["handoff_bundle_id"],
        "head_trust_handoff_id": head["head_bundle_id"],
        "acceptance_entry_delta": acceptance_entry_delta,
        "receiver_entry_delta": receiver_entry_delta,
        "trust_entry_delta": trust_entry_delta,
        "generation_delta": generation_delta,
        "segment_delta": segment_delta,
    }
    core = {
        "admitted": not violations,
        "policy_sha256": policy_hash,
        "identity": identity,
        "evidence": evidence,
        "violations": violations,
    }
    return {**core, "decision_id": _decision_id(core)}


_core.default_policy = default_policy
_core.validate_policy = validate_policy
_core.policy_sha256 = policy_sha256
_core._decision_id = _decision_id
_core._policy_outside_bundle = _policy_outside_bundle
_core.evaluate_bundle = evaluate_bundle

load_policy = _core.load_policy
main = _core.main


def adapter_report() -> dict[str, Any]:
    return {
        "valid": True,
        "source": "agent_audit_trust_receiver_admission.py",
        "bundle_module": "agent_audit_trust_receiver_acceptance_bundle.py",
        "manifest_name": MANIFEST_NAME,
        "rule_prefix": RULE_PREFIX,
        "policy_version": POLICY_VERSION,
        "candidate_fields": sorted(CANDIDATE_FIELDS),
        "transition_fields": sorted(TRANSITION_FIELDS),
    }


if __name__ == "__main__":
    raise SystemExit(main())
