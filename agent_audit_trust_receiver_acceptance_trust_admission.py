#!/usr/bin/env python3
"""Consumer-owned admission policy for verified receiver-acceptance trust handoffs."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from agent_audit_trust_receiver_acceptance_trust_bundle import (
    AuditTrustReceiverAcceptanceTrustBundleError,
    MANIFEST_NAME,
    load_manifest,
    verify_bundle,
)

POLICY_VERSION = 1
RULE_PREFIX = "ABM"
ALLOWED_BUNDLE_TYPES = frozenset({"snapshot", "transition"})
ALLOWED_RELATIONS = frozenset({"right-descendant"})

POLICY_FIELDS = {"version", "bundle", "candidate", "selection", "transition"}
BUNDLE_FIELDS = {"allowed_types", "max_files", "max_bytes", "min_proofs", "max_proofs"}
CANDIDATE_FIELDS = {
    "min_acceptance_trust_entries", "max_acceptance_trust_entries",
    "min_acceptance_entries", "max_acceptance_entries",
    "min_receiver_entries", "max_receiver_entries",
    "min_trust_entries", "max_trust_entries",
    "min_generation", "max_generation",
    "min_segment_count", "max_segment_count",
    "allowed_acceptance_trust_state_ids", "allowed_acceptance_trust_checkpoint_ids",
    "allowed_acceptance_state_ids", "allowed_acceptance_checkpoint_ids",
    "allowed_head_acceptance_bundle_ids", "allowed_head_receiver_bundle_ids",
    "allowed_head_trust_handoff_ids", "allowed_receiver_state_ids",
    "allowed_receiver_checkpoint_ids", "allowed_trust_state_ids",
    "allowed_trust_checkpoint_ids",
}
SELECTION_FIELDS = {
    "required_sequences", "allowed_sequences",
    "required_acceptance_bundle_ids", "allowed_acceptance_bundle_ids",
    "require_anchor", "require_head",
}
TRANSITION_FIELDS = {
    "allowed_relations",
    "min_acceptance_trust_entry_delta", "max_acceptance_trust_entry_delta",
    "min_acceptance_entry_delta", "max_acceptance_entry_delta",
    "min_receiver_entry_delta", "max_receiver_entry_delta",
    "min_trust_entry_delta", "max_trust_entry_delta",
    "min_generation_delta", "max_generation_delta",
    "min_segment_delta", "max_segment_delta",
    "allowed_previous_acceptance_trust_state_ids",
    "allowed_previous_acceptance_trust_checkpoint_ids",
    "allowed_previous_acceptance_state_ids",
    "allowed_previous_acceptance_checkpoint_ids",
    "allowed_previous_receiver_state_ids",
    "allowed_previous_receiver_checkpoint_ids",
    "allowed_previous_trust_state_ids",
    "allowed_previous_trust_checkpoint_ids",
    "require_single_step",
}


class AuditTrustReceiverAcceptanceTrustAdmissionError(ValueError):
    """Raised when an acceptance-trust handoff policy or evaluation is unsafe."""

    def __init__(self, message: str, *, rule_id: str = "ABM000") -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and rule_id.startswith("ARA") and len(rule_id) == 6:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id


def _load_isolated_core() -> ModuleType:
    source = Path(__file__).with_name("agent_audit_trust_receiver_admission.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_acceptance_trust_admission_core", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceTrustAdmissionError(
            "unable to load reviewed receiver-admission engine", rule_id="ABM000"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_core = _load_isolated_core()
_core.__doc__ = __doc__
_core.AuditTrustReceiverAdmissionError = AuditTrustReceiverAcceptanceTrustAdmissionError
_core.AuditTrustReceiverBundleError = AuditTrustReceiverAcceptanceTrustBundleError
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
            "min_acceptance_trust_entries": 1,
            "max_acceptance_trust_entries": 1_000_000,
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
            "allowed_acceptance_trust_state_ids": [],
            "allowed_acceptance_trust_checkpoint_ids": [],
            "allowed_acceptance_state_ids": [],
            "allowed_acceptance_checkpoint_ids": [],
            "allowed_head_acceptance_bundle_ids": [],
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
            "required_acceptance_bundle_ids": [],
            "allowed_acceptance_bundle_ids": [],
            "require_anchor": False,
            "require_head": True,
        },
        "transition": {
            "allowed_relations": ["right-descendant"],
            "min_acceptance_trust_entry_delta": 1,
            "max_acceptance_trust_entry_delta": 1_000_000,
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
            "allowed_previous_acceptance_trust_state_ids": [],
            "allowed_previous_acceptance_trust_checkpoint_ids": [],
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
    root = _core._exact(value, POLICY_FIELDS, "acceptance-trust admission policy")
    if root["version"] != POLICY_VERSION:
        raise AuditTrustReceiverAcceptanceTrustAdmissionError(
            f"acceptance-trust admission policy version must be {POLICY_VERSION}"
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
        "candidate": {},
        "selection": {
            "required_sequences": _core._integers(
                selection["required_sequences"], "selection.required_sequences"
            ),
            "allowed_sequences": _core._integers(
                selection["allowed_sequences"], "selection.allowed_sequences"
            ),
            "required_acceptance_bundle_ids": _core._strings(
                selection["required_acceptance_bundle_ids"],
                "selection.required_acceptance_bundle_ids", hashes=True,
            ),
            "allowed_acceptance_bundle_ids": _core._strings(
                selection["allowed_acceptance_bundle_ids"],
                "selection.allowed_acceptance_bundle_ids", hashes=True,
            ),
            "require_anchor": _core._boolean(
                selection["require_anchor"], "selection.require_anchor"
            ),
            "require_head": _core._boolean(
                selection["require_head"], "selection.require_head"
            ),
        },
        "transition": {},
    }

    for name in (
        "acceptance_trust_entries", "acceptance_entries", "receiver_entries",
        "trust_entries", "generation", "segment_count",
    ):
        normalized["candidate"][f"min_{name}"] = _core._integer(
            candidate[f"min_{name}"], f"candidate.min_{name}", 1
        )
        normalized["candidate"][f"max_{name}"] = _core._integer(
            candidate[f"max_{name}"], f"candidate.max_{name}", 1
        )

    candidate_hash_fields = (
        "allowed_acceptance_trust_state_ids",
        "allowed_acceptance_trust_checkpoint_ids",
        "allowed_acceptance_state_ids",
        "allowed_acceptance_checkpoint_ids",
        "allowed_head_acceptance_bundle_ids",
        "allowed_head_receiver_bundle_ids",
        "allowed_head_trust_handoff_ids",
        "allowed_receiver_state_ids",
        "allowed_receiver_checkpoint_ids",
        "allowed_trust_state_ids",
        "allowed_trust_checkpoint_ids",
    )
    for field in candidate_hash_fields:
        normalized["candidate"][field] = _core._strings(
            candidate[field], f"candidate.{field}", hashes=True
        )

    normalized["transition"]["allowed_relations"] = _core._strings(
        transition["allowed_relations"], "transition.allowed_relations",
        allowed=ALLOWED_RELATIONS, require_nonempty=True,
    )
    for name in (
        "acceptance_trust_entry_delta", "acceptance_entry_delta",
        "receiver_entry_delta", "trust_entry_delta", "generation_delta",
    ):
        normalized["transition"][f"min_{name}"] = _core._integer(
            transition[f"min_{name}"], f"transition.min_{name}", 1
        )
        normalized["transition"][f"max_{name}"] = _core._integer(
            transition[f"max_{name}"], f"transition.max_{name}", 1
        )
    normalized["transition"]["min_segment_delta"] = _core._integer(
        transition["min_segment_delta"], "transition.min_segment_delta"
    )
    normalized["transition"]["max_segment_delta"] = _core._integer(
        transition["max_segment_delta"], "transition.max_segment_delta"
    )
    previous_hash_fields = (
        "allowed_previous_acceptance_trust_state_ids",
        "allowed_previous_acceptance_trust_checkpoint_ids",
        "allowed_previous_acceptance_state_ids",
        "allowed_previous_acceptance_checkpoint_ids",
        "allowed_previous_receiver_state_ids",
        "allowed_previous_receiver_checkpoint_ids",
        "allowed_previous_trust_state_ids",
        "allowed_previous_trust_checkpoint_ids",
    )
    for field in previous_hash_fields:
        normalized["transition"][field] = _core._strings(
            transition[field], f"transition.{field}", hashes=True
        )
    normalized["transition"]["require_single_step"] = _core._boolean(
        transition["require_single_step"], "transition.require_single_step"
    )

    if normalized["bundle"]["min_proofs"] > normalized["bundle"]["max_proofs"]:
        raise AuditTrustReceiverAcceptanceTrustAdmissionError(
            "bundle.min_proofs must not exceed bundle.max_proofs"
        )
    for section, names in (
        ("candidate", (
            "acceptance_trust_entries", "acceptance_entries", "receiver_entries",
            "trust_entries", "generation", "segment_count",
        )),
        ("transition", (
            "acceptance_trust_entry_delta", "acceptance_entry_delta",
            "receiver_entry_delta", "trust_entry_delta", "generation_delta",
            "segment_delta",
        )),
    ):
        for name in names:
            if normalized[section][f"min_{name}"] > normalized[section][f"max_{name}"]:
                raise AuditTrustReceiverAcceptanceTrustAdmissionError(
                    f"{section}.{name} minimum must not exceed maximum"
                )

    required_sequences = set(normalized["selection"]["required_sequences"])
    allowed_sequences = set(normalized["selection"]["allowed_sequences"])
    if allowed_sequences and not required_sequences <= allowed_sequences:
        raise AuditTrustReceiverAcceptanceTrustAdmissionError(
            "required sequences must be a subset of allowed sequences"
        )
    required_bundles = set(normalized["selection"]["required_acceptance_bundle_ids"])
    allowed_bundles = set(normalized["selection"]["allowed_acceptance_bundle_ids"])
    if allowed_bundles and not required_bundles <= allowed_bundles:
        raise AuditTrustReceiverAcceptanceTrustAdmissionError(
            "required acceptance bundle IDs must be a subset of allowed acceptance bundle IDs"
        )
    return normalized


def policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(validate_policy(policy))).hexdigest()


def _decision_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"audit-trust-receiver-acceptance-trust-admission-decision-v1\x00"
        + canonical_json(payload)
    ).hexdigest()


def _policy_outside_bundle(policy_path: Path, bundle_dir: Path) -> None:
    policy = Path(policy_path).resolve(strict=False)
    bundle = Path(bundle_dir).resolve(strict=False)
    try:
        policy.relative_to(bundle)
    except ValueError:
        return
    raise AuditTrustReceiverAcceptanceTrustAdmissionError(
        "acceptance-trust admission policy must remain outside the handoff bundle"
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
    except AuditTrustReceiverAcceptanceTrustBundleError as exc:
        raise AuditTrustReceiverAcceptanceTrustAdmissionError(
            f"acceptance-trust handoff verification failed ({exc.rule_id}): {exc}"
        ) from exc
    if manifest["bundle_id"] != verified["bundle_id"]:
        raise AuditTrustReceiverAcceptanceTrustAdmissionError(
            "acceptance-trust handoff manifest identity changed after verification"
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
    acceptance_bundle_ids = [entry["handoff_bundle_id"] for entry in entries]

    if verified["bundle_type"] not in bundle_policy["allowed_types"]:
        _core._deny(violations, "ABM001", "acceptance-trust handoff type is not allowed", bundle_type=verified["bundle_type"])
    if verified["files"] > bundle_policy["max_files"] or verified["bytes"] > bundle_policy["max_bytes"]:
        _core._deny(violations, "ABM002", "acceptance-trust handoff size exceeds policy", files=verified["files"], max_files=bundle_policy["max_files"], bytes=verified["bytes"], max_bytes=bundle_policy["max_bytes"])
    if not bundle_policy["min_proofs"] <= verified["proof_count"] <= bundle_policy["max_proofs"]:
        _core._deny(violations, "ABM003", "acceptance-trust proof count is outside policy", actual=verified["proof_count"], minimum=bundle_policy["min_proofs"], maximum=bundle_policy["max_proofs"])

    counts = (
        (candidate["entry_count"], "acceptance_trust_entries", "ABM004"),
        (head["entry_count"], "acceptance_entries", "ABM005"),
        (head["receiver_entry_count"], "receiver_entries", "ABM005"),
        (head["trust_entry_count"], "trust_entries", "ABM005"),
        (head["generation"], "generation", "ABM006"),
        (head["segment_count"], "segment_count", "ABM006"),
    )
    for actual, name, rule_id in counts:
        if not candidate_policy[f"min_{name}"] <= actual <= candidate_policy[f"max_{name}"]:
            _core._deny(violations, rule_id, f"candidate {name.replace('_', ' ')} is outside policy", actual=actual)

    outer_identities = (
        (candidate["state_id"], candidate_policy["allowed_acceptance_trust_state_ids"], "acceptance-trust state ID"),
        (candidate["checkpoint_id"], candidate_policy["allowed_acceptance_trust_checkpoint_ids"], "acceptance-trust checkpoint ID"),
    )
    for actual, allowed, label in outer_identities:
        if not _core._allowed(actual, allowed):
            _core._deny(violations, "ABM007", f"candidate {label} is not allowed", identity=actual)

    nested_identities = (
        (head["state_id"], candidate_policy["allowed_acceptance_state_ids"], "acceptance state ID"),
        (head["checkpoint_id"], candidate_policy["allowed_acceptance_checkpoint_ids"], "acceptance checkpoint ID"),
        (head["handoff_bundle_id"], candidate_policy["allowed_head_acceptance_bundle_ids"], "head acceptance bundle ID"),
        (head["head_receiver_bundle_id"], candidate_policy["allowed_head_receiver_bundle_ids"], "head receiver bundle ID"),
        (head["trust_handoff_id"], candidate_policy["allowed_head_trust_handoff_ids"], "head trust handoff ID"),
        (head["receiver_state_id"], candidate_policy["allowed_receiver_state_ids"], "receiver state ID"),
        (head["receiver_checkpoint_id"], candidate_policy["allowed_receiver_checkpoint_ids"], "receiver checkpoint ID"),
        (head["trust_state_id"], candidate_policy["allowed_trust_state_ids"], "trust state ID"),
        (head["trust_checkpoint_id"], candidate_policy["allowed_trust_checkpoint_ids"], "trust checkpoint ID"),
    )
    for actual, allowed, label in nested_identities:
        if not _core._allowed(actual, allowed):
            _core._deny(violations, "ABM008", f"candidate {label} is not allowed", identity=actual)

    selected_sequences = set(sequences)
    required_sequences = set(selection_policy["required_sequences"])
    allowed_sequences = set(selection_policy["allowed_sequences"])
    if not required_sequences <= selected_sequences:
        _core._deny(violations, "ABM009", "required acceptance-trust sequences are missing", missing=sorted(required_sequences - selected_sequences))
    if allowed_sequences and not selected_sequences <= allowed_sequences:
        _core._deny(violations, "ABM009", "selected acceptance-trust sequences exceed the allowlist", unexpected=sorted(selected_sequences - allowed_sequences))
    selected_bundles = set(acceptance_bundle_ids)
    required_bundles = set(selection_policy["required_acceptance_bundle_ids"])
    allowed_bundles = set(selection_policy["allowed_acceptance_bundle_ids"])
    if not required_bundles <= selected_bundles:
        _core._deny(violations, "ABM010", "required acceptance bundle IDs are missing", missing=sorted(required_bundles - selected_bundles))
    if allowed_bundles and not selected_bundles <= allowed_bundles:
        _core._deny(violations, "ABM010", "selected acceptance bundle IDs exceed the allowlist", unexpected=sorted(selected_bundles - allowed_bundles))
    if selection_policy["require_anchor"] and 1 not in selected_sequences:
        _core._deny(violations, "ABM011", "acceptance-trust anchor proof is required")
    if selection_policy["require_head"] and candidate["entry_count"] not in selected_sequences:
        _core._deny(violations, "ABM011", "candidate acceptance-trust head proof is required")

    previous = verified["previous"]
    deltas = {
        "acceptance_trust_entry_delta": None,
        "acceptance_entry_delta": None,
        "receiver_entry_delta": None,
        "trust_entry_delta": None,
        "generation_delta": None,
        "segment_delta": None,
    }
    if verified["bundle_type"] == "transition":
        relation = verified["consistency"]["relation"]
        if relation not in transition_policy["allowed_relations"]:
            _core._deny(violations, "ABM012", "acceptance-trust consistency relation is not allowed", relation=relation)
        previous_head = previous["head"]
        deltas = {
            "acceptance_trust_entry_delta": candidate["entry_count"] - previous["entry_count"],
            "acceptance_entry_delta": head["entry_count"] - previous_head["entry_count"],
            "receiver_entry_delta": head["receiver_entry_count"] - previous_head["receiver_entry_count"],
            "trust_entry_delta": head["trust_entry_count"] - previous_head["trust_entry_count"],
            "generation_delta": head["generation"] - previous_head["generation"],
            "segment_delta": head["segment_count"] - previous_head["segment_count"],
        }
        outer_delta = deltas["acceptance_trust_entry_delta"]
        if not transition_policy["min_acceptance_trust_entry_delta"] <= outer_delta <= transition_policy["max_acceptance_trust_entry_delta"]:
            _core._deny(violations, "ABM013", "acceptance-trust entry delta is outside policy", actual=outer_delta)
        for name in (
            "acceptance_entry_delta", "receiver_entry_delta", "trust_entry_delta",
            "generation_delta", "segment_delta",
        ):
            actual = deltas[name]
            if not transition_policy[f"min_{name}"] <= actual <= transition_policy[f"max_{name}"]:
                _core._deny(violations, "ABM014", f"{name.replace('_', ' ')} is outside policy", actual=actual)
        previous_identities = (
            (previous["state_id"], transition_policy["allowed_previous_acceptance_trust_state_ids"], "previous acceptance-trust state ID"),
            (previous["checkpoint_id"], transition_policy["allowed_previous_acceptance_trust_checkpoint_ids"], "previous acceptance-trust checkpoint ID"),
            (previous_head["state_id"], transition_policy["allowed_previous_acceptance_state_ids"], "previous acceptance state ID"),
            (previous_head["checkpoint_id"], transition_policy["allowed_previous_acceptance_checkpoint_ids"], "previous acceptance checkpoint ID"),
            (previous_head["receiver_state_id"], transition_policy["allowed_previous_receiver_state_ids"], "previous receiver state ID"),
            (previous_head["receiver_checkpoint_id"], transition_policy["allowed_previous_receiver_checkpoint_ids"], "previous receiver checkpoint ID"),
            (previous_head["trust_state_id"], transition_policy["allowed_previous_trust_state_ids"], "previous trust state ID"),
            (previous_head["trust_checkpoint_id"], transition_policy["allowed_previous_trust_checkpoint_ids"], "previous trust checkpoint ID"),
        )
        for actual, allowed, label in previous_identities:
            if not _core._allowed(actual, allowed):
                _core._deny(violations, "ABM015", f"{label} is not allowed", identity=actual)
        if transition_policy["require_single_step"] and outer_delta != 1:
            _core._deny(violations, "ABM016", "acceptance-trust transition must append exactly one entry", actual=outer_delta)

    policy_hash = policy_sha256(normalized_policy)
    identity = {
        "bundle_id": verified["bundle_id"],
        "bundle_type": verified["bundle_type"],
        "candidate_acceptance_trust_checkpoint_id": candidate["checkpoint_id"],
        "candidate_acceptance_trust_state_id": candidate["state_id"],
        "previous_acceptance_trust_checkpoint_id": previous["checkpoint_id"] if previous else None,
        "previous_acceptance_trust_state_id": previous["state_id"] if previous else None,
    }
    evidence = {
        "files": verified["files"],
        "bytes": verified["bytes"],
        "proof_count": verified["proof_count"],
        "selected_sequences": sequences,
        "selected_acceptance_bundle_ids": acceptance_bundle_ids,
        "candidate_acceptance_trust_entries": candidate["entry_count"],
        "candidate_acceptance_entries": head["entry_count"],
        "candidate_receiver_entries": head["receiver_entry_count"],
        "candidate_trust_entries": head["trust_entry_count"],
        "candidate_generation": head["generation"],
        "candidate_segment_count": head["segment_count"],
        "head_acceptance_bundle_id": head["handoff_bundle_id"],
        "head_receiver_bundle_id": head["head_receiver_bundle_id"],
        "head_trust_handoff_id": head["trust_handoff_id"],
        **deltas,
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
        "bundle_module": "agent_audit_trust_receiver_acceptance_trust_bundle.py",
        "manifest_name": MANIFEST_NAME,
        "rule_prefix": RULE_PREFIX,
        "policy_version": POLICY_VERSION,
        "candidate_fields": sorted(CANDIDATE_FIELDS),
        "transition_fields": sorted(TRANSITION_FIELDS),
    }


if __name__ == "__main__":
    raise SystemExit(main())
