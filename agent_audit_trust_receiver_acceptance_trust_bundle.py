#!/usr/bin/env python3
"""Create and verify exact-boundary receiver-acceptance trust handoff bundles."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import agent_audit_trust_receiver_acceptance_trust as acceptance_trust
import agent_audit_trust_receiver_acceptance_trust_checkpoint as checkpoint
import agent_audit_trust_receiver_acceptance_trust_consistency as consistency

RULE_PREFIX = "ABB"
BUNDLE_DOMAIN = b"audit-trust-receiver-acceptance-trust-evidence-bundle-v1"


class AuditTrustReceiverAcceptanceTrustBundleError(ValueError):
    """Raised when portable acceptance-trust evidence cannot be handled safely."""

    def __init__(self, message: str, *, rule_id: str = "ABB002", denied: bool = False) -> None:
        super().__init__(message)
        if isinstance(rule_id, str) and rule_id.startswith("ARB") and len(rule_id) == 6:
            rule_id = RULE_PREFIX + rule_id[3:]
        self.rule_id = rule_id
        self.denied = denied


def _load_isolated_core() -> ModuleType:
    source = Path(__file__).with_name("agent_audit_trust_receiver_bundle.py")
    spec = importlib.util.spec_from_file_location(
        "_agent_audit_trust_receiver_acceptance_trust_bundle_core", source
    )
    if spec is None or spec.loader is None:
        raise AuditTrustReceiverAcceptanceTrustBundleError(
            "unable to load reviewed receiver-bundle engine", rule_id="ABB001"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _identifier(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        BUNDLE_DOMAIN + b"\x00" + _core._manifest_bytes(payload)
    ).hexdigest()


_core = _load_isolated_core()
_core.__doc__ = __doc__
_core.receiver_json = acceptance_trust.canonical_json
_core.AuditTrustReceiverCheckpointError = (
    checkpoint.AuditTrustReceiverAcceptanceTrustCheckpointError
)
_core.AuditTrustReceiverConsistencyError = (
    consistency.AuditTrustReceiverAcceptanceTrustConsistencyError
)
_core.AuditTrustReceiverBundleError = AuditTrustReceiverAcceptanceTrustBundleError
_core.load_checkpoint = checkpoint.load_checkpoint
_core.load_proof = checkpoint.load_proof
_core.proof_matches_checkpoint = checkpoint.proof_matches_checkpoint
_core.validate_checkpoint = checkpoint.validate_checkpoint
_core.validate_proof = checkpoint.validate_proof
_core.load_consistency_proof = consistency.load_consistency_proof
_core.proof_matches_checkpoints = consistency.proof_matches_checkpoints
_core.validate_consistency_proof = consistency.validate_consistency_proof
_core.MANIFEST_NAME = "audit-trust-receiver-acceptance-trust-bundle-manifest.json"
_core.CANDIDATE_CHECKPOINT_NAME = "candidate-acceptance-trust-checkpoint.json"
_core.PREVIOUS_CHECKPOINT_NAME = "previous-acceptance-trust-checkpoint.json"
_core.CONSISTENCY_NAME = "acceptance-trust-consistency-proof.json"
_core.FILE_ROLES = {
    "candidate-acceptance-trust-checkpoint",
    "previous-acceptance-trust-checkpoint",
    "acceptance-trust-consistency-proof",
    "acceptance-trust-inclusion-proof",
}
_core._identifier = _identifier

BUNDLE_VERSION = _core.BUNDLE_VERSION
MANIFEST_NAME = _core.MANIFEST_NAME
CHECKSUMS_NAME = _core.CHECKSUMS_NAME
CANDIDATE_CHECKPOINT_NAME = _core.CANDIDATE_CHECKPOINT_NAME
PREVIOUS_CHECKPOINT_NAME = _core.PREVIOUS_CHECKPOINT_NAME
CONSISTENCY_NAME = _core.CONSISTENCY_NAME
MAX_MANIFEST_BYTES = _core.MAX_MANIFEST_BYTES
MAX_BUNDLE_FILES = _core.MAX_BUNDLE_FILES
MAX_BUNDLE_BYTES = _core.MAX_BUNDLE_BYTES
MAX_PROOFS = _core.MAX_PROOFS
FILE_ROLES = _core.FILE_ROLES

validate_manifest = _core.validate_manifest
load_manifest = _core.load_manifest
create_bundle = _core.create_bundle
verify_bundle = _core.verify_bundle
main = _core.main


def adapter_report() -> dict[str, Any]:
    return {
        "valid": True,
        "source": "agent_audit_trust_receiver_bundle.py",
        "manifest_name": MANIFEST_NAME,
        "candidate_checkpoint_name": CANDIDATE_CHECKPOINT_NAME,
        "previous_checkpoint_name": PREVIOUS_CHECKPOINT_NAME,
        "consistency_name": CONSISTENCY_NAME,
        "file_roles": sorted(FILE_ROLES),
        "rule_prefix": RULE_PREFIX,
        "bundle_domain": BUNDLE_DOMAIN.decode("ascii"),
    }


if __name__ == "__main__":
    raise SystemExit(main())
