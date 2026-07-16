#!/usr/bin/env python3
"""Maintain pinned consumer trust for admitted receiver-acceptance bundles."""
from __future__ import annotations

from pathlib import Path
from types import ModuleType
from typing import Any


class AuditTrustReceiverAcceptanceTrustBootstrapError(RuntimeError):
    """Raised when the reviewed acceptance-state adapter cannot load safely."""


_REPLACEMENTS = (
    (
        '"""Maintain a pinned acceptance state for admitted receiver checkpoint bundles."""',
        '"""Maintain pinned consumer trust for admitted receiver-acceptance bundles."""',
    ),
    (
        "from agent_audit_trust_receiver_admission import (",
        "from agent_audit_trust_receiver_acceptance_admission import (",
    ),
    (
        "from agent_audit_trust_receiver_bundle import (",
        "from agent_audit_trust_receiver_acceptance_bundle import (",
    ),
    ("AuditTrustReceiverAdmissionError", "AuditTrustReceiverAcceptanceAdmissionError"),
    ("AuditTrustReceiverBundleError", "AuditTrustReceiverAcceptanceBundleError"),
    ("AuditTrustReceiverAcceptanceError", "AuditTrustReceiverAcceptanceTrustError"),
    ('RULE_PREFIX = "ARS"', 'RULE_PREFIX = "ABT"'),
    ("ARS", "ABT"),
    (
        'ENTRY_DOMAIN = b"audit-trust-receiver-acceptance-entry-v1"',
        'ENTRY_DOMAIN = b"audit-trust-receiver-acceptance-trust-entry-v1"',
    ),
    (
        'STATE_DOMAIN = b"audit-trust-receiver-acceptance-state-v1"',
        'STATE_DOMAIN = b"audit-trust-receiver-acceptance-trust-state-v1"',
    ),
    ("candidate_receiver_checkpoint_id", "candidate_acceptance_checkpoint_id"),
    ("candidate_receiver_state_id", "candidate_acceptance_state_id"),
    ("previous_receiver_checkpoint_id", "previous_acceptance_checkpoint_id"),
    ("previous_receiver_state_id", "previous_acceptance_state_id"),
    ("candidate_receiver_entries", "candidate_acceptance_entries"),
    ("candidate_trust_entries", "candidate_receiver_entries"),
    ("receiver_entry_delta", "acceptance_entry_delta"),
    ('details.get("trust_entry_delta")', 'details.get("receiver_entry_delta")'),
    (
        '"head_handoff_bundle_id": verified.get("head_handoff_bundle_id")',
        '"head_receiver_bundle_id": verified.get("head_handoff_bundle_id")',
    ),
    ('"trust_checkpoint_id"', '"receiver_checkpoint_id"'),
    ('"trust_state_id"', '"receiver_state_id"'),
    ('"trust_entry_count"', '"receiver_entry_count"'),
    ("receiver acceptance", "acceptance-bundle trust"),
    ("receiver bundle", "acceptance bundle"),
    ("receiver checkpoint", "acceptance checkpoint"),
    ("receiver state", "acceptance state"),
    ("receiver entry", "acceptance entry"),
    ("underlying trust entry", "receiver entry"),
    ("receiver admission", "acceptance admission"),
)

_FORBIDDEN_AFTER_ADAPTATION = (
    "agent_audit_trust_receiver_admission import",
    "agent_audit_trust_receiver_bundle import",
    "AuditTrustReceiverAdmissionError",
    "AuditTrustReceiverBundleError",
    "AuditTrustReceiverAcceptanceError",
    "ARS",
    "candidate_receiver_checkpoint_id",
    "candidate_receiver_state_id",
    "previous_receiver_checkpoint_id",
    "previous_receiver_state_id",
    "candidate_trust_entries",
    'details.get("trust_entry_delta")',
    '"head_handoff_bundle_id": verified.get',
    '"trust_checkpoint_id"',
    '"trust_state_id"',
    '"trust_entry_count"',
)


def _load_isolated_core() -> ModuleType:
    source_path = Path(__file__).with_name("agent_audit_trust_receiver_acceptance.py")
    try:
        source = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditTrustReceiverAcceptanceTrustBootstrapError(
            f"unable to read reviewed acceptance-state engine: {exc}"
        ) from exc
    missing = [old for old, _new in _REPLACEMENTS if old not in source]
    if missing:
        raise AuditTrustReceiverAcceptanceTrustBootstrapError(
            "reviewed acceptance-state source no longer matches trust adapter: "
            + ", ".join(missing)
        )
    adapted = source
    for old, new in _REPLACEMENTS:
        adapted = adapted.replace(old, new)
    leftovers = [token for token in _FORBIDDEN_AFTER_ADAPTATION if token in adapted]
    if leftovers:
        raise AuditTrustReceiverAcceptanceTrustBootstrapError(
            "receiver-specific tokens remain after trust adaptation: "
            + ", ".join(leftovers)
        )
    module = ModuleType("_agent_audit_trust_receiver_acceptance_trust_core")
    module.__file__ = str(source_path)
    module.__package__ = ""
    exec(compile(adapted, str(source_path), "exec"), module.__dict__)
    return module


_core = _load_isolated_core()

AuditTrustReceiverAcceptanceTrustError = _core.AuditTrustReceiverAcceptanceTrustError
canonical_json = _core.canonical_json
ZERO_HASH = _core.ZERO_HASH
STATE_VERSION = _core.STATE_VERSION
ENTRY_VERSION = _core.ENTRY_VERSION
STATE_FIELDS = _core.STATE_FIELDS
ENTRY_FIELDS = _core.ENTRY_FIELDS
ADMISSION_FIELDS = _core.ADMISSION_FIELDS
EVIDENCE_FIELDS = _core.EVIDENCE_FIELDS
TRANSITION_FIELDS = _core.TRANSITION_FIELDS
HEAD_FIELDS = _core.HEAD_FIELDS
MAX_STATE_BYTES = _core.MAX_STATE_BYTES
MAX_ENTRIES = _core.MAX_ENTRIES

create_state = _core.create_state
append_transition = _core.append_transition
validate_state = _core.validate_state
load_state = _core.load_state
main = _core.main


def adapter_report() -> dict[str, Any]:
    """Return the immutable nested trust adapter contract."""
    return {
        "valid": True,
        "source": "agent_audit_trust_receiver_acceptance.py",
        "bundle_module": "agent_audit_trust_receiver_acceptance_bundle.py",
        "admission_module": "agent_audit_trust_receiver_acceptance_admission.py",
        "rule_prefix": "ABT",
        "entry_domain": "audit-trust-receiver-acceptance-trust-entry-v1",
        "state_domain": "audit-trust-receiver-acceptance-trust-state-v1",
        "evidence_fields": sorted(EVIDENCE_FIELDS),
        "transition_fields": sorted(TRANSITION_FIELDS),
        "replacement_count": len(_REPLACEMENTS),
    }


if __name__ == "__main__":
    raise SystemExit(main())
