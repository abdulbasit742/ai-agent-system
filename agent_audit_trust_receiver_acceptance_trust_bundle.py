#!/usr/bin/env python3
"""Create and verify exact-boundary receiver-acceptance trust handoff bundles."""
from __future__ import annotations

from pathlib import Path
from types import ModuleType
from typing import Any


class AuditTrustReceiverAcceptanceTrustBundleBootstrapError(RuntimeError):
    """Raised when the reviewed bundle adapter cannot be loaded safely."""


_REPLACEMENTS = (
    ('"""Create and verify exact-boundary audit trust receiver handoff bundles."""', '"""Create and verify exact-boundary receiver-acceptance trust handoff bundles."""'),
    ('from agent_audit_trust_receiver import canonical_json as receiver_json', 'from agent_audit_trust_receiver_acceptance_trust import canonical_json as receiver_json'),
    ('from agent_audit_trust_receiver_checkpoint import (', 'from agent_audit_trust_receiver_acceptance_trust_checkpoint import ('),
    ('from agent_audit_trust_receiver_consistency import (', 'from agent_audit_trust_receiver_acceptance_trust_consistency import ('),
    ('AuditTrustReceiverCheckpointError', 'AuditTrustReceiverAcceptanceTrustCheckpointError'),
    ('AuditTrustReceiverConsistencyError', 'AuditTrustReceiverAcceptanceTrustConsistencyError'),
    ('AuditTrustReceiverBundleError', 'AuditTrustReceiverAcceptanceTrustBundleError'),
    ('audit-trust-receiver-bundle-manifest.json', 'audit-trust-receiver-acceptance-trust-bundle-manifest.json'),
    ('candidate-receiver-checkpoint.json', 'candidate-acceptance-trust-checkpoint.json'),
    ('previous-receiver-checkpoint.json', 'previous-acceptance-trust-checkpoint.json'),
    ('receiver-consistency-proof.json', 'acceptance-trust-consistency-proof.json'),
    ('candidate-receiver-checkpoint', 'candidate-acceptance-trust-checkpoint'),
    ('previous-receiver-checkpoint', 'previous-acceptance-trust-checkpoint'),
    ('receiver-consistency-proof', 'acceptance-trust-consistency-proof'),
    ('receiver-inclusion-proof', 'acceptance-trust-inclusion-proof'),
    ('proofs/receiver-entry-', 'proofs/acceptance-trust-entry-'),
    ('audit-trust-receiver-evidence-bundle-v1', 'audit-trust-receiver-acceptance-trust-evidence-bundle-v1'),
    ('"ARB', '"ABB'),
    ('receiver bundle', 'acceptance trust bundle'),
    ('receiver checkpoint', 'acceptance trust checkpoint'),
    ('receiver consistency', 'acceptance trust consistency'),
    ('receiver inclusion', 'acceptance trust inclusion'),
    ('receiver evidence', 'acceptance trust evidence'),
    ('receiver-head', 'acceptance-trust-head'),
)

_REJECTED_TOKENS = (
    'agent_audit_trust_receiver_checkpoint import',
    'agent_audit_trust_receiver_consistency import',
    'audit-trust-receiver-bundle-manifest.json',
    'candidate-receiver-checkpoint',
    'previous-receiver-checkpoint',
    'receiver-consistency-proof',
    'receiver-inclusion-proof',
    'proofs/receiver-entry-',
    '"ARB',
)


def _load_isolated_core() -> ModuleType:
    source_path = Path(__file__).with_name('agent_audit_trust_receiver_bundle.py')
    try:
        source = source_path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditTrustReceiverAcceptanceTrustBundleBootstrapError(
            f'unable to read reviewed receiver-bundle engine: {exc}'
        ) from exc
    missing = [old for old, _new in _REPLACEMENTS if old not in source]
    if missing:
        raise AuditTrustReceiverAcceptanceTrustBundleBootstrapError(
            'reviewed receiver-bundle source no longer matches the acceptance-trust adapter: '
            + ', '.join(missing)
        )
    adapted = source
    for old, new in _REPLACEMENTS:
        adapted = adapted.replace(old, new)
    leftovers = [token for token in _REJECTED_TOKENS if token in adapted]
    if leftovers:
        raise AuditTrustReceiverAcceptanceTrustBundleBootstrapError(
            'receiver-specific tokens remain after acceptance-trust adaptation: '
            + ', '.join(leftovers)
        )
    module = ModuleType('_agent_audit_trust_receiver_acceptance_trust_bundle_core')
    module.__file__ = str(source_path)
    module.__package__ = ''
    exec(compile(adapted, str(source_path), 'exec'), module.__dict__)
    return module


_core = _load_isolated_core()

AuditTrustReceiverAcceptanceTrustBundleError = _core.AuditTrustReceiverAcceptanceTrustBundleError
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
        'valid': True,
        'source': 'agent_audit_trust_receiver_bundle.py',
        'manifest_name': MANIFEST_NAME,
        'candidate_checkpoint_name': CANDIDATE_CHECKPOINT_NAME,
        'previous_checkpoint_name': PREVIOUS_CHECKPOINT_NAME,
        'consistency_name': CONSISTENCY_NAME,
        'file_roles': sorted(FILE_ROLES),
        'rule_prefix': 'ABB',
        'replacement_count': len(_REPLACEMENTS),
    }


if __name__ == '__main__':
    raise SystemExit(main())
