# Security audit: Python distribution

Task 6 introduced the installable wheel and console scripts. Tasks 14 through 42 expand the reviewed runtime boundary through audit, trust, receiver, acceptance, consumer-state, checkpoint, consistency, bundle, admission, and receiver-persistence layers while keeping the package dependency-free.

## Dependency boundary

- The project declares no runtime dependencies.
- Python 3.11 or newer is required.
- The build backend is used only to construct the artifact; runtime commands remain standard-library-only.
- External agent repositories are never copied into the wheel.

## Version integrity

- `agent_version.py` is the single version source.
- Package metadata reads that attribute dynamically.
- All installed console aliases display the same version where a version flag is part of their interface.
- Unit tests reject version drift between the wrapper and package metadata.

## Wheel contents

`scripts/validate_wheel.py` derives the exact reviewed boundary from canonical `pyproject.toml` metadata and enforces thirty-nine modules. The newest reviewed modules are:

- `agent_audit_trust_receiver_acceptance_trust_admission.py`;
- `agent_audit_trust_receiver_acceptance_trust_receiver.py`.

The admission module fully verifies Task 40 handoffs before applying consumer-owned policy. The receiver module records admitted handoffs in an independently pinned hash-chained state with exact outer and nested acceptance/receiver/trust continuity. Both adapters load reviewed engines in private namespaces and retain independent `ABM` and `ABN` diagnostics without mutating prior public modules.

The validator rejects:

- undeclared or unexpected Python source;
- missing reviewed modules;
- runtime dependency declarations;
- multiple `.dist-info` directories;
- unsafe archive paths;
- tests, workflow metadata, integration locks, environment files, audit data, generated states, checkpoints, inclusion or consistency proofs, bundles, policies, decisions, lock files, baselines, and reports;
- wrong project name, version, Python requirement, or console entry points.

## Installed command boundary

The exact reviewed command set contains fifty-eight aliases. The newest pairs are:

- `basit-agent-audit-trust-receiver-acceptance-trust-admission` and `agent-audit-trust-receiver-acceptance-trust-admission`;
- `basit-agent-audit-trust-receiver-acceptance-trust-receiver` and `agent-audit-trust-receiver-acceptance-trust-receiver`.

The release-admission policy uses the same exact package metadata boundary, preventing validator and consumer policy drift.

## Integration and data boundaries

External integrations remain source-checkout-only. Generated audit logs, archives, catalogs, states, checkpoints, proofs, handoff bundles, policies, decisions, freshness pins, sidecar locks, and CI evidence never enter the wheel.

## Release boundary

Pull-request and push CI build and validate the wheel but do not publish it. No registry token, signing key, or OIDC request is used.

## Installation verification

CI builds and validates wheels on Python 3.11 and 3.12, installs without dependencies outside the source checkout, and validates all fifty-eight aliases. The newest package smoke creates retained and candidate acceptance-trust states and portable handoffs, initializes the installed consumer policy, anchors a pinned acceptance-trust receiver through one alias, advances through the compatibility alias, and re-verifies the current-head handoff with mode-`0600` state storage.
