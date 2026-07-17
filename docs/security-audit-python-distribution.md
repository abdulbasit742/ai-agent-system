# Security audit: Python distribution

Task 6 introduced the installable wheel and console scripts. Tasks 14 through 38 expand the reviewed runtime boundary through audit, trust, receiver, acceptance, consumer-state, checkpoint, consistency, bundle, and admission layers while keeping the package dependency-free.

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

`scripts/validate_wheel.py` derives the exact reviewed boundary from canonical `pyproject.toml` metadata and enforces thirty-five modules. The newest reviewed modules are:

- `agent_audit_trust_receiver_acceptance_trust.py`
- `agent_audit_trust_receiver_acceptance_trust_checkpoint.py`

The remaining modules are the previously reviewed audit, catalog, checkpoint, consistency, bundle, admission, trust, receiver, acceptance, scanner, policy, Git-scope, CLI, and version modules.

The checkpoint module loads the reviewed receiver-checkpoint engine in a private namespace, binds the Task 37 acceptance-trust state and acceptance-bundle verifier, and emits independent `ABP001`–`ABP011` evidence without mutating prior checkpoint modules.

The validator rejects:

- undeclared or unexpected Python source;
- missing reviewed modules;
- runtime dependency declarations;
- multiple `.dist-info` directories;
- unsafe archive paths;
- tests, workflow metadata, integration locks, environment files, audit data, generated states, checkpoints, proofs, bundles, policies, decisions, lock files, baselines, and reports;
- wrong project name, version, Python requirement, or console entry points.

## Installed command boundary

The exact reviewed command set contains fifty aliases. The newest pair is:

- `basit-agent-audit-trust-receiver-acceptance-trust-checkpoint`
- `agent-audit-trust-receiver-acceptance-trust-checkpoint`

The release-admission policy uses the same exact package metadata boundary, preventing validator and consumer policy drift.

## Integration and data boundaries

External integrations remain source-checkout-only. Generated audit logs, archives, catalogs, states, checkpoints, proofs, bundles, policies, decisions, freshness pins, and CI evidence never enter the wheel.

## Release boundary

Pull-request and push CI build and validate the wheel but do not publish it. No registry token, signing key, or OIDC request is used.

## Installation verification

CI builds and validates wheels on Python 3.11 and 3.12, installs without dependencies outside the source checkout, and exercises all fifty aliases. The newest package smoke creates an acceptance-trust checkpoint and proof, deletes the complete state, and verifies the proof through both installed aliases.
