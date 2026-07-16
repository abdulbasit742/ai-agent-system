# Security audit: Python distribution

Task 6 introduced the installable wheel and console scripts. Tasks 14 through 37 expand the reviewed runtime boundary for strict audit integrity, typed event admission, segment rotation, canonical catalogs, portable catalog checkpoints, compact catalog consistency proofs, portable audit evidence bundles, consumer-owned bundle admission, pinned audit bundle trust states, portable audit trust checkpoints, compact audit trust consistency proofs, portable trust handoff bundles, consumer-owned trust handoff admission, pinned receiver states, portable receiver checkpoints, compact receiver consistency proofs, portable receiver checkpoint bundles, consumer-owned receiver bundle admission, pinned receiver-bundle acceptance states, portable acceptance-state checkpoints, compact acceptance consistency proofs, portable acceptance checkpoint bundles, consumer-owned acceptance-bundle admission, and pinned acceptance-bundle trust states while keeping the package dependency-free.

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

`scripts/validate_wheel.py` enforces an exact thirty-four-module allowlist:

- `agent_audit.py`
- `agent_audit_admission.py`
- `agent_audit_bundle.py`
- `agent_audit_catalog.py`
- `agent_audit_checkpoint.py`
- `agent_audit_consistency.py`
- `agent_audit_events.py`
- `agent_audit_segments.py`
- `agent_audit_trust.py`
- `agent_audit_trust_admission.py`
- `agent_audit_trust_checkpoint.py`
- `agent_audit_trust_consistency.py`
- `agent_audit_trust_bundle.py`
- `agent_audit_trust_bundle_core.py`
- `agent_audit_trust_receiver.py`
- `agent_audit_trust_receiver_acceptance.py`
- `agent_audit_trust_receiver_acceptance_admission.py`
- `agent_audit_trust_receiver_acceptance_bundle.py`
- `agent_audit_trust_receiver_acceptance_checkpoint.py`
- `agent_audit_trust_receiver_acceptance_consistency.py`
- `agent_audit_trust_receiver_acceptance_trust.py`
- `agent_audit_trust_receiver_admission.py`
- `agent_audit_trust_receiver_bundle.py`
- `agent_audit_trust_receiver_checkpoint.py`
- `agent_audit_trust_receiver_consistency.py`
- `agent_baseline.py`
- `agent_changed_lines.py`
- `agent_cli.py`
- `agent_config.py`
- `agent_git.py`
- `agent_policy.py`
- `agent_system.py`
- `agent_system_legacy.py`
- `agent_version.py`

The audit, trust, receiver, acceptance, checkpoint, consistency, bundle, and admission modules preserve strict canonical schemas, external pinning, immutable artifacts, and consumer-owned authorization. `agent_audit_trust_receiver_acceptance_trust.py` loads the reviewed acceptance-state engine in an isolated namespace, binds task-35 bundle verification and task-36 admission decisions, applies independent `ABT001`–`ABT010` rules, and uses distinct entry/state hash domains without mutating the original acceptance-state module. The small `agent_system.py` wrapper combines audit controls while `agent_system_legacy.py` retains the reviewed scanner, baseline, policy, Git-scope, guard, and dispatcher implementation.

The validator rejects:

- undeclared or unexpected Python source;
- missing reviewed modules;
- runtime dependency declarations;
- multiple `.dist-info` directories;
- unsafe archive paths;
- tests, action metadata, integration locks, environment files, audit-log data, segment archives, catalogs, checkpoints, inclusion/consistency proofs, evidence or trust handoff bundles, receiver or acceptance checkpoint bundles, admission policies, decisions, trust states, receiver states, acceptance states, acceptance-bundle trust states, lock files, baselines, and generated reports;
- wrong project name, version, Python requirement, or console entry points.

## Installed command boundary

The exact reviewed command set contains forty-eight aliases. The `basit-agent-*` surface adds `basit-agent-audit-trust-receiver-acceptance-trust`; the corresponding `agent-audit-trust-receiver-acceptance-trust` compatibility alias exposes the same lifecycle.

The release-admission default policy uses the same exact module and command allowlists as the wheel validator, preventing package validation and consumer policy from drifting independently.

## Integration boundary

The installed wheel does not contain `integrations.lock.json` or cloned external projects. The `doctor` and `run` commands therefore fail closed with a clear source-checkout requirement. This prevents a package build from silently changing or vendoring reviewed integration pins.

## Audit-data boundary

Audit runtime code is included, but audit JSON Lines files, segment directories, manifests, catalog files, checkpoint files, inclusion/consistency proof files, evidence bundle directories, trust handoff directories, receiver or acceptance checkpoint bundle directories, admission policies, decisions, trust-state files, receiver-state files, acceptance-state files, acceptance-bundle trust-state files, lock sidecars, recovery copies, reports, and CI evidence are not package source. Raw paths, command arrays, and Git refs are normalized to domain-separated references before new audit records are stored.

Trust handoff, receiver bundle, and acceptance bundle manifests contain only bounded checkpoint references, authenticated entry evidence, exact roles, sizes, digests, policy hashes, decision IDs, counts, Merkle roots, compact frontiers, and stable diagnostics. The package does not contain generated evidence, consumer policies, decisions, trust histories, or externally retained freshness pins.

## Release boundary

Ordinary pull-request and push CI builds and validates the wheel but does not publish it. Publication requires a separate explicit release workflow and independent review. No package registry token is read by the current workflow.

## Installation verification

CI builds a wheel on Python 3.11 and 3.12, validates the exact archive and script boundary, installs it into an isolated virtual environment without dependencies, and executes from outside the source checkout. Dedicated package workflows exercise all forty-eight console aliases. The acceptance-trust package smoke constructs real acceptance histories and bundles through installed modules, initializes and advances the pinned trust state through both installed aliases, and verifies the current head bundle on each supported Python version.
