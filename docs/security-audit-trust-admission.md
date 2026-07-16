# Security audit: audit trust handoff admission

## Security objective

Prevent a receiving consumer from treating every structurally valid audit trust handoff as authorized. The control verifies the complete handoff first, then applies an independently owned canonical policy.

## Trust boundaries

- Handoff integrity is delegated only to `agent_audit_trust_bundle.verify_bundle`.
- The policy remains outside the handoff and is identified by canonical SHA-256.
- Freshness depends on caller-supplied bundle and checkpoint pins.
- The decision ID binds the policy hash, verified identities, bounded evidence summary, and ordered violations.
- No signature, witness, transparency-log, or remote authorization claim is made.

## Fail-closed behavior

The evaluator rejects before policy processing when the handoff is malformed, unsafe, checksum-invalid, proof-invalid, checkpoint-substituted, consistency-invalid, or stale-pinned. Those cases return exit `2`; they are never converted into ordinary policy denials.

A fully verified handoff that violates policy returns exit `1`. Stable denials are:

- `ATA001`: bundle type
- `ATA002`: file/byte limits
- `ATA003`: proof-count limits
- `ATA004`: candidate trust-entry count
- `ATA005`: candidate generation
- `ATA006`: candidate segment count
- `ATA007`: candidate state/checkpoint identity
- `ATA008`: candidate head bundle/catalog identity
- `ATA009`: selected sequence requirements/allowlist
- `ATA010`: selected bundle requirements/allowlist
- `ATA011`: anchor/head proof requirements
- `ATA012`: consistency relation
- `ATA013`: trust-entry delta
- `ATA014`: generation delta
- `ATA015`: previous state/checkpoint identity
- `ATA016`: single-step transition requirement

## Input hardening

- strict UTF-8 JSON with duplicate-key and non-finite-number rejection
- exact policy schemas and version
- sorted duplicate-free arrays
- lowercase 64-character ID validation
- canonical serialization enforcement
- bounded policy size
- non-symlink regular policy files
- no-overwrite policy initialization

## Privacy and disclosure

Admission decisions contain hashes, IDs, counts, selected sequence numbers, and policy diagnostics. They do not add raw audit records, commands, paths, prompts, credentials, sealed segment bytes, complete trust states, or inclusion-proof payloads.

## Verification coverage

Regression tests cover snapshot and transition admission, every policy section, identity allowlists, selection rules, delta controls, deterministic policy/decision binding, invalid-handoff separation, canonical policy loading, overwrite refusal, and CLI exit semantics. Read-only CI also builds and installs the exact dependency-free wheel on Python 3.11 and 3.12 and evaluates a handoff outside the source checkout through both installed aliases.
