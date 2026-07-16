# Ordered development workflow: 1–400

Each user-provided number triggers one autonomous, reviewable repository improvement.

## Rules

1. Read the current `main` state before selecting work.
2. Choose the highest-value improvement that fits the existing architecture.
3. Preserve all working features and repository safety boundaries.
4. Implement one coherent vertical slice rather than disconnected files.
5. Add or update regression tests and documentation.
6. Run unit tests, compilation, configuration validation, policy validation, baseline validation, Git scope validation, action validation, package validation, release-evidence validation, supply-chain evidence validation, release-admission validation, release-transition validation, release-trust-state validation, release-checkpoint validation, self-scan, and command-guard checks.
7. Commit only after verification succeeds.
8. Update `development-progress.json` with the completed number, outcome, files, and verification evidence.
9. Continue sequentially; do not skip or silently redo a number.

## Current state

- Task 1 introduced configurable scanner rule packs with a mandatory, non-disableable core security baseline.
- Task 2 introduced exact-fingerprint repository baselines and new-findings-only CI gating with integrity and control-scope validation.
- Task 3 introduced Git-aware merge-base changed-file gates with safe path parsing and changed-scope baseline classification.
- Task 4 introduced added-line-only gates with separate new-side finding scope and old-side baseline-resolution scope.
- Task 5 introduced a first-party, read-only GitHub Action with preview-free annotations, JSON/SARIF artifacts, immutable pull-request refs, workspace path containment, and composite-action CI validation.
- Task 6 introduced an installable dependency-free Python wheel with canonical versioning, reviewed console entry points, exact archive validation, isolated installation tests, and a fail-closed source-only integration boundary.
- Task 7 introduced deterministic release-evidence bundles with byte-for-byte wheel comparison, exact source identity, canonical manifests, SHA-256 checksums, tamper detection, and a read-only non-publishing CI gate.
- Task 8 introduced deterministic SPDX 2.3 SBOMs and unsigned in-toto/SLSA-style provenance that are manifest-bound, checksum-covered, and semantically regenerated from each bundled wheel during verification.
- Task 9 introduced a consumer-owned, versioned release-admission policy with canonical policy hashing, exact expected source identity, stable `ADMxxx` denials, and distinct admitted, denied, and invalid exit semantics.
- Task 10 introduced deterministic comparison of fully verified previous and candidate bundles, caller-pinned trust anchors, stable `TRNxxx` rollback/replay controls, module/interface/dependency/license change analysis, and read-only transition CI.
- Task 11 introduced canonical hash-chained consumer trust states with externally retained state IDs, exact anchor/head binding, accepted-transition recording, duplicate-release prevention, atomic lock-coordinated updates, and stale/fork/tamper rejection.
- Task 12 introduced canonical unsigned Merkle checkpoints, portable release inclusion proofs, externally pinned checkpoint IDs, immutable proof artifacts, and stable rollback/fork lineage diagnostics.
