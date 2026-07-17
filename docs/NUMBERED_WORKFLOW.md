# Ordered development workflow: 1–400

Each user-provided number triggers one autonomous, reviewable repository improvement.

## Rules

1. Read the current `main` state before selecting work.
2. Choose the highest-value improvement that fits the existing architecture.
3. Preserve all working features and repository safety boundaries.
4. Implement one coherent vertical slice rather than disconnected files.
5. Add or update regression tests and documentation.
6. Run unit tests, compilation, configuration validation, policy validation, baseline validation, Git scope validation, action validation, package validation, all audit/trust/receiver/acceptance state, checkpoint, consistency, bundle, admission, and nested receiver-state workflows including receiver-acceptance-trust handoff and pinned-receiver validation, release-evidence validation, supply-chain evidence validation, release-admission validation, release-transition validation, release-trust-state validation, release-checkpoint validation, release-consistency validation, self-scan, and command-guard checks.
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
- Task 8 introduced deterministic SPDX 2.3 JSON SBOMs and unsigned in-toto/SLSA-style provenance that are manifest-bound, checksum-covered, and semantically regenerated from each bundled wheel during verification.
- Task 9 introduced a consumer-owned, versioned release-admission policy with canonical policy hashing, exact expected source identity, stable `ADMxxx` denials, and distinct admitted, denied, and invalid exit semantics.
- Task 10 introduced deterministic comparison of fully verified previous and candidate bundles, caller-pinned trust anchors, stable `TRNxxx` rollback/replay controls, module/interface/dependency/license change analysis, and read-only transition CI.
- Task 11 introduced canonical hash-chained consumer trust states with externally retained state IDs, exact anchor/head binding, accepted-transition recording, duplicate-release prevention, atomic lock-coordinated updates, and stale/fork/tamper rejection.
- Task 12 introduced canonical unsigned Merkle checkpoints, portable release inclusion proofs, externally pinned checkpoint IDs, immutable proof artifacts, and stable rollback/fork lineage diagnostics.
- Task 13 introduced compact append-only Merkle consistency proofs that verify retained-to-candidate checkpoint continuity with canonical `O(log n)` hash frontiers, proof-only verification, and stable rollback/fork denials.
- Task 14 introduced strict canonical audit-log records, complete-chain append preflight, stable `AUDxxx` diagnostics, external freshness pins, immutable verified-prefix recovery copies, and corrupt-log command blocking.
- Task 15 introduced versioned typed audit-event schemas, bounded generic events, privacy-preserving references, typed coverage enforcement, and stable `AUD022`–`AUD024` diagnostics.
- Task 16 introduced atomic audit segment rotation with canonical sealed manifests, exact archived bytes, typed active-log continuity records, complete ordered-chain verification, externally pinned latest segment IDs, and stable `AUS001`–`AUS008` diagnostics.
- Task 17 introduced canonical audit segment catalogs with automatic sealed-directory discovery, exact catalog-to-segment binding, externally pinned catalog IDs, predecessor-linked generations, complete-coverage checks, and right-descendant-only synchronization under stable `AUC001`–`AUC010` diagnostics.
- Task 18 introduced portable audit catalog Merkle checkpoints and compact per-segment inclusion proofs with externally pinned checkpoint IDs, proof-only verification, optional sealed-segment binding, immutable artifacts, and stable `AUP001`–`AUP010` diagnostics.
- Task 19 introduced compact append-only consistency proofs between externally pinned audit catalog checkpoints with canonical logarithmic hash frontiers, proof-only root reconstruction, direct predecessor and generation controls, and stable `AUK009`–`AUK011` rollback/fork/regression denials.
- Task 20 introduced portable snapshot and transition audit evidence bundles with canonical manifests, exact file boundaries, external bundle/checkpoint pins, proof-only offline verification, optional sealed-segment inclusion, immutable output directories, and stable `AUB001`–`AUB012` diagnostics.
- Task 21 introduced consumer-owned audit bundle admission policies with verify-before-policy ordering, deterministic policy hashes and decision IDs, and stable `AUA001`–`AUA016` denials.
- Task 22 introduced consumer-owned pinned audit bundle trust states with snapshot initialization, transition advancement, external freshness pins, replay protection, and stable `ATS001`–`ATS010` diagnostics.
- Task 23 introduced portable audit trust-state Merkle checkpoints and compact inclusion proofs with proof-only verification and stable lineage denials.
- Task 24 introduced compact audit trust consistency proofs with independent root reconstruction and stable rollback/fork denials.
- Task 25 introduced portable exact-boundary audit trust handoff bundles with mandatory head proofs and offline verification.
- Task 26 introduced consumer-owned audit trust handoff admission policies with deterministic decisions and stable denials.
- Task 27 introduced a pinned audit trust receiver state with atomic advancement and replay/rollback protection.
- Task 28 introduced portable receiver-state Merkle checkpoints and per-handoff inclusion proofs.
- Task 29 introduced compact consistency proofs between externally pinned receiver checkpoints.
- Task 30 introduced portable exact-boundary receiver checkpoint bundles.
- Task 31 introduced consumer-owned receiver checkpoint bundle admission policies.
- Task 32 introduced a pinned receiver-bundle acceptance state.
- Task 33 introduced portable acceptance-state Merkle checkpoints and inclusion proofs.
- Task 34 introduced compact consistency proofs between acceptance checkpoints.
- Task 35 introduced portable exact-boundary receiver-acceptance checkpoint bundles.
- Task 36 introduced consumer-owned receiver-acceptance bundle admission policies.
- Task 37 introduced a pinned receiver-acceptance trust state.
- Task 38 introduced portable receiver-acceptance trust-state Merkle checkpoints and inclusion proofs.
- Task 39 introduced compact consistency proofs between receiver-acceptance trust checkpoints.
- Task 40 introduced portable exact-boundary receiver-acceptance trust handoff bundles with mandatory candidate-head inclusion proofs, optional retained-checkpoint consistency evidence, external pins, offline verification, immutable publication, and stable `ABB001`–`ABB012` diagnostics.
- Task 41 introduced consumer-owned receiver-acceptance trust handoff admission policies that verify complete handoffs before applying four-depth history bounds, nested identity allowlists, proof-selection controls, transition-delta constraints, canonical policy hashes, deterministic decision IDs, and stable `ABM001`–`ABM016` denials.
- Task 42 introduced a pinned consumer-owned receiver state for admitted receiver-acceptance trust handoffs with exact four-depth predecessor continuity, external freshness pins, replay/rollback protection, mode-`0600` lock-coordinated atomic updates, and stable `ABN001`–`ABN010` diagnostics.
