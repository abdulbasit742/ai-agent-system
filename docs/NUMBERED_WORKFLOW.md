# Ordered development workflow: 1–400

Each user-provided number triggers one autonomous, reviewable repository improvement.

## Rules

1. Read the current `main` state before selecting work.
2. Choose the highest-value improvement that fits the existing architecture.
3. Preserve all working features and repository safety boundaries.
4. Implement one coherent vertical slice rather than disconnected files.
5. Add or update regression tests and documentation.
6. Run unit tests, compilation, configuration validation, policy validation, baseline validation, Git scope validation, action validation, package validation, audit-integrity, typed-event-admission, audit-segment, audit-catalog, audit-catalog-checkpoint, audit-catalog-consistency, audit-evidence-bundle, audit-bundle-admission, audit-bundle-trust, audit-trust-checkpoint, and audit-trust-consistency validation, release-evidence validation, supply-chain evidence validation, release-admission validation, release-transition validation, release-trust-state validation, release-checkpoint validation, release-consistency validation, self-scan, and command-guard checks.
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
- Task 13 introduced compact append-only Merkle consistency proofs that verify retained-to-candidate checkpoint continuity with canonical `O(log n)` hash frontiers, proof-only verification, and stable rollback/fork denials.
- Task 14 introduced strict canonical audit-log records, complete-chain append preflight, stable `AUDxxx` diagnostics, external freshness pins, immutable verified-prefix recovery copies, and corrupt-log command blocking.
- Task 15 introduced versioned typed audit-event admission, exact reserved-event schemas, bounded generic events, privacy-preserving path/command/Git-ref digests, typed coverage enforcement, and stable `AUD022`–`AUD024` diagnostics.
- Task 16 introduced atomic audit segment rotation with canonical sealed manifests, exact archived bytes, typed active-log continuity records, complete ordered-chain verification, externally pinned latest segment IDs, and stable `AUS001`–`AUS008` diagnostics.
- Task 17 introduced canonical audit segment catalogs with automatic sealed-directory discovery, exact catalog-to-segment binding, externally pinned catalog IDs, predecessor-linked generations, complete-coverage checks, and right-descendant-only synchronization under stable `AUC001`–`AUC010` diagnostics.
- Task 18 introduced portable audit catalog Merkle checkpoints and compact per-segment inclusion proofs with externally pinned checkpoint IDs, proof-only verification, optional sealed-segment binding, immutable artifacts, and stable `AUP001`–`AUP010` diagnostics.
- Task 19 introduced compact append-only consistency proofs between externally pinned audit catalog checkpoints, canonical logarithmic hash frontiers, proof-only root reconstruction, direct predecessor and generation controls, and stable `AUK009`–`AUK011` rollback/fork/regression denials.
- Task 20 introduced portable snapshot and transition audit evidence bundles with canonical manifests, exact file boundaries, external bundle/checkpoint pins, proof-only offline verification, optional sealed-segment inclusion, immutable output directories, and stable `AUB001`–`AUB012` diagnostics.
- Task 21 introduced consumer-owned audit bundle admission policies that verify complete bundle evidence first, apply deterministic type/size/proof/sealed-evidence/catalog/selection/transition controls, emit canonical policy hashes and decision IDs, and retain stable `AUA001`–`AUA016` denials with distinct admitted, denied, and invalid outcomes.
- Task 22 introduced consumer-owned pinned audit bundle trust states with snapshot-only initialization, transition-only advancement, exact previous-head binding, domain-separated entry/state hashes, externally retained `state_id` freshness pins, replay/rollback protection, and lock-coordinated atomic updates under stable `ATS001`–`ATS010` diagnostics.
- Task 23 introduced portable audit trust-state Merkle checkpoints and compact per-bundle inclusion proofs with externally pinned checkpoint IDs, proof-only verification, optional full bundle binding, immutable evidence, and stable `ATC010` rollback and `ATC011` fork lineage denials.
- Task 24 introduced compact append-only consistency proofs between externally pinned audit trust checkpoints with canonical logarithmic frontiers, independent root reconstruction, authenticated first-transition boundaries, proof-only verification, and stable `ATK009` rollback / `ATK010` fork denials.
