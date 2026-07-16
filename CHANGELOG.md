# Changelog

All notable public distribution changes are recorded here.

## Unreleased

- deterministic release-evidence bundles with canonical JSON manifests and SHA-256 checksums
- byte-for-byte wheel reproducibility verification using one source commit epoch
- exact source commit, package metadata, artifact size, digest, and console-command evidence
- deterministic SPDX 2.3 JSON SBOMs for every reviewed wheel
- unsigned in-toto Statement v1 provenance with a SLSA provenance v1 predicate
- per-module SHA-1/SHA-256 inventory, MIT license conclusions, source binding, and package verification code
- evidence digests, media types, and sizes bound into release manifest schema version 2
- semantic evidence regeneration that rejects modified SBOM/provenance even after manifest and checksum rewriting
- fail-closed bundle verification for tampering, extra files, symlinks, malformed checksums, and metadata drift
- versioned consumer release-admission policies with canonical policy hashes and stable `ADMxxx` denial rules
- exact expected commit, version, optional release-ID, module, command, dependency, license, checksum, SBOM, and provenance admission constraints
- distinct admitted (`0`), denied (`1`), and malformed/unverifiable (`2`) exit semantics
- verified release-to-release comparison with stable `TRNxxx` rollback, replay, mutation, interface, dependency, and license controls
- deterministic module-hash, console-command, dependency-count, and license-set change reports with canonical transition IDs
- caller-pinned previous release IDs and candidate commit/version/release identities for offline transition authorization
- canonical hash-chained consumer trust states with externally retained `state_id` rollback and fork checkpoints
- lock-coordinated atomic trust-state advancement that records only accepted transition IDs and policy hashes
- stale-pin, duplicate-release, non-canonical serialization, symlink, truncation, and tampered-history rejection
- canonical unsigned Merkle checkpoints with externally retained `checkpoint_id` freshness pins
- portable inclusion proofs for individual trusted releases without distributing the complete history
- stable `CHK010` rollback and `CHK011` fork lineage denials with common-prefix diagnostics
- compact append-only release consistency proofs that reconstruct retained and candidate checkpoint roots from `O(log n)` hashes
- canonical aligned power-of-two prefix/suffix frontiers with rehashed-layout and subtree-tamper rejection
- stable `CNS010` rollback and `CNS011` fork denials that never create proof artifacts
- strict canonical JSON Lines audit records with versioned sequences and complete-chain append preflight
- stable `AUDxxx` diagnostics for malformed JSON, duplicate keys, partial writes, schema drift, chain breaks, and canonicalization failures
- externally pinned audit record counts and head hashes for rollback/replay detection
- immutable atomic verified-prefix recovery copies that never mutate damaged source logs
- versioned typed audit-event schemas for scan, added-line, baseline, guard, scrub, and dispatch records
- bounded generic audit events with credential-bearing key/value rejection
- domain-separated SHA-256 references for paths, command arrays, and Git refs without retaining raw values
- typed/untyped coverage, event counts, privacy-state reporting, and optional typed-only migration enforcement
- stable `AUD022`, `AUD023`, and `AUD024` event-admission diagnostics
- atomic audit segment rotation into new no-overwrite directories with exact sealed JSON Lines bytes and canonical manifests
- typed archived-to-active continuity records binding segment IDs, content digests, audit heads, counts, and sizes
- complete ordered segment-chain verification with independently retained latest-segment rollback pins
- stable `AUS001` through `AUS008` diagnostics for unsafe paths, invalid sources, manifest drift, content tamper, continuity failures, stale pins, and empty rotation sources
- canonical audit segment catalogs that auto-discover sealed archives and bind safe directory names, manifest/data digests, audit heads, counts, and continuity IDs
- catalog generations linked by predecessor IDs with externally retained `catalog_id` freshness pins
- exact discovery coverage and right-descendant-only synchronization that reject missing, renamed, replaced, unindexed, reordered, or forked segments
- stable `AUC001` through `AUC010` diagnostics with distinct accepted, denied, and invalid exit semantics
- portable audit catalog Merkle checkpoints that bind catalog identity, generation, predecessor, totals, latest segment, and RFC 6962 roots
- compact per-segment inclusion proofs with proof-only verification and optional sealed-directory evidence binding
- domain-separated leaf, node, checkpoint, and proof hashes with rehashed audit-path tamper rejection
- stable `AUP001` through `AUP010` diagnostics and externally retained checkpoint freshness pins
- compact append-only catalog consistency proofs with canonical previous/append frontiers and proof-only checkpoint verification
- direct predecessor binding, multi-generation append-only continuity, and logarithmic proof size
- stable `AUK009` rollback, `AUK010` fork/predecessor, and `AUK011` generation-regression denials
- rehashed frontier, noncanonical layout, stale pin, unsafe output, and checkpoint-substitution rejection
- portable snapshot and transition audit evidence bundles with canonical manifests, exact file roles, SHA-256 checksums, and domain-separated bundle IDs
- proof-only offline verification after removal of source catalogs, proof files, and segment archives
- optional sealed-segment copying with proof-to-directory verification before creation and independent re-verification after transfer
- stable `AUB001` through `AUB012` diagnostics for unsafe paths, invalid composition, stale pins, duplicate evidence, checksum drift, extra files, and overwrite attempts
- consumer-owned audit bundle admission policies that verify the complete bundle before applying authorization controls
- exact bundle-type, size, proof-count, sealed-evidence, candidate-generation, segment-selection, consistency-relation, predecessor, and generation-delta constraints
- canonical policy SHA-256, deterministic decision IDs, and stable `AUA001` through `AUA016` denials
- separate admitted (`0`), verified-but-denied (`1`), and malformed/unsafe/unverifiable (`2`) audit-bundle outcomes
- consumer-owned audit bundle trust states with snapshot-only anchors, transition-only advancement, and externally retained `state_id` freshness pins
- domain-separated entry/state hashes binding bundle, checkpoint, catalog, generation, segment count, Merkle root, admission decision, policy hash, and transition delta
- stale-pin, replay, duplicate identity, head mismatch, non-increasing generation, symlink, lock, tamper, and overwrite rejection with stable `ATS001` through `ATS010` diagnostics
- advisory-lock-coordinated mode-0600 atomic trust-state updates that preserve bytes on denials and invalid operations
- portable audit trust-state Merkle checkpoints binding exact state IDs, entry counts, current heads, and RFC 6962 roots
- compact per-bundle inclusion proofs with proof-only verification and optional full portable-bundle re-verification
- stable `ATC001` through `ATC011` diagnostics, including explicit rollback and fork lineage denials
- immutable checkpoint/proof outputs, external freshness pins, rehashed audit-path rejection, and no signing-key or witness claims
- compact append-only audit trust consistency proofs with canonical aligned frontiers and independent retained/candidate root reconstruction
- authenticated first-appended transition entries binding retained head hash, checkpoint, catalog, and generation continuity
- stable `ATK009` rollback, `ATK010` fork, and `ATK011` invalid-boundary denials that never create proof artifacts
- proof-only consistency verification after removal of both complete trust states
- portable snapshot and transition audit trust handoff bundles with exact manifests, sorted checksums, external bundle/checkpoint pins, and mandatory candidate-head proofs
- offline handoff verification after removal of complete trust states and all loose checkpoint/proof inputs
- stable `ATB001` through `ATB012` diagnostics for unsafe paths, stale pins, invalid composition, substitution, boundary drift, and overwrite attempts
- consumer-owned audit trust handoff admission policies that fully verify handoffs before applying size, proof, identity, selection, and transition controls
- canonical policy SHA-256, deterministic decision IDs, and stable `ATA001` through `ATA016` denials
- separate admitted (`0`), verified-but-denied (`1`), and malformed/unsafe/unverifiable (`2`) trust-handoff outcomes
- consumer-owned pinned audit trust receiver states with snapshot-only anchors, transition-only advancement, and externally retained receiver `state_id` freshness pins
- domain-separated receiver entry/state hashes binding handoff, trust checkpoint/state, authenticated head, admission decision, policy, and transition deltas
- stable `ATR001` through `ATR010` diagnostics for unsafe paths, stale pins, policy denials, wrong roles, head mismatch, replay, rollback, ownership, and lock failures
- lock-coordinated mode-0600 atomic receiver updates that preserve bytes on denied and invalid operations
- portable receiver-state Merkle checkpoints binding exact receiver state IDs, accepted-entry counts, current heads, and RFC 6962 roots
- compact per-handoff receiver inclusion proofs with proof-only verification and optional complete handoff re-verification
- stable `ARC001` through `ARC011` diagnostics with immutable outputs, external pins, checkpoint-substitution rejection, rollback, and fork lineage gates
- installed audit-bundle, admission, trust, trust-checkpoint, trust-consistency, trust-handoff, trust-handoff-admission, trust-receiver, and receiver-checkpoint aliases, a reviewed twenty-five-module/thirty-command wheel, and synchronized release-admission boundaries
- read-only CI release-readiness, release admission/transition/trust/checkpoint/consistency, audit integrity/event/segment/catalog/checkpoint/consistency/bundle/admission/trust/trust-checkpoint/trust-consistency/trust-handoff/trust-handoff-admission/trust-receiver/receiver-checkpoint, and installed-package artifacts with no publication, signing key, OIDC request, or registry credentials

## 0.1.0 — 2026-07-16

Initial installable package release candidate.

- dependency-free repository, policy, baseline, Git-scope, and command-gate control plane
- full, changed-file, and added-line scanners
- JSON and SARIF reports
- exact-fingerprint baseline classification
- four initial installed console commands: `basit-agent`, `basit-agent-lines`, `agent-system`, and `agent-changed-lines`
- fail-closed source-checkout boundary for external integration dispatch
- reviewed wheel-content validation

The GitHub Action remains usable directly from a reviewed commit independently of package publication.
