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
- compact append-only consistency proofs that reconstruct retained and candidate checkpoint roots from `O(log n)` hashes
- canonical aligned power-of-two prefix/suffix frontiers with rehashed-layout and subtree-tamper rejection
- stable `CNS010` rollback and `CNS011` fork denials that never create proof artifacts
- read-only CI release-readiness, admission, transition, trust-state, checkpoint, and consistency artifacts with no publication, signing key, OIDC request, or registry credentials

## 0.1.0 — 2026-07-16

Initial installable package release candidate.

- dependency-free repository, policy, baseline, Git-scope, and command-gate control plane
- full, changed-file, and added-line scanners
- JSON and SARIF reports
- exact-fingerprint baseline classification
- four installed console commands: `basit-agent`, `basit-agent-lines`, `agent-system`, and `agent-changed-lines`
- fail-closed source-checkout boundary for external integration dispatch
- reviewed wheel-content validation

The GitHub Action remains usable directly from a reviewed commit independently of package publication.
