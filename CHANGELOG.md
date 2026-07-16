# Changelog

All notable public distribution changes are recorded here.

## Unreleased

- deterministic release-evidence bundles with canonical JSON manifests and SHA-256 checksums
- byte-for-byte wheel reproducibility verification using one source commit epoch
- exact source commit, package metadata, artifact size, digest, and console-command evidence
- fail-closed bundle verification for tampering, extra files, symlinks, malformed checksums, and metadata drift
- read-only CI release-readiness artifacts with no registry publication or credentials

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
