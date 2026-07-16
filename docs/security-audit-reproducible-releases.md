# Security audit: reproducible release evidence

Task 7 adds deterministic release-bundle creation, verification, and byte-for-byte wheel comparison. This document records the trust boundaries and intentionally excluded capabilities.

## Artifact input boundary

- Only existing regular `.whl` files are accepted.
- Wheel symlinks are rejected before validation or copying.
- Artifact filenames use a conservative portable character allowlist.
- Duplicate artifact filenames are rejected.
- Every wheel passes the existing exact module, metadata, entry-point, Python-version, and zero-runtime-dependency validator.
- All artifacts in one bundle must have the same project name and package version.

## Output boundary

- The output path must be a real directory, not a symlink.
- The directory must be new or empty.
- The command never clears, replaces, or recursively deletes an existing directory.
- Bundle creation copies only validated wheel bytes and creates only `release-manifest.json` and `SHA256SUMS`.
- Verification rejects missing or additional files and directories.

## Source identity

- The source commit must be an exact 40-character hexadecimal SHA.
- The source timestamp is supplied as a non-negative `SOURCE_DATE_EPOCH` value.
- The UTC timestamp is derived only from that epoch.
- No mutable branch name is recorded as release identity.
- The manifest contains no wall-clock build time, runner path, host identifier, or environment value.

## Integrity evidence

- Each artifact record includes SHA-256 and byte size.
- The checksum file contains canonical path-free entries for every artifact and the manifest.
- The manifest `release_id` is the SHA-256 of canonical JSON excluding only the `release_id` field itself.
- Verification revalidates artifact hashes, sizes, wheel metadata, source metadata, manifest integrity, checksums, and the exact file boundary.
- A metadata-equivalent but byte-different wheel fails reproducibility comparison.

## Secret and privacy boundary

The release evidence contains no:

- source-code excerpts or scanner previews
- environment variables or secrets
- registry credentials
- GitHub tokens
- audit logs
- baselines or suppression contents
- temporary paths

Artifact filenames, package metadata, source commit, source epoch, sizes, and cryptographic digests are intentionally public release metadata.

## CI permissions

The release-readiness job uses only `contents: read`. It builds and verifies artifacts locally and uploads the verified bundle as a workflow artifact. It does not:

- publish to PyPI or another registry
- create a Git tag or GitHub Release
- request OIDC identity tokens
- read registry credentials
- modify repository contents
- sign on behalf of a release authority

Publishing and signing remain separate, explicit, human-reviewed operations.

## Residual limitations

SHA-256 checksums prove artifact identity and tampering after bundle creation, but they do not establish publisher identity. A later task may add a separately reviewed signing or provenance layer. That layer must not weaken the current deterministic bundle and fail-closed verification boundary.
