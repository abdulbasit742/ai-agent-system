# Security audit: portable audit evidence bundles

## Scope

Task 20 adds a dependency-free directory-bundle format for transferring selected audit transparency evidence. The format composes existing verified catalog checkpoints, inclusion proofs, optional consistency proofs, and optional sealed segment directories.

The bundle layer does not create new audit history. It verifies and copies already reviewed evidence into an exact-boundary handoff directory.

## Security objectives

The implementation is designed to ensure that:

1. invalid source evidence is rejected before output creation
2. every bundled file is identified by path, role, size, and SHA-256
3. unexpected or missing files are detected
4. candidate and previous checkpoint freshness is caller-pinned
5. inclusion proofs remain bound to the candidate checkpoint
6. transition consistency evidence remains bound to both checkpoints
7. selected segment bytes remain bound to their inclusion proofs
8. output is immutable and never overwrites an existing destination
9. verification works without trusting the original source directory
10. bundle integrity is not misrepresented as signer authentication

## Composition boundary

Two bundle types are supported.

### Snapshot

A snapshot requires:

- one externally pinned candidate checkpoint
- one or more inclusion proofs that validate against that checkpoint

Optional sealed segment directories may be included. When a segment root is supplied, every proof must resolve to one safe immediate segment-directory name beneath that root, and the segment is independently verified before copying.

### Transition

A transition requires the complete snapshot inputs plus:

- one externally pinned previous checkpoint
- one consistency proof that validates against the previous and candidate checkpoints

Partial transition input is rejected with `AUB012`. The implementation never silently downgrades incomplete transition evidence into a snapshot.

## Canonical manifest

The manifest uses an exact versioned schema and canonical JSON serialization. It binds:

- bundle type
- candidate checkpoint summary
- optional previous checkpoint summary
- optional consistency-proof summary
- ordered inclusion-proof entries
- exact payload-file records
- domain-separated `bundle_id`

Unknown, missing, duplicate, or noncanonical fields fail closed.

The bundle identifier is recalculated from the normalized manifest core. Rewriting the manifest and merely preserving the old identifier is detected.

## File-boundary verification

The verifier recursively enumerates the bundle directory and rejects:

- symbolic links
- non-regular files
- absolute paths
- traversal components
- backslashes
- control characters
- unsafe or oversized path components
- files not declared by the manifest
- manifest-declared files that are missing

The exact allowed filesystem set is:

- `audit-bundle-manifest.json`
- `SHA256SUMS`
- every path declared in the manifest file records

Directories are structural only and are not independently declared.

## Checksums and metadata

Every payload file record carries:

- role
- safe relative path
- SHA-256 digest
- byte size

`SHA256SUMS` covers every payload file and the manifest. Verification compares:

1. the actual filesystem boundary
2. checksum-file membership
3. SHA-256 of each actual file
4. manifest record digest and size

This prevents a modified file from being accepted merely because one metadata layer was rewritten incompletely.

## Checkpoint and proof verification

The candidate checkpoint is always loaded using the existing strict canonical checkpoint parser and compared with an externally retained checkpoint ID.

Each inclusion proof is:

1. parsed using the strict proof schema
2. cryptographically reconstructed to its Merkle root
3. compared with the candidate checkpoint reference
4. compared with its manifest entry

Duplicate segment indexes, IDs, directory names, proof IDs, or proof paths are rejected with `AUB009`.

## Transition verification

For a transition bundle, the previous checkpoint is also externally pinned. The consistency proof is:

1. strictly parsed
2. independently validated
3. used to reconstruct previous and candidate roots
4. compared with both supplied checkpoints
5. compared with the manifest consistency summary

Rollback, fork, predecessor, or generation controls remain enforced by the underlying `AUKxxx` implementation and are normalized to the bundle `AUB005` boundary.

## Sealed segment verification

When segment bytes are included, the bundle contains only:

- `manifest.json`
- `segment.jsonl`

The source segment directory is verified against its inclusion proof before copying. During bundle verification, the copied directory is independently re-inspected and compared with the proof entry again.

This two-stage verification prevents the bundler from trusting copied filenames or source-directory ordering.

## Output publication

The requested output directory must not exist and must not be a symlink. Creation uses a temporary sibling directory. The completed staging directory is fully verified before it is renamed to the final output path.

On failure, the temporary directory is removed and the requested output remains absent. Existing destinations are never deleted, emptied, merged, or overwritten.

The implementation does not produce ZIP or TAR archives. This avoids extraction-time path traversal, link, ownership, and device-node semantics.

## Resource limits

Reviewed limits prevent unbounded memory, filesystem, and parsing work:

- 128 inclusion proofs
- 1,024 payload files
- 256 MiB payload bytes
- 2 MiB manifest
- canonical bounded checkpoint and proof formats inherited from prior tasks

Boolean values are rejected where integer counts are required.

## Diagnostics

Stable rules are:

- `AUB001`: unsafe path, symlink, or non-regular file
- `AUB002`: strict JSON, schema, or canonicalization failure
- `AUB003`: bundle identity or external bundle pin mismatch
- `AUB004`: checkpoint validation or pin mismatch
- `AUB005`: consistency-proof mismatch
- `AUB006`: inclusion-proof mismatch
- `AUB007`: sealed-segment mismatch
- `AUB008`: file boundary, checksum, or metadata mismatch
- `AUB009`: duplicate evidence identity or selection
- `AUB010`: count or byte limit exceeded
- `AUB011`: existing output or publication conflict
- `AUB012`: unsupported or incomplete bundle composition

Exit `1` is reserved for valid evidence that conflicts with an external pin or reviewed relationship. Exit `2` represents malformed, unsafe, incomplete, or tampered evidence.

## Privacy review

Bundle manifests contain only:

- hashes and IDs
- counts and sizes
- safe relative directory names
- fixed roles and algorithm relationships

They do not contain raw command arrays, raw source paths, source code, environment variables, credentials, or audit record bodies beyond explicitly selected sealed segment files.

Including sealed segment files intentionally transfers their typed audit records. Operators should choose proof-only bundles when record transfer is unnecessary.

## Residual risks

### Unsigned evidence

The bundle and all current audit evidence are unsigned. An attacker who controls every input and every external pin can produce a different internally valid history. The security model therefore requires pins to be retained independently from the transferred bundle.

### Directory publication race

The implementation verifies a staging directory and checks that the destination is absent before rename. The repository does not depend on platform-specific `renameat2(RENAME_NOREPLACE)`. Cooperative concurrent creators are protected by unique staging names and destination checks, but a hostile process with write access to the parent directory remains outside the trust boundary.

### Availability

Exact-boundary verification intentionally rejects partial recovery, missing optional-looking files, and local repair. Operators must retain independent backups of bundles and pins.

### Producer identity

`bundle_id` authenticates content only when the expected value is obtained through a trusted channel. It does not identify who created the bundle.

## CI evidence

Read-only CI validates:

- 20 bundle-specific regression scenarios
- Python 3.11 and 3.12
- snapshot and transition composition
- real sealed-segment copying and re-verification
- source-evidence deletion followed by bundle-only verification
- stale pin, checksum tamper, extra-file, symlink, duplicate, and overwrite rejection
- isolated dependency-free wheel installation
- both installed bundle command aliases
- existing audit and release workflows

The workflows request only `contents: read`. They do not publish packages, create releases, request OIDC credentials, use signing keys, or access registry secrets.
