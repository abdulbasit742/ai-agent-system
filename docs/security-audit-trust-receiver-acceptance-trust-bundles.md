# Security audit: receiver-acceptance trust handoff bundles

## Scope

Task 40 adds immutable snapshot and transition bundles above the pinned receiver-acceptance trust checkpoint and compact consistency layers.

## Security invariants

1. Candidate and previous checkpoints must pass strict canonical validation.
2. Every inclusion proof must bind exactly to the candidate checkpoint.
3. At least one inclusion proof must prove inclusion of the candidate head entry in the candidate checkpoint.
4. Transition bundles require a compact proof whose relation is `right-descendant` and whose checkpoint references exactly equal the copied checkpoints.
5. Caller-supplied candidate, previous, and bundle IDs are validated before comparison and act as external freshness pins.
6. Manifest paths are safe relative paths; duplicate paths, duplicate proof identities, symlinks, and unreviewed files are rejected.
7. Every evidence file is bound by role, size, SHA-256 digest, canonical manifest, sorted checksums, and a domain-separated bundle ID.
8. Creation stages all bytes, re-verifies the staged directory, fsyncs files/directories, and publishes only to a new path.
9. Existing outputs are never overwritten. Failure leaves no accepted partial bundle.
10. The adapter executes only the packaged reviewed receiver-bundle source after a fixed fail-closed token transformation in an isolated namespace; no external source or runtime input is compiled.
11. The scanner exception is not a rule disable: `.agent-system-policy.json` binds `BAS013` to the exact adapter path and fingerprint, names an owner and rationale, and expires on 2027-07-17. Any source change invalidates the suppression automatically.

## Diagnostics

- `ABB001`: unsafe path, symlink, or non-regular file;
- `ABB002`: malformed, noncanonical, or unsupported manifest/evidence;
- `ABB003`: invalid or stale external pin;
- `ABB004`: checkpoint validation or binding failure;
- `ABB005`: invalid snapshot/transition composition;
- `ABB006`: non-descendant transition evidence;
- `ABB007`: duplicate or excessive proof evidence;
- `ABB008`: checksum, exact-boundary, or copied-evidence mismatch;
- `ABB009`: size or count limit failure;
- `ABB010`: staging/publication integrity failure;
- `ABB011`: immutable-output violation;
- `ABB012`: missing candidate-head inclusion proof.

## Threat coverage

The implementation rejects loose-file substitution, proof/checkpoint swapping, rehashed manifest tampering, checksum rewriting without a matching pinned bundle ID, extra-file injection, path traversal, symlink redirection, stale checkpoint replay, partial transitions, duplicate proof selection, and overwrite races.

## Residual boundary

The evidence is unsigned. SHA-256 identifiers establish integrity and append-only composition only when consumers retain trusted IDs independently. The module does not claim producer authentication, transparency-log witnessing, timestamp authority, key custody, or policy authorization. A subsequent consumer admission layer should decide whether a fully verified handoff is acceptable.
