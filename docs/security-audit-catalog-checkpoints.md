# Security audit: audit catalog checkpoints

Task 18 adds portable Merkle checkpoints and per-segment inclusion proofs above the canonical audit segment catalog introduced in Task 17.

## Reviewed trust boundary

Checkpoint creation accepts only a catalog that:

- is canonical strict JSON
- matches an externally supplied `catalog_id`
- exactly covers every discovered immediate sealed segment directory
- validates every segment manifest, segment byte digest, and audit chain
- optionally matches the current typed active audit log

The checkpoint does not trust stored catalog summaries alone. It is regenerated from the fully validated catalog entries.

## Merkle construction

The implementation uses a fixed algorithm identifier: `sha256-rfc6962-v1`.

- leaf hash: `SHA-256(0x00 || canonical catalog entry)`
- node hash: `SHA-256(0x01 || left || right)`
- tree split: largest power of two smaller than the current leaf count
- odd leaves are not duplicated
- an empty tree is invalid

The separate leaf and node domains prevent an encoded internal node from being interpreted as a leaf.

## Checkpoint binding

A checkpoint commits to:

- catalog ID
- generation
- previous catalog ID
- segment count
- total records and bytes
- latest segment ID
- Merkle algorithm and root

The `checkpoint_id` is a domain-separated SHA-256 digest over the exact canonical checkpoint payload. Rehashing modified metadata is still detected when the checkpoint is compared with the pinned catalog or when a proof reconstructs the original Merkle root.

## Inclusion-proof verification

Proof validation independently checks:

- exact schema and canonical serialization
- checkpoint reference fields
- catalog entry schema and segment index
- bounded lowercase SHA-256 sibling hashes
- exact recursive root reconstruction
- no missing or extra audit-path hashes
- domain-separated `proof_id`
- exact equality with the separately supplied checkpoint reference

A proof can therefore be verified without the full catalog. The checkpoint ID must still be retained independently; a self-consistent proof and checkpoint pair does not prove freshness.

## Optional sealed-segment binding

When `--segment-dir` is supplied, verification additionally checks:

- safe exact directory basename
- regular non-symlink manifest and segment files
- canonical manifest identity
- exact segment byte digest and size
- complete typed audit-chain validity
- segment index and previous segment ID
- segment ID and audit head
- record and byte counts
- exact equality with the proof entry

This prevents a valid proof for one segment from being paired with different archive bytes.

## Filesystem boundary

Checkpoint and proof outputs:

- refuse existing paths and symlinks
- use same-directory temporary files
- flush file data before linking the final path
- never overwrite earlier evidence
- are limited to reviewed maximum sizes

Generated checkpoint and proof files remain runtime evidence. They are not package source and do not enter the wheel.

## Privacy boundary

The checkpoint stores only catalog summaries and hashes. A proof stores one catalog entry and sibling hashes. Neither artifact contains audit event details, command arguments, paths from audit records, source contents, credentials, environment values, or raw segment bytes.

The optional segment verification reads the caller-supplied archive but does not copy its content into the report.

## Signature boundary

No signing key, OIDC identity, registry token, or network service is used. Checkpoint and proof IDs are integrity hashes, not digital signatures. The implementation makes no claim of producer authentication, non-repudiation, witness consensus, or public transparency logging.

## Failure semantics

- `0`: accepted
- `1`: reviewed external pin or membership/evidence binding denied
- `2`: malformed, unsafe, noncanonical, oversized, or unverifiable input

Stable rules are:

- `AUP001`: unsafe path, symlink, or overwrite attempt
- `AUP002`: malformed schema, type, hash, pin, or canonical JSON
- `AUP003`: checkpoint identity or Merkle construction failure
- `AUP004`: checkpoint/catalog verification mismatch
- `AUP005`: proof schema or proof identity failure
- `AUP006`: proof/checkpoint or Merkle reconstruction mismatch
- `AUP007`: externally retained checkpoint pin mismatch
- `AUP008`: invalid or absent requested segment membership
- `AUP009`: supplied sealed segment evidence mismatch
- `AUP010`: checkpoint or proof size boundary violation

## CI review

Read-only CI runs:

- 20 dedicated regression scenarios on Python 3.11 and 3.12
- earlier catalog, segment, and strict audit regressions
- real three-segment checkpoint and proof creation
- proof verification after removing the full catalog and unrelated segments
- rehashed audit-path tamper rejection
- stale checkpoint-pin rejection
- isolated dependency-free wheel installation and both installed checkpoint aliases

The workflow uploads generated evidence for review but does not publish packages, create releases, request OIDC credentials, or use signing keys.
