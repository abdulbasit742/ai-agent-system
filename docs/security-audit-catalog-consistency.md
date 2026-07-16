# Security audit: audit catalog consistency proofs

Task 19 adds portable compact consistency proofs between externally pinned audit catalog checkpoints.

## Security objective

A consumer that retained an earlier catalog/checkpoint identity must be able to determine whether a candidate catalog is an append-only continuation without trusting directory ordering, caller-provided summaries, or a self-declared proof identifier.

## Inputs and trust anchors

Proof creation requires:

- a previous canonical catalog and its listed sealed segments;
- a previous canonical checkpoint;
- a candidate canonical catalog and its listed sealed segments;
- a candidate canonical checkpoint;
- exact external pins for both catalog IDs and both checkpoint IDs.

Proof verification requires the proof, both checkpoints, and all four retained identities. Full catalogs and segment archives are not required after proof creation.

## Validation sequence

The implementation performs these checks in order:

1. path, symlink, size, UTF-8, duplicate-key, JSON, and canonical-serialization validation;
2. catalog structural validation and independent verification of every listed segment;
3. checkpoint structural validation and exact external pin comparison;
4. checkpoint-to-catalog regeneration and equality comparison;
5. exact segment-entry prefix classification;
6. candidate generation and direct predecessor validation;
7. canonical compact-range layout validation;
8. previous Merkle-root reconstruction;
9. candidate Merkle-root reconstruction after binary-carry frontier merging;
10. domain-separated consistency-ID validation.

A matching `consistency_id` never substitutes for root reconstruction.

## Hash domains

Catalog entry leaves and internal nodes reuse the reviewed checkpoint construction:

- leaves: `SHA256(0x00 || canonical_entry)`;
- nodes: `SHA256(0x01 || left || right)`.

The consistency identifier uses a separate domain:

- `audit-catalog-consistency-proof-v1`.

Lineage and denial decisions use separate domains so their identifiers cannot be confused with proof identifiers.

## Compact-range correctness

Both frontiers must use the canonical maximal aligned power-of-two cover for their exact ranges. The verifier rejects:

- missing ranges;
- extra ranges;
- overlapping or noncontiguous ranges;
- unaligned ranges;
- non-power-of-two sizes;
- changed range boundaries;
- previous frontiers that do not cover the retained checkpoint;
- candidate forests that do not normalize to the canonical candidate layout.

The verifier reconstructs the previous root before appending any candidate hashes, then applies binary-carry merging and reconstructs the candidate root.

## Relation controls

Only identical and right-descendant histories are accepted.

- `AUK009` rejects rollback to an older exact prefix.
- `AUK010` rejects divergent histories, same-size mutation, and a direct next generation that does not retain the previous catalog ID.
- `AUK011` rejects a larger candidate tree with a non-increasing generation.

Denied creation does not write a proof file.

## Multi-generation boundary

When the candidate generation is exactly one greater than the retained generation, the candidate must name the retained catalog ID as its predecessor and `direct_predecessor_verified` is true.

For larger generation gaps, the proof establishes only that segment entries are append-only between the two pinned checkpoints. It does not authenticate omitted intermediate catalog IDs, checkpoint producers, or synchronization decisions.

## Freshness and replay

Self-consistent catalogs, checkpoints, and proofs do not prove freshness. The caller must retain both catalog IDs and both checkpoint IDs outside the evidence set being evaluated.

A stale or substituted checkpoint/catalog pin fails with `AUK007`. Proof references that differ from the supplied pinned checkpoints fail with `AUK004`.

## Filesystem safety

Proof output is:

- canonical UTF-8 JSON;
- bounded to the reviewed size limit;
- created only at a new path;
- protected against output symlinks and symlink parents;
- written through a same-directory temporary file;
- flushed and linked atomically without overwrite;
- followed by directory synchronization where supported.

Existing files remain unchanged on every denial or invalid operation.

## Data minimization

A proof contains hashes, counts, catalog/checkpoint identities, generations, totals, latest segment IDs, compact range offsets, and range sizes. It excludes:

- audit JSON Lines records;
- source code and scanner previews;
- raw file paths and command arguments;
- credentials and environment variables;
- segment directory contents;
- release-policy or trust-state data.

## Stable diagnostics

- `AUK001`: unsafe file or directory boundary;
- `AUK002`: malformed schema, JSON, value, or size;
- `AUK003`: consistency-ID mismatch;
- `AUK004`: catalog/checkpoint binding failure;
- `AUK005`: compact-range or relation-layout failure;
- `AUK006`: Merkle-root reconstruction failure;
- `AUK007`: external pin mismatch;
- `AUK008`: output overwrite or race;
- `AUK009`: rollback denial;
- `AUK010`: fork or predecessor-link denial;
- `AUK011`: generation-regression denial.

Exit `1` represents a valid but denied transition or stale trust pin. Exit `2` represents malformed, unsafe, or unverifiable input.

## CI boundary

Pull-request CI:

- runs 20 consistency regressions on Python 3.11 and 3.12;
- rebuilds prior checkpoint, catalog, segment, and audit suites;
- constructs real retained, descendant, and forked catalog histories;
- verifies proof portability after deleting full catalogs and archives;
- rejects rollback, fork, and rehashed-frontier attacks;
- builds and validates the dependency-free wheel;
- runs both installed consistency aliases outside the source checkout.

The workflow uses read-only repository permissions and does not publish packages, create releases, request OIDC credentials, load signing keys, or read registry secrets.

## Residual limitations

- Evidence is unsigned and does not authenticate the producer.
- There is no public witness, gossip protocol, or transparency-log quorum.
- Intermediate catalog generations are not proven when the retained and candidate generations are nonadjacent.
- External pin storage and promotion remain consumer responsibilities.
