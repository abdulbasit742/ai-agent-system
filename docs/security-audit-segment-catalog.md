# Security audit: segment catalog

Task 17 introduces a canonical catalog for the sealed audit segments created by Task 16.

## Security goals

The catalog must let an offline verifier determine that:

- every cataloged segment directory exists beneath one dedicated archive root;
- each segment manifest and data file still match the cataloged digests and metadata;
- all segments form one complete append-only history beginning at index 1;
- no discovered segment has been silently omitted from the catalog;
- synchronization only appends right-descendant segments to a pinned catalog;
- the optional active log continues from the latest sealed segment;
- a retained catalog cannot be replaced by an older or forked catalog without detection.

## Catalog identity

`catalog_id` is SHA-256 over a domain separator and the canonical catalog payload excluding the ID itself. The payload binds:

- schema version;
- generation;
- previous catalog ID;
- ordered segment entries;
- segment count;
- total records and bytes;
- latest segment ID.

Every segment entry binds the immediate-child directory name, segment index and IDs, manifest SHA-256, segment SHA-256, audit head, record count, and byte count.

The hash is an integrity commitment, not a signature. A verifier must compare it with an independently retained expected catalog ID.

## Filesystem boundary

- The catalog must be a regular non-symlink file.
- Segment directories must be regular, non-symlink immediate children of the catalog directory.
- Directory names may not be hidden, absolute, nested, traversal-based, or contain control characters.
- The archive root rejects symlink entries and unrelated directories.
- Segment verification continues to reject symlink manifests or data files.
- Catalog creation refuses overwrite and uses a same-directory temporary file plus no-overwrite link.
- Catalog synchronization holds a sidecar advisory lock and uses a same-directory fsynced atomic replacement.

Generated catalog, lock, segment, and report files remain outside the public wheel and repository source.

## Discovery completeness

Catalog verification does not trust only the stored list. It independently discovers the archive root, verifies every segment directory, orders entries by the committed segment index, and requires the discovered entries to equal the catalog entries exactly.

This detects:

- deleted segment directories;
- renamed directories;
- replaced segment contents;
- extra unindexed segments;
- duplicate IDs;
- index gaps;
- reordered or forked continuity.

## Synchronization boundary

Synchronization requires an externally retained current catalog ID. Before mutation it verifies:

1. canonical catalog structure and ID;
2. the external catalog pin;
3. every currently cataloged segment;
4. the existing complete segment chain;
5. the newly discovered complete chain;
6. that old entries are an exact prefix of discovered entries;
7. the optional active-log continuation from the discovered head.

Only then is a new generation produced. Stale pins, missing prefixes, replacements, forks, and active mismatch leave the existing catalog bytes unchanged.

A no-op sync performs all verification but does not rewrite the catalog.

## Failure semantics

Policy or trust-state conflicts use exit code `1`; malformed or unsafe input uses exit code `2`. Stable diagnostics avoid embedding audit event bodies or source contents.

The implementation does not:

- repair or infer missing history;
- rename, delete, or reorder segment directories;
- merge forks;
- rotate the active log automatically;
- delete old catalog generations or segment archives;
- publish, sign, or upload catalog evidence;
- claim authenticated operator identity.

## Operational assumptions

The archive root is operator-owned and dedicated to segment storage. Rotation and catalog synchronization should not be run concurrently. If another immutable segment appears after a synchronization snapshot, the resulting catalog remains a valid prefix but complete verification will report it as stale until the next pinned synchronization.

The latest returned `catalog_id` should be retained in a separate trusted location. Losing that pin removes rollback detection but does not weaken structural and cryptographic verification of the files that remain.
