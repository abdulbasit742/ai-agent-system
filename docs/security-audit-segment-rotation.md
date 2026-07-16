# Security audit: audit segment rotation

## Reviewed threat model

The rotation feature addresses operational growth beyond the active log's 64 MiB verification limit while preserving append-only evidence. It is designed to detect accidental damage, content tampering, metadata rewriting, rollback to an older segment chain, and continuity breaks between archived and active logs.

It does not provide signer authentication, witness consensus, remote availability, or non-repudiation.

## Design comparison

Three mature transparency systems informed the design without copying their code:

- Rekor keeps inactive shards verifiable and exposes checkpoints for both inactive and active trees. The local implementation similarly seals old history and keeps it independently verifiable while a new active segment accepts events.
- Trillian defines a log checkpoint as a commitment to entry count and contents that must remain consistent with earlier checkpoints. The local segment manifest commits to records, bytes, head hash, content SHA-256, and the previous segment ID.
- immudb clients retain prior state and verify that a newer state includes a consistent earlier history. The local verifier requires an externally retained latest segment ID and validates every previous-to-next continuity record.

The implementation remains a standard-library-only local control plane rather than a network transparency service.

## Admission before rotation

Rotation refuses:

- missing or empty active logs
- structurally invalid logs
- logs with pre-schema untyped records
- stale expected record-count or head-hash pins
- symlinked active logs
- existing or symlinked output directories

The source is inspected while the active sidecar lock is held. No next segment metadata is derived from an unverified chain.

## Atomicity and failure ordering

The sealed bytes, canonical manifest, and replacement active record are prepared before mutation.

1. Build a new sibling temporary archive directory.
2. Write and fsync `segment.jsonl` and `manifest.json` with mode `0600`.
3. Independently verify the staged segment.
4. Rename the complete directory to the requested new output path.
5. Atomically replace the active log with the linked start record.
6. Fsync affected directories.

The archive is committed before active replacement. A failure between those operations leaves the original active data intact and an independently verifiable extra copy. No source truncation occurs.

## Manifest integrity

The manifest uses strict UTF-8 canonical JSON with an exact field set. Its `segment_id` is SHA-256 over a domain separator and the canonical manifest core. Verification rejects:

- duplicate JSON keys
- noncanonical whitespace or ordering
- unsupported versions
- extra or missing fields
- malformed hashes or counts
- changed manifest fields even when the file is reserialized
- changed segment bytes
- disagreement with independently recalculated audit metadata

Recomputing the manifest ID after editing metadata is insufficient because the verifier recalculates the segment's audit head, record count, typed coverage, and byte digest.

## Continuity model

Segment 1 must use the all-zero previous segment ID. Each later archived segment must:

- increment the index by exactly one
- name the immediately preceding segment ID in its manifest
- begin with an exact `audit-segment-start` event committing to the preceding segment ID, byte SHA-256, audit head, record count, byte count, and index

The active log must begin with the same commitment to the latest sealed segment.

A verifier accepts only a complete caller-supplied sequence beginning at segment 1. It never searches directories, guesses missing history, sorts ambiguous inputs, or repairs a fork automatically.

## Rollback boundary

A self-consistent archived chain can be copied or rolled back. The verifier therefore supports `--expected-latest-segment-id`, which must be retained independently from the segment storage.

The pin authenticates neither the producer nor the storage. It provides rollback detection only to the extent that the retained value itself is protected.

## Privacy boundary

Rotation accepts only fully typed logs. The sealed bytes therefore inherit typed event admission and privacy normalization. Segment manifests contain only counts, hashes, versions, booleans, fixed filenames, and indexes. They do not contain raw commands, source paths, Git refs, scanner previews, environment values, or credentials.

The continuity event contains only prior segment hashes and counts.

## Residual risks

- Unsigned manifests can be replaced together with all retained pins by an attacker controlling both locations.
- File deletion is detected only when complete history is supplied or availability is checked externally.
- The active replacement and archive directory rename cannot form one cross-directory filesystem transaction; failure ordering is chosen to preserve source data.
- Concurrent writers not using the shared sidecar lock are outside the guarantee.
- Segment directories remain mutable filesystem objects; integrity is verified on every read rather than enforced by filesystem immutability.
