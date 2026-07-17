# Security audit: receiver-acceptance trust consistency

## Reviewed guarantees

- Proof creation accepts only canonical, fully validated receiver-acceptance trust states and matching checkpoints.
- External state and checkpoint pins are validated before evidence creation.
- Canonical compact frontiers reconstruct the retained and candidate Merkle roots independently.
- Right-descendant proofs expose and authenticate the first appended transition entry.
- The boundary binds the previous entry hash, previous acceptance checkpoint/state IDs, all nested entry-count deltas, generation delta, and segment delta.
- Rollback and fork denials do not publish proof artifacts.
- Proof files are canonical JSON, bounded, symlink-safe, mode `0600`, fsynced, and no-overwrite.
- Proof verification requires only the proof and two externally pinned checkpoints.

## Failure rules

- `ABR001`: unsafe file or isolated-engine boundary;
- `ABR002`: malformed, noncanonical, or unsupported evidence;
- `ABR003`: malformed or stale external pin;
- `ABR004`: state/checkpoint or proof/checkpoint mismatch;
- `ABR005`: invalid compact-range layout;
- `ABR006`: Merkle-root reconstruction failure;
- `ABR007`: consistency identifier mismatch;
- `ABR008`: immutable-output violation;
- `ABR009`: rollback denial;
- `ABR010`: fork denial;
- `ABR011`: invalid acceptance-trust transition boundary.

## Residual boundary

These artifacts are unsigned. Hashes and externally retained IDs prove integrity and freshness relative to the consumer's retained pins, but do not prove who produced the evidence. Signing and producer authentication remain deployment responsibilities.
