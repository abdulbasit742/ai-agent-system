# Security audit: audit trust consistency proofs

## Security objective

The consistency layer proves that a candidate audit bundle trust checkpoint retains the complete entry prefix committed by a retained checkpoint. Verification can operate from two externally pinned checkpoints and one compact proof without either full trust state.

## Reviewed controls

- Both source trust states are strictly validated before proof creation.
- Both checkpoints must match their exact source states and external state/checkpoint pins.
- Only `same` and exact right-descendant relations create proof files.
- `ATK009` rejects rollback and `ATK010` rejects forks.
- Canonical aligned compact frontiers reconstruct both Merkle roots independently.
- Frontier shape is validated; hashes cannot be reordered, merged, split, omitted, or added.
- Recomputing `consistency_id` after changing a frontier does not bypass root reconstruction.
- A descendant proof exposes the first appended transition as an authenticated one-leaf segment.
- `ATK011` checks that boundary transition against the retained head hash, checkpoint, catalog, and generation.
- Verification binds the proof references to both externally pinned checkpoint files.
- Strict UTF-8 canonical JSON rejects duplicate keys, non-finite numbers, schema drift, and alternate serialization.
- Outputs are bounded, mode `0600`, symlink-safe, fsync-backed, atomic, and no-overwrite.
- Denied creation does not produce a proof artifact.

## Trust and freshness boundary

Checkpoint and consistency IDs are unsigned integrity commitments. They do not authenticate an operator, prove wall-clock freshness, provide witness consensus, or establish non-repudiation. Consumers must retain accepted checkpoint IDs in an independent trusted location.

A valid multi-entry proof establishes append-only Merkle continuity between the two checkpoint sizes. The authenticated first appended entry proves continuity across the retained boundary. Intermediate transition entries remain individually hash-linked and Merkle-committed, but their original portable bundles are not re-verified by this command.

## Data minimization

Proofs contain trust-entry hashes, checkpoint/catalog/bundle identities, generations, counts, policy hashes, one boundary entry, and compact frontier hashes. They do not include audit records, sealed segment bytes, source files, raw paths, commands, environment values, credentials, or signing material.

## CI boundary

Pull-request CI is read-only. It uses temporary synthetic trust evidence, verifies proof-only operation after deleting both full states, checks rollback/fork denials, builds an isolated dependency-free wheel, and does not publish packages, request OIDC credentials, or read registry secrets.
