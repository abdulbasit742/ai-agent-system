# Security audit: portable release checkpoints

## Scope

This review covers `scripts/release_checkpoint.py`, its unit tests, and the read-only checkpoint workflow. It assumes release bundles and trust states have already passed their own strict verification.

## Assets protected

- exact release trust-state identity
- append-only trust history
- current trusted release head
- portable evidence that one trust entry existed in a reviewed state
- detection of stale, rolled-back, or forked trust-state copies

## Threats and controls

### Checkpoint tampering

The checkpoint uses an exact schema, canonical JSON, a domain-separated SHA-256 Merkle root, and a canonical `checkpoint_id`. Unknown fields, malformed digests, unsupported versions, head/count mismatch, non-canonical serialization, oversized input, or symlinks fail closed.

When a full state is supplied, the checkpoint is regenerated from that state and compared as a complete object. Recalculating a checkpoint ID after changing the Merkle root does not bypass state comparison.

### Stale checkpoint substitution

Every verification requires an externally supplied expected checkpoint ID. Internal checkpoint integrity alone is not described as freshness protection.

Checkpoint creation also requires the externally retained trust-state ID, preventing a silently substituted valid-but-old state from creating an accepted checkpoint.

### Inclusion-proof tampering

Proofs bind:

- exact checkpoint ID
- project and state ID
- entry count
- Merkle root
- full canonical trust entry
- Merkle audit path
- canonical proof ID

The verifier recomputes the entry hash and Merkle root. Modifying an entry or audit path and then recalculating the proof ID still fails because the reconstructed root differs from the pinned checkpoint.

Audit paths are limited to 64 hashes, and entry sequences must lie inside the checkpoint tree size.

### Merkle ambiguity

Leaves and internal nodes use separate domain prefixes (`0x00` and `0x01`). The tree follows the RFC 6962 largest-power-of-two split and never duplicates an odd leaf. This prevents leaf/node type confusion and removes ambiguity about odd-sized tree construction.

### Rollback and forked histories

Lineage comparison validates both complete trust states and requires both external state-ID pins. The right state is accepted only when identical to or a strict descendant of the left state.

- `CHK010` denies a right-side rollback
- `CHK011` denies a divergent fork

The tool reports the common prefix but never attempts an automatic merge or chooses a winning fork.

### Output overwrite and symlink attacks

Checkpoint and proof outputs are immutable. Existing paths and symlinks are rejected. Files are written with mode `0600` to a same-directory temporary file, flushed, and exposed through an atomic no-overwrite hard link. The directory is flushed where supported.

### Secret or source disclosure

Checkpoint and proof artifacts contain only release identities, hashes, versions, source commit IDs, source epochs, transition IDs, policy hashes, and Merkle data. They contain no wheel bytes, module contents, scanner previews, credentials, environment values, registry tokens, or signing keys.

### False signature claims

The checkpoint is unsigned. The implementation and documentation do not claim authenticated signer identity, non-repudiation, certificate validation, transparency logging, or revocation. External systems may sign canonical checkpoint bytes or the checkpoint ID, but key management is outside this repository.

## CI permissions

The checkpoint workflow uses only:

```yaml
permissions:
  contents: read
```

It builds local verification artifacts and uploads them as workflow evidence. It does not publish packages, create GitHub Releases, request OIDC credentials, access registry secrets, or use signing material.

## Residual risks

- SHA-256 integrity does not authenticate who created a checkpoint.
- A compromised external checkpoint-ID store can authorize an attacker-controlled checkpoint.
- Inclusion proofs do not prove that a checkpoint is the newest available state.
- Local filesystem permissions and host compromise remain outside the tool's control.
- Fork resolution remains a human or external policy decision.
- Hard-link-based immutable creation requires filesystem support; unsupported operations fail rather than falling back to unsafe overwrite behavior.

## Verification targets

- canonical checkpoint and proof schemas
- deterministic roots and IDs
- single-entry and odd-sized Merkle trees
- first, middle, and last inclusion proofs
- rehashed entry and audit-path tampering
- wrong checkpoint and stale external pins
- immutable output and symlink rejection
- same, descendant, rollback, fork, and cross-project lineage
- Python 3.11 and 3.12
- real verified release bundles and trust-state integration
