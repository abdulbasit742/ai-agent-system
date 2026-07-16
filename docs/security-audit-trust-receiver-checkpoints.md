# Security audit: receiver checkpoints and inclusion proofs

## Reviewed guarantees

- Complete receiver states are strictly validated before checkpoint or proof creation.
- RFC 6962 domain-separated leaf/node hashing commits every canonical receiver entry.
- Checkpoints bind exact receiver state IDs, entry counts, heads, Merkle roots, and checkpoint IDs.
- Inclusion proofs authenticate one exact receiver entry and reject missing, extra, reordered, or substituted audit-path hashes.
- Optional handoff verification re-validates the complete portable handoff and compares its normalized evidence with the authenticated receiver entry.
- Lineage accepts only identical or exact-prefix right-descendant histories.
- New checkpoint/proof paths are non-overwriting, mode `0600`, fsynced, and symlink-safe.

## Stable diagnostics

- `ARC001`: unsafe path, symlink, or non-regular file
- `ARC002`: strict JSON, schema, canonicalization, or identifier failure
- `ARC003`: external state/checkpoint pin mismatch
- `ARC004`: checkpoint does not match the complete receiver state
- `ARC005`: invalid or missing proof selector
- `ARC006`: invalid entry hash, audit path, Merkle reconstruction, or proof ID
- `ARC007`: checkpoint substitution
- `ARC008`: handoff verification or authenticated-entry binding failure
- `ARC009`: immutable output already exists
- `ARC010`: rollback lineage
- `ARC011`: fork lineage

## Explicit limitations

The checkpoint and proof formats are unsigned. They establish integrity, exact membership, and state lineage only when consumers retain trusted state/checkpoint IDs independently. They do not authenticate an operator, witness, organization, or signing identity. Ordinary CI contains no signing key, OIDC request, registry credential, or publication step.
