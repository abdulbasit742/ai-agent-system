# Security audit: receiver-acceptance trust checkpoints

Task 38 adds portable checkpoints and inclusion proofs over the Task 37 consumer-owned acceptance-trust history.

## Enforced controls

- Creation requires a fully validated state and exact external `state_id` pin.
- Checkpoints bind entry count, complete outer and nested head, Merkle root, and a domain-separated ID.
- Proof creation requires an exact checkpoint match and one selector: sequence or acceptance bundle ID.
- RFC 6962 leaf and node domains are separate; odd subtrees are not duplicated.
- Verification reconstructs the root and rejects missing, extra, malformed, or changed audit-path elements.
- Optional handoff verification checks the complete acceptance bundle against the authenticated entry.
- Checkpoint substitution and stale external pins fail closed.
- Lineage accepts identical or right-descendant histories only. Rollback is `ABP010`; fork is `ABP011`.
- JSON is strict and canonical. Outputs are regular, immutable, mode-0600, fsynced, and symlink-safe.
- Generated checkpoints and proofs remain outside package source.

`ABP001` through `ABP009` cover unsafe paths, malformed evidence, stale pins, mismatches, selector errors, proof changes, substitutions, and overwrite attempts.

These artifacts prove integrity and consumer-observed continuity, not producer identity. Consumers retain checkpoint IDs externally and apply authenticated transport or signatures separately where required.
