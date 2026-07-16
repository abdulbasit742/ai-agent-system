# Security audit: receiver acceptance checkpoints

## Scope

This audit covers `agent_audit_trust_receiver_acceptance_checkpoint.py`, its source and installed-package workflows, and the acceptance checkpoint/proof artifacts introduced by Task 33.

## Reviewed controls

- Complete acceptance states are strictly validated before checkpoint or proof creation.
- Creation requires an externally retained acceptance `state_id` pin.
- Verification requires an externally retained checkpoint ID.
- Checkpoints bind the exact state ID, entry count, acceptance head, Merkle algorithm/root, and canonical checkpoint ID.
- Inclusion proofs bind one complete accepted receiver-bundle entry and reconstruct the exact checkpoint root.
- Proof selection requires exactly one sequence or receiver-bundle ID selector.
- Optional bundle binding re-verifies the complete receiver checkpoint bundle and compares its normalized evidence to the authenticated entry.
- Lineage accepts only identical or exact right-descendant histories.
- Strict JSON rejects duplicate keys, non-finite numbers, unsupported schemas, and noncanonical serialization.
- Outputs reject symlinks and existing paths, use mode `0600`, flush and fsync before publication, and never overwrite.
- The acceptance adapter loads the reviewed receiver-checkpoint engine into an isolated namespace; the original receiver checkpoint module and diagnostics are not mutated.

## Stable diagnostics

- `ASC001`: unsafe path or filesystem boundary.
- `ASC002`: malformed, noncanonical, unsupported, or internally inconsistent evidence.
- `ASC003`: malformed or stale external pin.
- `ASC004`: checkpoint/state mismatch.
- `ASC005`: invalid or missing proof selector.
- `ASC006`: inclusion-path or Merkle-root failure.
- `ASC007`: proof/checkpoint substitution.
- `ASC008`: receiver-bundle verification or authenticated-entry mismatch.
- `ASC009`: overwrite or immutable-output violation.
- `ASC010`: rollback lineage denial.
- `ASC011`: fork lineage denial.

## Residual boundary

Checkpoint and proof IDs are unsigned hashes. They do not authenticate producer identity or freshness by themselves. Consumers must retain the latest IDs outside the generated evidence and obtain those pins through an authenticated channel.

No signing keys, credentials, runtime dependencies, acceptance states, checkpoints, proofs, receiver bundles, policies, or generated reports are included in the wheel.
