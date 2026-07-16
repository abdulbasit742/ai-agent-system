# Audit trust receiver acceptance checkpoints

Task 33 adds portable Merkle checkpoints and per-receiver-bundle inclusion proofs for the consumer-owned acceptance state introduced in Task 32.

## Purpose

An acceptance state records receiver checkpoint bundles that a consumer fully verified and admitted. A checkpoint commits one exact externally pinned acceptance state to an RFC 6962-style Merkle root. An inclusion proof authenticates one accepted receiver bundle entry without distributing the complete acceptance history.

## Commands

Create a checkpoint:

```bash
basit-agent-audit-trust-receiver-acceptance-checkpoint create \
  receiver-acceptance.json acceptance-checkpoint.json \
  --expected-state-id "$ACCEPTANCE_STATE_ID"
```

Create a proof by sequence or receiver bundle ID:

```bash
basit-agent-audit-trust-receiver-acceptance-checkpoint prove \
  receiver-acceptance.json acceptance-checkpoint.json acceptance-proof.json \
  --expected-state-id "$ACCEPTANCE_STATE_ID" \
  --expected-checkpoint-id "$ACCEPTANCE_CHECKPOINT_ID" \
  --handoff-bundle-id "$RECEIVER_BUNDLE_ID"
```

Verify after deleting the complete acceptance state:

```bash
agent-audit-trust-receiver-acceptance-checkpoint verify-proof \
  acceptance-proof.json acceptance-checkpoint.json \
  --expected-checkpoint-id "$ACCEPTANCE_CHECKPOINT_ID"
```

Supplying `--handoff <receiver-bundle-directory>` additionally re-verifies the complete portable receiver checkpoint bundle and binds it to the authenticated acceptance entry.

## Evidence model

The checkpoint binds the exact acceptance `state_id`, entry count, current acceptance head, Merkle algorithm/root, and domain-separated checkpoint ID. Proofs bind the complete canonical acceptance entry, checkpoint reference, compact audit path, and domain-separated proof ID.

The implementation uses RFC 6962 leaf and node domains. Odd leaves are not duplicated. Proof verification rejects missing or extra path hashes, checkpoint substitution, rehashed entry/path tampering, stale external pins, unsafe paths, and noncanonical JSON.

## Lineage

Lineage accepts only identical or exact right-descendant acceptance histories.

- `ASC010`: rollback.
- `ASC011`: fork.

All outputs are immutable, regular non-symlink files created with mode `0600`, fsynced before publication, and never overwritten.

## Trust boundary

These artifacts are unsigned. They prove integrity and append-only continuity, not producer identity. Consumers must retain state/checkpoint IDs separately and obtain checkpoints through an authenticated channel.
