# Audit trust receiver checkpoints

Receiver checkpoints make one exact consumer-owned receiver-state generation portable without distributing the complete receiver history.

## Create a checkpoint

Retain the current receiver `state_id` outside the state file, then create an immutable checkpoint:

```bash
basit-agent-audit-trust-receiver-checkpoint create \
  receiver-state.json receiver-checkpoint.json \
  --expected-state-id "$RECEIVER_STATE_ID"
```

The checkpoint binds the exact receiver state ID, accepted-entry count, current receiver head, Merkle algorithm, RFC 6962 root, and a domain-separated checkpoint ID.

## Create an inclusion proof

Select one accepted handoff by sequence:

```bash
basit-agent-audit-trust-receiver-checkpoint prove \
  receiver-state.json receiver-checkpoint.json handoff-proof.json \
  --expected-state-id "$RECEIVER_STATE_ID" \
  --expected-checkpoint-id "$RECEIVER_CHECKPOINT_ID" \
  --sequence 2
```

Or select it by exact handoff bundle ID:

```bash
--handoff-bundle-id "$HANDOFF_BUNDLE_ID"
```

## Verify without the complete state

```bash
agent-audit-trust-receiver-checkpoint verify-proof \
  handoff-proof.json receiver-checkpoint.json \
  --expected-checkpoint-id "$RECEIVER_CHECKPOINT_ID"
```

Supplying `--handoff portable-handoff` additionally re-verifies the complete snapshot or transition handoff and binds its exact bytes to the authenticated receiver entry.

## Lineage

```bash
agent-audit-trust-receiver-checkpoint lineage \
  retained-receiver.json candidate-receiver.json \
  --expected-left-state-id "$RETAINED_RECEIVER_STATE_ID" \
  --expected-right-state-id "$CANDIDATE_RECEIVER_STATE_ID"
```

Accepted relations are `same` and `right-descendant`. Rollback is `ARC010`; fork is `ARC011`.

## Operational boundary

- Checkpoints and proofs are strict canonical JSON.
- New outputs are immutable, mode `0600`, fsynced, symlink-safe, and never overwritten.
- Caller-supplied checkpoint and state pins provide freshness.
- Proof verification can operate after the complete receiver state has been removed.
- These artifacts prove integrity and continuity; they are unsigned and do not establish signer identity.
