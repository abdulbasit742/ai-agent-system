# Receiver-acceptance trust checkpoints

`agent_audit_trust_receiver_acceptance_trust_checkpoint.py` creates portable Merkle checkpoints and per-bundle inclusion proofs for the pinned receiver-acceptance trust state introduced in Task 37.

## Commands

```bash
basit-agent-audit-trust-receiver-acceptance-trust-checkpoint create \
  acceptance-trust.json acceptance-trust-checkpoint.json \
  --expected-state-id "$STATE_ID"

basit-agent-audit-trust-receiver-acceptance-trust-checkpoint prove \
  acceptance-trust.json acceptance-trust-checkpoint.json bundle-proof.json \
  --expected-state-id "$STATE_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --handoff-bundle-id "$ACCEPTANCE_BUNDLE_ID"

agent-audit-trust-receiver-acceptance-trust-checkpoint verify-proof \
  bundle-proof.json acceptance-trust-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID"
```

The complete trust state is not required during proof verification. Supplying `--handoff <bundle-directory>` re-verifies the complete snapshot or transition acceptance bundle and binds it to the authenticated entry.

## Commitments

A checkpoint binds:

- the exact externally pinned acceptance-trust `state_id`;
- accepted-entry count;
- the complete outer acceptance and nested receiver/trust head;
- RFC 6962 domain-separated Merkle root; and
- domain-separated `checkpoint_id`.

An inclusion proof binds one complete trust entry, its checkpoint reference, canonical audit path, and domain-separated `proof_id`. Entries may be selected by sequence or exact acceptance bundle ID.

## Lineage and safety

Lineage accepts only identical or right-descendant states. `ABP010` denotes rollback and `ABP011` denotes fork. Outputs are strict canonical JSON, immutable no-overwrite regular files, mode `0600`, fsynced, and symlink-safe. Callers retain checkpoint IDs independently for freshness.

These artifacts are unsigned integrity evidence and do not authenticate the producer.
