# Audit trust receiver state

Task 27 adds a consumer-owned state that records only admitted audit trust handoff bundles.

## Initialize

A new state accepts only an admitted snapshot handoff. Keep the returned `state_id` outside the repository and outside the handoff bundle.

```bash
basit-agent-audit-trust-receiver init receiver-state.json snapshot-handoff \
  --policy audit-trust-admission.json \
  --expected-bundle-id "$HANDOFF_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$TRUST_CHECKPOINT_ID"
```

## Advance

Advancement accepts only an admitted transition handoff whose previous checkpoint, previous trust-state ID, and previous entry count equal the receiver head.

```bash
agent-audit-trust-receiver advance receiver-state.json transition-handoff \
  --policy audit-trust-admission.json \
  --expected-state-id "$RECEIVER_STATE_ID" \
  --expected-bundle-id "$NEXT_HANDOFF_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$NEXT_TRUST_CHECKPOINT_ID"
```

## Verify

```bash
basit-agent-audit-trust-receiver verify receiver-state.json \
  --expected-state-id "$RECEIVER_STATE_ID" \
  --bundle current-handoff
```

The optional handoff is fully re-verified and must equal the receiver head.

## State contents

Each hash-chained entry binds the handoff bundle ID, candidate trust checkpoint and trust-state IDs, trust entry count, Merkle root, authenticated trust head, generation and segment count, admission decision ID, admission policy hash, and transition deltas. Duplicate handoffs, checkpoints, or candidate trust-state IDs are rejected.

## Exit codes

- `0`: created, verified, or advanced
- `1`: verified input denied, including stale receiver pins or replay/head mismatch
- `2`: malformed, unsafe, or unverifiable input

Diagnostics are `ATR001` through `ATR010`. State writes use a sidecar advisory lock, mode `0600`, fsync, and atomic replacement. Denied and invalid operations do not modify state bytes.
