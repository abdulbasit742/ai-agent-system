# Audit trust receiver acceptance state

Task 32 adds a consumer-owned pinned state for receiver checkpoint bundles that have passed receiver-bundle admission.

## Purpose

Receiver bundle verification proves integrity. Receiver admission decides whether a verified bundle satisfies local policy. The acceptance state remembers the admitted sequence so a consumer can reject replay, rollback, alternate predecessors, and stale local state.

## Commands

Initialize from an admitted receiver snapshot bundle:

```bash
basit-agent-audit-trust-receiver-acceptance init \
  receiver-acceptance.json receiver-snapshot-bundle \
  --policy receiver-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$RECEIVER_CHECKPOINT_ID"
```

Retain the returned `state_id` separately. Advance only through an admitted receiver transition bundle:

```bash
basit-agent-audit-trust-receiver-acceptance advance \
  receiver-acceptance.json receiver-transition-bundle \
  --policy receiver-admission.json \
  --expected-state-id "$ACCEPTANCE_STATE_ID" \
  --expected-bundle-id "$CANDIDATE_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_RECEIVER_CHECKPOINT_ID"
```

Verify the pinned state and optionally re-verify its current receiver bundle:

```bash
agent-audit-trust-receiver-acceptance verify \
  receiver-acceptance.json \
  --expected-state-id "$ACCEPTANCE_STATE_ID" \
  --bundle receiver-transition-bundle
```

## Bound evidence

Each canonical hash-chain entry binds:

- receiver bundle ID and type;
- candidate receiver checkpoint and receiver-state IDs;
- receiver entry count, receiver Merkle root, and receiver head entry;
- underlying trusted checkpoint, trusted state, trusted entry count, generation, and segment count;
- admission decision ID and policy SHA-256;
- for transitions, exact previous receiver checkpoint/state and receiver/trust/generation deltas.

## State transitions

- Initialization accepts only an admitted snapshot receiver bundle.
- Advancement accepts only an admitted transition whose previous receiver checkpoint/state/count equals the current acceptance head.
- The underlying trust checkpoint/state/count must also equal the current head.
- Receiver entry count, trusted entry count, and generation must increase; segment count must not decrease.
- Previously accepted receiver bundle, checkpoint, or state identities cannot be replayed.

## Filesystem boundary

The state and policy must stay outside the receiver bundle. State updates use the reviewed sidecar lock, strict canonical JSON, mode `0600`, same-directory temporary files, fsync, and atomic replacement. Denied or invalid operations do not change accepted state bytes.

## Exit codes

- `0`: state initialized, verified, or advanced.
- `1`: verified evidence was denied, stale-pinned, replayed, or did not advance the retained head.
- `2`: malformed, unsafe, or unverifiable input.

Stable diagnostics use `ARS001` through `ARS010`. The state is unsigned; consumers must retain the latest `state_id` independently to detect rollback or replacement.
