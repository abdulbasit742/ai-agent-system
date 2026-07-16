# Pinned receiver-acceptance bundle trust state

Task 37 turns admitted receiver-acceptance checkpoint bundles into persistent consumer-owned history.

## Purpose

Bundle verification proves exact evidence integrity. Admission decides whether that evidence satisfies consumer policy. The trust state records accepted decisions so a receiver cannot later substitute an older, replayed, or divergent acceptance bundle without changing the externally retained state identity.

## Commands

Initialize from an admitted snapshot bundle:

```bash
basit-agent-audit-trust-receiver-acceptance-trust init acceptance-trust.json snapshot-bundle \
  --policy acceptance-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CHECKPOINT_ID"
```

Retain the returned `state_id` outside the state file. Advance only through an admitted transition:

```bash
agent-audit-trust-receiver-acceptance-trust advance acceptance-trust.json transition-bundle \
  --policy acceptance-admission.json \
  --expected-state-id "$STATE_ID" \
  --expected-bundle-id "$CANDIDATE_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Verify the pinned state and optionally re-verify the current-head bundle:

```bash
basit-agent-audit-trust-receiver-acceptance-trust verify acceptance-trust.json \
  --expected-state-id "$STATE_ID" \
  --bundle current-head-bundle
```

## State commitments

Each canonical hash-chained entry binds:

- the acceptance-bundle ID;
- the acceptance checkpoint and state IDs, entry count, Merkle root, and head entry hash;
- the authenticated head receiver-bundle ID;
- the nested receiver checkpoint/state IDs and receiver entry count;
- generation and segment counts;
- the admission decision ID and policy hash;
- previous acceptance checkpoint/state identity and exact acceptance/receiver/generation deltas for transitions.

The state uses domain-separated entry and state hashes. The acceptance checkpoint already commits the complete nested receiver and trust history, while the admission decision independently verifies and authorizes the acceptance, receiver, and trust identities.

## Mutation rules

- initialization accepts only an admitted snapshot;
- advancement accepts only an admitted transition whose previous acceptance checkpoint, state, entry count, and nested receiver head equal the retained state head;
- acceptance and receiver entry counts and generation must increase;
- segment count must not decrease;
- duplicate bundle, checkpoint, or state identities are rejected;
- state and policy paths must remain outside the bundle;
- updates use a sidecar advisory lock, mode-0600 temporary files, fsync, and same-directory atomic replacement;
- denied or invalid operations preserve the original bytes.

## Exit status

- `0`: initialized, verified, or advanced;
- `1`: fully verified evidence was denied or rejected as stale/replay/head mismatch;
- `2`: malformed, unsafe, unverifiable, or incorrectly composed input.

Stable diagnostics use `ABT001` through `ABT010`.

## Trust boundary

This state is unsigned. Hashes prove canonical integrity and append-only linkage, not producer identity. Freshness depends on retaining the latest `state_id` independently and supplying exact bundle/checkpoint pins.
