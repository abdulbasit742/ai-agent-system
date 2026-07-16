# Receiver-acceptance trust state

`agent_audit_trust_receiver_acceptance_trust.py` converts admitted receiver-acceptance checkpoint bundles into a persistent consumer-owned history.

## Lifecycle

- `init` accepts only an admitted snapshot bundle.
- `advance` accepts only an admitted transition bundle whose previous acceptance checkpoint, acceptance state, nested receiver head, and nested trust head equal the current trust-state head.
- `verify` requires an externally retained `state_id` and may re-verify the current acceptance bundle.

```bash
basit-agent-audit-trust-receiver-acceptance-trust init \
  acceptance-trust.json snapshot-acceptance-bundle \
  --policy acceptance-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$ACCEPTANCE_CHECKPOINT_ID"

agent-audit-trust-receiver-acceptance-trust advance \
  acceptance-trust.json transition-acceptance-bundle \
  --policy acceptance-admission.json \
  --expected-state-id "$STATE_ID" \
  --expected-bundle-id "$CANDIDATE_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

## Bound evidence

Each hash-chained entry binds:

- acceptance bundle, checkpoint, state, entry count, Merkle root, and head entry hash;
- accepted receiver bundle, checkpoint, state, and receiver entry count;
- underlying trust handoff, checkpoint, state, and trust entry count;
- trusted generation and segment count;
- admission decision ID and policy hash; and
- exact acceptance, receiver, trust, generation, and segment deltas.

The state uses domain-separated entry and state hashes. Duplicate bundle/checkpoint/state identities, replay, rollback, nested-head substitution, stale pins, policy denial, malformed JSON, symlinks, and lock failures are rejected.

## Mutation safety

State updates use the reviewed sidecar advisory lock and same-directory atomic replace implementation. The state and policy must remain outside transferred bundles. Denied or invalid operations do not modify state bytes.

Exit codes are:

- `0`: created, verified, or advanced;
- `1`: verified evidence denied, replayed, stale-pinned, or inconsistent with the retained head;
- `2`: malformed, unsafe, or unverifiable input.

Stable diagnostics are `ABT001` through `ABT010`.

## Trust boundary

This state is consumer-owned integrity and freshness evidence. It is unsigned and does not authenticate the producer. Retain the current `state_id` independently and apply transport or signature policy separately when producer identity is required.
