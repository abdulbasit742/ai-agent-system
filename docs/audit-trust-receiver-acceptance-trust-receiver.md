# Pinned receiver-acceptance trust handoff state

Task 42 adds a consumer-owned pinned state for admitted receiver-acceptance trust handoff bundles.

## Purpose

A handoff admission decision is intentionally stateless. The receiver state records which admitted snapshot established the local trust anchor and which admitted transitions advanced it. This prevents a consumer from silently accepting replayed, older, or alternate handoff histories after a valid policy decision.

The state and policy must remain outside the handoff bundle. The latest returned `state_id` must be retained independently and supplied on every later verification or advancement.

## Commands

Initialize from an admitted snapshot handoff:

```bash
basit-agent-audit-trust-receiver-acceptance-trust-receiver init \
  acceptance-trust-receiver.json snapshot-handoff \
  --policy acceptance-trust-policy.json \
  --expected-bundle-id "$SNAPSHOT_HANDOFF_ID" \
  --expected-candidate-checkpoint-id "$ACCEPTANCE_TRUST_CHECKPOINT_ID"
```

Verify the state and optionally re-verify its current-head handoff:

```bash
agent-audit-trust-receiver-acceptance-trust-receiver verify \
  acceptance-trust-receiver.json \
  --expected-state-id "$RECEIVER_STATE_ID" \
  --bundle current-head-handoff
```

Advance through an admitted transition:

```bash
basit-agent-audit-trust-receiver-acceptance-trust-receiver advance \
  acceptance-trust-receiver.json transition-handoff \
  --policy acceptance-trust-policy.json \
  --expected-state-id "$RECEIVER_STATE_ID" \
  --expected-bundle-id "$TRANSITION_HANDOFF_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_ACCEPTANCE_TRUST_CHECKPOINT_ID"
```

## Canonical history

Every state entry binds:

- the handoff bundle ID;
- the candidate acceptance-trust checkpoint ID, state ID, entry count, Merkle root, and head entry hash;
- the nested acceptance checkpoint/state/count and head acceptance bundle ID;
- the nested receiver checkpoint/state/count and head receiver bundle ID;
- the nested trust checkpoint/state/count and trust handoff ID;
- generation and segment count;
- the admission decision ID and policy hash;
- exact transition deltas and the previous acceptance-trust checkpoint/state IDs.

Entries use a domain-separated SHA-256 hash chain. The canonical state ID commits the complete entry list and exact current head.

## Advancement rules

Initialization accepts only an admitted snapshot. Advancement accepts only an admitted transition whose previous checkpoint exactly matches the current receiver head, including:

- outer acceptance-trust checkpoint/state/count/Merkle root;
- the outer head entry hash;
- all nested acceptance, receiver, and trust identities and counts;
- generation and segment count.

The candidate must increase all four history depths and generation. Segment count may stay equal or increase. Duplicate handoff, checkpoint, or state identities are rejected.

## Exit semantics

- `0`: state created, verified, or advanced;
- `1`: verified input denied by policy, stale state pin, replay, rollback, fork, or head mismatch;
- `2`: malformed, unsafe, noncanonical, lock-unavailable, or unverifiable input.

Stable diagnostics are `ABN001` through `ABN010`:

- `ABN001`: unsafe path, symlink, or output boundary;
- `ABN002`: malformed schema, hash chain, or handoff/admission input;
- `ABN003`: externally retained state pin mismatch;
- `ABN004`: policy denial;
- `ABN005`: invalid snapshot/transition role;
- `ABN006`: retained-head continuity mismatch;
- `ABN007`: duplicate or replayed identity;
- `ABN008`: non-advancing nested history;
- `ABN009`: state or policy placed inside the handoff bundle;
- `ABN010`: locking or atomic I/O failure.

Denied and invalid operations leave the existing state bytes unchanged.

## Storage boundary

The state engine uses a same-directory sidecar advisory lock, canonical mode-`0600` temporary files, `fsync`, and atomic replacement. The state, lock sidecar, policy, handoff bundles, retained IDs, decisions, and CI evidence are generated consumer data and are not part of the wheel.

The state is unsigned. Hashes and external pins prove integrity, continuity, and freshness; they do not authenticate the producer.
