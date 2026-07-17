# Receiver-acceptance trust consistency proofs

This control creates compact append-only evidence between two externally pinned receiver-acceptance trust checkpoints.

## Create a proof

```bash
basit-agent-audit-trust-receiver-acceptance-trust-consistency prove \
  retained-state.json retained-checkpoint.json \
  candidate-state.json candidate-checkpoint.json \
  acceptance-trust-consistency.json \
  --expected-previous-state-id "$RETAINED_STATE_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-state-id "$CANDIDATE_STATE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Creation fully validates both canonical trust states and both checkpoints. A rollback or fork denial does not create an output artifact.

## Verify without complete states

```bash
agent-audit-trust-receiver-acceptance-trust-consistency verify \
  acceptance-trust-consistency.json \
  retained-checkpoint.json candidate-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Verification reconstructs both RFC 6962 Merkle roots from canonical aligned power-of-two frontiers. The complete receiver-acceptance trust states are not required.

## Authenticated append boundary

For a right-descendant proof, the first appended entry is exposed as a one-leaf frontier segment. The verifier requires it to:

- immediately follow the retained entry count;
- be a transition entry;
- retain the previous trust-entry hash;
- retain the previous acceptance checkpoint and state identities;
- carry exact positive acceptance, receiver, trust, and generation deltas;
- carry an exact non-negative segment delta;
- be committed by the append frontier; and
- advance the candidate checkpoint head without reducing segment count.

## Exit codes and diagnostics

- `0`: proof created or verified;
- `1`: valid rollback or fork denial;
- `2`: malformed, unsafe, stale-pinned, or unverifiable input.

Stable diagnostics are `ABR001` through `ABR011`. `ABR009` is rollback, `ABR010` is fork, and `ABR011` is an invalid nested transition boundary.

## Trust boundary

The proof authenticates integrity and append-only continuity, not producer identity. Retain checkpoint IDs outside the proof package and authenticate the producer channel separately when identity matters.
