# Compact audit trust consistency proofs

`agent_audit_trust_consistency.py` creates portable evidence that one pinned audit bundle trust checkpoint is identical to, or an append-only ancestor of, another checkpoint.

The proof is useful when a verifier retains old and new checkpoint files but does not receive either complete trust-state history.

## Create a proof

```bash
basit-agent-audit-trust-consistency prove \
  retained-state.json retained-checkpoint.json \
  candidate-state.json candidate-checkpoint.json \
  audit-trust-consistency.json \
  --expected-previous-state-id "$RETAINED_STATE_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-state-id "$CANDIDATE_STATE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Creation fully validates both canonical trust states, binds each checkpoint to its exact externally pinned state, classifies lineage, and refuses to create evidence for rollback or fork relations.

## Verify without trust states

```bash
agent-audit-trust-consistency verify \
  audit-trust-consistency.json \
  retained-checkpoint.json candidate-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Verification reconstructs both checkpoint Merkle roots from the proof. The complete trust states are not read.

## Proof contents

A proof contains:

- exact references to both pinned checkpoints;
- relation: `same` or `right-descendant`;
- a canonical compact frontier covering the retained prefix;
- a canonical compact frontier covering appended entries;
- the first appended transition entry for descendant proofs;
- a domain-separated canonical `consistency_id`.

The first appended entry is exposed as a one-leaf frontier segment. Verification checks its sequence, previous entry hash, previous checkpoint/catalog identities, generation delta, and Merkle authentication. This prevents a compact root proof from hiding an invalid transition at the retained boundary.

## Merkle construction

Trust entries use the same tree construction as audit trust checkpoints:

- leaf: `SHA-256(0x00 || canonical-entry-bytes)`;
- node: `SHA-256(0x01 || left || right)`;
- RFC 6962 largest-power-of-two splitting;
- odd leaves are never duplicated.

Frontiers use canonical maximal aligned power-of-two ranges. Proof size grows logarithmically for ordinary append-only histories.

## Outcomes

- exit `0`: identical or right-descendant proof created/verified;
- exit `1`: rollback, fork, or stale external pin;
- exit `2`: malformed, unsafe, non-canonical, or unverifiable input.

Stable diagnostics are `ATK001` through `ATK011`. `ATK009` is rollback, `ATK010` is fork, and `ATK011` is invalid transition-boundary continuity.

## Operational model

Retain checkpoint IDs independently from the checkpoint and proof files. A self-consistent unsigned proof does not establish freshness. Proof outputs are strict canonical JSON, bounded, mode `0600`, symlink-safe, and immutable atomic no-overwrite files.
