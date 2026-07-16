# Audit trust receiver acceptance consistency proofs

This control creates compact append-only consistency evidence between two externally pinned acceptance-state checkpoints.

## Create a proof

```bash
basit-agent-audit-trust-receiver-acceptance-consistency prove \
  retained-acceptance.json retained-acceptance-checkpoint.json \
  candidate-acceptance.json candidate-acceptance-checkpoint.json \
  acceptance-consistency.json \
  --expected-previous-state-id "$RETAINED_ACCEPTANCE_STATE_ID" \
  --expected-previous-checkpoint-id "$RETAINED_ACCEPTANCE_CHECKPOINT_ID" \
  --expected-candidate-state-id "$CANDIDATE_ACCEPTANCE_STATE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_ACCEPTANCE_CHECKPOINT_ID"
```

Creation fully validates both acceptance histories and both checkpoints. It accepts identical histories or an exact right-descendant extension. Rollback and fork relations do not create proof artifacts.

## Verify without complete states

```bash
agent-audit-trust-receiver-acceptance-consistency verify \
  acceptance-consistency.json \
  retained-acceptance-checkpoint.json candidate-acceptance-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_ACCEPTANCE_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_ACCEPTANCE_CHECKPOINT_ID"
```

Verification reconstructs both Merkle roots from canonical aligned power-of-two frontiers. The complete acceptance-state files are not required.

## Authenticated transition boundary

For a right-descendant proof, the first appended acceptance entry is exposed as a single-leaf frontier segment and must:

- be the next sequence and a transition entry;
- retain the exact previous acceptance entry hash;
- retain the previous receiver checkpoint and receiver state identifiers;
- bind the exact receiver-entry, underlying-trust-entry, and generation deltas;
- authenticate its canonical entry bytes through the first append-frontier hash;
- advance receiver entries, trust entries, and generation while never decreasing segment count.

The remaining suffix is represented by a canonical compact range. Proof size therefore grows logarithmically with history size rather than containing every accepted bundle entry.

## Safety and exit semantics

Proof files are strict canonical JSON, immutable no-overwrite artifacts, symlink-safe, fsynced, and mode `0600`.

- `0`: identical or right-descendant proof created or verified.
- `1`: valid rollback or fork denial.
- `2`: malformed, unsafe, stale-pinned, substituted, or unverifiable input.

Stable rules are `ASR001` through `ASR011`. `ASR009` denotes rollback, `ASR010` denotes fork or same-size checkpoint substitution, and `ASR011` denotes invalid acceptance-transition boundary continuity.

These proofs provide integrity and append-only lineage, not producer identity. Consumers must retain checkpoint IDs independently and apply their own authentication or signing policy.