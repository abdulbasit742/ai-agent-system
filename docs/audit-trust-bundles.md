# Portable audit trust handoff bundles

Audit trust handoff bundles package checkpoint-level trust evidence into one immutable, exact-boundary directory for offline transfer and verification.

## Bundle types

A **snapshot** handoff contains:

- one externally pinned candidate audit-trust checkpoint;
- one or more inclusion proofs bound to that checkpoint;
- exactly one inclusion proof for the candidate checkpoint head;
- a canonical manifest and sorted `SHA256SUMS`.

A **transition** handoff additionally contains:

- one externally pinned previous audit-trust checkpoint;
- one compact right-descendant consistency proof binding the previous and candidate checkpoints.

The candidate-head proof is mandatory so a handoff cannot provide only selected historical entries while omitting authenticated evidence for the current trusted bundle.

## Create a snapshot handoff

```bash
basit-agent-audit-trust-bundle create audit-trust-handoff \
  --candidate-checkpoint candidate-trust-checkpoint.json \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof candidate-head-proof.json
```

Additional `--proof` options may carry selected historical bundle entries. Proofs must be unique and belong to the candidate checkpoint.

## Create a transition handoff

```bash
basit-agent-audit-trust-bundle create audit-trust-handoff \
  --candidate-checkpoint candidate-trust-checkpoint.json \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof candidate-head-proof.json \
  --previous-checkpoint retained-trust-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --consistency-proof trust-consistency-proof.json
```

All source evidence is fully verified before the output directory is created. The destination must not already exist.

## Offline verification

Snapshot:

```bash
agent-audit-trust-bundle verify audit-trust-handoff \
  --expected-bundle-id "$HANDOFF_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Transition:

```bash
agent-audit-trust-bundle verify audit-trust-handoff \
  --expected-bundle-id "$HANDOFF_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID"
```

Verification requires no trust-state files and no loose source proofs. It checks the exact filesystem boundary, manifest schema, checksums, per-file digests and sizes, checkpoint pins, inclusion-proof bindings, consistency-proof binding, and the mandatory candidate-head entry.

## Exit codes

- `0`: created or fully verified;
- `1`: structurally valid evidence denied because an external pin or transition relation is unacceptable;
- `2`: malformed, unsafe, non-canonical, tampered, incomplete, or otherwise unverifiable input.

Stable diagnostics use `ATB001` through `ATB012`.

## Trust boundary

The handoff bundle is an unsigned integrity and portability container. Its bundle ID and checksums do not authenticate a producer, provide a trusted timestamp, establish witness consensus, or replace separately retained bundle/checkpoint pins.
