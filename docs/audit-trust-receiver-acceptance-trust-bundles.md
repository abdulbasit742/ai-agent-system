# Receiver-acceptance trust handoff bundles

Task 40 packages pinned receiver-acceptance trust checkpoints and proofs into immutable exact-boundary directories for offline transfer.

## Bundle types

A **snapshot** contains:

- one candidate acceptance-trust checkpoint;
- one or more inclusion proofs for that checkpoint;
- a mandatory proof for the candidate head entry;
- a canonical manifest and sorted `SHA256SUMS`.

A **transition** additionally contains:

- one previous acceptance-trust checkpoint;
- one compact `right-descendant` consistency proof binding previous and candidate checkpoints.

Creation fully validates all loose evidence before publishing the final directory. Verification needs only the bundle and externally retained bundle/checkpoint IDs; complete acceptance-trust states are not required.

## Create a snapshot

```bash
basit-agent-audit-trust-receiver-acceptance-trust-bundle create trust-handoff \
  --candidate-checkpoint candidate-checkpoint.json \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof candidate-head-proof.json
```

## Create a transition

```bash
basit-agent-audit-trust-receiver-acceptance-trust-bundle create trust-transition \
  --candidate-checkpoint candidate-checkpoint.json \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof candidate-head-proof.json \
  --previous-checkpoint retained-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --consistency-proof acceptance-trust-consistency.json
```

## Verify offline

```bash
agent-audit-trust-receiver-acceptance-trust-bundle verify trust-transition \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID"
```

After creation, the loose states, checkpoints, proofs, and consistency file may be removed. The bundle remains independently verifiable because every copied byte is manifest- and checksum-bound.

## Files and limits

The manifest is `audit-trust-receiver-acceptance-trust-bundle-manifest.json`. Reviewed roles are:

- `candidate-acceptance-trust-checkpoint`;
- `previous-acceptance-trust-checkpoint`;
- `acceptance-trust-consistency-proof`;
- `acceptance-trust-inclusion-proof`.

Bundles are bounded by 260 files, 128 inclusion proofs, and 64 MiB total bytes. Paths must be safe POSIX-relative names. Symlinks, extra files, missing files, duplicate evidence, stale pins, partial transition arguments, and output overwrite attempts are rejected.

## Exit semantics

- `0`: created or verified;
- `1`: verified evidence is denied by a continuity rule;
- `2`: malformed, unsafe, stale-pinned, substituted, or unverifiable evidence.

Stable diagnostics use `ABB001` through `ABB012`. `ABB012` requires the candidate-head proof. `ABB011` protects immutable publication.

## Trust boundary

Bundle IDs and SHA-256 checksums prove integrity and composition, not producer identity. Retain the latest accepted bundle and checkpoint IDs outside the transferred directory. Signing, witness, and publication policy remain consumer responsibilities.
