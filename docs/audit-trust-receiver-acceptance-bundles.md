# Portable receiver-acceptance checkpoint bundles

Task 35 packages pinned receiver-acceptance checkpoints and their portable proofs into immutable exact-boundary directories for offline handoff.

## Bundle types

A **snapshot** bundle contains:

- one candidate acceptance checkpoint;
- one or more acceptance inclusion proofs;
- exactly one proof for the candidate head;
- a canonical manifest and sorted SHA-256 checksums.

A **transition** bundle additionally contains:

- one previous acceptance checkpoint;
- one compact acceptance consistency proof with relation `right-descendant`.

Creation validates all source evidence before writing a staged directory. The staged directory is independently verified before it is atomically renamed to the requested output path.

## Installed commands

```bash
basit-agent-audit-trust-receiver-acceptance-bundle create acceptance-handoff \
  --candidate-checkpoint candidate-acceptance-checkpoint.json \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof candidate-head-proof.json
```

Transition creation adds:

```bash
--previous-checkpoint retained-acceptance-checkpoint.json \
--expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
--consistency-proof acceptance-consistency.json
```

Verify without complete acceptance states or loose proof files:

```bash
agent-audit-trust-receiver-acceptance-bundle verify acceptance-handoff \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID"
```

Do not pass `--expected-previous-checkpoint-id` for snapshot bundles.

## Exact layout

Generated files use acceptance-specific names:

- `audit-trust-receiver-acceptance-bundle-manifest.json`
- `SHA256SUMS`
- `candidate-acceptance-checkpoint.json`
- optional `previous-acceptance-checkpoint.json`
- optional `acceptance-consistency-proof.json`
- `proofs/acceptance-entry-XXXXXXXX.json`

The manifest binds bundle type, candidate and previous checkpoint identities, consistency identity, selected acceptance entries, exact file roles, byte sizes, SHA-256 digests, and a domain-separated bundle ID.

## Exit codes

- `0`: bundle created or fully verified;
- `1`: structurally valid evidence denied by an external pin or continuity rule;
- `2`: malformed, unsafe, tampered, incomplete, or noncanonical evidence.

## Freshness and identity

Bundle IDs and checksums prove integrity, not producer identity. Retain the latest bundle and checkpoint IDs in an independent trusted channel. Signing and key management remain outside this repository.
