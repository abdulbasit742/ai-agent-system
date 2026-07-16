# Portable audit bundle trust checkpoints

Audit bundle trust states are consumer-owned histories of admitted snapshot and transition bundles. A portable checkpoint commits one exact externally pinned trust-state generation to a Merkle root, while an inclusion proof authenticates one admitted bundle entry without distributing the complete state.

## Trust boundary

A checkpoint is created only from a completely validated trust state whose exact `state_id` is supplied by the caller. Verification requires an externally retained `checkpoint_id`. The files are unsigned integrity commitments; they do not identify or authenticate a producer.

Retain at least these values outside the evidence files:

- the latest trust-state `state_id`
- the checkpoint `checkpoint_id`
- the reviewed admission policy and bundle pins used by the trust-state workflow

## Create a checkpoint

```bash
basit-agent-audit-trust-checkpoint create \
  audit-trust-state.json audit-trust-checkpoint.json \
  --expected-state-id "$STATE_ID" \
  --format json
```

The checkpoint binds:

- checkpoint schema version
- exact trust-state ID
- entry count
- current trust-state head
- RFC 6962-style SHA-256 Merkle root
- domain-separated checkpoint ID

Leaves use `SHA256(0x00 || canonical_entry)` and internal nodes use `SHA256(0x01 || left || right)`. Odd leaves are not duplicated.

## Verify a checkpoint

Checkpoint-only verification:

```bash
agent-audit-trust-checkpoint verify audit-trust-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID"
```

Bind it again to the complete state:

```bash
agent-audit-trust-checkpoint verify audit-trust-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --state audit-trust-state.json \
  --expected-state-id "$STATE_ID"
```

## Create an inclusion proof

Select exactly one trust entry by sequence:

```bash
basit-agent-audit-trust-checkpoint prove \
  audit-trust-state.json audit-trust-checkpoint.json bundle-proof.json \
  --expected-state-id "$STATE_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --sequence 4
```

Or select it by exact bundle ID:

```bash
basit-agent-audit-trust-checkpoint prove \
  audit-trust-state.json audit-trust-checkpoint.json bundle-proof.json \
  --expected-state-id "$STATE_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --bundle-id "$BUNDLE_ID"
```

The proof contains the complete privacy-safe trust entry and only the sibling hashes needed to reconstruct the checkpoint root.

## Verify a proof without the state

```bash
agent-audit-trust-checkpoint verify-proof \
  bundle-proof.json audit-trust-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID"
```

Optionally bind the authenticated entry to the actual portable bundle:

```bash
agent-audit-trust-checkpoint verify-proof \
  bundle-proof.json audit-trust-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --bundle admitted-transition-bundle
```

The optional bundle mode fully verifies the bundle with the identities authenticated by the proof and checks snapshot/transition type, checkpoint, catalog, generation, segment count, and Merkle root.

## Compare trust-state lineage

```bash
agent-audit-trust-checkpoint lineage retained-state.json candidate-state.json \
  --expected-left-state-id "$RETAINED_STATE_ID" \
  --expected-right-state-id "$CANDIDATE_STATE_ID"
```

Relations:

- `same`: accepted
- `right-descendant`: accepted
- `rollback`: denied with `ATC010`
- `fork`: denied with `ATC011`

Forks are never merged or repaired automatically.

## Exit codes

- `0`: created, verified, or accepted lineage
- `1`: valid rollback or fork denial
- `2`: malformed, unsafe, stale-pinned, tampered, or unverifiable input

## Diagnostics

- `ATC001`: unsafe path, symlink, or non-regular file
- `ATC002`: schema, canonical JSON, size, type, or identifier failure
- `ATC003`: stale or malformed external pin
- `ATC004`: checkpoint/state mismatch
- `ATC005`: invalid or missing proof selector
- `ATC006`: inclusion path or proof integrity failure
- `ATC007`: proof/checkpoint substitution
- `ATC008`: proof/portable-bundle mismatch
- `ATC009`: immutable output or overwrite failure
- `ATC010`: rollback lineage
- `ATC011`: fork lineage
