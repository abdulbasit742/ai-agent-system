# Portable release trust checkpoints

`release_checkpoint.py` turns a fully validated release trust state into a compact, canonical Merkle checkpoint. It can also create portable inclusion proofs for individual trusted releases and compare two complete trust states for descendant, rollback, or fork relationships.

The checkpoint format is intentionally unsigned. It is designed to be pinned, transported, mirrored, or signed by an external system, but this repository does not create or store signing keys and does not claim authenticated signer identity.

## Security model

A checkpoint binds:

- the exact canonical `state_id`
- project identity
- entry count
- current trust-state head
- a domain-separated SHA-256 Merkle root over every canonical trust entry
- a canonical `checkpoint_id`

The caller must retain the returned `checkpoint_id` through an independent trusted channel. A checkpoint file that validates internally but is not compared with the externally retained ID does not provide freshness, rollback, or fork protection.

Merkle leaves use:

```text
SHA256(0x00 || canonical_entry_json)
```

Internal nodes use:

```text
SHA256(0x01 || left_child || right_child)
```

The tree split follows the RFC 6962 largest-power-of-two rule. The implementation supports one-entry and odd-sized histories without duplicating leaves.

## Create a checkpoint

```bash
python scripts/release_checkpoint.py create \
  release-trust-state.json \
  release-checkpoint.json \
  --expected-state-id "$EXPECTED_STATE_ID"
```

Creation requires the externally retained trust-state ID. Output is immutable: an existing path or symlink is rejected. The file is written through a same-directory temporary file and an atomic no-overwrite hard link.

## Verify a checkpoint

Verify only the checkpoint and its external pin:

```bash
python scripts/release_checkpoint.py verify \
  release-checkpoint.json \
  --expected-checkpoint-id "$EXPECTED_CHECKPOINT_ID"
```

Verify it against the complete trust state as well:

```bash
python scripts/release_checkpoint.py verify \
  release-checkpoint.json \
  --expected-checkpoint-id "$EXPECTED_CHECKPOINT_ID" \
  --state release-trust-state.json \
  --expected-state-id "$EXPECTED_STATE_ID"
```

When the state is supplied, the Merkle root, head, entry count, project, and state ID are regenerated from the canonical state and must match exactly.

## Create an inclusion proof

Select by sequence:

```bash
python scripts/release_checkpoint.py prove \
  release-trust-state.json \
  release-checkpoint.json \
  release-inclusion-proof.json \
  --expected-state-id "$EXPECTED_STATE_ID" \
  --expected-checkpoint-id "$EXPECTED_CHECKPOINT_ID" \
  --sequence 3
```

Or select by release ID:

```bash
python scripts/release_checkpoint.py prove \
  release-trust-state.json \
  release-checkpoint.json \
  release-inclusion-proof.json \
  --expected-state-id "$EXPECTED_STATE_ID" \
  --expected-checkpoint-id "$EXPECTED_CHECKPOINT_ID" \
  --release-id "$RELEASE_ID"
```

The proof contains one canonical trust entry, the checkpoint reference, and the minimum Merkle audit path needed to reconstruct the root. It does not include wheel bytes, source files, credentials, or environment values.

## Verify a proof without the trust-state file

```bash
python scripts/release_checkpoint.py verify-proof \
  release-inclusion-proof.json \
  release-checkpoint.json \
  --expected-checkpoint-id "$EXPECTED_CHECKPOINT_ID"
```

The verifier recomputes the entry hash, leaf hash, audit path, Merkle root, proof ID, and checkpoint reference. Rehashing a modified proof does not make it valid because the reconstructed root must still equal the externally pinned checkpoint.

An inclusion proof establishes only that the disclosed entry belongs to the checkpointed history. It does not prove that the checkpoint is the newest checkpoint, that a signer approved it, or that no later trust-state entries exist.

## Diagnose trust-state lineage

Treat the left state as the retained trusted state and the right state as a candidate state:

```bash
python scripts/release_checkpoint.py lineage \
  retained-state.json \
  candidate-state.json \
  --expected-left-state-id "$LEFT_STATE_ID" \
  --expected-right-state-id "$RIGHT_STATE_ID"
```

Relationships:

- `same`: both histories are identical
- `right-descendant`: the right history contains the complete left history plus new entries
- `rollback`: the right history is an older prefix; denied with `CHK010`
- `fork`: histories diverge after a common prefix; denied with `CHK011`

Exit codes:

- `0`: same or right-descendant lineage
- `1`: valid states but rollback or fork detected
- `2`: malformed state, checkpoint, proof, pin, path, or unsupported schema

Lineage comparison never merges histories automatically. Fork recovery requires an explicit consumer decision and a separately reviewed process.

## Operational guidance

Keep the trust state, checkpoint, and external pins in separate failure domains when possible. A practical arrangement is:

1. retain the full trust state in controlled storage
2. mirror the compact checkpoint in another system
3. retain the checkpoint ID in a protected configuration or approval record
4. distribute inclusion proofs to consumers that need to verify one release without receiving the full history

Authenticated signatures may be added by an external signing system over the canonical checkpoint bytes or `checkpoint_id`. This repository deliberately leaves key custody, signer identity, certificate policy, transparency logging, and revocation outside its trust boundary.
