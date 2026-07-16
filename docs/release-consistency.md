# Compact Merkle consistency proofs

`release_consistency.py` proves that one retained release checkpoint is an append-only prefix of a newer checkpoint without requiring the verifier to possess either complete trust-state history.

## Why this exists

A Merkle checkpoint commits to one full trust state. An inclusion proof shows that one release entry belongs to that checkpoint. Neither artifact alone proves that a later checkpoint extends an earlier checkpoint.

A consistency proof fills that gap. It binds two externally pinned checkpoints and carries only the compact subtree hashes needed to reconstruct both Merkle roots.

## Security model

The proof uses:

- the existing domain-separated trust-entry leaf hash: `SHA256(0x00 || canonical_entry)`
- the existing node hash: `SHA256(0x01 || left || right)`
- canonical maximal aligned power-of-two ranges
- a previous-prefix frontier
- an appended-suffix frontier
- canonical JSON and a deterministic `consistency_id`

The verifier first reconstructs the previous Merkle root from the prefix frontier. It then appends the suffix ranges using binary-carry merges and reconstructs the candidate root. Both roots must match externally pinned checkpoint files.

The proof contains `O(log n)` hashes rather than all `n` trust entries.

## Create a proof

```bash
python scripts/release_consistency.py prove \
  retained-state.json \
  retained-checkpoint.json \
  candidate-state.json \
  candidate-checkpoint.json \
  release-consistency-proof.json \
  --expected-previous-state-id "$RETAINED_STATE_ID" \
  --expected-candidate-state-id "$CANDIDATE_STATE_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Proof creation fully validates both trust states and both checkpoints. It accepts only:

- `same`
- `right-descendant`

Rollback and fork relations do not create proof files.

## Verify without trust-state histories

```bash
python scripts/release_consistency.py verify \
  release-consistency-proof.json \
  retained-checkpoint.json \
  candidate-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

The verifier requires only:

- the compact proof
- the retained checkpoint
- the candidate checkpoint
- independently retained checkpoint IDs

## Exit codes

- `0`: proof created or verified; candidate is identical or append-only
- `1`: valid trust states describe rollback or a fork
- `2`: malformed, unsafe, stale, non-canonical, or unverifiable input

Stable denial rules:

- `CNS010`: candidate is older than the retained history
- `CNS011`: candidate diverges from the retained history

## Canonical range layout

Each range is decomposed into the maximal aligned power-of-two subtrees that cover it exactly. For example:

```text
[0, 7)  -> [0,4), [4,6), [6,7)
[5, 13) -> [5,6), [6,8), [8,12), [12,13)
```

The verifier rejects reordered, overlapping, gapped, non-aligned, non-power-of-two, or non-maximal layouts even when an attacker recalculates `consistency_id`.

## Artifact boundaries

Consistency proofs contain checkpoint identities, counts, roots, aligned ranges, hashes, relation, and `consistency_id`. They do not contain:

- source files or source previews
- release bundle bytes
- transition policy contents
- credentials or environment values
- signing keys

Proof output is immutable, symlink-safe, canonical, and created through an atomic no-overwrite write.

## Authentication boundary

A compact proof demonstrates append-only Merkle consistency between two checkpoint roots. It does not authenticate who created either checkpoint. Consumers must protect checkpoint IDs through an independent trusted channel or add an external signing layer.
