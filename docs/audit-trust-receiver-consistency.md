# Audit trust receiver consistency proofs

Receiver consistency proofs show that a candidate pinned receiver checkpoint retains every accepted handoff entry committed by a retained checkpoint. Creation reads and fully validates both receiver states and both checkpoints. Verification needs only the proof and the two externally pinned checkpoints.

## Commands

Create a proof:

```bash
basit-agent-audit-trust-receiver-consistency prove \
  retained-receiver.json retained-receiver-checkpoint.json \
  candidate-receiver.json candidate-receiver-checkpoint.json \
  receiver-consistency.json \
  --expected-previous-state-id "$RETAINED_RECEIVER_STATE_ID" \
  --expected-previous-checkpoint-id "$RETAINED_RECEIVER_CHECKPOINT_ID" \
  --expected-candidate-state-id "$CANDIDATE_RECEIVER_STATE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_RECEIVER_CHECKPOINT_ID"
```

Verify after the complete receiver states have been removed:

```bash
agent-audit-trust-receiver-consistency verify \
  receiver-consistency.json \
  retained-receiver-checkpoint.json candidate-receiver-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_RECEIVER_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_RECEIVER_CHECKPOINT_ID"
```

Both command aliases expose the same interface.

## Proof structure

The canonical proof binds:

- `consistency_version` and `algorithm`;
- exact retained and candidate checkpoint references;
- a canonical aligned power-of-two frontier for the retained prefix;
- a canonical append frontier whose first leaf is exposed;
- the first appended receiver transition entry;
- a domain-separated `consistency_id`.

The retained and candidate Merkle roots are reconstructed independently. The proof size grows with the compact frontier rather than with the complete receiver history.

## Authenticated transition boundary

For a right-descendant proof, the first appended entry must:

- be the transition at retained entry count plus one;
- retain the retained receiver head entry hash;
- retain the retained trust checkpoint ID and trust state ID;
- report the exact trust-entry-count delta;
- report the exact generation delta;
- be authenticated as the first one-leaf append-frontier segment;
- lead to a candidate head with increasing trusted entry count and generation and a non-decreasing segment count.

This prevents a valid Merkle append from being interpreted as a valid receiver transition when the receiver-specific predecessor evidence is wrong.

## Relations and exit codes

Accepted relations are:

- `same` for identical checkpoints;
- `right-descendant` for an exact append-only extension.

Exit codes are:

- `0` for created or verified evidence;
- `1` for a valid rollback/fork relation or stale external pin;
- `2` for malformed, unsafe, noncanonical, tampered, or unverifiable evidence.

Stable diagnostics are `ARR001` through `ARR011`. In particular:

- `ARR009` is rollback;
- `ARR010` is fork or checkpoint substitution;
- `ARR011` is invalid receiver transition-boundary continuity.

Denied proof creation never creates an output artifact.

## Filesystem and trust boundary

Proof outputs are new files only, mode `0600`, written through a same-directory temporary file, fsynced, and linked without overwrite. Symlink outputs and unsafe parents are rejected.

The proof is unsigned. Hashes prove integrity and append-only relationship, not producer identity. Retain both checkpoint IDs outside the proof and distribute checkpoints through an independently trusted channel.
