# Audit trust receiver checkpoint bundles

Receiver bundles package pinned receiver checkpoints and inclusion/consistency proofs into an immutable exact-boundary directory for offline transfer.

## Snapshot bundle

A snapshot bundle contains:

- one externally pinned candidate receiver checkpoint;
- one or more receiver inclusion proofs;
- exactly one proof authenticating the candidate receiver head;
- a canonical manifest and sorted SHA-256 checksum file.

Create and verify:

```bash
basit-agent-audit-trust-receiver-bundle create receiver-handoff \
  --candidate-checkpoint candidate-receiver-checkpoint.json \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof candidate-head-proof.json

agent-audit-trust-receiver-bundle verify receiver-handoff \
  --expected-bundle-id "$RECEIVER_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

## Transition bundle

A transition bundle additionally contains a retained receiver checkpoint and a right-descendant receiver consistency proof:

```bash
basit-agent-audit-trust-receiver-bundle create receiver-transition \
  --candidate-checkpoint candidate-receiver-checkpoint.json \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof candidate-head-proof.json \
  --previous-checkpoint retained-receiver-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --consistency-proof receiver-consistency.json
```

Verification also requires `--expected-previous-checkpoint-id`.

## Exact evidence boundary

The directory contains only:

- `audit-trust-receiver-bundle-manifest.json`;
- `SHA256SUMS`;
- the candidate checkpoint;
- the optional retained checkpoint and consistency proof;
- canonical proof files under `proofs/`.

The manifest binds roles, paths, sizes, digests, checkpoint references, selected receiver entries, head marker, bundle type, and a domain-separated `bundle_id`. Missing, extra, renamed, substituted, symlinked, or modified files are rejected.

Receiver checkpoints and proofs retain their native canonical indented JSON encoding. The manifest uses compact canonical JSON. Bundle verification does not require complete receiver-state files or the original loose evidence.

## Filesystem behavior

Creation verifies every source artifact before staging. Files are written mode `0600` under a mode `0700` same-parent staging directory, fsynced, independently verified, and then published by a no-overwrite directory rename. Existing or symlink output paths are rejected.

## Exit semantics

- `0`: bundle created or verified.
- `1`: externally pinned but valid evidence is denied, such as a stale bundle/checkpoint pin.
- `2`: malformed, unsafe, incomplete, noncanonical, tampered, or unverifiable evidence.

Stable diagnostics are `ARB001` through `ARB012`. In particular, `ARB003` covers external pin mismatch, `ARB008` exact file/checksum boundary failure, `ARB011` immutable output failure, and `ARB012` missing or inconsistent candidate-head proof.

Bundles are unsigned integrity evidence. Retain the bundle and checkpoint IDs outside the directory and distribute them through an independently trusted channel.
