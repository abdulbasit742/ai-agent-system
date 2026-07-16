# Audit catalog checkpoints and inclusion proofs

Audit segment catalogs can grow to many entries. A catalog checkpoint provides a small portable commitment to one exact catalog generation, while an inclusion proof demonstrates that one sealed segment entry belongs to that checkpoint without distributing the complete catalog.

## Security model

A checkpoint binds:

- the exact externally pinned `catalog_id`
- catalog generation and predecessor catalog ID
- segment count, total records, total bytes, and latest segment ID
- an RFC 6962-style Merkle root over every canonical catalog segment entry
- a domain-separated canonical `checkpoint_id`

Leaves use `SHA-256(0x00 || canonical-entry)`. Internal nodes use `SHA-256(0x01 || left || right)`. Trees use the RFC 6962 largest-power-of-two split and never duplicate an odd leaf.

A proof contains:

- the externally pinnable checkpoint reference
- one complete canonical catalog entry
- only the sibling hashes needed to reconstruct the checkpoint root
- a domain-separated canonical `proof_id`

Checkpoint and proof files are unsigned integrity commitments. They do not authenticate the producer or provide non-repudiation. Retain the latest reviewed `checkpoint_id` independently.

## Create a checkpoint

The source catalog is fully verified against every discovered sealed segment and, when supplied, the active audit log before a checkpoint is written.

```bash
basit-agent-catalog-checkpoint create \
  audit-archive/catalog.json \
  audit-catalog-checkpoint.json \
  --expected-catalog-id "$CATALOG_ID" \
  --active .agent-system/audit.jsonl \
  --format json
```

Retain the returned `checkpoint_id` outside the audit storage.

## Verify a checkpoint

Verify the portable checkpoint structure and external pin:

```bash
agent-audit-catalog-checkpoint verify \
  audit-catalog-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --format json
```

Rebind it to the complete current archive and active log:

```bash
agent-audit-catalog-checkpoint verify \
  audit-catalog-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --catalog audit-archive/catalog.json \
  --expected-catalog-id "$CATALOG_ID" \
  --active .agent-system/audit.jsonl \
  --format json
```

## Create a segment inclusion proof

Select exactly one segment by index:

```bash
basit-agent-catalog-checkpoint prove \
  audit-archive/catalog.json \
  audit-catalog-checkpoint.json \
  segment-proof.json \
  --expected-catalog-id "$CATALOG_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --active .agent-system/audit.jsonl \
  --segment-index 12 \
  --format json
```

Or select by exact segment ID:

```bash
basit-agent-catalog-checkpoint prove \
  audit-archive/catalog.json \
  audit-catalog-checkpoint.json \
  segment-proof.json \
  --expected-catalog-id "$CATALOG_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --segment-id "$SEGMENT_ID" \
  --format json
```

Proof creation verifies the checkpoint against the complete pinned catalog before selecting the entry.

## Verify without the catalog

Only the proof, checkpoint, and externally retained checkpoint ID are required to verify membership:

```bash
agent-audit-catalog-checkpoint verify-proof \
  segment-proof.json \
  audit-catalog-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --format json
```

Optionally verify the actual sealed archive directory against the entry carried by the proof:

```bash
agent-audit-catalog-checkpoint verify-proof \
  segment-proof.json \
  audit-catalog-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --segment-dir audit-archive/segment-0012 \
  --format json
```

This independently verifies `manifest.json`, exact `segment.jsonl` bytes, audit-chain validity, directory name, IDs, hashes, record count, and byte count.

## Exit codes

- `0`: checkpoint or proof accepted
- `1`: externally pinned identity, catalog binding, requested membership, or supplied segment evidence was denied
- `2`: malformed, unsafe, noncanonical, oversized, or otherwise unverifiable input

Stable diagnostics use `AUP001` through `AUP010`.

## Operational rules

- Keep checkpoint and proof outputs outside the archive root used for catalog discovery.
- Outputs are immutable no-overwrite files; choose a new path for every reviewed generation or proof.
- Keep the catalog and checkpoint pins in an independently retained location.
- A proof demonstrates inclusion in one exact checkpoint, not freshness of that checkpoint.
- A checkpoint does not replace full archive verification when creating or reviewing a new checkpoint.
- Do not describe these unsigned files as signatures or authenticated transparency-log statements.
