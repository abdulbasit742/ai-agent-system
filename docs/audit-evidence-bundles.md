# Portable audit evidence bundles

Audit evidence is produced in several independently verifiable layers:

- sealed audit segments
- canonical segment catalogs
- catalog Merkle checkpoints
- per-segment inclusion proofs
- optional checkpoint consistency proofs

A portable audit evidence bundle collects a reviewed subset of those files into one exact-boundary directory. The bundle can be transferred to another machine and verified without the original catalog or source archive.

## Installed commands

```bash
basit-agent-audit-bundle --help
agent-audit-bundle --help
```

Both commands use the same dependency-free implementation.

## Snapshot bundle

A snapshot bundle contains:

- one candidate catalog checkpoint
- one or more inclusion proofs bound to that checkpoint
- optionally, the sealed segment directory represented by each proof

Create a proof-only snapshot bundle:

```bash
basit-agent-audit-bundle create audit-handoff \
  --checkpoint candidate-checkpoint.json \
  --expected-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof segment-0001-proof.json \
  --proof segment-0012-proof.json \
  --format json
```

Include the independently verified sealed segment bytes for every supplied proof:

```bash
basit-agent-audit-bundle create audit-handoff \
  --checkpoint candidate-checkpoint.json \
  --expected-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --proof segment-0001-proof.json \
  --proof segment-0012-proof.json \
  --segment-root audit-archive \
  --format json
```

The directory names carried by the proofs are resolved only beneath the supplied segment root. Every selected segment is independently verified against its proof before any bundle output is published.

## Transition bundle

A transition bundle adds:

- the previous catalog checkpoint
- a compact consistency proof binding the previous and candidate checkpoints

```bash
basit-agent-audit-bundle create audit-transition-handoff \
  --checkpoint candidate-checkpoint.json \
  --expected-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --previous-checkpoint retained-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --consistency-proof catalog-consistency.json \
  --proof segment-0012-proof.json \
  --format json
```

The three transition arguments are one reviewed unit. Supplying only part of that unit fails closed and creates no bundle.

## Verification

A snapshot bundle requires the externally retained bundle and candidate checkpoint IDs:

```bash
agent-audit-bundle verify audit-handoff \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --format json
```

A transition bundle additionally requires the previous checkpoint pin:

```bash
agent-audit-bundle verify audit-transition-handoff \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --format json
```

Verification does not require the source catalogs, proof source files, or original segment archive. Included segment bytes are reverified from the bundle directory itself.

## Canonical layout

A proof-only snapshot resembles:

```text
audit-handoff/
├── SHA256SUMS
├── audit-bundle-manifest.json
├── candidate-checkpoint.json
└── proofs/
    ├── segment-00000001.json
    └── segment-00000012.json
```

A transition bundle with segment bytes may additionally contain:

```text
previous-checkpoint.json
consistency-proof.json
segments/<safe-directory>/manifest.json
segments/<safe-directory>/segment.jsonl
```

The manifest records every payload file using:

- safe relative path
- exact role
- SHA-256 digest
- byte size

`SHA256SUMS` covers every payload file plus the canonical manifest. The checksum file does not recursively checksum itself.

## Bundle identity

`bundle_id` is a domain-separated SHA-256 commitment over the canonical manifest payload. It binds:

- snapshot or transition type
- candidate checkpoint identity
- optional previous checkpoint identity
- optional consistency-proof identity and relation
- ordered segment proof identities
- segment inclusion markers
- exact file records

Retain the latest accepted `bundle_id` outside the bundle. A self-consistent bundle alone does not establish freshness.

## Output rules

Creation verifies all source evidence before touching the output path. It then:

1. creates a temporary sibling directory
2. writes canonical checkpoint and proof files
3. copies only independently verified selected segment files
4. writes the canonical manifest and checksums
5. verifies the completed staging directory
6. renames it to the requested new output directory

Existing outputs and symlinks are never overwritten.

## Limits

The reviewed defaults are:

- at least one inclusion proof
- at most 128 inclusion proofs
- at most 1,024 payload files
- at most 256 MiB of payload data
- at most 2 MiB for the bundle manifest
- safe path components of at most 128 characters

## Exit codes

- `0`: bundle created or verified
- `1`: valid evidence conflicts with an external pin or reviewed relationship
- `2`: malformed, unsafe, incomplete, oversized, or tampered input

Stable diagnostics are `AUB001` through `AUB012`.

## Trust boundary

Audit evidence bundles are unsigned integrity and portability containers. They do not provide:

- producer authentication
- witness consensus
- non-repudiation
- public transparency logging
- freshness without externally retained pins

Cryptographic signatures or witness receipts may be layered on top of the canonical `bundle_id` by an independent system. This repository does not store signing keys or claim that unsigned bundles are authenticated.
