# Audit segment rotation

The active JSON Lines audit log has a reviewed 64 MiB verification boundary. Segment rotation preserves long-running history without silently truncating, deleting, or weakening that boundary.

## Rotate one active log

The source log must exist, contain at least one record, pass structural validation, and have 100% typed event coverage.

```bash
basit-agent-segments rotate \
  --path .agent-system/audit.jsonl \
  --output-dir .agent-system/segments/0001 \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json
```

The output directory must not already exist. A successful rotation creates exactly:

```text
0001/
├── manifest.json
└── segment.jsonl
```

`segment.jsonl` is an exact byte copy of the verified active log. `manifest.json` records its SHA-256, byte count, record count, typed coverage, head hash, segment index, previous segment ID, and a domain-separated segment ID.

Only after the staged directory independently verifies is the active log atomically replaced. The replacement contains one typed `audit-segment-start` record linking the next active history to the sealed segment.

## Verify a complete chain

Supply segment directories in chronological order, starting with segment 1:

```bash
basit-agent-segments verify \
  .agent-system/segments/0001 \
  .agent-system/segments/0002 \
  --active .agent-system/audit.jsonl \
  --expected-latest-segment-id "$LATEST_SEGMENT_ID" \
  --format json
```

Verification checks:

- strict canonical manifest JSON with no duplicate keys
- exact manifest schema and domain-separated segment ID
- sealed byte size and SHA-256
- complete structural and typed audit validation of every segment
- record count, head hash, event schema, and privacy metadata
- indexes forming a complete sequence beginning at 1
- each non-initial segment beginning with the exact previous-segment continuity record
- the active log beginning with the exact latest-segment continuity record
- the latest segment ID matching the independently retained pin

## Crash and overwrite behavior

Rotation uses a sidecar lock on the active log. The archive is assembled in a sibling temporary directory, fsynced, independently verified, and renamed to its final new path. The active log is replaced only after that archive commit.

A crash after the archive rename but before active replacement can leave a valid extra sealed copy while the original active log remains intact. It does not lose or truncate audit data. Operators should verify the archive and active link before retaining a new latest-segment pin.

Rotation never overwrites an existing archive directory. Segment verification rejects symlinked directories, manifests, or data files.

## Trust boundary

Segment manifests and continuity events are unsigned. Their hashes detect modification and chain discontinuity, but they do not authenticate an operator or prove freshness by themselves.

Retain the latest segment ID outside the audit storage and provide it with `--expected-latest-segment-id`. Without that external pin, a self-consistent older chain can be replayed.

Keep every sealed segment available. Removing an older directory breaks complete-chain verification and data availability.

## Stable diagnostics

| Rule | Meaning |
|---|---|
| `AUS001` | unsafe path, symlink, existing output, or filesystem failure |
| `AUS002` | source active audit log is invalid or not fully typed |
| `AUS003` | manifest schema, JSON, version, or canonicalization failure |
| `AUS004` | sealed bytes or audit metadata do not match the manifest |
| `AUS005` | archived segment ordering or continuity failure |
| `AUS006` | active log does not continue from the latest segment |
| `AUS007` | latest segment differs from the external pin |
| `AUS008` | rotation source is empty |
