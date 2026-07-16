# Strict audit-log integrity

The control plane writes a local JSON Lines audit chain for scans, guards, scrubs, baseline creation, and integration dispatch. Task 14 makes that chain fail closed instead of trusting only the final record.

## Record schemas

New records use schema version 1:

```json
{
  "audit_version": 1,
  "sequence": 1,
  "time": "2026-07-16T00:00:00+00:00",
  "event": "scan",
  "details": {},
  "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "..."
}
```

The verifier also accepts the exact five-field legacy schema produced before task 14. A valid legacy chain can be extended safely: the next record is versioned and its `sequence` equals its physical line number.

Every record must be strict UTF-8 JSON with:

- no duplicate object keys or non-finite numbers
- one canonical JSON object per LF-terminated line
- no blank lines or partial final record
- an exact reviewed field set
- a canonical UTC timestamp
- a printable non-empty event name
- object-valued JSON details
- lowercase 64-character SHA-256 values
- an exact previous-hash link
- a canonical record hash
- a versioned sequence matching the physical line number

## Verify a log

```bash
python agent_system.py audit \
  --path .agent-system/audit.jsonl \
  --format json
```

The report contains only metadata and diagnostics: record counts, legacy/versioned counts, file bytes, chain head, recoverable-prefix boundaries, and the first stable `AUDxxx` failure. It never repeats event detail values.

Text output remains available:

```bash
python agent_system.py audit --path .agent-system/audit.jsonl
```

Exit codes:

- `0`: the complete log and any supplied pins are valid
- `1`: the log is structurally invalid or differs from an external pin
- `2`: arguments, output boundaries, or the audit operation itself are unsafe

## Detect truncation, replay, or rollback

A self-consistent shorter chain cannot prove its own freshness. Retain the latest record count and head hash through an independent trusted channel, then verify both:

```bash
python agent_system.py audit \
  --path .agent-system/audit.jsonl \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json
```

`AUD020` reports a count mismatch. `AUD021` reports a head mismatch. Pin mismatches are deliberately not considered safely recoverable because they may represent rollback or replay rather than an interrupted write.

## Recover a verified prefix

A partial final write, malformed later record, or broken later chain can have a verified prefix. Create a new immutable copy without modifying the source:

```bash
python agent_system.py audit \
  --path damaged-audit.jsonl \
  --recover-to recovered-audit.jsonl \
  --format json
```

The output path must not exist or be a symlink. The tool copies only the byte range covered by fully verified records, writes it through a same-directory atomic no-overwrite operation, and independently verifies the result. The source log is never edited, truncated, or deleted.

The command still exits `1` when the source was invalid, even if the recovery copy was created successfully.

## Append behavior

Before a new record is appended:

1. a persistent sidecar advisory lock is acquired;
2. the complete existing file is strictly verified;
3. the next sequence and previous hash are derived from the verified report;
4. one canonical versioned record is appended with `O_APPEND`;
5. the file descriptor is synchronized.

An invalid chain is never extended. The CLI also performs a preflight verification before audited commands, so a known-corrupt log blocks scan, guard, scrub, baseline creation, or dispatch before those commands proceed.

## Stable diagnostics

- `AUD001`: symlink log
- `AUD002`: file-size limit
- `AUD003`: partial final record
- `AUD004`: line-size limit
- `AUD005`: blank record
- `AUD006`: invalid UTF-8
- `AUD007`: non-strict JSON
- `AUD008`: schema/version mismatch
- `AUD010`: sequence mismatch
- `AUD011`: timestamp mismatch
- `AUD012`: event mismatch
- `AUD013`: details mismatch
- `AUD014`: malformed hash
- `AUD015`: previous-hash break
- `AUD016`: record-hash mismatch
- `AUD017`: non-canonical serialization or line ending
- `AUD020`: external record-count mismatch
- `AUD021`: external head-hash mismatch

The report stops at the first invalid record and gives its line plus byte offset. `recoverable_prefix` always describes only records that passed every check.
