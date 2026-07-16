# Typed audit event admission

Task 15 adds an admission layer in front of the tamper-evident audit chain. Hash integrity proves that stored bytes did not change; event admission additionally proves that newly stored details matched a reviewed schema and did not contain raw high-risk references.

## Design basis

The implementation adopts three established transparency-log principles without copying external code:

- define exactly what each log entry represents and enforce machine-checkable admission criteria
- use versioned typed entries with field and cross-field validation
- keep freshness state outside the log when rollback or replay detection is required

Task 14 already supplied external record-count and head-hash pins. Task 15 adds the missing typed-entry and privacy admission boundary.

## Event catalog

```bash
python agent_system.py audit-events --format json
```

Reviewed event names:

- `scan`
- `scan-added-lines`
- `baseline-create`
- `guard`
- `scrub`
- `dispatch`

Each reviewed event has an exact input field set and deterministic normalization. Unknown lowercase hyphenated events remain available through a bounded generic JSON schema.

## Privacy transformations

New typed records include `_event_schema: 1` inside `details`.

Raw values are not retained for these evidence classes:

- paths become `{kind, sha256}` references
- command argument arrays become `{argc, sha256}` references
- Git base/head refs become domain-separated SHA-256 references

The hashes use separate domains so the same text used as a path, command, or Git ref does not produce the same stored identifier.

Free-form generic details reject:

- credential-bearing field names
- credential-shaped values
- control characters
- floating-point values
- unsupported object types
- excessive nesting, arrays, fields, strings, or encoded size

## Verification

```bash
python agent_system.py audit \
  --path .agent-system/audit.jsonl \
  --format json
```

Reports now include:

- `typed_records`
- `untyped_records`
- `typed_coverage_percent`
- `privacy_safe`
- `event_counts`
- `event_schema_version`

## Migration gate

Pre-schema records remain structurally valid by default so existing audit chains can continue. They are reported as untyped and make `privacy_safe` false.

Require complete typed coverage when a migration checkpoint has been established:

```bash
python agent_system.py audit \
  --path .agent-system/audit.jsonl \
  --require-typed \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json
```

`--require-typed` fails with `AUD024` when any pre-schema record remains. This policy failure is not treated as a recoverable corruption because removing valid history would violate append-only semantics.

## Stable rules

- `AUD022`: typed event schema, field, type, or canonicalization failure
- `AUD023`: credential-bearing audit detail rejected
- `AUD024`: typed coverage required but legacy untyped records remain

Structural `AUD001` through `AUD021` checks continue to run first.

## Safety boundary

Typed admission does not authenticate the producer. External head/count pins detect rollback or replay relative to a retained checkpoint, but neither pins nor schemas provide signatures, identity, non-repudiation, or a transparency service.
