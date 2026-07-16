# Security audit: typed event admission

## Threat model

A cryptographically intact audit record can still be unsafe when it contains unbounded data, raw command arguments, private filesystem locations, credentials, or fields that do not match the event being claimed. Task 15 treats event contents as an admission-control problem separate from hash-chain integrity.

## Reviewed controls

### Exact reserved schemas

Reserved control-plane event names have exact accepted fields. Missing and unexpected fields fail before append. Stored typed details are normalized again during verification and must reproduce identical canonical details.

### Generic event boundary

Unknown events are permitted only when the name is lowercase and hyphenated. Details must be bounded JSON containing nulls, booleans, integers, strings, arrays, and objects. Floating-point and unsupported runtime objects are rejected.

### Privacy-preserving references

Paths, command arrays, and Git refs are converted before storage. Domain separation prevents cross-context correlation through equal digests. Raw references are not included alongside their hashes.

### Credential exclusion

Generic object keys associated with authentication material are rejected recursively. Credential-shaped free-form string values are also rejected. Reserved path and command fields are not stored in raw form.

### Bounded resources

Admission limits event names, identifiers, paths, command argument counts, string length, array length, object field count, nesting depth, and canonical encoded detail size.

### Legacy migration

Records created before event schemas remain verifiable so an existing hash chain is not discarded. Reports distinguish typed and untyped records. Consumers may enforce `--require-typed` only after retaining an appropriate migration checkpoint.

## Failure rules

- `AUD022` indicates an event schema or canonicalization violation.
- `AUD023` indicates credential-bearing detail admission failure.
- `AUD024` indicates a typed-only policy violation caused by earlier untyped records.

For a typed-content violation, the structural prefix before the offending record is reported. For `AUD024`, no recovery prefix is offered because valid historical records must not be silently removed to satisfy policy.

## Non-goals

This feature does not:

- identify or authenticate the event producer
- sign audit records or checkpoints
- encrypt audit data
- provide public inclusion or consistency proofs
- guarantee freshness without an externally retained head/count pin
- recover a record that was admitted under an older untyped policy

## Verification coverage

Python 3.11 and 3.12 tests cover exact schemas, generic boundaries, path and command references, credential rejection, typed canonicalization, legacy coverage reporting, typed-only enforcement, catalog output, real guard events, package contents, and read-only CI evidence.
