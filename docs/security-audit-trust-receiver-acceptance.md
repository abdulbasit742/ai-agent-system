# Security audit: audit trust receiver acceptance state

## Scope

This review covers `agent_audit_trust_receiver_acceptance.py`, its canonical state schema, admission-to-state binding, filesystem mutation semantics, CLI behavior, package aliases, tests, and read-only CI.

## Security properties

- Full receiver bundle verification occurs before local policy evaluation and state mutation.
- Initialization accepts only an admitted snapshot; advancement accepts only an admitted transition.
- The previous receiver checkpoint, receiver state, receiver entry count, underlying trust checkpoint, underlying trust state, and trusted entry count must equal the retained head.
- Receiver and trusted entry counts and trusted generation must increase; segment count cannot decrease.
- Receiver bundle, checkpoint, and state identities cannot repeat.
- Admission decision ID and policy hash are committed into each entry.
- Domain-separated entry and state hashes bind strict canonical JSON.
- Externally retained `state_id` pins detect stale or substituted local histories.
- Sidecar locking serializes writers. Updates are same-directory, fsynced, mode `0600`, and atomic.
- Policy and state paths inside the receiver bundle are rejected.
- Denied, stale, replayed, malformed, or unverifiable operations preserve state bytes.

## Stable diagnostics

- `ARS001`: unsafe path, symlink, lock, or overwrite boundary.
- `ARS002`: malformed or noncanonical state/schema.
- `ARS003`: external state freshness pin mismatch.
- `ARS004`: receiver admission denial.
- `ARS005`: wrong snapshot/transition operation.
- `ARS006`: retained receiver or trusted-head mismatch.
- `ARS007`: replayed receiver identity.
- `ARS008`: non-advancing or regressing candidate.
- `ARS009`: state hash-chain or head inconsistency.
- `ARS010`: filesystem or unexpected processing failure.

## Threat analysis

### Rollback or stale local file

A valid older state has a different domain-separated `state_id`. The required external pin causes fail-closed rejection before advancement.

### Alternate predecessor or fork

A transition bundle must name the exact receiver checkpoint/state and underlying trusted checkpoint/state/count stored at the current acceptance head. A valid alternate branch therefore cannot advance this state.

### Replay

Accepted receiver bundle, receiver checkpoint, and receiver state IDs are unique across the history. Reuse is rejected even when the evidence remains cryptographically valid.

### Admission decision substitution

The state re-verifies the receiver bundle and checks the admission report identity and evidence summary before sealing the decision and policy hashes.

### Concurrent writers or crash

The shared sidecar lock prevents concurrent writes. Temporary bytes are flushed and fsynced before an atomic replacement; the parent directory is fsynced afterward.

### Bundle-contained policy or state

Containment checks reject consumer policy or acceptance-state paths inside evidence controlled by the producer.

## Residual trust

The state is unsigned and does not authenticate producer or consumer identity. Security depends on independently retaining the latest state ID, protecting the local policy, reviewing the installed code boundary, and using authentic receiver bundle pins.
