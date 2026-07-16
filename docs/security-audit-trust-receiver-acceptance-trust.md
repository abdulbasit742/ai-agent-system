# Security audit: receiver-acceptance bundle trust state

## Reviewed guarantees

- Full acceptance-bundle verification and consumer policy admission occur before state mutation.
- The policy and state must remain outside the bundle boundary.
- Snapshot evidence can only create an anchor; transition evidence can only advance an existing state.
- The externally supplied `state_id` detects stale, replaced, truncated, or replayed state files.
- A transition must begin at the exact retained acceptance checkpoint/state/count and nested receiver checkpoint/state/count.
- Acceptance and receiver counts and generation advance monotonically; segment count cannot decrease.
- Duplicate bundle, checkpoint, and state identities are rejected.
- Canonical JSON, strict schemas, domain-separated entry/state hashes, and complete-chain verification detect tampering.
- Sidecar advisory locks, mode-0600 staging, fsync, and atomic replacement prevent partial concurrent updates.
- Denied and invalid operations leave state bytes unchanged.

## Stable diagnostics

- `ABT001`: unsafe path, ownership, or lock boundary;
- `ABT002`: malformed, noncanonical, or tampered state;
- `ABT003`: externally retained state pin mismatch;
- `ABT004`: admission denial or invalid admission binding;
- `ABT005`: wrong snapshot/transition role;
- `ABT006`: transition does not start from retained nested head;
- `ABT007`: duplicate or replayed identity;
- `ABT008`: non-advancing or rollback evidence;
- `ABT009`: state/policy placement or output safety failure;
- `ABT010`: lock or atomic update failure.

## Adversarial cases covered

The regression and integration suites cover report/bundle substitution, wrong previous acceptance identity, wrong nested receiver identity, stale external pins, replay, duplicate identities, decreasing counts, hash tampering, invalid deltas, policy denial, symlinks, and byte preservation after failed operations.

## Explicit non-guarantees

The state is not signed and does not authenticate the producer. It does not replace independent retention of the latest `state_id`, bundle ID, checkpoint ID, or the consumer policy. Hash linkage demonstrates integrity and continuity only for the evidence actually admitted by the consumer.
