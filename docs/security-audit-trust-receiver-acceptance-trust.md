# Security audit: receiver-acceptance trust state

## Scope

Task 37 adds a consumer-owned state over admitted receiver-acceptance checkpoint bundles. The state is outside transferred evidence and remembers the exact accepted outer acceptance history plus nested receiver and trust heads.

## Controls

- Complete acceptance-bundle verification occurs before admission or mutation.
- The consumer policy and trust state must remain outside the bundle directory.
- Initialization accepts snapshot bundles only.
- Advancement accepts transition bundles only.
- The transition previous acceptance checkpoint/state/count must equal the retained head.
- The previous nested receiver bundle/checkpoint/state/count and trust handoff/checkpoint/state/count must also equal the retained head.
- Acceptance, receiver, trust, and generation counts must advance; segment count must not decrease.
- Admission decision IDs, policy hashes, identities, selected evidence, and all deltas are rebound before append.
- Bundle, checkpoint, and state identities cannot repeat.
- Every entry and complete state use domain-separated SHA-256 identifiers.
- Strict canonical JSON, duplicate-key rejection, bounded size/count, symlink rejection, POSIX advisory locking, mode-0600 files, fsync, and same-directory atomic replacement are inherited from the reviewed receiver-state engine in a private namespace.
- Denied and invalid operations leave the state bytes unchanged.
- Callers must retain the latest `state_id` independently.

## Diagnostics

- `ABT001`: unsafe path or non-regular evidence.
- `ABT002`: malformed, noncanonical, or tampered state/evidence.
- `ABT003`: invalid or stale external pin.
- `ABT004`: admission denial.
- `ABT005`: wrong snapshot/transition role.
- `ABT006`: previous outer or nested head mismatch.
- `ABT007`: replay or duplicate identity.
- `ABT008`: non-advancing or rollback evidence.
- `ABT009`: consumer ownership boundary violation.
- `ABT010`: lock or atomic-update failure.

## Residual boundary

The state proves integrity and consumer-observed continuity, not producer identity. No signing key, OIDC token, registry credential, or witness service is introduced. Independent checkpoint IDs, signatures, transport authentication, or organizational approval remain external policy decisions.
