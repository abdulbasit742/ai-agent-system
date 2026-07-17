# Security audit: pinned receiver-acceptance trust handoff state

## Reviewed objective

Task 42 converts fully verified and admitted receiver-acceptance trust handoffs into a persistent consumer-owned history. The control is designed to prevent valid evidence from being replayed, rolled back, forked, or substituted after admission.

## Verify before mutate

Every initialization or advancement first:

1. validates the externally supplied handoff bundle ID and checkpoint pin;
2. fully verifies the exact-boundary handoff bundle;
3. evaluates the consumer-owned admission policy outside the bundle;
4. independently binds the decision report to the verified evidence;
5. validates the complete existing state and external state pin;
6. checks exact predecessor continuity and advancement deltas;
7. writes only after every check succeeds.

No policy is read from the bundle. The state itself is also rejected when placed inside the bundle.

## Identity and continuity binding

The state head binds the candidate acceptance-trust checkpoint and state, entry count, Merkle root, and head entry hash. It additionally binds the nested acceptance, receiver, and trust checkpoint/state/count identities, the associated head bundle IDs, generation, and segment count.

A transition is accepted only when its previous checkpoint reproduces the current head at every depth. Checking only the outer checkpoint ID is insufficient; the nested head identities and counts must also match exactly.

## Replay and rollback controls

The engine rejects:

- duplicate handoff bundle IDs;
- duplicate acceptance-trust checkpoint IDs;
- duplicate acceptance-trust state IDs;
- transitions whose previous checkpoint does not equal the current state head;
- candidates that fail to advance any required nested history depth or generation;
- candidates whose segment count decreases;
- stale externally retained receiver state IDs.

A policy denial, continuity denial, stale pin, malformed bundle, or other failure leaves the original state bytes unchanged.

## Canonical integrity

Entries and the complete state use separate domain-separated SHA-256 identifiers. Validation recomputes:

- exact schemas and integer/hash types;
- sequence and anchor/transition roles;
- previous-entry hashes;
- admission decision and policy identities;
- transition deltas;
- duplicate identities;
- each entry hash;
- the exact head;
- the final state ID.

Noncanonical JSON, duplicate keys, truncation, reordering, field substitution, and rehashed semantic drift fail closed.

## Filesystem boundary

Mutating commands require POSIX advisory locking. The sidecar lock and state must be regular non-symlink files. Writes use a same-directory mode-`0600` temporary file, flush and `fsync`, atomic replacement, and directory synchronization. Existing state is never overwritten during initialization.

The state, lock, policy, decisions, handoffs, retained pins, and reports are generated evidence and are excluded from the package.

## Diagnostics

Stable rules are `ABN001`–`ABN010`. Exit `1` represents a verified denial such as stale pin, policy denial, replay, or continuity failure. Exit `2` represents malformed, unsafe, lock-unavailable, or unverifiable input. This distinction lets automation treat authorization denial separately from evidence failure.

## Residual trust boundary

The state is intentionally unsigned. Domain-separated hashes and externally retained IDs detect mutation, rollback, replay, and substitution but do not identify the producer. Consumers that require producer authentication must separately sign or authenticate the retained state/checkpoint IDs outside this repository.
