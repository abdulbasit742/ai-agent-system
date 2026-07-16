# Security audit: pinned release trust state

## Scope

This review covers `scripts/release_trust.py`, its regression tests, and the read-only trust-state workflow. It evaluates integrity, rollback resistance, fork detection, file-system safety, concurrency, information exposure, and publication boundaries.

## Trust assumptions

- Release bundles have already been produced by the reviewed deterministic bundle format.
- The trust-state command independently verifies every bundle it consumes.
- The consumer protects the latest `state_id` outside the state file.
- The transition policy and previous release bundle are consumer-owned inputs.
- Advisory locking is available for state mutation.

The state file alone cannot prove freshness against an attacker who can replace it with an older, fully valid copy. Freshness comes from comparing it with the separately retained `state_id`.

## Reviewed controls

### Exact schema and canonical encoding

The state root, every entry, every release identity, every transition reference, and the head use exact field sets. Unknown fields, unsupported versions, duplicate releases, malformed hashes, non-contiguous sequences, and non-canonical JSON fail closed.

Canonical serialization prevents alternate encodings from representing one logical state. The state-size and entry-count limits bound parsing work.

### Hash-chain integrity

Every entry hash covers:

- entry version and sequence
- anchor or transition kind
- previous entry hash
- complete release identity
- transition ID and policy SHA-256 when applicable

The state ID covers the complete ordered history and current head. Editing, reordering, truncating, inserting, or deleting entries invalidates the chain or state ID.

### External rollback and fork pin

Every verification and advance requires the expected externally retained state ID. A correctly recomputed older state, parallel fork, or stale backup therefore fails before bundle evaluation or mutation.

A successful advance returns a new state ID. Consumers must replace their external checkpoint only after the state file has been durably stored.

### Anchor binding

Initialization requires exact expected release ID, source commit, and package version. The complete anchor bundle is verified before state creation. Existing states are never overwritten.

### Advance binding

An advance requires:

- exact current state ID
- previous bundle identity equal to the current state head
- a consumer-owned transition policy outside both bundles
- candidate source commit and version pins
- optional exact candidate release ID
- an accepted transition report
- a release ID not already present in history

Denied transitions leave the state bytes unchanged.

### File-system safety

- state files and lock files may not be symlinks
- trust state and policy paths must remain outside release bundles
- writes occur under a sidecar advisory lock
- temporary state files use restrictive permissions
- state replacement is same-directory and atomic
- file and directory synchronization is attempted before success is reported

The persistent lock file coordinates compliant writers across atomic state replacement. It is not treated as evidence.

### Data minimization

Reports and state entries contain identities, hashes, versions, sequence values, and policy references only. They omit source contents, wheel bytes, scanner evidence, credentials, environment values, runner identity, and secret material.

### CI boundary

The workflow uses only `contents: read`. It builds and verifies local evidence, initializes a temporary trust state, advances it under explicit same-version-mutation approval, checks stale-pin and tamper rejection, and uploads only test evidence.

It does not:

- publish packages
- create GitHub Releases
- request OIDC tokens
- use signing keys
- read registry credentials
- update repository files or external trust storage

## Known boundaries

- The state is integrity-protected and externally pinned but not digitally signed.
- Advisory locks coordinate compliant local processes; hostile processes with direct storage control can still replace files, which is why the external state pin is mandatory.
- Consumers must define an independent durable channel for the latest state ID.
- Recovery from a lost state pin is a manual trust re-establishment event and must not be automated from the state file alone.
- State mutation fails closed on platforms without the required advisory-lock primitive.

## Verification evidence

The regression suite covers canonical state creation, schema rejection, hash tampering, history truncation, duplicate releases, non-canonical encoding, symlinks, overwrite protection, anchor pins, stale state pins, bundle/head mismatch, accepted chaining, denied transitions, state preservation, and a real verified bundle initialization/verification path.

The dedicated workflow additionally exercises real deterministic bundles, an accepted distinct candidate, stale-pin denial, tampered-history denial, atomic update output, and machine-readable evidence artifacts.
