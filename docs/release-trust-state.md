# Pinned release trust state

A verified release bundle proves that one artifact set is internally consistent. A transition report proves that one candidate is acceptable relative to one trusted release. A **release trust state** preserves the accepted sequence so later upgrades cannot silently replace, truncate, fork, or roll back the consumer's history.

The trust state is consumer-owned, offline, dependency-free, and deterministic. It is never loaded from a release bundle and is never selected automatically.

## Security model

Each state contains:

- one immutable anchor release
- an ordered sequence of accepted transitions
- a hash for every history entry
- the previous entry hash inside every non-anchor entry
- the accepted transition ID and transition-policy SHA-256
- the current release identity
- a canonical whole-state `state_id`

The caller must retain the latest `state_id` outside the state file and supply it to every `verify` or `advance` operation. The internal hash chain detects editing and truncation. The external state pin detects a fully recomputed but old or forked state.

A self-consistent state file without an external pin is not sufficient rollback protection.

## Initialize an anchor

Start from a fully reviewed release bundle and pin all of its known identity fields:

```bash
python scripts/release_trust.py init \
  release-trust-state.json \
  trusted-release \
  --expected-release-id "$TRUSTED_RELEASE_ID" \
  --expected-source-commit "$TRUSTED_SOURCE_COMMIT" \
  --expected-version "$TRUSTED_VERSION" \
  --format json
```

Initialization:

1. verifies the complete release bundle
2. checks the expected release ID, source commit, and package version
3. refuses to overwrite an existing state
4. creates one canonical anchor entry
5. returns the first externally retained `state_id`

The state file and its `.lock` companion must remain outside the release bundle.

## Verify current trust

Verify the state against the latest retained state pin:

```bash
python scripts/release_trust.py verify \
  release-trust-state.json \
  --expected-state-id "$EXPECTED_STATE_ID"
```

Also bind the state head to a retained release bundle:

```bash
python scripts/release_trust.py verify \
  release-trust-state.json \
  --expected-state-id "$EXPECTED_STATE_ID" \
  --bundle trusted-release
```

Verification checks the exact schema, canonical serialization, entry sequence, previous-entry hashes, unique release IDs, transition references, entry hashes, head metadata, whole-state hash, external state pin, and optional bundle identity.

## Advance to a candidate

Advance only after the release transition policy accepts the candidate:

```bash
python scripts/release_trust.py advance \
  release-trust-state.json \
  trusted-release \
  candidate-release \
  --policy .release-transition.example.json \
  --expected-state-id "$EXPECTED_STATE_ID" \
  --expected-candidate-source-commit "$CANDIDATE_COMMIT" \
  --expected-candidate-version "$CANDIDATE_VERSION" \
  --expected-candidate-release-id "$CANDIDATE_RELEASE_ID" \
  --format json
```

Advance performs these steps while holding the state lock:

1. verifies the current state and external state pin
2. verifies both release bundles
3. requires the previous bundle to match the current state head exactly
4. applies the reviewed transition policy and candidate identity pins
5. refuses denied transitions and duplicate release IDs
6. appends one hash-chained transition entry
7. writes the new state through same-directory atomic replacement
8. returns the new `state_id` for external retention

The old `state_id` becomes stale immediately after a successful advance.

## Exit codes

- `0`: initialization, verification, or advance succeeded
- `1`: both bundles and state were valid, but the transition or duplicate-release rule denied advancement
- `2`: state, policy, pins, bundle evidence, locking, or serialization was malformed or unverifiable

Stable trust-state denial rules currently include:

- `TST003`: candidate release ID already exists in trust history
- `TST004`: underlying release-transition policy denied the candidate

Integrity and stale-pin errors use exit code `2` because the consumer cannot safely authorize an update from that state.

## Atomicity and locking

Writers use a persistent sidecar lock file named `<state>.lock`. On supported POSIX systems it is protected with an advisory file lock. State replacement uses a temporary file in the same directory, restrictive permissions, file synchronization, and atomic `os.replace`.

The lock file is not a trust anchor. The externally retained `state_id` is the rollback/fork checkpoint.

Platforms without the required advisory-lock primitive fail closed for state writes.

## State boundary

The canonical state stores only:

- project, version, release ID, source commit, and source epoch
- sequence and hash-chain values
- transition IDs and policy SHA-256 values

It does not store source contents, wheel bytes, scanner previews, credentials, environment values, signing keys, or registry secrets.

Generated state and lock files should be stored in consumer-controlled durable storage and excluded from the source repository. Backups must preserve the matching latest `state_id` through an independent trusted channel.
