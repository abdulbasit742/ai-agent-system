# Audit bundle trust state

The audit bundle trust state is a consumer-owned, canonical, hash-chained record of admitted audit evidence bundles. It converts one-time admission decisions into a persistent offline trust anchor without placing trust policy or state inside producer-controlled bundles.

## Security model

A portable audit bundle proves the integrity of its checkpoint, inclusion proofs, optional consistency proof, and optional sealed segment evidence. The admission policy decides whether that verified bundle is acceptable. The trust state records only admitted evidence and requires an externally retained `state_id` on every verify or advance operation.

The state does not authenticate the bundle producer and does not replace signatures, witnesses, or public transparency services.

## State contents

Every entry records:

- a contiguous sequence number
- `anchor` or `transition` kind
- the previous entry hash
- exact bundle ID
- candidate checkpoint ID
- candidate catalog ID
- catalog generation and segment count
- catalog Merkle root
- admission decision ID
- admission policy SHA-256
- transition previous checkpoint/catalog identities and generation delta when applicable
- a domain-separated entry hash

The state head repeats the final sequence, entry hash, bundle/checkpoint/catalog identity, generation, and segment count. A domain-separated `state_id` commits the complete canonical state.

## Initialize an anchor

Initialization accepts only an admitted snapshot bundle:

```bash
basit-agent-audit-trust init audit-trust-state.json snapshot-bundle \
  --policy audit-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CHECKPOINT_ID" \
  --format json
```

The state file must not already exist. The policy and state must remain outside the bundle. Retain the returned `state_id` separately from the state file.

## Verify the pinned state

Verify state structure and freshness:

```bash
agent-audit-trust verify audit-trust-state.json \
  --expected-state-id "$STATE_ID" \
  --format json
```

Also verify that a portable bundle exactly matches the current head:

```bash
agent-audit-trust verify audit-trust-state.json \
  --expected-state-id "$STATE_ID" \
  --bundle current-head-bundle \
  --format json
```

The verifier derives the expected bundle and checkpoint identities from the externally pinned state. A transition head also binds its previous checkpoint identity.

## Advance through a transition bundle

```bash
basit-agent-audit-trust advance audit-trust-state.json transition-bundle \
  --policy audit-admission.json \
  --expected-state-id "$STATE_ID" \
  --expected-bundle-id "$CANDIDATE_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --format json
```

Advancement requires all of the following:

- current state matches the externally retained `state_id`
- complete transition bundle verification succeeds
- the consumer policy admits the candidate
- bundle type is `transition`
- transition previous checkpoint and catalog equal the current state head
- candidate generation strictly increases
- candidate bundle, checkpoint, and catalog identities do not already exist in history
- reported generation delta equals the actual head-to-candidate delta

An accepted advance appends one hash-chained entry and atomically replaces the state. Retain the new `state_id`; the previous pin is then stale.

## Exit codes

- `0`: state created, verified, or advanced
- `1`: fully verified evidence was denied by policy or rejected as replay/rollback/head mismatch
- `2`: malformed, tampered, unsafe, stale-pinned, or unverifiable input

## Stable diagnostics

- `ATS001`: unsafe state or lock path
- `ATS002`: malformed, noncanonical, or tampered state/evidence
- `ATS003`: external state pin mismatch
- `ATS004`: admission policy denied the bundle
- `ATS005`: wrong anchor or advancement bundle type
- `ATS006`: transition or verified bundle does not match the current head
- `ATS007`: duplicate bundle/checkpoint/catalog identity
- `ATS008`: generation rollback or non-advancing candidate
- `ATS009`: policy or state located inside the bundle
- `ATS010`: lock or atomic persistence failure

## Mutation and locking

Writes use a persistent sidecar advisory lock. Initialization and advancement hold an exclusive lock; verification holds a shared lock. The state is written to a same-directory temporary file, flushed and fsynced, then atomically replaced. The parent directory is fsynced when supported.

The implementation rejects symlink state files, symlink lock files, non-regular outputs, unsafe parents, duplicate JSON keys, non-finite JSON values, noncanonical serialization, non-contiguous sequences, hash-chain breaks, duplicate identities, and state/head drift.

## Immutability guarantees

The state bytes remain unchanged when:

- admission denies the candidate
- the supplied state pin is stale
- the transition starts from another checkpoint/catalog
- the candidate is replayed
- the candidate generation does not advance
- bundle verification fails
- policy or path validation fails

The persistent `.lock` sidecar may exist even when initialization is denied; it contains no trust evidence.

## Operational retention

Retain independently:

- latest `state_id`
- current state file and lock sidecar
- current admitted head bundle
- admission policy used for future advancement
- bundle and checkpoint pins supplied during each accepted operation

Do not infer a trusted previous state automatically. Do not merge forks or rewrite history. A stale but internally valid state is rejected when its external pin no longer matches.
