# Security audit: audit bundle trust state

Task 22 adds a consumer-owned persistent trust anchor for admitted portable audit bundles. The design reuses the repository's verify-before-authorize boundary and adds pinned, tamper-evident history plus atomic state advancement.

## Reviewed guarantees

### Complete evidence verification before state mutation

Initialization and advancement call the audit-bundle admission engine with exact external bundle and checkpoint pins. Admission performs complete bundle verification before policy evaluation. Trust-state code then independently verifies the same pinned bundle and requires the verified candidate identity to equal the admitted identity before recording it.

No state write occurs when bundle verification or policy evaluation fails.

### Snapshot-only anchor

The first entry may come only from an admitted snapshot bundle. A transition bundle cannot silently become an unanchored trust root. The anchor binds the exact candidate checkpoint, catalog, generation, segment count, Merkle root, bundle ID, admission decision ID, and policy hash.

### Transition-only advancement

Every later entry requires an admitted transition bundle. Its previous checkpoint and catalog must equal the current state head. Candidate generation must strictly increase, and the reported generation delta must equal the actual difference.

The state does not infer a predecessor from directory ordering, filenames, mutable branch names, or the candidate bundle itself.

### Replay and duplicate prevention

The validator rejects duplicate bundle IDs, checkpoint IDs, and catalog IDs anywhere in the state. Advancement rejects candidates already represented in history and transitions that do not begin at the current head.

An exact replay after a successful advancement therefore cannot mutate the state.

### External freshness pin

Every verify and advance operation requires the latest externally retained `state_id`. The ID is a domain-separated SHA-256 commitment to the canonical state payload. An internally valid older state is rejected with `ATS003` when the retained pin has moved forward.

The state file alone is not rollback protection.

### Canonical hash chain

Each entry has a domain-separated hash over:

- entry version and sequence
- entry kind
- previous entry hash
- evidence identity
- admission identity
- optional transition identity

Sequences must begin at one and remain contiguous. The first entry must be an anchor with the all-zero predecessor and no transition evidence. Later entries must be transitions linked to the previous entry hash and previous checkpoint/catalog identity.

The root `state_id` commits the complete entry list and exact head summary.

### Strict parsing

The loader enforces:

- UTF-8 JSON
- duplicate-key rejection
- non-finite-number rejection
- exact fields at every level
- exact lowercase 64-character hexadecimal identifiers
- integer type checks that reject booleans
- maximum 5 MB state size
- maximum 10,000 entries
- canonical pretty JSON serialization
- exact head-to-final-entry equality

Reformatting, unknown fields, truncation, entry changes, state-ID changes, or head drift fail closed.

### Consumer-owned path boundary

The trust state and admission policy must remain outside the audit bundle. This prevents producer-controlled evidence from selecting its own authorization policy or retained trust state.

State files, lock files, and parents must be regular non-symlink filesystem objects. The public wheel contains runtime code only; generated state and policy data do not enter package artifacts.

### Locking and atomicity

POSIX advisory locking is required for state operations. A persistent sidecar lock uses `O_NOFOLLOW` where available and is checked as a regular file. Initialization and advancement take exclusive locks; verification takes a shared lock.

Writes use a mode-0600 same-directory temporary file, file flush and fsync, atomic `os.replace`, and parent-directory fsync when supported. Denied or invalid operations do not replace the state.

Unsupported platforms fail closed for state operations rather than pretending concurrency safety.

## Stable failure classes

- `ATS001`: unsafe state, parent, output, or lock path
- `ATS002`: malformed, noncanonical, tampered, or inconsistent state/evidence
- `ATS003`: stale externally retained state pin
- `ATS004`: verified candidate denied by admission policy
- `ATS005`: invalid anchor or advancement bundle type
- `ATS006`: candidate transition or verified bundle does not match the state head
- `ATS007`: replay or duplicate bundle/checkpoint/catalog identity
- `ATS008`: generation rollback or non-advancing candidate
- `ATS009`: consumer policy or trust state placed inside a bundle
- `ATS010`: lock or persistence failure

Policy denials and valid replay/head/generation denials return exit code `1`. Malformed, unsafe, stale-pinned, or unverifiable inputs return `2`.

## Privacy boundary

Trust entries contain only identifiers, counts, generation numbers, Merkle roots, admission decision IDs, policy hashes, and hash-chain metadata. They do not contain:

- audit record bodies
- raw paths
- command arrays
- Git references
- scanner previews
- credentials
- environment values
- sealed segment bytes
- admission-policy contents

## Unsigned evidence limitation

The state authenticates internal integrity and consumer-retained continuity only. It does not prove who produced a bundle, who approved the policy, or whether independent witnesses observed the same history. No signing keys, OIDC credentials, registry secrets, or transparency-log publication are introduced.

## CI boundary

The trust workflows use `contents: read` only. They create temporary bundles, policies, states, and decisions, validate Python 3.11/3.12 behavior, exercise isolated wheels, and upload test evidence. They do not publish packages, create GitHub releases, request OIDC credentials, or read signing/registry secrets.

## Residual risks

- A compromised consumer that replaces both state and externally retained `state_id` can choose a new history.
- Advisory locks require cooperating processes.
- Filesystem or kernel failures can exceed application-level guarantees.
- Unsigned evidence does not establish producer identity.
- Multi-generation transition proofs authenticate append-only continuity represented by the bundle but not omitted independent witnesses.

These limits are documented rather than hidden behind stronger claims.
