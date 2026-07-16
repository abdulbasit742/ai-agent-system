# Audit trust handoff admission

A valid audit trust handoff proves integrity and continuity. Admission is the separate consumer-owned decision about whether that verified handoff is acceptable for the receiving environment.

The policy is never embedded in the handoff. Retain and review it independently.

## Commands

Create a canonical default policy:

```bash
basit-agent-audit-trust-admission init audit-trust-admission.json
```

Validate a policy and print its canonical SHA-256:

```bash
agent-audit-trust-admission validate audit-trust-admission.json
```

Evaluate a snapshot handoff:

```bash
basit-agent-audit-trust-admission evaluate audit-trust-handoff \
  --policy audit-trust-admission.json \
  --expected-bundle-id "$HANDOFF_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_TRUST_CHECKPOINT_ID"
```

Transition handoffs additionally require the retained previous checkpoint pin:

```bash
--expected-previous-checkpoint-id "$PREVIOUS_TRUST_CHECKPOINT_ID"
```

## Policy controls

The version-1 policy has four exact sections:

- `bundle`: allowed snapshot/transition types and file, byte, and proof-count limits.
- `candidate`: trust-entry, generation, and segment-count ranges plus optional state, checkpoint, head-bundle, and head-catalog allowlists.
- `selection`: required or allowed trust sequences and bundle IDs, with optional anchor and mandatory-head requirements.
- `transition`: allowed consistency relation, entry/generation deltas, previous state/checkpoint allowlists, and optional single-step advancement.

An empty ID or selection allowlist means unrestricted. Required lists remain enforced independently.

## Decision evidence

Every evaluation first performs complete handoff verification. A successful evaluation returns:

- `admitted`
- canonical `policy_sha256`
- deterministic `decision_id`
- exact candidate and previous identities
- bounded evidence counts and selected trust entries
- stable policy violations

Exit codes are:

- `0`: verified and admitted
- `1`: verified but denied by policy
- `2`: malformed, unsafe, stale-pinned, or unverifiable policy/handoff

Stable policy denials are `ATA001` through `ATA016`.

## Operational boundary

A self-consistent handoff does not establish freshness without external pins. Always supply the expected bundle ID, candidate checkpoint ID, and—for transitions—the previous checkpoint ID from an independently retained channel.
