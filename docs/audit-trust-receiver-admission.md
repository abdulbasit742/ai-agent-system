# Audit trust receiver bundle admission

Task 31 adds consumer-owned authorization policies for portable audit trust receiver checkpoint bundles.

Bundle verification proves integrity. Admission decides whether that verified evidence satisfies the receiving consumer's requirements. Policies remain outside bundles and are never trusted from transferred evidence.

## Commands

Create the default canonical policy:

```bash
basit-agent-audit-trust-receiver-admission init receiver-admission.json
```

Validate a policy and obtain its canonical hash:

```bash
agent-audit-trust-receiver-admission validate receiver-admission.json --format json
```

Evaluate a snapshot bundle:

```bash
basit-agent-audit-trust-receiver-admission evaluate receiver-bundle \
  --policy receiver-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_RECEIVER_CHECKPOINT_ID" \
  --format json
```

A transition bundle also requires:

```bash
--expected-previous-checkpoint-id "$PREVIOUS_RECEIVER_CHECKPOINT_ID"
```

## Policy controls

The versioned exact-schema policy controls:

- allowed snapshot or transition bundle types;
- maximum files and bytes;
- minimum and maximum inclusion-proof count;
- candidate receiver entry-count bounds;
- candidate trusted-entry, generation, and segment-count bounds;
- receiver state/checkpoint allowlists;
- candidate-head handoff, trust-state, and trust-checkpoint allowlists;
- required and allowed selected receiver sequences;
- required and allowed selected handoff IDs;
- mandatory anchor or head proofs;
- allowed consistency relations;
- receiver-entry, trust-entry, and generation delta bounds;
- previous receiver state/checkpoint allowlists;
- optional one-receiver-entry transition enforcement.

An empty identity or selection allowlist means unrestricted. Required selections remain mandatory.

## Decisions

Every decision contains:

- `admitted`;
- canonical `policy_sha256`;
- exact bundle and receiver checkpoint/state identity;
- selected sequence and handoff evidence;
- candidate receiver/trust counts and generation;
- transition deltas when applicable;
- sorted stable violations;
- domain-separated deterministic `decision_id`.

The evaluator verifies the complete bundle before applying policy. It then reloads the canonical manifest and requires its `bundle_id` to equal the verified report, preventing post-verification manifest replacement.

## Exit codes

- `0`: policy initialized/validated or bundle admitted;
- `1`: bundle fully verified but policy denied it;
- `2`: malformed policy, unsafe path, policy inside bundle, stale external pin, or unverifiable bundle.

Stable policy denials use `ARA001` through `ARA016`.

## Trust boundary

Admission does not sign evidence or establish producer identity. Consumers must retain expected bundle and checkpoint IDs independently. The policy file must be protected as consumer-owned configuration and must not be placed inside the evaluated bundle.
