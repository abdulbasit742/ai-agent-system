# Consumer admission for receiver-acceptance trust handoffs

A valid handoff proves integrity against externally retained bundle and checkpoint IDs. Admission is a separate consumer-owned decision about whether that verified handoff is acceptable.

The policy must remain outside the handoff directory. Evaluation always verifies the complete handoff before applying policy.

## Commands

Create the default canonical policy:

```bash
basit-agent-audit-trust-receiver-acceptance-trust-admission init policy.json
```

Validate a policy:

```bash
agent-audit-trust-receiver-acceptance-trust-admission validate policy.json
```

Evaluate a snapshot:

```bash
basit-agent-audit-trust-receiver-acceptance-trust-admission evaluate handoff \
  --policy policy.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CHECKPOINT_ID"
```

A transition additionally requires:

```bash
--expected-previous-checkpoint-id "$PREVIOUS_CHECKPOINT_ID"
```

Exit codes are:

- `0`: verified and admitted;
- `1`: verified but denied by policy;
- `2`: malformed policy, unsafe path, stale pin, or unverifiable handoff.

## Policy controls

The policy independently constrains:

- handoff type, files, bytes, and proof count;
- receiver-acceptance trust-state depth;
- nested receiver-acceptance, receiver, and original trust depths;
- generation and segment bounds;
- candidate and previous IDs at all four layers;
- selected acceptance-bundle sequences and IDs;
- anchor/head proof requirements;
- acceptance-trust, acceptance, receiver, trust, generation, and segment deltas;
- optional single-step transition advancement.

Empty identity allowlists mean unrestricted. Non-empty allowlists are exact lowercase SHA-256 ID sets.

## Decision report

Every result includes a canonical policy hash and deterministic decision ID. The evidence summary contains the selected proofs, four nested history depths, nested head identities, and transition deltas. No raw audit events or unbounded paths are added.

The default example is `.audit-trust-receiver-acceptance-trust-admission.example.json`.
