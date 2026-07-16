# Receiver-acceptance bundle admission

Task 36 adds consumer-owned authorization policies for portable receiver-acceptance checkpoint bundles. Bundle verification proves integrity and append-only evidence. Admission separately decides whether that verified evidence is acceptable to a particular consumer.

## Commands

Create a canonical default policy:

```bash
basit-agent-audit-trust-receiver-acceptance-admission init acceptance-admission.json
```

Validate a policy:

```bash
agent-audit-trust-receiver-acceptance-admission validate acceptance-admission.json
```

Evaluate a snapshot bundle:

```bash
basit-agent-audit-trust-receiver-acceptance-admission evaluate acceptance-handoff \
  --policy acceptance-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Evaluate a transition bundle by additionally retaining the previous checkpoint pin:

```bash
--expected-previous-checkpoint-id "$PREVIOUS_CHECKPOINT_ID"
```

The policy must remain outside the evaluated bundle.

## Policy controls

The exact version-1 policy contains four sections:

- `bundle`: allowed snapshot/transition types, file/byte limits, and proof-count limits;
- `candidate`: acceptance, receiver, and trust entry ranges; generation and segment bounds; and acceptance/receiver/trust identity allowlists;
- `selection`: required or allowed acceptance sequences and receiver-bundle IDs, plus anchor/head requirements;
- `transition`: relation, acceptance/receiver/trust/generation/segment deltas, previous identity allowlists, and optional single-step advancement.

An empty identity allowlist means that field is not restricted. Required selections must be subsets of non-empty allowed selections.

## Decisions and exit codes

Every result contains:

- `admitted`;
- canonical `policy_sha256`;
- deterministic `decision_id`;
- exact bundle/checkpoint identity;
- bounded evidence and delta summaries;
- stable violations.

Exit codes are:

- `0`: bundle fully verified and admitted;
- `1`: bundle fully verified but denied by policy;
- `2`: malformed policy, unsafe path, stale external pin, or unverifiable bundle.

Stable policy denials are `ABA001` through `ABA016`.

## Trust boundary

The evaluator fully verifies the exact-boundary acceptance bundle before applying policy. It then reloads the canonical manifest and requires its bundle ID to equal the verified identity, preventing a post-verification manifest replacement from being authorized. Policies and externally retained pins are consumer-owned and are never loaded from bundle contents.

Policy hashes and decision IDs prove deterministic content identity, not signer identity. Signing, witness, and key management remain outside this repository.
