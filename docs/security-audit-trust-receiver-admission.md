# Security audit: audit trust receiver bundle admission

## Scope

This audit covers `agent_audit_trust_receiver_admission.py`, its canonical policy file, deterministic decisions, source tests, integration workflow, and isolated installed-wheel workflow. It does not alter receiver states, checkpoints, proofs, consistency evidence, or bundles.

## Verify before authorize

The evaluator first calls the complete receiver-bundle verifier with externally retained bundle and checkpoint IDs. Bundle verification checks canonical manifests, exact file boundaries, sorted checksums, file metadata, receiver checkpoints, inclusion proofs, consistency proofs, and candidate-head proof presence.

Only after verification succeeds does admission apply consumer policy. Invalid or stale-pinned bundles produce exit `2`, not a policy denial.

After verification, the canonical manifest is reloaded and its `bundle_id` must equal the verified report. Because the ID commits to the complete canonical manifest, a post-verification replacement cannot silently change selected entries or checkpoint references.

## Consumer-owned policy

The policy must be a regular non-symlink file outside the evaluated bundle. CLI path containment rejects a policy stored anywhere under the bundle directory before bundle verification begins.

Policy parsing rejects:

- duplicate JSON keys;
- non-finite numbers;
- booleans in integer fields;
- missing or extra schema fields;
- unsupported values;
- unsorted or duplicate arrays;
- malformed SHA-256 identifiers;
- inverted bounds;
- required selections outside explicit allowlists;
- noncanonical serialization;
- files exceeding the reviewed size limit.

New policies use exclusive create semantics and mode `0600`.

## Authorization controls

The evaluator applies independent controls for bundle type, size, proof count, receiver and trust counts, generation, segment count, receiver identities, head trust identities, selected sequences, selected handoff IDs, required anchor/head evidence, transition relation, receiver/trust/generation deltas, previous receiver identities, and optional single-step advancement.

Empty allowlists mean unrestricted. This behavior is explicit and tested. Required selections are not weakened by empty allowlists.

## Deterministic reports

Policies are hashed from strict canonical JSON. Decisions include exact identity and bounded evidence summaries, sorted violations in evaluation order, and a domain-separated SHA-256 `decision_id`. Re-evaluating identical verified evidence under the same policy produces the same decision.

Reports do not include raw filesystem paths or unbounded transferred content.

## Failure semantics

Policy denials use:

- `ARA001`: bundle type;
- `ARA002`: bundle size;
- `ARA003`: proof count;
- `ARA004`: receiver or trust entry count;
- `ARA005`: generation;
- `ARA006`: segment count;
- `ARA007`: candidate receiver identity;
- `ARA008`: candidate-head handoff/trust identity;
- `ARA009`: selected receiver sequences;
- `ARA010`: selected handoff IDs;
- `ARA011`: required anchor/head proof;
- `ARA012`: consistency relation;
- `ARA013`: receiver-entry delta;
- `ARA014`: trust-entry or generation delta;
- `ARA015`: previous receiver identity;
- `ARA016`: single-step receiver advancement.

Exit `1` means the bundle was fully verified but denied. Exit `2` means policy or evidence was malformed, unsafe, stale-pinned, or unverifiable.

## Distribution boundary

The module is standard-library-only and adds two reviewed aliases. The wheel excludes generated policies, decisions, bundle directories, checkpoints, proofs, consistency evidence, states, pins, reports, and CI artifacts. Isolated Python 3.11 and 3.12 jobs build and validate the wheel, install it without dependencies, create a real transition receiver bundle, remove loose evidence, initialize/validate policy, and evaluate through both installed aliases outside the source checkout.

## Residual trust assumptions

Admission is authorization, not signature verification. The consumer remains responsible for protecting policy files and external pins, obtaining checkpoint IDs through an authenticated channel, and deciding whether the policy itself is appropriate.
