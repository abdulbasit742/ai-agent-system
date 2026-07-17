# Security audit: receiver-acceptance trust handoff admission

## Scope

Task 41 adds consumer-owned authorization after complete verification of Task 40 snapshot or transition handoffs. The handoff never supplies its own policy.

## Verification before authorization

Evaluation first verifies the exact manifest, checksums, file boundary, candidate checkpoint, mandatory inclusion proofs, optional retained checkpoint, consistency proof, and all externally retained pins. It then reloads the manifest and requires its bundle ID to equal the verified report, preventing post-verification manifest replacement.

Malformed or unverifiable evidence exits `2`; it is never represented as an ordinary policy denial.

## Stable denials

- `ABM001`: handoff type is not allowed;
- `ABM002`: file or byte limit exceeded;
- `ABM003`: proof count outside policy;
- `ABM004`: receiver-acceptance trust depth outside policy;
- `ABM005`: nested acceptance, receiver, or trust depth outside policy;
- `ABM006`: generation or segment count outside policy;
- `ABM007`: outer acceptance-trust state/checkpoint identity not allowed;
- `ABM008`: nested acceptance, receiver, trust, or head identity not allowed;
- `ABM009`: selected sequence constraint failed;
- `ABM010`: selected acceptance-bundle constraint failed;
- `ABM011`: required anchor or candidate-head proof missing;
- `ABM012`: transition relation not allowed;
- `ABM013`: outer acceptance-trust entry delta outside policy;
- `ABM014`: nested acceptance, receiver, trust, generation, or segment delta outside policy;
- `ABM015`: previous nested identity not allowed;
- `ABM016`: single-step transition requirement failed.

## Canonical policy and decisions

Policies use strict canonical JSON with exact schemas, bounded positive integers, sorted duplicate-free arrays, lowercase SHA-256 IDs, and validated minimum/maximum pairs. `policy_sha256` commits the normalized policy. `decision_id` commits the admitted flag, policy hash, identities, bounded evidence summary, and ordered violations.

## Filesystem and privacy boundary

The policy must resolve outside the handoff directory. Generated decisions contain IDs, counts, deltas, and stable diagnostics only. Complete bundles and policies are not uploaded by ordinary admission CI; only decision reports are retained.

## Trust boundary

The underlying handoff is unsigned. Merkle proofs and SHA-256 IDs establish inclusion and integrity relative to independently retained pins; they do not authenticate a producer. Admission expresses consumer authorization under one exact policy and does not add signatures, timestamps, witnesses, or non-repudiation.
