# Verified release transitions

A release-admission decision answers whether one bundle is acceptable. A release-transition decision answers whether moving from one already trusted release to a candidate release is safe.

The transition gate is dependency-free, offline, deterministic, and fail closed. The caller supplies the previous trusted bundle; the tool never downloads a prior release, resolves a mutable tag, or selects a trust anchor automatically.

## Validate or create a policy

```bash
python scripts/release_transition.py policy .release-transition.example.json
python scripts/release_transition.py policy .release-transition.json --init
```

Policies use an exact versioned schema and a canonical SHA-256. Unknown fields, unsupported versions, non-boolean controls, negative limits, symlink policies, and overwrite attempts fail closed.

## Compare two verified bundles

```bash
python scripts/release_transition.py compare \
  trusted-release \
  candidate-release \
  --policy .release-transition.example.json \
  --format json
```

`compare` always returns `0` after valid evidence is analyzed. The report still contains `accepted`, `risk`, changes, and stable `TRNxxx` violations. This mode is intended for review and release-note generation.

## Gate a transition

```bash
python scripts/release_transition.py gate \
  trusted-release \
  candidate-release \
  --policy .release-transition.example.json \
  --expected-previous-release-id "$TRUSTED_RELEASE_ID" \
  --expected-candidate-source-commit "$CANDIDATE_COMMIT" \
  --expected-candidate-version "0.2.0" \
  --expected-candidate-release-id "$CANDIDATE_RELEASE_ID" \
  --format json
```

The previous release ID, candidate source commit, and candidate version are mandatory. The candidate release ID is strongly recommended when one reviewed manifest is known.

Exit codes:

- `0`: accepted transition
- `1`: both bundles are valid, but the transition violates policy
- `2`: policy, arguments, trusted anchor, or release evidence are malformed or unverifiable

## Verification sequence

The tool performs these operations in order:

1. Validate the consumer-owned transition policy.
2. Fully verify the previous bundle, including wheel, manifest, checksums, SBOM, and provenance.
3. Fully verify the candidate bundle using the same evidence rules.
4. Require canonical numeric dot-separated versions for deterministic rollback comparison.
5. Bind the previous bundle to the caller-supplied trusted release ID.
6. Bind the candidate to the expected source commit, version, and optional release ID.
7. Compare source epochs, commits, release IDs, module hashes, commands, dependency counts, and license sets.
8. Produce a canonical transition ID, policy hash, risk classification, changes, and stable violations.

## Default policy

The reviewed example policy denies:

- an exact release replay
- a lower package version
- different release bytes under the same package version
- an older or reused source epoch
- reuse of one source commit for different release bytes
- runtime module removal
- console-command removal
- any runtime dependency increase
- package or module license-set drift

It allows runtime module additions, console-command additions, and changes to reviewed module bytes. These remain visible in the deterministic change report.

## Stable transition rules

| Rule | Meaning |
| --- | --- |
| `TRN001` | project identity changed |
| `TRN002` | package version rollback |
| `TRN003` | exact release replay |
| `TRN004` | same-version release mutation |
| `TRN005`–`TRN007` | source epoch or commit rollback/reuse |
| `TRN008`–`TRN011` | expected trusted/candidate identity mismatch |
| `TRN020`–`TRN022` | module addition, removal, or byte change denied by policy |
| `TRN023`–`TRN024` | console-command addition or removal denied by policy |
| `TRN025` | runtime dependency increase exceeds policy |
| `TRN026` | reviewed license set changed |

## Trust boundary

The previous bundle is a caller-selected trust anchor. The tool proves the relationship between that anchor and the candidate, but it does not prove how the caller originally trusted or stored the previous bundle.

For strong rollback resistance, retain the trusted bundle and release ID in a separately controlled location. Do not take the previous bundle from the same untrusted delivery channel as the candidate without an independent identity check.

Transition evidence is unsigned. The report proves deterministic internal analysis; it does not claim authenticated signer identity, transparency-log inclusion, or non-repudiation.
