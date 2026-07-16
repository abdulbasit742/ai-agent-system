# Basit Agent System

A dependency-free AI-agent control plane for repository scanning, command guarding, trace redaction, safe integration dispatch, privacy-safe audit history, and offline software-supply-chain verification.

## Capabilities

- repository, MCP, workflow, prompt, secret, and autonomy-boundary scanning
- configurable rule packs with mandatory core protections
- exact-fingerprint baselines and new-findings-only CI gates
- Git-aware changed-file and added-line pull-request gates
- first-party GitHub Action with JSON, SARIF, annotations, summaries, and structured outputs
- installable dependency-free Python package with an exact reviewed wheel boundary
- strict canonical audit chains with external freshness pins and safe recovery copies
- typed privacy-safe audit events
- atomic audit segment rotation and canonical segment catalogs
- portable catalog Merkle checkpoints, inclusion proofs, and compact consistency proofs
- portable snapshot and transition audit evidence bundles
- consumer-owned audit bundle admission policies
- pinned, hash-chained audit bundle trust states
- portable audit trust-state Merkle checkpoints, per-bundle proofs, lineage gates, and compact consistency proofs
- reproducible release bundles with deterministic SPDX SBOM and in-toto/SLSA-style provenance
- release admission, transition, trust-state, checkpoint, and consistency controls
- destructive-command policy gate and dry-run-first integration dispatcher
- credential, PII, and prompt-marker redaction
- versioned suppression policies with ownership, justification, and expiration

## Quick start

```bash
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard git reset --hard HEAD~3
python agent_system.py scrub trace.log --output sanitized/trace.log
python agent_system.py audit --format json
python agent_system.py audit-events --format json
python agent_system.py doctor
```

Optional pinned integrations can be installed from a source checkout with:

```bash
python scripts/bootstrap_integrations.py
```

## Python package

Install from a reviewed immutable commit:

```bash
pipx install git+https://github.com/abdulbasit742/ai-agent-system.git@<reviewed-commit-sha>
```

Or install a local checkout:

```bash
python -m pip install .
```

Representative installed commands:

```bash
basit-agent --version
basit-agent scan . --format json --fail-on high
basit-agent-lines . --changed-from origin/main --format sarif
basit-agent-segments rotate --path .agent-system/audit.jsonl --output-dir audit-archive/0001
basit-agent-catalog init audit-archive/catalog.json --active .agent-system/audit.jsonl
basit-agent-catalog-checkpoint create audit-archive/catalog.json checkpoint.json \
  --expected-catalog-id "$CATALOG_ID"
basit-agent-catalog-consistency verify consistency.json retained-checkpoint.json candidate-checkpoint.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
basit-agent-audit-bundle verify audit-handoff \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID"
basit-agent-audit-admission evaluate audit-handoff \
  --policy audit-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CHECKPOINT_ID"
basit-agent-audit-trust verify audit-trust-state.json \
  --expected-state-id "$STATE_ID" \
  --bundle current-head-bundle
basit-agent-audit-trust-checkpoint verify audit-trust-checkpoint.json \
  --expected-checkpoint-id "$TRUST_CHECKPOINT_ID"
basit-agent-audit-trust-consistency verify audit-trust-consistency.json \
  retained-trust-checkpoint.json candidate-trust-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_TRUST_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_TRUST_CHECKPOINT_ID"
```

Compatibility aliases are:

- `agent-system`
- `agent-changed-lines`
- `agent-audit-segments`
- `agent-audit-catalog`
- `agent-audit-catalog-checkpoint`
- `agent-audit-catalog-consistency`
- `agent-audit-bundle`
- `agent-audit-admission`
- `agent-audit-trust`
- `agent-audit-trust-checkpoint`
- `agent-audit-trust-consistency`

The wheel has no runtime dependencies and contains only the twenty reviewed modules enforced by `scripts/validate_wheel.py`. Runtime code is included; audit logs, archives, catalogs, checkpoints, proofs, bundles, admission policies, decisions, trust states, trust checkpoints/proofs, trust consistency proofs, lock files, reports, tests, integrations, and generated evidence never enter the wheel.

Installed-wheel `doctor` and integration `run` fail closed because external integrations remain source-checkout-only.

```bash
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/validate_wheel.py dist/*.whl
```

See [docs/python-distribution.md](docs/python-distribution.md), [docs/security-audit-python-distribution.md](docs/security-audit-python-distribution.md), and [CHANGELOG.md](CHANGELOG.md).

## Strict audit-log integrity

Audited commands write canonical UTF-8 JSON Lines records linked by SHA-256. New records include a schema version and physical-line sequence. Exact legacy records remain structurally verifiable.

```bash
python agent_system.py audit \
  --path .agent-system/audit.jsonl \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json
```

Create an immutable copy containing only the verified prefix of a damaged log:

```bash
python agent_system.py audit \
  --path damaged-audit.jsonl \
  --recover-to recovered-audit.jsonl \
  --format json
```

A self-consistent file alone does not prove freshness. Retain the latest record count and head hash separately.

See [docs/audit-log-integrity.md](docs/audit-log-integrity.md) and [docs/security-audit-log-integrity.md](docs/security-audit-log-integrity.md).

## Typed privacy-safe audit events

Reserved events use exact versioned schemas. Other lowercase hyphenated events use a bounded generic JSON schema. Paths, command arrays, and Git refs are stored as domain-separated SHA-256 references rather than raw values.

```bash
python agent_system.py audit-events --format json
python agent_system.py audit --path .agent-system/audit.jsonl --require-typed --format json
```

See [docs/audit-event-admission.md](docs/audit-event-admission.md) and [docs/security-audit-event-admission.md](docs/security-audit-event-admission.md).

## Audit segments and catalogs

```bash
basit-agent-segments rotate \
  --path .agent-system/audit.jsonl \
  --output-dir audit-archive/0001 \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD"

basit-agent-catalog init audit-archive/catalog.json \
  --active .agent-system/audit.jsonl

basit-agent-catalog sync audit-archive/catalog.json \
  --expected-catalog-id "$CATALOG_ID" \
  --active .agent-system/audit.jsonl
```

Every archive contains exact `segment.jsonl` bytes and a canonical `manifest.json`. Catalog synchronization accepts only an exact right-descendant extension of the externally pinned catalog.

See [docs/audit-segment-rotation.md](docs/audit-segment-rotation.md), [docs/audit-segment-catalog.md](docs/audit-segment-catalog.md), and their security audits.

## Portable catalog checkpoints and proofs

```bash
basit-agent-catalog-checkpoint create \
  audit-archive/catalog.json audit-catalog-checkpoint.json \
  --expected-catalog-id "$CATALOG_ID" \
  --active .agent-system/audit.jsonl

basit-agent-catalog-checkpoint prove \
  audit-archive/catalog.json audit-catalog-checkpoint.json segment-proof.json \
  --expected-catalog-id "$CATALOG_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --segment-index 12

agent-audit-catalog-checkpoint verify-proof \
  segment-proof.json audit-catalog-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --segment-dir audit-archive/segment-0012
```

See [docs/audit-catalog-checkpoints.md](docs/audit-catalog-checkpoints.md) and [docs/security-audit-catalog-checkpoints.md](docs/security-audit-catalog-checkpoints.md).

## Audit catalog consistency proofs

A compact consistency proof shows that a candidate checkpoint retains every segment entry committed by a retained checkpoint.

```bash
basit-agent-catalog-consistency prove \
  retained/segments/catalog.json retained-checkpoint.json \
  candidate/segments/catalog.json candidate-checkpoint.json \
  catalog-consistency.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Stable denials are `AUK009` rollback, `AUK010` fork/predecessor mismatch, and `AUK011` generation regression.

See [docs/audit-catalog-consistency.md](docs/audit-catalog-consistency.md) and [docs/security-audit-catalog-consistency.md](docs/security-audit-catalog-consistency.md).

## Portable audit evidence bundles

A snapshot bundle packages a pinned candidate checkpoint and inclusion proofs. A transition bundle additionally packages a pinned previous checkpoint and consistency proof. Selected sealed segments may be copied after proof-to-directory verification.

```bash
basit-agent-audit-bundle create audit-handoff \
  --checkpoint candidate-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --proof segment-proof.json \
  --segment-root audit-archive

agent-audit-bundle verify audit-handoff \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID"
```

Transition creation additionally accepts:

```bash
--previous-checkpoint retained-checkpoint.json \
--expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
--consistency-proof catalog-consistency.json
```

See [docs/audit-evidence-bundles.md](docs/audit-evidence-bundles.md) and [docs/security-audit-evidence-bundles.md](docs/security-audit-evidence-bundles.md).

## Consumer audit bundle admission

Bundle verification proves integrity; admission decides whether verified evidence satisfies consumer policy. The policy must remain outside the bundle.

```bash
basit-agent-audit-admission init audit-admission.json
agent-audit-admission validate audit-admission.json

basit-agent-audit-admission evaluate audit-handoff \
  --policy audit-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CHECKPOINT_ID"
```

Transition evaluation also requires `--expected-previous-checkpoint-id`.

Exit codes are `0` admitted, `1` fully verified but denied, and `2` malformed, unsafe, stale-pinned, or unverifiable. Decisions include canonical policy hashes, deterministic decision IDs, evidence summaries, and `AUA001`–`AUA016` diagnostics.

See [docs/audit-bundle-admission.md](docs/audit-bundle-admission.md) and [docs/security-audit-bundle-admission.md](docs/security-audit-bundle-admission.md).

## Pinned audit bundle trust state

A trust state turns admitted bundles into persistent consumer-owned history. Initialization accepts only an admitted snapshot. Advancement accepts only an admitted transition whose previous checkpoint and catalog equal the current head.

Initialize and retain the returned `state_id` separately:

```bash
basit-agent-audit-trust init audit-trust-state.json snapshot-bundle \
  --policy audit-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CHECKPOINT_ID"
```

Verify the state and optional current-head bundle:

```bash
agent-audit-trust verify audit-trust-state.json \
  --expected-state-id "$STATE_ID" \
  --bundle current-head-bundle
```

Advance through an admitted transition:

```bash
basit-agent-audit-trust advance audit-trust-state.json transition-bundle \
  --policy audit-admission.json \
  --expected-state-id "$STATE_ID" \
  --expected-bundle-id "$CANDIDATE_BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Each entry binds bundle/checkpoint/catalog identity, generation, segment count, Merkle root, admission decision ID, policy hash, predecessor evidence, and a domain-separated hash. Stale pins, policy denials, replay, head mismatch, or generation rollback leave state bytes unchanged.

Exit codes are `0` created/verified/advanced, `1` verified evidence denied or rejected as replay/head mismatch, and `2` malformed, unsafe, stale-pinned, or unverifiable input. Stable diagnostics are `ATS001`–`ATS010`.

See [docs/audit-bundle-trust-state.md](docs/audit-bundle-trust-state.md) and [docs/security-audit-bundle-trust-state.md](docs/security-audit-bundle-trust-state.md).

## Portable audit trust checkpoints

A trust checkpoint commits one exact pinned trust-state generation to an RFC 6962-style Merkle root. A compact inclusion proof authenticates one admitted bundle entry without distributing the complete state.

```bash
basit-agent-audit-trust-checkpoint create \
  audit-trust-state.json audit-trust-checkpoint.json \
  --expected-state-id "$STATE_ID"

basit-agent-audit-trust-checkpoint prove \
  audit-trust-state.json audit-trust-checkpoint.json bundle-proof.json \
  --expected-state-id "$STATE_ID" \
  --expected-checkpoint-id "$TRUST_CHECKPOINT_ID" \
  --bundle-id "$BUNDLE_ID"

agent-audit-trust-checkpoint verify-proof \
  bundle-proof.json audit-trust-checkpoint.json \
  --expected-checkpoint-id "$TRUST_CHECKPOINT_ID" \
  --bundle admitted-bundle
```

The state may be omitted during proof verification. Supplying `--bundle` fully re-verifies the portable snapshot or transition bundle and binds it to the authenticated trust entry. Lineage accepts only identical or right-descendant states; `ATC010` is rollback and `ATC011` is fork. These artifacts are unsigned and require externally retained state/checkpoint IDs for freshness.

See [docs/audit-trust-checkpoints.md](docs/audit-trust-checkpoints.md) and [docs/security-audit-trust-checkpoints.md](docs/security-audit-trust-checkpoints.md).

## Compact audit trust consistency proofs

A compact proof demonstrates that a candidate audit trust checkpoint retains every trust entry committed by a retained checkpoint. Creation validates both complete states; verification needs only the proof and the two externally pinned checkpoints.

```bash
basit-agent-audit-trust-consistency prove \
  retained-state.json retained-checkpoint.json \
  candidate-state.json candidate-checkpoint.json \
  audit-trust-consistency.json \
  --expected-previous-state-id "$RETAINED_STATE_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-state-id "$CANDIDATE_STATE_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"

agent-audit-trust-consistency verify \
  audit-trust-consistency.json retained-checkpoint.json candidate-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Both Merkle roots are reconstructed from canonical compact frontiers. Descendant proofs authenticate the first appended transition against the retained head. `ATK009` is rollback, `ATK010` is fork, and `ATK011` is invalid transition-boundary continuity. Denied creation never writes a proof file.

See [docs/audit-trust-consistency.md](docs/audit-trust-consistency.md) and [docs/security-audit-trust-consistency.md](docs/security-audit-trust-consistency.md).

## Pull-request change gates

```bash
python agent_system.py scan . --changed-from origin/main --format json --fail-on high
python agent_changed_lines.py . --changed-from origin/main --new-only --show-existing \
  --format sarif --output agent-system.sarif
```

Refs resolve to commit SHAs, merge-base diffs use NUL-delimited paths, and paths remain repository-bound.

See [docs/changed-file-gating.md](docs/changed-file-gating.md) and [docs/added-line-gating.md](docs/added-line-gating.md).

## GitHub Action

```yaml
name: agent-security
on: [pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: abdulbasit742/ai-agent-system@<reviewed-commit-sha>
        with:
          mode: added-lines
          fail-on: high
          annotations: true
```

Supported modes are `full`, `changed-files`, and `added-lines`. Generated JSON/SARIF remains under `.agent-system/`, and annotations omit scanner preview evidence.
