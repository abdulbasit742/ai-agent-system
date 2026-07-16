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
- versioned typed audit events with privacy-preserving path, command, and Git-ref references
- atomic audit segment rotation, canonical catalogs, Merkle checkpoints, inclusion proofs, and compact consistency proofs
- portable snapshot and transition audit evidence bundles
- consumer-owned audit bundle admission policies with deterministic decisions
- reproducible release bundles with deterministic SPDX SBOM and in-toto/SLSA-style provenance
- consumer release-admission policies, verified transition gates, pinned trust states, release checkpoints, and consistency proofs
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

The wheel has no runtime dependencies and contains only the seventeen reviewed modules enforced by `scripts/validate_wheel.py`. Runtime code is included; audit logs, archives, catalogs, checkpoints, proofs, bundles, admission policies, admission decisions, reports, tests, integrations, and generated evidence never enter the wheel.

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

## Audit segment rotation and catalogs

```bash
basit-agent-segments rotate \
  --path .agent-system/audit.jsonl \
  --output-dir audit-archive/0001 \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json

basit-agent-catalog init audit-archive/catalog.json \
  --active .agent-system/audit.jsonl --format json

basit-agent-catalog sync audit-archive/catalog.json \
  --expected-catalog-id "$CATALOG_ID" \
  --active .agent-system/audit.jsonl --format json
```

Every archive contains exact `segment.jsonl` bytes and a canonical `manifest.json`. Catalog synchronization accepts only an exact right-descendant extension of the externally pinned catalog.

See [docs/audit-segment-rotation.md](docs/audit-segment-rotation.md), [docs/audit-segment-catalog.md](docs/audit-segment-catalog.md), and their security audits.

## Portable catalog checkpoints and proofs

```bash
basit-agent-catalog-checkpoint create \
  audit-archive/catalog.json audit-catalog-checkpoint.json \
  --expected-catalog-id "$CATALOG_ID" \
  --active .agent-system/audit.jsonl --format json

basit-agent-catalog-checkpoint prove \
  audit-archive/catalog.json audit-catalog-checkpoint.json segment-proof.json \
  --expected-catalog-id "$CATALOG_ID" \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --segment-index 12 --format json

agent-audit-catalog-checkpoint verify-proof \
  segment-proof.json audit-catalog-checkpoint.json \
  --expected-checkpoint-id "$CHECKPOINT_ID" \
  --segment-dir audit-archive/segment-0012 --format json
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

agent-audit-catalog-consistency verify \
  catalog-consistency.json retained-checkpoint.json candidate-checkpoint.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Stable denials are `AUK009` rollback, `AUK010` fork/predecessor mismatch, and `AUK011` generation regression.

See [docs/audit-catalog-consistency.md](docs/audit-catalog-consistency.md) and [docs/security-audit-catalog-consistency.md](docs/security-audit-catalog-consistency.md).

## Portable audit evidence bundles

A snapshot bundle packages a pinned candidate checkpoint and one or more inclusion proofs. A transition bundle also packages a pinned previous checkpoint and a consistency proof. Selected sealed segments may be included after independent proof-to-directory verification.

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

Bundle verification proves integrity; admission determines whether that verified evidence satisfies consumer policy. The policy must remain outside the bundle.

```bash
basit-agent-audit-admission init audit-admission.json
agent-audit-admission validate audit-admission.json --format json

basit-agent-audit-admission evaluate audit-handoff \
  --policy audit-admission.json \
  --expected-bundle-id "$BUNDLE_ID" \
  --expected-candidate-checkpoint-id "$CHECKPOINT_ID" \
  --format json
```

Transition evaluation also requires `--expected-previous-checkpoint-id`.

Exit codes:

- `0`: fully verified and admitted
- `1`: fully verified but denied by policy
- `2`: malformed policy, unsafe input, stale pin, or unverifiable bundle

The decision includes a canonical policy SHA-256, deterministic decision ID, evidence counts, selected segment identities, and stable `AUA001`–`AUA016` diagnostics. These values are unsigned integrity commitments, not authenticated identities or signatures.

See [docs/audit-bundle-admission.md](docs/audit-bundle-admission.md) and [docs/security-audit-bundle-admission.md](docs/security-audit-bundle-admission.md).

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
