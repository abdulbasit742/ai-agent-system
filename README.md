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
- atomic audit segment rotation with canonical sealed manifests and linked active logs
- canonical segment catalogs with automatic archive discovery and pinned right-descendant synchronization
- portable catalog Merkle checkpoints, per-segment inclusion proofs, and compact append-only consistency proofs
- reproducible release bundles with exact source identity and SHA-256 checksums
- deterministic SPDX SBOMs and source-bound in-toto/SLSA-style provenance
- consumer release-admission policies and verified release-transition rollback gates
- pinned release trust states, Merkle checkpoints, inclusion proofs, and compact consistency proofs
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

Installed commands include:

```bash
basit-agent --version
basit-agent scan . --format json --fail-on high
basit-agent-lines . --changed-from origin/main --format sarif
basit-agent-segments rotate --path .agent-system/audit.jsonl --output-dir audit-archive/0001
basit-agent-catalog init audit-archive/catalog.json --active .agent-system/audit.jsonl
basit-agent-catalog-checkpoint create audit-archive/catalog.json checkpoint.json --expected-catalog-id "$CATALOG_ID"
basit-agent-catalog-consistency verify consistency.json retained-checkpoint.json candidate-checkpoint.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Compatibility aliases are:

- `agent-system`
- `agent-changed-lines`
- `agent-audit-segments`
- `agent-audit-catalog`
- `agent-audit-catalog-checkpoint`
- `agent-audit-catalog-consistency`

The wheel has no runtime dependencies and contains only the fifteen reviewed modules enforced by `scripts/validate_wheel.py`. Runtime code is included; audit logs, archives, catalogs, checkpoints, inclusion/consistency proofs, reports, tests, integrations, and generated evidence never enter the wheel.

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

The verifier rejects malformed UTF-8/JSON, duplicate keys, partial records, schema drift, invalid timestamps, malformed hashes, previous-hash breaks, noncanonical serialization, symlinks, and stale external pins. Every append holds a sidecar advisory lock and verifies the complete chain first.

A self-consistent file alone does not prove freshness. Retain the latest record count and head hash separately.

See [docs/audit-log-integrity.md](docs/audit-log-integrity.md) and [docs/security-audit-log-integrity.md](docs/security-audit-log-integrity.md).

## Typed privacy-safe audit events

Reserved events—`scan`, `scan-added-lines`, `baseline-create`, `guard`, `scrub`, and `dispatch`—use exact versioned schemas. Other lowercase hyphenated events use a bounded generic JSON schema.

Paths, command arrays, and Git refs are stored as domain-separated SHA-256 references rather than raw values. Credential-bearing generic fields and credential-shaped free-form values are rejected.

```bash
python agent_system.py audit-events --format json
python agent_system.py audit --path .agent-system/audit.jsonl --require-typed --format json
```

See [docs/audit-event-admission.md](docs/audit-event-admission.md) and [docs/security-audit-event-admission.md](docs/security-audit-event-admission.md).

## Audit segment rotation

```bash
basit-agent-segments rotate \
  --path .agent-system/audit.jsonl \
  --output-dir audit-archive/0001 \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json

basit-agent-segments verify \
  audit-archive/0001 audit-archive/0002 \
  --active .agent-system/audit.jsonl \
  --expected-latest-segment-id "$LATEST_SEGMENT_ID" \
  --format json
```

Every archive contains exact `segment.jsonl` bytes and a canonical `manifest.json`. The archive verifies before the active log is atomically replaced with one typed continuity record. Existing directories are never overwritten.

See [docs/audit-segment-rotation.md](docs/audit-segment-rotation.md) and [docs/security-audit-segment-rotation.md](docs/security-audit-segment-rotation.md).

## Audit segment catalogs

```bash
basit-agent-catalog init audit-archive/catalog.json \
  --active .agent-system/audit.jsonl --format json

agent-audit-catalog verify audit-archive/catalog.json \
  --expected-catalog-id "$CATALOG_ID" \
  --active .agent-system/audit.jsonl --format json

basit-agent-catalog sync audit-archive/catalog.json \
  --expected-catalog-id "$CATALOG_ID" \
  --active .agent-system/audit.jsonl --format json
```

Synchronization accepts only an exact right-descendant extension of the pinned catalog. Missing, renamed, replaced, reordered, extra, or forked segments fail closed. A verified no-op does not rewrite catalog bytes.

See [docs/audit-segment-catalog.md](docs/audit-segment-catalog.md) and [docs/security-audit-segment-catalog.md](docs/security-audit-segment-catalog.md).

## Portable audit catalog checkpoints

A checkpoint commits one exact pinned catalog generation to an RFC 6962-style Merkle root. A compact proof demonstrates membership of one complete segment entry without distributing the full catalog.

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

A consistency proof shows that a candidate checkpoint retains every segment entry committed by a retained checkpoint. Full catalogs and segment archives are needed during proof creation, but proof verification needs only the compact proof, two checkpoints, and four externally retained IDs.

```bash
basit-agent-catalog-consistency prove \
  retained/segments/catalog.json retained-checkpoint.json \
  candidate/segments/catalog.json candidate-checkpoint.json \
  catalog-consistency.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --candidate-active candidate/active.jsonl --format json

agent-audit-catalog-consistency verify \
  catalog-consistency.json retained-checkpoint.json candidate-checkpoint.json \
  --expected-previous-catalog-id "$RETAINED_CATALOG_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-catalog-id "$CANDIDATE_CATALOG_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID" \
  --format json
```

A direct next generation must retain the previous catalog ID. A larger generation gap proves append-only segment continuity but does not authenticate omitted intermediate checkpoints. Stable denials are `AUK009` rollback, `AUK010` fork/predecessor mismatch, and `AUK011` generation regression.

These unsigned proofs establish integrity and append-only continuity, not producer identity, witness consensus, or public transparency-log publication.

See [docs/audit-catalog-consistency.md](docs/audit-catalog-consistency.md) and [docs/security-audit-catalog-consistency.md](docs/security-audit-catalog-consistency.md).

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

See [docs/github-action.md](docs/github-action.md).

## Baselines, configuration, and suppressions

```bash
python agent_system.py config --init
python agent_system.py policy --init
python agent_system.py baseline --create --scan-path .
python agent_system.py scan . --new-only --format json --fail-on high
```

The mandatory `core` pack and rules `BAS000` through `BAS003` cannot be disabled. Suppressions require an owner, meaningful reason, and expiration. Baselines omit source previews and are bound to active controls.

## Reproducible releases and evidence

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
python -m pip wheel . --no-deps --wheel-dir dist-one
python -m pip wheel . --no-deps --wheel-dir dist-two
python scripts/release_bundle.py compare dist-one/*.whl dist-two/*.whl
python scripts/release_bundle.py create \
  --wheel dist-one/*.whl --output-dir release \
  --source-commit "$(git rev-parse HEAD)" \
  --source-date-epoch "$SOURCE_DATE_EPOCH"
python scripts/release_bundle.py verify release
```

Each bundle contains the wheel, SPDX 2.3 SBOM, unsigned in-toto/SLSA provenance, canonical manifest, and checksums. Verification regenerates expected evidence from the wheel.

## Admission, transitions, and retained trust

```bash
python scripts/release_admission.py evaluate release \
  --policy .release-admission.example.json \
  --expected-source-commit "$(git rev-parse HEAD)" \
  --expected-version "0.1.0"

python scripts/release_transition.py gate trusted-release candidate-release \
  --policy .release-transition.example.json \
  --expected-previous-release-id "$TRUSTED_RELEASE_ID" \
  --expected-candidate-source-commit "$CANDIDATE_COMMIT" \
  --expected-candidate-version "$CANDIDATE_VERSION"
```

Accepted transitions can be retained in a pinned hash-chained trust state, summarized by Merkle checkpoints, proved per release, and compared using compact consistency proofs.

## Safe dispatch

```bash
python agent_system.py run workflow-warden
python agent_system.py run workflow-warden --approve
```

Integration execution is shown first and does nothing until `--approve` is supplied. Publishing is never the default.

## Validation

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_audit.py agent_audit_events.py agent_audit_segments.py agent_audit_catalog.py agent_audit_checkpoint.py agent_audit_consistency.py agent_system.py agent_system_legacy.py agent_policy.py agent_config.py agent_baseline.py agent_git.py agent_changed_lines.py agent_cli.py agent_version.py tests scripts
python -m unittest discover -s tests -p "test_audit_catalog_consistency.py" -v
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard python -m unittest discover -s tests
```

## Numbered development workflow

Development is tracked as an ordered 1-to-400 sequence. Every number preserves working features, adds tests and documentation, verifies CI, and updates [development-progress.json](development-progress.json). See [docs/NUMBERED_WORKFLOW.md](docs/NUMBERED_WORKFLOW.md).

## License boundary

`Dicklesworthstone/destructive_command_guard` is not copied, fetched, indexed, vendored, or included because its current license contains an OpenAI/Anthropic restriction. The command gate here is an independent implementation based on general safety requirements and the user's own projects.
