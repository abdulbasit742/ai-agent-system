# Basit Agent System

A dependency-free AI-agent control plane for repository scanning, command guarding, trace redaction, safe integration dispatch, strict tamper-evident audit logs, typed privacy-safe events, and offline software-supply-chain verification.

## Capabilities

- repository, MCP, workflow, prompt, secret, and autonomy-boundary scanning
- configurable rule packs with mandatory core protections
- exact-fingerprint baselines and new-findings-only CI gates
- Git-aware changed-file and added-line pull-request gates
- first-party GitHub Action with annotations, summaries, JSON, SARIF, and structured outputs
- installable dependency-free Python package with reviewed wheel contents
- strict canonical audit chains with external freshness pins and safe recovery copies
- versioned typed audit events with privacy-preserving path, command, and Git-ref references
- atomic audit segment rotation with canonical manifests, active-log continuity, and rollback pins
- reproducible release bundles with exact source identity and SHA-256 checksums
- deterministic SPDX SBOMs and source-bound in-toto/SLSA-style provenance
- consumer release-admission policies and verified release-transition rollback gates
- pinned release trust states, Merkle checkpoints, inclusion proofs, and compact consistency proofs
- destructive-command policy gate
- credential, PII, and prompt-marker redaction
- dry-run-first integration dispatcher
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

The root CLI works without downloading integrations. Optional pinned integrations can be installed with:

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

Installed commands:

```bash
basit-agent --version
basit-agent scan . --format json --fail-on high
basit-agent guard git reset --hard HEAD~1
basit-agent audit --format json
basit-agent audit-events --format json
basit-agent-lines . --changed-from origin/main --format sarif
basit-agent-segments rotate --path .agent-system/audit.jsonl --output-dir .agent-system/segments/0001
agent-audit-segments verify .agent-system/segments/0001 --active .agent-system/audit.jsonl
```

Compatibility aliases `agent-system` and `agent-changed-lines` are also installed. The wheel has no runtime dependencies and contains only the twelve reviewed modules enforced by `scripts/validate_wheel.py`. Audit and segment runtime code is included, but audit data, segment archives, lock files, reports, baselines, tests, integrations, and generated evidence never enter the wheel.

External integrations are not vendored. Installed-wheel calls to `doctor` or integration `run` fail closed and require a source checkout.

```bash
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/validate_wheel.py dist/*.whl
```

See [docs/python-distribution.md](docs/python-distribution.md), [docs/security-audit-python-distribution.md](docs/security-audit-python-distribution.md), and [CHANGELOG.md](CHANGELOG.md).

## Strict audit-log integrity

Audited commands write canonical JSON Lines records linked by SHA-256. New records include an audit schema version and physical-line sequence. Exact legacy records remain verifiable and can be extended safely.

Verify the default log:

```bash
python agent_system.py audit --format json
```

Verify a selected log against independently retained freshness pins:

```bash
python agent_system.py audit \
  --path .agent-system/audit.jsonl \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json
```

Create a new immutable copy containing only the verified prefix of a damaged log:

```bash
python agent_system.py audit \
  --path damaged-audit.jsonl \
  --recover-to recovered-audit.jsonl \
  --format json
```

The verifier rejects malformed UTF-8/JSON, duplicate keys, blank lines, missing final newlines, partial records, schema drift, invalid UTC timestamps, unsafe events, malformed hashes, previous-hash breaks, canonical-hash mismatches, noncanonical serialization, symlinks, and stale external pins. Reports use stable `AUDxxx` rules without repeating event details.

Every append holds a persistent sidecar advisory lock and verifies the complete existing chain first. Scan, guard, scrub, baseline creation, and integration dispatch preflight the selected audit log; a known-corrupt chain blocks execution before another event is written.

A self-consistent file alone does not prove freshness. Retain the latest record count and head hash separately. Recovery never edits or truncates the source log.

See [docs/audit-log-integrity.md](docs/audit-log-integrity.md) and [docs/security-audit-log-integrity.md](docs/security-audit-log-integrity.md).

## Typed privacy-safe audit events

Hash integrity proves that stored bytes did not change. Typed event admission additionally proves that newly stored details matched a reviewed schema and privacy boundary.

Inspect the stable event catalog:

```bash
python agent_system.py audit-events --format json
```

Reserved event names—`scan`, `scan-added-lines`, `baseline-create`, `guard`, `scrub`, and `dispatch`—use exact field schemas. Other lowercase hyphenated events use a bounded generic JSON schema. Credential-bearing generic keys and credential-shaped free-form values are rejected.

New records contain `_event_schema: 1`. Paths become `{kind, sha256}` references, command arrays become `{argc, sha256}` references, and Git refs become domain-separated SHA-256 references. Raw values are not stored alongside those references.

Audit reports now include typed/untyped counts, coverage percentage, privacy state, event counts, and the event-schema version. Existing pre-schema history remains verifiable but is reported as untyped.

After retaining a migration checkpoint, require complete typed coverage:

```bash
python agent_system.py audit \
  --path .agent-system/audit.jsonl \
  --require-typed \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json
```

Stable event-admission rules are `AUD022` for typed schema/canonicalization failure, `AUD023` for credential-bearing details, and `AUD024` when typed-only policy encounters earlier untyped records.

See [docs/audit-event-admission.md](docs/audit-event-admission.md) and [docs/security-audit-event-admission.md](docs/security-audit-event-admission.md).

## Audit segment rotation

Seal a verified, fully typed active log before it reaches the reviewed 64 MiB boundary:

```bash
basit-agent-segments rotate \
  --path .agent-system/audit.jsonl \
  --output-dir .agent-system/segments/0001 \
  --expected-records "$EXPECTED_RECORDS" \
  --expected-head "$EXPECTED_HEAD" \
  --format json
```

Verify complete archived history plus the current active log:

```bash
basit-agent-segments verify \
  .agent-system/segments/0001 \
  .agent-system/segments/0002 \
  --active .agent-system/audit.jsonl \
  --expected-latest-segment-id "$LATEST_SEGMENT_ID" \
  --format json
```

Each new archive directory contains an exact `segment.jsonl` and canonical `manifest.json`. The archive is independently verified and committed before the active log is atomically replaced with one typed continuity record. Existing directories are never overwritten.

Segment hashes and manifests detect modification but are unsigned. Retain the latest segment ID outside the audit storage for rollback detection, and keep every sealed segment available for complete-chain verification.

See [docs/audit-segment-rotation.md](docs/audit-segment-rotation.md) and [docs/security-audit-segment-rotation.md](docs/security-audit-segment-rotation.md).

## Pull-request change gates

Scan only files changed from a reviewed base reference:

```bash
python agent_system.py scan . \
  --changed-from origin/main \
  --format json \
  --fail-on high
```

For the lowest-noise gate, report only findings beginning on added or replaced lines:

```bash
python agent_changed_lines.py . \
  --changed-from origin/main \
  --new-only \
  --show-existing \
  --format sarif \
  --output agent-system.sarif
```

Refs resolve to commit SHAs, merge-base diffs use NUL-delimited paths, and paths remain repository-bound. Added-line mode uses separate old/new hunk coordinates so safe line shifts do not reclassify legacy findings.

See [docs/changed-file-gating.md](docs/changed-file-gating.md) and [docs/added-line-gating.md](docs/added-line-gating.md).

## GitHub Action

```yaml
name: agent-security
on:
  pull_request:

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

Supported modes are `full`, `changed-files`, and `added-lines`. Pull-request defaults use exact base/head SHAs. Inputs remain beneath `GITHUB_WORKSPACE`; generated JSON/SARIF stays beneath `.agent-system/`; annotations and reports omit scanner preview evidence.

See [docs/github-action.md](docs/github-action.md) and [examples/github-actions/security.yml.example](examples/github-actions/security.yml.example).

## Baseline adoption

```bash
python agent_system.py scan . --format json
python agent_system.py baseline --create --scan-path .
python agent_system.py scan . --new-only --format json --fail-on high
```

Baselines contain no source previews. They carry an integrity hash and are bound to active rule-pack and suppression controls. Changed controls, malformed files, or manual edits fail closed.

See [docs/baseline-gating.md](docs/baseline-gating.md).

## Configuration and suppressions

```bash
python agent_system.py config --init
python agent_system.py config .agent-system.json
python agent_system.py policy --init
python agent_system.py policy .agent-system-policy.json
```

The mandatory `core` pack and rules `BAS000` through `BAS003` cannot be disabled. Suppressions require a unique ID, owner, meaningful reason, and ISO expiration date.

See [docs/rule-pack-configuration.md](docs/rule-pack-configuration.md) and [docs/policy-suppressions.md](docs/policy-suppressions.md).

## Reproducible releases and evidence

Build the same reviewed source twice with one deterministic source epoch:

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
python -m pip wheel . --no-deps --wheel-dir dist-one
python -m pip wheel . --no-deps --wheel-dir dist-two
python scripts/release_bundle.py compare dist-one/*.whl dist-two/*.whl
```

Create and verify a release bundle:

```bash
python scripts/release_bundle.py create \
  --wheel dist-one/*.whl \
  --output-dir release \
  --source-commit "$(git rev-parse HEAD)" \
  --source-date-epoch "$SOURCE_DATE_EPOCH"
python scripts/release_bundle.py verify release
```

Each bundle contains the wheel, SPDX 2.3 SBOM, unsigned in-toto Statement v1/SLSA provenance v1 evidence, canonical manifest, and checksums. Verification regenerates expected evidence from the wheel and fails on modified evidence even after hash/manifest rewriting.

Unsigned provenance proves deterministic internal consistency, not authenticated signer identity, transparency logging, or non-repudiation.

See [docs/reproducible-releases.md](docs/reproducible-releases.md) and [docs/supply-chain-evidence.md](docs/supply-chain-evidence.md).

## Admission, transitions, and retained trust

Admit one verified bundle under a consumer-owned policy:

```bash
python scripts/release_admission.py evaluate release \
  --policy .release-admission.example.json \
  --expected-source-commit "$(git rev-parse HEAD)" \
  --expected-version "0.1.0"
```

Compare a retained trusted release with a candidate:

```bash
python scripts/release_transition.py gate \
  trusted-release candidate-release \
  --policy .release-transition.example.json \
  --expected-previous-release-id "$TRUSTED_RELEASE_ID" \
  --expected-candidate-source-commit "$CANDIDATE_COMMIT" \
  --expected-candidate-version "$CANDIDATE_VERSION"
```

Accepted transitions can be retained in a pinned hash-chained trust state, summarized by Merkle checkpoints, proved per release with inclusion proofs, and compared between checkpoints using compact append-only consistency proofs.

See [docs/release-admission.md](docs/release-admission.md), [docs/release-transition.md](docs/release-transition.md), [docs/release-trust-state.md](docs/release-trust-state.md), [docs/release-checkpoints.md](docs/release-checkpoints.md), and [docs/release-consistency.md](docs/release-consistency.md).

## Safe dispatch

Integration execution is shown first and does nothing until `--approve` is supplied:

```bash
python agent_system.py run workflow-warden
python agent_system.py run workflow-warden --approve
```

The root dispatcher does not publish by default.

## Validation

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_audit.py agent_audit_events.py agent_audit_segments.py agent_system.py agent_system_legacy.py agent_policy.py agent_config.py agent_baseline.py agent_git.py agent_changed_lines.py agent_cli.py agent_version.py tests scripts
python agent_system.py config .agent-system.example.json
python agent_system.py policy .agent-system-policy.example.json
python agent_system.py audit-events --format json
python agent_system.py scan . --format json --fail-on high
python agent_system.py audit --format json
python -m unittest discover -s tests -p "test_audit_event_admission.py" -v
python -m unittest discover -s tests -p "test_audit_segments.py" -v
python agent_system.py guard python -m unittest discover -s tests
```

## Numbered development workflow

Development is tracked as an ordered 1-to-400 sequence. Every number preserves working features, adds tests/documentation, verifies CI, and updates [development-progress.json](development-progress.json). See [docs/NUMBERED_WORKFLOW.md](docs/NUMBERED_WORKFLOW.md).

## License boundary

`Dicklesworthstone/destructive_command_guard` is not copied, fetched, indexed, vendored, or included because its current license contains an OpenAI/Anthropic restriction. The command gate here is an independent implementation based on general safety requirements and the user's own projects.
