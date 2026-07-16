# Basit Agent System

A dependency-free AI agent control plane for repository scanning, command guarding, trace redaction, safe integration dispatch, tamper-evident audit logs, and offline software-supply-chain verification.

## Capabilities

- repository, MCP, workflow, prompt, secret, and autonomy-boundary scanning
- configurable rule packs with mandatory core protections
- exact-fingerprint baselines and new-findings-only CI gates
- Git-aware changed-file and added-line pull-request gates
- first-party GitHub Action with annotations, summaries, JSON, SARIF, and structured outputs
- installable dependency-free Python package with reviewed wheel contents and console commands
- reproducible release bundles with exact source identity and SHA-256 checksums
- deterministic SPDX SBOMs and source-bound in-toto/SLSA-style provenance
- consumer release-admission policies and verified release-transition rollback gates
- pinned, hash-chained consumer release trust states
- portable Merkle checkpoints and individual release inclusion proofs
- compact append-only consistency proofs between externally pinned checkpoints
- destructive-command policy gate
- credential, PII, and prompt-marker redaction
- dry-run-first integration dispatcher
- hash-chained audit-log verification
- versioned suppression policies with ownership, justification, and expiration

## Quick start

```bash
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard git reset --hard HEAD~3
python agent_system.py scrub trace.log --output sanitized/trace.log
python agent_system.py doctor
python agent_system.py audit
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
basit-agent-lines . --changed-from origin/main --format sarif
```

Compatibility aliases `agent-system` and `agent-changed-lines` are also installed. The wheel has no runtime dependencies and contains only the eight reviewed control-plane modules. External integrations are not vendored; installed-wheel calls to `doctor` or integration `run` fail closed and require a source checkout.

Build and inspect the wheel:

```bash
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/validate_wheel.py dist/*.whl
```

See [docs/python-distribution.md](docs/python-distribution.md), [docs/security-audit-python-distribution.md](docs/security-audit-python-distribution.md), and [CHANGELOG.md](CHANGELOG.md).

## Reproducible releases and supply-chain evidence

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

Each bundle contains the reviewed wheel, an SPDX 2.3 JSON SBOM, an unsigned in-toto Statement v1 with a SLSA provenance v1 predicate, `release-manifest.json`, and `SHA256SUMS`. The manifest binds the source commit, deterministic epoch, wheel identity, evidence filenames, media types, sizes, digests, and canonical `release_id`.

Verification regenerates expected SBOM and provenance objects from the validated wheel. Modified evidence still fails even if its hash, manifest release ID, and checksum file are recalculated. Extra files, symlinks, checksum drift, metadata drift, source drift, or byte-different builds fail closed.

The provenance is intentionally unsigned. It proves deterministic internal consistency but does not claim authenticated signer identity, transparency logging, or non-repudiation. CI creates read-only evidence artifacts; it does not publish packages, create releases, request OIDC credentials, read registry secrets, or use signing keys.

See [docs/reproducible-releases.md](docs/reproducible-releases.md), [docs/supply-chain-evidence.md](docs/supply-chain-evidence.md), [docs/security-audit-reproducible-releases.md](docs/security-audit-reproducible-releases.md), and [docs/security-audit-supply-chain-evidence.md](docs/security-audit-supply-chain-evidence.md).

## Release admission

Admission decides whether one verified release is acceptable under a consumer-owned policy:

```bash
python scripts/release_admission.py evaluate release \
  --policy .release-admission.example.json \
  --expected-source-commit "$(git rev-parse HEAD)" \
  --expected-version "0.1.0" \
  --format json
```

The policy can constrain project identity, exact versions, source repository, artifact count and size, modules, console commands, runtime dependencies, licenses, checksums, SBOM fields, provenance type, builder workflow, build definition, and unsigned-evidence acceptance. Results use stable `ADMxxx` rules and distinct admitted (`0`), denied (`1`), and malformed or unverifiable (`2`) exits.

See [docs/release-admission.md](docs/release-admission.md) and [docs/security-audit-release-admission.md](docs/security-audit-release-admission.md).

## Verified release transitions

A transition compares an independently retained trusted bundle with a candidate. Both bundles are fully verified before rollback, replay, same-version mutation, module hashes, commands, dependencies, and licenses are compared:

```bash
python scripts/release_transition.py gate \
  trusted-release candidate-release \
  --policy .release-transition.example.json \
  --expected-previous-release-id "$TRUSTED_RELEASE_ID" \
  --expected-candidate-source-commit "$CANDIDATE_COMMIT" \
  --expected-candidate-version "$CANDIDATE_VERSION" \
  --expected-candidate-release-id "$CANDIDATE_RELEASE_ID" \
  --format json
```

The default policy rejects exact replay, numeric version or source-epoch rollback, different bytes under one version, source-commit reuse, module or command removal, dependency increase, and license drift. Reports carry canonical policy and transition hashes with stable `TRNxxx` rules but never include module contents or credentials.

The caller chooses and protects the previous trust anchor. The tool never downloads or automatically selects it. See [docs/release-transition.md](docs/release-transition.md) and [docs/security-audit-release-transition.md](docs/security-audit-release-transition.md).

## Pinned release trust state

A transition decision is temporary unless the accepted sequence is retained. `release_trust.py` stores that sequence in a canonical hash chain and requires the latest `state_id` to be retained through an independent trusted channel.

Initialize one reviewed anchor:

```bash
python scripts/release_trust.py init \
  release-trust-state.json \
  trusted-release \
  --expected-release-id "$TRUSTED_RELEASE_ID" \
  --expected-source-commit "$TRUSTED_SOURCE_COMMIT" \
  --expected-version "$TRUSTED_VERSION" \
  --format json
```

Verify the state and its current release bundle:

```bash
python scripts/release_trust.py verify \
  release-trust-state.json \
  --expected-state-id "$EXPECTED_STATE_ID" \
  --bundle trusted-release
```

Advance only through an accepted transition:

```bash
python scripts/release_trust.py advance \
  release-trust-state.json \
  trusted-release \
  candidate-release \
  --policy .release-transition.example.json \
  --expected-state-id "$EXPECTED_STATE_ID" \
  --expected-candidate-source-commit "$CANDIDATE_COMMIT" \
  --expected-candidate-version "$CANDIDATE_VERSION" \
  --expected-candidate-release-id "$CANDIDATE_RELEASE_ID" \
  --format json
```

Each entry binds the release identity, previous entry hash, accepted transition ID, and transition-policy SHA-256. The whole file has a canonical `state_id`. Editing, truncation, duplicate release IDs, stale state pins, forked histories, non-canonical encoding, symlinks, or mismatched previous bundles fail closed. State writes use a persistent sidecar lock and same-directory atomic replacement.

The state file alone does not prove freshness: consumers must protect the latest returned `state_id` separately. See [docs/release-trust-state.md](docs/release-trust-state.md) and [docs/security-audit-release-trust.md](docs/security-audit-release-trust.md).

## Merkle checkpoints, inclusion proofs, and consistency proofs

Create a portable checkpoint for one pinned trust state:

```bash
python scripts/release_checkpoint.py create \
  release-trust-state.json \
  release-checkpoint.json \
  --expected-state-id "$EXPECTED_STATE_ID"
```

An inclusion proof demonstrates that one release entry belongs to one checkpoint. A compact consistency proof demonstrates that a candidate checkpoint is identical to or an append-only descendant of a retained checkpoint.

Create compact consistency evidence from the complete states:

```bash
python scripts/release_consistency.py prove \
  retained-state.json \
  retained-checkpoint.json \
  candidate-state.json \
  candidate-checkpoint.json \
  release-consistency-proof.json \
  --expected-previous-state-id "$RETAINED_STATE_ID" \
  --expected-candidate-state-id "$CANDIDATE_STATE_ID" \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

Verify later without distributing either full trust-state history:

```bash
python scripts/release_consistency.py verify \
  release-consistency-proof.json \
  retained-checkpoint.json \
  candidate-checkpoint.json \
  --expected-previous-checkpoint-id "$RETAINED_CHECKPOINT_ID" \
  --expected-candidate-checkpoint-id "$CANDIDATE_CHECKPOINT_ID"
```

The proof carries canonical maximal aligned power-of-two frontiers and normally contains only `O(log n)` hashes. Verification independently reconstructs both pinned Merkle roots. A recalculated `consistency_id` cannot hide changed subtree hashes or a non-canonical range layout. Rollback and fork requests return `CNS010` or `CNS011`, exit with status `1`, and do not create proof files.

Checkpoints and consistency proofs are intentionally unsigned. They prove internal Merkle relationships, not producer identity. Consumers must protect checkpoint IDs separately. See [docs/release-checkpoints.md](docs/release-checkpoints.md), [docs/release-consistency.md](docs/release-consistency.md), [docs/security-audit-release-checkpoints.md](docs/security-audit-release-checkpoints.md), and [docs/security-audit-release-consistency.md](docs/security-audit-release-consistency.md).

## GitHub Action

A repository can run the control plane directly in a read-only pull-request workflow:

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

      - name: Scan added lines
        uses: abdulbasit742/ai-agent-system@<reviewed-commit-sha>
        with:
          mode: added-lines
          fail-on: high
          annotations: true
```

The action defaults to the exact pull-request base and head commit SHAs, constrains file inputs and outputs to `GITHUB_WORKSPACE`, removes stale reports before execution, and never places matched source previews in annotations, summaries, or SARIF messages.

Supported modes are `full`, `changed-files`, and `added-lines`. See [docs/github-action.md](docs/github-action.md) and [examples/github-actions/security.yml.example](examples/github-actions/security.yml.example).

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

Refs are resolved to commit SHAs, merge-base diffs use NUL-delimited paths, and paths are constrained to the repository. Deleted and renamed paths participate in scoped baseline resolution. Added-line mode uses separate old and new hunk coordinates so safe line shifts do not reclassify legacy findings.

See [docs/changed-file-gating.md](docs/changed-file-gating.md) and [docs/added-line-gating.md](docs/added-line-gating.md).

## Baseline adoption

```bash
python agent_system.py scan . --format json
python agent_system.py baseline --create --scan-path .
python agent_system.py scan . --new-only --format json --fail-on high
```

Baselines contain no secret previews or source evidence. They carry an integrity hash and are bound to active rule-pack and suppression controls. Changed controls, malformed files, or manual edits fail closed. See [docs/baseline-gating.md](docs/baseline-gating.md).

## Configuration and suppressions

```bash
python agent_system.py config --init
python agent_system.py config .agent-system.json
python agent_system.py policy --init
python agent_system.py policy .agent-system-policy.json
```

The mandatory `core` pack and rules `BAS000` through `BAS003` cannot be disabled. Suppressions require a unique ID, owner, meaningful reason, and ISO expiration date. Expired suppressions never hide findings and make validation fail.

See [docs/rule-pack-configuration.md](docs/rule-pack-configuration.md), [.agent-system.example.json](.agent-system.example.json), [docs/policy-suppressions.md](docs/policy-suppressions.md), and [.agent-system-policy.example.json](.agent-system-policy.example.json).

## Safe dispatch

Integration execution is shown first and does nothing until `--approve` is supplied:

```bash
python agent_system.py run workflow-warden
python agent_system.py run workflow-warden --approve
```

The social integration is fixed to `npm run dry-run`; the root dispatcher does not publish.

## Numbered development workflow

Development is tracked as an ordered 1-to-400 sequence. Every number must preserve working features, add tests, run verification, and update [development-progress.json](development-progress.json). See [docs/NUMBERED_WORKFLOW.md](docs/NUMBERED_WORKFLOW.md).

## License boundary

`Dicklesworthstone/destructive_command_guard` is not copied, fetched, indexed, vendored, or included because its current license contains an OpenAI/Anthropic restriction. The command gate here is an independent implementation based on general safety requirements and the user's own projects.

## Validation

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_system.py agent_policy.py agent_config.py agent_baseline.py agent_git.py agent_changed_lines.py agent_cli.py agent_version.py tests scripts
python agent_system.py config .agent-system.example.json
python agent_system.py policy .agent-system-policy.example.json
python agent_system.py --audit-log /tmp/agent-audit.jsonl baseline /tmp/agent-baseline.json --create --scan-path .
python agent_system.py --audit-log /tmp/agent-audit.jsonl scan . --new-only --baseline /tmp/agent-baseline.json --format json --fail-on high
python agent_changed_lines.py . --changed-from HEAD --format json --audit-log /tmp/agent-line-audit.jsonl
python -m unittest discover -s tests -p "test_github_action.py" -v
python -m unittest discover -s tests -p "test_packaging.py" -v
python -m unittest discover -s tests -p "test_release_bundle.py" -v
python -m unittest discover -s tests -p "test_supply_chain_evidence.py" -v
python -m unittest discover -s tests -p "test_release_admission.py" -v
python -m unittest discover -s tests -p "test_release_transition.py" -v
python -m unittest discover -s tests -p "test_release_trust.py" -v
python -m unittest discover -s tests -p "test_release_checkpoint.py" -v
python -m unittest discover -s tests -p "test_release_consistency.py" -v
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/validate_wheel.py dist/*.whl
python scripts/release_bundle.py create --wheel dist/*.whl --output-dir release --source-commit "$(git rev-parse HEAD)" --source-date-epoch "$(git show -s --format=%ct HEAD)"
python scripts/release_bundle.py verify release
python scripts/release_admission.py evaluate release --policy .release-admission.example.json --expected-source-commit "$(git rev-parse HEAD)" --expected-version "0.1.0"
python scripts/release_transition.py policy .release-transition.example.json
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard python -m unittest discover -s tests
```
