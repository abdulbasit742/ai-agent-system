# Basit Agent System

A dependency-free AI agent control plane for repository scanning, command guarding, trace redaction, safe integration dispatch, and tamper-evident audit logs.

## Capabilities

- repository, MCP, workflow, prompt, secret, and autonomy-boundary scanning
- configurable rule packs with mandatory core protections
- exact-fingerprint baselines and new-findings-only CI gates
- Git-aware changed-file pull-request gates
- added-line-only regression gates for low-noise reviews
- first-party GitHub Action with annotations, job summaries, JSON, SARIF, and structured outputs
- installable dependency-free Python package with reviewed wheel contents and console commands
- reproducible release evidence with exact source identity, canonical manifests, and SHA-256 checksums
- destructive-command policy gate
- credential, PII, and prompt-marker redaction
- text, JSON, and SARIF reports
- dry-run-first integration dispatcher
- hash-chained audit log verification
- versioned suppression policies with mandatory ownership, justification, and expiration

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

## Reproducible release evidence

Build the same reviewed source twice with one deterministic source epoch:

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
python -m pip wheel . --no-deps --wheel-dir dist-one
python -m pip wheel . --no-deps --wheel-dir dist-two
python scripts/release_bundle.py compare dist-one/*.whl dist-two/*.whl
```

Create and verify a release evidence bundle:

```bash
python scripts/release_bundle.py create \
  --wheel dist-one/*.whl \
  --output-dir release \
  --source-commit "$(git rev-parse HEAD)" \
  --source-date-epoch "$SOURCE_DATE_EPOCH"

python scripts/release_bundle.py verify release
```

A verified bundle contains only the reviewed wheel, `release-manifest.json`, and `SHA256SUMS`. The manifest records the exact source commit, deterministic source timestamp, package identity, artifact size, wheel metadata, SHA-256 digest, and a canonical `release_id`. Extra files, symlinks, tampering, checksum drift, metadata drift, or byte-different builds fail closed.

CI uploads the verified bundle only as a read-only workflow artifact. It does not publish to a package registry, create a GitHub Release, request OIDC credentials, or read registry secrets.

See [docs/reproducible-releases.md](docs/reproducible-releases.md) and [docs/security-audit-reproducible-releases.md](docs/security-audit-reproducible-releases.md).

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

Replace the placeholder with a reviewed release or commit. The action defaults to the exact pull-request base and head commit SHAs, constrains all file inputs and outputs to `GITHUB_WORKSPACE`, removes stale reports before execution, and never places matched source previews in annotations, job summaries, or generated SARIF messages.

Supported modes are `full`, `changed-files`, and `added-lines`. Outputs include status, finding counts, baseline counts, JSON report path, and SARIF path. See [docs/github-action.md](docs/github-action.md) and [examples/github-actions/security.yml.example](examples/github-actions/security.yml.example).

## Pull-request changed-file gates

Scan only files changed from a reviewed base reference to `HEAD`:

```bash
python agent_system.py scan . \
  --changed-from origin/main \
  --format json \
  --fail-on high
```

Combine the Git scope with an existing baseline so only new findings in changed files fail:

```bash
python agent_system.py scan . \
  --changed-from origin/main \
  --new-only \
  --format sarif \
  --output agent-system.sarif
```

The system resolves refs to commit SHAs, calculates a merge-base diff, parses NUL-delimited paths, and fails closed for missing history, invalid refs, malformed output, or paths escaping the repository. Deleted and renamed paths participate in scoped baseline resolution without being read from disk.

See [docs/changed-file-gating.md](docs/changed-file-gating.md).

## Added-line-only gates

For the lowest-noise pull-request gate, report only findings whose starting line was added or replaced:

```bash
python agent_changed_lines.py . \
  --changed-from origin/main \
  --format json \
  --fail-on high
```

Use the same reviewed baseline while restricting both new findings and resolved findings to the changed line ranges:

```bash
python agent_changed_lines.py . \
  --changed-from origin/main \
  --new-only \
  --show-existing \
  --format sarif \
  --output agent-system.sarif
```

Added and copied files are scanned fully. Deleted files place all old findings in resolution scope. Modified files use separate old and new zero-context hunk ranges, so inserting safe lines before a legacy issue does not falsely reclassify it. A pure rename creates no added-line finding.

See [docs/added-line-gating.md](docs/added-line-gating.md).

## Baseline adoption for existing repositories

Review current findings and create an exact-fingerprint baseline:

```bash
python agent_system.py scan . --format json
python agent_system.py baseline --create --scan-path .
```

Then fail CI only when a new finding is introduced:

```bash
python agent_system.py scan . --new-only --format json --fail-on high
```

The scanner automatically discovers `.agent-system-baseline.json`. Use `--show-existing` to include existing and resolved entries in JSON or text reports. SARIF baseline mode contains only new findings.

Baselines contain no secret previews or source evidence. They carry an integrity hash and are bound to the active rule-pack and suppression controls. Changed controls, malformed files, or manual edits fail closed.

See [docs/baseline-gating.md](docs/baseline-gating.md).

## Rule-pack configuration

Create a project configuration:

```bash
python agent_system.py config --init
```

Validate it:

```bash
python agent_system.py config .agent-system.json
```

The scanner automatically discovers `.agent-system.json` in the scanned project root. An explicit configuration can be supplied with:

```bash
python agent_system.py scan . --config policies/backend.json
```

Available packs:

- `core`: sensitive artifacts, private keys, credentials, and provider tokens
- `boundaries`: authentication, permissions, shell execution, dynamic execution, and approval bypasses
- `workflows`: GitHub Actions permission, trigger, runner, remote-script, and action-pin checks

The `core` pack and its rules cannot be disabled. Unknown packs and rule IDs fail closed. Optional packs can be omitted, and individual non-core rules can be listed in `disabled_rules`.

See [docs/rule-pack-configuration.md](docs/rule-pack-configuration.md) and [.agent-system.example.json](.agent-system.example.json).

## Reviewed suppression policies

Create a policy template:

```bash
python agent_system.py policy --init
```

Validate it:

```bash
python agent_system.py policy .agent-system-policy.json
```

Scan with automatic policy discovery:

```bash
python agent_system.py scan . --format json --show-suppressed
```

Or pass an explicit path:

```bash
python agent_system.py scan . --policy policies/repository.json
```

Each suppression must have a unique `id`, `owner`, meaningful `reason`, and ISO `expires` date. It may match by `rule_id`, path glob, and optional exact fingerprint. Expired suppressions never hide findings and make validation fail.

See [docs/policy-suppressions.md](docs/policy-suppressions.md) and [.agent-system-policy.example.json](.agent-system-policy.example.json).

## Safe dispatch

Integration execution is shown first and does nothing until `--approve` is supplied:

```bash
python agent_system.py run workflow-warden
python agent_system.py run workflow-warden --approve
```

The social integration is fixed to `npm run dry-run`; the root dispatcher does not publish.

## Numbered development workflow

Development is tracked as an ordered 1-to-400 sequence. Every number must preserve working features, add tests, run the documented verification commands, and update [development-progress.json](development-progress.json). See [docs/NUMBERED_WORKFLOW.md](docs/NUMBERED_WORKFLOW.md).

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
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/validate_wheel.py dist/*.whl
python scripts/release_bundle.py create --wheel dist/*.whl --output-dir release --source-commit "$(git rev-parse HEAD)" --source-date-epoch "$(git show -s --format=%ct HEAD)"
python scripts/release_bundle.py verify release
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard python -m unittest discover -s tests
```
