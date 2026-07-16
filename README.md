# Basit Agent System

A dependency-free AI agent control plane for repository scanning, command guarding, trace redaction, safe integration dispatch, and tamper-evident audit logs.

## Capabilities

- repository, MCP, workflow, prompt, secret, and autonomy-boundary scanning
- configurable rule packs with mandatory core protections
- exact-fingerprint baselines and new-findings-only CI gates
- Git-aware changed-file pull-request gates
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
python -m compileall -q agent_system.py agent_policy.py agent_config.py agent_baseline.py agent_git.py tests scripts
python agent_system.py config .agent-system.example.json
python agent_system.py policy .agent-system-policy.example.json
python agent_system.py --audit-log /tmp/agent-audit.jsonl baseline /tmp/agent-baseline.json --create --scan-path .
python agent_system.py --audit-log /tmp/agent-audit.jsonl scan . --new-only --baseline /tmp/agent-baseline.json --format json --fail-on high
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard python -m unittest discover -s tests
```
