# Baseline and new-findings-only gating

Security baselines let an existing repository adopt Basit Agent System without pretending its current findings are fixed. A baseline records exact finding fingerprints, then CI fails only when a new finding appears.

## Create a baseline

Review the current scanner report first, then create the baseline:

```bash
python agent_system.py scan . --format json
python agent_system.py baseline --create --scan-path .
```

The default output is `.agent-system-baseline.json`. Existing files are never overwritten unless `--force` is supplied.

## Gate only new findings

```bash
python agent_system.py scan . --new-only --format json --fail-on high
```

`--new-only` automatically discovers `.agent-system-baseline.json` in the scanned project root. An explicit file can be supplied:

```bash
python agent_system.py scan . \
  --new-only \
  --baseline security/backend-baseline.json \
  --show-existing
```

In baseline mode:

- `findings` contains only new findings
- `existing_findings` and `resolved_findings` are included only with `--show-existing`
- SARIF contains only new findings, preventing duplicate legacy alerts
- exit status is calculated from new findings plus expired suppression policy state
- audit records include baseline source and new, existing, and resolved counts

## Exact matching

A baseline match requires the exact 64-character scanner fingerprint. The fingerprint includes rule ID, repository path, line, and matched evidence. Moving or changing a finding therefore produces one `new` finding and one `resolved` baseline entry. This conservative behavior prevents broad patterns from hiding regressions.

The baseline never stores finding previews, matched secrets, remediation text, or source contents.

## Control-scope binding

Each baseline is bound to a SHA-256 digest of:

- enabled rule packs
- disabled non-core rules
- enabled scanner rules
- reviewed suppression policy entries

Changing those controls invalidates the baseline and makes the scan fail closed with exit code `2`. Review the new scope and recreate the baseline deliberately.

Expired suppression state also changes the control digest. Resolve or renew the reviewed exception before creating a replacement baseline.

## Integrity model

The baseline includes `baseline_sha256`, calculated over its version, timestamp, scan root, controls digest, and sorted findings. Manual edits or accidental corruption are rejected.

This is an integrity check, not a cryptographic signature. A person able to modify the repository can regenerate the hash. Protect baseline changes through normal code review and branch protection.

## CI example

```yaml
- run: python agent_system.py scan . --new-only --format sarif --output agent-system.sarif
```

For the first adoption commit, create and review `.agent-system-baseline.json`. Later pull requests should normally change the baseline only when legacy findings are intentionally accepted or removed.
