# Rule-pack configuration

Basit Agent System discovers `.agent-system.json` from the root being scanned. This file controls which project-specific scanner packs run without weakening the mandatory credential and secret baseline.

## Schema

```json
{
  "version": 1,
  "enabled_packs": ["core", "boundaries", "workflows"],
  "disabled_rules": []
}
```

## Packs

| Pack | Rules | Purpose |
| --- | --- | --- |
| `core` | `BAS000`–`BAS003` | Sensitive files, private keys, hardcoded credentials, provider tokens |
| `boundaries` | `BAS010`–`BAS013`, `BAS030` | Trust boundaries, authentication, shell execution, dynamic execution, approval bypasses |
| `workflows` | `BAS020`–`BAS024` | GitHub Actions permissions, triggers, runners, remote scripts, mutable action references |

## Safety behavior

- `core` is mandatory and cannot be removed from `enabled_packs`.
- Core rule IDs cannot appear in `disabled_rules`.
- Unknown packs, unknown rule IDs, duplicate entries, malformed JSON, and unsupported versions fail closed with exit code `2`.
- Configuration is applied before suppression policy evaluation, so reports and audit events record both controls independently.
- JSON and SARIF summaries record enabled packs and disabled rules for review evidence.

## Commands

```bash
python agent_system.py config --init
python agent_system.py config .agent-system.json
python agent_system.py scan . --config .agent-system.json --format json
```

Use a suppression policy rather than disabling a rule when a specific, reviewed finding is accepted temporarily. Suppressions carry ownership, justification, and expiration; pack configuration is intended for durable project scope.
