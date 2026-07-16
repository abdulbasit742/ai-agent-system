# Repository Agent Guidance

- Keep the root control plane dependency-free, local-first, and dry-run-first.
- Never commit secrets, populated `.env` files, private data, generated reports, or audit logs.
- Do not copy, fetch, vendor, or include `Dicklesworthstone/destructive_command_guard`; its current license restricts OpenAI and related parties.
- Preserve licenses and reviewed commits in `integrations.lock.json`.
- Add stable rule IDs and regression tests for scanner or command-guard changes.
- Require explicit `--approve` for integration execution; publishing must never be the default.
- Execute the numbered 1-to-400 workflow in order. Preserve completed work and update `development-progress.json` after every verified step.
- The `core` scanner pack and rules `BAS000` through `BAS003` are mandatory and must never be configurable off.
- Baselines may match only exact scanner fingerprints, must omit finding evidence, and must fail closed when their integrity or control scope changes.
- Git change scopes must use read-only argument-array commands, resolved commit SHAs, merge-base semantics, NUL-delimited path parsing, and repository-bound path validation.
- Changed-scope baseline resolution must never classify unrelated baseline paths as resolved.

Verification:

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_system.py agent_policy.py agent_config.py agent_baseline.py agent_git.py tests scripts
python agent_system.py config .agent-system.example.json
python agent_system.py policy .agent-system-policy.example.json
python agent_system.py --audit-log /tmp/agent-audit.jsonl baseline /tmp/agent-baseline.json --create --scan-path .
python agent_system.py --audit-log /tmp/agent-audit.jsonl scan . --new-only --baseline /tmp/agent-baseline.json --format json --fail-on high
python agent_system.py scan . --format json --fail-on high
```
