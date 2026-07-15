# Repository Agent Guidance

- Keep the root control plane dependency-free, local-first, and dry-run-first.
- Never commit secrets, populated `.env` files, private data, generated reports, or audit logs.
- Do not copy, fetch, vendor, or include `Dicklesworthstone/destructive_command_guard`; its current license restricts OpenAI and related parties.
- Preserve licenses and reviewed commits in `integrations.lock.json`.
- Add stable rule IDs and regression tests for scanner or command-guard changes.
- Require explicit `--approve` for integration execution; publishing must never be the default.

Verification:

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_system.py tests scripts
python agent_system.py scan . --format json --fail-on high
```
