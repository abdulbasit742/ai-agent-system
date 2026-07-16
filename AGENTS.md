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
- Added-line gates must filter current findings with new-side ranges and baseline resolutions with old-side ranges; never reuse one coordinate system for both.
- Pure renames must remain silent in added-line mode unless content hunks exist. Added/copied files are full new-file scope and deleted files are full old-file resolution scope.
- GitHub Action values must enter through environment variables and validated argument arrays, never through shell interpolation.
- Action-controlled input paths must remain beneath `GITHUB_WORKSPACE`; generated report and SARIF paths must remain beneath `.agent-system/`, be distinct, and resist symlink escape.
- Stale generated reports must be deleted before execution only after the output boundary validates.
- Workflow annotations, job summaries, and generated SARIF must never contain scanner preview evidence.
- Recommended pull-request workflows must remain read-only and must not use `pull_request_target` for untrusted code.

Verification:

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_system.py agent_policy.py agent_config.py agent_baseline.py agent_git.py agent_changed_lines.py tests scripts
python agent_system.py config .agent-system.example.json
python agent_system.py policy .agent-system-policy.example.json
python agent_system.py --audit-log /tmp/agent-audit.jsonl baseline /tmp/agent-baseline.json --create --scan-path .
python agent_system.py --audit-log /tmp/agent-audit.jsonl scan . --new-only --baseline /tmp/agent-baseline.json --format json --fail-on high
python agent_changed_lines.py . --changed-from HEAD --format json --audit-log /tmp/agent-line-audit.jsonl
python -m unittest discover -s tests -p "test_github_action.py" -v
python -m unittest discover -s tests -p "test_action_entrypoint.py" -v
python agent_system.py scan . --format json --fail-on high
```
