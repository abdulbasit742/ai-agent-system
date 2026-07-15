# Basit Agent System

A dependency-free AI Agent Control Plane that combines the capabilities of the user's recent security and automation repositories behind one safe CLI.

## Included capabilities

- unified repository, MCP, workflow, prompt, secret, and autonomy-boundary scanning
- destructive-command policy gate
- trace redaction for credentials, PII, and prompt markers
- text, JSON, and SARIF output
- composable skills and reusable agent templates
- dry-run-first integration dispatcher
- tamper-evident hash-chained audit log
- reviewed commit pins for six repositories created during the last seven days
- reviewed catalog pins for Awesome LLM Apps and Skills for Real Engineers

## License boundary

`Dicklesworthstone/destructive_command_guard` is not copied, fetched, indexed, vendored, or included because its current license contains an OpenAI/Anthropic restriction. The command gate here is an independent implementation based on general safety requirements and the user's own projects.

## Setup

```bash
git clone https://github.com/abdulbasit742/ai-agent-system.git
cd ai-agent-system
python scripts/bootstrap_integrations.py
```

The root CLI works without downloading integrations:

```bash
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard git reset --hard HEAD~3
python agent_system.py scrub trace.log --output sanitized/trace.log
python agent_system.py skills
python agent_system.py agents
python agent_system.py doctor
python agent_system.py audit
```

Integration execution is always shown first and does nothing until `--approve` is supplied:

```bash
python agent_system.py run workflow-warden
python agent_system.py run workflow-warden --approve
```

The social integration is fixed to `npm run dry-run`; the root dispatcher does not publish.

## Validation

```bash
python -m unittest discover -s tests -v
python -m compileall -q agent_system.py tests scripts
python agent_system.py scan . --format json --fail-on high
python agent_system.py guard python -m unittest discover -s tests
```
