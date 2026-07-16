# Python package distribution

Basit Agent System can be built and installed as the dependency-free `basit-agent-system` Python package. The package targets Python 3.11 or newer and keeps one canonical version in `agent_version.py`.

## Install from a reviewed commit

Until a reviewed package release is published, install directly from an immutable Git commit:

```bash
pipx install git+https://github.com/abdulbasit742/ai-agent-system.git@<reviewed-commit-sha>
```

For a local checkout:

```bash
python -m pip install .
```

## Installed commands

```bash
basit-agent --version
basit-agent scan . --format json --fail-on high
basit-agent guard git reset --hard HEAD~1
basit-agent-lines . --changed-from origin/main --format sarif
```

Compatibility aliases are also installed:

- `agent-system`
- `agent-changed-lines`

All four commands use the same canonical version source.

## Distribution boundary

The wheel contains only these reviewed runtime modules:

- `agent_system`
- `agent_policy`
- `agent_config`
- `agent_baseline`
- `agent_git`
- `agent_changed_lines`
- `agent_cli`
- `agent_version`

It contains no runtime dependencies, tests, documentation, GitHub Action internals, external integrations, audit logs, generated reports, baselines, or populated environment files.

The installed wheel supports scanning, command guarding, redaction, configuration, suppression policy, baselines, Git scopes, audit verification, skills, and agent listing. `doctor` and integration `run` require a source checkout because external repositories are intentionally not vendored into the wheel; those commands fail closed with exit status `2` when invoked from an installed wheel.

## Build and validate

```bash
rm -rf dist build *.egg-info
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/validate_wheel.py dist/*.whl
```

Install the built artifact in an isolated environment before release:

```bash
python -m venv /tmp/basit-agent-venv
/tmp/basit-agent-venv/bin/python -m pip install --no-deps dist/*.whl
/tmp/basit-agent-venv/bin/basit-agent --version
```

The validator checks the project name, canonical version, Python requirement, zero runtime dependencies, exact module allowlist, exact console entry points, metadata completeness, archive-path safety, and forbidden-file exclusions.

## Version changes

1. Update only `agent_version.py`.
2. Add the release notes to `CHANGELOG.md`.
3. Run the full unit, wheel, installation, self-scan, and command-guard verification.
4. Review the built wheel with `scripts/validate_wheel.py`.
5. Publish only through a separately reviewed release process; package publication is never an automatic side effect of ordinary CI.
