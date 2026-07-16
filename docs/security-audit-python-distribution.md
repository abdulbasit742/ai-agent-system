# Security audit: Python distribution

Task 6 introduced the installable wheel and console scripts. Tasks 14 and 15 expand the reviewed runtime boundary for strict audit integrity and typed event admission while keeping the package dependency-free.

## Dependency boundary

- The project declares no runtime dependencies.
- Python 3.11 or newer is required.
- The build backend is used only to construct the artifact; runtime commands remain standard-library-only.
- External agent repositories are never copied into the wheel.

## Version integrity

- `agent_version.py` is the single version source.
- Package metadata reads that attribute dynamically.
- All installed console aliases display the same version.
- Unit tests reject version drift between the wrapper and package metadata.

## Wheel contents

`scripts/validate_wheel.py` enforces an exact eleven-module allowlist:

- `agent_audit.py`
- `agent_audit_events.py`
- `agent_baseline.py`
- `agent_changed_lines.py`
- `agent_cli.py`
- `agent_config.py`
- `agent_git.py`
- `agent_policy.py`
- `agent_system.py`
- `agent_system_legacy.py`
- `agent_version.py`

`agent_audit.py` verifies and appends canonical hash-chain records. `agent_audit_events.py` performs typed event admission and privacy normalization. The small `agent_system.py` wrapper combines those controls while `agent_system_legacy.py` retains the previously reviewed scanner, baseline, policy, Git-scope, guard, and dispatcher implementation.

The validator rejects:

- undeclared or unexpected Python source
- missing reviewed modules
- runtime dependency declarations
- multiple `.dist-info` directories
- unsafe archive paths
- tests, action metadata, integration locks, environment files, audit-log data, baselines, and generated reports
- wrong project name, version, Python requirement, or console entry points

## Integration boundary

The installed wheel does not contain `integrations.lock.json` or cloned external projects. The `doctor` and `run` commands therefore fail closed with a clear source-checkout requirement. This prevents a package build from silently changing or vendoring reviewed integration pins.

## Audit-data boundary

Audit runtime code is included, but audit JSON Lines files, lock files, recovery copies, reports, and CI evidence are not package source. Raw paths, command arrays, and Git refs are normalized to domain-separated references before new audit records are stored.

## Release boundary

Ordinary pull-request and push CI builds and validates the wheel but does not publish it. Publication requires a separate explicit release workflow and independent review. No package registry token is read by the current workflow.

## Installation verification

CI builds a wheel on Python 3.11 and 3.12, validates the archive, installs it into an isolated virtual environment without dependencies, checks all console aliases, performs a repository self-scan from outside the source directory, and verifies that installed audit commands create a fully typed privacy-safe chain.
