# Security audit: Python distribution

Task 6 introduced the installable wheel and console scripts. Tasks 14 through 17 expand the reviewed runtime boundary for strict audit integrity, typed event admission, offline segment rotation, and canonical segment catalogs while keeping the package dependency-free.

## Dependency boundary

- The project declares no runtime dependencies.
- Python 3.11 or newer is required.
- The build backend is used only to construct the artifact; runtime commands remain standard-library-only.
- External agent repositories are never copied into the wheel.

## Version integrity

- `agent_version.py` is the single version source.
- Package metadata reads that attribute dynamically.
- All installed console aliases display the same version where a version flag is part of their interface.
- Unit tests reject version drift between the wrapper and package metadata.

## Wheel contents

`scripts/validate_wheel.py` enforces an exact thirteen-module allowlist:

- `agent_audit.py`
- `agent_audit_catalog.py`
- `agent_audit_events.py`
- `agent_audit_segments.py`
- `agent_baseline.py`
- `agent_changed_lines.py`
- `agent_cli.py`
- `agent_config.py`
- `agent_git.py`
- `agent_policy.py`
- `agent_system.py`
- `agent_system_legacy.py`
- `agent_version.py`

`agent_audit.py` verifies and appends canonical hash-chain records. `agent_audit_events.py` performs typed event admission and privacy normalization. `agent_audit_segments.py` seals verified typed logs, creates canonical segment manifests, and verifies archived-to-active continuity. `agent_audit_catalog.py` discovers sealed archives, creates canonical pinned catalogs, and synchronizes only right-descendant segment histories. The small `agent_system.py` wrapper combines audit controls while `agent_system_legacy.py` retains the previously reviewed scanner, baseline, policy, Git-scope, guard, and dispatcher implementation.

The validator rejects:

- undeclared or unexpected Python source
- missing reviewed modules
- runtime dependency declarations
- multiple `.dist-info` directories
- unsafe archive paths
- tests, action metadata, integration locks, environment files, audit-log data, segment archives, segment catalogs, baselines, and generated reports
- wrong project name, version, Python requirement, or console entry points

## Installed command boundary

The exact reviewed command set is:

- `basit-agent`
- `basit-agent-lines`
- `basit-agent-segments`
- `basit-agent-catalog`
- `agent-system`
- `agent-changed-lines`
- `agent-audit-segments`
- `agent-audit-catalog`

The release-admission default policy sources both module and command allowlists from `scripts/validate_wheel.py`, preventing package validation and consumer policy from drifting independently.

## Integration boundary

The installed wheel does not contain `integrations.lock.json` or cloned external projects. The `doctor` and `run` commands therefore fail closed with a clear source-checkout requirement. This prevents a package build from silently changing or vendoring reviewed integration pins.

## Audit-data boundary

Audit runtime code is included, but audit JSON Lines files, segment directories, manifests, catalog files, lock files, recovery copies, reports, and CI evidence are not package source. Raw paths, command arrays, and Git refs are normalized to domain-separated references before new audit records are stored.

Segment manifests and catalog entries contain only safe relative directory names, fixed filenames, versions, indexes, counts, booleans, and hashes. Installed commands create archives and catalogs only in caller-selected runtime locations.

## Release boundary

Ordinary pull-request and push CI builds and validates the wheel but does not publish it. Publication requires a separate explicit release workflow and independent review. No package registry token is read by the current workflow.

## Installation verification

CI builds a wheel on Python 3.11 and 3.12, validates the exact archive and script boundary, installs it into an isolated virtual environment without dependencies, and executes from outside the source checkout. It checks all eight console aliases, performs a repository self-scan, verifies a fully typed privacy-safe audit chain, rotates that chain, initializes a catalog, retains the returned catalog ID, and independently verifies the catalog plus active continuation through the compatibility aliases.
