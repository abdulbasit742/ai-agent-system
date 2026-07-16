# Security audit: Python distribution

Task 6 introduces an installable wheel and console scripts. This document records the reviewed package boundary.

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

`scripts/validate_wheel.py` enforces an exact eight-module allowlist. It rejects:

- undeclared or unexpected Python source
- missing reviewed modules
- runtime dependency declarations
- multiple `.dist-info` directories
- unsafe archive paths
- tests, action metadata, integration locks, environment files, audit artifacts, baselines, and generated reports
- wrong project name, version, Python requirement, or console entry points

## Integration boundary

The installed wheel does not contain `integrations.lock.json` or cloned external projects. The `doctor` and `run` commands therefore fail closed with a clear source-checkout requirement. This prevents a package build from silently changing or vendoring reviewed integration pins.

## Release boundary

Ordinary pull-request and push CI builds and validates the wheel but does not publish it. Publication requires a separate explicit release workflow and independent review. No package registry token is read by the current workflow.

## Installation verification

CI builds a wheel on Python 3.11 and 3.12, validates the archive, installs it into an isolated virtual environment without dependencies, checks all console aliases, and performs a repository self-scan from outside the source directory.
