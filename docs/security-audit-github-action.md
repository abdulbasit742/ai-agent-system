# Security audit: GitHub Action runner

Task 5 adds a composite GitHub Action and a Python runner. This document records its trust boundaries.

## Inputs and command execution

- Composite-action values enter the runner through environment variables, not interpolated shell arguments.
- The runner accepts only enumerated scan modes and severities, strict booleans, and bounded integers.
- Git refs reject control characters and are passed to the existing Git layer as argument-array values.
- Scanner execution uses `subprocess.run([...], shell=False)` semantics.

## Filesystem containment

- Scan, configuration, policy, and baseline paths are repository-relative.
- Absolute paths and parent traversal are rejected.
- Every input path is resolved and must remain beneath `GITHUB_WORKSPACE`, including symlink resolution.
- Optional control files must already exist.
- The scan path must be an existing directory.
- JSON and SARIF outputs are independently confined beneath `.agent-system/`.
- Report and SARIF paths must be different files and cannot escape the generated directory through symlinks.

## Output integrity

- Existing JSON and SARIF output files are deleted before scanner execution only after the generated-output boundary succeeds.
- Cleanup cannot target ordinary source, baseline, configuration, policy, or documentation files.
- A missing or malformed fresh JSON report causes exit status `2`.
- Stale successful output cannot hide a scanner configuration or execution failure.
- GitHub outputs are single-line validated values written through `GITHUB_OUTPUT`.

## Secret exposure boundary

Scanner findings contain a masked preview for local review, but the action deliberately excludes `preview` from:

- workflow annotations
- job summaries
- generated SARIF messages and rule metadata

Annotations contain only the rule ID, title, file, line, severity class, and remediation. Workflow command properties and data escape percent signs, carriage returns, line feeds, colons, and commas.

## Pull-request permissions

The action does not read `GITHUB_TOKEN`, call the GitHub API, publish content, or modify the repository. The recommended workflow uses `pull_request` and `contents: read`. It does not use `pull_request_target`.

Pull-request base and head values default to the exact event commit SHAs. This avoids trusting mutable branch names when the event already supplies immutable commits.

## Report conversion

The runner converts the scanner JSON report into SARIF after successful report parsing. It emits deterministic rule descriptors and result locations without embedding matched source evidence. The caller may preserve SARIF as an artifact or separately upload it with permissions appropriate to that repository.

## Remaining boundary

The action relies on the caller to checkout the target repository. Merge-base modes require sufficient Git history. Missing commits or merge bases fail closed in the existing Git scope layer.
