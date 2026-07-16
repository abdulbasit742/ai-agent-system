# Security audit: verified release transitions

## Scope

This review covers `scripts/release_transition.py`, `.release-transition.example.json`, transition tests, and the read-only transition workflow.

## Security objectives

- never select a previous trust anchor automatically
- fully verify both bundles before comparing them
- distinguish invalid evidence from a valid but denied transition
- detect version and source-time rollback
- detect exact replay and same-version mutation
- detect source-commit reuse for different release bytes
- expose module, command, dependency, and license changes without source previews
- bind gate decisions to caller-supplied trusted and candidate identities
- keep the workflow read-only and non-publishing

## Trust assumptions

The caller controls and reviews the transition policy. The previous bundle and its expected release ID are trusted inputs retained independently from the candidate delivery channel. The operating system, Python runtime, repository checkout, and local filesystem are trusted for execution.

The transition report is deterministic but unsigned. It is not an authenticated statement from a release producer.

## Fail-closed behavior

The gate returns exit code `2` for:

- malformed or missing policy
- policy symlinks
- policy files located inside either release bundle
- unsupported policy versions or unknown fields
- non-canonical numeric versions
- malformed expected commits or release IDs
- invalid, missing, tampered, or semantically inconsistent bundle evidence
- conflicting module hashes or licenses across verified wheel artifacts

A valid but disallowed transition returns exit code `1`. Accepted transitions return `0`.

## Rollback and replay controls

- `TRN002` rejects lower numeric package versions.
- `TRN003` rejects an exact release replay unless the consumer explicitly allows it.
- `TRN004` rejects different release bytes under an unchanged version unless explicitly allowed.
- `TRN005` rejects an older source epoch.
- `TRN006` rejects reuse of the trusted epoch for different release bytes when strict epoch increase is enabled.
- `TRN007` rejects reuse of one source commit for different release bytes.
- `TRN008` binds the previous bundle to the externally retained release ID.
- `TRN009`–`TRN011` bind the candidate to reviewed commit, version, and optional release ID values.

## Change-analysis boundary

The tool reads only verified manifest, SPDX, and provenance identities. It reports filenames, hashes, command names, dependency counts, license identifiers, commits, epochs, versions, and release IDs. It does not emit module contents, scanner evidence, secrets, environment values, tokens, or credentials.

Module hash changes are derived from the semantically regenerated SPDX documents that release verification has already matched to the wheel bytes. Matching manifest hashes alone are not trusted.

## Filesystem behavior

The tool reads bundle and policy files. It does not modify bundles. Policy initialization refuses to overwrite existing files unless `--force` is supplied and rejects symlink outputs. The workflow writes build directories and decision reports only to ignored workspace paths or `RUNNER_TEMP`.

## Network and credential boundary

The transition logic performs no network access. The workflow grants only `contents: read`. It does not publish packages, create releases or tags, request OIDC tokens, use signing keys, or read registry credentials.

## Residual risks

- If an attacker replaces both the candidate and the supposed previous trusted bundle, comparison cannot recover the lost trust anchor. Keep the previous release ID independently.
- Numeric version comparison intentionally rejects non-numeric version formats instead of guessing ordering.
- Source epochs are producer-controlled metadata; they supplement but do not replace the externally pinned previous release ID.
- Unsigned transition reports can be replaced outside the controlled workflow. Preserve workflow provenance or add authenticated signing in a separately reviewed future design.
