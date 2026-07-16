# Supply-chain evidence

Task 8 adds deterministic software-bill-of-materials and provenance evidence to every release bundle. Evidence is generated from the already validated wheel and then independently regenerated during verification.

## Evidence files

Each wheel produces two files:

- `<wheel-name>.spdx.json` — SPDX 2.3 JSON SBOM
- `<wheel-name>.provenance.json` — in-toto Statement v1 with a SLSA provenance v1 predicate

The release manifest records the exact filename, media type, byte size, and SHA-256 digest for both files. `SHA256SUMS` covers both evidence files as well.

## SBOM boundary

The SBOM describes the public wheel boundary, not the entire source repository. It includes the reviewed runtime modules only:

- `agent_baseline.py`
- `agent_changed_lines.py`
- `agent_cli.py`
- `agent_config.py`
- `agent_git.py`
- `agent_policy.py`
- `agent_system.py`
- `agent_version.py`

Every file entry carries SHA-1 and SHA-256 checksums. The package record carries the wheel SHA-256, MIT license declarations, exact source commit, package version, and deterministic package verification code.

External integrations, tests, docs, action internals, reports, audit logs, and local configuration files remain outside the package SBOM because they are not shipped in the wheel.

## Provenance boundary

The provenance statement identifies the wheel as its only subject and binds that subject to:

- exact wheel SHA-256
- package name and version
- exact Git source commit
- deterministic `SOURCE_DATE_EPOCH`
- reviewed runtime module list
- installed console-command list
- zero runtime dependencies
- repository workflow path used as builder identity

No environment variables, runner hostnames, temporary paths, user identity, tokens, or wall-clock generation timestamps are recorded.

## Verification model

Verification does not trust the evidence merely because its digest matches the manifest. It:

1. verifies the wheel against the package allowlist
2. verifies manifest and checksum integrity
3. verifies evidence filename, media type, size, and digest
4. regenerates the expected SBOM from the wheel bytes
5. regenerates the expected provenance from the wheel and source identity
6. requires exact JSON-object equality
7. rejects any extra or missing bundle file

This prevents an attacker from modifying evidence and then simply updating the evidence hash, release manifest, release ID, and checksum file.

## Signing status

The provenance statement is unsigned. It provides deterministic, tamper-evident internal consistency but does not provide external signer authentication or non-repudiation.

A later task may add keyless or offline signing only after the repository has a separate permission model, identity policy, transparency-log policy, and human-reviewed publication workflow. Ordinary CI remains read-only and non-publishing.
