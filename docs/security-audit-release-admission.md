# Security audit: release admission

## Scope

This audit covers `.release-admission.example.json`, `scripts/release_admission.py`, `scripts/release_admission_core.py`, release-readiness CI integration, and the generated admission decision.

## Trust boundaries

- The release bundle is untrusted until `verify_bundle` succeeds.
- The admission policy is consumer-owned and must not be sourced from the release bundle.
- Expected source commit, version, and optional release ID are supplied by the caller or reviewed CI context.
- Network services, mutable branches, registries, and remote metadata are outside the admission decision.

## Controls

### Policy parsing

- exact top-level and nested field sets
- supported schema version only
- canonical HTTPS repository URL without credentials, query, fragment, or `.git` suffix
- safe repository-relative builder and build-definition paths
- sorted, unique, non-empty allowlists
- explicit checksum and unsigned-provenance requirements
- canonical policy SHA-256 in every decision

### Bundle-before-policy ordering

Admission never evaluates unverified evidence. The existing bundle verifier first checks:

- exact file boundary and symlink rejection
- manifest integrity and release ID
- wheel allowlist and metadata
- SHA-256 checksums and sizes
- deterministic SPDX and provenance regeneration
- exact source commit and source epoch binding

Malformed evidence returns exit code `2`, not a policy denial.

### Identity binding

The admission gate independently binds:

- manifest project and version
- caller-supplied exact source commit
- optional exact release ID
- SBOM document namespace and source information
- provenance subject wheel digest
- provenance resolved source material
- reviewed builder workflow and build definition

### Consumer constraints

Stable `ADMxxx` violations cover artifact count and size, module and command allowlists, dependency maximums, licenses, checksum algorithms, SPDX fields, provenance types, and unsigned provenance acceptance.

## Threats tested

- wrong expected commit, version, or release ID
- unauthorized license
- reduced or changed module allowlist
- oversized artifact
- changed source repository identity
- unsigned provenance rejected by policy
- unknown policy fields
- path traversal in reviewed workflow paths
- overwrite of an existing policy during initialization
- distinct admit, deny, and invalid exit semantics

## Residual risks

- The current provenance is unsigned and does not authenticate a builder identity.
- A malicious consumer can intentionally weaken its own policy; the policy SHA-256 makes that reviewed input visible but cannot prevent bad governance.
- Admission does not perform vulnerability-database lookups because the package has no runtime dependencies and the gate is intentionally offline.
- The policy currently targets one package family and one source repository. Cross-project federation is out of scope.

## Conclusion

The gate separates cryptographic/semantic verification from consumer authorization, fails closed on malformed inputs, produces deterministic machine-readable decisions, and does not expand CI permissions or publication authority.
