# Release admission policy

Release verification proves that a bundle is internally consistent. Release admission answers a separate consumer question: **is this verified bundle acceptable under the consumer's reviewed policy?**

The admission gate is dependency-free, offline, deterministic, and fail closed. It never downloads artifacts, resolves mutable tags, contacts a registry, or trusts a policy embedded inside the release bundle.

## Workflow

Validate a reviewed policy:

```bash
python scripts/release_admission.py validate .release-admission.example.json
```

Evaluate a verified release bundle:

```bash
python scripts/release_admission.py evaluate release \
  --policy .release-admission.example.json \
  --expected-source-commit "$(git rev-parse HEAD)" \
  --expected-version "0.1.0" \
  --format json
```

To bind the decision to one exact manifest, also provide its release ID:

```bash
RELEASE_ID="$(python -c 'import json; print(json.load(open("release/release-manifest.json"))["release_id"])')"

python scripts/release_admission.py evaluate release \
  --policy .release-admission.example.json \
  --expected-source-commit "$(git rev-parse HEAD)" \
  --expected-version "0.1.0" \
  --expected-release-id "$RELEASE_ID"
```

## Decision sequence

The evaluator performs these steps in order:

1. Validate the policy's exact versioned schema.
2. Fully verify the release bundle, wheel, manifest, checksums, SPDX SBOM, and provenance.
3. Bind the bundle to the caller-supplied exact source commit and expected version.
4. Optionally bind the bundle to one exact release ID.
5. Apply the consumer policy to project identity, artifact count and size, runtime modules, console commands, dependencies, licenses, checksums, source repository, builder workflow, build definition, and provenance type.
6. Return a deterministic decision with stable `ADMxxx` rule IDs and the canonical policy SHA-256.

## Exit codes

- `0`: bundle admitted
- `1`: bundle is valid but denied by policy
- `2`: policy, arguments, or bundle evidence are malformed or unverifiable

Policy denial is intentionally different from evidence failure. Consumers can distinguish a trustworthy but unacceptable artifact from an artifact whose evidence cannot be trusted.

## Reviewed policy fields

The policy controls:

- project name and allowed versions
- canonical HTTPS source repository
- exact artifact count and maximum artifact size
- exact runtime module and console-command boundaries
- maximum runtime dependencies
- SPDX version and data license
- allowed package and module licenses
- required module checksum algorithms
- required `filesAnalyzed` value
- in-toto statement and SLSA predicate types
- reviewed builder workflow and build-definition paths
- explicit acceptance or rejection of unsigned provenance

Lists must be sorted and unique. Unknown fields, unsupported versions, malformed URLs, unsafe paths, duplicate values, and weak checksum policies fail closed.

## Stable denial rules

| Rule | Meaning |
| --- | --- |
| `ADM001`–`ADM005` | project, version, commit, or release-ID identity mismatch |
| `ADM010`–`ADM015` | artifact count, size, modules, commands, or dependency boundary mismatch |
| `ADM020`–`ADM026` | SPDX, license, checksum, analysis, or SBOM source mismatch |
| `ADM030`–`ADM036` | provenance type, subject, builder, build definition, source material, or unsigned-policy mismatch |

Reports contain identities and rule messages only. They do not include scanner previews, credentials, wheel source contents, or environment values.

## Unsigned provenance boundary

Current provenance is deterministic but unsigned. The policy must explicitly set `accept_unsigned` to `true` to admit it. Setting the field to `false` produces `ADM036` rather than pretending the evidence has authenticated signer identity.

A later signing workflow can tighten this policy without weakening the current evidence and admission model.
