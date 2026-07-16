# Reproducible release evidence

Basit Agent System builds release candidates as deterministic evidence bundles before any publication decision. The workflow proves that the same source commit and `SOURCE_DATE_EPOCH` produce the same wheel bytes, then records the artifact identity, SPDX SBOM, provenance statement, manifest, and checksums.

No package registry is contacted by this workflow.

## Release-readiness sequence

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"

python -m pip wheel . --no-deps --wheel-dir dist-one
python -m pip wheel . --no-deps --wheel-dir dist-two

python scripts/release_bundle.py compare \
  dist-one/*.whl \
  dist-two/*.whl

python scripts/release_bundle.py create \
  --wheel dist-one/*.whl \
  --output-dir release \
  --source-commit "$(git rev-parse HEAD)" \
  --source-date-epoch "$SOURCE_DATE_EPOCH"

python scripts/release_bundle.py verify release
```

## Bundle contents

For each reviewed wheel, a verified bundle contains exactly:

- the reviewed `.whl` artifact
- `<wheel-name>.spdx.json`
- `<wheel-name>.provenance.json`
- one shared `release-manifest.json`
- one shared `SHA256SUMS`

No additional file or directory is accepted.

The manifest records:

- manifest schema version 2
- project and package version
- exact 40-character source commit
- source date epoch and deterministic UTC representation
- wheel filename, byte size, SHA-256 digest, media type, module count, console commands, and runtime dependency count
- SBOM and provenance filenames, media types, sizes, and SHA-256 digests
- a `release_id` derived from canonical JSON for the complete manifest payload

The manifest deliberately contains no wall-clock generation time, runner hostname, temporary path, token, repository secret, or matched scanner evidence.

## SPDX SBOM

The deterministic SPDX 2.3 JSON document describes the reviewed dependency-free package and all eight runtime Python modules. It records:

- package name and version
- wheel SHA-256
- MIT declared and concluded license
- source repository and exact commit
- each runtime module filename, size, SHA-1, and SHA-256
- package-to-file `CONTAINS` relationships
- a deterministic package verification code

The SBOM is regenerated from the bundled wheel during verification. Updating only its digest in the manifest is not enough to make a modified SBOM pass.

## Provenance statement

The deterministic provenance file uses an in-toto Statement v1 envelope with a SLSA provenance v1 predicate. It binds:

- the wheel filename and SHA-256 subject
- exact package name and version
- exact source commit
- deterministic source date epoch
- reviewed runtime modules and console commands
- zero runtime dependencies
- the repository workflow used as the builder identity

The statement is intentionally **unsigned evidence**. It proves internal consistency and source binding but does not claim cryptographic signer identity. Signing remains a separate future control.

## Safety behavior

- output directories must be new or empty
- existing files are never deleted or overwritten
- wheel inputs, evidence files, and bundle directories must not be symlinks
- artifact filenames are restricted to a conservative portable character set
- source commits must be exact hexadecimal commit SHAs
- wheels pass the exact module, metadata, entry-point, and dependency validator before copying
- duplicate filenames are rejected
- checksum lines must be canonical, unique, and path-free
- evidence JSON is canonical and deterministic
- verification regenerates the expected SBOM and provenance from the wheel and source identity
- any artifact, evidence, manifest, checksum, size, metadata, timestamp, or file-boundary mismatch fails closed

## Reproducibility comparison

`compare` validates both wheels independently, requires matching filenames and metadata, and then compares SHA-256 and byte size. A metadata-equivalent wheel with different bytes is rejected.

This check is intentionally stricter than semantic package equivalence. The release-readiness workflow requires byte-for-byte reproducibility.

## GitHub Actions behavior

The `release-readiness` job:

1. obtains the source epoch from the reviewed commit
2. builds the wheel twice with the same `SOURCE_DATE_EPOCH`
3. verifies byte identity
4. creates the release bundle, SPDX SBOM, and provenance statement
5. verifies all evidence against the bundled wheel and source identity
6. uploads the bundle only as a GitHub Actions artifact

The job has only `contents: read` permission. It does not use a registry token, trusted publisher, package index, GitHub release write permission, automatic tag creation, signing key, or OIDC request.

Publication and cryptographic signing remain separate human-reviewed operations.
