# Reproducible release evidence

Basit Agent System builds release candidates as deterministic evidence bundles before any publication decision. The workflow proves that the same source commit and `SOURCE_DATE_EPOCH` produce the same wheel bytes, then records the artifact identity in a machine-readable manifest and checksum file.

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

A verified bundle contains exactly:

- one or more reviewed `.whl` files
- `release-manifest.json`
- `SHA256SUMS`

No additional file or directory is accepted.

The manifest records:

- manifest schema version
- project and package version
- exact 40-character source commit
- source date epoch and deterministic UTC representation
- wheel filename, byte size, SHA-256 digest, media type, module count, console commands, and runtime dependency count
- a `release_id` derived from canonical JSON for the complete manifest payload

The manifest deliberately contains no wall-clock generation time, runner hostname, temporary path, token, repository secret, or matched scanner evidence.

## Safety behavior

- output directories must be new or empty
- existing files are never deleted or overwritten
- wheel inputs and bundle directories must not be symlinks
- artifact filenames are restricted to a conservative portable character set
- source commits must be exact hexadecimal commit SHAs
- wheels pass the existing exact module, metadata, entry-point, and dependency validator before copying
- duplicate filenames are rejected
- checksum lines must be canonical, unique, and path-free
- any artifact, manifest, checksum, size, metadata, timestamp, or file-boundary mismatch fails closed

## Reproducibility comparison

`compare` validates both wheels independently, requires matching filenames and metadata, and then compares SHA-256 and byte size. A metadata-equivalent wheel with different bytes is rejected.

This check is intentionally stricter than semantic package equivalence. The release-readiness workflow requires byte-for-byte reproducibility.

## GitHub Actions behavior

The `release-readiness` job:

1. obtains the source epoch from the reviewed commit
2. builds the wheel twice with the same `SOURCE_DATE_EPOCH`
3. verifies byte identity
4. creates and verifies the release evidence bundle
5. uploads the bundle only as a GitHub Actions artifact

The job has only `contents: read` permission. It does not use a registry token, trusted publisher, package index, GitHub release write permission, or automatic tag creation.

Publication remains a separate human-reviewed operation.
