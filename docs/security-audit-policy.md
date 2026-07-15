# Changed-area security audit

## Trust boundary

Policy JSON is untrusted local input. It is parsed with the standard library, requires an exact schema version, validates types and lengths, normalizes paths, and never executes code.

## Suppression safety

- expired entries do not match
- duplicate IDs are rejected
- fingerprints require exactly 64 lowercase hexadecimal characters
- wildcard matching is limited to finding rule IDs and normalized repository paths
- suppressed finding previews remain masked by the scanner
- report output includes only policy ownership metadata, not arbitrary policy fields

## Side effects

`policy --init` is the only new write path. It refuses to overwrite an existing file unless `--force` is present. Scan output creates parent directories only when the user explicitly supplies `--output`, matching existing behavior.

## Residual risks

Path globs can still be broader than intended. Reviewers should prefer exact rule IDs, narrow fixture directories, and fingerprints. A future release may add organization-level maximum expiry durations and signed policies.
