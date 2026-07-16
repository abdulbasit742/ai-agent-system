# Changed-area security audit: baseline gating

## Trust boundary

Baseline JSON is untrusted repository input. It is parsed with the standard library and validated against an exact version 1 schema before it can influence exit status or report filtering.

## Safety controls

- only exact 64-character lowercase hexadecimal fingerprints are accepted
- rule IDs must match `BAS###`
- severities and positive line numbers are validated
- duplicate fingerprints are rejected
- findings must be sorted deterministically
- backslash paths and unknown fields are rejected
- a content hash detects accidental or manual edits
- a controls hash binds the baseline to rule-pack and suppression configuration
- baseline records omit finding previews, matched evidence, fixes, and source contents
- missing, malformed, stale, or scope-mismatched baselines fail closed with exit code `2`

## Write behavior

`baseline --create` is the only new write path. It refuses to overwrite an existing baseline unless `--force` is explicitly supplied. Parent directories are created only for the user-selected output path.

## Exit behavior

Normal scans are unchanged. In `--new-only` mode, severity threshold evaluation uses only new findings. Expired suppressions still fail the scan. SARIF intentionally emits only new findings.

## Residual risks

`baseline_sha256` is an integrity checksum, not an authenticated signature. Anyone able to modify code and baseline files can regenerate it. Repository review and branch protection remain required. Exact line-sensitive fingerprints can also create churn after harmless file movement; this is accepted in favor of avoiding broad suppression.
