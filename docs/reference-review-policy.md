# Policy feature reference review

Reviewed on 2026-07-15.

## Semgrep

Repository: `semgrep/semgrep`

Relevant patterns: configurable rules, stable finding identities, baseline-aware scans, and regression coverage around changed findings. Adopted here as deterministic fingerprints and policy-aware reporting without adding a parser or external dependency.

## Gitleaks

Repository: `gitleaks/gitleaks`

Relevant patterns: repository-local configuration, baseline reports, allowlists, redacted output, and multiple report formats. Adopted here as auto-discovered policy files, exact fingerprint matching, and suppressed-finding summaries.

## Trivy

Repository: `aquasecurity/trivy`

Relevant patterns: structured ignore files, visible suppressed results, statements explaining accepted risk, and expiration metadata. Adopted here as mandatory reason, owner, expiry, `--show-suppressed`, and fail-closed expired entries.

## Deliberate limits

- No inline source comments are accepted as suppressions.
- No suppression can omit ownership, justification, or expiration.
- Policies cannot add executable rules or commands.
- External policy URLs are not fetched; only local reviewed JSON is accepted.
