# Suppression policy

The scanner automatically loads `.agent-system-policy.json` from the scanned directory, or accepts an explicit file through `--policy`.

## Schema

```json
{
  "version": 1,
  "suppressions": [
    {
      "id": "reviewed-test-fixture",
      "rule_id": "BAS003",
      "path": "tests/fixtures/**",
      "fingerprint": "optional 64-character finding fingerprint",
      "owner": "security-team",
      "reason": "Synthetic token used only by an isolated scanner fixture.",
      "expires": "2099-12-31"
    }
  ]
}
```

`id`, `owner`, `reason`, and `expires` are mandatory. `rule_id` defaults to `*`, and `path` defaults to `**`. A fingerprint narrows the exception to one exact finding.

## Security behavior

- Invalid JSON or schema returns exit code `2`.
- Expired entries never suppress findings.
- Any expired entry makes `policy` and `scan` return nonzero until reviewed.
- Suppressed findings are excluded from the failure threshold but counted in all report formats.
- `--show-suppressed` exposes reviewed findings and their ownership metadata.
- Scan audit records include active, suppressed, policy source, and expired-suppression counts.

## Workflow

1. Fix the finding when practical.
2. When accepting a temporary risk, create the narrowest possible suppression.
3. Prefer an exact fingerprint for a single known finding.
4. Assign a real owner and short expiration date.
5. Review or remove the exception before it expires.

The initializer refuses to overwrite an existing file unless `--force` is explicitly supplied.
