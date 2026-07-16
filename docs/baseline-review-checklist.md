# Baseline review checklist

Use this checklist whenever `.agent-system-baseline.json` changes in a pull request.

- Confirm the baseline was generated from the intended scan root.
- Review the full non-baseline scan before accepting legacy findings.
- Confirm no new suppression was added only to reduce baseline size.
- Verify `controls_sha256` changed only when rule-pack or suppression controls changed.
- Confirm resolved findings were removed by code changes, not hidden by configuration.
- Ensure baseline entries contain fingerprints and locations only, never evidence or secrets.
- Require CI to pass both normal self-scan and `--new-only` baseline mode.
- Treat unexpected large baseline growth as a security regression requiring investigation.
