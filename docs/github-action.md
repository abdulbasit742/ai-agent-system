# First-party GitHub Action

The repository root contains a composite `action.yml` that runs Basit Agent System directly in another repository. It supports full-repository, changed-file, and added-line-only security gates.

## Pull-request workflow

```yaml
name: agent-security
on:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - name: Scan added lines
        id: basit
        uses: abdulbasit742/ai-agent-system@<reviewed-commit-sha>
        with:
          mode: added-lines
          fail-on: high
          annotations: true

      - name: Preserve reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: basit-agent-system
          path: |
            .agent-system/action-report.json
            .agent-system/action-results.sarif
```

Replace `<reviewed-commit-sha>` with a reviewed release or commit. Full history is required for merge-base modes, so the checkout uses `fetch-depth: 0`.

## Modes

| Mode | Behavior |
| --- | --- |
| `full` | Scans every supported file under `path`. No Git base is required. |
| `changed-files` | Scans complete current files changed from the merge base. |
| `added-lines` | Reports only findings beginning on added or replaced lines. This is the default. |

For pull-request events, changed modes default to the exact base and head commit SHAs from the event payload. Explicit `base-ref` and `head-ref` inputs override those values. Changed modes fail closed when no base ref is available.

## Baseline mode

```yaml
      - uses: abdulbasit742/ai-agent-system@<reviewed-commit-sha>
        with:
          mode: added-lines
          new-only: true
          baseline: .agent-system-baseline.json
          fail-on: high
```

The baseline remains integrity-checked and bound to the active rule-pack and suppression controls.

## Inputs

- `mode`: `full`, `changed-files`, or `added-lines`
- `path`: repository-relative directory to scan
- `fail-on`: `low`, `medium`, `high`, or `critical`
- `base-ref`, `head-ref`: optional explicit Git refs or commit SHAs
- `new-only`: enable exact-fingerprint baseline classification
- `baseline`, `config`, `policy`: optional repository-relative control files
- `annotations`: emit workflow annotations without matched source previews
- `max-annotations`: integer from 0 to 50
- `report-path`, `sarif-path`: distinct output files beneath `.agent-system/`
- `python-version`: Python selected through `actions/setup-python`

Scan and control paths are resolved beneath `GITHUB_WORKSPACE`. Generated JSON and SARIF paths are more restrictive: they must remain beneath `.agent-system/`, must be different files, and may not escape that directory through symlinks. Absolute paths, parent traversal, control characters, and missing control files are rejected.

## Outputs

- `status`: `passed`, `findings`, or `error`
- `finding-count`, `suppressed-count`
- `new-count`, `existing-count`, `resolved-count`
- `report-path`, `sarif-path`

The action also writes a GitHub job summary. Annotations and summaries include rule IDs, locations, severity, and remediation, but never include scanner preview evidence.

## Fork-safe default

The action does not require a GitHub token and does not modify repository content. A pull-request workflow can run with only `contents: read`. Do not switch the workflow to `pull_request_target` for untrusted code.

Uploading SARIF to GitHub code scanning is an optional caller decision because that requires additional repository permissions. Artifact upload works with the read-only workflow shown above.

## Failure behavior

- exit `0`: no finding meets `fail-on`
- exit `1`: one or more reported findings meet `fail-on`
- exit `2`: invalid input, unavailable Git history, malformed controls, unsafe path, output collision, or scanner execution/report error

Before each run, stale JSON and SARIF outputs are removed from the generated-output directory. A scanner error cannot be masked by an old successful report, and cleanup cannot target ordinary repository files.
