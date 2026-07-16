# Added-line-only security gating

The added-line gate reduces pull-request noise further than changed-file mode. It scans changed files with the normal rule engine, then reports only findings whose starting line belongs to an added or replaced line range in the merge-base diff.

## Basic usage

```bash
python agent_changed_lines.py . \
  --changed-from origin/main \
  --format json \
  --fail-on high
```

The target defaults to `HEAD`. Use `--changed-to` when a different reviewed target commit is required.

## Baseline mode

```bash
python agent_changed_lines.py . \
  --changed-from origin/main \
  --new-only \
  --show-existing \
  --format sarif \
  --output agent-system.sarif
```

The gate reuses the standard versioned configuration, reviewed suppression policy, exact-fingerprint baseline, SARIF output, severity threshold, and hash-chained audit log.

## Line semantics

- a finding is in scope when its start line is inside an added or replacement range on the new side of a zero-context diff
- an added file and a copied target are scanned as full new files
- a deleted file places all of its old baseline findings in resolution scope
- a modified file places only removed or replaced old lines in baseline resolution scope
- a pure rename has no added-line or removed-line scope, so it creates neither a new finding nor a resolved finding
- inserting safe lines before a legacy finding does not reclassify that finding merely because its absolute line number moved

This behavior is intentionally stricter than changed-file mode. Use `agent_system.py scan --changed-from ...` when the entire changed file should be reviewed.

## Why old and new ranges are both required

New ranges determine which current findings may be reported. Old ranges independently determine which exact baseline entries may become resolved. Keeping the two coordinate systems separate prevents an insertion near a legacy issue from falsely resolving the old fingerprint.

## Git safety model

The gate inherits the Git scope protections from `agent_git.py`:

- user references are resolved to commit SHAs before diffing
- merge-base semantics isolate the pull-request branch
- Git commands use argument arrays and never invoke a shell
- changed paths are NUL-delimited and repository-bound
- added-line hunks are parsed from binary zero-context patch output, so source content does not need to decode as UTF-8
- missing history, invalid references, malformed paths, or symlink escapes fail closed with exit status `2`

## Reports and audit records

Text, JSON, and SARIF output include:

- resolved base, head, and merge-base SHAs
- changed, current, deleted, and renamed file counts
- line-scoped file count
- added and removed range counts
- full new-file scan count
- full deleted-file baseline resolution count

The audit event is named `scan-added-lines` and stores only compact scope metadata and finding counts. Patch text and matched source evidence are not written to the audit log.

## Matching boundary

Rules are filtered by the line on which the regex match starts. The current rule set is predominantly line-local, making this predictable. A future multi-line rule whose dangerous portion begins before an added range may require an explicit rule-level line policy rather than silently widening every diff hunk.
