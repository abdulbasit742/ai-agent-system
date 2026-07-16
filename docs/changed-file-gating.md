# Git-aware changed-file security gates

Changed-file mode limits scanner inspection and reporting to files changed between a merge base and a target commit. It is designed for pull requests and large repositories where a full scan already runs separately.

## Basic usage

```bash
python agent_system.py scan . \
  --changed-from origin/main \
  --format json \
  --fail-on high
```

The target defaults to `HEAD`. An explicit target can be supplied:

```bash
python agent_system.py scan . \
  --changed-from origin/main \
  --changed-to feature-commit
```

## Merge-base semantics

The system resolves both references to commit SHAs, calculates their merge base, and scans the equivalent of:

```text
merge-base(base, head) .. head
```

This prevents unrelated changes on the base branch from becoming part of the pull-request scope.

## File handling

- added, modified, copied, renamed, type-changed, and other current regular-file targets are eligible for scanning
- deleted files are not read, but remain in baseline scope so their previous findings can be reported as resolved
- renamed files place both the old and new paths in baseline scope
- copies place only the new target in baseline scope because the original remains present
- subdirectory scan paths include only changes inside that directory
- NUL-delimited Git output supports spaces, tabs, and newlines in valid UTF-8 filenames

The scanner still applies its normal supported-file rules, size limit, configured rule packs, and suppression policy.

## Combining with a baseline

```bash
python agent_system.py scan . \
  --changed-from origin/main \
  --new-only \
  --show-existing \
  --format json
```

Baseline classification is restricted to changed current paths, deleted paths, and old rename paths. Findings in unrelated files are never incorrectly marked resolved.

An exact-fingerprint finding moved by a rename is conservative by design: the new path is reported as `new`, and the old path is reported as `resolved`.

## Fail-closed behavior

Changed-file mode exits with configuration status `2` when:

- Git is unavailable
- the scan path is not an existing directory inside a Git worktree
- a reference cannot be resolved to a commit
- required shallow-clone history is missing
- no merge base exists
- Git returns malformed or non-UTF-8 path data
- a changed path is absolute, contains parent traversal, or resolves outside the repository through a symlink
- `--changed-to` is supplied without `--changed-from`

For GitHub Actions, fetch enough history for the base and head commits before using a remote base reference.

## Report and audit evidence

Text, JSON, and SARIF summaries include the original references, resolved commit SHAs, merge-base SHA, and changed/current/deleted/renamed counts. JSON reports also include per-file status metadata. Hash-chained audit records store the compact scope summary.
