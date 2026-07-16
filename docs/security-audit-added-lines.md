# Security audit: added-line gate

## Scope

This review covers `agent_changed_lines.py` and the line-range additions in `agent_git.py`.

## Findings

### Ref and command safety

The feature reuses validated Git references, resolves them to commit SHAs, calculates a merge base, and invokes only read-only Git commands through argument arrays. No shell is used.

### Patch parsing

Zero-context patch output is handled as bytes. Only anchored hunk headers are parsed; source lines, secrets, and arbitrary file contents are not decoded or persisted by the line-scope engine.

### Path containment

File discovery remains based on NUL-delimited name-status records. Every path is rejected if it is absolute, contains parent traversal, or resolves outside the repository through a symlink.

### Baseline correctness

Current findings are filtered against new-side line ranges. Baseline findings are independently filtered against old-side ranges. Deleted files use full old-file resolution scope, while pure renames use no line scope. This prevents unrelated baseline entries from being marked resolved.

### Fail-closed behavior

Invalid refs, unavailable Git, missing merge-base history, malformed paths, non-regular changed targets, configuration errors, policy errors, and baseline integrity mismatches exit with configuration status `2`.

## Data handling

Reports may contain the same masked previews already emitted by the root scanner. Added-line scope metadata contains paths, statuses, commit SHAs, and numeric line ranges. Patch bodies and raw matched evidence are not written to the audit log.

## Residual limitations

- A finding is assigned to the line where its regex match starts.
- Added and copied files are intentionally treated as full-file additions.
- A pure rename is silent in added-line mode; changed-file mode remains available when path movement itself requires review.
- The baseline integrity hash is not a signature and still depends on repository review controls.

## Result

No shell-injection path, repository-escape path, broad baseline-resolution path, or raw-patch persistence was identified in the implemented design.
