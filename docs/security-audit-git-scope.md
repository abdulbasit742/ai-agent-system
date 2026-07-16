# Changed-area security audit: Git scope

## Trust boundary

Git references and repository path data are untrusted inputs. The implementation never invokes a shell. References are length-limited, reject leading option markers and whitespace/control characters, and are resolved to full commit SHAs before they are passed to diff operations.

## Path safety

- Git output is parsed as NUL-delimited records rather than line-delimited text.
- Absolute paths and parent traversal are rejected.
- Every path is resolved against the discovered worktree root.
- Symlink resolution outside the repository fails closed.
- Non-UTF-8 path data is rejected rather than normalized ambiguously.
- Changed-file mode requires an existing directory scan root inside the discovered repository.

## History safety

The diff uses the resolved merge base and head commit. Missing refs, absent shallow-clone history, unrelated histories, or an unavailable Git executable return configuration status `2`.

## Baseline interaction

Only baseline entries whose paths are part of the changed scope participate in classification. Deleted paths and old rename paths are included, preventing unrelated baseline entries from appearing resolved.

## Side effects

Git commands are read-only: `rev-parse`, `merge-base`, and `diff`. No fetch, checkout, reset, clean, index mutation, or working-tree write occurs.

## Residual risks

A repository can contain an extremely large number of changed paths. Reports therefore may be large because JSON includes per-file status evidence. A future task may introduce an explicit report-detail cap while preserving the full audit digest.
