# Task 3 design: Git-aware changed-file gates

This temporary design record captures the implementation constraints for task 3.

- resolve user refs to commit SHAs before diffing
- compute a merge-base diff without shell execution
- parse NUL-delimited Git output for unusual file names
- reject paths that are absolute, escape the worktree, or resolve through symlinks outside it
- scan current added/modified/renamed targets; retain deleted and old rename paths only for baseline resolution
- bind new-only baseline classification to the changed-path scope so unrelated findings are never marked resolved
- fail closed when Git, refs, merge-base history, or repository discovery is unavailable
