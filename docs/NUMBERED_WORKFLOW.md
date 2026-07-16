# Ordered development workflow: 1–400

Each user-provided number triggers one autonomous, reviewable repository improvement.

## Rules

1. Read the current `main` state before selecting work.
2. Choose the highest-value improvement that fits the existing architecture.
3. Preserve all working features and repository safety boundaries.
4. Implement one coherent vertical slice rather than disconnected files.
5. Add or update regression tests and documentation.
6. Run unit tests, compilation, configuration validation, policy validation, self-scan, and command-guard checks.
7. Commit only after verification succeeds.
8. Update `development-progress.json` with the completed number, outcome, files, and verification evidence.
9. Continue sequentially; do not skip or silently redo a number.

## Current state

Task 1 introduced configurable scanner rule packs with a mandatory, non-disableable core security baseline.
