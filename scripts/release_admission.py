#!/usr/bin/env python3
"""Validate release-admission policies and evaluate verified release bundles."""
from __future__ import annotations

try:
    from scripts.release_admission_core import main
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from release_admission_core import main


if __name__ == "__main__":
    raise SystemExit(main())
