#!/usr/bin/env python3
"""Fail-closed output boundary for the GitHub composite action."""
from __future__ import annotations

import os
import sys
from pathlib import Path, PurePosixPath
from typing import Mapping

try:
    from scripts import github_action
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    import github_action  # type: ignore


class OutputBoundaryError(ValueError):
    """Raised when generated action output could overwrite repository content."""


def _text(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name, default)
    if any(character in value for character in ("\0", "\r", "\n")):
        raise OutputBoundaryError(f"{name} contains control characters")
    return value.strip()


def _generated_path(workspace: Path, raw: str, label: str) -> Path:
    logical = PurePosixPath(raw.replace("\\", "/"))
    if not raw or logical.is_absolute() or ".." in logical.parts:
        raise OutputBoundaryError(f"{label} must be inside .agent-system/")
    target = workspace.joinpath(*logical.parts).resolve(strict=False)
    generated_root = (workspace / ".agent-system").resolve(strict=False)
    try:
        target.relative_to(generated_root)
    except ValueError as exc:
        raise OutputBoundaryError(f"{label} must be inside .agent-system/") from exc
    if target == generated_root:
        raise OutputBoundaryError(f"{label} must name a file inside .agent-system/")
    return target


def validate_output_paths(env: Mapping[str, str] | None = None) -> tuple[Path, Path]:
    source = os.environ if env is None else env
    workspace_raw = _text(source, "GITHUB_WORKSPACE", "")
    if not workspace_raw:
        raise OutputBoundaryError("GITHUB_WORKSPACE is required")
    workspace = Path(workspace_raw).resolve()
    if not workspace.is_dir():
        raise OutputBoundaryError("GITHUB_WORKSPACE must be an existing directory")
    report = _generated_path(
        workspace,
        _text(source, "BASIT_REPORT_PATH", ".agent-system/action-report.json"),
        "report-path",
    )
    sarif = _generated_path(
        workspace,
        _text(source, "BASIT_SARIF_PATH", ".agent-system/action-results.sarif"),
        "sarif-path",
    )
    if report == sarif:
        raise OutputBoundaryError("report-path and sarif-path must be different files")
    return report, sarif


def main() -> int:
    try:
        validate_output_paths()
    except OutputBoundaryError as exc:
        print(f"Action input error: {exc}", file=sys.stderr)
        return 2
    return github_action.main()


if __name__ == "__main__":
    raise SystemExit(main())
