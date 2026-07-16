"""Installed console entry points for Basit Agent System."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence

import agent_changed_lines
import agent_system
from agent_version import __version__

VERSION_TEXT = f"basit-agent-system {__version__}"
SOURCE_ONLY_COMMANDS = {"doctor", "run"}


def _arguments(argv: Sequence[str] | None) -> list[str]:
    return list(sys.argv[1:] if argv is None else argv)


def _source_checkout_available() -> bool:
    root = Path(agent_system.__file__).resolve().parent
    return (root / "integrations.lock.json").is_file()


def _reject_source_only_command(arguments: list[str]) -> int | None:
    if arguments and arguments[0] in SOURCE_ONLY_COMMANDS and not _source_checkout_available():
        print(
            f"{arguments[0]} requires a source checkout with integrations.lock.json; "
            "the installed wheel intentionally does not vendor external repositories.",
            file=sys.stderr,
        )
        return 2
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """Run the full control-plane CLI from an installed console script."""
    arguments = _arguments(argv)
    if arguments in (["--version"], ["version"]):
        print(VERSION_TEXT)
        return 0
    rejected = _reject_source_only_command(arguments)
    if rejected is not None:
        return rejected
    return agent_system.main(arguments)


def changed_lines_main(argv: Sequence[str] | None = None) -> int:
    """Run the added-line-only gate from an installed console script."""
    arguments = _arguments(argv)
    if arguments in (["--version"], ["version"]):
        print(VERSION_TEXT)
        return 0
    return agent_changed_lines.main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
