#!/usr/bin/env python3
"""Validate the public Basit Agent System wheel boundary without installing it."""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import Any

try:
    from agent_version import __version__
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from agent_version import __version__

EXPECTED_NAME = "basit-agent-system"
EXPECTED_VERSION = __version__
EXPECTED_MODULES = {
    "agent_audit.py",
    "agent_audit_catalog.py",
    "agent_audit_events.py",
    "agent_audit_segments.py",
    "agent_baseline.py",
    "agent_changed_lines.py",
    "agent_cli.py",
    "agent_config.py",
    "agent_git.py",
    "agent_policy.py",
    "agent_system.py",
    "agent_system_legacy.py",
    "agent_version.py",
}
EXPECTED_SCRIPTS = {
    "agent-audit-catalog": "agent_audit_catalog:main",
    "agent-audit-segments": "agent_audit_segments:main",
    "agent-changed-lines": "agent_cli:changed_lines_main",
    "agent-system": "agent_cli:main",
    "basit-agent": "agent_cli:main",
    "basit-agent-catalog": "agent_audit_catalog:main",
    "basit-agent-lines": "agent_cli:changed_lines_main",
    "basit-agent-segments": "agent_audit_segments:main",
}
FORBIDDEN_FRAGMENTS = {
    ".env",
    ".agent-system",
    "audit.jsonl",
    "baseline.json",
    "action.yml",
    "development-progress",
    "integrations.lock",
}
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class WheelValidationError(ValueError):
    """Raised when a wheel violates the reviewed distribution boundary."""


def _dist_info(names: set[str]) -> str:
    directories = {
        name.split("/", 1)[0]
        for name in names
        if ".dist-info/" in name and "/" in name
    }
    if len(directories) != 1:
        raise WheelValidationError("wheel must contain exactly one .dist-info directory")
    return next(iter(directories))


def _entry_points(text: str) -> dict[str, str]:
    section = None
    scripts: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == "console_scripts":
            if "=" not in line:
                raise WheelValidationError("malformed console_scripts entry")
            name, target = (part.strip() for part in line.split("=", 1))
            scripts[name] = target
    return scripts


def validate_wheel(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.suffix != ".whl":
        raise WheelValidationError(f"not a wheel file: {path}")
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise WheelValidationError(f"invalid wheel archive: {path}") from exc

    with archive:
        names = set(archive.namelist())
        if any(name.startswith("/") or ".." in Path(name).parts for name in names):
            raise WheelValidationError("wheel contains an unsafe archive path")
        root_python = {name for name in names if "/" not in name and name.endswith(".py")}
        if root_python != EXPECTED_MODULES:
            missing = sorted(EXPECTED_MODULES - root_python)
            unexpected = sorted(root_python - EXPECTED_MODULES)
            raise WheelValidationError(
                f"wheel module boundary mismatch; missing={missing}, unexpected={unexpected}"
            )
        forbidden = sorted(
            name for name in names
            if any(fragment in name.lower() for fragment in FORBIDDEN_FRAGMENTS)
        )
        if forbidden:
            raise WheelValidationError(f"wheel contains forbidden files: {forbidden}")
        unexpected_source = sorted(
            name for name in names
            if name.endswith(".py") and name not in EXPECTED_MODULES
        )
        if unexpected_source:
            raise WheelValidationError(f"wheel contains unexpected Python source: {unexpected_source}")

        dist_info = _dist_info(names)
        required = {
            f"{dist_info}/METADATA",
            f"{dist_info}/WHEEL",
            f"{dist_info}/RECORD",
            f"{dist_info}/entry_points.txt",
        }
        missing_metadata = sorted(required - names)
        if missing_metadata:
            raise WheelValidationError(f"wheel metadata is incomplete: {missing_metadata}")

        metadata = Parser().parsestr(archive.read(f"{dist_info}/METADATA").decode("utf-8"))
        if metadata.get("Name", "").lower().replace("_", "-") != EXPECTED_NAME:
            raise WheelValidationError("wheel project name does not match the reviewed name")
        if metadata.get("Version") != EXPECTED_VERSION:
            raise WheelValidationError("wheel version does not match agent_version.py")
        if metadata.get("Requires-Python") != ">=3.11":
            raise WheelValidationError("wheel Requires-Python must be >=3.11")
        if metadata.get_all("Requires-Dist"):
            raise WheelValidationError("wheel must not declare runtime dependencies")

        scripts = _entry_points(
            archive.read(f"{dist_info}/entry_points.txt").decode("utf-8")
        )
        if scripts != EXPECTED_SCRIPTS:
            raise WheelValidationError(
                f"console script boundary mismatch; expected={EXPECTED_SCRIPTS}, actual={scripts}"
            )

        record = archive.read(f"{dist_info}/RECORD").decode("utf-8")
        for line in record.splitlines():
            fields = line.split(",")
            if len(fields) >= 2 and fields[1].startswith("sha256="):
                digest = fields[1].removeprefix("sha256=")
                if not digest:
                    raise WheelValidationError("wheel RECORD contains an empty digest")

    return {
        "wheel": str(path),
        "project": EXPECTED_NAME,
        "version": EXPECTED_VERSION,
        "modules": len(EXPECTED_MODULES),
        "console_scripts": sorted(EXPECTED_SCRIPTS),
        "runtime_dependencies": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", nargs="+", type=Path)
    args = parser.parse_args(argv)
    summaries = [validate_wheel(path) for path in args.wheels]
    print(json.dumps({"validated": summaries}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
