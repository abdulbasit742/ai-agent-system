#!/usr/bin/env python3
"""Validate the exact dependency-free public wheel boundary."""
from __future__ import annotations

import argparse
import json
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
    "agent_audit.py", "agent_audit_admission.py", "agent_audit_bundle.py",
    "agent_audit_catalog.py", "agent_audit_checkpoint.py", "agent_audit_consistency.py",
    "agent_audit_events.py", "agent_audit_segments.py", "agent_audit_trust.py",
    "agent_audit_trust_checkpoint.py", "agent_audit_trust_consistency.py",
    "agent_audit_trust_bundle.py", "agent_audit_trust_bundle_core.py",
    "agent_audit_trust_admission.py", "agent_audit_trust_receiver.py",
    "agent_audit_trust_receiver_checkpoint.py", "agent_audit_trust_receiver_consistency.py",
    "agent_audit_trust_receiver_bundle.py",
    "agent_baseline.py", "agent_changed_lines.py", "agent_cli.py", "agent_config.py",
    "agent_git.py", "agent_policy.py", "agent_system.py", "agent_system_legacy.py",
    "agent_version.py",
}
EXPECTED_SCRIPTS = {
    "agent-audit-admission": "agent_audit_admission:main",
    "agent-audit-bundle": "agent_audit_bundle:main",
    "agent-audit-catalog": "agent_audit_catalog:main",
    "agent-audit-catalog-checkpoint": "agent_audit_checkpoint:main",
    "agent-audit-catalog-consistency": "agent_audit_consistency:main",
    "agent-audit-segments": "agent_audit_segments:main",
    "agent-audit-trust": "agent_audit_trust:main",
    "agent-audit-trust-checkpoint": "agent_audit_trust_checkpoint:main",
    "agent-audit-trust-consistency": "agent_audit_trust_consistency:main",
    "agent-audit-trust-bundle": "agent_audit_trust_bundle:main",
    "agent-audit-trust-admission": "agent_audit_trust_admission:main",
    "agent-audit-trust-receiver": "agent_audit_trust_receiver:main",
    "agent-audit-trust-receiver-checkpoint": "agent_audit_trust_receiver_checkpoint:main",
    "agent-audit-trust-receiver-consistency": "agent_audit_trust_receiver_consistency:main",
    "agent-audit-trust-receiver-bundle": "agent_audit_trust_receiver_bundle:main",
    "agent-changed-lines": "agent_cli:changed_lines_main",
    "agent-system": "agent_cli:main",
    "basit-agent": "agent_cli:main",
    "basit-agent-audit-admission": "agent_audit_admission:main",
    "basit-agent-audit-bundle": "agent_audit_bundle:main",
    "basit-agent-audit-trust": "agent_audit_trust:main",
    "basit-agent-audit-trust-checkpoint": "agent_audit_trust_checkpoint:main",
    "basit-agent-audit-trust-consistency": "agent_audit_trust_consistency:main",
    "basit-agent-audit-trust-bundle": "agent_audit_trust_bundle:main",
    "basit-agent-audit-trust-admission": "agent_audit_trust_admission:main",
    "basit-agent-audit-trust-receiver": "agent_audit_trust_receiver:main",
    "basit-agent-audit-trust-receiver-checkpoint": "agent_audit_trust_receiver_checkpoint:main",
    "basit-agent-audit-trust-receiver-consistency": "agent_audit_trust_receiver_consistency:main",
    "basit-agent-audit-trust-receiver-bundle": "agent_audit_trust_receiver_bundle:main",
    "basit-agent-catalog": "agent_audit_catalog:main",
    "basit-agent-catalog-checkpoint": "agent_audit_checkpoint:main",
    "basit-agent-catalog-consistency": "agent_audit_consistency:main",
    "basit-agent-lines": "agent_cli:changed_lines_main",
    "basit-agent-segments": "agent_audit_segments:main",
}
FORBIDDEN_FRAGMENTS = {
    ".env", ".agent-system", "audit.jsonl", "baseline.json", "action.yml",
    "development-progress", "integrations.lock",
}


class WheelValidationError(ValueError):
    pass


def _entry_points(text: str) -> dict[str, str]:
    section = None
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif section == "console_scripts":
            if "=" not in line:
                raise WheelValidationError("malformed console_scripts entry")
            name, target = (part.strip() for part in line.split("=", 1))
            result[name] = target
    return result


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
            raise WheelValidationError(
                f"wheel module boundary mismatch; missing={sorted(EXPECTED_MODULES-root_python)}, "
                f"unexpected={sorted(root_python-EXPECTED_MODULES)}"
            )
        forbidden = sorted(
            name for name in names
            if any(fragment in name.lower() for fragment in FORBIDDEN_FRAGMENTS)
        )
        if forbidden:
            raise WheelValidationError(f"wheel contains forbidden files: {forbidden}")
        unexpected = sorted(
            name for name in names if name.endswith(".py") and name not in EXPECTED_MODULES
        )
        if unexpected:
            raise WheelValidationError(f"wheel contains unexpected Python source: {unexpected}")
        dist_infos = {
            name.split("/", 1)[0] for name in names
            if ".dist-info/" in name and "/" in name
        }
        if len(dist_infos) != 1:
            raise WheelValidationError("wheel must contain exactly one .dist-info directory")
        dist_info = next(iter(dist_infos))
        required = {
            f"{dist_info}/METADATA", f"{dist_info}/WHEEL", f"{dist_info}/RECORD",
            f"{dist_info}/entry_points.txt",
        }
        if required - names:
            raise WheelValidationError("wheel metadata is incomplete")
        metadata = Parser().parsestr(archive.read(f"{dist_info}/METADATA").decode())
        if metadata.get("Name", "").lower().replace("_", "-") != EXPECTED_NAME:
            raise WheelValidationError("wheel project name does not match the reviewed name")
        if metadata.get("Version") != EXPECTED_VERSION:
            raise WheelValidationError("wheel version does not match agent_version.py")
        if metadata.get("Requires-Python") != ">=3.11":
            raise WheelValidationError("wheel Requires-Python must be >=3.11")
        if metadata.get_all("Requires-Dist"):
            raise WheelValidationError("wheel must not declare runtime dependencies")
        scripts = _entry_points(archive.read(f"{dist_info}/entry_points.txt").decode())
        if scripts != EXPECTED_SCRIPTS:
            raise WheelValidationError("console script boundary mismatch")
        for line in archive.read(f"{dist_info}/RECORD").decode().splitlines():
            fields = line.split(",")
            if len(fields) >= 2 and fields[1].startswith("sha256=") and fields[1] == "sha256=":
                raise WheelValidationError("wheel RECORD contains an empty digest")
    return {
        "wheel": str(path), "project": EXPECTED_NAME, "version": EXPECTED_VERSION,
        "modules": len(EXPECTED_MODULES), "console_scripts": sorted(EXPECTED_SCRIPTS),
        "runtime_dependencies": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", nargs="+", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps({"validated": [validate_wheel(path) for path in args.wheels]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
