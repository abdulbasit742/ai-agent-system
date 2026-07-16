#!/usr/bin/env python3
"""Canonical reviewed public package and command surface."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

SURFACE_VERSION = 1
PROJECT_NAME = "basit-agent-system"
PYTHON_REQUIRES = ">=3.11"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")

MODULES = (
    "agent_audit", "agent_audit_admission", "agent_audit_bundle",
    "agent_audit_catalog", "agent_audit_checkpoint", "agent_audit_consistency",
    "agent_audit_events", "agent_audit_segments", "agent_audit_trust",
    "agent_audit_trust_admission", "agent_audit_trust_bundle",
    "agent_audit_trust_bundle_core", "agent_audit_trust_checkpoint",
    "agent_audit_trust_consistency", "agent_audit_trust_receiver",
    "agent_audit_trust_receiver_checkpoint", "agent_audit_trust_receiver_consistency",
    "agent_baseline", "agent_changed_lines", "agent_cli", "agent_config",
    "agent_git", "agent_policy", "agent_public_surface", "agent_system",
    "agent_system_legacy", "agent_version",
)

SCRIPTS = {
    "agent-audit-admission": "agent_audit_admission:main",
    "agent-audit-bundle": "agent_audit_bundle:main",
    "agent-audit-catalog": "agent_audit_catalog:main",
    "agent-audit-catalog-checkpoint": "agent_audit_checkpoint:main",
    "agent-audit-catalog-consistency": "agent_audit_consistency:main",
    "agent-audit-segments": "agent_audit_segments:main",
    "agent-audit-trust": "agent_audit_trust:main",
    "agent-audit-trust-admission": "agent_audit_trust_admission:main",
    "agent-audit-trust-bundle": "agent_audit_trust_bundle:main",
    "agent-audit-trust-checkpoint": "agent_audit_trust_checkpoint:main",
    "agent-audit-trust-consistency": "agent_audit_trust_consistency:main",
    "agent-audit-trust-receiver": "agent_audit_trust_receiver:main",
    "agent-audit-trust-receiver-checkpoint": "agent_audit_trust_receiver_checkpoint:main",
    "agent-audit-trust-receiver-consistency": "agent_audit_trust_receiver_consistency:main",
    "agent-changed-lines": "agent_cli:changed_lines_main",
    "agent-public-surface": "agent_public_surface:main",
    "agent-system": "agent_cli:main",
    "basit-agent": "agent_cli:main",
    "basit-agent-audit-admission": "agent_audit_admission:main",
    "basit-agent-audit-bundle": "agent_audit_bundle:main",
    "basit-agent-audit-trust": "agent_audit_trust:main",
    "basit-agent-audit-trust-admission": "agent_audit_trust_admission:main",
    "basit-agent-audit-trust-bundle": "agent_audit_trust_bundle:main",
    "basit-agent-audit-trust-checkpoint": "agent_audit_trust_checkpoint:main",
    "basit-agent-audit-trust-consistency": "agent_audit_trust_consistency:main",
    "basit-agent-audit-trust-receiver": "agent_audit_trust_receiver:main",
    "basit-agent-audit-trust-receiver-checkpoint": "agent_audit_trust_receiver_checkpoint:main",
    "basit-agent-audit-trust-receiver-consistency": "agent_audit_trust_receiver_consistency:main",
    "basit-agent-catalog": "agent_audit_catalog:main",
    "basit-agent-catalog-checkpoint": "agent_audit_checkpoint:main",
    "basit-agent-catalog-consistency": "agent_audit_consistency:main",
    "basit-agent-lines": "agent_cli:changed_lines_main",
    "basit-agent-public-surface": "agent_public_surface:main",
    "basit-agent-segments": "agent_audit_segments:main",
}


class PublicSurfaceError(ValueError):
    def __init__(self, message: str, *, rule_id: str = "APS002") -> None:
        super().__init__(message)
        self.rule_id = rule_id


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def manifest() -> dict[str, Any]:
    core = {
        "surface_version": SURFACE_VERSION,
        "project": PROJECT_NAME,
        "requires_python": PYTHON_REQUIRES,
        "runtime_dependencies": 0,
        "modules": list(MODULES),
        "scripts": dict(sorted(SCRIPTS.items())),
    }
    return {
        **core,
        "surface_id": hashlib.sha256(b"agent-public-surface-v1\x00" + canonical_json(core)).hexdigest(),
    }


def validate_manifest(value: Any) -> dict[str, Any]:
    expected = manifest()
    if not isinstance(value, dict) or value != expected:
        raise PublicSurfaceError("public surface manifest differs from the reviewed contract")
    if not HEX_64.fullmatch(value["surface_id"]):
        raise PublicSurfaceError("public surface id is malformed")
    return expected


def _load_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise PublicSurfaceError(f"required file is missing or unsafe: {path}", rule_id="APS001")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicSurfaceError(f"cannot read JSON from {path}: {exc}", rule_id="APS001") from exc


def validate_repository(root: Path) -> dict[str, Any]:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise PublicSurfaceError("repository root must be a regular non-symlink directory", rule_id="APS001")
    pyproject_path = root / "pyproject.toml"
    if pyproject_path.is_symlink() or not pyproject_path.is_file():
        raise PublicSurfaceError("pyproject.toml is missing or unsafe", rule_id="APS001")
    try:
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PublicSurfaceError(f"pyproject.toml is invalid: {exc}", rule_id="APS001") from exc
    project = pyproject.get("project", {})
    setuptools = pyproject.get("tool", {}).get("setuptools", {})
    if project.get("name") != PROJECT_NAME or project.get("requires-python") != PYTHON_REQUIRES:
        raise PublicSurfaceError("project identity or Python requirement drifted", rule_id="APS003")
    if project.get("dependencies") != []:
        raise PublicSurfaceError("runtime dependency boundary drifted", rule_id="APS003")
    if tuple(setuptools.get("py-modules", [])) != MODULES:
        raise PublicSurfaceError("pyproject module boundary drifted", rule_id="APS003")
    if project.get("scripts") != SCRIPTS:
        raise PublicSurfaceError("pyproject console script boundary drifted", rule_id="APS003")
    policy = _load_json(root / ".release-admission.example.json")
    artifacts = policy.get("artifacts", {}) if isinstance(policy, dict) else {}
    if artifacts.get("modules") != [f"{name}.py" for name in MODULES]:
        raise PublicSurfaceError("release admission module allowlist drifted", rule_id="APS004")
    if artifacts.get("console_scripts") != sorted(SCRIPTS):
        raise PublicSurfaceError("release admission command allowlist drifted", rule_id="APS004")
    return {
        "valid": True,
        "surface": manifest(),
        "module_count": len(MODULES),
        "command_count": len(SCRIPTS),
    }


def _emit(payload: dict[str, Any], output_format: str, *, stream: Any = None) -> None:
    stream = stream or sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
    else:
        for key in ("valid", "surface_id", "module_count", "command_count", "rule_id", "error"):
            if key in payload:
                print(f"{key}: {payload[key]}", file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    show = subparsers.add_parser("show")
    show.add_argument("--format", choices=("json", "text"), default="json")
    verify = subparsers.add_parser("validate")
    verify.add_argument("root", nargs="?", type=Path, default=Path("."))
    verify.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        if args.command == "show":
            payload = manifest()
            _emit({"valid": True, **payload, "module_count": len(MODULES), "command_count": len(SCRIPTS)}, args.format)
        else:
            payload = validate_repository(args.root)
            _emit({"valid": True, "surface_id": payload["surface"]["surface_id"], "module_count": payload["module_count"], "command_count": payload["command_count"]}, args.format)
        return 0
    except PublicSurfaceError as exc:
        _emit({"valid": False, "rule_id": exc.rule_id, "error": str(exc)}, args.format, stream=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
