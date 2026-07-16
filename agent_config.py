"""Validated rule-pack configuration for Basit Agent System."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONFIG_VERSION = 1
DEFAULT_CONFIG_NAME = ".agent-system.json"

RULE_PACKS: dict[str, tuple[str, ...]] = {
    "core": ("BAS000", "BAS001", "BAS002", "BAS003"),
    "boundaries": ("BAS010", "BAS011", "BAS012", "BAS013", "BAS030"),
    "workflows": ("BAS020", "BAS021", "BAS022", "BAS023", "BAS024"),
}
MANDATORY_PACKS = frozenset({"core"})
MANDATORY_RULES = frozenset(RULE_PACKS["core"])
ALL_RULES = frozenset(rule_id for rules in RULE_PACKS.values() for rule_id in rules)


class ConfigError(ValueError):
    """Raised when scanner configuration weakens mandatory safety controls."""


def default_config() -> dict[str, Any]:
    enabled_packs = list(RULE_PACKS)
    return {
        "version": CONFIG_VERSION,
        "source": None,
        "enabled_packs": enabled_packs,
        "disabled_rules": [],
        "enabled_rules": sorted(ALL_RULES),
    }


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ConfigError(f"{field} must be an array of non-empty strings")
    normalized = [item.strip() for item in value]
    if len(normalized) != len(set(normalized)):
        raise ConfigError(f"{field} must not contain duplicates")
    return normalized


def load_config(path: Path | None) -> dict[str, Any]:
    """Load a versioned scanner configuration and enforce mandatory protections."""
    if path is None:
        return default_config()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid config JSON at line {exc.lineno}: {exc.msg}") from exc
    except OSError as exc:
        raise ConfigError(f"unable to read config file: {path}") from exc

    if not isinstance(payload, dict):
        raise ConfigError("config root must be a JSON object")
    if payload.get("version") != CONFIG_VERSION:
        raise ConfigError(f"config version must be {CONFIG_VERSION}")

    enabled_packs = _string_list(payload.get("enabled_packs", list(RULE_PACKS)), "enabled_packs")
    unknown_packs = sorted(set(enabled_packs) - set(RULE_PACKS))
    if unknown_packs:
        raise ConfigError("unknown rule pack(s): " + ", ".join(unknown_packs))
    missing_mandatory = sorted(MANDATORY_PACKS - set(enabled_packs))
    if missing_mandatory:
        raise ConfigError("mandatory rule pack(s) cannot be disabled: " + ", ".join(missing_mandatory))

    disabled_rules = [item.upper() for item in _string_list(payload.get("disabled_rules", []), "disabled_rules")]
    unknown_rules = sorted(set(disabled_rules) - ALL_RULES)
    if unknown_rules:
        raise ConfigError("unknown rule id(s): " + ", ".join(unknown_rules))
    blocked = sorted(set(disabled_rules) & MANDATORY_RULES)
    if blocked:
        raise ConfigError("mandatory core rule(s) cannot be disabled: " + ", ".join(blocked))

    enabled_rules = {
        rule_id
        for pack in enabled_packs
        for rule_id in RULE_PACKS[pack]
        if rule_id not in disabled_rules
    }
    enabled_rules.update(MANDATORY_RULES)
    return {
        "version": CONFIG_VERSION,
        "source": str(path),
        "enabled_packs": enabled_packs,
        "disabled_rules": disabled_rules,
        "enabled_rules": sorted(enabled_rules),
    }


def discover_config(scan_root: Path, explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    root = scan_root if scan_root.is_dir() else scan_root.parent
    candidate = root / DEFAULT_CONFIG_NAME
    return candidate if candidate.exists() else None


def config_template() -> dict[str, Any]:
    return {
        "version": CONFIG_VERSION,
        "enabled_packs": ["core", "boundaries", "workflows"],
        "disabled_rules": [],
    }
