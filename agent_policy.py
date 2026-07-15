"""Validated, expiring suppression policies for Basit Agent System."""
from __future__ import annotations

import fnmatch
import json
from datetime import date
from pathlib import Path
from typing import Any

POLICY_VERSION = 1
DEFAULT_POLICY_NAME = ".agent-system-policy.json"


class PolicyError(ValueError):
    """Raised when a policy file is missing required safety metadata."""


def empty_policy() -> dict[str, Any]:
    return {"version": POLICY_VERSION, "source": None, "suppressions": [], "expired_ids": []}


def _nonempty_text(value: Any, field: str, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise PolicyError(f"{field} must be a non-empty string")
    return value.strip()


def _parse_expiry(value: Any, suppression_id: str) -> date:
    raw = _nonempty_text(value, f"suppression {suppression_id!r} expires")
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise PolicyError(f"suppression {suppression_id!r} expires must use YYYY-MM-DD") from exc


def load_policy(path: Path | None, *, today: date | None = None) -> dict[str, Any]:
    """Load and validate a versioned suppression policy."""
    if path is None:
        return empty_policy()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid policy JSON at line {exc.lineno}: {exc.msg}") from exc
    except OSError as exc:
        raise PolicyError(f"unable to read policy file: {path}") from exc

    if not isinstance(payload, dict):
        raise PolicyError("policy root must be a JSON object")
    if payload.get("version") != POLICY_VERSION:
        raise PolicyError(f"policy version must be {POLICY_VERSION}")
    items = payload.get("suppressions", [])
    if not isinstance(items, list):
        raise PolicyError("suppressions must be a JSON array")

    current = today or date.today()
    seen: set[str] = set()
    suppressions: list[dict[str, Any]] = []
    expired_ids: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise PolicyError(f"suppression at index {index} must be an object")
        suppression_id = _nonempty_text(item.get("id"), f"suppression[{index}].id")
        if suppression_id in seen:
            raise PolicyError(f"duplicate suppression id: {suppression_id}")
        seen.add(suppression_id)
        owner = _nonempty_text(item.get("owner"), f"suppression {suppression_id!r} owner")
        reason = _nonempty_text(item.get("reason"), f"suppression {suppression_id!r} reason", minimum=8)
        expiry = _parse_expiry(item.get("expires"), suppression_id)
        rule_id = _nonempty_text(item.get("rule_id", "*"), "rule_id").upper()
        path_glob = _nonempty_text(item.get("path", "**"), "path")
        fingerprint = item.get("fingerprint")
        if fingerprint is not None:
            fingerprint = _nonempty_text(fingerprint, "fingerprint").lower()
            if len(fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in fingerprint):
                raise PolicyError(f"suppression {suppression_id!r} fingerprint must be 64 lowercase hex characters")
        normalized = {
            "id": suppression_id,
            "owner": owner,
            "reason": reason,
            "expires": expiry.isoformat(),
            "rule_id": rule_id,
            "path": path_glob.replace("\\", "/"),
            "fingerprint": fingerprint,
            "expired": expiry < current,
        }
        suppressions.append(normalized)
        if normalized["expired"]:
            expired_ids.append(suppression_id)
    return {"version": POLICY_VERSION, "source": str(path), "suppressions": suppressions, "expired_ids": expired_ids}


def _path_matches(path: str, pattern: str) -> bool:
    normalized = path.replace("\\", "/")
    if pattern in {"*", "**"}:
        return True
    return fnmatch.fnmatchcase(normalized, pattern) or (
        pattern.startswith("**/") and fnmatch.fnmatchcase(normalized, pattern[3:])
    )


def suppression_matches(finding: dict[str, Any], suppression: dict[str, Any]) -> bool:
    if suppression.get("expired"):
        return False
    if suppression["rule_id"] not in {"*", str(finding.get("rule_id", "")).upper()}:
        return False
    if not _path_matches(str(finding.get("path", "")), suppression["path"]):
        return False
    expected = suppression.get("fingerprint")
    return expected is None or expected == str(finding.get("fingerprint", "")).lower()


def apply_policy(findings: list[dict[str, Any]], policy: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        match = next((item for item in policy.get("suppressions", []) if suppression_matches(finding, item)), None)
        if match is None:
            active.append(finding)
            continue
        copy = dict(finding)
        copy["suppression"] = {key: match[key] for key in ("id", "owner", "reason", "expires")}
        suppressed.append(copy)
    return active, suppressed


def discover_policy(scan_root: Path, explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    root = scan_root if scan_root.is_dir() else scan_root.parent
    candidate = root / DEFAULT_POLICY_NAME
    return candidate if candidate.exists() else None


def policy_template() -> dict[str, Any]:
    return {
        "version": POLICY_VERSION,
        "suppressions": [{
            "id": "example-reviewed-fixture",
            "rule_id": "BAS003",
            "path": "tests/fixtures/**",
            "owner": "security@example.invalid",
            "reason": "Synthetic provider token used only by an isolated scanner fixture.",
            "expires": "2099-12-31",
        }],
    }
