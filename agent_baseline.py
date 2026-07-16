"""Exact-fingerprint security baselines for Basit Agent System."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASELINE_VERSION = 1
DEFAULT_BASELINE_NAME = ".agent-system-baseline.json"
SEVERITIES = frozenset({"low", "medium", "high", "critical"})
BASELINE_KEYS = frozenset({
    "version",
    "generated_at",
    "scan_root",
    "controls_sha256",
    "findings",
    "baseline_sha256",
})
FINDING_KEYS = frozenset({"fingerprint", "rule_id", "severity", "path", "line"})
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
RULE_ID = re.compile(r"^BAS\d{3}$")


class BaselineError(ValueError):
    """Raised when a baseline is malformed, stale, or outside the active control scope."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def controls_digest(config: dict[str, Any], policy: dict[str, Any]) -> str:
    """Hash rule-pack and suppression controls without depending on local file paths."""
    suppressions = []
    for item in policy.get("suppressions", []):
        suppressions.append({
            "id": item["id"],
            "owner": item["owner"],
            "reason": item["reason"],
            "expires": item["expires"],
            "rule_id": item["rule_id"],
            "path": item["path"],
            "fingerprint": item.get("fingerprint"),
            "expired": bool(item.get("expired")),
        })
    suppressions.sort(key=lambda item: item["id"])
    payload = {
        "config": {
            "version": config["version"],
            "enabled_packs": list(config["enabled_packs"]),
            "disabled_rules": list(config["disabled_rules"]),
            "enabled_rules": list(config["enabled_rules"]),
        },
        "policy": {
            "version": policy["version"],
            "suppressions": suppressions,
        },
    }
    return _sha256(payload)


def _baseline_body(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "baseline_sha256"}


def build_baseline(
    findings: list[dict[str, Any]],
    config: dict[str, Any],
    policy: dict[str, Any],
    scan_root: Path,
) -> dict[str, Any]:
    """Build a portable baseline containing no finding previews or secret evidence."""
    entries = [{
        "fingerprint": item["fingerprint"],
        "rule_id": item["rule_id"],
        "severity": item["severity"],
        "path": item["path"],
        "line": item["line"],
    } for item in findings]
    entries.sort(key=lambda item: item["fingerprint"])
    payload = {
        "version": BASELINE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_root": str(scan_root),
        "controls_sha256": controls_digest(config, policy),
        "findings": entries,
    }
    payload["baseline_sha256"] = _sha256(payload)
    return payload


def _nonempty_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BaselineError(f"{field} must be a non-empty string")
    return value.strip()


def _validate_finding(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise BaselineError(f"finding at index {index} must be an object")
    if set(item) != FINDING_KEYS:
        raise BaselineError(f"finding at index {index} must contain exactly: {', '.join(sorted(FINDING_KEYS))}")
    fingerprint = _nonempty_text(item.get("fingerprint"), f"finding[{index}].fingerprint").lower()
    if not HEX_64.fullmatch(fingerprint):
        raise BaselineError(f"finding[{index}].fingerprint must be 64 lowercase hex characters")
    rule_id = _nonempty_text(item.get("rule_id"), f"finding[{index}].rule_id").upper()
    if not RULE_ID.fullmatch(rule_id):
        raise BaselineError(f"finding[{index}].rule_id must match BAS###")
    severity = _nonempty_text(item.get("severity"), f"finding[{index}].severity").lower()
    if severity not in SEVERITIES:
        raise BaselineError(f"finding[{index}].severity is invalid")
    path = _nonempty_text(item.get("path"), f"finding[{index}].path")
    if "\\" in path:
        raise BaselineError(f"finding[{index}].path must use forward slashes")
    line = item.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise BaselineError(f"finding[{index}].line must be a positive integer")
    return {
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "severity": severity,
        "path": path,
        "line": line,
    }


def load_baseline(path: Path, *, expected_controls_sha256: str | None = None) -> dict[str, Any]:
    """Load and verify an exact-fingerprint baseline."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"invalid baseline JSON at line {exc.lineno}: {exc.msg}") from exc
    except OSError as exc:
        raise BaselineError(f"unable to read baseline file: {path}") from exc

    if not isinstance(payload, dict):
        raise BaselineError("baseline root must be a JSON object")
    if set(payload) != BASELINE_KEYS:
        raise BaselineError("baseline must contain exactly the documented version 1 fields")
    if payload.get("version") != BASELINE_VERSION:
        raise BaselineError(f"baseline version must be {BASELINE_VERSION}")
    generated_at = _nonempty_text(payload.get("generated_at"), "generated_at")
    scan_root = _nonempty_text(payload.get("scan_root"), "scan_root")
    controls_sha256 = _nonempty_text(payload.get("controls_sha256"), "controls_sha256").lower()
    baseline_sha256 = _nonempty_text(payload.get("baseline_sha256"), "baseline_sha256").lower()
    if not HEX_64.fullmatch(controls_sha256):
        raise BaselineError("controls_sha256 must be 64 lowercase hex characters")
    if not HEX_64.fullmatch(baseline_sha256):
        raise BaselineError("baseline_sha256 must be 64 lowercase hex characters")
    if baseline_sha256 != _sha256(_baseline_body(payload)):
        raise BaselineError("baseline integrity hash does not match its contents")
    if expected_controls_sha256 is not None and controls_sha256 != expected_controls_sha256:
        raise BaselineError("baseline controls do not match the active rule-pack and suppression configuration")

    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        raise BaselineError("findings must be a JSON array")
    findings = [_validate_finding(item, index) for index, item in enumerate(raw_findings)]
    fingerprints = [item["fingerprint"] for item in findings]
    if len(fingerprints) != len(set(fingerprints)):
        raise BaselineError("baseline contains duplicate finding fingerprints")
    if fingerprints != sorted(fingerprints):
        raise BaselineError("baseline findings must be sorted by fingerprint")
    return {
        "version": BASELINE_VERSION,
        "source": str(path),
        "generated_at": generated_at,
        "scan_root": scan_root,
        "controls_sha256": controls_sha256,
        "baseline_sha256": baseline_sha256,
        "findings": findings,
    }


def classify_findings(
    findings: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Split current findings into new, existing, and resolved baseline entries."""
    known = {item["fingerprint"]: item for item in baseline["findings"]}
    current = {item["fingerprint"] for item in findings}
    new_findings: list[dict[str, Any]] = []
    existing_findings: list[dict[str, Any]] = []
    for finding in findings:
        copy = dict(finding)
        if finding["fingerprint"] in known:
            copy["baseline_state"] = "existing"
            existing_findings.append(copy)
        else:
            copy["baseline_state"] = "new"
            new_findings.append(copy)
    resolved = [dict(item, baseline_state="resolved") for item in baseline["findings"] if item["fingerprint"] not in current]
    return new_findings, existing_findings, resolved


def discover_baseline(scan_root: Path, explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    root = scan_root if scan_root.is_dir() else scan_root.parent
    candidate = root / DEFAULT_BASELINE_NAME
    return candidate if candidate.exists() else None
