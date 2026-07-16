#!/usr/bin/env python3
"""Typed, privacy-safe admission rules for audit event details."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

EVENT_SCHEMA_VERSION = 1
SCHEMA_FIELD = "_event_schema"
MAX_DETAILS_BYTES = 16 * 1024
MAX_STRING_LENGTH = 512
MAX_LIST_ITEMS = 64
MAX_OBJECT_FIELDS = 64
MAX_EVENT_DEPTH = 8
MAX_COMMAND_ARGUMENTS = 256
MAX_REFERENCE_LENGTH = 4096

EVENT_NAME = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
SAFE_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:api_?key|access_?key|authorization|bearer|cookie|credential|passwd|password|private_?key|secret|session|token)(?:$|_)",
    re.IGNORECASE,
)
_SECRET_PATTERNS = (
    re.compile(r"\b(?:s" + r"k-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", re.IGNORECASE),
)

KNOWN_EVENTS = (
    "baseline-create",
    "dispatch",
    "guard",
    "scan",
    "scan-added-lines",
    "scrub",
)


class AuditEventError(ValueError):
    """Raised when an event fails typed admission or privacy controls."""

    def __init__(self, message: str, *, rule_id: str = "AUD022") -> None:
        super().__init__(message)
        self.rule_id = rule_id


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _domain_hash(domain: str, value: str) -> str:
    return hashlib.sha256(f"{domain}\0{value}".encode("utf-8")).hexdigest()


def _reject_secret_text(value: str, label: str) -> None:
    if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise AuditEventError(
            f"{label} contains credential-like material and must be replaced by a digest or reference",
            rule_id="AUD023",
        )


def _text(value: Any, label: str, *, maximum: int = MAX_STRING_LENGTH) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AuditEventError(f"{label} must be a canonical non-empty string")
    if len(value) > maximum or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AuditEventError(f"{label} exceeds the reviewed printable-string boundary")
    _reject_secret_text(value, label)
    return value


def _identifier(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    text = _text(value, label, maximum=128)
    if not SAFE_IDENTIFIER.fullmatch(text):
        raise AuditEventError(f"{label} must be a safe identifier")
    return text


def _event_name(value: Any) -> str:
    if not isinstance(value, str) or not EVENT_NAME.fullmatch(value):
        raise AuditEventError("audit event must use a lowercase hyphenated name")
    return value


def _integer(value: Any, label: str, *, nullable: bool = False) -> int | None:
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuditEventError(f"{label} must be a non-negative integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise AuditEventError(f"{label} must be a boolean")
    return value


def _hex(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AuditEventError(f"{label} must be lowercase hexadecimal with the reviewed length")
    return value


def _identifiers(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise AuditEventError(f"{label} must be a bounded array")
    normalized = [_identifier(item, f"{label} item") for item in value]
    if len(normalized) != len(set(normalized)):
        raise AuditEventError(f"{label} must not contain duplicates")
    return sorted(normalized)


def _expect_fields(details: dict[str, Any], required: set[str], optional: set[str] = frozenset()) -> None:
    fields = set(details)
    allowed = required | optional
    missing = sorted(required - fields)
    unexpected = sorted(fields - allowed)
    if missing or unexpected:
        raise AuditEventError(
            f"audit event fields do not match the reviewed schema; missing={missing}, unexpected={unexpected}"
        )


def _reference_text(value: Any, label: str) -> str:
    if isinstance(value, Path):
        value = str(value)
    if not isinstance(value, str) or not value or len(value) > MAX_REFERENCE_LENGTH:
        raise AuditEventError(f"{label} must be a bounded non-empty reference")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AuditEventError(f"{label} contains control characters")
    _reject_secret_text(value, label)
    return value.replace("\\", "/")


def path_reference(value: Any, label: str = "path") -> dict[str, Any] | None:
    """Convert a path into a non-reversible, domain-separated reference."""
    if value is None:
        return None
    if isinstance(value, dict):
        _expect_fields(value, {"kind", "sha256"})
        kind = _identifier(value["kind"], f"{label}.kind")
        if kind not in {"absolute", "relative"}:
            raise AuditEventError(f"{label}.kind must be absolute or relative")
        return {"kind": kind, "sha256": _hex(value["sha256"], f"{label}.sha256", HEX_64)}
    text = _reference_text(value, label)
    absolute = text.startswith("/") or bool(re.match(r"^[A-Za-z]:/", text))
    return {
        "kind": "absolute" if absolute else "relative",
        "sha256": _domain_hash("audit-path-v1", text),
    }


def command_reference(value: Any, label: str = "command") -> dict[str, Any]:
    """Convert an argument array into a digest and argument count without storing arguments."""
    if isinstance(value, dict):
        _expect_fields(value, {"argc", "sha256"})
        return {
            "argc": _integer(value["argc"], f"{label}.argc"),
            "sha256": _hex(value["sha256"], f"{label}.sha256", HEX_64),
        }
    if not isinstance(value, list) or not value or len(value) > MAX_COMMAND_ARGUMENTS:
        raise AuditEventError(f"{label} must be a bounded non-empty argument array")
    arguments = [_reference_text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    return {
        "argc": len(arguments),
        "sha256": _domain_hash("audit-command-v1", _canonical_bytes(arguments).decode("ascii")),
    }


def _scope_reference(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise AuditEventError("scope must be an object or null")

    raw_fields = {
        "type", "base_ref", "head_ref", "base_sha", "head_sha", "merge_base_sha",
        "changed", "current_files", "deleted", "renamed", "line_mode", "line_files",
        "added_ranges", "removed_ranges", "full_file_scans", "full_file_resolutions",
    }
    stored_fields = (raw_fields - {"base_ref", "head_ref"}) | {"base_ref_sha256", "head_ref_sha256"}
    if set(value).issubset(raw_fields):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if key == "type":
                output[key] = _identifier(item, "scope.type")
            elif key in {"base_ref", "head_ref"}:
                output[f"{key}_sha256"] = _domain_hash(
                    "audit-git-ref-v1", _reference_text(item, f"scope.{key}")
                )
            elif key in {"base_sha", "head_sha", "merge_base_sha"}:
                output[key] = _hex(item, f"scope.{key}", HEX_40)
            elif key == "line_mode":
                output[key] = _boolean(item, "scope.line_mode")
            else:
                output[key] = _integer(item, f"scope.{key}")
        return dict(sorted(output.items()))

    if not set(value).issubset(stored_fields):
        raise AuditEventError("scope contains unreviewed fields")
    output = {}
    for key, item in value.items():
        if key == "type":
            output[key] = _identifier(item, "scope.type")
        elif key in {"base_ref_sha256", "head_ref_sha256"}:
            output[key] = _hex(item, f"scope.{key}", HEX_64)
        elif key in {"base_sha", "head_sha", "merge_base_sha"}:
            output[key] = _hex(item, f"scope.{key}", HEX_40)
        elif key == "line_mode":
            output[key] = _boolean(item, "scope.line_mode")
        else:
            output[key] = _integer(item, f"scope.{key}")
    return dict(sorted(output.items()))


def _decision(details: dict[str, Any], *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    required = {"allowed", "rule_id", "severity", "reason", "safer_alternative"}
    if extra:
        required |= set(extra)
    _expect_fields(details, required)
    output: dict[str, Any] = {
        SCHEMA_FIELD: EVENT_SCHEMA_VERSION,
        "allowed": _boolean(details["allowed"], "allowed"),
        "reason": _text(details["reason"], "reason"),
        "rule_id": _identifier(details["rule_id"], "rule_id", nullable=True),
        "safer_alternative": _text(details["safer_alternative"], "safer_alternative"),
        "severity": _identifier(details["severity"], "severity", nullable=True),
    }
    if output["severity"] not in {None, "low", "medium", "high", "critical"}:
        raise AuditEventError("severity is outside the reviewed set")
    if extra:
        output.update(extra)
    return dict(sorted(output.items()))


def _scan(details: dict[str, Any]) -> dict[str, Any]:
    required = {
        "path", "active", "reported", "suppressed", "policy", "expired_suppressions",
        "config", "enabled_packs", "disabled_rules", "new_only", "baseline", "new",
        "existing", "resolved", "scope",
    }
    _expect_fields(details, required)
    return dict(sorted({
        SCHEMA_FIELD: EVENT_SCHEMA_VERSION,
        "active": _integer(details["active"], "active"),
        "baseline": path_reference(details["baseline"], "baseline"),
        "config": path_reference(details["config"], "config"),
        "disabled_rules": _identifiers(details["disabled_rules"], "disabled_rules"),
        "enabled_packs": _identifiers(details["enabled_packs"], "enabled_packs"),
        "existing": _integer(details["existing"], "existing", nullable=True),
        "expired_suppressions": _identifiers(details["expired_suppressions"], "expired_suppressions"),
        "new": _integer(details["new"], "new", nullable=True),
        "new_only": _boolean(details["new_only"], "new_only"),
        "path": path_reference(details["path"], "path"),
        "reported": _integer(details["reported"], "reported"),
        "resolved": _integer(details["resolved"], "resolved", nullable=True),
        "scope": _scope_reference(details["scope"]),
        "suppressed": _integer(details["suppressed"], "suppressed"),
    }.items()))


def _baseline_create(details: dict[str, Any]) -> dict[str, Any]:
    _expect_fields(details, {"path", "scan_path", "findings", "suppressed", "controls_sha256", "baseline_sha256"})
    return dict(sorted({
        SCHEMA_FIELD: EVENT_SCHEMA_VERSION,
        "baseline_sha256": _hex(details["baseline_sha256"], "baseline_sha256", HEX_64),
        "controls_sha256": _hex(details["controls_sha256"], "controls_sha256", HEX_64),
        "findings": _integer(details["findings"], "findings"),
        "path": path_reference(details["path"], "path"),
        "scan_path": path_reference(details["scan_path"], "scan_path"),
        "suppressed": _integer(details["suppressed"], "suppressed"),
    }.items()))


def _guard(details: dict[str, Any]) -> dict[str, Any]:
    return _decision(details)


def _scrub(details: dict[str, Any]) -> dict[str, Any]:
    _expect_fields(details, {"source", "matches", "output"})
    return dict(sorted({
        SCHEMA_FIELD: EVENT_SCHEMA_VERSION,
        "matches": _integer(details["matches"], "matches"),
        "output": path_reference(details["output"], "output"),
        "source": path_reference(details["source"], "source"),
    }.items()))


def _dispatch(details: dict[str, Any]) -> dict[str, Any]:
    _expect_fields(details, {"integration", "command", "allowed", "rule_id", "severity", "reason", "safer_alternative"})
    decision = _decision({
        "allowed": details["allowed"],
        "rule_id": details["rule_id"],
        "severity": details["severity"],
        "reason": details["reason"],
        "safer_alternative": details["safer_alternative"],
    })
    decision.update({
        "command": command_reference(details["command"]),
        "integration": _identifier(details["integration"], "integration"),
    })
    return dict(sorted(decision.items()))


def _generic_value(value: Any, label: str, *, depth: int = 0) -> Any:
    if depth > MAX_EVENT_DEPTH:
        raise AuditEventError(f"{label} exceeds the reviewed nesting depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise AuditEventError(f"{label} must not contain floating-point values")
    if isinstance(value, str):
        return _text(value, label)
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise AuditEventError(f"{label} exceeds the reviewed array length")
        return [_generic_value(item, f"{label}[{index}]", depth=depth + 1) for index, item in enumerate(value)]
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_FIELDS:
            raise AuditEventError(f"{label} exceeds the reviewed object-field count")
        output: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not SAFE_KEY.fullmatch(key):
                raise AuditEventError(f"{label} contains an unsafe field name")
            if key == SCHEMA_FIELD or SENSITIVE_KEY.search(key):
                raise AuditEventError(
                    f"{label}.{key} is a reserved or credential-bearing field",
                    rule_id="AUD023",
                )
            output[key] = _generic_value(item, f"{label}.{key}", depth=depth + 1)
        return dict(sorted(output.items()))
    raise AuditEventError(f"{label} contains unsupported type {type(value).__name__}")


def _generic(details: dict[str, Any]) -> dict[str, Any]:
    normalized = _generic_value(details, "details")
    normalized[SCHEMA_FIELD] = EVENT_SCHEMA_VERSION
    return dict(sorted(normalized.items()))


_NORMALIZERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "baseline-create": _baseline_create,
    "dispatch": _dispatch,
    "guard": _guard,
    "scan": _scan,
    "scan-added-lines": _scan,
    "scrub": _scrub,
}


def prepare_event(event: Any, details: Any) -> tuple[str, dict[str, Any]]:
    """Normalize an event into its typed, privacy-safe stored representation."""
    normalized_event = _event_name(event)
    if not isinstance(details, dict):
        raise AuditEventError("audit details must be a JSON object")
    raw = dict(details)
    raw.pop(SCHEMA_FIELD, None)
    normalizer = _NORMALIZERS.get(normalized_event, _generic)
    normalized = normalizer(raw)
    if len(_canonical_bytes(normalized)) > MAX_DETAILS_BYTES:
        raise AuditEventError("audit event details exceed the reviewed encoded-size boundary")
    return normalized_event, normalized


def validate_stored_event(event: Any, details: Any) -> bool:
    """Validate one stored event. Return False for pre-schema legacy details."""
    normalized_event = _event_name(event)
    if not isinstance(details, dict):
        raise AuditEventError("audit details must be a JSON object")
    if SCHEMA_FIELD not in details:
        return False
    if details.get(SCHEMA_FIELD) != EVENT_SCHEMA_VERSION:
        raise AuditEventError("audit event schema version is unsupported")
    _, normalized = prepare_event(normalized_event, details)
    if normalized != details:
        raise AuditEventError("audit event details are not in canonical typed form")
    return True


def inspect_event_records(
    path: Path,
    report: dict[str, Any],
    *,
    require_typed: bool = False,
) -> dict[str, Any]:
    """Extend a structurally valid audit report with event-schema and privacy checks."""
    extended = dict(report)
    extended.update({
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "typed_records": 0,
        "untyped_records": 0,
        "typed_coverage_percent": 100 if report.get("records", 0) == 0 else 0,
        "privacy_safe": report.get("records", 0) == 0,
        "event_counts": {},
        "require_typed": bool(require_typed),
    })
    if not report.get("valid") or not Path(path).exists() or report.get("records", 0) == 0:
        return extended

    raw = Path(path).read_bytes()
    offset = 0
    event_counts: dict[str, int] = {}
    for line_number, raw_line in enumerate(raw.splitlines(keepends=True), 1):
        record = json.loads(raw_line)
        event = record["event"]
        event_counts[event] = event_counts.get(event, 0) + 1
        try:
            typed = validate_stored_event(event, record["details"])
        except AuditEventError as exc:
            extended["valid"] = False
            extended["error"] = {
                "rule_id": exc.rule_id,
                "message": str(exc),
                "line": line_number,
                "byte_offset": offset,
                "recoverable": True,
            }
            extended["recoverable_prefix"] = {
                "records": line_number - 1,
                "bytes": offset,
                "head_hash": record["previous_hash"],
            }
            break
        if typed:
            extended["typed_records"] += 1
        else:
            extended["untyped_records"] += 1
            if require_typed:
                extended["valid"] = False
                extended["error"] = {
                    "rule_id": "AUD024",
                    "message": "audit log contains a pre-schema event record while typed coverage is required",
                    "line": line_number,
                    "byte_offset": offset,
                    "recoverable": False,
                }
                extended["recoverable_prefix"] = None
                break
        offset += len(raw_line)

    extended["event_counts"] = dict(sorted(event_counts.items()))
    records = extended["typed_records"] + extended["untyped_records"]
    if records:
        extended["typed_coverage_percent"] = (100 * extended["typed_records"]) // records
        extended["privacy_safe"] = extended["untyped_records"] == 0 and extended["valid"]
    return extended


def event_catalog() -> dict[str, Any]:
    """Return the stable event-admission catalog without implementation details."""
    return {
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "known_events": list(KNOWN_EVENTS),
        "generic_events": {
            "allowed": True,
            "event_name": "lowercase hyphenated",
            "details": "bounded safe JSON object without credential-bearing keys or values",
        },
        "privacy": {
            "commands": "domain-separated SHA-256 plus argument count",
            "paths": "domain-separated SHA-256 plus absolute/relative kind",
            "git_refs": "domain-separated SHA-256",
            "credential_like_material": "rejected",
            "maximum_details_bytes": MAX_DETAILS_BYTES,
        },
        "rules": {
            "AUD022": "typed event schema or canonicalization failure",
            "AUD023": "credential-bearing audit detail rejected",
            "AUD024": "typed coverage required but legacy untyped records remain",
        },
    }
