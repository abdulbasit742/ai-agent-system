#!/usr/bin/env python3
"""Basit Agent System compatibility wrapper with strict audit-log controls."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import agent_audit as _audit
import agent_system_legacy as _legacy
from agent_audit import (
    AuditError,
    append_audit as _strict_append_audit,
    inspect_audit as _strict_inspect_audit,
    recover_audit,
)
from agent_audit_events import (
    AuditEventError,
    event_catalog,
    inspect_event_records,
    prepare_event,
)
from agent_system_legacy import *  # noqa: F401,F403


def inspect_audit(
    path: Path,
    *,
    expected_head: str | None = None,
    expected_records: int | None = None,
    require_typed: bool = False,
) -> dict[str, Any]:
    """Validate structural integrity, event admission, and optional typed coverage."""
    report = _strict_inspect_audit(
        path,
        expected_head=expected_head,
        expected_records=expected_records,
    )
    error = report.get("error")
    if (
        error
        and error.get("rule_id") == "AUD008"
        and str(error.get("message", "")).startswith("audit details ")
    ):
        report = dict(report)
        report["error"] = {**error, "rule_id": "AUD013"}
    return inspect_event_records(Path(path), report, require_typed=require_typed)


def append_audit(
    path: Path,
    event: str,
    details: dict[str, Any],
    *,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Admit, privacy-normalize, and append one typed audit event."""
    try:
        normalized_event, normalized_details = prepare_event(event, details)
    except AuditEventError as exc:
        raise AuditError(f"{exc.rule_id}: audit event admission failed: {exc}") from exc
    return _strict_append_audit(
        path,
        normalized_event,
        normalized_details,
        timestamp=timestamp,
    )


def verify_audit(path: Path) -> tuple[bool, int]:
    """Compatibility verifier using both structural and event-level validation."""
    report = inspect_audit(path)
    if report["valid"]:
        return True, report["records"]
    line = report["error"]["line"] if report.get("error") else None
    return False, line or report["records"]


# Keep public and internal compatibility APIs while replacing audit admission.
_load_controls = _legacy._load_controls
_baseline_for_scope = _legacy._baseline_for_scope
_scope_summary = _legacy._scope_summary
_audit.append_audit = append_audit
_audit.inspect_audit = inspect_audit
_audit.verify_audit = verify_audit
_legacy.append_audit = append_audit
_legacy.verify_audit = verify_audit

_DEFAULT_AUDIT = Path(".agent-system/audit.jsonl")
_AUDITED_COMMANDS = {"scan", "guard", "scrub", "run"}


def _command_context(arguments: list[str]) -> tuple[str | None, list[str], Path]:
    audit_path = _DEFAULT_AUDIT
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--audit-log":
            if index + 1 >= len(arguments):
                raise AuditError("--audit-log requires a path")
            audit_path = Path(arguments[index + 1])
            index += 2
            continue
        if token.startswith("--audit-log="):
            value = token.split("=", 1)[1]
            if not value:
                raise AuditError("--audit-log requires a path")
            audit_path = Path(value)
            index += 1
            continue
        if token.startswith("-"):
            return None, [], audit_path
        return token, arguments[index + 1 :], audit_path
    return None, [], audit_path


def _audit_text(report: dict[str, Any]) -> str:
    state = "VALID" if report["valid"] else "INVALID"
    lines = [
        f"{state} {report['records']} record(s)",
        f"head: {report['head_hash']}",
        f"records: legacy={report['legacy_records']} versioned={report['versioned_records']}",
        f"events: typed={report['typed_records']} untyped={report['untyped_records']} "
        f"coverage={report['typed_coverage_percent']}% privacy_safe={str(report['privacy_safe']).lower()}",
    ]
    if report.get("event_counts"):
        lines.append(
            "event-counts: "
            + ", ".join(f"{name}={count}" for name, count in report["event_counts"].items())
        )
    error = report.get("error")
    if error:
        location = ""
        if error["line"] is not None:
            location = f" line={error['line']}"
        lines.append(
            f"{error['rule_id']}:{location} byte={error['byte_offset']} {error['message']}"
        )
    prefix = report.get("recoverable_prefix")
    if prefix is not None:
        lines.append(
            f"recoverable-prefix: records={prefix['records']} bytes={prefix['bytes']} "
            f"head={prefix['head_hash']}"
        )
    recovery = report.get("recovery")
    if recovery:
        lines.append(
            f"recovery-copy: {recovery['created']} records={recovery['records']} "
            f"head={recovery['head_hash']}"
        )
    return "\n".join(lines)


def _audit_main(command_arguments: list[str], default_path: Path) -> int:
    parser = argparse.ArgumentParser(prog="agent-system audit")
    parser.add_argument("--path", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-records", type=int)
    parser.add_argument("--require-typed", action="store_true")
    parser.add_argument("--recover-to", type=Path)
    args = parser.parse_args(command_arguments)
    path = args.path or default_path
    try:
        report = inspect_audit(
            path,
            expected_head=args.expected_head,
            expected_records=args.expected_records,
            require_typed=args.require_typed,
        )
        if args.recover_to is not None:
            report = dict(report)
            report["recovery"] = recover_audit(path, args.recover_to, report)
    except AuditError as exc:
        print(f"Audit error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(_audit_text(report))
    return 0 if report["valid"] else 1


def _audit_events_main(command_arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="agent-system audit-events")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(command_arguments)
    catalog = event_catalog()
    if args.format == "json":
        print(json.dumps(catalog, sort_keys=True, indent=2))
    else:
        print(f"Audit event schema v{catalog['event_schema_version']}")
        print("Known events: " + ", ".join(catalog["known_events"]))
        print("Generic events: bounded safe JSON; credential-bearing material rejected")
        print("Paths, commands, and Git refs are stored as domain-separated SHA-256 references")
    return 0


def _preflight_required(command: str | None, command_arguments: list[str]) -> bool:
    if command in _AUDITED_COMMANDS:
        return True
    return command == "baseline" and "--create" in command_arguments


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        command, command_arguments, audit_path = _command_context(arguments)
        if command == "audit":
            return _audit_main(command_arguments, audit_path)
        if command == "audit-events":
            return _audit_events_main(command_arguments)
        if _preflight_required(command, command_arguments):
            report = inspect_audit(audit_path)
            if not report["valid"]:
                error = report["error"]
                line = f" line {error['line']}" if error["line"] is not None else ""
                print(
                    f"Audit error: {error['rule_id']}{line}: {error['message']}",
                    file=sys.stderr,
                )
                return 2
        return _legacy.main(arguments)
    except AuditError as exc:
        print(f"Audit error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
