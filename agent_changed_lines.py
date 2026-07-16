#!/usr/bin/env python3
"""Added-line-only security gate built on the Basit Agent System control plane."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import agent_system as core
from agent_baseline import (
    DEFAULT_BASELINE_NAME,
    BaselineError,
    classify_findings,
    controls_digest,
    discover_baseline,
    load_baseline,
)
from agent_config import ConfigError
from agent_git import GitDiffError, changed_scope, public_scope
from agent_policy import PolicyError, apply_policy


def _line_matches(line: int, ranges: list[list[int]] | None) -> bool:
    return ranges is None or any(start <= line <= end for start, end in ranges)


def filter_added_line_findings(
    findings: list[dict[str, Any]],
    line_scope: dict[str, list[list[int]] | None],
) -> list[dict[str, Any]]:
    """Keep only findings whose starting line belongs to the added-line scope."""
    return [
        finding
        for finding in findings
        if finding["path"] in line_scope
        and _line_matches(int(finding["line"]), line_scope[finding["path"]])
    ]


def baseline_for_line_scope(
    baseline: dict[str, Any],
    line_scope: dict[str, list[list[int]] | None],
) -> dict[str, Any]:
    """Limit baseline resolution to old lines changed or removed by the diff."""
    scoped = dict(baseline)
    scoped["findings"] = [
        item
        for item in baseline["findings"]
        if item["path"] in line_scope
        and _line_matches(int(item["line"]), line_scope[item["path"]])
    ]
    return scoped


def _scope_summary(scope: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "type", "base_ref", "head_ref", "base_sha", "head_sha", "merge_base_sha",
        "changed", "current_files", "deleted", "renamed", "line_mode", "line_files",
        "added_ranges", "removed_ranges", "full_file_scans", "full_file_resolutions",
    )
    return {key: scope[key] for key in keys if key in scope}


def _render(
    findings: list[dict[str, Any]],
    suppressed: list[dict[str, Any]],
    policy: dict[str, Any],
    config: dict[str, Any],
    output_format: str,
    show_suppressed: bool,
    *,
    baseline: dict[str, Any] | None,
    existing: list[dict[str, Any]],
    resolved: list[dict[str, Any]],
    show_existing: bool,
    scope: dict[str, Any],
) -> str:
    report = core.render_scan(
        findings,
        suppressed,
        policy,
        config,
        output_format,
        show_suppressed,
        baseline=baseline,
        existing=existing,
        resolved=resolved,
        show_existing=show_existing,
        scope=scope,
    )
    scope_summary = _scope_summary(scope)
    if output_format == "json":
        payload = json.loads(report)
        payload["summary"]["scope"] = scope_summary
        return json.dumps(payload, indent=2)
    if output_format == "sarif":
        payload = json.loads(report)
        payload["runs"][0]["properties"]["scope"] = scope_summary
        return json.dumps(payload, indent=2)

    lines = report.splitlines()
    detail = (
        f"Added-line scope: {scope['line_files']} file(s), {scope['added_ranges']} added range(s), "
        f"{scope['removed_ranges']} removed range(s), {scope['full_file_scans']} full new file(s)"
    )
    insertion = next((index + 1 for index, line in enumerate(lines) if line.startswith("Git scope:")), 1)
    lines.insert(insertion, detail)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-changed-lines",
        description="Scan only findings whose start line was added or replaced in a merge-base Git diff.",
    )
    parser.add_argument("path", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--changed-from", required=True)
    parser.add_argument("--changed-to", default="HEAD")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--fail-on", choices=list(core.SEVERITY), default="high")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--new-only", action="store_true")
    parser.add_argument("--show-existing", action="store_true")
    parser.add_argument("--show-suppressed", action="store_true")
    parser.add_argument("--audit-log", type=Path, default=Path(".agent-system/audit.jsonl"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.baseline and not args.new_only:
        print("Configuration error: --baseline requires --new-only", file=sys.stderr)
        return 2
    if args.show_existing and not args.new_only:
        print("Configuration error: --show-existing requires --new-only", file=sys.stderr)
        return 2

    try:
        config, policy = core._load_controls(args.path, args.config, args.policy)
        internal_scope = changed_scope(
            args.path,
            args.changed_from,
            args.changed_to,
            line_only=True,
        )
        raw_findings = core.scan(
            args.path,
            set(config["enabled_rules"]),
            set(internal_scope["_scan_paths"]),
        )
        line_findings = filter_added_line_findings(raw_findings, internal_scope["_scan_lines"])
        active, suppressed = apply_policy(line_findings, policy)

        baseline = None
        existing: list[dict[str, Any]] = []
        resolved: list[dict[str, Any]] = []
        reported = active
        if args.new_only:
            baseline_path = discover_baseline(args.path, args.baseline)
            if baseline_path is None:
                raise BaselineError(
                    f"no {DEFAULT_BASELINE_NAME} found; create one with 'agent-system baseline --create'"
                )
            baseline = load_baseline(
                baseline_path,
                expected_controls_sha256=controls_digest(config, policy),
            )
            reported, existing, resolved = classify_findings(
                active,
                baseline_for_line_scope(baseline, internal_scope["_baseline_lines"]),
            )
    except (BaselineError, ConfigError, GitDiffError, PolicyError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    report_scope = public_scope(internal_scope)
    report = _render(
        reported,
        suppressed,
        policy,
        config,
        args.format,
        args.show_suppressed,
        baseline=baseline,
        existing=existing,
        resolved=resolved,
        show_existing=args.show_existing,
        scope=report_scope,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)

    core.append_audit(args.audit_log, "scan-added-lines", {
        "path": str(args.path),
        "active": len(active),
        "reported": len(reported),
        "suppressed": len(suppressed),
        "policy": policy.get("source"),
        "expired_suppressions": policy.get("expired_ids", []),
        "config": config.get("source"),
        "enabled_packs": config["enabled_packs"],
        "disabled_rules": config["disabled_rules"],
        "new_only": bool(args.new_only),
        "baseline": baseline.get("source") if baseline else None,
        "new": len(reported) if baseline else None,
        "existing": len(existing) if baseline else None,
        "resolved": len(resolved) if baseline else None,
        "scope": _scope_summary(report_scope),
    })
    threshold_failed = any(
        core.SEVERITY[item["severity"]] >= core.SEVERITY[args.fail_on]
        for item in reported
    )
    return int(threshold_failed or bool(policy.get("expired_ids")))


if __name__ == "__main__":
    raise SystemExit(main())
