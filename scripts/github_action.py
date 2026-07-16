#!/usr/bin/env python3
"""Secure GitHub composite-action runner for Basit Agent System."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

ALLOWED_MODES = {"full", "changed-files", "added-lines"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
SEVERITY_TO_ANNOTATION = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "notice",
}


class ActionInputError(ValueError):
    """Raised when action inputs could escape the workspace or weaken execution."""


def _text(env: Mapping[str, str], name: str, default: str = "") -> str:
    value = env.get(name, default)
    if "\0" in value or "\r" in value or "\n" in value:
        raise ActionInputError(f"{name} contains control characters")
    return value.strip()


def _choice(env: Mapping[str, str], name: str, allowed: set[str], default: str) -> str:
    value = _text(env, name, default).lower()
    if value not in allowed:
        raise ActionInputError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return value


def _boolean(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    value = _text(env, name, "true" if default else "false").lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ActionInputError(f"{name} must be true or false")


def _integer(env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    value = _text(env, name, str(default))
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ActionInputError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ActionInputError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _workspace_path(
    workspace: Path,
    raw: str,
    label: str,
    *,
    must_exist: bool = False,
    directory: bool = False,
) -> Path:
    value = raw.strip() or "."
    logical = PurePosixPath(value.replace("\\", "/"))
    if logical.is_absolute() or ".." in logical.parts:
        raise ActionInputError(f"{label} must stay inside the GitHub workspace")
    target = workspace.joinpath(*logical.parts).resolve(strict=False)
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise ActionInputError(f"{label} resolves outside the GitHub workspace") from exc
    if must_exist and not target.exists():
        raise ActionInputError(f"{label} does not exist: {value}")
    if directory and not target.is_dir():
        raise ActionInputError(f"{label} must be an existing directory")
    return target


def _relative(workspace: Path, path: Path) -> str:
    return path.relative_to(workspace).as_posix()


def _optional_workspace_argument(
    env: Mapping[str, str],
    name: str,
    workspace: Path,
    label: str,
) -> str | None:
    raw = _text(env, name)
    if not raw:
        return None
    return str(_workspace_path(workspace, raw, label, must_exist=True))


def resolve_refs(env: Mapping[str, str], mode: str) -> tuple[str | None, str | None]:
    if mode == "full":
        return None, None
    base = _text(env, "BASIT_BASE_REF") or _text(env, "BASIT_EVENT_BASE_SHA")
    head = (
        _text(env, "BASIT_HEAD_REF")
        or _text(env, "BASIT_EVENT_HEAD_SHA")
        or "HEAD"
    )
    if not base:
        raise ActionInputError(
            "changed-file modes require base-ref or a pull_request event base SHA"
        )
    return base, head


def load_inputs(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    source = os.environ if env is None else env
    workspace_raw = _text(source, "GITHUB_WORKSPACE")
    action_root_raw = _text(source, "GITHUB_ACTION_PATH")
    if not workspace_raw or not action_root_raw:
        raise ActionInputError("GITHUB_WORKSPACE and GITHUB_ACTION_PATH are required")
    workspace = Path(workspace_raw).resolve()
    action_root = Path(action_root_raw).resolve()
    if not workspace.is_dir():
        raise ActionInputError("GITHUB_WORKSPACE must be an existing directory")
    if not action_root.is_dir():
        raise ActionInputError("GITHUB_ACTION_PATH must be an existing directory")

    mode = _choice(source, "BASIT_MODE", ALLOWED_MODES, "added-lines")
    fail_on = _choice(source, "BASIT_FAIL_ON", ALLOWED_SEVERITIES, "high")
    new_only = _boolean(source, "BASIT_NEW_ONLY", False)
    annotations = _boolean(source, "BASIT_ANNOTATIONS", True)
    max_annotations = _integer(source, "BASIT_MAX_ANNOTATIONS", 10, 0, 50)
    scan_path = _workspace_path(
        workspace,
        _text(source, "BASIT_PATH", "."),
        "path",
        must_exist=True,
        directory=True,
    )
    report_path = _workspace_path(
        workspace,
        _text(source, "BASIT_REPORT_PATH", ".agent-system/action-report.json"),
        "report-path",
    )
    sarif_path = _workspace_path(
        workspace,
        _text(source, "BASIT_SARIF_PATH", ".agent-system/action-results.sarif"),
        "sarif-path",
    )
    baseline = _optional_workspace_argument(
        source, "BASIT_BASELINE", workspace, "baseline"
    )
    config = _optional_workspace_argument(source, "BASIT_CONFIG", workspace, "config")
    policy = _optional_workspace_argument(source, "BASIT_POLICY", workspace, "policy")
    if baseline and not new_only:
        raise ActionInputError("baseline requires new-only=true")
    base_ref, head_ref = resolve_refs(source, mode)
    return {
        "workspace": workspace,
        "action_root": action_root,
        "mode": mode,
        "fail_on": fail_on,
        "new_only": new_only,
        "annotations": annotations,
        "max_annotations": max_annotations,
        "scan_path": scan_path,
        "report_path": report_path,
        "sarif_path": sarif_path,
        "baseline": baseline,
        "config": config,
        "policy": policy,
        "base_ref": base_ref,
        "head_ref": head_ref,
    }


def build_command(settings: Mapping[str, Any]) -> list[str]:
    action_root = Path(settings["action_root"])
    workspace = Path(settings["workspace"])
    scan_path = str(settings["scan_path"])
    report_path = str(settings["report_path"])
    audit_path = str(
        _workspace_path(
            workspace,
            ".agent-system/action-audit.jsonl",
            "audit path",
        )
    )
    common: list[str] = [
        scan_path,
        "--format",
        "json",
        "--output",
        report_path,
        "--fail-on",
        str(settings["fail_on"]),
    ]
    for flag, key in (
        ("--config", "config"),
        ("--policy", "policy"),
        ("--baseline", "baseline"),
    ):
        if settings.get(key):
            common.extend([flag, str(settings[key])])
    if settings["new_only"]:
        common.append("--new-only")

    mode = settings["mode"]
    if mode == "added-lines":
        command = [
            sys.executable,
            str(action_root / "agent_changed_lines.py"),
            *common,
            "--changed-from",
            str(settings["base_ref"]),
            "--changed-to",
            str(settings["head_ref"]),
            "--audit-log",
            audit_path,
        ]
    else:
        command = [
            sys.executable,
            str(action_root / "agent_system.py"),
            "--audit-log",
            audit_path,
            "scan",
            *common,
        ]
        if mode == "changed-files":
            command.extend(
                [
                    "--changed-from",
                    str(settings["base_ref"]),
                    "--changed-to",
                    str(settings["head_ref"]),
                ]
            )
    return command


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", [])
    results = []
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id", "BAS000"))
        title = str(finding.get("title", rule_id))
        severity = str(finding.get("severity", "medium")).lower()
        fix = str(finding.get("fix", "")).strip()
        path = str(finding.get("path", ""))
        line = max(1, int(finding.get("line", 1)))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": title.replace(" ", ""),
                "shortDescription": {"text": title},
                "help": {"text": fix or "Review and remediate this finding."},
                "properties": {"severity": severity},
            },
        )
        message = f"{rule_id}: {title}"
        if fix:
            message += f". {fix}"
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if severity in {"critical", "high"} else (
                    "warning" if severity == "medium" else "note"
                ),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": path},
                            "region": {"startLine": line},
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": str(
                        finding.get("fingerprint", rule_id)
                    )
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Basit Agent System",
                        "informationUri": "https://github.com/abdulbasit742/ai-agent-system",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
                "properties": dict(report.get("summary", {})),
            }
        ],
    }


def _escape_command_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_command_property(value: str) -> str:
    return (
        _escape_command_data(value)
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def annotation_lines(
    findings: list[Mapping[str, Any]],
    limit: int,
) -> list[str]:
    output = []
    for finding in findings[:limit]:
        severity = str(finding.get("severity", "medium")).lower()
        kind = SEVERITY_TO_ANNOTATION.get(severity, "warning")
        path = _escape_command_property(str(finding.get("path", "")))
        line = max(1, int(finding.get("line", 1)))
        rule_id = str(finding.get("rule_id", "BAS000"))
        title = _escape_command_property(f"{rule_id}: {finding.get('title', rule_id)}")
        fix = str(finding.get("fix", "")).strip()
        message = f"{rule_id}: {finding.get('title', rule_id)}"
        if fix:
            message += f". {fix}"
        output.append(
            f"::{kind} file={path},line={line},title={title}::"
            f"{_escape_command_data(message)}"
        )
    return output


def _safe_markdown(value: Any) -> str:
    text = " ".join(str(value).split())
    return text.replace("|", "\\|").replace("`", "\\`")


def summary_markdown(report: Mapping[str, Any], mode: str, limit: int = 20) -> str:
    findings = list(report.get("findings", []))
    summary = dict(report.get("summary", {}))
    lines = [
        "## Basit Agent System",
        "",
        f"**Mode:** `{_safe_markdown(mode)}`",
        "",
        "| Result | Count |",
        "| --- | ---: |",
        f"| Reported findings | {len(findings)} |",
        f"| Suppressed | {int(summary.get('suppressed', 0) or 0)} |",
    ]
    if "new" in summary:
        lines.extend(
            [
                f"| New | {int(summary.get('new', 0) or 0)} |",
                f"| Existing | {int(summary.get('existing', 0) or 0)} |",
                f"| Resolved | {int(summary.get('resolved', 0) or 0)} |",
            ]
        )
    if findings:
        lines.extend(
            [
                "",
                "### Findings",
                "",
                "| Severity | Rule | Location | Remediation |",
                "| --- | --- | --- | --- |",
            ]
        )
        for finding in findings[:limit]:
            lines.append(
                "| {severity} | {rule} | `{path}:{line}` | {fix} |".format(
                    severity=_safe_markdown(finding.get("severity", "")),
                    rule=_safe_markdown(finding.get("rule_id", "")),
                    path=_safe_markdown(finding.get("path", "")),
                    line=int(finding.get("line", 1)),
                    fix=_safe_markdown(
                        finding.get("fix", "Review and remediate this finding.")
                    ),
                )
            )
        if len(findings) > limit:
            lines.extend(["", f"{len(findings) - limit} additional finding(s) omitted."])
    lines.extend(
        [
            "",
            "Matched source previews are intentionally excluded from annotations and summaries.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(
    output_path: Path | None,
    report: Mapping[str, Any],
    report_path: str,
    sarif_path: str,
    status: int,
) -> None:
    if output_path is None:
        return
    summary = dict(report.get("summary", {}))
    values = {
        "status": "passed" if status == 0 else ("findings" if status == 1 else "error"),
        "finding-count": str(len(report.get("findings", []))),
        "suppressed-count": str(int(summary.get("suppressed", 0) or 0)),
        "new-count": str(int(summary.get("new", len(report.get("findings", []))) or 0)),
        "existing-count": str(int(summary.get("existing", 0) or 0)),
        "resolved-count": str(int(summary.get("resolved", 0) or 0)),
        "report-path": report_path,
        "sarif-path": sarif_path,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise ActionInputError(f"unsafe output value for {key}")
            handle.write(f"{key}={value}\n")


def run(settings: Mapping[str, Any], env: Mapping[str, str] | None = None) -> int:
    command = build_command(settings)
    workspace = Path(settings["workspace"])
    report_path = Path(settings["report_path"])
    sarif_path = Path(settings["sarif_path"])
    for generated in (report_path, sarif_path):
        if generated.exists():
            if not generated.is_file():
                print(f"Action error: output path is not a regular file: {generated}", file=sys.stderr)
                return 2
            generated.unlink()
    try:
        completed = subprocess.run(
            command,
            cwd=workspace,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as exc:
        print(f"Action error: unable to start scanner: {exc}", file=sys.stderr)
        return 2
    if completed.stdout.strip():
        print(completed.stdout.rstrip())
    if completed.stderr.strip():
        print(completed.stderr.rstrip(), file=sys.stderr)
    if not report_path.exists():
        return completed.returncode if completed.returncode else 2

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Action error: unable to read scanner report: {exc}", file=sys.stderr)
        return 2
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        print("Action error: scanner report has an invalid structure", file=sys.stderr)
        return 2

    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(
        json.dumps(report_to_sarif(report), indent=2) + "\n",
        encoding="utf-8",
    )
    if settings["annotations"]:
        for line in annotation_lines(report["findings"], settings["max_annotations"]):
            print(line)
        omitted = len(report["findings"]) - min(
            len(report["findings"]), settings["max_annotations"]
        )
        if omitted:
            print(
                "::notice title=Basit Agent System::"
                f"{omitted} additional finding(s) are available in the report."
            )

    environment = os.environ if env is None else env
    summary_file = _text(environment, "GITHUB_STEP_SUMMARY")
    if summary_file:
        Path(summary_file).parent.mkdir(parents=True, exist_ok=True)
        with Path(summary_file).open("a", encoding="utf-8") as handle:
            handle.write(summary_markdown(report, str(settings["mode"])))

    output_file = _text(environment, "GITHUB_OUTPUT")
    write_outputs(
        Path(output_file) if output_file else None,
        report,
        _relative(workspace, report_path),
        _relative(workspace, sarif_path),
        completed.returncode,
    )
    return completed.returncode


def main() -> int:
    try:
        settings = load_inputs()
        return run(settings)
    except ActionInputError as exc:
        print(f"Action input error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
