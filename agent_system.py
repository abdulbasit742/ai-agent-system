#!/usr/bin/env python3
"""Basit Agent System: dependency-free AI agent control plane."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_baseline import (
    DEFAULT_BASELINE_NAME,
    BaselineError,
    build_baseline,
    classify_findings,
    controls_digest,
    discover_baseline,
    load_baseline,
)
from agent_config import (
    DEFAULT_CONFIG_NAME,
    ConfigError,
    config_template,
    discover_config,
    load_config,
)
from agent_policy import (
    DEFAULT_POLICY_NAME,
    PolicyError,
    apply_policy,
    discover_policy,
    load_policy,
    policy_template,
)

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
IGNORED = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
TEXT_EXT = {
    ".py", ".js", ".ts", ".json", ".jsonl", ".toml", ".yaml", ".yml",
    ".md", ".txt", ".log", ".sh", ".ps1", ".env",
}
SENSITIVE_FILES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"}

RULES = [
    ("BAS001", "critical", "Private key material", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Remove it, rotate the key, and purge it from history.", True),
    ("BAS002", "high", "Hardcoded credential", r"(?m)^\s*(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9_./+\-=]{12,}", "Use an environment variable or secret manager.", True),
    ("BAS003", "high", "Provider token", r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b", "Revoke the token and replace it with a secret reference.", True),
    ("BAS010", "high", "Wildcard trust boundary", r"(?:allow(?:ed)?[_-]?(?:origins?|permissions?)|cors)[^\n]{0,80}[\"']\*[\"']", "Replace the wildcard with an explicit allowlist.", False),
    ("BAS011", "high", "Authentication disabled", r"(?:auth(?:entication)?[_-]?(?:required|enabled)|require[_-]?auth)\s*[:=]\s*(?:false|0|off)", "Require authentication outside isolated fixtures.", False),
    ("BAS012", "high", "Unsafe shell execution", r"subprocess\.(?:run|call|Popen)[^\n]{0,160}shell\s*=\s*True", "Use an argument array and explicit command allowlist.", False),
    ("BAS013", "medium", "Dynamic code execution", r"\b(?:eval|exec)\s*\(", "Replace it with explicit parsing.", False),
    ("BAS020", "high", "Workflow write-all", r"(?m)^\s*permissions\s*:\s*write-all\s*$", "Declare only required workflow permissions.", False),
    ("BAS021", "high", "Untrusted pull_request_target", r"(?m)^\s*pull_request_target\s*:", "Use pull_request or isolate privileged operations.", False),
    ("BAS022", "medium", "Self-hosted runner", r"runs-on\s*:\s*(?:\[[^\]]*self-hosted|self-hosted)", "Use isolated ephemeral runners for untrusted work.", False),
    ("BAS023", "high", "Remote script pipe", r"(?:curl|wget)[^\n|]{0,300}\|\s*(?:ba)?sh\b", "Download, verify, inspect, then execute.", False),
    ("BAS024", "medium", "Unpinned third-party action", r"uses\s*:\s*(?!actions/)[^\s@]+/[^\s@]+@(?![0-9a-f]{40}\b)[^\s#]+", "Pin the action to a reviewed commit SHA.", False),
    ("BAS030", "high", "Approval bypass instruction", r"(?:without|skip|remove|no)\s+(?:human\s+)?(?:approval|confirmation|review)[^\n]{0,120}(?:delete|deploy|publish|merge|execute|send|pay)", "Require explicit action-specific approval.", False),
]
COMPILED_RULES = [
    (rule_id, severity, title, re.compile(pattern, re.I | re.M), fix, secret)
    for rule_id, severity, title, pattern, fix, secret in RULES
]

COMMAND_RULES = [
    ("CMD001", "critical", r"(?:^|[;&|]\s*)rm\s+-[^\n]*r[^\n]*f[^\n]*(?:\s/\s*$|\s\$HOME\s*$)", "Recursive forced deletion targets a system or home root.", "Delete only a reviewed project subdirectory."),
    ("CMD002", "high", r"\bgit\s+reset\s+--hard\b", "This can destroy uncommitted work.", "Create a backup branch or stash first."),
    ("CMD003", "high", r"\bgit\s+clean\s+-[^\n]*(?:f[^\n]*d|d[^\n]*f)", "This can permanently remove untracked files.", "Run git clean -nd first."),
    ("CMD004", "high", r"\bgit\s+push\b[^\n]*(?:--force\b|-f\b)", "This can rewrite shared history.", "Use --force-with-lease after checking the remote."),
    ("CMD005", "critical", r"\b(?:drop\s+(?:database|table)|truncate\s+table)\b", "This can destroy database data.", "Back up and use a reviewed migration."),
    ("CMD006", "critical", r"\b(?:mkfs(?:\.|\s)|wipefs\b|dd\s+[^\n]*of=/dev/)", "This can destroy a disk or filesystem.", "Verify the exact device with read-only tools."),
    ("CMD007", "high", r"(?:curl|wget)[^\n|]{0,300}\|\s*(?:ba)?sh\b", "Remote code is piped directly to a shell.", "Download, verify checksum/signature, inspect, then run."),
    ("CMD008", "high", r"\b(?:kubectl\s+delete\s+namespace|docker\s+system\s+prune\s+-a|terraform\s+destroy)\b", "This has broad infrastructure side effects.", "Generate a dry-run/plan and require explicit approval."),
]
COMPILED_COMMANDS = [
    (rule_id, severity, re.compile(pattern, re.I), reason, alternative)
    for rule_id, severity, pattern, reason, alternative in COMMAND_RULES
]

SCRUB_RULES = [
    ("provider-key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b")),
    ("bearer-token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")),
    ("secret-assignment", re.compile(r"(?im)^\s*(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[^\s\"']{8,}")),
    ("email-address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone-number", re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)")),
    ("prompt-instruction", re.compile(r"(?im)^\s*(?:system|developer)\s*(?:prompt|instructions?)\s*[:=-]")),
]

SKILLS = ["intake", "spec", "tdd", "code-review", "security-scan", "trace-scrub", "safe-dispatch"]
AGENTS = {
    "repo-auditor": ["security-scan", "code-review"],
    "trace-sanitizer": ["trace-scrub"],
    "workflow-reviewer": ["security-scan", "spec"],
    "safe-social-drafter": ["safe-dispatch"],
    "engineering-orchestrator": ["intake", "spec", "tdd", "code-review", "security-scan"],
}


def masked(value: str, secret: bool) -> str:
    value = " ".join(value.strip().split())[:140]
    return f"{value[:4]}…{value[-2:]}" if secret and len(value) > 7 else value


def fingerprint(rule_id: str, path: str, line: int, evidence: str) -> str:
    return hashlib.sha256(f"{rule_id}\0{path}\0{line}\0{evidence[:100]}".encode()).hexdigest()


def candidates(root: Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file() and not any(part in IGNORED for part in path.parts):
            if path.name in SENSITIVE_FILES or path.suffix.lower() in TEXT_EXT | {".pem", ".key", ".p12", ".pfx"}:
                yield path


def scan(root: Path, enabled_rule_ids: set[str] | None = None):
    enabled = enabled_rule_ids or {"BAS000", *(rule[0] for rule in RULES)}
    root, findings = root.resolve(), []
    base = root if root.is_dir() else root.parent
    for path in candidates(root):
        relative_path = path.relative_to(base).as_posix()
        if "BAS000" in enabled and (path.name in SENSITIVE_FILES or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}):
            findings.append({
                "rule_id": "BAS000",
                "severity": "high",
                "title": "Sensitive artifact",
                "path": relative_path,
                "line": 1,
                "preview": path.name,
                "fix": "Remove it, rotate credentials, and add an ignore rule.",
                "fingerprint": fingerprint("BAS000", relative_path, 1, path.name),
            })
        try:
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rule_id, severity, title, pattern, fix, secret in COMPILED_RULES:
            if rule_id not in enabled:
                continue
            if rule_id.startswith("BAS02") and path.suffix.lower() not in {".yml", ".yaml"}:
                continue
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append({
                    "rule_id": rule_id,
                    "severity": severity,
                    "title": title,
                    "path": relative_path,
                    "line": line,
                    "preview": masked(match.group(0), secret),
                    "fix": fix,
                    "fingerprint": fingerprint(rule_id, relative_path, line, match.group(0)),
                })
    return sorted(
        findings,
        key=lambda item: (-SEVERITY[item["severity"]], item["path"], item["line"], item["rule_id"]),
    )


def guard(command: str):
    normalized = " ".join(command.strip().split())
    for rule_id, severity, pattern, reason, alternative in COMPILED_COMMANDS:
        if pattern.search(normalized):
            return {
                "allowed": False,
                "rule_id": rule_id,
                "severity": severity,
                "reason": reason,
                "safer_alternative": alternative,
            }
    return {
        "allowed": bool(normalized),
        "rule_id": None,
        "severity": None,
        "reason": "No blocked destructive pattern matched." if normalized else "No command provided.",
        "safer_alternative": "Use least privilege and a dry run when available.",
    }


def scrub(text: str):
    matches = []
    for kind, pattern in SCRUB_RULES:
        for match in pattern.finditer(text):
            matches.append((
                match.start(), match.end(), kind,
                text.count("\n", 0, match.start()) + 1,
                masked(match.group(0), True),
            ))
    matches.sort()
    output, cursor = [], 0
    for start, end, kind, _line, _preview in matches:
        if start < cursor:
            continue
        output.extend([text[cursor:start], f"[REDACTED:{kind}]"])
        cursor = end
    output.append(text[cursor:])
    return "".join(output), matches


def append_audit(path: Path, event: str, details: dict):
    previous_hash = "0" * 64
    if path.exists():
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        if lines:
            previous_hash = json.loads(lines[-1])["hash"]
    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "details": details,
        "previous_hash": previous_hash,
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    record["hash"] = hashlib.sha256(previous_hash.encode() + raw).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def verify_audit(path: Path):
    previous_hash, count = "0" * 64, 0
    if not path.exists():
        return True, 0
    for count, line in enumerate(path.read_text().splitlines(), 1):
        record = json.loads(line)
        stored_hash = record.pop("hash")
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        expected_hash = hashlib.sha256(previous_hash.encode() + raw).hexdigest()
        if record["previous_hash"] != previous_hash or stored_hash != expected_hash:
            return False, count
        previous_hash = stored_hash
    return True, count


def load_integrations(root: Path):
    return json.loads((root / "integrations.lock.json").read_text())["integrations"]


def render_scan(
    findings,
    suppressed,
    policy,
    config,
    output_format,
    show_suppressed,
    *,
    baseline=None,
    existing=None,
    resolved=None,
    show_existing=False,
):
    existing = existing or []
    resolved = resolved or []
    baseline_mode = baseline is not None
    active_count = len(findings) + len(existing) if baseline_mode else len(findings)
    summary = {
        "active": active_count,
        "suppressed": len(suppressed),
        "expired_suppressions": policy.get("expired_ids", []),
        "enabled_packs": config["enabled_packs"],
        "disabled_rules": config["disabled_rules"],
    }
    if baseline_mode:
        summary.update({
            "new": len(findings),
            "existing": len(existing),
            "resolved": len(resolved),
        })

    if output_format == "json":
        payload = {"findings": findings, "summary": summary}
        if show_suppressed:
            payload["suppressed"] = suppressed
        if baseline_mode:
            payload["baseline"] = {
                "source": baseline["source"],
                "version": baseline["version"],
                "generated_at": baseline["generated_at"],
                "baseline_sha256": baseline["baseline_sha256"],
            }
            if show_existing:
                payload["existing_findings"] = existing
                payload["resolved_findings"] = resolved
        if policy.get("source"):
            payload["policy"] = {"source": policy["source"], "version": policy["version"]}
        if config.get("source"):
            payload["config"] = {"source": config["source"], "version": config["version"]}
        return json.dumps(payload, indent=2)

    if output_format == "sarif":
        results = [{
            "ruleId": item["rule_id"],
            "level": "error" if SEVERITY[item["severity"]] >= 3 else "warning",
            "message": {"text": item["title"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item["path"]},
                    "region": {"startLine": item["line"]},
                }
            }],
            "partialFingerprints": {"primaryLocationLineHash": item["fingerprint"]},
        } for item in findings]
        return json.dumps({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "Basit Agent System"}},
                "results": results,
                "properties": summary,
            }],
        }, indent=2)

    if baseline_mode:
        lines = [
            f"Basit Agent System: {len(findings)} new, {len(existing)} existing, "
            f"{len(resolved)} resolved, {len(suppressed)} suppressed",
            f"Baseline: {baseline['source']}",
        ]
    else:
        lines = [
            f"Basit Agent System: {len(findings)} active finding(s), {len(suppressed)} suppressed",
        ]
    lines.append("Rule packs: " + ", ".join(config["enabled_packs"]))
    if config["disabled_rules"]:
        lines.append("Disabled rules: " + ", ".join(config["disabled_rules"]))
    if config.get("source"):
        lines.append(f"Config: {config['source']}")
    if policy.get("source"):
        lines.append(f"Policy: {policy['source']}")
    if policy.get("expired_ids"):
        lines.append("Expired suppressions: " + ", ".join(policy["expired_ids"]))
    prefix = "NEW " if baseline_mode else ""
    lines.extend(
        f"- {prefix}{item['severity'].upper()} {item['rule_id']} {item['path']}:{item['line']} {item['title']}\n"
        f"  preview: {item['preview']}\n  fix: {item['fix']}"
        for item in findings
    )
    if baseline_mode and show_existing:
        lines.extend(
            f"- EXISTING {item['severity'].upper()} {item['rule_id']} "
            f"{item['path']}:{item['line']} {item['title']}"
            for item in existing
        )
        lines.extend(
            f"- RESOLVED {item['severity'].upper()} {item['rule_id']} "
            f"{item['path']}:{item['line']}"
            for item in resolved
        )
    if show_suppressed:
        lines.extend(
            f"- SUPPRESSED {item['rule_id']} {item['path']}:{item['line']} "
            f"by {item['suppression']['id']} until {item['suppression']['expires']}"
            for item in suppressed
        )
    return "\n".join(lines)


def _write_template(path: Path, payload: dict, force: bool, label: str) -> int:
    if path.exists() and not force:
        print(f"Refusing to overwrite existing {label}: {path}", file=sys.stderr)
        return 2
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Created {label} template: {path}")
    return 0


def _load_controls(scan_path: Path, config_path: Path | None, policy_path: Path | None):
    config = load_config(discover_config(scan_path, config_path))
    policy = load_policy(discover_policy(scan_path, policy_path))
    return config, policy


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agent-system")
    parser.add_argument("--audit-log", type=Path, default=Path(".agent-system/audit.jsonl"))
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    scanner = subparsers.add_parser("scan")
    scanner.add_argument("path", type=Path, nargs="?", default=Path("."))
    scanner.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scanner.add_argument("--fail-on", choices=list(SEVERITY), default="high")
    scanner.add_argument("--output", type=Path)
    scanner.add_argument("--policy", type=Path)
    scanner.add_argument("--config", type=Path)
    scanner.add_argument("--baseline", type=Path)
    scanner.add_argument("--new-only", action="store_true")
    scanner.add_argument("--show-existing", action="store_true")
    scanner.add_argument("--show-suppressed", action="store_true")

    gate = subparsers.add_parser("guard")
    gate.add_argument("command", nargs=argparse.REMAINDER)
    redactor = subparsers.add_parser("scrub")
    redactor.add_argument("source", type=Path)
    redactor.add_argument("--output", type=Path)
    subparsers.add_parser("skills")
    subparsers.add_parser("agents")
    subparsers.add_parser("doctor")
    audit = subparsers.add_parser("audit")
    audit.add_argument("--path", type=Path)

    policy_command = subparsers.add_parser("policy")
    policy_command.add_argument("path", type=Path, nargs="?", default=Path(DEFAULT_POLICY_NAME))
    policy_command.add_argument("--init", action="store_true")
    policy_command.add_argument("--force", action="store_true")

    config_command = subparsers.add_parser("config")
    config_command.add_argument("path", type=Path, nargs="?", default=Path(DEFAULT_CONFIG_NAME))
    config_command.add_argument("--init", action="store_true")
    config_command.add_argument("--force", action="store_true")

    baseline_command = subparsers.add_parser("baseline")
    baseline_command.add_argument("path", type=Path, nargs="?", default=Path(DEFAULT_BASELINE_NAME))
    baseline_command.add_argument("--create", action="store_true")
    baseline_command.add_argument("--scan-path", type=Path, default=Path("."))
    baseline_command.add_argument("--policy", type=Path)
    baseline_command.add_argument("--config", type=Path)
    baseline_command.add_argument("--force", action="store_true")

    runner = subparsers.add_parser("run")
    runner.add_argument("integration")
    runner.add_argument("--approve", action="store_true")
    runner.add_argument("args", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent

    if args.cmd == "scan":
        if args.baseline and not args.new_only:
            print("Configuration error: --baseline requires --new-only", file=sys.stderr)
            return 2
        if args.show_existing and not args.new_only:
            print("Configuration error: --show-existing requires --new-only", file=sys.stderr)
            return 2
        try:
            config, policy = _load_controls(args.path, args.config, args.policy)
            active, suppressed = apply_policy(scan(args.path, set(config["enabled_rules"])), policy)
            baseline = None
            existing = []
            resolved = []
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
                reported, existing, resolved = classify_findings(active, baseline)
        except (BaselineError, ConfigError, PolicyError) as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2

        report = render_scan(
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
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report + "\n", encoding="utf-8")
        else:
            print(report)
        append_audit(args.audit_log, "scan", {
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
        })
        threshold_failed = any(
            SEVERITY[item["severity"]] >= SEVERITY[args.fail_on]
            for item in reported
        )
        return int(threshold_failed or bool(policy.get("expired_ids")))

    if args.cmd == "policy":
        if args.init:
            return _write_template(args.path, policy_template(), args.force, "policy")
        try:
            policy = load_policy(args.path)
        except PolicyError as exc:
            print(f"Policy error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({
            "source": policy["source"],
            "version": policy["version"],
            "suppressions": len(policy["suppressions"]),
            "expired_suppressions": policy["expired_ids"],
        }, indent=2))
        return int(bool(policy["expired_ids"]))

    if args.cmd == "config":
        if args.init:
            return _write_template(args.path, config_template(), args.force, "config")
        try:
            config = load_config(args.path)
        except ConfigError as exc:
            print(f"Config error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({
            "source": config["source"],
            "version": config["version"],
            "enabled_packs": config["enabled_packs"],
            "disabled_rules": config["disabled_rules"],
            "enabled_rules": config["enabled_rules"],
        }, indent=2))
        return 0

    if args.cmd == "baseline":
        if args.create:
            if args.path.exists() and not args.force:
                print(f"Refusing to overwrite existing baseline: {args.path}", file=sys.stderr)
                return 2
            try:
                config, policy = _load_controls(args.scan_path, args.config, args.policy)
            except (ConfigError, PolicyError) as exc:
                print(f"Configuration error: {exc}", file=sys.stderr)
                return 2
            if policy.get("expired_ids"):
                print("Configuration error: cannot create a baseline with expired suppressions", file=sys.stderr)
                return 2
            active, suppressed = apply_policy(
                scan(args.scan_path, set(config["enabled_rules"])),
                policy,
            )
            payload = build_baseline(active, config, policy, args.scan_path)
            args.path.parent.mkdir(parents=True, exist_ok=True)
            args.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            append_audit(args.audit_log, "baseline-create", {
                "path": str(args.path),
                "scan_path": str(args.scan_path),
                "findings": len(active),
                "suppressed": len(suppressed),
                "controls_sha256": payload["controls_sha256"],
                "baseline_sha256": payload["baseline_sha256"],
            })
            print(json.dumps({
                "created": str(args.path),
                "findings": len(active),
                "suppressed": len(suppressed),
                "controls_sha256": payload["controls_sha256"],
                "baseline_sha256": payload["baseline_sha256"],
            }, indent=2))
            return 0
        try:
            baseline = load_baseline(args.path)
        except BaselineError as exc:
            print(f"Baseline error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({
            "source": baseline["source"],
            "version": baseline["version"],
            "generated_at": baseline["generated_at"],
            "scan_root": baseline["scan_root"],
            "findings": len(baseline["findings"]),
            "controls_sha256": baseline["controls_sha256"],
            "baseline_sha256": baseline["baseline_sha256"],
        }, indent=2))
        return 0

    if args.cmd == "guard":
        decision = guard(" ".join(args.command))
        append_audit(args.audit_log, "guard", decision)
        print(json.dumps(decision, indent=2))
        return int(not decision["allowed"])
    if args.cmd == "scrub":
        text = args.source.read_text(errors="replace")
        redacted, matches = scrub(text)
        print(f"{len(matches)} sensitive match(es)")
        for _start, _end, kind, line, preview in matches:
            print(f"- {kind} line {line}: {preview}")
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(redacted)
            print(f"Sanitized copy: {args.output}")
        append_audit(args.audit_log, "scrub", {
            "source": str(args.source),
            "matches": len(matches),
            "output": str(args.output) if args.output else None,
        })
        return int(bool(matches) and not args.output)
    if args.cmd == "skills":
        print("\n".join(SKILLS))
        return 0
    if args.cmd == "agents":
        for name, pipeline in AGENTS.items():
            print(f"{name}: {' -> '.join(pipeline)}")
        return 0
    if args.cmd == "doctor":
        missing = 0
        for item in load_integrations(root):
            present = (root / item["path"]).exists()
            missing += not present
            print(f"{'OK' if present else 'MISSING'} {item['name']} @ {item['commit'][:12]}")
        return int(bool(missing))
    if args.cmd == "audit":
        valid, count = verify_audit(args.path or args.audit_log)
        print(f"{'VALID' if valid else 'INVALID'} {count} record(s)")
        return int(not valid)
    if args.cmd == "run":
        items = {item["name"]: item for item in load_integrations(root)}
        commands = {
            "agent-boundary-guard": ["python", "-m", "agent_boundary_guard", "scan", "."],
            "mcp-policy-guard": ["python", "-m", "mcp_policy_guard", "scan", "."],
            "promptleak-scrubber": ["python", "-m", "promptleak_scrubber", "scan", "."],
            "repo-risk-radar": ["python", "-m", "repo_risk_radar", "scan", "."],
            "workflow-warden": ["python", "-m", "workflow_warden", "."],
            "social-autopilot": ["npm", "run", "dry-run"],
        }
        if args.integration not in commands or args.integration not in items:
            print("Unknown or catalog-only integration", file=sys.stderr)
            return 2
        command = commands[args.integration] + args.args
        decision = guard(" ".join(command))
        append_audit(args.audit_log, "dispatch", {
            "integration": args.integration,
            "command": command,
            **decision,
        })
        if not decision["allowed"]:
            print(json.dumps(decision, indent=2))
            return 1
        working_directory = root / items[args.integration]["path"]
        print(f"DRY RUN: cwd={working_directory} command={' '.join(command)}")
        if not args.approve:
            print("Nothing executed; add --approve after review.")
            return 0
        if not working_directory.exists():
            print("Integration missing; run scripts/bootstrap_integrations.py", file=sys.stderr)
            return 2
        return subprocess.run(command, cwd=working_directory, check=False).returncode
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
