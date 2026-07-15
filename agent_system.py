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

from agent_policy import DEFAULT_POLICY_NAME, PolicyError, apply_policy, discover_policy, load_policy, policy_template

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
IGNORED = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
TEXT_EXT = {".py", ".js", ".ts", ".json", ".jsonl", ".toml", ".yaml", ".yml", ".md", ".txt", ".log", ".sh", ".ps1", ".env"}
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
COMPILED_RULES = [(rid, sev, title, re.compile(pattern, re.I | re.M), fix, secret) for rid, sev, title, pattern, fix, secret in RULES]

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
COMPILED_COMMANDS = [(rid, sev, re.compile(pattern, re.I), reason, alternative) for rid, sev, pattern, reason, alternative in COMMAND_RULES]

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


def scan(root: Path):
    root, out = root.resolve(), []
    base = root if root.is_dir() else root.parent
    for path in candidates(root):
        rel = path.relative_to(base).as_posix()
        if path.name in SENSITIVE_FILES or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
            out.append({
                "rule_id": "BAS000", "severity": "high", "title": "Sensitive artifact",
                "path": rel, "line": 1, "preview": path.name,
                "fix": "Remove it, rotate credentials, and add an ignore rule.",
                "fingerprint": fingerprint("BAS000", rel, 1, path.name),
            })
        try:
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rid, sev, title, pattern, fix, secret in COMPILED_RULES:
            if rid.startswith("BAS02") and path.suffix.lower() not in {".yml", ".yaml"}:
                continue
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                out.append({
                    "rule_id": rid, "severity": sev, "title": title, "path": rel, "line": line,
                    "preview": masked(match.group(0), secret), "fix": fix,
                    "fingerprint": fingerprint(rid, rel, line, match.group(0)),
                })
    return sorted(out, key=lambda item: (-SEVERITY[item["severity"]], item["path"], item["line"], item["rule_id"]))


def guard(command: str):
    normalized = " ".join(command.strip().split())
    for rid, sev, pattern, reason, alternative in COMPILED_COMMANDS:
        if pattern.search(normalized):
            return {"allowed": False, "rule_id": rid, "severity": sev, "reason": reason, "safer_alternative": alternative}
    return {"allowed": bool(normalized), "rule_id": None, "severity": None, "reason": "No blocked destructive pattern matched." if normalized else "No command provided.", "safer_alternative": "Use least privilege and a dry run when available."}


def scrub(text: str):
    matches = []
    for kind, pattern in SCRUB_RULES:
        for match in pattern.finditer(text):
            matches.append((match.start(), match.end(), kind, text.count("\n", 0, match.start()) + 1, masked(match.group(0), True)))
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
    prev = "0" * 64
    if path.exists():
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        if lines:
            prev = json.loads(lines[-1])["hash"]
    record = {"time": datetime.now(timezone.utc).isoformat(), "event": event, "details": details, "previous_hash": prev}
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    record["hash"] = hashlib.sha256(prev.encode() + raw).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def verify_audit(path: Path):
    prev, count = "0" * 64, 0
    if not path.exists():
        return True, 0
    for count, line in enumerate(path.read_text().splitlines(), 1):
        record = json.loads(line)
        stored = record.pop("hash")
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        if record["previous_hash"] != prev or stored != hashlib.sha256(prev.encode() + raw).hexdigest():
            return False, count
        prev = stored
    return True, count


def load_integrations(root: Path):
    return json.loads((root / "integrations.lock.json").read_text())["integrations"]


def render_scan(findings, suppressed, policy, output_format, show_suppressed):
    summary = {"active": len(findings), "suppressed": len(suppressed), "expired_suppressions": policy.get("expired_ids", [])}
    if output_format == "json":
        payload = {"findings": findings, "summary": summary}
        if show_suppressed:
            payload["suppressed"] = suppressed
        if policy.get("source"):
            payload["policy"] = {"source": policy["source"], "version": policy["version"]}
        return json.dumps(payload, indent=2)
    if output_format == "sarif":
        results = [{
            "ruleId": item["rule_id"],
            "level": "error" if SEVERITY[item["severity"]] >= 3 else "warning",
            "message": {"text": item["title"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": item["path"]}, "region": {"startLine": item["line"]}}}],
            "partialFingerprints": {"primaryLocationLineHash": item["fingerprint"]},
        } for item in findings]
        return json.dumps({
            "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Basit Agent System"}}, "results": results, "properties": summary}],
        }, indent=2)
    lines = [f"Basit Agent System: {len(findings)} active finding(s), {len(suppressed)} suppressed"]
    if policy.get("source"):
        lines.append(f"Policy: {policy['source']}")
    if policy.get("expired_ids"):
        lines.append("Expired suppressions: " + ", ".join(policy["expired_ids"]))
    lines.extend(f"- {item['severity'].upper()} {item['rule_id']} {item['path']}:{item['line']} {item['title']}\n  preview: {item['preview']}\n  fix: {item['fix']}" for item in findings)
    if show_suppressed:
        lines.extend(f"- SUPPRESSED {item['rule_id']} {item['path']}:{item['line']} by {item['suppression']['id']} until {item['suppression']['expires']}" for item in suppressed)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agent-system")
    parser.add_argument("--audit-log", type=Path, default=Path(".agent-system/audit.jsonl"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    scanner = sub.add_parser("scan")
    scanner.add_argument("path", type=Path, nargs="?", default=Path("."))
    scanner.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scanner.add_argument("--fail-on", choices=list(SEVERITY), default="high")
    scanner.add_argument("--output", type=Path)
    scanner.add_argument("--policy", type=Path)
    scanner.add_argument("--show-suppressed", action="store_true")

    gate = sub.add_parser("guard")
    gate.add_argument("command", nargs=argparse.REMAINDER)
    redactor = sub.add_parser("scrub")
    redactor.add_argument("source", type=Path)
    redactor.add_argument("--output", type=Path)
    sub.add_parser("skills")
    sub.add_parser("agents")
    sub.add_parser("doctor")
    audit = sub.add_parser("audit")
    audit.add_argument("--path", type=Path)
    policy_cmd = sub.add_parser("policy")
    policy_cmd.add_argument("path", type=Path, nargs="?", default=Path(DEFAULT_POLICY_NAME))
    policy_cmd.add_argument("--init", action="store_true")
    policy_cmd.add_argument("--force", action="store_true")
    runner = sub.add_parser("run")
    runner.add_argument("integration")
    runner.add_argument("--approve", action="store_true")
    runner.add_argument("args", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent

    if args.cmd == "scan":
        try:
            policy = load_policy(discover_policy(args.path, args.policy))
        except PolicyError as exc:
            print(f"Policy error: {exc}", file=sys.stderr)
            return 2
        active, suppressed = apply_policy(scan(args.path), policy)
        report = render_scan(active, suppressed, policy, args.format, args.show_suppressed)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report + "\n", encoding="utf-8")
        else:
            print(report)
        append_audit(args.audit_log, "scan", {"path": str(args.path), "active": len(active), "suppressed": len(suppressed), "policy": policy.get("source"), "expired_suppressions": policy.get("expired_ids", [])})
        threshold_failed = any(SEVERITY[item["severity"]] >= SEVERITY[args.fail_on] for item in active)
        return int(threshold_failed or bool(policy.get("expired_ids")))

    if args.cmd == "policy":
        if args.init:
            if args.path.exists() and not args.force:
                print(f"Refusing to overwrite existing policy: {args.path}", file=sys.stderr)
                return 2
            args.path.parent.mkdir(parents=True, exist_ok=True)
            args.path.write_text(json.dumps(policy_template(), indent=2) + "\n", encoding="utf-8")
            print(f"Created policy template: {args.path}")
            return 0
        try:
            policy = load_policy(args.path)
        except PolicyError as exc:
            print(f"Policy error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"source": policy["source"], "version": policy["version"], "suppressions": len(policy["suppressions"]), "expired_suppressions": policy["expired_ids"]}, indent=2))
        return int(bool(policy["expired_ids"]))

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
        append_audit(args.audit_log, "scrub", {"source": str(args.source), "matches": len(matches), "output": str(args.output) if args.output else None})
        return int(bool(matches) and not args.output)
    if args.cmd == "skills":
        print("\n".join(SKILLS)); return 0
    if args.cmd == "agents":
        for name, pipeline in AGENTS.items():
            print(f"{name}: {' -> '.join(pipeline)}")
        return 0
    if args.cmd == "doctor":
        missing = 0
        for item in load_integrations(root):
            present = (root / item["path"]).exists(); missing += not present
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
            print("Unknown or catalog-only integration", file=sys.stderr); return 2
        command = commands[args.integration] + args.args
        decision = guard(" ".join(command))
        append_audit(args.audit_log, "dispatch", {"integration": args.integration, "command": command, **decision})
        if not decision["allowed"]:
            print(json.dumps(decision, indent=2)); return 1
        cwd = root / items[args.integration]["path"]
        print(f"DRY RUN: cwd={cwd} command={' '.join(command)}")
        if not args.approve:
            print("Nothing executed; add --approve after review."); return 0
        if not cwd.exists():
            print("Integration missing; run scripts/bootstrap_integrations.py", file=sys.stderr); return 2
        return subprocess.run(command, cwd=cwd, check=False).returncode
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
