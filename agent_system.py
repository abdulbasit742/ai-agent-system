#!/usr/bin/env python3
"""Basit Agent System: dependency-free AI agent control plane."""
from __future__ import annotations

import argparse, hashlib, json, re, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

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
COMPILED_RULES = [(a, b, c, re.compile(d, re.I | re.M), e, f) for a, b, c, d, e, f in RULES]

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
COMPILED_COMMANDS = [(a, b, re.compile(c, re.I), d, e) for a, b, c, d, e in COMMAND_RULES]

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


def candidates(root: Path):
    if root.is_file():
        yield root; return
    for path in root.rglob("*"):
        if path.is_file() and not any(part in IGNORED for part in path.parts):
            if path.name in SENSITIVE_FILES or path.suffix.lower() in TEXT_EXT or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
                yield path


def scan(root: Path):
    root, out = root.resolve(), []
    base = root if root.is_dir() else root.parent
    for path in candidates(root):
        rel = path.relative_to(base).as_posix()
        if path.name in SENSITIVE_FILES or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
            out.append({"rule_id": "BAS000", "severity": "high", "title": "Sensitive artifact", "path": rel, "line": 1, "preview": path.name, "fix": "Remove it, rotate credentials, and add an ignore rule."})
        try:
            if path.stat().st_size > 2_000_000: continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError: continue
        for rid, sev, title, pattern, fix, secret in COMPILED_RULES:
            if rid.startswith("BAS02") and path.suffix.lower() not in {".yml", ".yaml"}: continue
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                fp = hashlib.sha256(f"{rid}\0{rel}\0{line}\0{match.group(0)[:100]}".encode()).hexdigest()
                out.append({"rule_id": rid, "severity": sev, "title": title, "path": rel, "line": line, "preview": masked(match.group(0), secret), "fix": fix, "fingerprint": fp})
    return sorted(out, key=lambda x: (-SEVERITY[x["severity"]], x["path"], x["line"], x["rule_id"]))


def guard(command: str):
    normalized = " ".join(command.strip().split())
    for rid, sev, pattern, reason, alternative in COMPILED_COMMANDS:
        if pattern.search(normalized):
            return {"allowed": False, "rule_id": rid, "severity": sev, "reason": reason, "safer_alternative": alternative}
    return {"allowed": bool(normalized), "rule_id": None, "severity": None, "reason": "No blocked destructive pattern matched." if normalized else "No command provided.", "safer_alternative": "Use least privilege and a dry run when available."}


def scrub(text: str):
    matches = []
    for kind, pattern in SCRUB_RULES:
        for m in pattern.finditer(text): matches.append((m.start(), m.end(), kind, text.count("\n", 0, m.start()) + 1, masked(m.group(0), True)))
    matches.sort(); output, cursor = [], 0
    for start, end, kind, _line, _preview in matches:
        if start < cursor: continue
        output += [text[cursor:start], f"[REDACTED:{kind}]"]; cursor = end
    output.append(text[cursor:])
    return "".join(output), matches


def append_audit(path: Path, event: str, details: dict):
    prev = "0" * 64
    if path.exists():
        lines = [x for x in path.read_text().splitlines() if x.strip()]
        if lines: prev = json.loads(lines[-1])["hash"]
    record = {"time": datetime.now(timezone.utc).isoformat(), "event": event, "details": details, "previous_hash": prev}
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode(); record["hash"] = hashlib.sha256(prev.encode() + raw).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f: f.write(json.dumps(record, sort_keys=True) + "\n")


def verify_audit(path: Path):
    prev, count = "0" * 64, 0
    if not path.exists(): return True, 0
    for count, line in enumerate(path.read_text().splitlines(), 1):
        record = json.loads(line); stored = record.pop("hash")
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        if record["previous_hash"] != prev or stored != hashlib.sha256(prev.encode() + raw).hexdigest(): return False, count
        prev = stored
    return True, count


def load_integrations(root: Path): return json.loads((root / "integrations.lock.json").read_text())["integrations"]


def main(argv=None):
    p = argparse.ArgumentParser(prog="agent-system"); p.add_argument("--audit-log", type=Path, default=Path(".agent-system/audit.jsonl")); sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("path", type=Path, nargs="?", default=Path(".")); s.add_argument("--format", choices=["text", "json", "sarif"], default="text"); s.add_argument("--fail-on", choices=list(SEVERITY), default="high"); s.add_argument("--output", type=Path)
    g = sub.add_parser("guard"); g.add_argument("command", nargs=argparse.REMAINDER)
    r = sub.add_parser("scrub"); r.add_argument("source", type=Path); r.add_argument("--output", type=Path)
    sub.add_parser("skills"); sub.add_parser("agents"); sub.add_parser("doctor"); a = sub.add_parser("audit"); a.add_argument("--path", type=Path)
    run = sub.add_parser("run"); run.add_argument("integration"); run.add_argument("--approve", action="store_true"); run.add_argument("args", nargs=argparse.REMAINDER)
    args = p.parse_args(argv); root = Path(__file__).resolve().parent
    if args.cmd == "scan":
        findings = scan(args.path); append_audit(args.audit_log, "scan", {"path": str(args.path), "findings": len(findings)})
        if args.format == "json": report = json.dumps({"findings": findings}, indent=2)
        elif args.format == "sarif":
            results = [{"ruleId": f["rule_id"], "level": "error" if SEVERITY[f["severity"]] >= 3 else "warning", "message": {"text": f["title"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}, "region": {"startLine": f["line"]}}}], "partialFingerprints": {"primaryLocationLineHash": f.get("fingerprint", f["rule_id"])}} for f in findings]
            report = json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Basit Agent System"}}, "results": results}]}, indent=2)
        else:
            report = "\n".join([f"Basit Agent System: {len(findings)} finding(s)"] + [f"- {f['severity'].upper()} {f['rule_id']} {f['path']}:{f['line']} {f['title']}\n  preview: {f['preview']}\n  fix: {f['fix']}" for f in findings])
        if args.output: args.output.write_text(report + "\n")
        else: print(report)
        return int(any(SEVERITY[f["severity"]] >= SEVERITY[args.fail_on] for f in findings))
    if args.cmd == "guard":
        decision = guard(" ".join(args.command)); append_audit(args.audit_log, "guard", decision); print(json.dumps(decision, indent=2)); return int(not decision["allowed"])
    if args.cmd == "scrub":
        text = args.source.read_text(errors="replace"); redacted, matches = scrub(text); print(f"{len(matches)} sensitive match(es)")
        for _s, _e, kind, line, preview in matches: print(f"- {kind} line {line}: {preview}")
        if args.output: args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(redacted); print(f"Sanitized copy: {args.output}")
        append_audit(args.audit_log, "scrub", {"source": str(args.source), "matches": len(matches), "output": str(args.output) if args.output else None}); return int(bool(matches) and not args.output)
    if args.cmd == "skills": print("\n".join(SKILLS)); return 0
    if args.cmd == "agents":
        for name, pipeline in AGENTS.items(): print(f"{name}: {' -> '.join(pipeline)}")
        return 0
    if args.cmd == "doctor":
        missing = 0
        for item in load_integrations(root):
            present = (root / item["path"]).exists(); missing += not present; print(f"{'OK' if present else 'MISSING'} {item['name']} @ {item['commit'][:12]}")
        return int(bool(missing))
    if args.cmd == "audit": valid, count = verify_audit(args.path or args.audit_log); print(f"{'VALID' if valid else 'INVALID'} {count} record(s)"); return int(not valid)
    if args.cmd == "run":
        items = {x["name"]: x for x in load_integrations(root)}
        commands = {"agent-boundary-guard": ["python", "-m", "agent_boundary_guard", "scan", "."], "mcp-policy-guard": ["python", "-m", "mcp_policy_guard", "scan", "."], "promptleak-scrubber": ["python", "-m", "promptleak_scrubber", "scan", "."], "repo-risk-radar": ["python", "-m", "repo_risk_radar", "scan", "."], "workflow-warden": ["python", "-m", "workflow_warden", "."], "social-autopilot": ["npm", "run", "dry-run"]}
        if args.integration not in commands or args.integration not in items: print("Unknown or catalog-only integration", file=sys.stderr); return 2
        command = commands[args.integration] + args.args; decision = guard(" ".join(command)); append_audit(args.audit_log, "dispatch", {"integration": args.integration, "command": command, **decision})
        if not decision["allowed"]: print(json.dumps(decision, indent=2)); return 1
        cwd = root / items[args.integration]["path"]; print(f"DRY RUN: cwd={cwd} command={' '.join(command)}")
        if not args.approve: print("Nothing executed; add --approve after review."); return 0
        if not cwd.exists(): print("Integration missing; run scripts/bootstrap_integrations.py", file=sys.stderr); return 2
        return subprocess.run(command, cwd=cwd, check=False).returncode
    return 2


if __name__ == "__main__": raise SystemExit(main())
