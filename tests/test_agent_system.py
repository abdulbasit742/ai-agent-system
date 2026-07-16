import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import agent_system as a


class Tests(unittest.TestCase):
    def test_guard(self):
        self.assertFalse(a.guard("git reset --hard HEAD~1")["allowed"])
        self.assertTrue(a.guard("python -m unittest")["allowed"])

    def test_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            risky = (
                'allow_' + 'origins=["*"]\n'
                + 'auth_' + 'required=false\n'
                + 'subprocess.' + 'run(x, shell=True)\n'
            )
            (root / "server.py").write_text(risky)
            findings = a.scan(root)
            ids = {item["rule_id"] for item in findings}
            self.assertTrue({"BAS010", "BAS011", "BAS012"}.issubset(ids))
            self.assertTrue(all(len(item["fingerprint"]) == 64 for item in findings))

    def test_scan_respects_enabled_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text('allow_' + 'origins=["*"]\n')
            findings = a.scan(root, {"BAS000", "BAS001", "BAS002", "BAS003"})
            self.assertNotIn("BAS010", {item["rule_id"] for item in findings})

    def test_scrub(self):
        token = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
        output, matches = a.scrub("token=" + token + "\nali@example.com")
        self.assertNotIn(token, output)
        self.assertGreaterEqual(len(matches), 2)

    def test_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            a.append_audit(path, "x", {"ok": True})
            a.append_audit(path, "y", {"ok": True})
            self.assertEqual(a.verify_audit(path), (True, 2))

    def test_cli_suppressed_high_finding_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.txt").write_text("sk-" + "x" * 30)
            policy = {
                "version": 1,
                "suppressions": [{
                    "id": "fixture-token",
                    "rule_id": "BAS003",
                    "path": "fixture.txt",
                    "owner": "security-team",
                    "reason": "Synthetic token used by an isolated test fixture.",
                    "expires": "2099-12-31"
                }]
            }
            (root / ".agent-system-policy.json").write_text(json.dumps(policy))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = a.main(["--audit-log", str(root / "audit.jsonl"), "scan", str(root), "--format", "json"])
            report = json.loads(output.getvalue())
        self.assertEqual(0, status)
        self.assertEqual(0, report["summary"]["active"])
        self.assertEqual(1, report["summary"]["suppressed"])

    def test_cli_auto_discovers_rule_pack_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / "workflow.yml"
            workflow.write_text("permissions: write-all\n")
            config = {
                "version": 1,
                "enabled_packs": ["core", "boundaries"],
                "disabled_rules": []
            }
            (root / ".agent-system.json").write_text(json.dumps(config))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = a.main(["--audit-log", str(root / "audit.jsonl"), "scan", str(root), "--format", "json"])
            report = json.loads(output.getvalue())
        self.assertEqual(0, status)
        self.assertEqual(["core", "boundaries"], report["summary"]["enabled_packs"])
        self.assertNotIn("BAS020", {item["rule_id"] for item in report["findings"]})

    def test_cli_expired_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = {
                "version": 1,
                "suppressions": [{
                    "id": "old-exception",
                    "rule_id": "BAS003",
                    "path": "fixture.txt",
                    "owner": "security-team",
                    "reason": "Temporary exception that must now be reviewed.",
                    "expires": "2000-01-01"
                }]
            }
            path = root / "policy.json"
            path.write_text(json.dumps(policy))
            with contextlib.redirect_stdout(io.StringIO()):
                status = a.main(["policy", str(path)])
        self.assertEqual(1, status)

    def test_policy_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text("do not replace")
            with contextlib.redirect_stderr(io.StringIO()):
                status = a.main(["policy", str(path), "--init"])
            self.assertEqual(2, status)
            self.assertEqual("do not replace", path.read_text())

    def test_config_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("do not replace")
            with contextlib.redirect_stderr(io.StringIO()):
                status = a.main(["config", str(path), "--init"])
            self.assertEqual(2, status)
            self.assertEqual("do not replace", path.read_text())


if __name__ == "__main__":
    unittest.main()
