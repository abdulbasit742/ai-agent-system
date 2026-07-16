import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import agent_system as app


class BaselineCliTests(unittest.TestCase):
    def create_baseline(self, root: Path) -> tuple[int, dict]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = app.main([
                "--audit-log", str(root / "audit.jsonl"),
                "baseline", str(root / ".agent-system-baseline.json"),
                "--create", "--scan-path", str(root),
            ])
        return status, json.loads(output.getvalue())

    def scan_new_only(self, root: Path) -> tuple[int, dict]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = app.main([
                "--audit-log", str(root / "audit.jsonl"),
                "scan", str(root), "--new-only", "--format", "json",
            ])
        return status, json.loads(output.getvalue())

    def test_existing_high_finding_passes_new_only_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "legacy.txt").write_text("sk-" + "a" * 30)
            create_status, created = self.create_baseline(root)
            scan_status, report = self.scan_new_only(root)
        self.assertEqual(0, create_status)
        self.assertEqual(1, created["findings"])
        self.assertEqual(0, scan_status)
        self.assertEqual(0, report["summary"]["new"])
        self.assertEqual(1, report["summary"]["existing"])
        self.assertEqual([], report["findings"])

    def test_new_high_finding_fails_new_only_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "legacy.txt").write_text("sk-" + "a" * 30)
            self.create_baseline(root)
            (root / "regression.txt").write_text("sk-" + "b" * 30)
            scan_status, report = self.scan_new_only(root)
        self.assertEqual(1, scan_status)
        self.assertEqual(1, report["summary"]["new"])
        self.assertEqual(1, report["summary"]["existing"])
        self.assertEqual("new", report["findings"][0]["baseline_state"])

    def test_changed_rule_scope_rejects_stale_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_baseline(root)
            (root / ".agent-system.json").write_text(json.dumps({
                "version": 1,
                "enabled_packs": ["core", "boundaries"],
                "disabled_rules": [],
            }))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = app.main([
                    "--audit-log", str(root / "audit.jsonl"),
                    "scan", str(root), "--new-only", "--format", "json",
                ])
        self.assertEqual(2, status)
        self.assertIn("controls do not match", error.getvalue())

    def test_baseline_create_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / ".agent-system-baseline.json"
            path.write_text("do not replace")
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = app.main([
                    "baseline", str(path), "--create", "--scan-path", str(root),
                ])
            preserved = path.read_text()
        self.assertEqual(2, status)
        self.assertEqual("do not replace", preserved)


if __name__ == "__main__":
    unittest.main()
