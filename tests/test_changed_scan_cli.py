import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import agent_system as app


class ChangedScanCliTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def init(self, root: Path) -> None:
        self.git(root, "init", "-b", "main")
        self.git(root, "config", "user.email", "tests@example.invalid")
        self.git(root, "config", "user.name", "Tests")

    def scan(self, root: Path, base: str, *extra: str):
        output = io.StringIO()
        error = io.StringIO()
        audit = root.parent / f"{root.name}-audit.jsonl"
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = app.main([
                "--audit-log", str(audit),
                "scan", str(root),
                "--changed-from", base,
                "--format", "json",
                *extra,
            ])
        report = json.loads(output.getvalue()) if output.getvalue() else None
        return status, report, error.getvalue()

    def test_unchanged_legacy_finding_is_outside_changed_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            (root / "legacy.txt").write_text("sk-" + "a" * 30)
            (root / "app.py").write_text("safe = True\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            (root / "app.py").write_text("safe = False\n")
            self.git(root, "commit", "-am", "safe change")
            status, report, _ = self.scan(root, base)
        self.assertEqual(0, status)
        self.assertEqual([], report["findings"])
        self.assertEqual(1, report["scope"]["changed"])
        self.assertEqual("app.py", report["scope"]["files"][0]["path"])

    def test_new_high_finding_in_changed_file_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            (root / "app.py").write_text("safe = True\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            (root / "app.py").write_text("sk-" + "b" * 30)
            self.git(root, "commit", "-am", "regression")
            status, report, _ = self.scan(root, base)
        self.assertEqual(1, status)
        self.assertEqual({"BAS003"}, {item["rule_id"] for item in report["findings"]})

    def test_changed_new_only_marks_only_deleted_scoped_baseline_entry_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            (root / "legacy.txt").write_text("sk-" + "a" * 30)
            (root / "remove.txt").write_text("sk-" + "b" * 30)
            (root / "safe.py").write_text("safe = True\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            with contextlib.redirect_stdout(io.StringIO()):
                create_status = app.main([
                    "--audit-log", str(root.parent / "baseline-audit.jsonl"),
                    "baseline", str(root / ".agent-system-baseline.json"),
                    "--create", "--scan-path", str(root),
                ])
            (root / "remove.txt").unlink()
            (root / "safe.py").write_text("safe = False\n")
            self.git(root, "add", "-u")
            self.git(root, "commit", "-m", "delete one finding")
            status, report, _ = self.scan(root, base, "--new-only", "--show-existing")
        self.assertEqual(0, create_status)
        self.assertEqual(0, status)
        self.assertEqual(0, report["summary"]["new"])
        self.assertEqual(0, report["summary"]["existing"])
        self.assertEqual(1, report["summary"]["resolved"])
        self.assertEqual("remove.txt", report["resolved_findings"][0]["path"])

    def test_rename_of_baselined_finding_is_new_and_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            (root / "old.txt").write_text("sk-" + "c" * 30)
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            with contextlib.redirect_stdout(io.StringIO()):
                app.main([
                    "--audit-log", str(root.parent / "rename-audit.jsonl"),
                    "baseline", str(root / ".agent-system-baseline.json"),
                    "--create", "--scan-path", str(root),
                ])
            self.git(root, "mv", "old.txt", "new.txt")
            self.git(root, "commit", "-m", "rename")
            status, report, _ = self.scan(root, base, "--new-only", "--show-existing")
        self.assertEqual(1, status)
        self.assertEqual("new.txt", report["findings"][0]["path"])
        self.assertEqual("old.txt", report["resolved_findings"][0]["path"])

    def test_changed_to_without_changed_from_is_rejected(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            status = app.main(["scan", ".", "--changed-to", "HEAD"])
        self.assertEqual(2, status)
        self.assertIn("requires --changed-from", error.getvalue())


if __name__ == "__main__":
    unittest.main()
