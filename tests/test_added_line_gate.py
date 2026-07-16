import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import agent_changed_lines as gate
import agent_system as core


class AddedLineGateTests(unittest.TestCase):
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

    def run_gate(self, root: Path, base: str, *extra: str):
        output = io.StringIO()
        error = io.StringIO()
        audit = root.parent / f"{root.name}-line-audit.jsonl"
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = gate.main([
                str(root),
                "--changed-from", base,
                "--format", "json",
                "--audit-log", str(audit),
                *extra,
            ])
        report = json.loads(output.getvalue()) if output.getvalue() else None
        return status, report, error.getvalue()

    def create_baseline(self, root: Path) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return core.main([
                "--audit-log", str(root.parent / f"{root.name}-baseline-audit.jsonl"),
                "baseline", str(root / ".agent-system-baseline.json"),
                "--create", "--scan-path", str(root),
            ])

    def test_unchanged_legacy_finding_in_modified_file_is_not_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            token = "sk-" + "a" * 30
            (root / "app.txt").write_text(token + "\nsafe = True\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            (root / "app.txt").write_text(token + "\nsafe = False\n")
            self.git(root, "commit", "-am", "change safe line")
            status, report, _ = self.run_gate(root, base)
        self.assertEqual(0, status)
        self.assertEqual([], report["findings"])
        self.assertEqual("git-added-lines", report["scope"]["type"])

    def test_new_token_on_added_line_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            (root / "app.txt").write_text("safe = True\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            (root / "app.txt").write_text("safe = True\n" + "sk-" + "b" * 30 + "\n")
            self.git(root, "commit", "-am", "add regression")
            status, report, _ = self.run_gate(root, base)
        self.assertEqual(1, status)
        self.assertEqual(1, len(report["findings"]))
        self.assertEqual(2, report["findings"][0]["line"])
        self.assertEqual("BAS003", report["findings"][0]["rule_id"])

    def test_inserting_safe_line_before_legacy_finding_does_not_reclassify_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            token = "sk-" + "c" * 30
            (root / "legacy.txt").write_text(token + "\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            baseline_status = self.create_baseline(root)
            (root / "legacy.txt").write_text("safe prefix\n" + token + "\n")
            self.git(root, "commit", "-am", "insert safe line")
            status, report, _ = self.run_gate(root, base, "--new-only", "--show-existing")
        self.assertEqual(0, baseline_status)
        self.assertEqual(0, status)
        self.assertEqual(0, report["summary"]["new"])
        self.assertEqual(0, report["summary"]["existing"])
        self.assertEqual(0, report["summary"]["resolved"])

    def test_deleting_baselined_file_marks_its_finding_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            (root / "remove.txt").write_text("sk-" + "d" * 30 + "\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            baseline_status = self.create_baseline(root)
            (root / "remove.txt").unlink()
            self.git(root, "add", "-u")
            self.git(root, "commit", "-m", "delete finding")
            status, report, _ = self.run_gate(root, base, "--new-only", "--show-existing")
        self.assertEqual(0, baseline_status)
        self.assertEqual(0, status)
        self.assertEqual(1, report["summary"]["resolved"])
        self.assertEqual("remove.txt", report["resolved_findings"][0]["path"])

    def test_pure_rename_does_not_create_new_or_resolved_line_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.init(root)
            (root / "old.txt").write_text("sk-" + "e" * 30 + "\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            baseline_status = self.create_baseline(root)
            self.git(root, "mv", "old.txt", "new.txt")
            self.git(root, "commit", "-m", "rename only")
            status, report, _ = self.run_gate(root, base, "--new-only", "--show-existing")
        self.assertEqual(0, baseline_status)
        self.assertEqual(0, status)
        self.assertEqual(0, report["summary"]["new"])
        self.assertEqual(0, report["summary"]["resolved"])


if __name__ == "__main__":
    unittest.main()
