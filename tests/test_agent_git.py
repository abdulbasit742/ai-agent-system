import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_git import GitDiffError, changed_scope


class GitScopeTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def repository(self, root: Path) -> str:
        self.git(root, "init", "-b", "main")
        self.git(root, "config", "user.email", "tests@example.invalid")
        self.git(root, "config", "user.name", "Tests")
        (root / "modified.py").write_text("modified base\n")
        (root / "deleted.py").write_text("delete me\n")
        (root / "old.py").write_text("rename me\n")
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "base")
        return self.git(root, "rev-parse", "HEAD")

    def test_modified_added_deleted_and_renamed_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = self.repository(root)
            (root / "modified.py").write_text("modified head\n")
            (root / "added file.py").write_text("new file\n")
            (root / "deleted.py").unlink()
            self.git(root, "mv", "old.py", "renamed.py")
            self.git(root, "add", "-A")
            self.git(root, "commit", "-m", "changes")
            scope = changed_scope(root, base)
        self.assertEqual(4, scope["changed"])
        self.assertEqual(3, scope["current_files"])
        self.assertEqual(1, scope["deleted"])
        self.assertEqual(1, scope["renamed"])
        self.assertEqual(
            ["added file.py", "modified.py", "renamed.py"],
            scope["_scan_paths"],
        )
        self.assertIn("deleted.py", scope["_baseline_paths"])
        self.assertIn("old.py", scope["_baseline_paths"])

    def test_nul_delimited_output_supports_newline_in_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = self.repository(root)
            unusual = "line\nbreak.py"
            (root / unusual).write_text("safe = True\n")
            self.git(root, "add", unusual)
            self.git(root, "commit", "-m", "unusual")
            scope = changed_scope(root, base)
        self.assertIn(unusual, scope["_scan_paths"])

    def test_subdirectory_scope_filters_other_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "other").mkdir()
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.email", "tests@example.invalid")
            self.git(root, "config", "user.name", "Tests")
            (root / "app" / "a.py").write_text("safe = True\n")
            (root / "other" / "b.py").write_text("safe = True\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            (root / "app" / "a.py").write_text("safe = False\n")
            (root / "other" / "b.py").write_text("safe = False\n")
            self.git(root, "commit", "-am", "changes")
            scope = changed_scope(root / "app", base)
        self.assertEqual(["a.py"], scope["_scan_paths"])
        self.assertEqual(1, scope["changed"])

    def test_invalid_and_option_like_refs_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            with self.assertRaises(GitDiffError):
                changed_scope(root, "missing-ref")
            with self.assertRaisesRegex(GitDiffError, "unsafe"):
                changed_scope(root, "--output=/tmp/x")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlink_escape_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            base = self.repository(root)
            link = root / "outside.py"
            link.symlink_to(Path(outside) / "outside.py")
            self.git(root, "add", "outside.py")
            self.git(root, "commit", "-m", "symlink")
            with self.assertRaisesRegex(GitDiffError, "escapes"):
                changed_scope(root, base)

    def test_missing_git_executable_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("agent_git.subprocess.run", side_effect=FileNotFoundError):
                with self.assertRaisesRegex(GitDiffError, "not found"):
                    changed_scope(Path(directory), "HEAD~1")


if __name__ == "__main__":
    unittest.main()
