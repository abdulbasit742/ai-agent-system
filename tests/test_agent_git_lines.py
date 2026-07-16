import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_git import _parse_hunk_ranges, changed_scope


class GitLineScopeTests(unittest.TestCase):
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

    def commit_base(self, root: Path, name: str, content: str) -> str:
        self.init(root)
        (root / name).write_text(content)
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "base")
        return self.git(root, "rev-parse", "HEAD")

    def test_modified_file_tracks_old_and_new_zero_context_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = self.commit_base(root, "app.py", "one\nold\nkeep\n")
            (root / "app.py").write_text("one\nnew\nkeep\nadded\n")
            self.git(root, "commit", "-am", "modify lines")
            scope = changed_scope(root, base, line_only=True)
        self.assertEqual([[2, 2], [4, 4]], scope["_scan_lines"]["app.py"])
        self.assertEqual([[2, 2]], scope["_baseline_lines"]["app.py"])
        self.assertEqual("added-lines", scope["line_mode"])

    def test_added_file_is_scanned_as_a_full_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = self.commit_base(root, "base.py", "safe = True\n")
            (root / "new.py").write_text("first\nsecond\n")
            self.git(root, "add", "new.py")
            self.git(root, "commit", "-m", "add file")
            scope = changed_scope(root, base, line_only=True)
        self.assertIsNone(scope["_scan_lines"]["new.py"])
        self.assertEqual(1, scope["full_file_scans"])

    def test_deleted_file_scopes_all_old_baseline_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = self.commit_base(root, "remove.py", "unsafe\n")
            (root / "remove.py").unlink()
            self.git(root, "add", "-u")
            self.git(root, "commit", "-m", "delete file")
            scope = changed_scope(root, base, line_only=True)
        self.assertIsNone(scope["_baseline_lines"]["remove.py"])
        self.assertEqual(1, scope["full_file_resolutions"])

    def test_pure_rename_has_no_added_or_removed_line_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = self.commit_base(root, "old.py", "same content\n")
            self.git(root, "mv", "old.py", "new.py")
            self.git(root, "commit", "-m", "rename only")
            scope = changed_scope(root, base, line_only=True)
        self.assertEqual({}, scope["_scan_lines"])
        self.assertEqual({}, scope["_baseline_lines"])
        self.assertEqual(1, scope["renamed"])

    def test_hunk_parser_merges_adjacent_ranges_and_ignores_zero_counts(self):
        patch = (
            b"@@ -2,2 +2,1 @@\n"
            b"@@ -8,0 +4,2 @@\n"
            b"@@ -10,1 +6,1 @@\n"
        )
        old_ranges, new_ranges = _parse_hunk_ranges(patch)
        self.assertEqual([[2, 3], [10, 10]], old_ranges)
        self.assertEqual([[2, 2], [4, 6]], new_ranges)


if __name__ == "__main__":
    unittest.main()
