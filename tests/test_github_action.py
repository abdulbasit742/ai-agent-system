import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import github_action as action


class GitHubActionTests(unittest.TestCase):
    def environment(self, root: Path, **updates: str) -> dict[str, str]:
        workspace = root / "workspace"
        action_root = root / "action"
        workspace.mkdir()
        action_root.mkdir()
        env = {
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_ACTION_PATH": str(action_root),
            "BASIT_MODE": "added-lines",
            "BASIT_EVENT_BASE_SHA": "a" * 40,
            "BASIT_EVENT_HEAD_SHA": "b" * 40,
        }
        env.update(updates)
        return env

    def finding(self, **updates):
        item = {
            "rule_id": "BAS003",
            "severity": "high",
            "title": "Provider token",
            "path": "src/app.py",
            "line": 7,
            "preview": "sk-secret-material",
            "fix": "Revoke the token.",
            "fingerprint": "c" * 64,
        }
        item.update(updates)
        return item

    def test_pull_request_event_shas_are_default_refs(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = action.load_inputs(self.environment(Path(directory)))
        self.assertEqual("a" * 40, settings["base_ref"])
        self.assertEqual("b" * 40, settings["head_ref"])
        self.assertEqual("added-lines", settings["mode"])

    def test_explicit_refs_override_event_shas(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(
                Path(directory),
                BASIT_BASE_REF="reviewed-base",
                BASIT_HEAD_REF="reviewed-head",
            )
            settings = action.load_inputs(env)
        self.assertEqual(("reviewed-base", "reviewed-head"), (
            settings["base_ref"], settings["head_ref"]
        ))

    def test_changed_mode_without_base_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(
                Path(directory),
                BASIT_EVENT_BASE_SHA="",
                BASIT_EVENT_HEAD_SHA="",
            )
            with self.assertRaisesRegex(action.ActionInputError, "require base-ref"):
                action.load_inputs(env)

    def test_full_mode_needs_no_git_refs(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(
                Path(directory),
                BASIT_MODE="full",
                BASIT_EVENT_BASE_SHA="",
                BASIT_EVENT_HEAD_SHA="",
            )
            settings = action.load_inputs(env)
        self.assertIsNone(settings["base_ref"])
        self.assertIsNone(settings["head_ref"])

    def test_workspace_traversal_and_control_characters_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(action.ActionInputError, "inside"):
                action.load_inputs(self.environment(root, BASIT_REPORT_PATH="../report.json"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(action.ActionInputError, "control"):
                action.load_inputs(self.environment(root, BASIT_BASE_REF="main\nmalicious"))

    def test_build_command_uses_argument_array_and_exact_refs(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = action.load_inputs(self.environment(Path(directory)))
            command = action.build_command(settings)
        self.assertEqual(Path(command[1]).name, "agent_changed_lines.py")
        self.assertIn("--changed-from", command)
        self.assertEqual("a" * 40, command[command.index("--changed-from") + 1])
        self.assertNotIn("shell=True", command)

    def test_sarif_and_annotations_exclude_matched_preview(self):
        finding = self.finding()
        report = {"findings": [finding], "summary": {"active": 1}}
        sarif = json.dumps(action.report_to_sarif(report))
        annotations = "\n".join(action.annotation_lines([finding], 10))
        self.assertNotIn(finding["preview"], sarif)
        self.assertNotIn(finding["preview"], annotations)
        self.assertIn("Revoke the token", sarif)
        self.assertIn("::error", annotations)

    def test_annotation_properties_are_workflow_command_escaped(self):
        finding = self.finding(path="src/a,b:line\nname.py", title="Bad: token")
        annotation = action.annotation_lines([finding], 1)[0]
        self.assertIn("%2C", annotation)
        self.assertIn("%3A", annotation)
        self.assertIn("%0A", annotation)
        self.assertNotIn("\n", annotation)

    def test_summary_excludes_preview_and_escapes_markdown(self):
        finding = self.finding(path="src/a|b.py")
        summary = action.summary_markdown(
            {"findings": [finding], "summary": {"suppressed": 2}},
            "added-lines",
        )
        self.assertNotIn(finding["preview"], summary)
        self.assertIn("src/a\\|b.py", summary)
        self.assertIn("Suppressed | 2", summary)

    def test_run_writes_outputs_sarif_and_preview_free_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = self.environment(root)
            env["GITHUB_OUTPUT"] = str(root / "output.txt")
            env["GITHUB_STEP_SUMMARY"] = str(root / "summary.md")
            settings = action.load_inputs(env)
            report = {
                "findings": [self.finding()],
                "summary": {
                    "active": 1,
                    "suppressed": 0,
                    "new": 1,
                    "existing": 0,
                    "resolved": 0,
                },
            }

            def fake_run(command, **kwargs):
                Path(settings["report_path"]).parent.mkdir(parents=True, exist_ok=True)
                Path(settings["report_path"]).write_text(json.dumps(report))
                return subprocess.CompletedProcess(command, 1, "", "")

            stdout = io.StringIO()
            with mock.patch("scripts.github_action.subprocess.run", side_effect=fake_run):
                with contextlib.redirect_stdout(stdout):
                    status = action.run(settings, env)

            output = Path(env["GITHUB_OUTPUT"]).read_text()
            summary = Path(env["GITHUB_STEP_SUMMARY"]).read_text()
            sarif = Path(settings["sarif_path"]).read_text()
        self.assertEqual(1, status)
        self.assertIn("status=findings", output)
        self.assertIn("finding-count=1", output)
        self.assertNotIn("sk-secret-material", summary)
        self.assertNotIn("sk-secret-material", sarif)
        self.assertNotIn("sk-secret-material", stdout.getvalue())

    def test_stale_report_is_not_used_after_scanner_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = action.load_inputs(self.environment(root))
            report_path = Path(settings["report_path"])
            report_path.parent.mkdir(parents=True)
            report_path.write_text(json.dumps({"findings": [self.finding()]}))
            completed = subprocess.CompletedProcess([], 2, "", "bad config")
            with mock.patch("scripts.github_action.subprocess.run", return_value=completed):
                with contextlib.redirect_stderr(io.StringIO()):
                    status = action.run(settings, {})
            self.assertFalse(report_path.exists())
        self.assertEqual(2, status)


if __name__ == "__main__":
    unittest.main()
