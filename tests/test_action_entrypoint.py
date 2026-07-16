import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import action_entrypoint as entrypoint


class ActionEntrypointTests(unittest.TestCase):
    def environment(self, root: Path, **updates: str) -> dict[str, str]:
        workspace = root / "workspace"
        workspace.mkdir()
        env = {"GITHUB_WORKSPACE": str(workspace)}
        env.update(updates)
        return env

    def test_default_outputs_are_confined_and_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = self.environment(root)
            report, sarif = entrypoint.validate_output_paths(env)
            generated = (Path(env["GITHUB_WORKSPACE"]) / ".agent-system").resolve()
        self.assertEqual(generated, report.parent)
        self.assertEqual(generated, sarif.parent)
        self.assertNotEqual(report, sarif)

    def test_output_outside_generated_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(
                Path(directory),
                BASIT_REPORT_PATH="repository-file.json",
            )
            with self.assertRaisesRegex(entrypoint.OutputBoundaryError, "inside"):
                entrypoint.validate_output_paths(env)

    def test_identical_report_and_sarif_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(
                Path(directory),
                BASIT_REPORT_PATH=".agent-system/same.json",
                BASIT_SARIF_PATH=".agent-system/same.json",
            )
            with self.assertRaisesRegex(entrypoint.OutputBoundaryError, "different"):
                entrypoint.validate_output_paths(env)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlink_escape_from_generated_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = self.environment(root)
            workspace = Path(env["GITHUB_WORKSPACE"])
            generated = workspace / ".agent-system"
            generated.mkdir()
            outside = workspace / "important.json"
            outside.write_text("keep")
            (generated / "report.json").symlink_to(outside)
            env["BASIT_REPORT_PATH"] = ".agent-system/report.json"
            with self.assertRaisesRegex(entrypoint.OutputBoundaryError, "inside"):
                entrypoint.validate_output_paths(env)

    def test_main_stops_before_runner_on_boundary_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory), BASIT_REPORT_PATH="README.md")
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch("scripts.action_entrypoint.github_action.main") as runner:
                    status = entrypoint.main()
            runner.assert_not_called()
        self.assertEqual(2, status)


if __name__ == "__main__":
    unittest.main()
