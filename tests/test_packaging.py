import contextlib
import io
import re
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import agent_cli
from agent_version import __version__


class PackagingTests(unittest.TestCase):
    def test_version_is_pep_440_compatible_release(self):
        self.assertRegex(__version__, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertEqual("basit-agent-system 0.1.0", agent_cli.VERSION_TEXT)

    def test_full_cli_version_flag(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main(["--version"])
        self.assertEqual(0, status)
        self.assertEqual(agent_cli.VERSION_TEXT, output.getvalue().strip())

    def test_full_cli_version_command(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main(["version"])
        self.assertEqual(0, status)
        self.assertEqual(agent_cli.VERSION_TEXT, output.getvalue().strip())

    def test_added_line_cli_version_flag(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.changed_lines_main(["--version"])
        self.assertEqual(0, status)
        self.assertEqual(agent_cli.VERSION_TEXT, output.getvalue().strip())

    def test_full_cli_delegates_argument_array(self):
        with mock.patch("agent_cli.agent_system.main", return_value=7) as delegated:
            status = agent_cli.main(["scan", ".", "--format", "json"])
        self.assertEqual(7, status)
        delegated.assert_called_once_with(["scan", ".", "--format", "json"])

    def test_added_line_cli_delegates_argument_array(self):
        arguments = [".", "--changed-from", "HEAD~1"]
        with mock.patch("agent_cli.agent_changed_lines.main", return_value=5) as delegated:
            status = agent_cli.changed_lines_main(arguments)
        self.assertEqual(5, status)
        delegated.assert_called_once_with(arguments)

    def test_wheel_rejects_source_only_integration_commands(self):
        error = io.StringIO()
        with mock.patch("agent_cli._source_checkout_available", return_value=False):
            with contextlib.redirect_stderr(error):
                status = agent_cli.main(["run", "workflow-warden"])
        self.assertEqual(2, status)
        self.assertIn("requires a source checkout", error.getvalue())

    def test_pyproject_has_reviewed_dependency_free_boundary(self):
        payload = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        project = payload["project"]
        setuptools = payload["tool"]["setuptools"]
        self.assertEqual("basit-agent-system", project["name"])
        self.assertEqual(">=3.11", project["requires-python"])
        self.assertEqual([], project["dependencies"])
        self.assertEqual(["version"], project["dynamic"])
        self.assertEqual(
            {"attr": "agent_version.__version__"},
            payload["tool"]["setuptools"]["dynamic"]["version"],
        )
        self.assertEqual(
            {
                "agent-changed-lines",
                "agent-system",
                "basit-agent",
                "basit-agent-lines",
            },
            set(project["scripts"]),
        )
        self.assertEqual(
            {
                "agent_baseline",
                "agent_changed_lines",
                "agent_cli",
                "agent_config",
                "agent_git",
                "agent_policy",
                "agent_system",
                "agent_version",
            },
            set(setuptools["py-modules"]),
        )


if __name__ == "__main__":
    unittest.main()
