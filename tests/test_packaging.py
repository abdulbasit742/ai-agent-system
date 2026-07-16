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
                status = agent_cli.main(["run", "missing-integration"])
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
        expected_scripts = {
            "agent-audit-admission", "agent-audit-bundle", "agent-audit-catalog",
            "agent-audit-catalog-checkpoint", "agent-audit-catalog-consistency",
            "agent-audit-segments", "agent-audit-trust", "agent-audit-trust-checkpoint",
            "agent-audit-trust-consistency", "agent-audit-trust-bundle",
            "agent-audit-trust-admission", "agent-audit-trust-receiver",
            "agent-audit-trust-receiver-checkpoint",
            "agent-audit-trust-receiver-consistency",
            "agent-audit-trust-receiver-bundle",
            "agent-audit-trust-receiver-admission",
            "agent-audit-trust-receiver-acceptance",
            "agent-audit-trust-receiver-acceptance-checkpoint",
            "agent-audit-trust-receiver-acceptance-consistency",
            "agent-changed-lines", "agent-system", "basit-agent",
            "basit-agent-audit-admission", "basit-agent-audit-bundle",
            "basit-agent-audit-trust", "basit-agent-audit-trust-checkpoint",
            "basit-agent-audit-trust-consistency", "basit-agent-audit-trust-bundle",
            "basit-agent-audit-trust-admission", "basit-agent-audit-trust-receiver",
            "basit-agent-audit-trust-receiver-checkpoint",
            "basit-agent-audit-trust-receiver-consistency",
            "basit-agent-audit-trust-receiver-bundle",
            "basit-agent-audit-trust-receiver-admission",
            "basit-agent-audit-trust-receiver-acceptance",
            "basit-agent-audit-trust-receiver-acceptance-checkpoint",
            "basit-agent-audit-trust-receiver-acceptance-consistency",
            "basit-agent-catalog", "basit-agent-catalog-checkpoint",
            "basit-agent-catalog-consistency", "basit-agent-lines", "basit-agent-segments",
        }
        self.assertEqual(expected_scripts, set(project["scripts"]))
        expected_modules = {
            "agent_audit", "agent_audit_admission", "agent_audit_bundle",
            "agent_audit_catalog", "agent_audit_checkpoint", "agent_audit_consistency",
            "agent_audit_events", "agent_audit_segments", "agent_audit_trust",
            "agent_audit_trust_checkpoint", "agent_audit_trust_consistency",
            "agent_audit_trust_bundle", "agent_audit_trust_bundle_core",
            "agent_audit_trust_admission", "agent_audit_trust_receiver",
            "agent_audit_trust_receiver_checkpoint",
            "agent_audit_trust_receiver_consistency",
            "agent_audit_trust_receiver_bundle",
            "agent_audit_trust_receiver_admission",
            "agent_audit_trust_receiver_acceptance",
            "agent_audit_trust_receiver_acceptance_checkpoint",
            "agent_audit_trust_receiver_acceptance_consistency",
            "agent_baseline", "agent_changed_lines", "agent_cli", "agent_config",
            "agent_git", "agent_policy", "agent_system", "agent_system_legacy",
            "agent_version",
        }
        self.assertEqual(expected_modules, set(setuptools["py-modules"]))


if __name__ == "__main__":
    unittest.main()
