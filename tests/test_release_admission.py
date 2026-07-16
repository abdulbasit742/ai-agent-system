import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from agent_version import __version__
from scripts.release_admission_core import (
    AdmissionError,
    canonical_json,
    default_policy,
    evaluate_bundle,
    load_policy,
    main,
    policy_sha256,
)
from scripts.release_bundle import create_bundle
from scripts.validate_wheel import EXPECTED_MODULES, EXPECTED_SCRIPTS

COMMIT = "a" * 40
EPOCH = 1_700_000_000


def build_wheel(path: Path) -> Path:
    dist_info = f"basit_agent_system-{__version__}.dist-info"
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: basit-agent-system\n"
        f"Version: {__version__}\n"
        "Requires-Python: >=3.11\n"
    )
    entry_points = "[console_scripts]\n" + "\n".join(
        f"{name} = {target}" for name, target in sorted(EXPECTED_SCRIPTS.items())
    ) + "\n"
    names = sorted(EXPECTED_MODULES) + [
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/RECORD",
    ]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for module in sorted(EXPECTED_MODULES):
            archive.writestr(module, f"# {module}\n")
        archive.writestr(f"{dist_info}/METADATA", metadata)
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: admission-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/entry_points.txt", entry_points)
        archive.writestr(
            f"{dist_info}/RECORD",
            "\n".join(f"{name},," for name in names) + "\n",
        )
    return path


class ReleaseAdmissionTests(unittest.TestCase):
    def write_policy(self, root: Path, policy=None) -> Path:
        path = root / "policy.json"
        path.write_bytes(canonical_json(policy or default_policy()))
        return path

    def build_bundle(self, root: Path):
        wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
        manifest = create_bundle([wheel], root / "release", COMMIT, EPOCH)
        return root / "release", manifest

    def test_default_policy_round_trip_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = load_policy(self.write_policy(Path(directory)))
        self.assertEqual(default_policy(), policy)
        self.assertEqual(64, len(policy_sha256(policy)))

    def test_hidden_builder_path_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = load_policy(self.write_policy(Path(directory)))
        self.assertEqual(".github/workflows/ci.yml", policy["provenance"]["builder_workflow"])

    def test_policy_rejects_unknown_field(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = default_policy()
            policy["unexpected"] = True
            with self.assertRaisesRegex(AdmissionError, "fields do not match"):
                load_policy(self.write_policy(root, policy))

    def test_policy_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = default_policy()
            policy["provenance"]["builder_workflow"] = "../ci.yml"
            with self.assertRaisesRegex(AdmissionError, "safe repository-relative"):
                load_policy(self.write_policy(root, policy))

    def test_valid_bundle_is_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, manifest = self.build_bundle(root)
            report = evaluate_bundle(bundle, default_policy(), COMMIT, __version__, manifest["release_id"])
        self.assertTrue(report["admitted"])
        self.assertEqual([], report["violations"])

    def test_wrong_expected_commit_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self.build_bundle(Path(directory))
            report = evaluate_bundle(bundle, default_policy(), "b" * 40, __version__)
        self.assertIn("ADM004", {item["rule_id"] for item in report["violations"]})

    def test_wrong_expected_version_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self.build_bundle(Path(directory))
            report = evaluate_bundle(bundle, default_policy(), COMMIT, "9.9.9")
        self.assertIn("ADM003", {item["rule_id"] for item in report["violations"]})

    def test_wrong_expected_release_id_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self.build_bundle(Path(directory))
            report = evaluate_bundle(bundle, default_policy(), COMMIT, __version__, "f" * 64)
        self.assertIn("ADM005", {item["rule_id"] for item in report["violations"]})

    def test_license_policy_denies_release(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self.build_bundle(Path(directory))
            policy = default_policy()
            policy["sbom"]["allowed_licenses"] = ["Apache-2.0"]
            report = evaluate_bundle(bundle, policy, COMMIT, __version__)
        ids = {item["rule_id"] for item in report["violations"]}
        self.assertTrue({"ADM022", "ADM023"}.issubset(ids))

    def test_module_boundary_policy_denies_release(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self.build_bundle(Path(directory))
            policy = default_policy()
            policy["artifacts"]["modules"] = policy["artifacts"]["modules"][1:]
            report = evaluate_bundle(bundle, policy, COMMIT, __version__)
        self.assertIn("ADM012", {item["rule_id"] for item in report["violations"]})

    def test_artifact_size_policy_denies_release(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self.build_bundle(Path(directory))
            policy = default_policy()
            policy["artifacts"]["max_size_bytes"] = 1
            report = evaluate_bundle(bundle, policy, COMMIT, __version__)
        self.assertIn("ADM011", {item["rule_id"] for item in report["violations"]})

    def test_unsigned_provenance_requires_explicit_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self.build_bundle(Path(directory))
            policy = default_policy()
            policy["provenance"]["accept_unsigned"] = False
            report = evaluate_bundle(bundle, policy, COMMIT, __version__)
        self.assertIn("ADM036", {item["rule_id"] for item in report["violations"]})

    def test_repository_identity_policy_denies_release(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self.build_bundle(Path(directory))
            policy = default_policy()
            policy["source"]["repository"] = "https://example.com/team/project"
            report = evaluate_bundle(bundle, policy, COMMIT, __version__)
        ids = {item["rule_id"] for item in report["violations"]}
        self.assertTrue({"ADM026", "ADM033", "ADM034", "ADM035"}.issubset(ids))

    def test_cli_exit_codes_for_admit_deny_and_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, _ = self.build_bundle(root)
            policy_path = self.write_policy(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                admitted = main([
                    "evaluate", str(bundle), "--policy", str(policy_path),
                    "--expected-source-commit", COMMIT, "--expected-version", __version__,
                    "--format", "json",
                ])
            report = json.loads(output.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                denied = main([
                    "evaluate", str(bundle), "--policy", str(policy_path),
                    "--expected-source-commit", "b" * 40, "--expected-version", __version__,
                ])
            with contextlib.redirect_stderr(io.StringIO()):
                invalid = main([
                    "evaluate", str(bundle), "--policy", str(policy_path),
                    "--expected-source-commit", "main", "--expected-version", __version__,
                ])
        self.assertEqual(0, admitted)
        self.assertTrue(report["admitted"])
        self.assertEqual(1, denied)
        self.assertEqual(2, invalid)

    def test_init_refuses_to_overwrite_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text("preserve")
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(["init", str(path)])
            preserved = path.read_text()
        self.assertEqual(2, status)
        self.assertEqual("preserve", preserved)


if __name__ == "__main__":
    unittest.main()
