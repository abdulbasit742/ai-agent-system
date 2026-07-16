import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from agent_version import __version__
from scripts.release_bundle import create_bundle
from scripts.release_transition import (
    TransitionError,
    canonical_json,
    default_policy,
    evaluate_bundles,
    evaluate_summaries,
    load_policy,
    main,
    policy_sha256,
)
from scripts.validate_wheel import EXPECTED_MODULES, EXPECTED_SCRIPTS


PREVIOUS_COMMIT = "a" * 40
CANDIDATE_COMMIT = "b" * 40
PREVIOUS_RELEASE = "1" * 64
CANDIDATE_RELEASE = "2" * 64


def build_wheel(
    path: Path,
    *,
    marker: str = "",
    module_overrides: dict[str, str] | None = None,
) -> Path:
    module_overrides = module_overrides or {}
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
            archive.writestr(module, module_overrides.get(module, f"# {module}\n"))
        archive.writestr(f"{dist_info}/METADATA", metadata)
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/entry_points.txt", entry_points)
        archive.writestr(
            f"{dist_info}/RECORD",
            "\n".join(f"{name},," for name in names) + "\n",
        )
        if marker:
            archive.writestr(f"{dist_info}/build-marker.txt", marker)
    return path


def make_bundle(
    root: Path,
    name: str,
    *,
    commit: str,
    epoch: int,
    marker: str = "",
    module_overrides: dict[str, str] | None = None,
) -> Path:
    wheel_dir = root / f"wheel-{name}"
    wheel_dir.mkdir()
    wheel = build_wheel(
        wheel_dir / f"basit_agent_system-{__version__}-py3-none-any.whl",
        marker=marker,
        module_overrides=module_overrides,
    )
    bundle = root / f"bundle-{name}"
    create_bundle([wheel], bundle, commit, epoch)
    return bundle


def synthetic_summary(**updates):
    base = {
        "project": "basit-agent-system",
        "version": "1.2.0",
        "release_id": PREVIOUS_RELEASE,
        "source_commit": PREVIOUS_COMMIT,
        "source_date_epoch": 100,
        "artifacts": {"package.whl": "3" * 64},
        "modules": {"a.py": "4" * 64, "b.py": "5" * 64},
        "module_licenses": {"a.py": "MIT", "b.py": "MIT"},
        "package_licenses": ["MIT"],
        "console_scripts": ["agent-system"],
        "runtime_dependencies": 0,
    }
    base.update(updates)
    return base


def candidate_summary(**updates):
    base = synthetic_summary(
        version="1.3.0",
        release_id=CANDIDATE_RELEASE,
        source_commit=CANDIDATE_COMMIT,
        source_date_epoch=200,
        artifacts={"package-new.whl": "6" * 64},
        modules={"a.py": "7" * 64, "b.py": "5" * 64},
    )
    base.update(updates)
    return base


class ReleaseTransitionTests(unittest.TestCase):
    def test_default_policy_is_canonical_and_hash_stable(self):
        policy = default_policy()
        self.assertEqual(policy, json.loads(canonical_json(policy)))
        self.assertEqual(64, len(policy_sha256(policy)))
        self.assertEqual(policy_sha256(policy), policy_sha256(default_policy()))

    def test_load_policy_rejects_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            policy = default_policy()
            policy["unknown"] = True
            path.write_text(json.dumps(policy))
            with self.assertRaisesRegex(TransitionError, "schema"):
                load_policy(path)

    def test_policy_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text("preserve")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(["policy", str(path), "--init"])
            self.assertEqual(2, status)
            self.assertEqual("preserve", path.read_text())

    def test_numeric_versions_reject_leading_zero_segments(self):
        previous = synthetic_summary(version="1.02.0")
        with self.assertRaisesRegex(TransitionError, "leading-zero"):
            evaluate_summaries(previous, candidate_summary(), default_policy())

    def test_replay_is_denied_by_default(self):
        previous = synthetic_summary()
        report = evaluate_summaries(previous, dict(previous), default_policy())
        self.assertFalse(report["accepted"])
        self.assertEqual("replay", report["risk"])
        self.assertIn("TRN003", {item["rule_id"] for item in report["violations"]})

    def test_replay_can_be_explicitly_allowed(self):
        previous = synthetic_summary()
        policy = default_policy()
        policy["identity"]["allow_replay"] = True
        report = evaluate_summaries(previous, dict(previous), policy)
        self.assertTrue(report["accepted"])
        self.assertEqual([], report["violations"])

    def test_version_rollback_is_denied(self):
        report = evaluate_summaries(
            synthetic_summary(version="2.0.0"),
            candidate_summary(version="1.9.9"),
            default_policy(),
        )
        self.assertEqual("rollback", report["risk"])
        self.assertIn("TRN002", {item["rule_id"] for item in report["violations"]})

    def test_same_version_mutation_is_denied(self):
        report = evaluate_summaries(
            synthetic_summary(version="1.2.0"),
            candidate_summary(version="1.2.0"),
            default_policy(),
        )
        self.assertIn("TRN004", {item["rule_id"] for item in report["violations"]})

    def test_source_epoch_rollback_is_denied(self):
        report = evaluate_summaries(
            synthetic_summary(source_date_epoch=300),
            candidate_summary(source_date_epoch=200),
            default_policy(),
        )
        self.assertIn("TRN005", {item["rule_id"] for item in report["violations"]})

    def test_source_epoch_reuse_is_denied(self):
        report = evaluate_summaries(
            synthetic_summary(source_date_epoch=200),
            candidate_summary(source_date_epoch=200),
            default_policy(),
        )
        self.assertIn("TRN006", {item["rule_id"] for item in report["violations"]})

    def test_source_commit_reuse_for_different_release_is_denied(self):
        report = evaluate_summaries(
            synthetic_summary(),
            candidate_summary(source_commit=PREVIOUS_COMMIT),
            default_policy(),
        )
        self.assertIn("TRN007", {item["rule_id"] for item in report["violations"]})

    def test_expected_anchor_and_candidate_identity_are_bound(self):
        report = evaluate_summaries(
            synthetic_summary(),
            candidate_summary(),
            default_policy(),
            expected_previous_release_id="f" * 64,
            expected_candidate_source_commit="e" * 40,
            expected_candidate_version="9.0.0",
            expected_candidate_release_id="d" * 64,
        )
        rules = {item["rule_id"] for item in report["violations"]}
        self.assertTrue({"TRN008", "TRN009", "TRN010", "TRN011"}.issubset(rules))

    def test_module_addition_and_change_are_allowed_by_default(self):
        candidate = candidate_summary(
            modules={"a.py": "7" * 64, "b.py": "5" * 64, "c.py": "8" * 64},
            module_licenses={"a.py": "MIT", "b.py": "MIT", "c.py": "MIT"},
        )
        report = evaluate_summaries(synthetic_summary(), candidate, default_policy())
        self.assertTrue(report["accepted"])
        self.assertEqual(["c.py"], report["changes"]["modules"]["added"])
        self.assertEqual(["a.py"], report["changes"]["modules"]["changed"])

    def test_module_removal_is_denied(self):
        candidate = candidate_summary(
            modules={"a.py": "7" * 64},
            module_licenses={"a.py": "MIT"},
        )
        report = evaluate_summaries(synthetic_summary(), candidate, default_policy())
        self.assertIn("TRN021", {item["rule_id"] for item in report["violations"]})

    def test_console_command_removal_is_denied(self):
        report = evaluate_summaries(
            synthetic_summary(console_scripts=["agent-system", "legacy-command"]),
            candidate_summary(console_scripts=["agent-system"]),
            default_policy(),
        )
        self.assertIn("TRN024", {item["rule_id"] for item in report["violations"]})

    def test_runtime_dependency_increase_is_denied(self):
        report = evaluate_summaries(
            synthetic_summary(),
            candidate_summary(runtime_dependencies=1),
            default_policy(),
        )
        self.assertIn("TRN025", {item["rule_id"] for item in report["violations"]})

    def test_license_change_is_denied(self):
        report = evaluate_summaries(
            synthetic_summary(),
            candidate_summary(
                package_licenses=["Apache-2.0"],
                module_licenses={"a.py": "Apache-2.0", "b.py": "Apache-2.0"},
            ),
            default_policy(),
        )
        self.assertIn("TRN026", {item["rule_id"] for item in report["violations"]})

    def test_real_verified_bundles_report_changed_module_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = make_bundle(
                root,
                "previous",
                commit=PREVIOUS_COMMIT,
                epoch=100,
            )
            candidate = make_bundle(
                root,
                "candidate",
                commit=CANDIDATE_COMMIT,
                epoch=200,
                module_overrides={"agent_system.py": "# changed\n"},
            )
            report = evaluate_bundles(previous, candidate, default_policy())
        self.assertIn("agent_system.py", report["changes"]["modules"]["changed"])
        self.assertIn("TRN004", {item["rule_id"] for item in report["violations"]})

    def test_cli_compare_returns_zero_but_gate_denies_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = make_bundle(root, "release", commit=PREVIOUS_COMMIT, epoch=100)
            manifest = json.loads((bundle / "release-manifest.json").read_text())
            policy = root / "policy.json"
            policy.write_bytes(canonical_json(default_policy()))
            with contextlib.redirect_stdout(io.StringIO()):
                compare_status = main(["compare", str(bundle), str(bundle), "--policy", str(policy)])
                gate_status = main(
                    [
                        "gate",
                        str(bundle),
                        str(bundle),
                        "--policy",
                        str(policy),
                        "--expected-previous-release-id",
                        manifest["release_id"],
                        "--expected-candidate-source-commit",
                        PREVIOUS_COMMIT,
                        "--expected-candidate-version",
                        __version__,
                        "--expected-candidate-release-id",
                        manifest["release_id"],
                    ]
                )
        self.assertEqual(0, compare_status)
        self.assertEqual(1, gate_status)

    def test_tampered_candidate_bundle_returns_invalid_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = make_bundle(root, "previous", commit=PREVIOUS_COMMIT, epoch=100)
            candidate = make_bundle(root, "candidate", commit=CANDIDATE_COMMIT, epoch=200)
            wheel = next(candidate.glob("*.whl"))
            wheel.write_bytes(wheel.read_bytes() + b"tamper")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(["compare", str(previous), str(candidate)])
        self.assertEqual(2, status)
        self.assertIn("digest mismatch", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
