import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from agent_version import __version__
from scripts.release_bundle import create_bundle
from scripts.release_transition import canonical_json as transition_json
from scripts.release_transition import default_policy
from scripts.release_trust import (
    TrustStateError,
    append_transition,
    canonical_json,
    create_state,
    load_state,
    main,
    validate_state,
)
from scripts.validate_wheel import EXPECTED_MODULES, EXPECTED_SCRIPTS


ANCHOR_COMMIT = "a" * 40
CANDIDATE_COMMIT = "b" * 40
ANCHOR_RELEASE = "1" * 64
CANDIDATE_RELEASE = "2" * 64
POLICY_SHA = "3" * 64
TRANSITION_ID = "4" * 64


def anchor_summary(**updates):
    value = {
        "project": "basit-agent-system",
        "version": "1.0.0",
        "release_id": ANCHOR_RELEASE,
        "source_commit": ANCHOR_COMMIT,
        "source_date_epoch": 100,
    }
    value.update(updates)
    return value


def candidate_summary(**updates):
    value = {
        "project": "basit-agent-system",
        "version": "1.1.0",
        "release_id": CANDIDATE_RELEASE,
        "source_commit": CANDIDATE_COMMIT,
        "source_date_epoch": 200,
    }
    value.update(updates)
    return value


def accepted_report(previous=None, candidate=None):
    previous = previous or anchor_summary()
    candidate = candidate or candidate_summary()
    return {
        "accepted": True,
        "transition_id": TRANSITION_ID,
        "policy": {"sha256": POLICY_SHA},
        "previous": {"release_id": previous["release_id"]},
        "candidate": {"release_id": candidate["release_id"]},
        "violations": [],
    }


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
            "Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/entry_points.txt", entry_points)
        archive.writestr(
            f"{dist_info}/RECORD",
            "\n".join(f"{name},," for name in names) + "\n",
        )
    return path


def make_bundle(root: Path, *, commit: str = ANCHOR_COMMIT, epoch: int = 100) -> Path:
    wheel_dir = root / "wheel"
    wheel_dir.mkdir()
    wheel = build_wheel(
        wheel_dir / f"basit_agent_system-{__version__}-py3-none-any.whl"
    )
    bundle = root / "bundle"
    create_bundle([wheel], bundle, commit, epoch)
    return bundle


def write_state(path: Path, state=None):
    value = state or create_state(anchor_summary())
    path.write_bytes(canonical_json(value))
    return value


class ReleaseTrustStateTests(unittest.TestCase):
    def test_create_state_is_canonical_and_hash_stable(self):
        first = create_state(anchor_summary())
        second = create_state(anchor_summary())
        self.assertEqual(first, second)
        self.assertEqual(first, json.loads(canonical_json(first)))
        self.assertEqual(64, len(first["state_id"]))
        self.assertEqual(first["entries"][0]["entry_hash"], first["head"]["entry_hash"])

    def test_validate_state_rejects_unknown_root_field(self):
        state = create_state(anchor_summary())
        state["unknown"] = True
        with self.assertRaisesRegex(TrustStateError, "schema"):
            validate_state(state)

    def test_validate_state_detects_entry_tampering(self):
        state = create_state(anchor_summary())
        state["entries"][0]["release"]["version"] = "9.0.0"
        with self.assertRaisesRegex(TrustStateError, "hash"):
            validate_state(state)

    def test_validate_state_detects_truncated_history(self):
        state = append_transition(
            create_state(anchor_summary()), candidate_summary(), accepted_report()
        )
        state["entries"].pop()
        with self.assertRaisesRegex(TrustStateError, "head|state id"):
            validate_state(state)

    def test_append_transition_rejects_duplicate_release(self):
        state = create_state(anchor_summary())
        report = accepted_report(candidate=anchor_summary())
        with self.assertRaisesRegex(TrustStateError, "already exists"):
            append_transition(state, anchor_summary(), report)

    def test_load_state_rejects_noncanonical_serialization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(create_state(anchor_summary())))
            with self.assertRaisesRegex(TrustStateError, "canonically"):
                load_state(path)

    def test_load_state_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            write_state(target)
            link = root / "state.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(TrustStateError, "symlink"):
                load_state(link)

    def test_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.json"
            state.write_text("preserve")
            with contextlib.redirect_stderr(io.StringIO()):
                status = main([
                    "init", str(state), str(root / "bundle"),
                    "--expected-release-id", ANCHOR_RELEASE,
                    "--expected-source-commit", ANCHOR_COMMIT,
                    "--expected-version", "1.0.0",
                ])
            self.assertEqual(2, status)
            self.assertEqual("preserve", state.read_text())

    def test_init_requires_pinned_anchor_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.json"
            with patch("scripts.release_trust._bundle_summary", return_value=anchor_summary()):
                with contextlib.redirect_stderr(io.StringIO()):
                    status = main([
                        "init", str(state), str(root / "bundle"),
                        "--expected-release-id", "f" * 64,
                        "--expected-source-commit", ANCHOR_COMMIT,
                        "--expected-version", "1.0.0",
                    ])
            self.assertEqual(2, status)
            self.assertFalse(state.exists())

    def test_verify_requires_external_state_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            write_state(state_path)
            with contextlib.redirect_stderr(io.StringIO()):
                status = main([
                    "verify", str(state_path),
                    "--expected-state-id", "f" * 64,
                ])
            self.assertEqual(2, status)

    def test_verify_bundle_must_match_head(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            state = write_state(state_path)
            with patch("scripts.release_trust._bundle_summary", return_value=candidate_summary()):
                with contextlib.redirect_stderr(io.StringIO()):
                    status = main([
                        "verify", str(state_path),
                        "--expected-state-id", state["state_id"],
                        "--bundle", str(root / "bundle"),
                    ])
            self.assertEqual(2, status)

    def test_append_transition_advances_hash_chain(self):
        state = create_state(anchor_summary())
        updated = append_transition(state, candidate_summary(), accepted_report())
        self.assertEqual(2, updated["head"]["sequence"])
        self.assertNotEqual(state["state_id"], updated["state_id"])
        self.assertEqual(
            updated["entries"][0]["entry_hash"],
            updated["entries"][1]["previous_entry_hash"],
        )
        self.assertEqual(TRANSITION_ID, updated["entries"][1]["transition"]["transition_id"])
        self.assertEqual(updated, validate_state(updated))

    def test_append_transition_rejects_denied_report(self):
        report = accepted_report()
        report["accepted"] = False
        with self.assertRaisesRegex(TrustStateError, "accepted transition"):
            append_transition(create_state(anchor_summary()), candidate_summary(), report)

    def test_advance_rejects_stale_state_id_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            write_state(state_path)
            before = state_path.read_bytes()
            policy = root / "policy.json"
            policy.write_bytes(transition_json(default_policy()))
            with contextlib.redirect_stderr(io.StringIO()):
                status = main([
                    "advance", str(state_path), str(root / "previous"), str(root / "candidate"),
                    "--policy", str(policy),
                    "--expected-state-id", "f" * 64,
                    "--expected-candidate-source-commit", CANDIDATE_COMMIT,
                    "--expected-candidate-version", "1.1.0",
                ])
            self.assertEqual(2, status)
            self.assertEqual(before, state_path.read_bytes())

    def test_advance_rejects_previous_bundle_not_head(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            state = write_state(state_path)
            policy = root / "policy.json"
            policy.write_bytes(transition_json(default_policy()))
            with patch("scripts.release_trust._bundle_summary", return_value=candidate_summary()):
                with contextlib.redirect_stderr(io.StringIO()):
                    status = main([
                        "advance", str(state_path), str(root / "previous"), str(root / "candidate"),
                        "--policy", str(policy),
                        "--expected-state-id", state["state_id"],
                        "--expected-candidate-source-commit", CANDIDATE_COMMIT,
                        "--expected-candidate-version", "1.1.0",
                    ])
            self.assertEqual(2, status)

    def test_advance_denied_transition_preserves_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            state = write_state(state_path)
            before = state_path.read_bytes()
            policy = root / "policy.json"
            policy.write_bytes(transition_json(default_policy()))
            denied = accepted_report()
            denied["accepted"] = False
            denied["violations"] = [{"rule_id": "TRN021", "message": "denied"}]
            with patch(
                "scripts.release_trust._bundle_summary",
                side_effect=[anchor_summary(), candidate_summary()],
            ), patch("scripts.release_trust.evaluate_bundles", return_value=denied):
                with contextlib.redirect_stdout(io.StringIO()):
                    status = main([
                        "advance", str(state_path), str(root / "previous"), str(root / "candidate"),
                        "--policy", str(policy),
                        "--expected-state-id", state["state_id"],
                        "--expected-candidate-source-commit", CANDIDATE_COMMIT,
                        "--expected-candidate-version", "1.1.0",
                    ])
            self.assertEqual(1, status)
            self.assertEqual(before, state_path.read_bytes())

    def test_advance_rejects_duplicate_release_even_when_transition_accepts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            state = write_state(state_path)
            policy = root / "policy.json"
            policy.write_bytes(transition_json(default_policy()))
            replay = accepted_report(candidate=anchor_summary())
            with patch(
                "scripts.release_trust._bundle_summary",
                side_effect=[anchor_summary(), anchor_summary()],
            ), patch("scripts.release_trust.evaluate_bundles", return_value=replay):
                with contextlib.redirect_stdout(io.StringIO()):
                    status = main([
                        "advance", str(state_path), str(root / "previous"), str(root / "candidate"),
                        "--policy", str(policy),
                        "--expected-state-id", state["state_id"],
                        "--expected-candidate-source-commit", ANCHOR_COMMIT,
                        "--expected-candidate-version", "1.0.0",
                    ])
            self.assertEqual(1, status)
            self.assertEqual(1, len(load_state(state_path)["entries"]))

    def test_real_verified_bundle_can_initialize_and_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = make_bundle(root)
            manifest = json.loads((bundle / "release-manifest.json").read_text())
            state_path = root / "consumer" / "state.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                init_status = main([
                    "init", str(state_path), str(bundle),
                    "--expected-release-id", manifest["release_id"],
                    "--expected-source-commit", ANCHOR_COMMIT,
                    "--expected-version", __version__,
                ])
            state_id = json.loads(stdout.getvalue())["state_id"]
            with contextlib.redirect_stdout(io.StringIO()):
                verify_status = main([
                    "verify", str(state_path),
                    "--expected-state-id", state_id,
                    "--bundle", str(bundle),
                ])
            self.assertEqual(0, init_status)
            self.assertEqual(0, verify_status)


if __name__ == "__main__":
    unittest.main()
