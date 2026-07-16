import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_audit_bundle import _canonical_bytes
from agent_audit_trust_checkpoint import create_checkpoint, create_proof
from agent_audit_trust_consistency import create_consistency_proof
from agent_audit_trust_bundle import (
    AuditTrustBundleError,
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    create_bundle,
    load_manifest,
    main,
    validate_manifest,
    verify_bundle,
)
from test_audit_trust_consistency import advance, anchor


def write_json(path, payload):
    path.write_bytes(_canonical_bytes(payload))


def make_inputs(root, candidate, previous=None, sequences=None):
    root.mkdir(parents=True, exist_ok=True)
    candidate_checkpoint = create_checkpoint(candidate)
    candidate_path = root / "candidate.json"
    write_json(candidate_path, candidate_checkpoint)
    if sequences is None:
        sequences = [candidate_checkpoint["entry_count"]]
    proof_paths = []
    for sequence in sequences:
        proof = create_proof(candidate, candidate_checkpoint, sequence=sequence)
        path = root / f"proof-{sequence}.json"
        write_json(path, proof)
        proof_paths.append(path)
    result = {
        "candidate": candidate_checkpoint,
        "candidate_path": candidate_path,
        "proof_paths": proof_paths,
    }
    if previous is not None:
        previous_checkpoint = create_checkpoint(previous)
        previous_path = root / "previous.json"
        consistency = create_consistency_proof(
            previous, previous_checkpoint, candidate, candidate_checkpoint
        )
        consistency_path = root / "consistency.json"
        write_json(previous_path, previous_checkpoint)
        write_json(consistency_path, consistency)
        result.update(
            previous=previous_checkpoint,
            previous_path=previous_path,
            consistency=consistency,
            consistency_path=consistency_path,
        )
    return result


def create_from_inputs(root, inputs, name="bundle"):
    return create_bundle(
        root / name,
        inputs["candidate_path"],
        inputs["candidate"]["checkpoint_id"],
        inputs["proof_paths"],
        previous_checkpoint_path=inputs.get("previous_path"),
        expected_previous_checkpoint_id=(
            inputs.get("previous", {}).get("checkpoint_id")
        ),
        consistency_path=inputs.get("consistency_path"),
    )


class AuditTrustBundleTests(unittest.TestCase):
    def test_snapshot_roundtrip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            manifest = create_from_inputs(root, inputs)
            report = verify_bundle(
                root / "bundle",
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
            )
        self.assertEqual("snapshot", report["bundle_type"])
        self.assertEqual(1, report["proof_count"])
        self.assertEqual(inputs["candidate"]["head"]["bundle_id"], report["head_bundle_id"])

    def test_transition_roundtrip_with_selected_history(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, candidate, previous, sequences=[1, 2])
            manifest = create_from_inputs(root, inputs)
            report = verify_bundle(
                root / "bundle",
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                expected_previous_checkpoint_id=inputs["previous"]["checkpoint_id"],
            )
        self.assertEqual("transition", report["bundle_type"])
        self.assertEqual(2, report["proof_count"])
        self.assertEqual("right-descendant", report["consistency"]["relation"])

    def test_bundle_verifies_without_source_states_or_loose_evidence(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, candidate, previous)
            manifest = create_from_inputs(root, inputs)
            for path in [
                inputs["candidate_path"], inputs["previous_path"],
                inputs["consistency_path"], *inputs["proof_paths"],
            ]:
                path.unlink()
            report = verify_bundle(
                root / "bundle",
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                expected_previous_checkpoint_id=inputs["previous"]["checkpoint_id"],
            )
        self.assertTrue(report["valid"])

    def test_candidate_head_proof_is_mandatory(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, candidate, sequences=[1])
            with self.assertRaisesRegex(AuditTrustBundleError, "head") as raised:
                create_from_inputs(root, inputs)
        self.assertEqual("ATB012", raised.exception.rule_id)

    def test_duplicate_proof_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            inputs["proof_paths"].append(inputs["proof_paths"][0])
            with self.assertRaisesRegex(AuditTrustBundleError, "duplicate"):
                create_from_inputs(root, inputs)

    def test_proof_from_another_checkpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor(1))
            other = make_inputs(root / "other", anchor(2))
            inputs["proof_paths"] = other["proof_paths"]
            with self.assertRaisesRegex(AuditTrustBundleError, "reference"):
                create_from_inputs(root, inputs)

    def test_partial_transition_composition_is_rejected(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, candidate, previous)
            with self.assertRaisesRegex(AuditTrustBundleError, "requires previous"):
                create_bundle(
                    root / "bundle",
                    inputs["candidate_path"],
                    inputs["candidate"]["checkpoint_id"],
                    inputs["proof_paths"],
                    previous_checkpoint_path=inputs["previous_path"],
                )

    def test_same_checkpoint_cannot_be_transition_bundle(self):
        state = anchor()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, state, state)
            with self.assertRaises(AuditTrustBundleError) as raised:
                create_from_inputs(root, inputs)
        self.assertIn(raised.exception.rule_id, {"ATB005", "ATB006"})

    def test_wrong_bundle_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            create_from_inputs(root, inputs)
            with self.assertRaises(AuditTrustBundleError) as raised:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id="f" * 64,
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )
        self.assertTrue(raised.exception.denied)
        self.assertEqual("ATB003", raised.exception.rule_id)

    def test_wrong_candidate_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            manifest = create_from_inputs(root, inputs)
            with self.assertRaises(AuditTrustBundleError) as raised:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id="f" * 64,
                )
        self.assertTrue(raised.exception.denied)

    def test_transition_requires_previous_pin(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, candidate, previous)
            manifest = create_from_inputs(root, inputs)
            with self.assertRaises(AuditTrustBundleError) as raised:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )
        self.assertTrue(raised.exception.denied)

    def test_wrong_previous_pin_is_denied(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, candidate, previous)
            manifest = create_from_inputs(root, inputs)
            with self.assertRaises(AuditTrustBundleError) as raised:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                    expected_previous_checkpoint_id="f" * 64,
                )
        self.assertTrue(raised.exception.denied)

    def test_extra_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            manifest = create_from_inputs(root, inputs)
            (root / "bundle" / "extra.txt").write_text("extra")
            with self.assertRaisesRegex(AuditTrustBundleError, "boundary"):
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )

    def test_checksum_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            manifest = create_from_inputs(root, inputs)
            proof_path = root / "bundle" / manifest["entries"][0]["proof_path"]
            proof_path.write_bytes(proof_path.read_bytes() + b" ")
            with self.assertRaisesRegex(AuditTrustBundleError, "checksum"):
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )

    def test_manifest_substitution_fails_external_bundle_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = make_inputs(root / "left", anchor(1))
            right = make_inputs(root / "right", anchor(2))
            left_manifest = create_from_inputs(root / "left", left)
            create_from_inputs(root / "right", right)
            left_bundle = root / "left" / "bundle"
            right_bundle = root / "right" / "bundle"
            for name in (MANIFEST_NAME, CHECKSUMS_NAME):
                (left_bundle / name).write_bytes((right_bundle / name).read_bytes())
            with self.assertRaises(AuditTrustBundleError):
                verify_bundle(
                    left_bundle,
                    expected_bundle_id=left_manifest["bundle_id"],
                    expected_candidate_checkpoint_id=left["candidate"]["checkpoint_id"],
                )

    def test_existing_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            create_from_inputs(root, inputs)
            with self.assertRaisesRegex(AuditTrustBundleError, "already exist"):
                create_from_inputs(root, inputs)

    def test_symlink_inside_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            manifest = create_from_inputs(root, inputs)
            target = root / "target"
            target.write_text("x")
            link = root / "bundle" / "linked"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(AuditTrustBundleError, "symlink"):
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )

    def test_manifest_loader_rejects_duplicate_and_noncanonical_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"bundle_version":1,"bundle_version":1}')
            with self.assertRaisesRegex(AuditTrustBundleError, "strict JSON"):
                load_manifest(duplicate)
            inputs = make_inputs(root, anchor())
            manifest = create_from_inputs(root, inputs)
            compact = root / "compact.json"
            compact.write_text(json.dumps(manifest, sort_keys=True))
            with self.assertRaisesRegex(AuditTrustBundleError, "canonically"):
                load_manifest(compact)

    def test_manifest_rejects_head_marker_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            manifest = create_from_inputs(root, inputs)
            changed = copy.deepcopy(manifest)
            changed["entries"][0]["is_head"] = False
            with self.assertRaisesRegex(AuditTrustBundleError, "head"):
                validate_manifest(changed)

    def test_cli_create_and_verify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            output = root / "bundle"
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                status = main([
                    "create", str(output),
                    "--candidate-checkpoint", str(inputs["candidate_path"]),
                    "--expected-candidate-checkpoint-id", inputs["candidate"]["checkpoint_id"],
                    "--proof", str(inputs["proof_paths"][0]),
                ])
            self.assertEqual(0, status)
            manifest = json.loads((output / MANIFEST_NAME).read_text())
            with contextlib.redirect_stdout(io.StringIO()):
                status = main([
                    "verify", str(output),
                    "--expected-bundle-id", manifest["bundle_id"],
                    "--expected-candidate-checkpoint-id", inputs["candidate"]["checkpoint_id"],
                ])
            self.assertEqual(0, status)
            self.assertIn('"created": true', captured.getvalue())

    def test_cli_denied_and_invalid_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, anchor())
            manifest = create_from_inputs(root, inputs)
            with contextlib.redirect_stderr(io.StringIO()):
                denied = main([
                    "verify", str(root / "bundle"),
                    "--expected-bundle-id", "f" * 64,
                    "--expected-candidate-checkpoint-id", inputs["candidate"]["checkpoint_id"],
                ])
                invalid = main([
                    "verify", str(root / "missing"),
                    "--expected-bundle-id", manifest["bundle_id"],
                    "--expected-candidate-checkpoint-id", inputs["candidate"]["checkpoint_id"],
                ])
        self.assertEqual(1, denied)
        self.assertEqual(2, invalid)


if __name__ == "__main__":
    unittest.main()
