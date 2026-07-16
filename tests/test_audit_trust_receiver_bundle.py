import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_audit_trust_receiver import canonical_json
from agent_audit_trust_receiver_bundle import (
    AuditTrustReceiverBundleError,
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    create_bundle,
    load_manifest,
    main,
    validate_manifest,
    verify_bundle,
)
from agent_audit_trust_receiver_checkpoint import create_checkpoint, create_proof
from agent_audit_trust_receiver_consistency import create_consistency_proof
from test_audit_trust_receiver_consistency import receiver_state


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(payload))


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
        expected_previous_checkpoint_id=inputs.get("previous", {}).get("checkpoint_id"),
        consistency_path=inputs.get("consistency_path"),
    )


class ReceiverBundleTests(unittest.TestCase):
    def test_01_snapshot_roundtrip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            report = verify_bundle(
                root / "bundle",
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
            )
        self.assertEqual("snapshot", report["bundle_type"])
        self.assertEqual(1, report["proof_count"])
        self.assertEqual(
            inputs["candidate"]["head"]["handoff_bundle_id"],
            report["head_handoff_bundle_id"],
        )

    def test_02_transition_roundtrip_with_selected_history(self):
        previous = receiver_state(1)
        candidate = receiver_state(3)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, candidate, previous, sequences=[1, 3])
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

    def test_03_bundle_verifies_without_loose_sources(self):
        previous = receiver_state(1)
        candidate = receiver_state(2)
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

    def test_04_candidate_head_proof_is_mandatory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(2), sequences=[1])
            with self.assertRaises(AuditTrustReceiverBundleError) as raised:
                create_from_inputs(root, inputs)
        self.assertEqual("ARB012", raised.exception.rule_id)

    def test_05_duplicate_proof_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            inputs["proof_paths"].append(inputs["proof_paths"][0])
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "duplicate"):
                create_from_inputs(root, inputs)

    def test_06_proof_from_another_checkpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1, 1))
            other = make_inputs(root / "other", receiver_state(1, 2))
            inputs["proof_paths"] = other["proof_paths"]
            with self.assertRaises(AuditTrustReceiverBundleError) as raised:
                create_from_inputs(root, inputs)
        self.assertEqual("ARB004", raised.exception.rule_id)

    def test_07_partial_transition_is_rejected(self):
        previous = receiver_state(1)
        candidate = receiver_state(2)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, candidate, previous)
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "requires previous"):
                create_bundle(
                    root / "bundle",
                    inputs["candidate_path"],
                    inputs["candidate"]["checkpoint_id"],
                    inputs["proof_paths"],
                    previous_checkpoint_path=inputs["previous_path"],
                )

    def test_08_same_checkpoint_cannot_be_transition(self):
        state = receiver_state(1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, state, state)
            with self.assertRaises(AuditTrustReceiverBundleError) as raised:
                create_from_inputs(root, inputs)
        self.assertIn(raised.exception.rule_id, {"ARB005", "ARB006"})

    def test_09_wrong_bundle_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            create_from_inputs(root, inputs)
            with self.assertRaises(AuditTrustReceiverBundleError) as raised:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id="f" * 64,
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )
        self.assertTrue(raised.exception.denied)
        self.assertEqual("ARB003", raised.exception.rule_id)

    def test_10_wrong_candidate_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            with self.assertRaises(AuditTrustReceiverBundleError) as raised:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id="f" * 64,
                )
        self.assertTrue(raised.exception.denied)

    def test_11_transition_requires_previous_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(2), receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            with self.assertRaises(AuditTrustReceiverBundleError) as raised:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )
        self.assertTrue(raised.exception.denied)

    def test_12_wrong_previous_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(2), receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            with self.assertRaises(AuditTrustReceiverBundleError) as raised:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                    expected_previous_checkpoint_id="f" * 64,
                )
        self.assertTrue(raised.exception.denied)

    def test_13_extra_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            (root / "bundle" / "extra.txt").write_text("extra")
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "boundary"):
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )

    def test_14_checksum_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            proof_path = root / "bundle" / manifest["entries"][0]["proof_path"]
            proof_path.write_bytes(proof_path.read_bytes() + b" ")
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "checksum"):
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )

    def test_15_manifest_substitution_fails_external_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = make_inputs(root / "left", receiver_state(1, 1))
            right = make_inputs(root / "right", receiver_state(1, 2))
            left_manifest = create_from_inputs(root / "left", left)
            create_from_inputs(root / "right", right)
            left_bundle = root / "left" / "bundle"
            right_bundle = root / "right" / "bundle"
            for name in (MANIFEST_NAME, CHECKSUMS_NAME):
                (left_bundle / name).write_bytes((right_bundle / name).read_bytes())
            with self.assertRaises(AuditTrustReceiverBundleError):
                verify_bundle(
                    left_bundle,
                    expected_bundle_id=left_manifest["bundle_id"],
                    expected_candidate_checkpoint_id=left["candidate"]["checkpoint_id"],
                )

    def test_16_existing_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            create_from_inputs(root, inputs)
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "already exist"):
                create_from_inputs(root, inputs)

    def test_17_symlink_inside_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            target = root / "target"
            target.write_text("x")
            link = root / "bundle" / "linked"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "symlink"):
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                )

    def test_18_manifest_loader_rejects_duplicate_and_noncanonical_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"bundle_version":1,"bundle_version":1}')
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "strict JSON"):
                load_manifest(duplicate)
            inputs = make_inputs(root, receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            pretty = root / "pretty.json"
            pretty.write_text(json.dumps(manifest, sort_keys=True, indent=2))
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "canonically"):
                load_manifest(pretty)

    def test_19_manifest_rejects_head_marker_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            manifest = create_from_inputs(root, inputs)
            changed = copy.deepcopy(manifest)
            changed["entries"][0]["is_head"] = False
            with self.assertRaisesRegex(AuditTrustReceiverBundleError, "head"):
                validate_manifest(changed)

    def test_20_cli_create_verify_and_invalid_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_inputs(root, receiver_state(1))
            output = root / "bundle"
            with contextlib.redirect_stdout(io.StringIO()):
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
            with contextlib.redirect_stderr(io.StringIO()):
                status = main([
                    "verify", str(output),
                    "--expected-bundle-id", "not-a-pin",
                    "--expected-candidate-checkpoint-id", inputs["candidate"]["checkpoint_id"],
                ])
            self.assertEqual(2, status)


if __name__ == "__main__":
    unittest.main()
