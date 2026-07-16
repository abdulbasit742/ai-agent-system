import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_audit_trust_receiver_admission import (
    AuditTrustReceiverAdmissionError,
    canonical_json,
    default_policy,
    evaluate_bundle,
    load_policy,
    main,
    policy_sha256,
    validate_policy,
)
from test_audit_trust_receiver_bundle import create_from_inputs, make_inputs
from test_audit_trust_receiver_consistency import receiver_state


def bundle_case(root: Path, entries: int, previous_entries: int | None = None, sequences=None):
    candidate = receiver_state(entries)
    previous = receiver_state(previous_entries) if previous_entries is not None else None
    inputs = make_inputs(root, candidate, previous, sequences=sequences)
    manifest = create_from_inputs(root, inputs)
    return inputs, manifest, root / "bundle"


def evaluate(root: Path, entries: int, previous_entries: int | None = None, policy=None, sequences=None):
    inputs, manifest, bundle = bundle_case(root, entries, previous_entries, sequences)
    report = evaluate_bundle(
        bundle,
        policy or default_policy(),
        expected_bundle_id=manifest["bundle_id"],
        expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
        expected_previous_checkpoint_id=(
            inputs["previous"]["checkpoint_id"] if previous_entries is not None else None
        ),
    )
    return inputs, manifest, bundle, report


class ReceiverAdmissionTests(unittest.TestCase):
    def test_01_default_policy_is_canonical_and_hash_is_deterministic(self):
        policy = default_policy()
        self.assertEqual(policy, validate_policy(policy))
        self.assertEqual(policy_sha256(policy), policy_sha256(copy.deepcopy(policy)))
        self.assertEqual(64, len(policy_sha256(policy)))

    def test_02_policy_rejects_extra_fields_and_boolean_integers(self):
        policy = default_policy()
        policy["extra"] = {}
        with self.assertRaises(AuditTrustReceiverAdmissionError):
            validate_policy(policy)
        policy = default_policy()
        policy["bundle"]["max_files"] = True
        with self.assertRaises(AuditTrustReceiverAdmissionError):
            validate_policy(policy)

    def test_03_policy_rejects_bad_ranges_and_unsorted_allowlists(self):
        policy = default_policy()
        policy["candidate"]["min_generation"] = 3
        policy["candidate"]["max_generation"] = 2
        with self.assertRaises(AuditTrustReceiverAdmissionError):
            validate_policy(policy)
        policy = default_policy()
        policy["selection"]["allowed_sequences"] = [2, 1]
        with self.assertRaises(AuditTrustReceiverAdmissionError):
            validate_policy(policy)

    def test_04_policy_file_requires_strict_canonical_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_bytes(canonical_json(default_policy()))
            self.assertEqual(default_policy(), load_policy(path))
            path.write_text(json.dumps(default_policy()))
            with self.assertRaisesRegex(AuditTrustReceiverAdmissionError, "canonically"):
                load_policy(path)

    def test_05_snapshot_bundle_is_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 1)
        self.assertTrue(report["admitted"])
        self.assertEqual("snapshot", report["identity"]["bundle_type"])
        self.assertEqual([1], report["evidence"]["selected_sequences"])

    def test_06_transition_bundle_is_admitted_with_distinct_deltas(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 3, 1, sequences=[1, 3])
        self.assertTrue(report["admitted"])
        self.assertEqual(2, report["evidence"]["receiver_entry_delta"])
        self.assertEqual(4, report["evidence"]["trust_entry_delta"])
        self.assertEqual(2, report["evidence"]["generation_delta"])

    def test_07_bundle_type_policy_denies_snapshot(self):
        policy = default_policy()
        policy["bundle"]["allowed_types"] = ["transition"]
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertFalse(report["admitted"])
        self.assertEqual("ARA001", report["violations"][0]["rule_id"])

    def test_08_bundle_size_policy_denies(self):
        policy = default_policy()
        policy["bundle"]["max_files"] = 1
        policy["bundle"]["max_bytes"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual("ARA002", report["violations"][0]["rule_id"])

    def test_09_proof_count_policy_denies(self):
        policy = default_policy()
        policy["bundle"]["min_proofs"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual("ARA003", report["violations"][0]["rule_id"])

    def test_10_candidate_entry_count_controls_deny(self):
        policy = default_policy()
        policy["candidate"]["max_receiver_entries"] = 1
        policy["candidate"]["max_trust_entries"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 2, 1, policy=policy)
        self.assertEqual({"ARA004"}, {v["rule_id"] for v in report["violations"]})

    def test_11_generation_and_segment_controls_deny(self):
        policy = default_policy()
        policy["candidate"]["max_generation"] = 1
        policy["candidate"]["max_segment_count"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 2, 1, policy=policy)
        self.assertEqual({"ARA005", "ARA006"}, {v["rule_id"] for v in report["violations"]})

    def test_12_candidate_receiver_identity_controls_deny(self):
        policy = default_policy()
        policy["candidate"]["allowed_receiver_state_ids"] = ["f" * 64]
        policy["candidate"]["allowed_receiver_checkpoint_ids"] = ["f" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual({"ARA007"}, {v["rule_id"] for v in report["violations"]})

    def test_13_head_trust_identity_controls_deny(self):
        policy = default_policy()
        policy["candidate"]["allowed_head_handoff_ids"] = ["f" * 64]
        policy["candidate"]["allowed_trust_state_ids"] = ["f" * 64]
        policy["candidate"]["allowed_trust_checkpoint_ids"] = ["f" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual({"ARA008"}, {v["rule_id"] for v in report["violations"]})

    def test_14_sequence_selection_controls_deny(self):
        policy = default_policy()
        policy["selection"]["required_sequences"] = [1, 2]
        policy["selection"]["allowed_sequences"] = [1, 2]
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual("ARA009", report["violations"][0]["rule_id"])

    def test_15_handoff_selection_controls_deny(self):
        policy = default_policy()
        policy["selection"]["required_handoff_ids"] = ["f" * 64]
        policy["selection"]["allowed_handoff_ids"] = ["f" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual("ARA010", report["violations"][0]["rule_id"])

    def test_16_anchor_and_head_requirements_deny_missing_selection(self):
        policy = default_policy()
        policy["selection"]["require_anchor"] = True
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(
                Path(temporary), 2, 1, policy=policy, sequences=[2]
            )
        self.assertIn("ARA011", {v["rule_id"] for v in report["violations"]})

    def test_17_transition_relation_policy_denies_unallowed_relation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, manifest, bundle = bundle_case(root, 2, 1)
            from agent_audit_trust_receiver_bundle import verify_bundle as real_verify

            verified = real_verify(
                bundle,
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                expected_previous_checkpoint_id=inputs["previous"]["checkpoint_id"],
            )
            verified = copy.deepcopy(verified)
            verified["consistency"]["relation"] = "fork"
            with mock.patch(
                "agent_audit_trust_receiver_admission.verify_bundle", return_value=verified
            ):
                report = evaluate_bundle(
                    bundle,
                    default_policy(),
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                    expected_previous_checkpoint_id=inputs["previous"]["checkpoint_id"],
                )
        self.assertEqual("ARA012", report["violations"][0]["rule_id"])

    def test_18_transition_delta_previous_and_single_step_controls_deny(self):
        policy = default_policy()
        policy["transition"]["max_receiver_entry_delta"] = 1
        policy["transition"]["max_trust_entry_delta"] = 1
        policy["transition"]["max_generation_delta"] = 1
        policy["transition"]["allowed_previous_receiver_state_ids"] = ["f" * 64]
        policy["transition"]["allowed_previous_receiver_checkpoint_ids"] = ["f" * 64]
        policy["transition"]["require_single_step"] = True
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = evaluate(Path(temporary), 3, 1, policy=policy)
        self.assertEqual(
            {"ARA013", "ARA014", "ARA015", "ARA016"},
            {v["rule_id"] for v in report["violations"]},
        )

    def test_19_manifest_identity_change_and_policy_inside_bundle_are_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, manifest, bundle = bundle_case(root, 1)
            changed = copy.deepcopy(manifest)
            changed["bundle_id"] = "f" * 64
            with mock.patch(
                "agent_audit_trust_receiver_admission.load_manifest", return_value=changed
            ):
                with self.assertRaisesRegex(
                    AuditTrustReceiverAdmissionError, "identity changed"
                ):
                    evaluate_bundle(
                        bundle,
                        default_policy(),
                        expected_bundle_id=manifest["bundle_id"],
                        expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
                    )
            policy_path = bundle / "policy.json"
            policy_path.write_bytes(canonical_json(default_policy()))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main(
                    [
                        "evaluate", str(bundle), "--policy", str(policy_path),
                        "--expected-bundle-id", manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        inputs["candidate"]["checkpoint_id"],
                    ]
                )
        self.assertEqual(2, status)
        self.assertIn("outside", error.getvalue())

    def test_20_cli_init_validate_admit_deny_and_invalid_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, manifest, bundle = bundle_case(root, 1)
            policy_path = root / "policy.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(policy_path)]))
                self.assertEqual(0, main(["validate", str(policy_path)]))
            admitted = io.StringIO()
            with contextlib.redirect_stdout(admitted):
                status = main(
                    [
                        "evaluate", str(bundle), "--policy", str(policy_path),
                        "--expected-bundle-id", manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        inputs["candidate"]["checkpoint_id"],
                    ]
                )
            self.assertEqual(0, status)
            self.assertTrue(json.loads(admitted.getvalue())["admitted"])
            policy = default_policy()
            policy["bundle"]["allowed_types"] = ["transition"]
            policy_path.write_bytes(canonical_json(policy))
            with contextlib.redirect_stdout(io.StringIO()):
                denied = main(
                    [
                        "evaluate", str(bundle), "--policy", str(policy_path),
                        "--expected-bundle-id", manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        inputs["candidate"]["checkpoint_id"],
                    ]
                )
            self.assertEqual(1, denied)
            with contextlib.redirect_stderr(io.StringIO()):
                invalid = main(
                    [
                        "evaluate", str(bundle), "--policy", str(policy_path),
                        "--expected-bundle-id", "f" * 64,
                        "--expected-candidate-checkpoint-id",
                        inputs["candidate"]["checkpoint_id"],
                    ]
                )
            self.assertEqual(2, invalid)


if __name__ == "__main__":
    unittest.main()
