import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_audit_trust_receiver_acceptance_trust_admission import (
    AuditTrustReceiverAcceptanceTrustAdmissionError,
    _policy_outside_bundle,
    adapter_report,
    default_policy,
    evaluate_bundle,
    main,
    policy_sha256,
    validate_policy,
)
from agent_audit_trust_receiver_acceptance_trust_bundle import (
    CANDIDATE_CHECKPOINT_NAME,
)
from test_audit_trust_receiver_acceptance_trust import h
from test_audit_trust_receiver_acceptance_trust_bundle import (
    AcceptanceTrustBundleTests,
)


class AcceptanceTrustAdmissionTests(unittest.TestCase):
    def helper(self):
        return AcceptanceTrustBundleTests()

    def snapshot(self, root: Path):
        state, checkpoint, bundle, manifest = self.helper().snapshot_bundle(root)
        return state, checkpoint, bundle, manifest

    def transition(self, root: Path, previous_entries=1, candidate_entries=2):
        helper = self.helper()
        if previous_entries == 1 and candidate_entries == 2:
            return helper.transition_bundle(root)
        previous, candidate, previous_cp, candidate_cp = helper.evidence(
            root, previous_entries, candidate_entries
        )
        bundle = root / "transition-bundle"
        from agent_audit_trust_receiver_acceptance_trust_bundle import create_bundle

        manifest = create_bundle(
            bundle,
            root / "candidate-checkpoint.json",
            candidate_cp["checkpoint_id"],
            [root / "candidate-proof.json"],
            previous_checkpoint_path=root / "previous-checkpoint.json",
            expected_previous_checkpoint_id=previous_cp["checkpoint_id"],
            consistency_path=root / "consistency.json",
        )
        return previous, candidate, previous_cp, candidate_cp, bundle, manifest

    def evaluate_snapshot(self, root: Path, policy=None):
        _state, checkpoint, bundle, manifest = self.snapshot(root)
        report = evaluate_bundle(
            bundle,
            policy or default_policy(),
            expected_bundle_id=manifest["bundle_id"],
            expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
        )
        return report, checkpoint, bundle, manifest

    def evaluate_transition(self, root: Path, policy=None, previous_entries=1, candidate_entries=2):
        previous, candidate, previous_cp, candidate_cp, bundle, manifest = self.transition(
            root, previous_entries, candidate_entries
        )
        report = evaluate_bundle(
            bundle,
            policy or default_policy(),
            expected_bundle_id=manifest["bundle_id"],
            expected_candidate_checkpoint_id=candidate_cp["checkpoint_id"],
            expected_previous_checkpoint_id=previous_cp["checkpoint_id"],
        )
        return report, previous, candidate, previous_cp, candidate_cp, bundle, manifest

    def assert_denial(self, rule_id, report):
        self.assertFalse(report["admitted"])
        self.assertIn(rule_id, {item["rule_id"] for item in report["violations"]})

    def test_01_default_policy_and_adapter_contract(self):
        policy = validate_policy(default_policy())
        report = adapter_report()
        self.assertEqual("ABM", report["rule_prefix"])
        self.assertIn("min_acceptance_trust_entries", report["candidate_fields"])
        self.assertIn("min_acceptance_trust_entry_delta", report["transition_fields"])
        self.assertEqual(policy, default_policy())

    def test_02_policy_hash_is_deterministic(self):
        first = default_policy()
        second = json.loads(json.dumps(first))
        self.assertEqual(policy_sha256(first), policy_sha256(second))
        second["bundle"]["max_files"] -= 1
        self.assertNotEqual(policy_sha256(first), policy_sha256(second))

    def test_03_snapshot_is_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, checkpoint, _bundle, manifest = self.evaluate_snapshot(Path(temporary))
            self.assertTrue(report["admitted"])
            self.assertEqual("snapshot", report["identity"]["bundle_type"])
            self.assertEqual(manifest["bundle_id"], report["identity"]["bundle_id"])
            self.assertEqual(checkpoint["checkpoint_id"], report["identity"]["candidate_acceptance_trust_checkpoint_id"])

    def test_04_transition_is_admitted_with_nested_deltas(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, *_rest = self.evaluate_transition(Path(temporary))
            self.assertTrue(report["admitted"])
            for name in (
                "acceptance_trust_entry_delta", "acceptance_entry_delta",
                "receiver_entry_delta", "trust_entry_delta", "generation_delta",
                "segment_delta",
            ):
                self.assertEqual(1, report["evidence"][name])

    def test_05_bundle_type_policy_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["bundle"]["allowed_types"] = ["transition"]
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM001", report)

    def test_06_bundle_size_policy_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["bundle"]["max_bytes"] = 1
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM002", report)

    def test_07_proof_count_policy_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["bundle"]["min_proofs"] = 2
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM003", report)

    def test_08_acceptance_trust_depth_policy_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["candidate"]["min_acceptance_trust_entries"] = 2
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM004", report)

    def test_09_acceptance_depth_policy_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["candidate"]["min_acceptance_entries"] = 2
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM005", report)

    def test_10_receiver_and_trust_depth_policy_denials(self):
        for field in ("min_receiver_entries", "min_trust_entries"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                policy = default_policy()
                policy["candidate"][field] = 2
                report, *_ = self.evaluate_snapshot(Path(temporary), policy)
                self.assert_denial("ABM005", report)

    def test_11_generation_and_segment_policy_denials(self):
        for field in ("min_generation", "min_segment_count"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                policy = default_policy()
                policy["candidate"][field] = 2
                report, *_ = self.evaluate_snapshot(Path(temporary), policy)
                self.assert_denial("ABM006", report)

    def test_12_outer_identity_allowlist_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["candidate"]["allowed_acceptance_trust_state_ids"] = [h(999001)]
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM007", report)

    def test_13_nested_identity_allowlist_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["candidate"]["allowed_receiver_checkpoint_ids"] = [h(999002)]
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM008", report)

    def test_14_sequence_selection_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["selection"]["required_sequences"] = [2]
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM009", report)

    def test_15_acceptance_bundle_selection_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["selection"]["required_acceptance_bundle_ids"] = [h(999003)]
            report, *_ = self.evaluate_snapshot(Path(temporary), policy)
            self.assert_denial("ABM010", report)

    def test_16_anchor_requirement_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = default_policy()
            policy["selection"]["require_anchor"] = True
            report, *_ = self.evaluate_transition(Path(temporary), policy)
            self.assert_denial("ABM011", report)

    def test_17_transition_delta_identity_and_single_step_denials(self):
        scenarios = (
            ("max_acceptance_trust_entry_delta", 1, "ABM013", 1, 3),
            ("max_receiver_entry_delta", 1, "ABM014", 1, 3),
            ("allowed_previous_acceptance_state_ids", [h(999004)], "ABM015", 1, 2),
            ("require_single_step", True, "ABM016", 1, 3),
        )
        for field, value, rule_id, previous_entries, candidate_entries in scenarios:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                policy = default_policy()
                policy["transition"][field] = value
                report, *_ = self.evaluate_transition(
                    Path(temporary), policy, previous_entries, candidate_entries
                )
                self.assert_denial(rule_id, report)

    def test_18_invalid_bundle_is_not_a_policy_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot(root)
            (bundle / CANDIDATE_CHECKPOINT_NAME).write_bytes(b"{}\n")
            with self.assertRaises(AuditTrustReceiverAcceptanceTrustAdmissionError) as raised:
                evaluate_bundle(
                    bundle,
                    default_policy(),
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                )
            self.assertEqual("ABM000", raised.exception.rule_id)

    def test_19_policy_must_remain_outside_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, _checkpoint, bundle, _manifest = self.snapshot(root)
            policy_path = bundle / "policy.json"
            policy_path.write_bytes(json.dumps(default_policy()).encode())
            with self.assertRaises(AuditTrustReceiverAcceptanceTrustAdmissionError):
                _policy_outside_bundle(policy_path, bundle)

    def test_20_cli_init_validate_admit_deny_and_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot(root)
            policy_path = root / "policy.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, main(["init", str(policy_path)]))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["validate", str(policy_path)]))
            evaluate_args = [
                "evaluate", str(bundle), "--policy", str(policy_path),
                "--expected-bundle-id", manifest["bundle_id"],
                "--expected-candidate-checkpoint-id", checkpoint["checkpoint_id"],
            ]
            admitted = io.StringIO()
            with contextlib.redirect_stdout(admitted):
                self.assertEqual(0, main(evaluate_args))
            decision = json.loads(admitted.getvalue())
            self.assertTrue(decision["admitted"])
            denied_policy = default_policy()
            denied_policy["bundle"]["allowed_types"] = ["transition"]
            policy_path.write_bytes(canonical_bytes(denied_policy))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, main(evaluate_args))
            (bundle / CANDIDATE_CHECKPOINT_NAME).write_bytes(b"{}\n")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, main(evaluate_args))


def canonical_bytes(payload):
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


if __name__ == "__main__":
    unittest.main()
