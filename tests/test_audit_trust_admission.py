import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

import audit_trust_bundle_cases as bundle_cases
from agent_audit_trust import canonical_json
from agent_audit_trust_admission import (
    AuditTrustAdmissionError,
    default_policy,
    evaluate_handoff,
    load_policy,
    main,
    policy_sha256,
    validate_policy,
)
from test_audit_trust_consistency import advance, anchor


bundle_cases.write_json = lambda path, payload: path.write_bytes(canonical_json(payload))


def make_bundle(root, candidate, previous=None, sequences=None, name="bundle"):
    inputs = bundle_cases.make_inputs(root, candidate, previous, sequences)
    manifest = bundle_cases.create_from_inputs(root, inputs, name=name)
    return inputs, manifest, root / name


def evaluate(root, candidate, previous=None, sequences=None, policy=None):
    inputs, manifest, bundle = make_bundle(root, candidate, previous, sequences)
    return evaluate_handoff(
        bundle,
        policy or default_policy(),
        expected_bundle_id=manifest["bundle_id"],
        expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
        expected_previous_checkpoint_id=(inputs.get("previous") or {}).get("checkpoint_id"),
    ), inputs, manifest, bundle


class AuditTrustAdmissionTests(unittest.TestCase):
    def test_default_policy_is_canonical_and_deterministic(self):
        policy = default_policy()
        self.assertEqual(policy, validate_policy(copy.deepcopy(policy)))
        self.assertEqual(policy_sha256(policy), policy_sha256(copy.deepcopy(policy)))

    def test_policy_rejects_schema_order_and_range_errors(self):
        policy = default_policy()
        policy["extra"] = True
        with self.assertRaises(AuditTrustAdmissionError):
            validate_policy(policy)
        policy = default_policy()
        policy["bundle"]["allowed_types"] = ["transition", "snapshot"]
        with self.assertRaisesRegex(AuditTrustAdmissionError, "sorted"):
            validate_policy(policy)
        policy = default_policy()
        policy["candidate"]["min_entry_count"] = 3
        policy["candidate"]["max_entry_count"] = 2
        with self.assertRaisesRegex(AuditTrustAdmissionError, "minimum"):
            validate_policy(policy)

    def test_policy_requires_canonical_serialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_text(json.dumps(default_policy()), encoding="utf-8")
            with self.assertRaisesRegex(AuditTrustAdmissionError, "canonically"):
                load_policy(path)

    def test_snapshot_is_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), anchor())
        self.assertTrue(report["admitted"])
        self.assertEqual([], report["violations"])
        self.assertIsNone(report["evidence"]["entry_delta"])

    def test_transition_is_admitted(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), candidate, previous, [1, 2])
        self.assertTrue(report["admitted"])
        self.assertEqual(1, report["evidence"]["entry_delta"])
        self.assertEqual(1, report["evidence"]["generation_delta"])

    def test_bundle_type_policy_denies(self):
        policy = default_policy()
        policy["bundle"]["allowed_types"] = ["transition"]
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), anchor(), policy=policy)
        self.assertFalse(report["admitted"])
        self.assertEqual("ATA001", report["violations"][0]["rule_id"])

    def test_size_and_proof_limits_deny(self):
        policy = default_policy()
        policy["bundle"]["max_files"] = 1
        policy["bundle"]["max_bytes"] = 1
        policy["bundle"]["min_proofs"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), anchor(), policy=policy)
        self.assertEqual({"ATA002", "ATA003"}, {item["rule_id"] for item in report["violations"]})

    def test_candidate_bounds_deny(self):
        policy = default_policy()
        policy["candidate"]["min_entry_count"] = 2
        policy["candidate"]["min_generation"] = 2
        policy["candidate"]["min_segment_count"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), anchor(), policy=policy)
        self.assertEqual({"ATA004", "ATA005", "ATA006"}, {item["rule_id"] for item in report["violations"]})

    def test_candidate_identity_allowlists(self):
        policy = default_policy()
        policy["candidate"]["allowed_state_ids"] = ["f" * 64]
        policy["candidate"]["allowed_checkpoint_ids"] = ["e" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), anchor(), policy=policy)
        self.assertEqual(["ATA007", "ATA007"], [item["rule_id"] for item in report["violations"]])

    def test_head_identity_allowlists(self):
        policy = default_policy()
        policy["candidate"]["allowed_head_bundle_ids"] = ["f" * 64]
        policy["candidate"]["allowed_head_catalog_ids"] = ["e" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), anchor(), policy=policy)
        self.assertEqual(["ATA008", "ATA008"], [item["rule_id"] for item in report["violations"]])

    def test_required_and_allowed_sequences(self):
        previous = anchor()
        candidate = advance(previous)
        policy = default_policy()
        policy["selection"]["required_sequences"] = [1]
        policy["selection"]["allowed_sequences"] = [1]
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), candidate, previous, [2], policy)
        self.assertEqual({"ATA009"}, {item["rule_id"] for item in report["violations"]})

    def test_required_and_allowed_bundle_ids(self):
        state = anchor()
        required = state["head"]["bundle_id"]
        policy = default_policy()
        policy["selection"]["required_bundle_ids"] = [required]
        policy["selection"]["allowed_bundle_ids"] = [required]
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), state, policy=policy)
        self.assertTrue(report["admitted"])
        policy["selection"]["required_bundle_ids"] = ["f" * 64]
        policy["selection"]["allowed_bundle_ids"] = []
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), state, policy=policy)
        self.assertEqual("ATA010", report["violations"][0]["rule_id"])

    def test_anchor_requirement_denies_head_only_transition(self):
        previous = anchor()
        candidate = advance(previous)
        policy = default_policy()
        policy["selection"]["require_anchor"] = True
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), candidate, previous, [2], policy)
        self.assertEqual("ATA011", report["violations"][0]["rule_id"])

    def test_transition_delta_controls(self):
        previous = anchor()
        candidate = advance(previous)
        policy = default_policy()
        policy["transition"]["min_entry_delta"] = 2
        policy["transition"]["min_generation_delta"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), candidate, previous, policy=policy)
        self.assertEqual({"ATA013", "ATA014"}, {item["rule_id"] for item in report["violations"]})

    def test_previous_identity_allowlists(self):
        previous = anchor()
        candidate = advance(previous)
        policy = default_policy()
        policy["transition"]["allowed_previous_state_ids"] = ["f" * 64]
        policy["transition"]["allowed_previous_checkpoint_ids"] = ["e" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), candidate, previous, policy=policy)
        self.assertEqual(["ATA015", "ATA015"], [item["rule_id"] for item in report["violations"]])

    def test_single_step_policy_denies_multi_append(self):
        previous = anchor()
        middle = advance(previous, 2)
        candidate = advance(middle, 3)
        policy = default_policy()
        policy["transition"]["require_single_step"] = True
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _, _ = evaluate(Path(temporary), candidate, previous, policy=policy)
        self.assertEqual("ATA016", report["violations"][0]["rule_id"])

    def test_invalid_handoff_is_invalid_not_policy_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(AuditTrustAdmissionError, "verification failed"):
                evaluate_handoff(
                    root / "missing",
                    default_policy(),
                    expected_bundle_id="f" * 64,
                    expected_candidate_checkpoint_id="e" * 64,
                )

    def test_decision_id_is_deterministic_and_policy_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, manifest, bundle = make_bundle(root, anchor())
            arguments = dict(
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=inputs["candidate"]["checkpoint_id"],
            )
            first = evaluate_handoff(bundle, default_policy(), **arguments)
            second = evaluate_handoff(bundle, default_policy(), **arguments)
            policy = default_policy()
            policy["candidate"]["max_entry_count"] = 10
            third = evaluate_handoff(bundle, policy, **arguments)
        self.assertEqual(first["decision_id"], second["decision_id"])
        self.assertNotEqual(first["decision_id"], third["decision_id"])

    def test_cli_init_validate_and_evaluate_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_path = root / "policy.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(policy_path)]))
                self.assertEqual(0, main(["validate", str(policy_path)]))
            inputs, manifest, bundle = make_bundle(root / "input", anchor())
            args = [
                "evaluate", str(bundle), "--policy", str(policy_path),
                "--expected-bundle-id", manifest["bundle_id"],
                "--expected-candidate-checkpoint-id", inputs["candidate"]["checkpoint_id"],
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(args))
            denied = default_policy()
            denied["bundle"]["allowed_types"] = ["transition"]
            policy_path.write_bytes(canonical_json(denied))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, main(args))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, main(args[:-1] + ["f" * 64]))

    def test_cli_refuses_policy_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_bytes(canonical_json(default_policy()))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, main(["init", str(path)]))


if __name__ == "__main__":
    unittest.main()
