import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_audit_trust_receiver_acceptance import canonical_json
from agent_audit_trust_receiver_acceptance_admission import (
    AuditTrustReceiverAcceptanceAdmissionError,
    adapter_report,
    default_policy,
    evaluate_bundle,
    load_policy,
    main,
    policy_sha256,
    validate_policy,
)
from agent_audit_trust_receiver_acceptance_bundle import create_bundle
from agent_audit_trust_receiver_acceptance_checkpoint import create_checkpoint, create_proof
from agent_audit_trust_receiver_acceptance_consistency import create_consistency_proof
from test_audit_trust_receiver_acceptance import h
from test_audit_trust_receiver_acceptance_consistency import acceptance_state


def bundle_case(
    root: Path,
    entries: int,
    previous_entries: int | None = None,
    sequences: list[int] | None = None,
):
    candidate = acceptance_state(entries)
    previous = acceptance_state(previous_entries) if previous_entries is not None else None
    candidate_cp = create_checkpoint(candidate)
    previous_cp = create_checkpoint(previous) if previous is not None else None
    selected = sequences or [candidate_cp["entry_count"]]
    proofs = [create_proof(candidate, candidate_cp, sequence=sequence) for sequence in selected]
    (root / "candidate-checkpoint.json").write_bytes(canonical_json(candidate_cp))
    proof_paths = []
    for index, proof in enumerate(proofs, 1):
        path = root / f"proof-{index}.json"
        path.write_bytes(canonical_json(proof))
        proof_paths.append(path)
    kwargs = {}
    if previous is not None and previous_cp is not None:
        consistency = create_consistency_proof(previous, previous_cp, candidate, candidate_cp)
        (root / "previous-checkpoint.json").write_bytes(canonical_json(previous_cp))
        (root / "consistency.json").write_bytes(canonical_json(consistency))
        kwargs = {
            "previous_checkpoint_path": root / "previous-checkpoint.json",
            "expected_previous_checkpoint_id": previous_cp["checkpoint_id"],
            "consistency_path": root / "consistency.json",
        }
    bundle = root / "bundle"
    manifest = create_bundle(
        bundle,
        root / "candidate-checkpoint.json",
        candidate_cp["checkpoint_id"],
        proof_paths,
        **kwargs,
    )
    return {
        "candidate": candidate_cp,
        "previous": previous_cp,
        "manifest": manifest,
        "bundle": bundle,
    }


def evaluate(
    root: Path,
    entries: int,
    previous_entries: int | None = None,
    policy=None,
    sequences: list[int] | None = None,
):
    case = bundle_case(root, entries, previous_entries, sequences)
    report = evaluate_bundle(
        case["bundle"],
        policy or default_policy(),
        expected_bundle_id=case["manifest"]["bundle_id"],
        expected_candidate_checkpoint_id=case["candidate"]["checkpoint_id"],
        expected_previous_checkpoint_id=(
            case["previous"]["checkpoint_id"] if case["previous"] is not None else None
        ),
    )
    return case, report


class AcceptanceAdmissionTests(unittest.TestCase):
    def test_01_adapter_contract_is_acceptance_specific(self):
        report = adapter_report()
        self.assertEqual("ABA", report["rule_prefix"])
        self.assertIn("acceptance", report["bundle_module"])
        self.assertIn("allowed_acceptance_state_ids", report["candidate_fields"])
        self.assertIn("min_acceptance_entry_delta", report["transition_fields"])

    def test_02_default_policy_is_canonical_and_hash_is_deterministic(self):
        policy = default_policy()
        self.assertEqual(policy, validate_policy(policy))
        self.assertEqual(policy_sha256(policy), policy_sha256(copy.deepcopy(policy)))
        self.assertEqual(64, len(policy_sha256(policy)))

    def test_03_policy_rejects_extra_fields_and_boolean_integers(self):
        policy = default_policy()
        policy["extra"] = {}
        with self.assertRaises(AuditTrustReceiverAcceptanceAdmissionError):
            validate_policy(policy)
        policy = default_policy()
        policy["bundle"]["max_files"] = True
        with self.assertRaises(AuditTrustReceiverAcceptanceAdmissionError):
            validate_policy(policy)

    def test_04_policy_rejects_bad_ranges_and_unsorted_allowlists(self):
        policy = default_policy()
        policy["candidate"]["min_acceptance_entries"] = 3
        policy["candidate"]["max_acceptance_entries"] = 2
        with self.assertRaises(AuditTrustReceiverAcceptanceAdmissionError):
            validate_policy(policy)
        policy = default_policy()
        policy["selection"]["allowed_sequences"] = [2, 1]
        with self.assertRaises(AuditTrustReceiverAcceptanceAdmissionError):
            validate_policy(policy)

    def test_05_policy_file_requires_strict_canonical_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_bytes(canonical_json(default_policy()))
            self.assertEqual(default_policy(), load_policy(path))
            path.write_text(json.dumps(default_policy()))
            with self.assertRaisesRegex(
                AuditTrustReceiverAcceptanceAdmissionError, "canonically"
            ):
                load_policy(path)

    def test_06_snapshot_bundle_is_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 1)
        self.assertTrue(report["admitted"])
        self.assertEqual("snapshot", report["identity"]["bundle_type"])
        self.assertEqual([1], report["evidence"]["selected_sequences"])

    def test_07_transition_bundle_is_admitted_with_all_deltas(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 3, 1, sequences=[1, 3])
        self.assertTrue(report["admitted"])
        self.assertEqual(2, report["evidence"]["acceptance_entry_delta"])
        self.assertEqual(2, report["evidence"]["receiver_entry_delta"])
        self.assertEqual(2, report["evidence"]["trust_entry_delta"])
        self.assertEqual(2, report["evidence"]["generation_delta"])
        self.assertEqual(2, report["evidence"]["segment_delta"])

    def test_08_bundle_type_policy_denies_snapshot(self):
        policy = default_policy()
        policy["bundle"]["allowed_types"] = ["transition"]
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual("ABA001", report["violations"][0]["rule_id"])

    def test_09_size_and_proof_count_policies_deny(self):
        policy = default_policy()
        policy["bundle"]["max_files"] = 1
        policy["bundle"]["max_bytes"] = 1
        policy["bundle"]["min_proofs"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual({"ABA002", "ABA003"}, {v["rule_id"] for v in report["violations"]})

    def test_10_candidate_acceptance_receiver_and_trust_counts_deny(self):
        policy = default_policy()
        policy["candidate"]["max_acceptance_entries"] = 1
        policy["candidate"]["max_receiver_entries"] = 1
        policy["candidate"]["max_trust_entries"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 2, 1, policy=policy)
        self.assertEqual({"ABA004", "ABA005"}, {v["rule_id"] for v in report["violations"]})

    def test_11_generation_and_segment_controls_deny(self):
        policy = default_policy()
        policy["candidate"]["max_generation"] = 1
        policy["candidate"]["max_segment_count"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 2, 1, policy=policy)
        self.assertEqual({"ABA006"}, {v["rule_id"] for v in report["violations"]})

    def test_12_candidate_acceptance_identity_controls_deny(self):
        policy = default_policy()
        policy["candidate"]["allowed_acceptance_state_ids"] = ["f" * 64]
        policy["candidate"]["allowed_acceptance_checkpoint_ids"] = ["f" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual({"ABA007"}, {v["rule_id"] for v in report["violations"]})

    def test_13_downstream_identity_controls_deny(self):
        policy = default_policy()
        for key in (
            "allowed_head_receiver_bundle_ids", "allowed_head_trust_handoff_ids",
            "allowed_receiver_state_ids", "allowed_receiver_checkpoint_ids",
            "allowed_trust_state_ids", "allowed_trust_checkpoint_ids",
        ):
            policy["candidate"][key] = ["f" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual({"ABA008"}, {v["rule_id"] for v in report["violations"]})

    def test_14_sequence_selection_controls_deny(self):
        policy = default_policy()
        policy["selection"]["required_sequences"] = [1, 2]
        policy["selection"]["allowed_sequences"] = [1, 2]
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual("ABA009", report["violations"][0]["rule_id"])

    def test_15_receiver_bundle_selection_controls_deny(self):
        policy = default_policy()
        policy["selection"]["required_receiver_bundle_ids"] = ["f" * 64]
        policy["selection"]["allowed_receiver_bundle_ids"] = ["f" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 1, policy=policy)
        self.assertEqual("ABA010", report["violations"][0]["rule_id"])

    def test_16_anchor_and_head_requirements_deny_missing_selection(self):
        policy = default_policy()
        policy["selection"]["require_anchor"] = True
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 2, 1, policy=policy, sequences=[2])
        self.assertIn("ABA011", {v["rule_id"] for v in report["violations"]})

    def test_17_transition_relation_policy_denies_unallowed_relation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = bundle_case(root, 2, 1)
            from agent_audit_trust_receiver_acceptance_bundle import verify_bundle as real_verify

            verified = real_verify(
                case["bundle"],
                expected_bundle_id=case["manifest"]["bundle_id"],
                expected_candidate_checkpoint_id=case["candidate"]["checkpoint_id"],
                expected_previous_checkpoint_id=case["previous"]["checkpoint_id"],
            )
            verified = copy.deepcopy(verified)
            verified["consistency"]["relation"] = "fork"
            with mock.patch(
                "agent_audit_trust_receiver_acceptance_admission.verify_bundle",
                return_value=verified,
            ):
                report = evaluate_bundle(
                    case["bundle"],
                    default_policy(),
                    expected_bundle_id=case["manifest"]["bundle_id"],
                    expected_candidate_checkpoint_id=case["candidate"]["checkpoint_id"],
                    expected_previous_checkpoint_id=case["previous"]["checkpoint_id"],
                )
        self.assertEqual("ABA012", report["violations"][0]["rule_id"])

    def test_18_transition_delta_previous_and_single_step_controls_deny(self):
        policy = default_policy()
        policy["transition"]["max_acceptance_entry_delta"] = 1
        policy["transition"]["max_receiver_entry_delta"] = 1
        policy["transition"]["max_trust_entry_delta"] = 1
        policy["transition"]["max_generation_delta"] = 1
        policy["transition"]["max_segment_delta"] = 1
        for key in (
            "allowed_previous_acceptance_state_ids",
            "allowed_previous_acceptance_checkpoint_ids",
            "allowed_previous_receiver_state_ids",
            "allowed_previous_receiver_checkpoint_ids",
            "allowed_previous_trust_state_ids",
            "allowed_previous_trust_checkpoint_ids",
        ):
            policy["transition"][key] = ["f" * 64]
        policy["transition"]["require_single_step"] = True
        with tempfile.TemporaryDirectory() as temporary:
            _, report = evaluate(Path(temporary), 3, 1, policy=policy)
        self.assertEqual(
            {"ABA013", "ABA014", "ABA015", "ABA016"},
            {v["rule_id"] for v in report["violations"]},
        )

    def test_19_manifest_identity_change_and_policy_inside_bundle_are_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = bundle_case(root, 1)
            changed = copy.deepcopy(case["manifest"])
            changed["bundle_id"] = "f" * 64
            with mock.patch(
                "agent_audit_trust_receiver_acceptance_admission.load_manifest",
                return_value=changed,
            ):
                with self.assertRaisesRegex(
                    AuditTrustReceiverAcceptanceAdmissionError, "identity changed"
                ):
                    evaluate_bundle(
                        case["bundle"],
                        default_policy(),
                        expected_bundle_id=case["manifest"]["bundle_id"],
                        expected_candidate_checkpoint_id=case["candidate"]["checkpoint_id"],
                    )
            policy_path = case["bundle"] / "policy.json"
            policy_path.write_bytes(canonical_json(default_policy()))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main(
                    [
                        "evaluate", str(case["bundle"]), "--policy", str(policy_path),
                        "--expected-bundle-id", case["manifest"]["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        case["candidate"]["checkpoint_id"],
                    ]
                )
        self.assertEqual(2, status)
        self.assertIn("outside", error.getvalue())

    def test_20_cli_init_validate_admit_deny_and_invalid_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = bundle_case(root, 1)
            policy_path = root / "policy.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(policy_path)]))
                self.assertEqual(0, main(["validate", str(policy_path)]))
            admitted = io.StringIO()
            with contextlib.redirect_stdout(admitted):
                status = main(
                    [
                        "evaluate", str(case["bundle"]), "--policy", str(policy_path),
                        "--expected-bundle-id", case["manifest"]["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        case["candidate"]["checkpoint_id"],
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
                        "evaluate", str(case["bundle"]), "--policy", str(policy_path),
                        "--expected-bundle-id", case["manifest"]["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        case["candidate"]["checkpoint_id"],
                    ]
                )
            self.assertEqual(1, denied)
            with contextlib.redirect_stderr(io.StringIO()):
                invalid = main(
                    [
                        "evaluate", str(case["bundle"]), "--policy", str(policy_path),
                        "--expected-bundle-id", "f" * 64,
                        "--expected-candidate-checkpoint-id",
                        case["candidate"]["checkpoint_id"],
                    ]
                )
            self.assertEqual(2, invalid)


if __name__ == "__main__":
    unittest.main()
