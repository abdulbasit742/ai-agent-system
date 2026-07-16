import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_audit_trust_receiver_acceptance_trust import (
    append_transition,
    canonical_json,
    create_state,
)
from agent_audit_trust_receiver_acceptance_trust_checkpoint import (
    AuditTrustReceiverAcceptanceTrustCheckpointError,
    _core,
    checkpoint_matches_state,
    create_checkpoint,
    create_proof,
    lineage,
    load_checkpoint,
    main,
    proof_matches_checkpoint,
    proof_matches_handoff,
    validate_checkpoint,
    validate_proof,
)
from test_audit_trust_receiver_acceptance_trust import (
    candidate,
    h,
    report,
    verified_snapshot,
    verified_transition,
)


def third_transition(previous):
    item = candidate(300, 3, 3, 3, 3, 3)
    return {
        "valid": True,
        "bundle_id": h(290),
        "bundle_type": "transition",
        "candidate": item,
        "previous": copy.deepcopy(previous),
        "consistency": {"relation": "right-descendant", "consistency_id": h(399)},
        "files": 7,
        "bytes": 3000,
        "proof_count": 1,
    }


def history():
    snapshot = verified_snapshot()
    transition2 = verified_transition(snapshot["candidate"])
    transition3 = third_transition(transition2["candidate"])
    state1 = create_state(report(snapshot), snapshot)
    state2 = append_transition(state1, report(transition2), transition2)
    state3 = append_transition(state2, report(transition3), transition3)
    return (state1, state2, state3), (snapshot, transition2, transition3)


class AcceptanceTrustCheckpointTests(unittest.TestCase):
    def test_checkpoint_is_canonical_and_deterministic(self):
        state = history()[0][2]
        first = create_checkpoint(state)
        second = create_checkpoint(copy.deepcopy(state))
        self.assertEqual(first, second)
        self.assertEqual(3, first["entry_count"])
        self.assertEqual(state["head"], first["head"])
        self.assertEqual("sha256-rfc6962-v1", first["merkle"]["algorithm"])

    def test_checkpoint_rejects_rehashed_payload_tamper(self):
        checkpoint = create_checkpoint(history()[0][1])
        checkpoint["entry_count"] += 1
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError):
            validate_checkpoint(checkpoint)

    def test_checkpoint_must_match_exact_state(self):
        states = history()[0]
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as raised:
            checkpoint_matches_state(create_checkpoint(states[0]), states[1])
        self.assertEqual("ABP004", raised.exception.rule_id)

    def test_single_leaf_anchor_proof(self):
        state = history()[0][0]
        proof = create_proof(state, create_checkpoint(state), sequence=1)
        self.assertEqual([], proof["audit_path"])
        self.assertEqual(1, validate_proof(proof)["entry"]["sequence"])

    def test_first_entry_proof_in_odd_tree(self):
        state = history()[0][2]
        proof = create_proof(state, create_checkpoint(state), sequence=1)
        self.assertEqual(1, validate_proof(proof)["entry"]["sequence"])

    def test_middle_entry_proof_in_odd_tree(self):
        state = history()[0][2]
        proof = create_proof(state, create_checkpoint(state), sequence=2)
        self.assertEqual(2, validate_proof(proof)["entry"]["sequence"])

    def test_head_entry_proof_in_odd_tree(self):
        state = history()[0][2]
        proof = create_proof(state, create_checkpoint(state), sequence=3)
        self.assertEqual(
            state["head"]["handoff_bundle_id"],
            proof["entry"]["evidence"]["handoff_bundle_id"],
        )

    def test_proof_selects_by_acceptance_bundle_id(self):
        state = history()[0][2]
        wanted = state["entries"][1]["evidence"]["handoff_bundle_id"]
        proof = create_proof(state, create_checkpoint(state), handoff_bundle_id=wanted)
        self.assertEqual(2, proof["entry"]["sequence"])

    def test_proof_requires_exactly_one_selector(self):
        state = history()[0][0]
        checkpoint = create_checkpoint(state)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as none:
            create_proof(state, checkpoint)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as both:
            create_proof(
                state,
                checkpoint,
                sequence=1,
                handoff_bundle_id=state["head"]["handoff_bundle_id"],
            )
        self.assertEqual("ABP005", none.exception.rule_id)
        self.assertEqual("ABP005", both.exception.rule_id)

    def test_missing_bundle_selector_is_rejected(self):
        state = history()[0][0]
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as raised:
            create_proof(state, create_checkpoint(state), handoff_bundle_id="f" * 64)
        self.assertEqual("ABP005", raised.exception.rule_id)

    def test_rehashed_audit_path_tamper_is_rejected(self):
        state = history()[0][2]
        proof = create_proof(state, create_checkpoint(state), sequence=2)
        proof["audit_path"][0] = "f" * 64
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as raised:
            validate_proof(proof)
        self.assertEqual("ABP006", raised.exception.rule_id)

    def test_extra_audit_path_hash_is_rejected(self):
        state = history()[0][0]
        proof = create_proof(state, create_checkpoint(state), sequence=1)
        proof["audit_path"].append("f" * 64)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as raised:
            validate_proof(proof)
        self.assertEqual("ABP006", raised.exception.rule_id)

    def test_checkpoint_substitution_is_rejected(self):
        states = history()[0]
        first = create_checkpoint(states[0])
        proof = create_proof(states[0], first, sequence=1)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as raised:
            proof_matches_checkpoint(proof, create_checkpoint(states[1]))
        self.assertEqual("ABP007", raised.exception.rule_id)

    def test_snapshot_acceptance_bundle_binding(self):
        states, verified = history()
        proof = create_proof(states[0], create_checkpoint(states[0]), sequence=1)
        with mock.patch.object(_core, "verify_bundle", return_value=verified[0]):
            actual = proof_matches_handoff(proof, Path("snapshot-bundle"))
        self.assertEqual("snapshot", actual["bundle_type"])

    def test_transition_acceptance_bundle_binding(self):
        states, verified = history()
        proof = create_proof(states[1], create_checkpoint(states[1]), sequence=2)
        with mock.patch.object(_core, "verify_bundle", return_value=verified[1]):
            actual = proof_matches_handoff(proof, Path("transition-bundle"))
        self.assertEqual("transition", actual["bundle_type"])

    def test_acceptance_bundle_substitution_is_rejected(self):
        states, verified = history()
        proof = create_proof(states[0], create_checkpoint(states[0]), sequence=1)
        with mock.patch.object(_core, "verify_bundle", return_value=verified[1]):
            with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as raised:
                proof_matches_handoff(proof, Path("wrong-bundle"))
        self.assertEqual("ABP008", raised.exception.rule_id)

    def test_checkpoint_loader_requires_strict_canonical_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint = create_checkpoint(history()[0][0])
            compact = root / "compact.json"
            compact.write_text(json.dumps(checkpoint), encoding="utf-8")
            with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError):
                load_checkpoint(compact)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"checkpoint_version":1,"checkpoint_version":1}',
                encoding="utf-8",
            )
            with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError):
                load_checkpoint(duplicate)

    def test_immutable_output_is_mode_0600_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "checkpoint.json"
            checkpoint = create_checkpoint(history()[0][0])
            _core._write_new(output, checkpoint, "acceptance trust checkpoint")
            self.assertEqual(0o600, os.stat(output).st_mode & 0o777)
            before = output.read_bytes()
            with self.assertRaises(AuditTrustReceiverAcceptanceTrustCheckpointError) as raised:
                _core._write_new(output, checkpoint, "acceptance trust checkpoint")
            self.assertEqual(before, output.read_bytes())
        self.assertEqual("ABP009", raised.exception.rule_id)

    def test_lineage_same_descendant_rollback_and_fork(self):
        states, verified = history()
        self.assertEqual("same", lineage(states[0], states[0])["relation"])
        self.assertEqual("right-descendant", lineage(states[0], states[2])["relation"])
        rollback = lineage(states[2], states[0])
        self.assertEqual("ABP010", rollback["violations"][0]["rule_id"])
        fork_verified = third_transition(verified[0]["candidate"])
        fork_verified["bundle_id"] = h(991)
        fork_verified["candidate"] = candidate(900, 2, 2, 2, 9, 2)
        fork = append_transition(states[0], report(fork_verified), fork_verified)
        result = lineage(states[1], fork)
        self.assertEqual("ABP011", result["violations"][0]["rule_id"])

    def test_cli_create_prove_verify_and_lineage(self):
        states = history()[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = root / "left.json"
            right = root / "right.json"
            checkpoint_path = root / "checkpoint.json"
            proof_path = root / "proof.json"
            left.write_bytes(canonical_json(states[0]))
            right.write_bytes(canonical_json(states[1]))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    main([
                        "create", str(right), str(checkpoint_path),
                        "--expected-state-id", states[1]["state_id"],
                    ]),
                )
            checkpoint = load_checkpoint(checkpoint_path)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    main([
                        "prove", str(right), str(checkpoint_path), str(proof_path),
                        "--expected-state-id", states[1]["state_id"],
                        "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                        "--handoff-bundle-id", states[1]["head"]["handoff_bundle_id"],
                    ]),
                )
                self.assertEqual(
                    0,
                    main([
                        "verify-proof", str(proof_path), str(checkpoint_path),
                        "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                    ]),
                )
                self.assertEqual(
                    0,
                    main([
                        "lineage", str(left), str(right),
                        "--expected-left-state-id", states[0]["state_id"],
                        "--expected-right-state-id", states[1]["state_id"],
                    ]),
                )


if __name__ == "__main__":
    unittest.main()
