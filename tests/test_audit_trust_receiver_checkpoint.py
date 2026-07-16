import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_audit_trust_receiver import append_transition, canonical_json, create_state
from agent_audit_trust_receiver_checkpoint import (
    AuditTrustReceiverCheckpointError,
    _write_new,
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
from audit_trust_receiver_cases import admitted
from test_audit_trust_consistency import advance, anchor


def history(root: Path):
    trust1 = anchor()
    trust2 = advance(trust1, 2)
    trust3 = advance(trust2, 3)
    handoff1 = admitted(root / "handoff1", trust1, name="snapshot")
    handoff2 = admitted(root / "handoff2", trust2, trust1, name="transition2")
    handoff3 = admitted(root / "handoff3", trust3, trust2, name="transition3")
    state1 = create_state(handoff1[0], handoff1[1])
    state2 = append_transition(state1, handoff2[0], handoff2[1])
    state3 = append_transition(state2, handoff3[0], handoff3[1])
    return (state1, state2, state3), (handoff1, handoff2, handoff3), (trust1, trust2, trust3)


class AuditTrustReceiverCheckpointTests(unittest.TestCase):
    def test_checkpoint_is_canonical_and_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][2]
            first = create_checkpoint(state)
            second = create_checkpoint(copy.deepcopy(state))
        self.assertEqual(first, second)
        self.assertEqual(3, first["entry_count"])
        self.assertEqual(state["head"], first["head"])
        self.assertEqual("sha256-rfc6962-v1", first["merkle"]["algorithm"])

    def test_checkpoint_rejects_rehashed_payload_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = create_checkpoint(history(Path(temporary))[0][1])
        checkpoint["entry_count"] += 1
        with self.assertRaises(AuditTrustReceiverCheckpointError):
            validate_checkpoint(checkpoint)

    def test_checkpoint_must_match_exact_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            states = history(Path(temporary))[0]
            checkpoint = create_checkpoint(states[0])
            with self.assertRaises(AuditTrustReceiverCheckpointError) as raised:
                checkpoint_matches_state(checkpoint, states[1])
        self.assertEqual("ARC004", raised.exception.rule_id)

    def test_single_leaf_anchor_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][0]
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=1)
        self.assertEqual([], proof["audit_path"])
        self.assertEqual(1, validate_proof(proof)["entry"]["sequence"])

    def test_first_entry_proof_in_odd_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][2]
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=1)
        self.assertEqual(1, validate_proof(proof)["entry"]["sequence"])

    def test_middle_entry_proof_in_odd_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][2]
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=2)
        self.assertEqual(2, validate_proof(proof)["entry"]["sequence"])

    def test_head_entry_proof_in_odd_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][2]
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=3)
        self.assertEqual(state["head"]["handoff_bundle_id"], proof["entry"]["evidence"]["handoff_bundle_id"])

    def test_proof_selects_by_handoff_bundle_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][2]
            checkpoint = create_checkpoint(state)
            wanted = state["entries"][1]["evidence"]["handoff_bundle_id"]
            proof = create_proof(state, checkpoint, handoff_bundle_id=wanted)
        self.assertEqual(2, proof["entry"]["sequence"])

    def test_proof_requires_exactly_one_selector(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][0]
            checkpoint = create_checkpoint(state)
            with self.assertRaises(AuditTrustReceiverCheckpointError) as none:
                create_proof(state, checkpoint)
            with self.assertRaises(AuditTrustReceiverCheckpointError) as both:
                create_proof(
                    state,
                    checkpoint,
                    sequence=1,
                    handoff_bundle_id=state["head"]["handoff_bundle_id"],
                )
        self.assertEqual("ARC005", none.exception.rule_id)
        self.assertEqual("ARC005", both.exception.rule_id)

    def test_missing_handoff_selector_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][0]
            checkpoint = create_checkpoint(state)
            with self.assertRaises(AuditTrustReceiverCheckpointError) as raised:
                create_proof(state, checkpoint, handoff_bundle_id="f" * 64)
        self.assertEqual("ARC005", raised.exception.rule_id)

    def test_rehashed_audit_path_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][2]
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=2)
        proof["audit_path"][0] = "f" * 64
        with self.assertRaises(AuditTrustReceiverCheckpointError) as raised:
            validate_proof(proof)
        self.assertEqual("ARC006", raised.exception.rule_id)

    def test_extra_audit_path_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = history(Path(temporary))[0][0]
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=1)
        proof["audit_path"].append("f" * 64)
        with self.assertRaises(AuditTrustReceiverCheckpointError) as raised:
            validate_proof(proof)
        self.assertEqual("ARC006", raised.exception.rule_id)

    def test_checkpoint_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            states = history(Path(temporary))[0]
            first = create_checkpoint(states[0])
            second = create_checkpoint(states[1])
            proof = create_proof(states[0], first, sequence=1)
            with self.assertRaises(AuditTrustReceiverCheckpointError) as raised:
                proof_matches_checkpoint(proof, second)
        self.assertEqual("ARC007", raised.exception.rule_id)

    def test_snapshot_handoff_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            states, handoffs, _ = history(Path(temporary))
            checkpoint = create_checkpoint(states[0])
            proof = create_proof(states[0], checkpoint, sequence=1)
            verified = proof_matches_handoff(proof, handoffs[0][4])
        self.assertEqual("snapshot", verified["bundle_type"])

    def test_transition_handoff_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            states, handoffs, _ = history(Path(temporary))
            checkpoint = create_checkpoint(states[1])
            proof = create_proof(states[1], checkpoint, sequence=2)
            verified = proof_matches_handoff(proof, handoffs[1][4])
        self.assertEqual("transition", verified["bundle_type"])

    def test_handoff_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            states, handoffs, _ = history(Path(temporary))
            checkpoint = create_checkpoint(states[0])
            proof = create_proof(states[0], checkpoint, sequence=1)
            with self.assertRaises(AuditTrustReceiverCheckpointError) as raised:
                proof_matches_handoff(proof, handoffs[1][4])
        self.assertEqual("ARC008", raised.exception.rule_id)

    def test_checkpoint_loader_requires_strict_canonical_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint = create_checkpoint(history(root / "input")[0][0])
            compact = root / "compact.json"
            compact.write_text(json.dumps(checkpoint), encoding="utf-8")
            with self.assertRaises(AuditTrustReceiverCheckpointError):
                load_checkpoint(compact)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"checkpoint_version":1,"checkpoint_version":1}', encoding="utf-8")
            with self.assertRaises(AuditTrustReceiverCheckpointError):
                load_checkpoint(duplicate)

    def test_immutable_output_is_mode_0600_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint = create_checkpoint(history(root / "input")[0][0])
            output = root / "checkpoint.json"
            _write_new(output, checkpoint, "receiver checkpoint")
            self.assertEqual(0o600, os.stat(output).st_mode & 0o777)
            before = output.read_bytes()
            with self.assertRaises(AuditTrustReceiverCheckpointError) as raised:
                _write_new(output, checkpoint, "receiver checkpoint")
            self.assertEqual(before, output.read_bytes())
        self.assertEqual("ARC009", raised.exception.rule_id)

    def test_lineage_same_descendant_rollback_and_fork(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            states, _, trusts = history(root / "main")
            self.assertEqual("same", lineage(states[0], states[0])["relation"])
            self.assertEqual("right-descendant", lineage(states[0], states[2])["relation"])
            rollback = lineage(states[2], states[0])
            self.assertFalse(rollback["accepted"])
            self.assertEqual("ARC010", rollback["violations"][0]["rule_id"])
            alternate_trust = advance(trusts[0], 9)
            alternate_handoff = admitted(root / "fork", alternate_trust, trusts[0], name="fork")
            alternate = append_transition(states[0], alternate_handoff[0], alternate_handoff[1])
            fork = lineage(states[1], alternate)
        self.assertFalse(fork["accepted"])
        self.assertEqual("ARC011", fork["violations"][0]["rule_id"])

    def test_cli_create_prove_verify_proof_and_lineage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            states, handoffs, _ = history(root / "input")
            left_path = root / "left.json"
            right_path = root / "right.json"
            left_path.write_bytes(canonical_json(states[0]))
            right_path.write_bytes(canonical_json(states[1]))
            checkpoint_path = root / "checkpoint.json"
            proof_path = root / "proof.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main([
                    "create", str(right_path), str(checkpoint_path),
                    "--expected-state-id", states[1]["state_id"],
                ]))
            checkpoint = load_checkpoint(checkpoint_path)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main([
                    "prove", str(right_path), str(checkpoint_path), str(proof_path),
                    "--expected-state-id", states[1]["state_id"],
                    "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                    "--handoff-bundle-id", states[1]["head"]["handoff_bundle_id"],
                ]))
                self.assertEqual(0, main([
                    "verify-proof", str(proof_path), str(checkpoint_path),
                    "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                    "--handoff", str(handoffs[1][4]),
                ]))
                self.assertEqual(0, main([
                    "lineage", str(left_path), str(right_path),
                    "--expected-left-state-id", states[0]["state_id"],
                    "--expected-right-state-id", states[1]["state_id"],
                ]))


if __name__ == "__main__":
    unittest.main()
