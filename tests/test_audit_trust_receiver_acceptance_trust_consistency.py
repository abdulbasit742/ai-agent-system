import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

import agent_audit_trust_receiver_acceptance_consistency as original_consistency
from agent_audit_trust_receiver_acceptance_trust import (
    append_transition,
    canonical_json,
    create_state,
)
from agent_audit_trust_receiver_acceptance_trust_checkpoint import create_checkpoint
from agent_audit_trust_receiver_acceptance_trust_consistency import (
    AuditTrustReceiverAcceptanceTrustConsistencyDenied,
    AuditTrustReceiverAcceptanceTrustConsistencyError,
    PROOF_DOMAIN,
    _identifier,
    _write_new,
    append_layout,
    create_consistency_proof,
    load_consistency_proof,
    main,
    proof_matches_checkpoints,
    range_layout,
    validate_consistency_proof,
)
from test_audit_trust_receiver_acceptance_trust import candidate, h, report


def snapshot(branch_seed=1):
    item = candidate(branch_seed * 10000 + 100, 1, 1, 1, 1, 1)
    return {
        "valid": True,
        "bundle_id": h(branch_seed * 10000 + 90),
        "bundle_type": "snapshot",
        "candidate": item,
        "previous": None,
        "consistency": None,
        "files": 4,
        "bytes": 1000,
        "proof_count": 1,
    }


def transition(previous, sequence, branch_seed=1):
    base = branch_seed * 10000 + sequence * 100
    item = candidate(base, sequence, sequence, sequence, sequence, sequence)
    return {
        "valid": True,
        "bundle_id": h(base - 10),
        "bundle_type": "transition",
        "candidate": item,
        "previous": copy.deepcopy(previous),
        "consistency": {"relation": "right-descendant", "consistency_id": h(base + 99)},
        "files": 7,
        "bytes": sequence * 1000,
        "proof_count": 1,
    }


def acceptance_trust_state(entries=1, branch_seed=1):
    verified = snapshot(branch_seed)
    state = create_state(report(verified), verified)
    previous = verified["candidate"]
    for sequence in range(2, entries + 1):
        verified = transition(previous, sequence, branch_seed)
        state = append_transition(state, report(verified), verified)
        previous = verified["candidate"]
    return state


def reseal(proof):
    core = {
        key: proof[key]
        for key in (
            "consistency_version", "algorithm", "relation", "previous", "candidate",
            "previous_frontier", "append_frontier", "boundary_entry",
        )
    }
    proof["consistency_id"] = _identifier(PROOF_DOMAIN, core)


class AcceptanceTrustConsistencyTests(unittest.TestCase):
    def proof(self, previous_entries=1, candidate_entries=2):
        previous = acceptance_trust_state(previous_entries)
        candidate_state = acceptance_trust_state(candidate_entries)
        previous_cp = create_checkpoint(previous)
        candidate_cp = create_checkpoint(candidate_state)
        proof = create_consistency_proof(previous, previous_cp, candidate_state, candidate_cp)
        return previous, candidate_state, previous_cp, candidate_cp, proof

    def assert_rule(self, expected, function):
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustConsistencyError) as raised:
            function()
        self.assertEqual(expected, raised.exception.rule_id)

    def test_01_same_state_round_trip(self):
        state = acceptance_trust_state(3)
        checkpoint = create_checkpoint(state)
        proof = create_consistency_proof(state, checkpoint, state, checkpoint)
        normalized = validate_consistency_proof(proof)
        self.assertEqual("same", normalized["relation"])
        self.assertEqual([], normalized["append_frontier"])
        self.assertIsNone(normalized["boundary_entry"])

    def test_02_direct_descendant_round_trip(self):
        _, _, previous_cp, candidate_cp, proof = self.proof()
        normalized = proof_matches_checkpoints(proof, previous_cp, candidate_cp)
        self.assertEqual("right-descendant", normalized["relation"])
        self.assertEqual(2, normalized["boundary_entry"]["sequence"])

    def test_03_multi_entry_descendant_round_trip(self):
        _, _, previous_cp, candidate_cp, proof = self.proof(2, 7)
        normalized = proof_matches_checkpoints(proof, previous_cp, candidate_cp)
        self.assertEqual(3, normalized["boundary_entry"]["sequence"])
        self.assertEqual(7, normalized["candidate"]["entry_count"])

    def test_04_frontier_layout_is_compact(self):
        *_, proof = self.proof(13, 63)
        self.assertLessEqual(len(proof["previous_frontier"]) + len(proof["append_frontier"]), 14)
        self.assertEqual([(0, 8), (8, 4), (12, 1)], range_layout(0, 13))
        self.assertEqual((13, 1), append_layout(13, 17)[0])

    def test_05_previous_root_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof["previous_frontier"][0]["hash"] = h(99991)
        reseal(proof)
        self.assert_rule("ABR006", lambda: validate_consistency_proof(proof))

    def test_06_candidate_root_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof["append_frontier"][0]["hash"] = h(99992)
        reseal(proof)
        self.assert_rule("ABR006", lambda: validate_consistency_proof(proof))

    def test_07_noncanonical_frontier_layout_is_rejected(self):
        *_, proof = self.proof(3, 6)
        proof["previous_frontier"].reverse()
        reseal(proof)
        self.assert_rule("ABR005", lambda: validate_consistency_proof(proof))

    def test_08_boundary_previous_hash_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof["boundary_entry"]["previous_entry_hash"] = h(99993)
        reseal(proof)
        self.assert_rule("ABR011", lambda: validate_consistency_proof(proof))

    def test_09_boundary_checkpoint_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof["boundary_entry"]["transition"]["previous_checkpoint_id"] = h(99994)
        reseal(proof)
        self.assert_rule("ABR011", lambda: validate_consistency_proof(proof))

    def test_10_boundary_state_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof["boundary_entry"]["transition"]["previous_state_id"] = h(99995)
        reseal(proof)
        self.assert_rule("ABR011", lambda: validate_consistency_proof(proof))

    def test_11_acceptance_delta_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof["boundary_entry"]["transition"]["acceptance_entry_delta"] += 1
        reseal(proof)
        self.assert_rule("ABR011", lambda: validate_consistency_proof(proof))

    def test_12_receiver_delta_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof["boundary_entry"]["transition"]["receiver_entry_delta"] += 1
        reseal(proof)
        self.assert_rule("ABR011", lambda: validate_consistency_proof(proof))

    def test_13_trust_delta_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof["boundary_entry"]["transition"]["trust_entry_delta"] += 1
        reseal(proof)
        self.assert_rule("ABR011", lambda: validate_consistency_proof(proof))

    def test_14_generation_and_segment_delta_tamper_are_rejected(self):
        *_, proof = self.proof()
        proof["boundary_entry"]["transition"]["generation_delta"] += 1
        reseal(proof)
        self.assert_rule("ABR011", lambda: validate_consistency_proof(proof))
        *_, proof = self.proof()
        proof["boundary_entry"]["transition"]["segment_delta"] += 1
        reseal(proof)
        self.assert_rule("ABR011", lambda: validate_consistency_proof(proof))

    def test_15_checkpoint_substitution_is_rejected(self):
        _, _, previous_cp, _, proof = self.proof()
        other = create_checkpoint(acceptance_trust_state(3))
        self.assert_rule("ABR004", lambda: proof_matches_checkpoints(proof, previous_cp, other))

    def test_16_rollback_is_denied(self):
        older = acceptance_trust_state(1)
        newer = acceptance_trust_state(3)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustConsistencyDenied) as raised:
            create_consistency_proof(newer, create_checkpoint(newer), older, create_checkpoint(older))
        self.assertEqual("ABR009", raised.exception.rule_id)

    def test_17_fork_is_denied(self):
        left = acceptance_trust_state(2, 1)
        right = acceptance_trust_state(2, 2)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustConsistencyDenied) as raised:
            create_consistency_proof(left, create_checkpoint(left), right, create_checkpoint(right))
        self.assertEqual("ABR010", raised.exception.rule_id)

    def test_18_output_is_immutable_and_json_is_strict(self):
        *_, proof = self.proof()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            _write_new(path, proof)
            before = path.read_bytes()
            self.assert_rule("ABR008", lambda: _write_new(path, proof))
            self.assertEqual(before, path.read_bytes())
            malformed = Path(temporary) / "malformed.json"
            malformed.write_text('{"a":1,"a":2}\n')
            self.assert_rule("ABR002", lambda: load_consistency_proof(malformed))

    def test_19_cli_proof_only_verification_and_stale_pin(self):
        previous, candidate_state, previous_cp, candidate_cp, _ = self.proof()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, payload in (
                ("previous-state.json", previous),
                ("candidate-state.json", candidate_state),
                ("previous-checkpoint.json", previous_cp),
                ("candidate-checkpoint.json", candidate_cp),
            ):
                (root / name).write_bytes(canonical_json(payload))
            with contextlib.redirect_stderr(io.StringIO()):
                status = main([
                    "prove", str(root / "previous-state.json"), str(root / "previous-checkpoint.json"),
                    str(root / "candidate-state.json"), str(root / "candidate-checkpoint.json"),
                    str(root / "denied.json"), "--expected-previous-state-id", h(99996),
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--expected-candidate-state-id", candidate_state["state_id"],
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                ])
            self.assertEqual(1, status)
            self.assertFalse((root / "denied.json").exists())
            with contextlib.redirect_stdout(io.StringIO()):
                status = main([
                    "prove", str(root / "previous-state.json"), str(root / "previous-checkpoint.json"),
                    str(root / "candidate-state.json"), str(root / "candidate-checkpoint.json"),
                    str(root / "proof.json"), "--expected-previous-state-id", previous["state_id"],
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--expected-candidate-state-id", candidate_state["state_id"],
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                ])
            self.assertEqual(0, status)
            (root / "previous-state.json").unlink()
            (root / "candidate-state.json").unlink()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "verify", str(root / "proof.json"), str(root / "previous-checkpoint.json"),
                    str(root / "candidate-checkpoint.json"),
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                ])
            self.assertEqual(0, status)
            self.assertTrue(json.loads(output.getvalue())["valid"])

    def test_20_original_acceptance_consistency_namespace_is_not_mutated(self):
        self.assertEqual(
            "ASR002", original_consistency.AuditTrustReceiverAcceptanceConsistencyError("x").rule_id
        )
        payload = {"x": 1}
        self.assertNotEqual(
            original_consistency._identifier(original_consistency.PROOF_DOMAIN, payload),
            _identifier(PROOF_DOMAIN, payload),
        )


if __name__ == "__main__":
    unittest.main()
