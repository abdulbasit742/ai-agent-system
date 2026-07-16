import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

import agent_audit_trust_consistency as original_consistency
from agent_audit_trust_receiver import (
    _entry_payload,
    _identifier as receiver_identifier,
    append_transition,
    canonical_json,
    create_state,
)
from agent_audit_trust_receiver_checkpoint import create_checkpoint
from agent_audit_trust_receiver_consistency import (
    AuditTrustReceiverConsistencyDenied,
    AuditTrustReceiverConsistencyError,
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


def h(value):
    return f"{value:064x}"


def verified_snapshot(seed=1):
    return {
        "valid": True,
        "bundle_id": h(1000 + seed),
        "bundle_type": "snapshot",
        "candidate": {
            "checkpoint_id": h(2000 + seed),
            "state_id": h(3000 + seed),
            "entry_count": seed,
            "merkle_root": h(4000 + seed),
            "head": {
                "entry_hash": h(5000 + seed),
                "bundle_id": h(6000 + seed),
                "checkpoint_id": h(7000 + seed),
                "catalog_id": h(8000 + seed),
                "generation": seed,
                "segment_count": seed,
            },
        },
        "previous": None,
        "consistency": None,
        "proof_count": 1,
        "files": 4,
        "bytes": 1000,
        "head_bundle_id": h(6000 + seed),
    }


def verified_transition(state, seed):
    head = state["head"]
    entry_delta = 2
    generation_delta = 1
    return {
        "valid": True,
        "bundle_id": h(1000 + seed),
        "bundle_type": "transition",
        "candidate": {
            "checkpoint_id": h(2000 + seed),
            "state_id": h(3000 + seed),
            "entry_count": head["entry_count"] + entry_delta,
            "merkle_root": h(4000 + seed),
            "head": {
                "entry_hash": h(5000 + seed),
                "bundle_id": h(6000 + seed),
                "checkpoint_id": h(7000 + seed),
                "catalog_id": h(8000 + seed),
                "generation": head["generation"] + generation_delta,
                "segment_count": head["segment_count"] + 1,
            },
        },
        "previous": {
            "checkpoint_id": head["checkpoint_id"],
            "state_id": head["state_id"],
            "entry_count": head["entry_count"],
        },
        "consistency": {
            "consistency_id": h(9000 + seed),
            "relation": "right-descendant",
            "direct_predecessor_verified": True,
        },
        "proof_count": 1,
        "files": 7,
        "bytes": 2000,
        "head_bundle_id": h(6000 + seed),
    }


def report(verified, seed):
    candidate = verified["candidate"]
    previous = verified.get("previous")
    head = candidate["head"]
    return {
        "admitted": True,
        "policy_sha256": h(10000 + seed),
        "decision_id": h(11000 + seed),
        "identity": {
            "bundle_id": verified["bundle_id"],
            "bundle_type": verified["bundle_type"],
            "candidate_checkpoint_id": candidate["checkpoint_id"],
            "candidate_state_id": candidate["state_id"],
            "previous_checkpoint_id": previous["checkpoint_id"] if previous else None,
            "previous_state_id": previous["state_id"] if previous else None,
        },
        "evidence": {
            "candidate_entry_count": candidate["entry_count"],
            "candidate_generation": head["generation"],
            "candidate_segment_count": head["segment_count"],
            "head_bundle_id": verified["head_bundle_id"],
            "entry_delta": (
                candidate["entry_count"] - previous["entry_count"] if previous else None
            ),
            "generation_delta": (
                head["generation"] - (head["generation"] - 1) if previous else None
            ),
        },
        "violations": [],
    }


def receiver_state(entries=1, branch_seed=1):
    snapshot = verified_snapshot(branch_seed)
    state = create_state(report(snapshot, branch_seed), snapshot)
    for sequence in range(2, entries + 1):
        seed = branch_seed * 100 + sequence
        verified = verified_transition(state, seed)
        state = append_transition(state, report(verified, seed), verified)
    return state


def reseal(proof):
    core = {
        key: proof[key]
        for key in (
            "consistency_version",
            "algorithm",
            "relation",
            "previous",
            "candidate",
            "previous_frontier",
            "append_frontier",
            "boundary_entry",
        )
    }
    proof["consistency_id"] = _identifier(PROOF_DOMAIN, core)


class ReceiverConsistencyTests(unittest.TestCase):
    def proof(self, previous_entries=1, candidate_entries=2):
        previous = receiver_state(previous_entries)
        candidate = receiver_state(candidate_entries)
        previous_checkpoint = create_checkpoint(previous)
        candidate_checkpoint = create_checkpoint(candidate)
        proof = create_consistency_proof(
            previous, previous_checkpoint, candidate, candidate_checkpoint
        )
        return previous, candidate, previous_checkpoint, candidate_checkpoint, proof

    def assert_rule(self, expected, function):
        with self.assertRaises(AuditTrustReceiverConsistencyError) as raised:
            function()
        self.assertEqual(expected, raised.exception.rule_id)

    def test_01_same_state_round_trip(self):
        state = receiver_state(3)
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
        _, _, _, _, proof = self.proof(13, 63)
        count = len(proof["previous_frontier"]) + len(proof["append_frontier"])
        self.assertLessEqual(count, 14)
        self.assertEqual(range_layout(0, 13), [(0, 8), (8, 4), (12, 1)])
        self.assertEqual(append_layout(13, 17)[0], (13, 1))

    def test_05_previous_root_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof = copy.deepcopy(proof)
        proof["previous_frontier"][0]["hash"] = h(99991)
        reseal(proof)
        self.assert_rule("ARR006", lambda: validate_consistency_proof(proof))

    def test_06_candidate_root_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof = copy.deepcopy(proof)
        proof["append_frontier"][0]["hash"] = h(99992)
        reseal(proof)
        self.assert_rule("ARR006", lambda: validate_consistency_proof(proof))

    def test_07_noncanonical_frontier_layout_is_rejected(self):
        *_, proof = self.proof(3, 6)
        proof = copy.deepcopy(proof)
        proof["previous_frontier"].reverse()
        reseal(proof)
        self.assert_rule("ARR005", lambda: validate_consistency_proof(proof))

    def test_08_boundary_previous_hash_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof = copy.deepcopy(proof)
        proof["boundary_entry"]["previous_entry_hash"] = h(99993)
        reseal(proof)
        self.assert_rule("ARR011", lambda: validate_consistency_proof(proof))

    def test_09_boundary_checkpoint_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof = copy.deepcopy(proof)
        proof["boundary_entry"]["transition"]["previous_checkpoint_id"] = h(99994)
        reseal(proof)
        self.assert_rule("ARR011", lambda: validate_consistency_proof(proof))

    def test_10_boundary_state_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof = copy.deepcopy(proof)
        proof["boundary_entry"]["transition"]["previous_state_id"] = h(99995)
        reseal(proof)
        self.assert_rule("ARR011", lambda: validate_consistency_proof(proof))

    def test_11_boundary_entry_delta_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof = copy.deepcopy(proof)
        proof["boundary_entry"]["transition"]["entry_delta"] += 1
        reseal(proof)
        self.assert_rule("ARR011", lambda: validate_consistency_proof(proof))

    def test_12_boundary_generation_delta_tamper_is_rejected(self):
        *_, proof = self.proof()
        proof = copy.deepcopy(proof)
        proof["boundary_entry"]["transition"]["generation_delta"] += 1
        reseal(proof)
        self.assert_rule("ARR011", lambda: validate_consistency_proof(proof))

    def test_13_checkpoint_substitution_is_rejected(self):
        _, _, previous_cp, _, proof = self.proof()
        other = create_checkpoint(receiver_state(3))
        self.assert_rule(
            "ARR004", lambda: proof_matches_checkpoints(proof, previous_cp, other)
        )

    def test_14_rollback_is_denied(self):
        older = receiver_state(1)
        newer = receiver_state(3)
        with self.assertRaises(AuditTrustReceiverConsistencyDenied) as raised:
            create_consistency_proof(
                newer, create_checkpoint(newer), older, create_checkpoint(older)
            )
        self.assertEqual("ARR009", raised.exception.rule_id)
        self.assertEqual("rollback", raised.exception.report["relation"])

    def test_15_fork_is_denied(self):
        left = receiver_state(2, branch_seed=1)
        right = receiver_state(2, branch_seed=2)
        with self.assertRaises(AuditTrustReceiverConsistencyDenied) as raised:
            create_consistency_proof(
                left, create_checkpoint(left), right, create_checkpoint(right)
            )
        self.assertEqual("ARR010", raised.exception.rule_id)
        self.assertEqual("fork", raised.exception.report["relation"])

    def test_16_output_is_immutable(self):
        *_, proof = self.proof()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            _write_new(path, proof)
            before = path.read_bytes()
            self.assert_rule("ARR008", lambda: _write_new(path, proof))
            self.assertEqual(before, path.read_bytes())

    def test_17_strict_json_loader_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            path.write_text('{"a":1,"a":2}\n')
            self.assert_rule("ARR002", lambda: load_consistency_proof(path))

    def test_18_cli_stale_state_pin_is_denied(self):
        previous, candidate, previous_cp, candidate_cp, _ = self.proof()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, payload in (
                ("previous-state.json", previous),
                ("candidate-state.json", candidate),
                ("previous-checkpoint.json", previous_cp),
                ("candidate-checkpoint.json", candidate_cp),
            ):
                (root / name).write_bytes(canonical_json(payload))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main([
                    "prove",
                    str(root / "previous-state.json"),
                    str(root / "previous-checkpoint.json"),
                    str(root / "candidate-state.json"),
                    str(root / "candidate-checkpoint.json"),
                    str(root / "proof.json"),
                    "--expected-previous-state-id", h(99996),
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--expected-candidate-state-id", candidate["state_id"],
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                ])
            self.assertEqual(1, status)
            self.assertFalse((root / "proof.json").exists())
            self.assertIn("ARR003", error.getvalue())

    def test_19_cli_proof_only_verification(self):
        previous, candidate, previous_cp, candidate_cp, _ = self.proof()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, payload in (
                ("previous-state.json", previous),
                ("candidate-state.json", candidate),
                ("previous-checkpoint.json", previous_cp),
                ("candidate-checkpoint.json", candidate_cp),
            ):
                (root / name).write_bytes(canonical_json(payload))
            with contextlib.redirect_stdout(io.StringIO()):
                status = main([
                    "prove",
                    str(root / "previous-state.json"),
                    str(root / "previous-checkpoint.json"),
                    str(root / "candidate-state.json"),
                    str(root / "candidate-checkpoint.json"),
                    str(root / "proof.json"),
                    "--expected-previous-state-id", previous["state_id"],
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--expected-candidate-state-id", candidate["state_id"],
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                ])
            self.assertEqual(0, status)
            (root / "previous-state.json").unlink()
            (root / "candidate-state.json").unlink()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "verify",
                    str(root / "proof.json"),
                    str(root / "previous-checkpoint.json"),
                    str(root / "candidate-checkpoint.json"),
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                ])
            self.assertEqual(0, status)
            self.assertTrue(json.loads(output.getvalue())["valid"])

    def test_20_original_consistency_namespace_is_not_mutated(self):
        self.assertEqual(
            "ATK002", original_consistency.AuditTrustConsistencyError("x").rule_id
        )
        payload = {"x": 1}
        self.assertNotEqual(
            original_consistency._identifier(b"audit-trust-consistency-proof-v1", payload),
            _identifier(PROOF_DOMAIN, payload),
        )


if __name__ == "__main__":
    unittest.main()
