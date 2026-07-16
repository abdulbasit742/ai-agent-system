import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_audit_trust import _atomic_write, append_transition, create_state
from agent_audit_trust_checkpoint import create_checkpoint
from agent_audit_trust_consistency import (
    AuditTrustConsistencyDenied,
    AuditTrustConsistencyError,
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


def snapshot(seed=1):
    return {
        "valid": True,
        "bundle_id": h(1000 + seed),
        "bundle_type": "snapshot",
        "candidate": {
            "checkpoint_id": h(2000 + seed),
            "catalog_id": h(3000 + seed),
            "generation": 1,
            "segment_count": 1,
            "merkle_root": h(4000 + seed),
        },
        "previous": None,
        "consistency": None,
        "proof_count": 1,
        "segment_count": 0,
        "proof_ids": [h(5000 + seed)],
        "segment_ids": [h(6000 + seed)],
        "files": 4,
        "bytes": 1000,
    }


def report(verified, decision):
    candidate = verified["candidate"]
    previous = verified.get("previous")
    return {
        "admitted": True,
        "policy_sha256": h(7000 + decision),
        "decision_id": h(8000 + decision),
        "identity": {
            "bundle_id": verified["bundle_id"],
            "bundle_type": verified["bundle_type"],
            "candidate_checkpoint_id": candidate["checkpoint_id"],
            "candidate_catalog_id": candidate["catalog_id"],
            "previous_checkpoint_id": previous["checkpoint_id"] if previous else None,
            "previous_catalog_id": previous["catalog_id"] if previous else None,
        },
        "evidence": {
            "files": verified["files"],
            "bytes": verified["bytes"],
            "proof_count": verified["proof_count"],
            "sealed_segment_count": verified["segment_count"],
            "selected_segment_indexes": [candidate["segment_count"]],
            "selected_segment_ids": [h(6000 + decision)],
            "sealed_segment_indexes": [],
            "candidate_generation": candidate["generation"],
            "candidate_segment_count": candidate["segment_count"],
            "generation_delta": candidate["generation"] - previous["generation"] if previous else None,
        },
        "violations": [],
    }


def anchor(seed=1):
    verified = snapshot(seed)
    return create_state(report(verified, seed), verified)


def advance(state, seed=2):
    head = state["head"]
    verified = {
        "valid": True,
        "bundle_id": h(1000 + seed),
        "bundle_type": "transition",
        "candidate": {
            "checkpoint_id": h(2000 + seed),
            "catalog_id": h(3000 + seed),
            "generation": head["generation"] + 1,
            "segment_count": head["segment_count"] + 1,
            "merkle_root": h(4000 + seed),
        },
        "previous": {
            "checkpoint_id": head["checkpoint_id"],
            "catalog_id": head["catalog_id"],
            "generation": head["generation"],
            "segment_count": head["segment_count"],
            "merkle_root": state["entries"][-1]["evidence"]["merkle_root"],
        },
        "consistency": {
            "consistency_id": h(9000 + seed),
            "relation": "right-descendant",
            "direct_predecessor_verified": True,
        },
        "proof_count": 1,
        "segment_count": 0,
        "proof_ids": [h(5000 + seed)],
        "segment_ids": [h(6000 + seed)],
        "files": 7,
        "bytes": 2000,
    }
    return append_transition(state, report(verified, seed), verified)


def make_proof(previous, candidate):
    return create_consistency_proof(
        previous,
        create_checkpoint(previous),
        candidate,
        create_checkpoint(candidate),
    )


def reseal(proof):
    core = {key: proof[key] for key in (
        "consistency_version", "algorithm", "relation", "previous", "candidate",
        "previous_frontier", "append_frontier", "boundary_entry",
    )}
    proof["consistency_id"] = _identifier(b"audit-trust-consistency-proof-v1", core)


def write_inputs(root, previous, candidate):
    previous_cp = create_checkpoint(previous)
    candidate_cp = create_checkpoint(candidate)
    _atomic_write(root / "previous-state.json", previous, require_absent=True)
    _atomic_write(root / "candidate-state.json", candidate, require_absent=True)
    for name, checkpoint in (("previous", previous_cp), ("candidate", candidate_cp)):
        (root / f"{name}-checkpoint.json").write_text(
            json.dumps(checkpoint, sort_keys=True, indent=2) + "\n"
        )
    return previous_cp, candidate_cp


class AuditTrustConsistencyTests(unittest.TestCase):
    def test_range_layout(self):
        self.assertEqual([(0, 4), (4, 2), (6, 1)], range_layout(0, 7))
        self.assertEqual([(3, 1), (4, 4), (8, 2)], range_layout(3, 10))

    def test_append_layout(self):
        self.assertEqual([], append_layout(4, 4))
        self.assertEqual([(4, 1), (5, 1), (6, 2)], append_layout(4, 8))

    def test_same_state(self):
        state = anchor()
        proof = make_proof(state, state)
        self.assertEqual("same", proof["relation"])
        self.assertIsNone(proof["boundary_entry"])
        self.assertEqual(proof, validate_consistency_proof(copy.deepcopy(proof)))

    def test_descendant_boundary(self):
        previous = anchor()
        proof = make_proof(previous, advance(previous))
        self.assertEqual("right-descendant", proof["relation"])
        self.assertEqual(2, proof["boundary_entry"]["sequence"])
        self.assertEqual(1, proof["append_frontier"][0]["size"])
        self.assertEqual(proof, validate_consistency_proof(copy.deepcopy(proof)))

    def test_compact_multi_append(self):
        previous = anchor()
        candidate = previous
        for seed in range(2, 18):
            candidate = advance(candidate, seed)
        proof = make_proof(previous, candidate)
        self.assertLess(
            len(proof["previous_frontier"]) + len(proof["append_frontier"]),
            len(candidate["entries"]),
        )
        validate_consistency_proof(proof)

    def test_previous_checkpoint_mismatch(self):
        previous = anchor()
        candidate = advance(previous)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "previous checkpoint"):
            create_consistency_proof(
                previous, create_checkpoint(anchor(9)), candidate, create_checkpoint(candidate)
            )

    def test_candidate_checkpoint_mismatch(self):
        previous = anchor()
        candidate = advance(previous)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "candidate checkpoint"):
            create_consistency_proof(
                previous, create_checkpoint(previous), candidate, create_checkpoint(anchor(9))
            )

    def test_rollback_denied(self):
        old = anchor()
        new = advance(old)
        with self.assertRaises(AuditTrustConsistencyDenied) as raised:
            make_proof(new, old)
        self.assertEqual("ATK009", raised.exception.rule_id)

    def test_fork_denied(self):
        base = anchor()
        with self.assertRaises(AuditTrustConsistencyDenied) as raised:
            make_proof(advance(base, 2), advance(base, 3))
        self.assertEqual("ATK010", raised.exception.rule_id)

    def test_previous_frontier_tamper(self):
        previous = anchor()
        proof = make_proof(previous, advance(previous))
        proof["previous_frontier"][0]["hash"] = "f" * 64
        reseal(proof)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "previous Merkle root"):
            validate_consistency_proof(proof)

    def test_append_frontier_tamper(self):
        previous = anchor()
        proof = make_proof(previous, advance(previous))
        proof["append_frontier"][0]["hash"] = "e" * 64
        reseal(proof)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "candidate Merkle root"):
            validate_consistency_proof(proof)

    def test_noncanonical_layout(self):
        previous = anchor()
        candidate = previous
        for seed in range(2, 6):
            candidate = advance(candidate, seed)
        proof = make_proof(previous, candidate)
        proof["append_frontier"][1]["size"] = 4
        reseal(proof)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "layout"):
            validate_consistency_proof(proof)

    def test_boundary_tamper(self):
        previous = anchor()
        proof = make_proof(previous, advance(previous))
        proof["boundary_entry"]["previous_entry_hash"] = "f" * 64
        reseal(proof)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "boundary trust entry"):
            validate_consistency_proof(proof)

    def test_checkpoint_substitution(self):
        previous = anchor()
        candidate = advance(previous)
        previous_cp = create_checkpoint(previous)
        candidate_cp = create_checkpoint(candidate)
        proof = create_consistency_proof(previous, previous_cp, candidate, candidate_cp)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "references"):
            proof_matches_checkpoints(proof, previous_cp, create_checkpoint(advance(candidate, 3)))

    def test_output_safety(self):
        state = anchor()
        proof = make_proof(state, state)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "proof.json"
            _write_new(output, proof)
            with self.assertRaisesRegex(AuditTrustConsistencyError, "already exist"):
                _write_new(output, proof)
            target = root / "target.json"
            target.write_text("safe")
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(AuditTrustConsistencyError, "symlink"):
                _write_new(link, proof)

    def test_strict_loading(self):
        state = anchor()
        proof = make_proof(state, state)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"consistency_version":1,"consistency_version":1}')
            with self.assertRaisesRegex(AuditTrustConsistencyError, "strict JSON"):
                load_consistency_proof(duplicate)
            compact = root / "compact.json"
            compact.write_text(json.dumps(proof, sort_keys=True))
            with self.assertRaisesRegex(AuditTrustConsistencyError, "canonically"):
                load_consistency_proof(compact)

    def test_cli_proof_only_lifecycle(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous_cp, candidate_cp = write_inputs(root, previous, candidate)
            output = root / "consistency.json"
            prove = [
                "prove", str(root / "previous-state.json"), str(root / "previous-checkpoint.json"),
                str(root / "candidate-state.json"), str(root / "candidate-checkpoint.json"), str(output),
                "--expected-previous-state-id", previous["state_id"],
                "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                "--expected-candidate-state-id", candidate["state_id"],
                "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(prove))
            (root / "previous-state.json").unlink()
            (root / "candidate-state.json").unlink()
            verify = [
                "verify", str(output), str(root / "previous-checkpoint.json"),
                str(root / "candidate-checkpoint.json"),
                "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(verify))

    def test_cli_rollback_no_output(self):
        old = anchor()
        new = advance(old)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous_cp, candidate_cp = write_inputs(root, new, old)
            output = root / "denied.json"
            args = [
                "prove", str(root / "previous-state.json"), str(root / "previous-checkpoint.json"),
                str(root / "candidate-state.json"), str(root / "candidate-checkpoint.json"), str(output),
                "--expected-previous-state-id", new["state_id"],
                "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                "--expected-candidate-state-id", old["state_id"],
                "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
            ]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(args))
            self.assertFalse(output.exists())

    def test_cli_stale_pin(self):
        previous = anchor()
        candidate = advance(previous)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, candidate_cp = write_inputs(root, previous, candidate)
            _write_new(root / "proof.json", make_proof(previous, candidate))
            args = [
                "verify", str(root / "proof.json"), str(root / "previous-checkpoint.json"),
                str(root / "candidate-checkpoint.json"),
                "--expected-previous-checkpoint-id", "f" * 64,
                "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
            ]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(args))

    def test_consistency_id_tamper(self):
        state = anchor()
        proof = make_proof(state, state)
        proof["consistency_id"] = "f" * 64
        with self.assertRaisesRegex(AuditTrustConsistencyError, "consistency ID"):
            validate_consistency_proof(proof)


if __name__ == "__main__":
    unittest.main()
