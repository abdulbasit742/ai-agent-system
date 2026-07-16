import contextlib
import copy
import io
import json
import os
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


def h(value: int) -> str:
    return f"{value:064x}"


def verified_snapshot(seed: int = 1) -> dict:
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


def admitted_report(verified: dict, *, decision: int = 1) -> dict:
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
            "generation_delta": (
                candidate["generation"] - previous["generation"] if previous else None
            ),
        },
        "violations": [],
    }


def anchor_state(seed: int = 1) -> dict:
    verified = verified_snapshot(seed)
    return create_state(admitted_report(verified, decision=seed), verified)


def advance_state(state: dict, seed: int = 2) -> dict:
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
    return append_transition(state, admitted_report(verified, decision=seed), verified)


def proof_core(proof: dict) -> dict:
    return {
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


def write_inputs(root: Path, previous: dict, candidate: dict):
    previous_checkpoint = create_checkpoint(previous)
    candidate_checkpoint = create_checkpoint(candidate)
    _atomic_write(root / "previous-state.json", previous, require_absent=True)
    _atomic_write(root / "candidate-state.json", candidate, require_absent=True)
    (root / "previous-checkpoint.json").write_bytes(
        (json.dumps(previous_checkpoint, sort_keys=True, indent=2) + "\n").encode()
    )
    (root / "candidate-checkpoint.json").write_bytes(
        (json.dumps(candidate_checkpoint, sort_keys=True, indent=2) + "\n").encode()
    )
    return previous_checkpoint, candidate_checkpoint


class AuditTrustConsistencyTests(unittest.TestCase):
    def test_range_layout_is_canonical(self):
        self.assertEqual([(0, 4), (4, 2), (6, 1)], range_layout(0, 7))
        self.assertEqual([(3, 1), (4, 4), (8, 2)], range_layout(3, 10))

    def test_append_layout_exposes_first_new_leaf(self):
        self.assertEqual([], append_layout(4, 4))
        self.assertEqual([(4, 1), (5, 1), (6, 2)], append_layout(4, 8))

    def test_same_state_proof_is_deterministic(self):
        state = anchor_state()
        checkpoint = create_checkpoint(state)
        proof = create_consistency_proof(state, checkpoint, state, checkpoint)
        self.assertEqual("same", proof["relation"])
        self.assertIsNone(proof["boundary_entry"])
        self.assertEqual([], proof["append_frontier"])
        self.assertEqual(proof, validate_consistency_proof(copy.deepcopy(proof)))

    def test_descendant_proof_authenticates_transition_boundary(self):
        previous = anchor_state()
        candidate = advance_state(previous, 2)
        proof = create_consistency_proof(
            previous,
            create_checkpoint(previous),
            candidate,
            create_checkpoint(candidate),
        )
        self.assertEqual("right-descendant", proof["relation"])
        self.assertEqual(2, proof["boundary_entry"]["sequence"])
        self.assertEqual(1, proof["append_frontier"][0]["size"])
        self.assertEqual(proof, validate_consistency_proof(copy.deepcopy(proof)))

    def test_multi_append_proof_remains_compact(self):
        previous = anchor_state()
        candidate = previous
        for seed in range(2, 18):
            candidate = advance_state(candidate, seed)
        proof = create_consistency_proof(
            previous,
            create_checkpoint(previous),
            candidate,
            create_checkpoint(candidate),
        )
        hashes = len(proof["previous_frontier"]) + len(proof["append_frontier"])
        self.assertLess(hashes, len(candidate["entries"]))
        self.assertEqual(proof, validate_consistency_proof(proof))

    def test_previous_checkpoint_must_match_previous_state(self):
        previous = anchor_state(1)
        candidate = advance_state(previous, 2)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "previous checkpoint"):
            create_consistency_proof(
                previous,
                create_checkpoint(anchor_state(9)),
                candidate,
                create_checkpoint(candidate),
            )

    def test_candidate_checkpoint_must_match_candidate_state(self):
        previous = anchor_state(1)
        candidate = advance_state(previous, 2)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "candidate checkpoint"):
            create_consistency_proof(
                previous,
                create_checkpoint(previous),
                candidate,
                create_checkpoint(anchor_state(9)),
            )

    def test_rollback_is_denied(self):
        old = anchor_state()
        new = advance_state(old, 2)
        with self.assertRaises(AuditTrustConsistencyDenied) as raised:
            create_consistency_proof(
                new, create_checkpoint(new), old, create_checkpoint(old)
            )
        self.assertEqual("ATK009", raised.exception.rule_id)

    def test_fork_is_denied(self):
        anchor = anchor_state()
        left = advance_state(anchor, 2)
        right = advance_state(anchor, 3)
        with self.assertRaises(AuditTrustConsistencyDenied) as raised:
            create_consistency_proof(
                left, create_checkpoint(left), right, create_checkpoint(right)
            )
        self.assertEqual("ATK010", raised.exception.rule_id)

    def test_rehashed_previous_frontier_tamper_is_rejected(self):
        previous = anchor_state()
        candidate = advance_state(previous, 2)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        changed = copy.deepcopy(proof)
        changed["previous_frontier"][0]["hash"] = "f" * 64
        changed["consistency_id"] = _identifier(
            b"audit-trust-consistency-proof-v1", proof_core(changed)
        )
        with self.assertRaisesRegex(AuditTrustConsistencyError, "previous Merkle root"):
            validate_consistency_proof(changed)

    def test_rehashed_append_frontier_tamper_is_rejected(self):
        previous = anchor_state()
        candidate = advance_state(previous, 2)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        changed = copy.deepcopy(proof)
        changed["append_frontier"][0]["hash"] = "e" * 64
        changed["consistency_id"] = _identifier(
            b"audit-trust-consistency-proof-v1", proof_core(changed)
        )
        with self.assertRaisesRegex(AuditTrustConsistencyError, "candidate Merkle root"):
            validate_consistency_proof(changed)

    def test_noncanonical_frontier_layout_is_rejected(self):
        previous = anchor_state()
        candidate = previous
        for seed in range(2, 6):
            candidate = advance_state(candidate, seed)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        changed = copy.deepcopy(proof)
        changed["append_frontier"][1]["size"] = 2
        changed["consistency_id"] = _identifier(
            b"audit-trust-consistency-proof-v1", proof_core(changed)
        )
        with self.assertRaisesRegex(AuditTrustConsistencyError, "layout"):
            validate_consistency_proof(changed)

    def test_boundary_entry_tamper_is_rejected(self):
        previous = anchor_state()
        candidate = advance_state(previous, 2)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        changed = copy.deepcopy(proof)
        changed["boundary_entry"]["previous_entry_hash"] = "f" * 64
        changed["consistency_id"] = _identifier(
            b"audit-trust-consistency-proof-v1", proof_core(changed)
        )
        with self.assertRaisesRegex(AuditTrustConsistencyError, "boundary trust entry"):
            validate_consistency_proof(changed)

    def test_checkpoint_substitution_is_rejected(self):
        previous = anchor_state()
        candidate = advance_state(previous, 2)
        previous_checkpoint = create_checkpoint(previous)
        candidate_checkpoint = create_checkpoint(candidate)
        proof = create_consistency_proof(
            previous, previous_checkpoint, candidate, candidate_checkpoint
        )
        other = advance_state(candidate, 3)
        with self.assertRaisesRegex(AuditTrustConsistencyError, "references"):
            proof_matches_checkpoints(
                proof, previous_checkpoint, create_checkpoint(other)
            )

    def test_output_overwrite_and_symlink_are_rejected(self):
        state = anchor_state()
        checkpoint = create_checkpoint(state)
        proof = create_consistency_proof(state, checkpoint, state, checkpoint)
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

    def test_strict_loading_rejects_duplicate_and_noncanonical_json(self):
        state = anchor_state()
        checkpoint = create_checkpoint(state)
        proof = create_consistency_proof(state, checkpoint, state, checkpoint)
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

    def test_cli_lifecycle_supports_proof_only_verification(self):
        previous = anchor_state()
        candidate = advance_state(previous, 2)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous_checkpoint, candidate_checkpoint = write_inputs(root, previous, candidate)
            output = root / "consistency.json"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "prove",
                        str(root / "previous-state.json"),
                        str(root / "previous-checkpoint.json"),
                        str(root / "candidate-state.json"),
                        str(root / "candidate-checkpoint.json"),
                        str(output),
                        "--expected-previous-state-id",
                        previous["state_id"],
                        "--expected-previous-checkpoint-id",
                        previous_checkpoint["checkpoint_id"],
                        "--expected-candidate-state-id",
                        candidate["state_id"],
                        "--expected-candidate-checkpoint-id",
                        candidate_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(0, status)
            (root / "previous-state.json").unlink()
            (root / "candidate-state.json").unlink()
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "verify",
                        str(output),
                        str(root / "previous-checkpoint.json"),
                        str(root / "candidate-checkpoint.json"),
                        "--expected-previous-checkpoint-id",
                        previous_checkpoint["checkpoint_id"],
                        "--expected-candidate-checkpoint-id",
                        candidate_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(0, status)

    def test_cli_rollback_returns_one_without_creating_output(self):
        old = anchor_state()
        new = advance_state(old, 2)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous_checkpoint, candidate_checkpoint = write_inputs(root, new, old)
            output = root / "denied.json"
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "prove",
                        str(root / "previous-state.json"),
                        str(root / "previous-checkpoint.json"),
                        str(root / "candidate-state.json"),
                        str(root / "candidate-checkpoint.json"),
                        str(output),
                        "--expected-previous-state-id",
                        new["state_id"],
                        "--expected-previous-checkpoint-id",
                        previous_checkpoint["checkpoint_id"],
                        "--expected-candidate-state-id",
                        old["state_id"],
                        "--expected-candidate-checkpoint-id",
                        candidate_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(1, status)
            self.assertFalse(output.exists())

    def test_cli_stale_checkpoint_pin_returns_one(self):
        previous = anchor_state()
        candidate = advance_state(previous, 2)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous_checkpoint, candidate_checkpoint = write_inputs(root, previous, candidate)
            proof = create_consistency_proof(
                previous, previous_checkpoint, candidate, candidate_checkpoint
            )
            _write_new(root / "proof.json", proof)
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "verify",
                        str(root / "proof.json"),
                        str(root / "previous-checkpoint.json"),
                        str(root / "candidate-checkpoint.json"),
                        "--expected-previous-checkpoint-id",
                        "f" * 64,
                        "--expected-candidate-checkpoint-id",
                        candidate_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(1, status)

    def test_consistency_id_tamper_is_rejected(self):
        state = anchor_state()
        checkpoint = create_checkpoint(state)
        proof = create_consistency_proof(state, checkpoint, state, checkpoint)
        proof["consistency_id"] = "f" * 64
        with self.assertRaisesRegex(AuditTrustConsistencyError, "consistency ID"):
            validate_consistency_proof(proof)


if __name__ == "__main__":
    unittest.main()
