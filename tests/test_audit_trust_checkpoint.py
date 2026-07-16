import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_audit import ZERO_HASH
from agent_audit_bundle import create_bundle
from agent_audit_catalog import _build_catalog
from agent_audit_checkpoint import _canonical_bytes as evidence_bytes
from agent_audit_checkpoint import create_checkpoint as create_catalog_checkpoint
from agent_audit_checkpoint import create_proof as create_catalog_proof
from agent_audit_consistency import create_consistency_proof
from agent_audit_trust import _atomic_write, append_transition, create_state
from agent_audit_trust_checkpoint import (
    AuditTrustCheckpointError,
    _proof_identifier,
    checkpoint_matches_state,
    create_checkpoint,
    create_proof,
    lineage,
    load_checkpoint,
    load_proof,
    main,
    proof_matches_bundle,
    proof_matches_checkpoint,
    validate_checkpoint,
    validate_proof,
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
    generation_delta = None
    if previous is not None:
        generation_delta = candidate["generation"] - previous["generation"]
    return {
        "admitted": True,
        "policy_sha256": h(7000 + decision),
        "decision_id": h(8000 + decision),
        "identity": {
            "bundle_id": verified["bundle_id"],
            "bundle_type": verified["bundle_type"],
            "candidate_checkpoint_id": candidate["checkpoint_id"],
            "candidate_catalog_id": candidate["catalog_id"],
            "previous_checkpoint_id": (
                previous["checkpoint_id"] if previous is not None else None
            ),
            "previous_catalog_id": previous["catalog_id"] if previous is not None else None,
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
            "generation_delta": generation_delta,
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


def segment(index: int, previous: str) -> dict:
    return {
        "segment_index": index,
        "directory": f"segment-{index:04d}",
        "segment_id": h(index),
        "previous_segment_id": previous,
        "manifest_sha256": h(index + 100),
        "segment_sha256": h(index + 200),
        "head_hash": h(index + 300),
        "records": index,
        "bytes": index * 100,
    }


def real_bundles(root: Path):
    first = segment(1, ZERO_HASH)
    previous_catalog = _build_catalog(
        [first], generation=1, previous_catalog_id=ZERO_HASH
    )
    second = segment(2, first["segment_id"])
    candidate_catalog = _build_catalog(
        [first, second],
        generation=2,
        previous_catalog_id=previous_catalog["catalog_id"],
    )
    previous_checkpoint = create_catalog_checkpoint(previous_catalog)
    candidate_checkpoint = create_catalog_checkpoint(candidate_catalog)
    previous_proof = create_catalog_proof(
        previous_catalog, previous_checkpoint, segment_index=1
    )
    candidate_proof = create_catalog_proof(
        candidate_catalog, candidate_checkpoint, segment_index=2
    )
    consistency = create_consistency_proof(
        previous_catalog,
        previous_checkpoint,
        candidate_catalog,
        candidate_checkpoint,
    )
    payloads = {
        "previous-checkpoint.json": previous_checkpoint,
        "candidate-checkpoint.json": candidate_checkpoint,
        "previous-proof.json": previous_proof,
        "candidate-proof.json": candidate_proof,
        "consistency.json": consistency,
    }
    for name, payload in payloads.items():
        (root / name).write_bytes(evidence_bytes(payload))
    anchor_manifest = create_bundle(
        root / "anchor-bundle",
        root / "previous-checkpoint.json",
        previous_checkpoint["checkpoint_id"],
        [root / "previous-proof.json"],
    )
    transition_manifest = create_bundle(
        root / "transition-bundle",
        root / "candidate-checkpoint.json",
        candidate_checkpoint["checkpoint_id"],
        [root / "candidate-proof.json"],
        previous_checkpoint_path=root / "previous-checkpoint.json",
        expected_previous_checkpoint_id=previous_checkpoint["checkpoint_id"],
        consistency_path=root / "consistency.json",
    )
    anchor_verified = {
        "valid": True,
        "bundle_id": anchor_manifest["bundle_id"],
        "bundle_type": "snapshot",
        "candidate": anchor_manifest["candidate"],
        "previous": None,
        "consistency": None,
        "proof_count": 1,
        "segment_count": 0,
        "proof_ids": [previous_proof["proof_id"]],
        "segment_ids": [first["segment_id"]],
        "files": len(anchor_manifest["files"]) + 2,
        "bytes": 1,
    }
    transition_verified = {
        "valid": True,
        "bundle_id": transition_manifest["bundle_id"],
        "bundle_type": "transition",
        "candidate": transition_manifest["candidate"],
        "previous": transition_manifest["previous"],
        "consistency": transition_manifest["consistency"],
        "proof_count": 1,
        "segment_count": 0,
        "proof_ids": [candidate_proof["proof_id"]],
        "segment_ids": [second["segment_id"]],
        "files": len(transition_manifest["files"]) + 2,
        "bytes": 1,
    }
    state = create_state(admitted_report(anchor_verified, decision=31), anchor_verified)
    updated = append_transition(
        state, admitted_report(transition_verified, decision=32), transition_verified
    )
    return state, updated, root / "anchor-bundle", root / "transition-bundle"


class AuditTrustCheckpointTests(unittest.TestCase):
    def test_checkpoint_is_deterministic_and_canonical(self):
        state = anchor_state()
        checkpoint = create_checkpoint(state)
        self.assertEqual(checkpoint, validate_checkpoint(copy.deepcopy(checkpoint)))
        self.assertEqual(state["state_id"], checkpoint["state_id"])
        self.assertEqual(1, checkpoint["entry_count"])
        self.assertEqual(64, len(checkpoint["checkpoint_id"]))

    def test_checkpoint_rejects_unknown_fields_and_boolean_counts(self):
        checkpoint = create_checkpoint(anchor_state())
        extra = dict(checkpoint)
        extra["extra"] = True
        with self.assertRaisesRegex(AuditTrustCheckpointError, "fields"):
            validate_checkpoint(extra)
        boolean = dict(checkpoint)
        boolean["entry_count"] = True
        with self.assertRaisesRegex(AuditTrustCheckpointError, "integer"):
            validate_checkpoint(boolean)

    def test_checkpoint_must_match_the_full_state(self):
        left = anchor_state(1)
        right = anchor_state(2)
        with self.assertRaisesRegex(AuditTrustCheckpointError, "does not match"):
            checkpoint_matches_state(create_checkpoint(left), right)

    def test_single_entry_inclusion_proof(self):
        state = anchor_state()
        checkpoint = create_checkpoint(state)
        proof = create_proof(state, checkpoint, sequence=1)
        self.assertEqual([], proof["audit_path"])
        self.assertEqual(proof, validate_proof(copy.deepcopy(proof)))
        self.assertEqual(proof, proof_matches_checkpoint(proof, checkpoint))

    def test_first_middle_and_last_proofs_for_odd_tree(self):
        state = anchor_state()
        for seed in range(2, 6):
            state = advance_state(state, seed)
        checkpoint = create_checkpoint(state)
        for sequence in (1, 3, 5):
            proof = create_proof(state, checkpoint, sequence=sequence)
            self.assertEqual(sequence, validate_proof(proof)["entry"]["sequence"])

    def test_proof_selector_by_bundle_id(self):
        state = advance_state(anchor_state(), 2)
        checkpoint = create_checkpoint(state)
        wanted = state["entries"][1]["evidence"]["bundle_id"]
        proof = create_proof(state, checkpoint, bundle_id=wanted)
        self.assertEqual(wanted, proof["entry"]["evidence"]["bundle_id"])

    def test_proof_selector_is_exact_and_entry_must_exist(self):
        state = anchor_state()
        checkpoint = create_checkpoint(state)
        with self.assertRaisesRegex(AuditTrustCheckpointError, "exactly one"):
            create_proof(state, checkpoint)
        with self.assertRaisesRegex(AuditTrustCheckpointError, "not present"):
            create_proof(state, checkpoint, bundle_id="f" * 64)

    def test_rehashed_audit_path_tampering_is_rejected(self):
        state = advance_state(anchor_state(), 2)
        checkpoint = create_checkpoint(state)
        proof = create_proof(state, checkpoint, sequence=2)
        changed = copy.deepcopy(proof)
        changed["audit_path"][0] = "f" * 64
        core = {key: changed[key] for key in ("proof_version", "checkpoint", "entry", "audit_path")}
        changed["proof_id"] = _proof_identifier(core)
        with self.assertRaisesRegex(AuditTrustCheckpointError, "reconstruct"):
            validate_proof(changed)

    def test_short_and_extra_audit_paths_are_rejected(self):
        state = advance_state(anchor_state(), 2)
        checkpoint = create_checkpoint(state)
        proof = create_proof(state, checkpoint, sequence=1)
        short = copy.deepcopy(proof)
        short["audit_path"] = []
        short["proof_id"] = _proof_identifier(
            {key: short[key] for key in ("proof_version", "checkpoint", "entry", "audit_path")}
        )
        with self.assertRaisesRegex(AuditTrustCheckpointError, "too short"):
            validate_proof(short)
        extra = copy.deepcopy(proof)
        extra["audit_path"].append("f" * 64)
        extra["proof_id"] = _proof_identifier(
            {key: extra[key] for key in ("proof_version", "checkpoint", "entry", "audit_path")}
        )
        with self.assertRaisesRegex(AuditTrustCheckpointError, "extra"):
            validate_proof(extra)

    def test_checkpoint_substitution_is_rejected(self):
        left_state = anchor_state(1)
        right_state = anchor_state(2)
        left_checkpoint = create_checkpoint(left_state)
        proof = create_proof(left_state, left_checkpoint, sequence=1)
        with self.assertRaisesRegex(AuditTrustCheckpointError, "reference"):
            proof_matches_checkpoint(proof, create_checkpoint(right_state))

    def test_snapshot_proof_binds_to_actual_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            state, _, anchor_bundle, _ = real_bundles(Path(temporary))
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=1)
            verified = proof_matches_bundle(proof, anchor_bundle)
        self.assertEqual("snapshot", verified["bundle_type"])

    def test_transition_proof_binds_to_actual_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, state, _, transition_bundle = real_bundles(Path(temporary))
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=2)
            verified = proof_matches_bundle(proof, transition_bundle)
        self.assertEqual("transition", verified["bundle_type"])

    def test_wrong_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state, _, anchor_bundle, transition_bundle = real_bundles(Path(temporary))
            checkpoint = create_checkpoint(state)
            proof = create_proof(state, checkpoint, sequence=1)
            with self.assertRaisesRegex(AuditTrustCheckpointError, "verification failed"):
                proof_matches_bundle(proof, transition_bundle)
            self.assertTrue(anchor_bundle.is_dir())

    def test_loaders_reject_duplicate_keys_and_noncanonical_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"checkpoint_version":1,"checkpoint_version":1}\n')
            with self.assertRaisesRegex(AuditTrustCheckpointError, "duplicate"):
                load_checkpoint(duplicate)
            checkpoint = create_checkpoint(anchor_state())
            noncanonical = root / "noncanonical.json"
            noncanonical.write_text(json.dumps(checkpoint, sort_keys=True) + "\n")
            with self.assertRaisesRegex(AuditTrustCheckpointError, "canonically"):
                load_checkpoint(noncanonical)

    def test_outputs_are_immutable_and_symlink_safe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = anchor_state()
            state_path = root / "state.json"
            _atomic_write(state_path, state, require_absent=True)
            checkpoint_path = root / "checkpoint.json"
            with contextlib.redirect_stdout(io.StringIO()):
                first = main([
                    "create", str(state_path), str(checkpoint_path),
                    "--expected-state-id", state["state_id"],
                ])
            with contextlib.redirect_stderr(io.StringIO()):
                second = main([
                    "create", str(state_path), str(checkpoint_path),
                    "--expected-state-id", state["state_id"],
                ])
            target = root / "target"
            target.mkdir()
            linked = root / "linked"
            linked.symlink_to(target, target_is_directory=True)
            with contextlib.redirect_stderr(io.StringIO()):
                unsafe = main([
                    "create", str(state_path), str(linked / "checkpoint.json"),
                    "--expected-state-id", state["state_id"],
                ])
        self.assertEqual((0, 2, 2), (first, second, unsafe))

    def test_lineage_accepts_same_and_right_descendant(self):
        anchor = anchor_state()
        descendant = advance_state(anchor, 2)
        self.assertEqual("same", lineage(anchor, anchor)["relation"])
        report = lineage(anchor, descendant)
        self.assertTrue(report["accepted"])
        self.assertEqual("right-descendant", report["relation"])

    def test_lineage_denies_rollback(self):
        anchor = anchor_state()
        descendant = advance_state(anchor, 2)
        report = lineage(descendant, anchor)
        self.assertFalse(report["accepted"])
        self.assertEqual("ATC010", report["violations"][0]["rule_id"])

    def test_lineage_denies_fork(self):
        anchor = anchor_state()
        left = advance_state(anchor, 2)
        right = advance_state(anchor, 3)
        report = lineage(left, right)
        self.assertFalse(report["accepted"])
        self.assertEqual("ATC011", report["violations"][0]["rule_id"])

    def test_cli_proof_only_flow_and_stale_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = advance_state(anchor_state(), 2)
            state_path = root / "state.json"
            _atomic_write(state_path, state, require_absent=True)
            checkpoint_path = root / "checkpoint.json"
            proof_path = root / "proof.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                created = main([
                    "create", str(state_path), str(checkpoint_path),
                    "--expected-state-id", state["state_id"], "--format", "json",
                ])
            checkpoint = json.loads(output.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                proved = main([
                    "prove", str(state_path), str(checkpoint_path), str(proof_path),
                    "--expected-state-id", state["state_id"],
                    "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                    "--sequence", "2",
                ])
            state_path.unlink()
            with contextlib.redirect_stdout(io.StringIO()):
                verified = main([
                    "verify-proof", str(proof_path), str(checkpoint_path),
                    "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                ])
            with contextlib.redirect_stderr(io.StringIO()):
                stale = main([
                    "verify", str(checkpoint_path),
                    "--expected-checkpoint-id", "f" * 64,
                ])
        self.assertEqual((0, 0, 0, 2), (created, proved, verified, stale))

    def test_cli_lineage_exit_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            anchor = anchor_state()
            descendant = advance_state(anchor, 2)
            anchor_path = root / "anchor.json"
            descendant_path = root / "descendant.json"
            _atomic_write(anchor_path, anchor, require_absent=True)
            _atomic_write(descendant_path, descendant, require_absent=True)
            with contextlib.redirect_stdout(io.StringIO()):
                accepted = main([
                    "lineage", str(anchor_path), str(descendant_path),
                    "--expected-left-state-id", anchor["state_id"],
                    "--expected-right-state-id", descendant["state_id"],
                ])
                denied = main([
                    "lineage", str(descendant_path), str(anchor_path),
                    "--expected-left-state-id", descendant["state_id"],
                    "--expected-right-state-id", anchor["state_id"],
                ])
        self.assertEqual((0, 1), (accepted, denied))


if __name__ == "__main__":
    unittest.main()
