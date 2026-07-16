import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.release_checkpoint import (
    CheckpointError,
    canonical_json,
    checkpoint_matches_state,
    create_checkpoint,
    create_proof,
    lineage,
    load_checkpoint,
    main,
    validate_checkpoint,
    validate_proof,
)
from scripts.release_trust import append_transition, canonical_json as trust_json, create_state


def digest(label: str, length: int = 64) -> str:
    value = hashlib.sha256(label.encode()).hexdigest()
    return value[:length]


def release(number: int, *, project: str = "basit-agent-system", version: str | None = None):
    return {
        "project": project,
        "version": version or f"1.{number - 1}.0",
        "release_id": digest(f"release-{project}-{number}"),
        "source_commit": digest(f"commit-{project}-{number}", 40),
        "source_date_epoch": 100 + number,
    }


def accepted(previous: dict, candidate: dict, marker: str):
    return {
        "accepted": True,
        "transition_id": digest(f"transition-{marker}"),
        "policy": {"sha256": digest(f"policy-{marker}")},
        "previous": {"release_id": previous["release_id"]},
        "candidate": {"release_id": candidate["release_id"]},
    }


def state_with_entries(count: int, *, project: str = "basit-agent-system"):
    summaries = [release(index, project=project) for index in range(1, count + 1)]
    state = create_state(summaries[0])
    for index in range(1, count):
        state = append_transition(
            state,
            summaries[index],
            accepted(summaries[index - 1], summaries[index], str(index)),
        )
    return state


def seal(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


class ReleaseCheckpointTests(unittest.TestCase):
    def test_checkpoint_is_deterministic_and_binds_state(self):
        state = state_with_entries(5)
        first = create_checkpoint(state)
        second = create_checkpoint(state)
        self.assertEqual(first, second)
        self.assertEqual(state["state_id"], first["state_id"])
        self.assertEqual(5, first["entry_count"])
        self.assertEqual(state["head"], first["head"])
        self.assertEqual(64, len(first["merkle"]["root"]))
        self.assertEqual(first, checkpoint_matches_state(first, state))

    def test_checkpoint_rejects_rehashed_merkle_tampering(self):
        checkpoint = create_checkpoint(state_with_entries(3))
        checkpoint["merkle"]["root"] = "f" * 64
        core = dict(checkpoint)
        core.pop("checkpoint_id")
        checkpoint["checkpoint_id"] = seal(core)
        with self.assertRaisesRegex(CheckpointError, "does not match"):
            checkpoint_matches_state(checkpoint, state_with_entries(3))

    def test_checkpoint_loader_rejects_noncanonical_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_text(json.dumps(create_checkpoint(state_with_entries(2))))
            with self.assertRaisesRegex(CheckpointError, "canonically"):
                load_checkpoint(path)

    def test_checkpoint_output_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = state_with_entries(1)
            state_path = root / "state.json"
            state_path.write_bytes(trust_json(state))
            output = root / "checkpoint.json"
            output.write_text("preserve")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "create",
                        str(state_path),
                        str(output),
                        "--expected-state-id",
                        state["state_id"],
                    ]
                )
            self.assertEqual(2, status)
            self.assertEqual("preserve", output.read_text())

    def test_checkpoint_output_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = state_with_entries(1)
            state_path = root / "state.json"
            state_path.write_bytes(trust_json(state))
            target = root / "target.json"
            target.write_text("preserve")
            output = root / "checkpoint.json"
            output.symlink_to(target)
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "create",
                        str(state_path),
                        str(output),
                        "--expected-state-id",
                        state["state_id"],
                    ]
                )
            self.assertEqual(2, status)
            self.assertEqual("preserve", target.read_text())

    def test_single_entry_proof_has_empty_path(self):
        state = state_with_entries(1)
        checkpoint = create_checkpoint(state)
        proof = create_proof(state, checkpoint, sequence=1)
        self.assertEqual([], proof["audit_path"])
        self.assertEqual(proof, validate_proof(proof))

    def test_odd_tree_first_middle_and_last_proofs_verify(self):
        state = state_with_entries(5)
        checkpoint = create_checkpoint(state)
        for sequence in (1, 3, 5):
            proof = create_proof(state, checkpoint, sequence=sequence)
            self.assertEqual(sequence, proof["entry"]["sequence"])
            self.assertEqual(proof, validate_proof(proof))

    def test_proof_can_select_release_id(self):
        state = state_with_entries(4)
        checkpoint = create_checkpoint(state)
        release_id = state["entries"][2]["release"]["release_id"]
        proof = create_proof(state, checkpoint, release_id=release_id)
        self.assertEqual(3, proof["entry"]["sequence"])
        self.assertEqual(release_id, proof["entry"]["release"]["release_id"])

    def test_proof_rejects_rehashed_entry_tampering(self):
        state = state_with_entries(3)
        proof = create_proof(state, create_checkpoint(state), sequence=2)
        proof["entry"]["release"]["version"] = "9.0.0"
        entry_core = dict(proof["entry"])
        entry_core.pop("entry_hash")
        proof["entry"]["entry_hash"] = seal(entry_core)
        proof_core = dict(proof)
        proof_core.pop("proof_id")
        proof["proof_id"] = seal(proof_core)
        with self.assertRaisesRegex(CheckpointError, "Merkle root"):
            validate_proof(proof)

    def test_proof_rejects_rehashed_audit_path_tampering(self):
        state = state_with_entries(5)
        proof = create_proof(state, create_checkpoint(state), sequence=3)
        proof["audit_path"][0] = "e" * 64
        proof_core = dict(proof)
        proof_core.pop("proof_id")
        proof["proof_id"] = seal(proof_core)
        with self.assertRaisesRegex(CheckpointError, "Merkle root"):
            validate_proof(proof)

    def test_proof_rejects_extra_audit_hash(self):
        state = state_with_entries(2)
        proof = create_proof(state, create_checkpoint(state), sequence=1)
        proof["audit_path"].append("d" * 64)
        proof_core = dict(proof)
        proof_core.pop("proof_id")
        proof["proof_id"] = seal(proof_core)
        with self.assertRaisesRegex(CheckpointError, "extra"):
            validate_proof(proof)

    def test_verify_proof_rejects_different_checkpoint(self):
        first_state = state_with_entries(2)
        second_state = state_with_entries(3)
        first_checkpoint = create_checkpoint(first_state)
        second_checkpoint = create_checkpoint(second_state)
        proof = create_proof(first_state, first_checkpoint, sequence=1)
        self.assertNotEqual(proof["checkpoint"], {
            "checkpoint_id": second_checkpoint["checkpoint_id"],
            "project": second_checkpoint["project"],
            "state_id": second_checkpoint["state_id"],
            "entry_count": second_checkpoint["entry_count"],
            "merkle_root": second_checkpoint["merkle"]["root"],
        })

    def test_lineage_accepts_same_state(self):
        state = state_with_entries(3)
        report = lineage(state, state)
        self.assertTrue(report["accepted"])
        self.assertEqual("same", report["relation"])
        self.assertEqual(3, report["common"]["entries"])

    def test_lineage_accepts_right_descendant(self):
        left = state_with_entries(2)
        right = state_with_entries(5)
        report = lineage(left, right)
        self.assertTrue(report["accepted"])
        self.assertEqual("right-descendant", report["relation"])
        self.assertEqual(2, report["common"]["entries"])

    def test_lineage_denies_rollback(self):
        report = lineage(state_with_entries(4), state_with_entries(2))
        self.assertFalse(report["accepted"])
        self.assertEqual("rollback", report["relation"])
        self.assertEqual({"CHK010"}, {item["rule_id"] for item in report["violations"]})

    def test_lineage_denies_fork(self):
        anchor = release(1)
        left_candidate = release(2)
        right_candidate = release(3, version="1.1.0")
        base = create_state(anchor)
        left = append_transition(base, left_candidate, accepted(anchor, left_candidate, "left"))
        right = append_transition(base, right_candidate, accepted(anchor, right_candidate, "right"))
        report = lineage(left, right)
        self.assertFalse(report["accepted"])
        self.assertEqual("fork", report["relation"])
        self.assertEqual({"CHK011"}, {item["rule_id"] for item in report["violations"]})

    def test_lineage_rejects_different_projects(self):
        with self.assertRaisesRegex(CheckpointError, "different projects"):
            lineage(state_with_entries(1), state_with_entries(1, project="other-project"))

    def test_cli_create_prove_and_verify_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = state_with_entries(5)
            state_path = root / "state.json"
            checkpoint_path = root / "checkpoint.json"
            proof_path = root / "proof.json"
            state_path.write_bytes(trust_json(state))
            with contextlib.redirect_stdout(io.StringIO()):
                create_status = main(
                    [
                        "create",
                        str(state_path),
                        str(checkpoint_path),
                        "--expected-state-id",
                        state["state_id"],
                    ]
                )
            checkpoint = load_checkpoint(checkpoint_path)
            with contextlib.redirect_stdout(io.StringIO()):
                prove_status = main(
                    [
                        "prove",
                        str(state_path),
                        str(checkpoint_path),
                        str(proof_path),
                        "--expected-state-id",
                        state["state_id"],
                        "--expected-checkpoint-id",
                        checkpoint["checkpoint_id"],
                        "--sequence",
                        "4",
                    ]
                )
                verify_status = main(
                    [
                        "verify-proof",
                        str(proof_path),
                        str(checkpoint_path),
                        "--expected-checkpoint-id",
                        checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual((0, 0, 0), (create_status, prove_status, verify_status))

    def test_cli_lineage_exit_codes_and_stale_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            newer = state_with_entries(4)
            older = state_with_entries(2)
            newer_path = root / "newer.json"
            older_path = root / "older.json"
            newer_path.write_bytes(trust_json(newer))
            older_path.write_bytes(trust_json(older))
            with contextlib.redirect_stdout(io.StringIO()):
                rollback_status = main(
                    [
                        "lineage",
                        str(newer_path),
                        str(older_path),
                        "--expected-left-state-id",
                        newer["state_id"],
                        "--expected-right-state-id",
                        older["state_id"],
                    ]
                )
            with contextlib.redirect_stderr(io.StringIO()):
                stale_status = main(
                    [
                        "lineage",
                        str(older_path),
                        str(newer_path),
                        "--expected-left-state-id",
                        "f" * 64,
                        "--expected-right-state-id",
                        newer["state_id"],
                    ]
                )
            self.assertEqual(1, rollback_status)
            self.assertEqual(2, stale_status)


if __name__ == "__main__":
    unittest.main()
