import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.release_checkpoint import canonical_json, create_checkpoint
from scripts.release_consistency import (
    ConsistencyDenied,
    ConsistencyError,
    create_consistency_proof,
    load_consistency_proof,
    main,
    range_layout,
    validate_consistency_proof,
)
from scripts.release_trust import append_transition, canonical_json as trust_json, create_state


def digest(label: str, length: int = 64) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:length]


def release(number: int, *, marker: str = "main", project: str = "basit-agent-system"):
    return {
        "project": project,
        "version": f"1.{number - 1}.0",
        "release_id": digest(f"release-{project}-{marker}-{number}"),
        "source_commit": digest(f"commit-{project}-{marker}-{number}", 40),
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


def state_with_entries(count: int, *, marker: str = "main", project: str = "basit-agent-system"):
    summaries = [release(index, marker=marker if index > 1 else "anchor", project=project) for index in range(1, count + 1)]
    state = create_state(summaries[0])
    for index in range(1, count):
        state = append_transition(
            state,
            summaries[index],
            accepted(summaries[index - 1], summaries[index], f"{marker}-{index}"),
        )
    return state


def descendant_from(state: dict, target_count: int, *, marker: str = "main"):
    result = state
    previous = result["entries"][-1]["release"]
    for number in range(len(result["entries"]) + 1, target_count + 1):
        candidate = release(number, marker=marker, project=result["project"])
        result = append_transition(result, candidate, accepted(previous, candidate, f"{marker}-{number}"))
        previous = candidate
    return result


def seal(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def write_evidence(root: Path, prefix: str, state: dict):
    state_path = root / f"{prefix}-state.json"
    checkpoint_path = root / f"{prefix}-checkpoint.json"
    checkpoint = create_checkpoint(state)
    state_path.write_bytes(trust_json(state))
    checkpoint_path.write_bytes(canonical_json(checkpoint))
    return state_path, checkpoint_path, checkpoint


class ReleaseConsistencyTests(unittest.TestCase):
    def test_range_layout_uses_maximal_aligned_power_of_two_segments(self):
        self.assertEqual([(0, 4), (4, 2), (6, 1)], range_layout(0, 7))
        self.assertEqual([(5, 1), (6, 2), (8, 4), (12, 1)], range_layout(5, 13))
        self.assertEqual([], range_layout(3, 3))

    def test_same_checkpoint_proof_is_deterministic_and_has_no_append_hashes(self):
        state = state_with_entries(5)
        checkpoint = create_checkpoint(state)
        first = create_consistency_proof(state, checkpoint, state, checkpoint)
        second = create_consistency_proof(state, checkpoint, state, checkpoint)
        self.assertEqual(first, second)
        self.assertEqual("same", first["relation"])
        self.assertEqual([], first["append_frontier"])
        self.assertEqual(first, validate_consistency_proof(first))

    def test_descendant_proofs_verify_across_uneven_tree_sizes(self):
        for previous_count, candidate_count in ((1, 2), (2, 5), (3, 10), (7, 13), (8, 17)):
            previous = state_with_entries(previous_count)
            candidate = descendant_from(previous, candidate_count)
            proof = create_consistency_proof(
                previous,
                create_checkpoint(previous),
                candidate,
                create_checkpoint(candidate),
            )
            self.assertEqual("right-descendant", proof["relation"])
            self.assertEqual(proof, validate_consistency_proof(proof))

    def test_large_history_proof_remains_compact(self):
        previous = state_with_entries(33)
        candidate = descendant_from(previous, 97)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        hashes = len(proof["previous_frontier"]) + len(proof["append_frontier"])
        self.assertLessEqual(hashes, 16)
        self.assertEqual(proof, validate_consistency_proof(proof))

    def test_proof_rejects_rehashed_previous_frontier_tampering(self):
        previous = state_with_entries(3)
        candidate = descendant_from(previous, 7)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        proof["previous_frontier"][0]["hash"] = "e" * 64
        core = dict(proof)
        core.pop("consistency_id")
        proof["consistency_id"] = seal(core)
        with self.assertRaisesRegex(ConsistencyError, "previous Merkle root"):
            validate_consistency_proof(proof)

    def test_proof_rejects_rehashed_append_frontier_tampering(self):
        previous = state_with_entries(4)
        candidate = descendant_from(previous, 9)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        proof["append_frontier"][0]["hash"] = "d" * 64
        core = dict(proof)
        core.pop("consistency_id")
        proof["consistency_id"] = seal(core)
        with self.assertRaisesRegex(ConsistencyError, "candidate Merkle root"):
            validate_consistency_proof(proof)

    def test_proof_rejects_rehashed_noncanonical_segment_layout(self):
        previous = state_with_entries(3)
        candidate = descendant_from(previous, 8)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        proof["append_frontier"][0]["size"] = 2
        core = dict(proof)
        core.pop("consistency_id")
        proof["consistency_id"] = seal(core)
        with self.assertRaisesRegex(ConsistencyError, "canonical compact-range layout"):
            validate_consistency_proof(proof)

    def test_proof_rejects_same_size_different_checkpoint_claim(self):
        state = state_with_entries(2)
        proof = create_consistency_proof(state, create_checkpoint(state), state, create_checkpoint(state))
        proof["candidate"]["state_id"] = "f" * 64
        core = dict(proof)
        core.pop("consistency_id")
        proof["consistency_id"] = seal(core)
        with self.assertRaisesRegex(ConsistencyError, "identical checkpoints"):
            validate_consistency_proof(proof)

    def test_proof_loader_rejects_noncanonical_json(self):
        previous = state_with_entries(2)
        candidate = descendant_from(previous, 4)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(proof))
            with self.assertRaisesRegex(ConsistencyError, "canonically"):
                load_consistency_proof(path)

    def test_create_cli_writes_and_verify_cli_accepts_portable_proof(self):
        previous = state_with_entries(3)
        candidate = descendant_from(previous, 11)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous_state, previous_checkpoint_path, previous_checkpoint = write_evidence(root, "previous", previous)
            candidate_state, candidate_checkpoint_path, candidate_checkpoint = write_evidence(root, "candidate", candidate)
            output = root / "consistency.json"
            with contextlib.redirect_stdout(io.StringIO()):
                create_status = main(
                    [
                        "prove", str(previous_state), str(previous_checkpoint_path),
                        str(candidate_state), str(candidate_checkpoint_path), str(output),
                        "--expected-previous-state-id", previous["state_id"],
                        "--expected-candidate-state-id", candidate["state_id"],
                        "--expected-previous-checkpoint-id", previous_checkpoint["checkpoint_id"],
                        "--expected-candidate-checkpoint-id", candidate_checkpoint["checkpoint_id"],
                    ]
                )
                verify_status = main(
                    [
                        "verify", str(output), str(previous_checkpoint_path), str(candidate_checkpoint_path),
                        "--expected-previous-checkpoint-id", previous_checkpoint["checkpoint_id"],
                        "--expected-candidate-checkpoint-id", candidate_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(0, create_status)
            self.assertEqual(0, verify_status)
            self.assertEqual(load_consistency_proof(output), validate_consistency_proof(load_consistency_proof(output)))

    def test_output_refuses_overwrite_without_changing_existing_bytes(self):
        previous = state_with_entries(1)
        candidate = descendant_from(previous, 2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p_state, p_checkpoint_path, p_checkpoint = write_evidence(root, "p", previous)
            c_state, c_checkpoint_path, c_checkpoint = write_evidence(root, "c", candidate)
            output = root / "proof.json"
            output.write_text("preserve")
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "prove", str(p_state), str(p_checkpoint_path), str(c_state),
                        str(c_checkpoint_path), str(output),
                        "--expected-previous-state-id", previous["state_id"],
                        "--expected-candidate-state-id", candidate["state_id"],
                        "--expected-previous-checkpoint-id", p_checkpoint["checkpoint_id"],
                        "--expected-candidate-checkpoint-id", c_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(2, status)
            self.assertEqual("preserve", output.read_text())

    def test_output_rejects_symlink_without_changing_target(self):
        previous = state_with_entries(1)
        candidate = descendant_from(previous, 2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p_state, p_checkpoint_path, p_checkpoint = write_evidence(root, "p", previous)
            c_state, c_checkpoint_path, c_checkpoint = write_evidence(root, "c", candidate)
            target = root / "target.json"
            target.write_text("preserve")
            output = root / "proof.json"
            output.symlink_to(target)
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "prove", str(p_state), str(p_checkpoint_path), str(c_state),
                        str(c_checkpoint_path), str(output),
                        "--expected-previous-state-id", previous["state_id"],
                        "--expected-candidate-state-id", candidate["state_id"],
                        "--expected-previous-checkpoint-id", p_checkpoint["checkpoint_id"],
                        "--expected-candidate-checkpoint-id", c_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(2, status)
            self.assertEqual("preserve", target.read_text())

    def test_wrong_previous_state_pin_returns_invalid_exit(self):
        previous = state_with_entries(1)
        candidate = descendant_from(previous, 2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p_state, p_checkpoint_path, p_checkpoint = write_evidence(root, "p", previous)
            c_state, c_checkpoint_path, c_checkpoint = write_evidence(root, "c", candidate)
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "prove", str(p_state), str(p_checkpoint_path), str(c_state),
                        str(c_checkpoint_path), str(root / "proof.json"),
                        "--expected-previous-state-id", "f" * 64,
                        "--expected-candidate-state-id", candidate["state_id"],
                        "--expected-previous-checkpoint-id", p_checkpoint["checkpoint_id"],
                        "--expected-candidate-checkpoint-id", c_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(2, status)

    def test_wrong_candidate_checkpoint_pin_returns_invalid_exit(self):
        previous = state_with_entries(1)
        candidate = descendant_from(previous, 2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _p_state, p_checkpoint_path, p_checkpoint = write_evidence(root, "p", previous)
            _c_state, c_checkpoint_path, _c_checkpoint = write_evidence(root, "c", candidate)
            proof = create_consistency_proof(
                previous, p_checkpoint, candidate, create_checkpoint(candidate)
            )
            proof_path = root / "proof.json"
            proof_path.write_bytes(canonical_json(proof))
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "verify", str(proof_path), str(p_checkpoint_path), str(c_checkpoint_path),
                        "--expected-previous-checkpoint-id", p_checkpoint["checkpoint_id"],
                        "--expected-candidate-checkpoint-id", "e" * 64,
                    ]
                )
            self.assertEqual(2, status)

    def test_verify_rejects_proof_referencing_different_candidate_checkpoint(self):
        previous = state_with_entries(1)
        candidate = descendant_from(previous, 2)
        other = descendant_from(previous, 3)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        self.assertNotEqual(proof["candidate"], {
            "checkpoint_id": create_checkpoint(other)["checkpoint_id"],
            "project": create_checkpoint(other)["project"],
            "state_id": create_checkpoint(other)["state_id"],
            "entry_count": create_checkpoint(other)["entry_count"],
            "merkle_root": create_checkpoint(other)["merkle"]["root"],
        })

    def test_rollback_is_denied_with_stable_rule_and_no_output(self):
        older = state_with_entries(2)
        newer = descendant_from(older, 5)
        with self.assertRaises(ConsistencyDenied) as captured:
            create_consistency_proof(newer, create_checkpoint(newer), older, create_checkpoint(older))
        self.assertEqual("CNS010", captured.exception.report["violations"][0]["rule_id"])
        self.assertEqual("rollback", captured.exception.report["relation"])

    def test_fork_is_denied_with_stable_rule(self):
        anchor = state_with_entries(1)
        left = descendant_from(anchor, 2, marker="left")
        right = descendant_from(anchor, 2, marker="right")
        with self.assertRaises(ConsistencyDenied) as captured:
            create_consistency_proof(left, create_checkpoint(left), right, create_checkpoint(right))
        self.assertEqual("CNS011", captured.exception.report["violations"][0]["rule_id"])
        self.assertEqual("fork", captured.exception.report["relation"])

    def test_cli_rollback_denial_returns_one_and_does_not_create_proof(self):
        older = state_with_entries(1)
        newer = descendant_from(older, 3)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            newer_state, newer_checkpoint_path, newer_checkpoint = write_evidence(root, "newer", newer)
            older_state, older_checkpoint_path, older_checkpoint = write_evidence(root, "older", older)
            output = root / "proof.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    [
                        "prove", str(newer_state), str(newer_checkpoint_path),
                        str(older_state), str(older_checkpoint_path), str(output),
                        "--expected-previous-state-id", newer["state_id"],
                        "--expected-candidate-state-id", older["state_id"],
                        "--expected-previous-checkpoint-id", newer_checkpoint["checkpoint_id"],
                        "--expected-candidate-checkpoint-id", older_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(1, status)
            self.assertFalse(output.exists())
            self.assertEqual("CNS010", json.loads(stdout.getvalue())["violations"][0]["rule_id"])

    def test_different_projects_are_invalid_not_policy_denials(self):
        left = state_with_entries(1, project="left-project")
        right = state_with_entries(1, project="right-project")
        with self.assertRaisesRegex(ConsistencyError, "different projects"):
            create_consistency_proof(left, create_checkpoint(left), right, create_checkpoint(right))

    def test_consistency_id_changes_when_candidate_changes(self):
        previous = state_with_entries(2)
        candidate_a = descendant_from(previous, 4, marker="a")
        candidate_b = descendant_from(previous, 4, marker="b")
        proof_a = create_consistency_proof(
            previous, create_checkpoint(previous), candidate_a, create_checkpoint(candidate_a)
        )
        proof_b = create_consistency_proof(
            previous, create_checkpoint(previous), candidate_b, create_checkpoint(candidate_b)
        )
        self.assertNotEqual(proof_a["consistency_id"], proof_b["consistency_id"])

    def test_proof_contains_hashes_not_release_source_content(self):
        previous = state_with_entries(4)
        candidate = descendant_from(previous, 12)
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        serialized = canonical_json(proof).decode()
        self.assertNotIn("source_date_epoch", serialized)
        self.assertNotIn("transition_id", serialized)
        self.assertNotIn("policy_sha256", serialized)


if __name__ == "__main__":
    unittest.main()
