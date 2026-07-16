import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import agent_system
from agent_audit import ZERO_HASH
from agent_audit_catalog import _build_catalog, initialize_catalog, load_catalog, synchronize_catalog
from agent_audit_checkpoint import _canonical_bytes, _identifier, create_checkpoint
from agent_audit_consistency import (
    AuditCatalogConsistencyDenied,
    AuditCatalogConsistencyError,
    create_consistency_proof,
    load_consistency_proof,
    main,
    proof_matches_checkpoints,
    range_layout,
    validate_consistency_proof,
)
from agent_audit_segments import rotate_audit


def fake_entry(index: int, previous: str, *, salt: int = 0) -> dict:
    base = index + salt * 10_000
    token = f"{base:064x}"
    return {
        "segment_index": index,
        "directory": f"segment-{index:04d}",
        "segment_id": token,
        "previous_segment_id": previous,
        "manifest_sha256": f"{base + 100:064x}",
        "segment_sha256": f"{base + 200:064x}",
        "head_hash": f"{base + 300:064x}",
        "records": index,
        "bytes": index * 100,
    }


def fake_entries(size: int, *, fork_at: int | None = None) -> list[dict]:
    entries = []
    previous = ZERO_HASH
    for index in range(1, size + 1):
        salt = 1 if fork_at is not None and index >= fork_at else 0
        entry = fake_entry(index, previous, salt=salt)
        entries.append(entry)
        previous = entry["segment_id"]
    return entries


def catalog(size: int, generation: int, previous_catalog_id: str, *, fork_at: int | None = None) -> dict:
    return _build_catalog(
        fake_entries(size, fork_at=fork_at),
        generation=generation,
        previous_catalog_id=previous_catalog_id,
    )


def direct_pair(previous_size: int = 2, candidate_size: int = 5) -> tuple[dict, dict]:
    previous = catalog(previous_size, 1, ZERO_HASH)
    candidate = _build_catalog(
        fake_entries(candidate_size),
        generation=2,
        previous_catalog_id=previous["catalog_id"],
    )
    return previous, candidate


def reidentify(payload: dict) -> dict:
    core = dict(payload)
    core.pop("consistency_id", None)
    return {
        **core,
        "consistency_id": _identifier(b"audit-catalog-consistency-proof-v1", core),
    }


def append_event(path: Path, value: int) -> None:
    agent_system.append_audit(path, "operation-complete", {"value": value})


def real_pair(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    candidate_root = root / "candidate"
    previous_root = root / "previous"
    candidate_archive = candidate_root / "segments"
    previous_archive = previous_root / "segments"
    candidate_active = candidate_root / "active.jsonl"
    candidate_archive.mkdir(parents=True)
    previous_archive.mkdir(parents=True)

    append_event(candidate_active, 1)
    first_segment = candidate_archive / "segment-0001"
    rotate_audit(candidate_active, first_segment)
    initial_catalog_path = candidate_archive / "catalog.json"
    initialize_catalog(initial_catalog_path, active_path=candidate_active)
    initial_catalog = load_catalog(initial_catalog_path)

    shutil.copytree(first_segment, previous_archive / first_segment.name)
    previous_catalog_path = previous_archive / "catalog.json"
    previous_catalog_path.write_bytes(initial_catalog_path.read_bytes())
    fork_active = root / "fork-active.jsonl"
    fork_active.write_bytes(candidate_active.read_bytes())

    append_event(candidate_active, 2)
    rotate_audit(candidate_active, candidate_archive / "segment-0002")
    append_event(candidate_active, 3)
    rotate_audit(candidate_active, candidate_archive / "segment-0003")
    synchronize_catalog(
        initial_catalog_path,
        expected_catalog_id=initial_catalog["catalog_id"],
        active_path=candidate_active,
    )

    previous_checkpoint_path = root / "previous-checkpoint.json"
    candidate_checkpoint_path = root / "candidate-checkpoint.json"
    previous_checkpoint_path.write_bytes(_canonical_bytes(create_checkpoint(initial_catalog)))
    candidate_checkpoint_path.write_bytes(
        _canonical_bytes(create_checkpoint(load_catalog(initial_catalog_path)))
    )
    return (
        previous_catalog_path,
        previous_checkpoint_path,
        initial_catalog_path,
        candidate_checkpoint_path,
        candidate_active,
    )


class AuditCatalogConsistencyTests(unittest.TestCase):
    def test_range_layout_is_canonical_and_aligned(self):
        self.assertEqual([(0, 8), (8, 2), (10, 1)], range_layout(0, 11))
        self.assertEqual([(3, 1), (4, 4), (8, 2)], range_layout(3, 10))

    def test_same_checkpoint_proof_validates(self):
        current = catalog(3, 1, ZERO_HASH)
        checkpoint = create_checkpoint(current)
        proof = create_consistency_proof(current, checkpoint, current, checkpoint)
        validated = validate_consistency_proof(proof)
        self.assertEqual("same", validated["relation"])
        self.assertEqual([], validated["append_frontier"])

    def test_direct_descendant_proof_validates_predecessor(self):
        previous, candidate = direct_pair()
        proof = create_consistency_proof(
            previous,
            create_checkpoint(previous),
            candidate,
            create_checkpoint(candidate),
        )
        self.assertEqual("right-descendant", proof["relation"])
        self.assertTrue(proof["direct_predecessor_verified"])
        self.assertEqual(proof, validate_consistency_proof(proof))

    def test_multi_generation_descendant_is_append_only_but_not_direct(self):
        previous = catalog(2, 1, ZERO_HASH)
        candidate = _build_catalog(
            fake_entries(6),
            generation=4,
            previous_catalog_id="f" * 64,
        )
        proof = create_consistency_proof(
            previous,
            create_checkpoint(previous),
            candidate,
            create_checkpoint(candidate),
        )
        self.assertFalse(proof["direct_predecessor_verified"])
        self.assertEqual("right-descendant", validate_consistency_proof(proof)["relation"])

    def test_proof_is_deterministic(self):
        previous, candidate = direct_pair(3, 7)
        first = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        second = create_consistency_proof(
            json.loads(json.dumps(previous)),
            create_checkpoint(previous),
            json.loads(json.dumps(candidate)),
            create_checkpoint(candidate),
        )
        self.assertEqual(first, second)

    def test_frontier_size_is_logarithmic(self):
        previous = catalog(511, 1, ZERO_HASH)
        candidate = _build_catalog(
            fake_entries(1025), generation=2, previous_catalog_id=previous["catalog_id"]
        )
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        self.assertLessEqual(
            len(proof["previous_frontier"]) + len(proof["append_frontier"]), 20
        )

    def test_rollback_is_denied(self):
        older, newer = direct_pair(2, 5)
        with self.assertRaises(AuditCatalogConsistencyDenied) as caught:
            create_consistency_proof(
                newer, create_checkpoint(newer), older, create_checkpoint(older)
            )
        self.assertEqual("AUK009", caught.exception.rule_id)
        self.assertEqual("rollback", caught.exception.report["relation"])

    def test_fork_is_denied(self):
        previous, candidate = direct_pair(2, 5)
        forked = _build_catalog(
            fake_entries(5, fork_at=3),
            generation=2,
            previous_catalog_id=previous["catalog_id"],
        )
        with self.assertRaises(AuditCatalogConsistencyDenied) as caught:
            create_consistency_proof(
                candidate,
                create_checkpoint(candidate),
                forked,
                create_checkpoint(forked),
            )
        self.assertEqual("AUK010", caught.exception.rule_id)

    def test_generation_regression_is_denied(self):
        previous = catalog(2, 3, "a" * 64)
        candidate = _build_catalog(
            fake_entries(4), generation=3, previous_catalog_id=previous["catalog_id"]
        )
        with self.assertRaises(AuditCatalogConsistencyDenied) as caught:
            create_consistency_proof(
                previous,
                create_checkpoint(previous),
                candidate,
                create_checkpoint(candidate),
            )
        self.assertEqual("AUK011", caught.exception.rule_id)

    def test_direct_generation_with_wrong_predecessor_is_denied(self):
        previous = catalog(2, 1, ZERO_HASH)
        candidate = _build_catalog(
            fake_entries(4), generation=2, previous_catalog_id="f" * 64
        )
        with self.assertRaises(AuditCatalogConsistencyDenied) as caught:
            create_consistency_proof(
                previous,
                create_checkpoint(previous),
                candidate,
                create_checkpoint(candidate),
            )
        self.assertEqual("AUK010", caught.exception.rule_id)

    def test_rehashed_previous_frontier_tamper_is_rejected(self):
        previous, candidate = direct_pair()
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        proof["previous_frontier"][0]["hash"] = "f" * 64
        proof = reidentify(proof)
        with self.assertRaisesRegex(AuditCatalogConsistencyError, "previous Merkle root") as caught:
            validate_consistency_proof(proof)
        self.assertEqual("AUK006", caught.exception.rule_id)

    def test_rehashed_append_frontier_tamper_is_rejected(self):
        previous, candidate = direct_pair()
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        proof["append_frontier"][0]["hash"] = "f" * 64
        proof = reidentify(proof)
        with self.assertRaisesRegex(AuditCatalogConsistencyError, "candidate Merkle root") as caught:
            validate_consistency_proof(proof)
        self.assertEqual("AUK006", caught.exception.rule_id)

    def test_noncanonical_frontier_layout_is_rejected(self):
        previous, candidate = direct_pair()
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        proof["append_frontier"][0]["size"] = 1
        proof = reidentify(proof)
        with self.assertRaisesRegex(AuditCatalogConsistencyError, "canonical compact-range") as caught:
            validate_consistency_proof(proof)
        self.assertEqual("AUK005", caught.exception.rule_id)

    def test_wrong_previous_checkpoint_is_rejected(self):
        previous, candidate = direct_pair()
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        unrelated = create_checkpoint(catalog(1, 1, ZERO_HASH))
        with self.assertRaisesRegex(AuditCatalogConsistencyError, "references") as caught:
            proof_matches_checkpoints(proof, unrelated, create_checkpoint(candidate))
        self.assertEqual("AUK004", caught.exception.rule_id)

    def test_wrong_candidate_checkpoint_is_rejected(self):
        previous, candidate = direct_pair()
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        unrelated = create_checkpoint(catalog(6, 1, ZERO_HASH))
        with self.assertRaisesRegex(AuditCatalogConsistencyError, "references") as caught:
            proof_matches_checkpoints(proof, create_checkpoint(previous), unrelated)
        self.assertEqual("AUK004", caught.exception.rule_id)

    def test_noncanonical_proof_file_is_rejected(self):
        previous, candidate = direct_pair()
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(proof, indent=2) + "\n")
            with self.assertRaisesRegex(AuditCatalogConsistencyError, "canonically serialized"):
                load_consistency_proof(path)

    def test_duplicate_proof_key_is_rejected(self):
        previous, candidate = direct_pair()
        proof = create_consistency_proof(
            previous, create_checkpoint(previous), candidate, create_checkpoint(candidate)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            encoded = _canonical_bytes(proof).decode().rstrip("\n}")
            path.write_text(encoded + ',"consistency_id":"' + "0" * 64 + '"}\n')
            with self.assertRaisesRegex(AuditCatalogConsistencyError, "strict JSON"):
                load_consistency_proof(path)

    def test_cli_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous_path, previous_cp, candidate_path, candidate_cp, active = real_pair(root)
            previous = load_catalog(previous_path)
            candidate = load_catalog(candidate_path)
            output = root / "proof.json"
            output.write_text("reserved")
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main([
                    "prove", str(previous_path), str(previous_cp),
                    str(candidate_path), str(candidate_cp), str(output),
                    "--expected-previous-catalog-id", previous["catalog_id"],
                    "--expected-previous-checkpoint-id", create_checkpoint(previous)["checkpoint_id"],
                    "--expected-candidate-catalog-id", candidate["catalog_id"],
                    "--expected-candidate-checkpoint-id", create_checkpoint(candidate)["checkpoint_id"],
                    "--candidate-active", str(active),
                ])
        self.assertEqual(2, status)
        self.assertIn("AUK008", error.getvalue())

    @unittest.skipIf(os.name == "nt", "symlink creation requires additional Windows privileges")
    def test_symlink_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous_path, previous_cp, candidate_path, candidate_cp, active = real_pair(root)
            previous = load_catalog(previous_path)
            candidate = load_catalog(candidate_path)
            target = root / "target.json"
            target.write_text("reserved")
            output = root / "proof.json"
            output.symlink_to(target)
            status = main([
                "prove", str(previous_path), str(previous_cp),
                str(candidate_path), str(candidate_cp), str(output),
                "--expected-previous-catalog-id", previous["catalog_id"],
                "--expected-previous-checkpoint-id", create_checkpoint(previous)["checkpoint_id"],
                "--expected-candidate-catalog-id", candidate["catalog_id"],
                "--expected-candidate-checkpoint-id", create_checkpoint(candidate)["checkpoint_id"],
                "--candidate-active", str(active),
            ])
        self.assertEqual(2, status)

    def test_cli_prove_verify_and_rollback_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous_path, previous_cp_path, candidate_path, candidate_cp_path, active = real_pair(root)
            previous = load_catalog(previous_path)
            candidate = load_catalog(candidate_path)
            previous_cp = create_checkpoint(previous)
            candidate_cp = create_checkpoint(candidate)
            proof_path = root / "consistency.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                prove_status = main([
                    "prove", str(previous_path), str(previous_cp_path),
                    str(candidate_path), str(candidate_cp_path), str(proof_path),
                    "--expected-previous-catalog-id", previous["catalog_id"],
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--expected-candidate-catalog-id", candidate["catalog_id"],
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                    "--candidate-active", str(active), "--format", "json",
                ])
            created = json.loads(output.getvalue())
            previous_path.unlink()
            candidate_path.unlink()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verify_status = main([
                    "verify", str(proof_path), str(previous_cp_path), str(candidate_cp_path),
                    "--expected-previous-catalog-id", previous["catalog_id"],
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--expected-candidate-catalog-id", candidate["catalog_id"],
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                    "--format", "json",
                ])
            verified = json.loads(output.getvalue())
            previous_path.write_bytes(_canonical_bytes(previous))
            candidate_path.write_bytes(_canonical_bytes(candidate))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rollback_status = main([
                    "lineage", str(candidate_path), str(candidate_cp_path),
                    str(previous_path), str(previous_cp_path),
                    "--expected-previous-catalog-id", candidate["catalog_id"],
                    "--expected-previous-checkpoint-id", candidate_cp["checkpoint_id"],
                    "--expected-candidate-catalog-id", previous["catalog_id"],
                    "--expected-candidate-checkpoint-id", previous_cp["checkpoint_id"],
                    "--previous-active", str(active), "--format", "json",
                ])
            rollback = json.loads(output.getvalue())
        self.assertEqual((0, 0, 1), (prove_status, verify_status, rollback_status))
        self.assertEqual(created["consistency_id"], verified["consistency_id"])
        self.assertEqual("rollback", rollback["relation"])


if __name__ == "__main__":
    unittest.main()
