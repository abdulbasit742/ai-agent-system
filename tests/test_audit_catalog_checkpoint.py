import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import agent_system
from agent_audit import ZERO_HASH
from agent_audit_catalog import _build_catalog, initialize_catalog, load_catalog
from agent_audit_checkpoint import (
    AuditCatalogCheckpointError,
    MAX_CHECKPOINT_BYTES,
    _canonical_bytes,
    _identifier,
    checkpoint_matches_catalog,
    create_checkpoint,
    create_proof,
    load_checkpoint,
    load_proof,
    main,
    proof_matches_checkpoint,
    proof_matches_segment_directory,
    validate_checkpoint,
    validate_proof,
)
from agent_audit_segments import SEGMENT_FILE, rotate_audit


def fake_entry(index: int, previous: str) -> dict:
    token = f"{index:064x}"
    return {
        "segment_index": index,
        "directory": f"segment-{index:04d}",
        "segment_id": token,
        "previous_segment_id": previous,
        "manifest_sha256": f"{index + 100:064x}",
        "segment_sha256": f"{index + 200:064x}",
        "head_hash": f"{index + 300:064x}",
        "records": index,
        "bytes": index * 100,
    }


def fake_catalog(size: int = 3) -> dict:
    entries = []
    previous = ZERO_HASH
    for index in range(1, size + 1):
        entry = fake_entry(index, previous)
        entries.append(entry)
        previous = entry["segment_id"]
    return _build_catalog(entries, generation=1, previous_catalog_id=ZERO_HASH)


def reidentify_checkpoint(payload: dict) -> dict:
    core = dict(payload)
    core.pop("checkpoint_id", None)
    return {
        **core,
        "checkpoint_id": _identifier(b"audit-catalog-checkpoint-v1", core),
    }


def reidentify_proof(payload: dict) -> dict:
    core = dict(payload)
    core.pop("proof_id", None)
    return {
        **core,
        "proof_id": _identifier(b"audit-catalog-inclusion-proof-v1", core),
    }


def append_event(path: Path, value: int) -> None:
    agent_system.append_audit(path, "operation-complete", {"value": value})


def real_catalog(root: Path, count: int = 3) -> tuple[Path, Path, list[Path]]:
    archive = root / "segments"
    active = root / "active.jsonl"
    archive.mkdir()
    directories = []
    for index in range(1, count + 1):
        append_event(active, index)
        directory = archive / f"segment-{index:04d}"
        rotate_audit(active, directory)
        directories.append(directory)
    catalog = archive / "catalog.json"
    initialize_catalog(catalog, active_path=active)
    return catalog, active, directories


class AuditCatalogCheckpointTests(unittest.TestCase):
    def test_checkpoint_is_deterministic_and_catalog_bound(self):
        catalog = fake_catalog(3)
        first = create_checkpoint(catalog)
        second = create_checkpoint(json.loads(json.dumps(catalog)))
        self.assertEqual(first, second)
        self.assertEqual(catalog["catalog_id"], first["catalog"]["catalog_id"])
        self.assertEqual(3, first["catalog"]["segment_count"])
        self.assertEqual(64, len(first["merkle"]["root"]))

    def test_single_entry_checkpoint_uses_leaf_root(self):
        checkpoint = create_checkpoint(fake_catalog(1))
        proof = create_proof(fake_catalog(1), checkpoint, segment_index=1)
        self.assertEqual([], proof["audit_path"])
        self.assertEqual(checkpoint["merkle"]["root"], proof["checkpoint"]["merkle_root"])

    def test_odd_tree_first_middle_and_last_proofs_validate(self):
        catalog = fake_catalog(5)
        checkpoint = create_checkpoint(catalog)
        for index in (1, 3, 5):
            with self.subTest(index=index):
                proof = create_proof(catalog, checkpoint, segment_index=index)
                self.assertEqual(index, validate_proof(proof)["entry"]["segment_index"])

    def test_proof_can_select_segment_by_id(self):
        catalog = fake_catalog(4)
        checkpoint = create_checkpoint(catalog)
        wanted = catalog["segments"][2]["segment_id"]
        proof = create_proof(catalog, checkpoint, segment_id=wanted)
        self.assertEqual(wanted, proof["entry"]["segment_id"])

    def test_checkpoint_id_tamper_is_rejected(self):
        checkpoint = create_checkpoint(fake_catalog())
        checkpoint["checkpoint_id"] = "f" * 64
        with self.assertRaisesRegex(AuditCatalogCheckpointError, "checkpoint ID") as caught:
            validate_checkpoint(checkpoint)
        self.assertEqual("AUP003", caught.exception.rule_id)

    def test_checkpoint_rehashed_catalog_reference_drift_is_rejected_against_catalog(self):
        catalog = fake_catalog(3)
        checkpoint = create_checkpoint(catalog)
        checkpoint["catalog"]["total_records"] += 1
        checkpoint = reidentify_checkpoint(checkpoint)
        with self.assertRaisesRegex(AuditCatalogCheckpointError, "canonical catalog") as caught:
            checkpoint_matches_catalog(checkpoint, catalog)
        self.assertEqual("AUP004", caught.exception.rule_id)

    def test_rehashed_audit_path_tamper_is_rejected(self):
        catalog = fake_catalog(4)
        checkpoint = create_checkpoint(catalog)
        proof = create_proof(catalog, checkpoint, segment_index=2)
        proof["audit_path"][0] = "f" * 64
        proof = reidentify_proof(proof)
        with self.assertRaisesRegex(AuditCatalogCheckpointError, "Merkle root") as caught:
            validate_proof(proof)
        self.assertEqual("AUP006", caught.exception.rule_id)

    def test_extra_audit_path_hash_is_rejected(self):
        catalog = fake_catalog(2)
        checkpoint = create_checkpoint(catalog)
        proof = create_proof(catalog, checkpoint, segment_index=1)
        proof["audit_path"].append("f" * 64)
        proof = reidentify_proof(proof)
        with self.assertRaisesRegex(AuditCatalogCheckpointError, "extra hashes"):
            validate_proof(proof)

    def test_proof_for_different_checkpoint_is_rejected(self):
        first_catalog = fake_catalog(2)
        second_catalog = fake_catalog(3)
        first_checkpoint = create_checkpoint(first_catalog)
        second_checkpoint = create_checkpoint(second_catalog)
        proof = create_proof(first_catalog, first_checkpoint, segment_index=1)
        with self.assertRaisesRegex(AuditCatalogCheckpointError, "supplied checkpoint") as caught:
            proof_matches_checkpoint(proof, second_checkpoint)
        self.assertEqual("AUP006", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_missing_segment_selection_is_denied(self):
        catalog = fake_catalog(2)
        checkpoint = create_checkpoint(catalog)
        with self.assertRaisesRegex(AuditCatalogCheckpointError, "not present") as caught:
            create_proof(catalog, checkpoint, segment_index=3)
        self.assertEqual("AUP008", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_noncanonical_checkpoint_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_text(json.dumps(create_checkpoint(fake_catalog()), indent=2) + "\n")
            with self.assertRaisesRegex(AuditCatalogCheckpointError, "canonically serialized"):
                load_checkpoint(path)

    def test_duplicate_checkpoint_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            payload = _canonical_bytes(create_checkpoint(fake_catalog())).decode().rstrip("\n}")
            path.write_text(payload + ',"checkpoint_id":"' + "0" * 64 + '"}\n')
            with self.assertRaisesRegex(AuditCatalogCheckpointError, "strict JSON"):
                load_checkpoint(path)

    def test_checkpoint_size_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_bytes(b"x" * (MAX_CHECKPOINT_BYTES + 1))
            with self.assertRaisesRegex(AuditCatalogCheckpointError, "size") as caught:
                load_checkpoint(path)
        self.assertEqual("AUP010", caught.exception.rule_id)

    def test_cli_refuses_checkpoint_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path, active, _ = real_catalog(root, 1)
            catalog = load_catalog(catalog_path)
            output = root / "checkpoint.json"
            output.write_text("reserved")
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main([
                    "create", str(catalog_path), str(output),
                    "--expected-catalog-id", catalog["catalog_id"],
                    "--active", str(active),
                ])
        self.assertEqual(2, status)
        self.assertIn("AUP001", error.getvalue())

    @unittest.skipIf(os.name == "nt", "symlink creation requires additional Windows privileges")
    def test_symlink_checkpoint_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path, active, _ = real_catalog(root, 1)
            catalog = load_catalog(catalog_path)
            target = root / "target.json"
            target.write_text("reserved")
            output = root / "checkpoint.json"
            output.symlink_to(target)
            status = main([
                "create", str(catalog_path), str(output),
                "--expected-catalog-id", catalog["catalog_id"],
                "--active", str(active),
            ])
        self.assertEqual(2, status)

    def test_proof_matches_real_sealed_segment_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path, _, segments = real_catalog(root, 2)
            catalog = load_catalog(catalog_path)
            checkpoint = create_checkpoint(catalog)
            proof = create_proof(catalog, checkpoint, segment_index=2)
            actual = proof_matches_segment_directory(proof, segments[1])
        self.assertEqual(proof["entry"], actual)

    def test_segment_byte_tamper_is_rejected_against_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path, _, segments = real_catalog(root, 1)
            catalog = load_catalog(catalog_path)
            checkpoint = create_checkpoint(catalog)
            proof = create_proof(catalog, checkpoint, segment_index=1)
            with (segments[0] / SEGMENT_FILE).open("ab") as handle:
                handle.write(b"x")
            with self.assertRaisesRegex(AuditCatalogCheckpointError, "independent verification") as caught:
                proof_matches_segment_directory(proof, segments[0])
        self.assertEqual("AUP009", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_cli_create_verify_prove_and_verify_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path, active, segments = real_catalog(root, 3)
            catalog = load_catalog(catalog_path)
            checkpoint_path = root / "checkpoint.json"
            proof_path = root / "proof.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                create_status = main([
                    "create", str(catalog_path), str(checkpoint_path),
                    "--expected-catalog-id", catalog["catalog_id"],
                    "--active", str(active), "--format", "json",
                ])
            created = json.loads(output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verify_status = main([
                    "verify", str(checkpoint_path),
                    "--expected-checkpoint-id", created["checkpoint_id"],
                    "--catalog", str(catalog_path),
                    "--expected-catalog-id", catalog["catalog_id"],
                    "--active", str(active), "--format", "json",
                ])
            self.assertTrue(json.loads(output.getvalue())["valid"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                prove_status = main([
                    "prove", str(catalog_path), str(checkpoint_path), str(proof_path),
                    "--expected-catalog-id", catalog["catalog_id"],
                    "--expected-checkpoint-id", created["checkpoint_id"],
                    "--active", str(active), "--segment-index", "2", "--format", "json",
                ])
            proved = json.loads(output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                proof_status = main([
                    "verify-proof", str(proof_path), str(checkpoint_path),
                    "--expected-checkpoint-id", created["checkpoint_id"],
                    "--segment-dir", str(segments[1]), "--format", "json",
                ])
            verified = json.loads(output.getvalue())
        self.assertEqual((0, 0, 0, 0), (create_status, verify_status, prove_status, proof_status))
        self.assertEqual(proved["proof_id"], verified["proof_id"])
        self.assertTrue(verified["segment_verified"])

    def test_cli_wrong_checkpoint_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint_path = root / "checkpoint.json"
            checkpoint_path.write_bytes(_canonical_bytes(create_checkpoint(fake_catalog())))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main([
                    "verify", str(checkpoint_path),
                    "--expected-checkpoint-id", "f" * 64,
                ])
        self.assertEqual(1, status)
        self.assertIn("AUP007", error.getvalue())

    def test_cli_malformed_checkpoint_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_text("{")
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main([
                    "verify", str(path),
                    "--expected-checkpoint-id", "f" * 64,
                ])
        self.assertEqual(2, status)
        self.assertIn("AUP002", error.getvalue())


if __name__ == "__main__":
    unittest.main()
