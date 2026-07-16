import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import agent_system
from agent_audit import ZERO_HASH
from agent_audit_bundle import (
    AuditEvidenceBundleError,
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    _bundle_id,
    _canonical_bytes,
    create_bundle,
    load_manifest,
    main,
    validate_manifest,
    verify_bundle,
)
from agent_audit_catalog import _build_catalog, initialize_catalog, load_catalog
from agent_audit_checkpoint import create_checkpoint, create_proof
from agent_audit_consistency import create_consistency_proof
from agent_audit_segments import SEGMENT_FILE, rotate_audit


def fake_entry(index: int, previous: str) -> dict:
    return {
        "segment_index": index,
        "directory": f"segment-{index:04d}",
        "segment_id": f"{index:064x}",
        "previous_segment_id": previous,
        "manifest_sha256": f"{index + 100:064x}",
        "segment_sha256": f"{index + 200:064x}",
        "head_hash": f"{index + 300:064x}",
        "records": index,
        "bytes": index * 100,
    }


def fake_catalog(size: int, *, generation: int = 1, previous_catalog_id: str = ZERO_HASH) -> dict:
    entries = []
    previous = ZERO_HASH
    for index in range(1, size + 1):
        entry = fake_entry(index, previous)
        entries.append(entry)
        previous = entry["segment_id"]
    return _build_catalog(entries, generation=generation, previous_catalog_id=previous_catalog_id)


def descendant(previous: dict, size: int) -> dict:
    entries = [dict(item) for item in previous["segments"]]
    prior = entries[-1]["segment_id"]
    for index in range(len(entries) + 1, size + 1):
        entry = fake_entry(index, prior)
        entries.append(entry)
        prior = entry["segment_id"]
    return _build_catalog(
        entries,
        generation=previous["generation"] + 1,
        previous_catalog_id=previous["catalog_id"],
    )


def write_payload(path: Path, payload: dict) -> None:
    path.write_bytes(_canonical_bytes(payload))


def snapshot_inputs(root: Path, size: int = 3, indexes: tuple[int, ...] = (1, 3)):
    catalog = fake_catalog(size)
    checkpoint = create_checkpoint(catalog)
    checkpoint_path = root / "checkpoint.json"
    write_payload(checkpoint_path, checkpoint)
    proof_paths = []
    for index in indexes:
        proof = create_proof(catalog, checkpoint, segment_index=index)
        path = root / f"proof-{index}.json"
        write_payload(path, proof)
        proof_paths.append(path)
    return catalog, checkpoint, checkpoint_path, proof_paths


def transition_inputs(root: Path):
    previous_catalog = fake_catalog(1)
    candidate_catalog = descendant(previous_catalog, 3)
    previous_checkpoint = create_checkpoint(previous_catalog)
    candidate_checkpoint = create_checkpoint(candidate_catalog)
    consistency = create_consistency_proof(
        previous_catalog,
        previous_checkpoint,
        candidate_catalog,
        candidate_checkpoint,
    )
    previous_path = root / "previous.json"
    candidate_path = root / "candidate.json"
    consistency_path = root / "consistency.json"
    write_payload(previous_path, previous_checkpoint)
    write_payload(candidate_path, candidate_checkpoint)
    write_payload(consistency_path, consistency)
    proof_paths = []
    for index in (1, 3):
        proof = create_proof(candidate_catalog, candidate_checkpoint, segment_index=index)
        path = root / f"proof-{index}.json"
        write_payload(path, proof)
        proof_paths.append(path)
    return (
        previous_checkpoint,
        candidate_checkpoint,
        previous_path,
        candidate_path,
        consistency_path,
        proof_paths,
    )


def append_event(path: Path, value: int) -> None:
    agent_system.append_audit(path, "operation-complete", {"value": value})


def real_inputs(root: Path):
    archive = root / "segments"
    active = root / "active.jsonl"
    archive.mkdir()
    directories = []
    for index in range(1, 3):
        append_event(active, index)
        directory = archive / f"segment-{index:04d}"
        rotate_audit(active, directory)
        directories.append(directory)
    catalog_path = archive / "catalog.json"
    initialize_catalog(catalog_path, active_path=active)
    catalog = load_catalog(catalog_path)
    checkpoint = create_checkpoint(catalog)
    proof = create_proof(catalog, checkpoint, segment_index=2)
    checkpoint_path = root / "checkpoint.json"
    proof_path = root / "proof.json"
    write_payload(checkpoint_path, checkpoint)
    write_payload(proof_path, proof)
    return archive, checkpoint, checkpoint_path, proof_path, directories


class AuditEvidenceBundleTests(unittest.TestCase):
    def test_snapshot_bundle_is_deterministic_and_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proof_paths = snapshot_inputs(root)
            first = create_bundle(root / "bundle-one", checkpoint_path, checkpoint["checkpoint_id"], proof_paths)
            second = create_bundle(root / "bundle-two", checkpoint_path, checkpoint["checkpoint_id"], proof_paths)
            report = verify_bundle(
                root / "bundle-one",
                expected_bundle_id=first["bundle_id"],
                expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
            )
        self.assertEqual(first, second)
        self.assertTrue(report["valid"])
        self.assertEqual("snapshot", report["bundle_type"])
        self.assertEqual(2, report["proof_count"])
        self.assertEqual(0, report["segment_count"])

    def test_transition_bundle_binds_consistency_and_previous_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, candidate, previous_path, candidate_path, consistency_path, proofs = transition_inputs(root)
            manifest = create_bundle(
                root / "bundle",
                candidate_path,
                candidate["checkpoint_id"],
                proofs,
                previous_checkpoint_path=previous_path,
                expected_previous_checkpoint_id=previous["checkpoint_id"],
                consistency_path=consistency_path,
            )
            report = verify_bundle(
                root / "bundle",
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=candidate["checkpoint_id"],
                expected_previous_checkpoint_id=previous["checkpoint_id"],
            )
        self.assertEqual("transition", report["bundle_type"])
        self.assertEqual("right-descendant", report["consistency"]["relation"])
        self.assertTrue(report["consistency"]["direct_predecessor_verified"])

    def test_real_sealed_segments_are_copied_and_reverified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, checkpoint, checkpoint_path, proof_path, _ = real_inputs(root)
            manifest = create_bundle(
                root / "bundle",
                checkpoint_path,
                checkpoint["checkpoint_id"],
                [proof_path],
                segment_root=archive,
            )
            report = verify_bundle(
                root / "bundle",
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
            )
        self.assertEqual(1, report["segment_count"])
        self.assertTrue(manifest["entries"][0]["segment_included"])

    def test_wrong_bundle_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], proofs)
            with self.assertRaisesRegex(AuditEvidenceBundleError, "externally retained") as caught:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id="f" * 64,
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                )
        self.assertEqual("AUB003", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_wrong_candidate_checkpoint_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            manifest = create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], proofs)
            with self.assertRaisesRegex(AuditEvidenceBundleError, "candidate checkpoint") as caught:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id="f" * 64,
                )
        self.assertEqual("AUB004", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_transition_verification_requires_previous_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, candidate, previous_path, candidate_path, consistency_path, proofs = transition_inputs(root)
            manifest = create_bundle(
                root / "bundle",
                candidate_path,
                candidate["checkpoint_id"],
                proofs,
                previous_checkpoint_path=previous_path,
                expected_previous_checkpoint_id=previous["checkpoint_id"],
                consistency_path=consistency_path,
            )
            with self.assertRaisesRegex(AuditEvidenceBundleError, "previous checkpoint pin") as caught:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=candidate["checkpoint_id"],
                )
        self.assertEqual("AUB004", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_snapshot_rejects_previous_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            manifest = create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], proofs)
            with self.assertRaisesRegex(AuditEvidenceBundleError, "does not accept") as caught:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                    expected_previous_checkpoint_id="f" * 64,
                )
        self.assertEqual("AUB012", caught.exception.rule_id)

    def test_partial_transition_arguments_are_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            output = root / "bundle"
            with self.assertRaisesRegex(AuditEvidenceBundleError, "requires previous") as caught:
                create_bundle(
                    output,
                    checkpoint_path,
                    checkpoint["checkpoint_id"],
                    proofs,
                    previous_checkpoint_path=checkpoint_path,
                )
            self.assertFalse(output.exists())
        self.assertEqual("AUB012", caught.exception.rule_id)

    def test_duplicate_proof_selection_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root, indexes=(1,))
            with self.assertRaisesRegex(AuditEvidenceBundleError, "duplicate segment_index") as caught:
                create_bundle(
                    root / "bundle",
                    checkpoint_path,
                    checkpoint["checkpoint_id"],
                    [proofs[0], proofs[0]],
                )
        self.assertEqual("AUB009", caught.exception.rule_id)

    def test_proof_for_different_checkpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_catalog, first_checkpoint, _, _ = snapshot_inputs(root / "first", indexes=(1,)) if False else (None, None, None, None)
            catalog = fake_catalog(2)
            other_catalog = fake_catalog(3)
            checkpoint = create_checkpoint(catalog)
            other_checkpoint = create_checkpoint(other_catalog)
            checkpoint_path = root / "checkpoint.json"
            proof_path = root / "proof.json"
            write_payload(checkpoint_path, checkpoint)
            write_payload(proof_path, create_proof(other_catalog, other_checkpoint, segment_index=1))
            with self.assertRaisesRegex(AuditEvidenceBundleError, "inclusion proof") as caught:
                create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], [proof_path])
        self.assertEqual("AUB006", caught.exception.rule_id)

    def test_consistency_for_different_candidate_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, candidate, previous_path, candidate_path, _, proofs = transition_inputs(root)
            other_catalog = descendant(fake_catalog(1), 2)
            other_checkpoint = create_checkpoint(other_catalog)
            wrong = create_consistency_proof(
                fake_catalog(1),
                create_checkpoint(fake_catalog(1)),
                other_catalog,
                other_checkpoint,
            )
            wrong_path = root / "wrong-consistency.json"
            write_payload(wrong_path, wrong)
            with self.assertRaisesRegex(AuditEvidenceBundleError, "consistency proof") as caught:
                create_bundle(
                    root / "bundle",
                    candidate_path,
                    candidate["checkpoint_id"],
                    proofs,
                    previous_checkpoint_path=previous_path,
                    expected_previous_checkpoint_id=previous["checkpoint_id"],
                    consistency_path=wrong_path,
                )
        self.assertEqual("AUB005", caught.exception.rule_id)

    def test_extra_file_is_rejected_by_exact_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            manifest = create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], proofs)
            (root / "bundle" / "extra.txt").write_text("extra")
            with self.assertRaisesRegex(AuditEvidenceBundleError, "boundary mismatch") as caught:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                )
        self.assertEqual("AUB008", caught.exception.rule_id)

    def test_modified_proof_is_rejected_by_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            manifest = create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], proofs)
            proof_file = root / "bundle" / manifest["entries"][0]["proof_path"]
            proof_file.write_bytes(proof_file.read_bytes() + b" ")
            with self.assertRaisesRegex(AuditEvidenceBundleError, "checksum mismatch") as caught:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                )
        self.assertEqual("AUB008", caught.exception.rule_id)

    def test_modified_segment_is_rejected_by_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, checkpoint, checkpoint_path, proof_path, _ = real_inputs(root)
            manifest = create_bundle(
                root / "bundle",
                checkpoint_path,
                checkpoint["checkpoint_id"],
                [proof_path],
                segment_root=archive,
            )
            entry = manifest["entries"][0]
            with (root / "bundle" / "segments" / entry["directory"] / SEGMENT_FILE).open("ab") as handle:
                handle.write(b"x")
            with self.assertRaisesRegex(AuditEvidenceBundleError, "checksum mismatch") as caught:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                )
        self.assertEqual("AUB008", caught.exception.rule_id)

    def test_noncanonical_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], proofs)
            manifest_path = root / "bundle" / MANIFEST_NAME
            payload = json.loads(manifest_path.read_text())
            manifest_path.write_text(json.dumps(payload, indent=2) + "\n")
            with self.assertRaisesRegex(AuditEvidenceBundleError, "canonically serialized") as caught:
                load_manifest(manifest_path)
        self.assertEqual("AUB002", caught.exception.rule_id)

    def test_duplicate_manifest_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text('{"bundle_version":1,"bundle_version":1}\n')
            with self.assertRaisesRegex(AuditEvidenceBundleError, "strict JSON") as caught:
                load_manifest(path)
        self.assertEqual("AUB002", caught.exception.rule_id)

    def test_reidentified_manifest_duplicate_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            manifest = create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], proofs)
            payload = json.loads(json.dumps(manifest))
            payload["entries"].append(dict(payload["entries"][0]))
            payload["entries"].sort(key=lambda item: item["segment_index"])
            payload["bundle_id"] = _bundle_id(payload)
            with self.assertRaisesRegex(AuditEvidenceBundleError, "duplicate segment_index") as caught:
                validate_manifest(payload)
        self.assertEqual("AUB009", caught.exception.rule_id)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            output = root / "bundle"
            output.mkdir()
            marker = output / "marker"
            marker.write_text("reserved")
            with self.assertRaisesRegex(AuditEvidenceBundleError, "must not already exist") as caught:
                create_bundle(output, checkpoint_path, checkpoint["checkpoint_id"], proofs)
            self.assertEqual("reserved", marker.read_text())
        self.assertEqual("AUB011", caught.exception.rule_id)

    @unittest.skipIf(os.name == "nt", "symlink creation requires additional Windows privileges")
    def test_symlink_inside_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root)
            manifest = create_bundle(root / "bundle", checkpoint_path, checkpoint["checkpoint_id"], proofs)
            target = root / "outside.txt"
            target.write_text("outside")
            (root / "bundle" / "link.txt").symlink_to(target)
            with self.assertRaisesRegex(AuditEvidenceBundleError, "symlink") as caught:
                verify_bundle(
                    root / "bundle",
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                )
        self.assertEqual("AUB001", caught.exception.rule_id)

    def test_cli_create_verify_and_wrong_pin_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, checkpoint_path, proofs = snapshot_inputs(root, indexes=(1,))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                create_status = main([
                    "create", str(root / "bundle"),
                    "--checkpoint", str(checkpoint_path),
                    "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                    "--proof", str(proofs[0]),
                    "--format", "json",
                ])
            created = json.loads(output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verify_status = main([
                    "verify", str(root / "bundle"),
                    "--expected-bundle-id", created["bundle_id"],
                    "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                    "--format", "json",
                ])
            verified = json.loads(output.getvalue())
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                wrong_status = main([
                    "verify", str(root / "bundle"),
                    "--expected-bundle-id", "f" * 64,
                    "--expected-checkpoint-id", checkpoint["checkpoint_id"],
                    "--format", "json",
                ])
        self.assertEqual((0, 0, 1), (create_status, verify_status, wrong_status))
        self.assertTrue(verified["valid"])
        self.assertIn("AUB003", error.getvalue())


if __name__ == "__main__":
    unittest.main()
