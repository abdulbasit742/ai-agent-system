import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import agent_system
from agent_audit import ZERO_HASH, _canonical_line, _record_hash
from agent_audit_segments import (
    AuditSegmentError,
    MANIFEST_FILE,
    SEGMENT_FILE,
    SCHEMA_FIELD,
    _canonical_json,
    _segment_id,
    inspect_segment_directory,
    main,
    rotate_audit,
    verify_segment_chain,
)

TIMESTAMP = "2026-07-16T00:00:00+00:00"


def append_event(path: Path, event: str = "operation-complete", value: int = 1) -> dict:
    return agent_system.append_audit(path, event, {"value": value}, timestamp=TIMESTAMP)


def legacy_record() -> dict:
    core = {
        "time": TIMESTAMP,
        "event": "legacy",
        "details": {"ok": True},
        "previous_hash": ZERO_HASH,
    }
    return {**core, "hash": _record_hash(ZERO_HASH, core)}


def load_manifest(directory: Path) -> dict:
    return json.loads((directory / MANIFEST_FILE).read_text())


def write_manifest(directory: Path, payload: dict) -> None:
    (directory / MANIFEST_FILE).write_bytes(_canonical_json(payload))


def reidentify(payload: dict) -> dict:
    core = dict(payload)
    core.pop("segment_id", None)
    return {**core, "segment_id": _segment_id(core)}


class AuditSegmentTests(unittest.TestCase):
    def test_rotate_seals_log_and_starts_linked_active_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "segments" / "0001"
            append_event(active)
            before = agent_system.inspect_audit(active, require_typed=True)
            result = rotate_audit(active, archive)
            sealed = inspect_segment_directory(archive)
            after = agent_system.inspect_audit(active, require_typed=True)
            first = json.loads(active.read_text().splitlines()[0])
        self.assertEqual(1, result["segment_index"])
        self.assertEqual(before["head_hash"], sealed["head_hash"])
        self.assertEqual(1, after["records"])
        self.assertEqual("audit-segment-start", first["event"])
        self.assertEqual(result["segment_id"], first["details"]["previous_segment_id"])
        self.assertEqual(result["segment_sha256"], first["details"]["previous_segment_sha256"])

    def test_two_rotations_form_complete_verified_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            first_dir = root / "segments" / "0001"
            second_dir = root / "segments" / "0002"
            append_event(active, value=1)
            first = rotate_audit(active, first_dir)
            append_event(active, value=2)
            second = rotate_audit(active, second_dir)
            report = verify_segment_chain(
                [first_dir, second_dir],
                active_path=active,
                expected_latest_segment_id=second["segment_id"],
            )
        self.assertTrue(report["valid"])
        self.assertEqual(2, report["segment_count"])
        self.assertEqual(first["segment_id"], report["segments"][1]["previous_segment_id"])
        self.assertEqual(second["segment_id"], report["latest_segment_id"])
        self.assertTrue(report["active"]["privacy_safe"])

    def test_latest_segment_pin_detects_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            rotate_audit(active, archive)
            with self.assertRaisesRegex(AuditSegmentError, "externally retained pin") as caught:
                verify_segment_chain([archive], expected_latest_segment_id="f" * 64)
        self.assertEqual("AUS007", caught.exception.rule_id)

    def test_segment_byte_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            rotate_audit(active, archive)
            with (archive / SEGMENT_FILE).open("ab") as handle:
                handle.write(b"x")
            with self.assertRaisesRegex(AuditSegmentError, "segment bytes") as caught:
                inspect_segment_directory(archive)
        self.assertEqual("AUS004", caught.exception.rule_id)

    def test_manifest_duplicate_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            rotate_audit(active, archive)
            manifest = (archive / MANIFEST_FILE).read_text().rstrip("\n}")
            (archive / MANIFEST_FILE).write_text(manifest + ',"segment_id":"' + "0" * 64 + '"}\n')
            with self.assertRaisesRegex(AuditSegmentError, "strict JSON"):
                inspect_segment_directory(archive)

    def test_noncanonical_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            rotate_audit(active, archive)
            payload = load_manifest(archive)
            (archive / MANIFEST_FILE).write_text(json.dumps(payload, indent=2) + "\n")
            with self.assertRaisesRegex(AuditSegmentError, "canonically serialized"):
                inspect_segment_directory(archive)

    def test_rehashed_manifest_metadata_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            rotate_audit(active, archive)
            payload = load_manifest(archive)
            payload["records"] += 1
            write_manifest(archive, reidentify(payload))
            with self.assertRaisesRegex(AuditSegmentError, "records") as caught:
                inspect_segment_directory(archive)
        self.assertEqual("AUS004", caught.exception.rule_id)

    def test_rehashed_manifest_continuity_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            first_dir = root / "0001"
            second_dir = root / "0002"
            append_event(active)
            rotate_audit(active, first_dir)
            append_event(active, value=2)
            rotate_audit(active, second_dir)
            payload = load_manifest(second_dir)
            payload["previous_segment_id"] = "f" * 64
            write_manifest(second_dir, reidentify(payload))
            with self.assertRaisesRegex(AuditSegmentError, "continuity ID") as caught:
                verify_segment_chain([first_dir, second_dir])
        self.assertEqual("AUS005", caught.exception.rule_id)

    def test_active_continuity_tamper_is_rejected_even_with_valid_record_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            rotate_audit(active, archive)
            record = json.loads(active.read_text())
            record["details"]["previous_records"] += 1
            core = dict(record)
            core.pop("hash")
            record["hash"] = _record_hash(record["previous_hash"], core)
            active.write_bytes(_canonical_line(record))
            self.assertTrue(agent_system.inspect_audit(active, require_typed=True)["valid"])
            with self.assertRaisesRegex(AuditSegmentError, "active log") as caught:
                verify_segment_chain([archive], active_path=active)
        self.assertEqual("AUS006", caught.exception.rule_id)

    def test_empty_log_cannot_be_rotated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(AuditSegmentError, "non-empty") as caught:
                rotate_audit(root / "missing.jsonl", root / "0001")
        self.assertEqual("AUS008", caught.exception.rule_id)

    def test_untyped_log_cannot_be_rotated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            active.write_bytes(_canonical_line(legacy_record()))
            with self.assertRaisesRegex(AuditSegmentError, "source audit log") as caught:
                rotate_audit(active, root / "0001")
        self.assertEqual("AUS002", caught.exception.rule_id)

    def test_corrupt_log_cannot_be_rotated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            active.write_bytes(b'{"partial"')
            before = active.read_bytes()
            with self.assertRaises(AuditSegmentError):
                rotate_audit(active, root / "0001")
            self.assertEqual(before, active.read_bytes())

    def test_existing_output_refuses_rotation_without_mutating_active(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            before = active.read_bytes()
            archive.mkdir()
            with self.assertRaisesRegex(AuditSegmentError, "must not already exist") as caught:
                rotate_audit(active, archive)
            self.assertEqual(before, active.read_bytes())
        self.assertEqual("AUS001", caught.exception.rule_id)

    def test_expected_source_pins_are_enforced_before_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            append_event(active)
            report = agent_system.inspect_audit(active, require_typed=True)
            result = rotate_audit(
                active,
                root / "0001",
                expected_head=report["head_hash"],
                expected_records=1,
            )
        self.assertEqual(1, result["sealed_records"])

    def test_wrong_source_pin_refuses_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            append_event(active)
            before = active.read_bytes()
            with self.assertRaises(AuditSegmentError):
                rotate_audit(active, root / "0001", expected_head="f" * 64)
            self.assertEqual(before, active.read_bytes())
            self.assertFalse((root / "0001").exists())

    def test_chain_requires_complete_indexes_from_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            first_dir = root / "0001"
            second_dir = root / "0002"
            append_event(active)
            rotate_audit(active, first_dir)
            append_event(active, value=2)
            rotate_audit(active, second_dir)
            with self.assertRaisesRegex(AuditSegmentError, "complete sequence") as caught:
                verify_segment_chain([second_dir])
        self.assertEqual("AUS005", caught.exception.rule_id)

    def test_cli_rotate_and_verify_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "rotate", "--path", str(active), "--output-dir", str(archive), "--format", "json"
                ])
            rotated = json.loads(output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verify_status = main([
                    "verify", str(archive), "--active", str(active),
                    "--expected-latest-segment-id", rotated["segment_id"], "--format", "json"
                ])
            verified = json.loads(output.getvalue())
        self.assertEqual(0, status)
        self.assertEqual(0, verify_status)
        self.assertTrue(verified["valid"])

    def test_cli_reports_stable_rule_on_error(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            status = main(["verify", "missing"])
        self.assertEqual(2, status)
        self.assertIn("AUS001", error.getvalue())

    @unittest.skipIf(os.name == "nt", "symlink creation requires additional Windows privileges")
    def test_symlink_segment_data_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "audit.jsonl"
            archive = root / "0001"
            append_event(active)
            rotate_audit(active, archive)
            target = root / "target.jsonl"
            (archive / SEGMENT_FILE).replace(target)
            (archive / SEGMENT_FILE).symlink_to(target)
            with self.assertRaisesRegex(AuditSegmentError, "non-symlink") as caught:
                inspect_segment_directory(archive)
        self.assertEqual("AUS001", caught.exception.rule_id)


if __name__ == "__main__":
    unittest.main()
