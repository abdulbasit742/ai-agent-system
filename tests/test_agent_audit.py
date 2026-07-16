import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import agent_system
from agent_audit import (
    AuditError,
    ZERO_HASH,
    _canonical_line,
    _record_hash,
    append_audit,
    inspect_audit,
    recover_audit,
    verify_audit,
)


TIMESTAMP = "2026-07-16T00:00:00+00:00"


def legacy_record(event: str = "legacy", details: dict | None = None) -> dict:
    core = {
        "time": TIMESTAMP,
        "event": event,
        "details": details or {"ok": True},
        "previous_hash": ZERO_HASH,
    }
    return {**core, "hash": _record_hash(ZERO_HASH, core)}


def mutate_record(path: Path, index: int, change, *, recompute: bool = True) -> None:
    lines = path.read_bytes().splitlines(keepends=True)
    record = json.loads(lines[index])
    change(record)
    if recompute:
        core = dict(record)
        core.pop("hash")
        record["hash"] = _record_hash(record["previous_hash"], core)
    lines[index] = _canonical_line(record)
    path.write_bytes(b"".join(lines))


class AuditLogTests(unittest.TestCase):
    def test_missing_log_is_valid_empty_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            report = inspect_audit(Path(directory) / "missing.jsonl")
        self.assertTrue(report["valid"])
        self.assertEqual(0, report["records"])
        self.assertEqual(ZERO_HASH, report["head_hash"])

    def test_append_creates_versioned_sequence_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            first = append_audit(path, "scan", {"active": 0}, timestamp=TIMESTAMP)
            second = append_audit(path, "guard", {"allowed": True}, timestamp=TIMESTAMP)
            report = inspect_audit(path)
        self.assertEqual(1, first["sequence"])
        self.assertEqual(2, second["sequence"])
        self.assertEqual(first["hash"], second["previous_hash"])
        self.assertTrue(report["valid"])
        self.assertEqual(2, report["versioned_records"])

    def test_legacy_chain_can_be_verified_and_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(_canonical_line(legacy_record()))
            appended = append_audit(path, "new", {"ok": True}, timestamp=TIMESTAMP)
            report = inspect_audit(path)
        self.assertEqual(2, appended["sequence"])
        self.assertEqual(1, report["legacy_records"])
        self.assertEqual(1, report["versioned_records"])

    def test_partial_final_record_reports_recoverable_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            valid_bytes = len(path.read_bytes())
            with path.open("ab") as handle:
                handle.write(b'{"partial"')
            report = inspect_audit(path)
        self.assertFalse(report["valid"])
        self.assertEqual("AUD003", report["error"]["rule_id"])
        self.assertEqual(valid_bytes, report["recoverable_prefix"]["bytes"])

    def test_blank_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(b"\n")
            report = inspect_audit(path)
        self.assertEqual("AUD005", report["error"]["rule_id"])

    def test_invalid_utf8_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(b"\xff\n")
            report = inspect_audit(path)
        self.assertEqual("AUD006", report["error"]["rule_id"])

    def test_duplicate_json_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text('{"event":"a","event":"b"}\n', encoding="utf-8")
            report = inspect_audit(path)
        self.assertEqual("AUD007", report["error"]["rule_id"])

    def test_unreviewed_record_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            record = legacy_record()
            record["extra"] = True
            path.write_bytes(_canonical_line(record))
            report = inspect_audit(path)
        self.assertEqual("AUD008", report["error"]["rule_id"])

    def test_sequence_mismatch_is_rejected_before_hash_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            mutate_record(path, 0, lambda record: record.__setitem__("sequence", 2))
            report = inspect_audit(path)
        self.assertEqual("AUD010", report["error"]["rule_id"])

    def test_non_utc_timestamp_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            mutate_record(path, 0, lambda record: record.__setitem__("time", "2026-07-16T01:00:00+01:00"))
            report = inspect_audit(path)
        self.assertEqual("AUD011", report["error"]["rule_id"])

    def test_control_character_event_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            mutate_record(path, 0, lambda record: record.__setitem__("event", "bad\nevent"))
            report = inspect_audit(path)
        self.assertEqual("AUD012", report["error"]["rule_id"])

    def test_non_object_details_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            mutate_record(path, 0, lambda record: record.__setitem__("details", []))
            report = inspect_audit(path)
        self.assertEqual("AUD013", report["error"]["rule_id"])

    def test_malformed_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            mutate_record(path, 0, lambda record: record.__setitem__("hash", "bad"), recompute=False)
            report = inspect_audit(path)
        self.assertEqual("AUD014", report["error"]["rule_id"])

    def test_previous_hash_break_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            append_audit(path, "two", {}, timestamp=TIMESTAMP)
            mutate_record(path, 1, lambda record: record.__setitem__("previous_hash", "f" * 64))
            report = inspect_audit(path)
        self.assertEqual("AUD015", report["error"]["rule_id"])
        self.assertEqual(1, report["records"])

    def test_payload_change_without_hash_update_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {"value": 1}, timestamp=TIMESTAMP)
            mutate_record(
                path,
                0,
                lambda record: record["details"].__setitem__("value", 2),
                recompute=False,
            )
            report = inspect_audit(path)
        self.assertEqual("AUD016", report["error"]["rule_id"])

    def test_noncanonical_serialization_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            record = append_audit(path, "one", {}, timestamp=TIMESTAMP)
            path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            report = inspect_audit(path)
        self.assertEqual("AUD017", report["error"]["rule_id"])

    def test_expected_record_count_detects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            report = inspect_audit(path, expected_records=2)
        self.assertEqual("AUD020", report["error"]["rule_id"])
        self.assertIsNone(report["recoverable_prefix"])

    def test_expected_head_detects_replay_or_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            report = inspect_audit(path, expected_head="f" * 64)
        self.assertEqual("AUD021", report["error"]["rule_id"])
        self.assertIsNone(report["recoverable_prefix"])

    def test_append_refuses_to_extend_invalid_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(b'{"partial"')
            before = path.read_bytes()
            with self.assertRaisesRegex(AuditError, "refusing to extend"):
                append_audit(path, "blocked", {}, timestamp=TIMESTAMP)
            after = path.read_bytes()
        self.assertEqual(before, after)

    def test_recovery_copy_contains_only_verified_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "audit.jsonl"
            output = root / "recovered.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            append_audit(path, "two", {}, timestamp=TIMESTAMP)
            with path.open("ab") as handle:
                handle.write(b'{"partial"')
            report = inspect_audit(path)
            result = recover_audit(path, output, report)
            recovered = inspect_audit(output)
        self.assertEqual(2, result["records"])
        self.assertTrue(recovered["valid"])
        self.assertEqual(2, recovered["records"])

    def test_recovery_copy_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "audit.jsonl"
            output = root / "recovered.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            output.write_text("preserve")
            with self.assertRaisesRegex(AuditError, "overwrite"):
                recover_audit(path, output)
            preserved = output.read_text()
        self.assertEqual("preserve", preserved)

    @unittest.skipIf(os.name == "nt", "symlink creation requires additional Windows privileges")
    def test_symlink_log_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.write_text("")
            link = root / "audit.jsonl"
            link.symlink_to(target)
            report = inspect_audit(link)
        self.assertEqual("AUD001", report["error"]["rule_id"])

    def test_cli_json_report_accepts_external_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            expected = inspect_audit(path)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = agent_system.main([
                    "--audit-log", str(path), "audit", "--format", "json",
                    "--expected-records", "1", "--expected-head", expected["head_hash"],
                ])
            report = json.loads(output.getvalue())
        self.assertEqual(0, status)
        self.assertTrue(report["valid"])
        self.assertEqual(expected["head_hash"], report["head_hash"])

    def test_corrupt_log_preflight_blocks_audited_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(b'{"partial"')
            error = io.StringIO()
            output = io.StringIO()
            with contextlib.redirect_stderr(error), contextlib.redirect_stdout(output):
                status = agent_system.main([
                    "--audit-log", str(path), "guard", "python", "-m", "unittest"
                ])
        self.assertEqual(2, status)
        self.assertIn("AUD003", error.getvalue())
        self.assertEqual("", output.getvalue())

    def test_compatibility_verifier_returns_tuple(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, "one", {}, timestamp=TIMESTAMP)
            result = verify_audit(path)
        self.assertEqual((True, 1), result)


if __name__ == "__main__":
    unittest.main()
