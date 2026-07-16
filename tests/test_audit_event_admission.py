import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import agent_system
from agent_audit import ZERO_HASH, _canonical_line, _record_hash
from agent_audit_events import (
    AuditEventError,
    EVENT_SCHEMA_VERSION,
    SCHEMA_FIELD,
    command_reference,
    event_catalog,
    path_reference,
    prepare_event,
)

TIMESTAMP = "2026-07-16T00:00:00+00:00"


def scan_details(path: str = "/home/private/project") -> dict:
    return {
        "path": path,
        "active": 0,
        "reported": 0,
        "suppressed": 0,
        "policy": "/home/private/project/policy.json",
        "expired_suppressions": [],
        "config": "/home/private/project/config.json",
        "enabled_packs": ["core", "boundaries"],
        "disabled_rules": [],
        "new_only": False,
        "baseline": None,
        "new": None,
        "existing": None,
        "resolved": None,
        "scope": None,
    }


def legacy_record(event: str = "legacy-event") -> dict:
    core = {
        "time": TIMESTAMP,
        "event": event,
        "details": {"ok": True},
        "previous_hash": ZERO_HASH,
    }
    return {**core, "hash": _record_hash(ZERO_HASH, core)}


def rewrite_record(path: Path, change) -> None:
    record = json.loads(path.read_text(encoding="utf-8"))
    change(record)
    core = dict(record)
    core.pop("hash")
    record["hash"] = _record_hash(record["previous_hash"], core)
    path.write_bytes(_canonical_line(record))


class AuditEventAdmissionTests(unittest.TestCase):
    def test_known_scan_event_hashes_paths(self):
        event, details = prepare_event("scan", scan_details())
        self.assertEqual("scan", event)
        self.assertEqual(EVENT_SCHEMA_VERSION, details[SCHEMA_FIELD])
        self.assertEqual("absolute", details["path"]["kind"])
        self.assertEqual(64, len(details["path"]["sha256"]))
        self.assertNotIn("/home/private/project", json.dumps(details))

    def test_dispatch_hashes_entire_command(self):
        opaque = "s" + "k" + "-" + "x" * 30
        event, details = prepare_event("dispatch", {
            "integration": "repo-risk-radar",
            "command": ["python", "tool.py", "--opaque", opaque],
            "allowed": True,
            "rule_id": None,
            "severity": None,
            "reason": "No blocked destructive pattern matched.",
            "safer_alternative": "Use least privilege and a dry run when available.",
        })
        self.assertEqual("dispatch", event)
        self.assertEqual(4, details["command"]["argc"])
        self.assertNotIn(opaque, json.dumps(details))

    def test_generic_event_rejects_sensitive_key(self):
        field = "api" + "_key"
        with self.assertRaisesRegex(AuditEventError, "credential-bearing"):
            prepare_event("custom-event", {field: "opaque"})

    def test_generic_event_rejects_sensitive_value(self):
        opaque = "s" + "k" + "-" + "y" * 30
        with self.assertRaises(AuditEventError) as captured:
            prepare_event("custom-event", {"message": opaque})
        self.assertEqual("AUD023", captured.exception.rule_id)

    def test_generic_event_rejects_nested_sensitive_key(self):
        field = "pass" + "word"
        with self.assertRaises(AuditEventError) as captured:
            prepare_event("custom-event", {"metadata": {field: "opaque"}})
        self.assertEqual("AUD023", captured.exception.rule_id)

    def test_known_event_rejects_unreviewed_field(self):
        details = scan_details()
        details["unexpected"] = True
        with self.assertRaisesRegex(AuditEventError, "unexpected"):
            prepare_event("scan", details)

    def test_event_name_must_be_canonical(self):
        with self.assertRaisesRegex(AuditEventError, "lowercase"):
            prepare_event("Scan Event", {"ok": True})

    def test_generic_event_rejects_floats(self):
        with self.assertRaisesRegex(AuditEventError, "floating-point"):
            prepare_event("custom-event", {"ratio": 0.5})

    def test_path_and_command_references_are_idempotent(self):
        path_ref = path_reference("relative/file.txt")
        command_ref = command_reference(["relative/file.txt"])
        self.assertEqual(path_ref, path_reference(path_ref))
        self.assertEqual(command_ref, command_reference(command_ref))
        self.assertNotEqual(path_ref["sha256"], command_ref["sha256"])

    def test_append_stores_typed_generic_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            agent_system.append_audit(path, "custom-event", {"count": 1}, timestamp=TIMESTAMP)
            record = json.loads(path.read_text(encoding="utf-8"))
            report = agent_system.inspect_audit(path)
        self.assertEqual(EVENT_SCHEMA_VERSION, record["details"][SCHEMA_FIELD])
        self.assertEqual(1, report["typed_records"])
        self.assertEqual(0, report["untyped_records"])
        self.assertTrue(report["privacy_safe"])

    def test_append_never_stores_raw_scan_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            private_path = "/home/alice/private-project"
            agent_system.append_audit(path, "scan", scan_details(private_path), timestamp=TIMESTAMP)
            raw = path.read_text(encoding="utf-8")
        self.assertNotIn(private_path, raw)
        self.assertNotIn("policy.json", raw)
        self.assertNotIn("config.json", raw)

    def test_legacy_untyped_record_is_reported_without_default_breakage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(_canonical_line(legacy_record()))
            report = agent_system.inspect_audit(path)
        self.assertTrue(report["valid"])
        self.assertEqual(0, report["typed_records"])
        self.assertEqual(1, report["untyped_records"])
        self.assertFalse(report["privacy_safe"])

    def test_require_typed_rejects_legacy_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(_canonical_line(legacy_record()))
            report = agent_system.inspect_audit(path, require_typed=True)
        self.assertFalse(report["valid"])
        self.assertEqual("AUD024", report["error"]["rule_id"])
        self.assertIsNone(report["recoverable_prefix"])

    def test_rehashed_noncanonical_typed_event_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            agent_system.append_audit(path, "scan", scan_details(), timestamp=TIMESTAMP)
            rewrite_record(path, lambda record: record["details"].__setitem__("path", "/raw/path"))
            report = agent_system.inspect_audit(path)
        self.assertFalse(report["valid"])
        self.assertEqual("AUD022", report["error"]["rule_id"])
        self.assertEqual(0, report["recoverable_prefix"]["records"])

    def test_rehashed_sensitive_generic_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            agent_system.append_audit(path, "custom-event", {"ok": True}, timestamp=TIMESTAMP)
            field = "sec" + "ret"
            rewrite_record(path, lambda record: record["details"].__setitem__(field, "opaque"))
            report = agent_system.inspect_audit(path)
        self.assertFalse(report["valid"])
        self.assertEqual("AUD023", report["error"]["rule_id"])

    def test_event_counts_and_coverage_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            agent_system.append_audit(path, "custom-event", {"one": 1}, timestamp=TIMESTAMP)
            agent_system.append_audit(path, "custom-event", {"two": 2}, timestamp=TIMESTAMP)
            report = agent_system.inspect_audit(path)
        self.assertEqual({"custom-event": 2}, report["event_counts"])
        self.assertEqual(100, report["typed_coverage_percent"])

    def test_cli_audit_require_typed_has_distinct_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(_canonical_line(legacy_record()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = agent_system.main([
                    "audit", "--path", str(path), "--require-typed", "--format", "json"
                ])
            report = json.loads(output.getvalue())
        self.assertEqual(1, status)
        self.assertEqual("AUD024", report["error"]["rule_id"])

    def test_cli_catalog_lists_known_events_and_privacy_rules(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_system.main(["audit-events", "--format", "json"])
        catalog = json.loads(output.getvalue())
        self.assertEqual(0, status)
        self.assertEqual(event_catalog(), catalog)
        self.assertIn("dispatch", catalog["known_events"])
        self.assertIn("AUD023", catalog["rules"])

    def test_real_guard_command_writes_typed_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with contextlib.redirect_stdout(io.StringIO()):
                status = agent_system.main([
                    "--audit-log", str(path), "guard", "python", "-m", "unittest"
                ])
            report = agent_system.inspect_audit(path, require_typed=True)
        self.assertEqual(0, status)
        self.assertTrue(report["valid"])
        self.assertEqual({"guard": 1}, report["event_counts"])


if __name__ == "__main__":
    unittest.main()
