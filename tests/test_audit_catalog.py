import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import agent_system
from agent_audit import _canonical_line, _record_hash
from agent_audit_catalog import (
    AuditCatalogError,
    _canonical_bytes,
    _catalog_id,
    initialize_catalog,
    load_catalog,
    main,
    synchronize_catalog,
    verify_catalog,
)
from agent_audit_segments import (
    MANIFEST_FILE,
    SEGMENT_FILE,
    _canonical_json as segment_canonical_json,
    _segment_id,
    rotate_audit,
)

TIMESTAMP = "2026-07-16T00:00:00+00:00"


def append_event(path: Path, value: int) -> dict:
    return agent_system.append_audit(
        path,
        "operation-complete",
        {"value": value},
        timestamp=TIMESTAMP,
    )


def build_segments(root: Path, count: int, names=None):
    active = root / "audit.jsonl"
    archive = root / "segments"
    archive.mkdir()
    names = names or [f"{index:04d}" for index in range(1, count + 1)]
    results = []
    for index in range(1, count + 1):
        append_event(active, index)
        results.append(rotate_audit(active, archive / names[index - 1]))
    return active, archive, results


def rewrite_catalog(path: Path, payload: dict) -> None:
    path.write_bytes(_canonical_bytes(payload))


def reidentify_catalog(payload: dict) -> dict:
    core = dict(payload)
    core.pop("catalog_id", None)
    return {**core, "catalog_id": _catalog_id(core)}


def rewrite_manifest(path: Path, payload: dict) -> None:
    core = dict(payload)
    core.pop("segment_id", None)
    payload = {**core, "segment_id": _segment_id(core)}
    path.write_bytes(segment_canonical_json(payload))


class AuditCatalogTests(unittest.TestCase):
    def test_init_discovers_unordered_directory_names_by_segment_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, archive, results = build_segments(
                root,
                2,
                names=["z-oldest", "a-newest"],
            )
            catalog = archive / "catalog.json"
            report = initialize_catalog(catalog, active_path=active)
        self.assertEqual(["z-oldest", "a-newest"], [item["directory"] for item in report["segments"]])
        self.assertEqual(results[-1]["segment_id"], report["latest_segment_id"])
        self.assertEqual(2, report["segment_count"])

    def test_catalog_is_canonical_and_id_round_trips(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            payload = load_catalog(catalog, expected_catalog_id=created["catalog_id"])
            raw = catalog.read_bytes()
        self.assertEqual(raw, _canonical_bytes(payload))
        self.assertEqual(64, len(payload["catalog_id"]))
        self.assertEqual(1, payload["generation"])

    def test_verify_catalog_checks_active_continuity_and_external_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, archive, _ = build_segments(root, 2)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog, active_path=active)
            report = verify_catalog(
                catalog,
                expected_catalog_id=created["catalog_id"],
                active_path=active,
            )
        self.assertTrue(report["valid"])
        self.assertTrue(report["active"]["privacy_safe"])
        self.assertEqual(created["catalog_id"], report["expected_catalog_id"])

    def test_wrong_catalog_pin_is_a_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            initialize_catalog(catalog)
            with self.assertRaisesRegex(AuditCatalogError, "externally retained pin") as caught:
                verify_catalog(catalog, expected_catalog_id="f" * 64)
        self.assertEqual("AUC007", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_duplicate_catalog_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            initialize_catalog(catalog)
            text = catalog.read_text().rstrip("\n}")
            catalog.write_text(text + ',"catalog_id":"' + "0" * 64 + '"}\n')
            with self.assertRaisesRegex(AuditCatalogError, "strict JSON") as caught:
                load_catalog(catalog)
        self.assertEqual("AUC002", caught.exception.rule_id)

    def test_noncanonical_catalog_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            initialize_catalog(catalog)
            payload = json.loads(catalog.read_text())
            catalog.write_text(json.dumps(payload, indent=2) + "\n")
            with self.assertRaisesRegex(AuditCatalogError, "canonically serialized"):
                load_catalog(catalog)

    def test_rehashed_catalog_summary_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            initialize_catalog(catalog)
            payload = json.loads(catalog.read_text())
            payload["total_records"] += 1
            rewrite_catalog(catalog, reidentify_catalog(payload))
            with self.assertRaisesRegex(AuditCatalogError, "total_records") as caught:
                load_catalog(catalog)
        self.assertEqual("AUC003", caught.exception.rule_id)

    def test_segment_byte_tamper_is_rejected_through_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            with (archive / "0001" / SEGMENT_FILE).open("ab") as handle:
                handle.write(b"x")
            with self.assertRaises(AuditCatalogError) as caught:
                verify_catalog(catalog, expected_catalog_id=created["catalog_id"])
        self.assertEqual("AUC004", caught.exception.rule_id)

    def test_missing_cataloged_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            shutil.rmtree(archive / "0001")
            with self.assertRaises(AuditCatalogError) as caught:
                verify_catalog(catalog, expected_catalog_id=created["catalog_id"])
        self.assertIn(caught.exception.rule_id, {"AUC001", "AUC004"})

    def test_unindexed_new_segment_makes_catalog_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            append_event(active, 2)
            rotate_audit(active, archive / "0002")
            with self.assertRaisesRegex(AuditCatalogError, "exactly cover") as caught:
                verify_catalog(catalog, expected_catalog_id=created["catalog_id"])
        self.assertEqual("AUC005", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_sync_appends_one_segment_and_links_catalog_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            append_event(active, 2)
            rotate_audit(active, archive / "0002")
            synced = synchronize_catalog(
                catalog,
                expected_catalog_id=created["catalog_id"],
                active_path=active,
            )
        self.assertTrue(synced["updated"])
        self.assertEqual(1, synced["added_segments"])
        self.assertEqual(2, synced["generation"])
        self.assertEqual(created["catalog_id"], synced["previous_catalog_id"])

    def test_sync_appends_multiple_discovered_segments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            append_event(active, 2)
            rotate_audit(active, archive / "later-two")
            append_event(active, 3)
            rotate_audit(active, archive / "later-three")
            synced = synchronize_catalog(
                catalog,
                expected_catalog_id=created["catalog_id"],
                active_path=active,
            )
        self.assertEqual(2, synced["added_segments"])
        self.assertEqual(3, synced["segment_count"])
        self.assertEqual([1, 2, 3], [item["segment_index"] for item in synced["segments"]])

    def test_sync_noop_preserves_catalog_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            before = catalog.read_bytes()
            synced = synchronize_catalog(
                catalog,
                expected_catalog_id=created["catalog_id"],
                active_path=active,
            )
            after = catalog.read_bytes()
        self.assertFalse(synced["updated"])
        self.assertEqual(before, after)
        self.assertEqual(created["catalog_id"], synced["catalog_id"])

    def test_sync_wrong_pin_preserves_catalog_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            initialize_catalog(catalog)
            before = catalog.read_bytes()
            with self.assertRaises(AuditCatalogError) as caught:
                synchronize_catalog(catalog, expected_catalog_id="f" * 64)
            after = catalog.read_bytes()
        self.assertEqual("AUC007", caught.exception.rule_id)
        self.assertEqual(before, after)

    def test_sync_rejects_forked_discovered_segment_and_preserves_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            before = catalog.read_bytes()
            fork = archive / "fork"
            shutil.copytree(archive / "0001", fork)
            manifest_path = fork / MANIFEST_FILE
            manifest = json.loads(manifest_path.read_text())
            manifest["segment_index"] = 2
            manifest["previous_segment_id"] = "f" * 64
            rewrite_manifest(manifest_path, manifest)
            with self.assertRaises(AuditCatalogError) as caught:
                synchronize_catalog(
                    catalog,
                    expected_catalog_id=created["catalog_id"],
                )
            after = catalog.read_bytes()
        self.assertEqual("AUC005", caught.exception.rule_id)
        self.assertEqual(before, after)

    def test_sync_active_mismatch_is_denied_before_catalog_update(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            created = initialize_catalog(catalog)
            append_event(active, 2)
            rotate_audit(active, archive / "0002")
            record = json.loads(active.read_text())
            record["details"]["previous_records"] += 1
            core = dict(record)
            core.pop("hash")
            record["hash"] = _record_hash(record["previous_hash"], core)
            active.write_bytes(_canonical_line(record))
            self.assertTrue(agent_system.inspect_audit(active, require_typed=True)["valid"])
            before = catalog.read_bytes()
            with self.assertRaises(AuditCatalogError) as caught:
                synchronize_catalog(
                    catalog,
                    expected_catalog_id=created["catalog_id"],
                    active_path=active,
                )
            after = catalog.read_bytes()
        self.assertEqual("AUC006", caught.exception.rule_id)
        self.assertEqual(before, after)

    @unittest.skipIf(os.name == "nt", "symlink creation requires additional Windows privileges")
    def test_symlink_catalog_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            initialize_catalog(catalog)
            target = archive / "catalog-target.json"
            catalog.replace(target)
            catalog.symlink_to(target)
            with self.assertRaises(AuditCatalogError) as caught:
                load_catalog(catalog)
        self.assertEqual("AUC001", caught.exception.rule_id)

    def test_unreviewed_archive_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, archive, _ = build_segments(root, 1)
            (archive / "misc").mkdir()
            with self.assertRaisesRegex(AuditCatalogError, "unreviewed directory") as caught:
                initialize_catalog(archive / "catalog.json")
        self.assertEqual("AUC001", caught.exception.rule_id)

    def test_cli_init_verify_and_exit_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, archive, _ = build_segments(root, 1)
            catalog = archive / "catalog.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                initialized = main([
                    "init", str(catalog), "--active", str(active), "--format", "json"
                ])
            payload = json.loads(output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verified = main([
                    "verify", str(catalog),
                    "--expected-catalog-id", payload["catalog_id"],
                    "--active", str(active), "--format", "json",
                ])
            with contextlib.redirect_stderr(io.StringIO()):
                denied = main([
                    "verify", str(catalog),
                    "--expected-catalog-id", "f" * 64,
                ])
                invalid = main([
                    "verify", str(archive / "missing.json"),
                    "--expected-catalog-id", "f" * 64,
                ])
        self.assertEqual(0, initialized)
        self.assertEqual(0, verified)
        self.assertEqual(1, denied)
        self.assertEqual(2, invalid)


if __name__ == "__main__":
    unittest.main()
