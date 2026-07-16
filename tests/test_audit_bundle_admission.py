import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

import agent_system
from agent_audit import ZERO_HASH
from agent_audit_admission import (
    AuditBundleAdmissionError,
    canonical_json,
    default_policy,
    evaluate_bundle,
    load_policy,
    main,
    policy_sha256,
    validate_policy,
)
from agent_audit_bundle import create_bundle
from agent_audit_catalog import _build_catalog, initialize_catalog, load_catalog
from agent_audit_checkpoint import create_checkpoint, create_proof
from agent_audit_consistency import create_consistency_proof
from agent_audit_segments import rotate_audit


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


def fake_catalog(
    size: int,
    *,
    generation: int = 1,
    previous_catalog_id: str = ZERO_HASH,
) -> dict:
    entries = []
    previous = ZERO_HASH
    for index in range(1, size + 1):
        entry = fake_entry(index, previous)
        entries.append(entry)
        previous = entry["segment_id"]
    return _build_catalog(
        entries,
        generation=generation,
        previous_catalog_id=previous_catalog_id,
    )


def descendant(previous: dict, size: int, *, generation_delta: int = 1) -> dict:
    entries = [dict(item) for item in previous["segments"]]
    prior = entries[-1]["segment_id"]
    for index in range(len(entries) + 1, size + 1):
        entry = fake_entry(index, prior)
        entries.append(entry)
        prior = entry["segment_id"]
    previous_id = previous["catalog_id"] if generation_delta == 1 else "e" * 64
    return _build_catalog(
        entries,
        generation=previous["generation"] + generation_delta,
        previous_catalog_id=previous_id,
    )


def write_payload(path: Path, payload: dict) -> None:
    path.write_bytes(canonical_json(payload))


def snapshot_bundle(root: Path, *, indexes: tuple[int, ...] = (1, 3)):
    catalog = fake_catalog(3)
    checkpoint = create_checkpoint(catalog)
    checkpoint_path = root / "checkpoint.json"
    write_payload(checkpoint_path, checkpoint)
    proofs = []
    for index in indexes:
        proof_path = root / f"proof-{index}.json"
        write_payload(
            proof_path,
            create_proof(catalog, checkpoint, segment_index=index),
        )
        proofs.append(proof_path)
    manifest = create_bundle(
        root / "bundle",
        checkpoint_path,
        checkpoint["checkpoint_id"],
        proofs,
    )
    return catalog, checkpoint, manifest, root / "bundle"


def transition_bundle(root: Path, *, generation_delta: int = 1):
    previous_catalog = fake_catalog(1)
    candidate_catalog = descendant(
        previous_catalog,
        3,
        generation_delta=generation_delta,
    )
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
    proof_path = root / "proof.json"
    write_payload(previous_path, previous_checkpoint)
    write_payload(candidate_path, candidate_checkpoint)
    write_payload(consistency_path, consistency)
    write_payload(
        proof_path,
        create_proof(candidate_catalog, candidate_checkpoint, segment_index=3),
    )
    manifest = create_bundle(
        root / "bundle",
        candidate_path,
        candidate_checkpoint["checkpoint_id"],
        [proof_path],
        previous_checkpoint_path=previous_path,
        expected_previous_checkpoint_id=previous_checkpoint["checkpoint_id"],
        consistency_path=consistency_path,
    )
    return (
        previous_catalog,
        candidate_catalog,
        previous_checkpoint,
        candidate_checkpoint,
        manifest,
        root / "bundle",
    )


def sealed_bundle(root: Path):
    archive = root / "segments"
    active = root / "active.jsonl"
    archive.mkdir()
    agent_system.append_audit(active, "operation-complete", {"value": 1})
    rotate_audit(active, archive / "segment-0001")
    catalog_path = archive / "catalog.json"
    initialize_catalog(catalog_path, active_path=active)
    catalog = load_catalog(catalog_path)
    checkpoint = create_checkpoint(catalog)
    checkpoint_path = root / "checkpoint.json"
    proof_path = root / "proof.json"
    write_payload(checkpoint_path, checkpoint)
    write_payload(
        proof_path,
        create_proof(catalog, checkpoint, segment_index=1),
    )
    manifest = create_bundle(
        root / "bundle",
        checkpoint_path,
        checkpoint["checkpoint_id"],
        [proof_path],
        segment_root=archive,
    )
    return catalog, checkpoint, manifest, root / "bundle"


def evaluate_snapshot(root: Path, policy: dict):
    catalog, checkpoint, manifest, bundle = snapshot_bundle(root)
    report = evaluate_bundle(
        bundle,
        policy,
        expected_bundle_id=manifest["bundle_id"],
        expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
    )
    return catalog, checkpoint, manifest, report


class AuditBundleAdmissionTests(unittest.TestCase):
    def test_default_policy_is_valid_and_hash_is_deterministic(self):
        policy = default_policy()
        self.assertEqual(policy, validate_policy(policy))
        self.assertEqual(policy_sha256(policy), policy_sha256(copy.deepcopy(policy)))
        self.assertEqual(64, len(policy_sha256(policy)))

    def test_policy_rejects_unknown_fields_and_bad_ranges(self):
        policy = default_policy()
        policy["extra"] = True
        with self.assertRaisesRegex(AuditBundleAdmissionError, "fields"):
            validate_policy(policy)
        policy = default_policy()
        policy["bundle"]["min_proofs"] = 3
        policy["bundle"]["max_proofs"] = 2
        with self.assertRaisesRegex(AuditBundleAdmissionError, "min_proofs"):
            validate_policy(policy)

    def test_policy_loader_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"version":1,"version":1}', encoding="utf-8")
            with self.assertRaisesRegex(
                AuditBundleAdmissionError,
                "duplicate JSON key",
            ):
                load_policy(path)

    def test_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.json"
            self.assertEqual(0, main(["init", str(output)]))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main(["init", str(output)])
        self.assertEqual(2, status)
        self.assertIn("overwrite", error.getvalue())

    def test_default_policy_admits_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(
                Path(directory),
                default_policy(),
            )
        self.assertTrue(report["admitted"])
        self.assertEqual([], report["violations"])
        self.assertEqual(64, len(report["decision_id"]))

    def test_default_policy_admits_direct_transition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (
                previous,
                candidate,
                previous_checkpoint,
                candidate_checkpoint,
                manifest,
                bundle,
            ) = transition_bundle(root)
            report = evaluate_bundle(
                bundle,
                default_policy(),
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=candidate_checkpoint[
                    "checkpoint_id"
                ],
                expected_previous_checkpoint_id=previous_checkpoint[
                    "checkpoint_id"
                ],
            )
        self.assertTrue(report["admitted"])
        self.assertEqual(1, report["evidence"]["generation_delta"])
        self.assertEqual(
            previous["catalog_id"],
            report["identity"]["previous_catalog_id"],
        )
        self.assertEqual(
            candidate["catalog_id"],
            report["identity"]["candidate_catalog_id"],
        )

    def test_bundle_type_policy_denial(self):
        policy = default_policy()
        policy["bundle"]["allowed_types"] = ["transition"]
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertFalse(report["admitted"])
        self.assertEqual("AUA001", report["violations"][0]["rule_id"])

    def test_file_and_byte_limits_are_denied(self):
        policy = default_policy()
        policy["bundle"]["max_files"] = 1
        policy["bundle"]["max_bytes"] = 1
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertEqual(
            ["AUA002", "AUA002"],
            [item["rule_id"] for item in report["violations"]],
        )

    def test_proof_count_bounds_are_denied(self):
        policy = default_policy()
        policy["bundle"]["min_proofs"] = 3
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertEqual("AUA003", report["violations"][0]["rule_id"])

    def test_required_all_sealed_segments_denies_proof_only_bundle(self):
        policy = default_policy()
        policy["bundle"]["sealed_segments"] = "required-all"
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertEqual("AUA004", report["violations"][0]["rule_id"])

    def test_forbidden_sealed_segments_denies_copied_evidence(self):
        policy = default_policy()
        policy["bundle"]["sealed_segments"] = "forbidden"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, manifest, bundle = sealed_bundle(root)
            report = evaluate_bundle(
                bundle,
                policy,
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
            )
        self.assertEqual("AUA004", report["violations"][0]["rule_id"])

    def test_candidate_generation_bounds_are_denied(self):
        policy = default_policy()
        policy["candidate"]["min_generation"] = 2
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertEqual("AUA005", report["violations"][0]["rule_id"])

    def test_candidate_segment_count_bounds_are_denied(self):
        policy = default_policy()
        policy["candidate"]["max_segment_count"] = 2
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertEqual("AUA006", report["violations"][0]["rule_id"])

    def test_candidate_catalog_allowlist_is_enforced(self):
        policy = default_policy()
        policy["candidate"]["allowed_catalog_ids"] = ["f" * 64]
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertEqual("AUA007", report["violations"][0]["rule_id"])

    def test_required_and_allowed_segment_indexes_are_enforced(self):
        policy = default_policy()
        policy["selection"]["required_segment_indexes"] = [2]
        policy["selection"]["allowed_segment_indexes"] = [1, 2]
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertEqual(
            ["AUA008", "AUA009"],
            [item["rule_id"] for item in report["violations"]],
        )

    def test_required_and_allowed_segment_ids_are_enforced(self):
        policy = default_policy()
        policy["selection"]["required_segment_ids"] = [f"{2:064x}"]
        policy["selection"]["allowed_segment_ids"] = [
            f"{1:064x}",
            f"{2:064x}",
        ]
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, report = evaluate_snapshot(Path(directory), policy)
        self.assertEqual(
            ["AUA010", "AUA011"],
            [item["rule_id"] for item in report["violations"]],
        )

    def test_transition_relation_and_direct_predecessor_are_enforced(self):
        policy = default_policy()
        policy["transition"]["allowed_relations"] = ["same"]
        policy["transition"]["require_direct_predecessor"] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (
                _,
                _,
                previous_checkpoint,
                candidate_checkpoint,
                manifest,
                bundle,
            ) = transition_bundle(root, generation_delta=2)
            report = evaluate_bundle(
                bundle,
                policy,
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=candidate_checkpoint[
                    "checkpoint_id"
                ],
                expected_previous_checkpoint_id=previous_checkpoint[
                    "checkpoint_id"
                ],
            )
        self.assertEqual(
            ["AUA012", "AUA013"],
            [item["rule_id"] for item in report["violations"]],
        )

    def test_transition_delta_and_previous_catalog_allowlist_are_enforced(self):
        policy = default_policy()
        policy["transition"]["min_generation_delta"] = 2
        policy["transition"]["allowed_previous_catalog_ids"] = ["f" * 64]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (
                _,
                _,
                previous_checkpoint,
                candidate_checkpoint,
                manifest,
                bundle,
            ) = transition_bundle(root)
            report = evaluate_bundle(
                bundle,
                policy,
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=candidate_checkpoint[
                    "checkpoint_id"
                ],
                expected_previous_checkpoint_id=previous_checkpoint[
                    "checkpoint_id"
                ],
            )
        self.assertEqual(
            ["AUA014", "AUA015"],
            [item["rule_id"] for item in report["violations"]],
        )

    def test_unverifiable_bundle_is_invalid_not_policy_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, manifest, bundle = snapshot_bundle(root)
            (bundle / "extra.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(
                AuditBundleAdmissionError,
                "verification failed",
            ):
                evaluate_bundle(
                    bundle,
                    default_policy(),
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                )

    def test_cli_exit_semantics_and_external_policy_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, checkpoint, manifest, bundle = snapshot_bundle(root)
            policy_path = root / "policy.json"
            policy_path.write_bytes(canonical_json(default_policy()))
            admitted = main(
                [
                    "evaluate",
                    str(bundle),
                    "--policy",
                    str(policy_path),
                    "--expected-bundle-id",
                    manifest["bundle_id"],
                    "--expected-candidate-checkpoint-id",
                    checkpoint["checkpoint_id"],
                ]
            )
            denied_policy = default_policy()
            denied_policy["bundle"]["allowed_types"] = ["transition"]
            policy_path.write_bytes(canonical_json(denied_policy))
            denied = main(
                [
                    "evaluate",
                    str(bundle),
                    "--policy",
                    str(policy_path),
                    "--expected-bundle-id",
                    manifest["bundle_id"],
                    "--expected-candidate-checkpoint-id",
                    checkpoint["checkpoint_id"],
                ]
            )
            internal = bundle / "policy.json"
            internal.write_bytes(canonical_json(default_policy()))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                invalid = main(
                    [
                        "evaluate",
                        str(bundle),
                        "--policy",
                        str(internal),
                        "--expected-bundle-id",
                        manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        checkpoint["checkpoint_id"],
                    ]
                )
        self.assertEqual(0, admitted)
        self.assertEqual(1, denied)
        self.assertEqual(2, invalid)
        self.assertIn("AUA016", error.getvalue())


if __name__ == "__main__":
    unittest.main()
