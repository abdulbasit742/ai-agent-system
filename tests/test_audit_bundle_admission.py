import contextlib
import copy
import io
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
from agent_audit_checkpoint import _canonical_bytes as evidence_bytes
from agent_audit_checkpoint import create_checkpoint, create_proof
from agent_audit_consistency import create_consistency_proof
from agent_audit_segments import rotate_audit


def entry(index: int, previous: str) -> dict:
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


def catalog(
    size: int,
    generation: int = 1,
    previous_catalog_id: str = ZERO_HASH,
) -> dict:
    items, previous = [], ZERO_HASH
    for index in range(1, size + 1):
        item = entry(index, previous)
        items.append(item)
        previous = item["segment_id"]
    return _build_catalog(
        items,
        generation=generation,
        previous_catalog_id=previous_catalog_id,
    )


def descendant(previous: dict, size: int, delta: int = 1) -> dict:
    items = [dict(item) for item in previous["segments"]]
    prior = items[-1]["segment_id"]
    for index in range(len(items) + 1, size + 1):
        item = entry(index, prior)
        items.append(item)
        prior = item["segment_id"]
    return _build_catalog(
        items,
        generation=previous["generation"] + delta,
        previous_catalog_id=(
            previous["catalog_id"] if delta == 1 else "e" * 64
        ),
    )


def write_evidence(path: Path, payload: dict) -> None:
    path.write_bytes(evidence_bytes(payload))


def make_snapshot(root: Path, indexes=(1, 3)):
    current = catalog(3)
    checkpoint = create_checkpoint(current)
    checkpoint_path = root / "checkpoint.json"
    write_evidence(checkpoint_path, checkpoint)
    proofs = []
    for index in indexes:
        path = root / f"proof-{index}.json"
        write_evidence(
            path,
            create_proof(current, checkpoint, segment_index=index),
        )
        proofs.append(path)
    manifest = create_bundle(
        root / "bundle",
        checkpoint_path,
        checkpoint["checkpoint_id"],
        proofs,
    )
    return current, checkpoint, manifest, root / "bundle"


def make_transition(root: Path, delta=1):
    previous = catalog(1)
    candidate = descendant(previous, 3, delta)
    previous_checkpoint = create_checkpoint(previous)
    candidate_checkpoint = create_checkpoint(candidate)
    consistency = create_consistency_proof(
        previous,
        previous_checkpoint,
        candidate,
        candidate_checkpoint,
    )
    previous_path = root / "previous.json"
    candidate_path = root / "candidate.json"
    consistency_path = root / "consistency.json"
    proof_path = root / "proof.json"
    write_evidence(previous_path, previous_checkpoint)
    write_evidence(candidate_path, candidate_checkpoint)
    write_evidence(consistency_path, consistency)
    write_evidence(
        proof_path,
        create_proof(candidate, candidate_checkpoint, segment_index=3),
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
        previous,
        candidate,
        previous_checkpoint,
        candidate_checkpoint,
        manifest,
        root / "bundle",
    )


def make_sealed(root: Path):
    archive, active = root / "segments", root / "active.jsonl"
    archive.mkdir()
    agent_system.append_audit(active, "operation-complete", {"value": 1})
    rotate_audit(active, archive / "segment-0001")
    catalog_path = archive / "catalog.json"
    initialize_catalog(catalog_path, active_path=active)
    current = load_catalog(catalog_path)
    checkpoint = create_checkpoint(current)
    checkpoint_path = root / "checkpoint.json"
    proof_path = root / "proof.json"
    write_evidence(checkpoint_path, checkpoint)
    write_evidence(
        proof_path,
        create_proof(current, checkpoint, segment_index=1),
    )
    manifest = create_bundle(
        root / "bundle",
        checkpoint_path,
        checkpoint["checkpoint_id"],
        [proof_path],
        segment_root=archive,
    )
    return checkpoint, manifest, root / "bundle"


def admit_snapshot(root: Path, policy: dict):
    current, checkpoint, manifest, bundle = make_snapshot(root)
    return current, checkpoint, manifest, evaluate_bundle(
        bundle,
        policy,
        expected_bundle_id=manifest["bundle_id"],
        expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
    )


class AuditBundleAdmissionTests(unittest.TestCase):
    def test_default_policy_is_valid_and_hash_is_deterministic(self):
        policy = default_policy()
        self.assertEqual(policy, validate_policy(policy))
        self.assertEqual(
            policy_sha256(policy),
            policy_sha256(copy.deepcopy(policy)),
        )

    def test_policy_rejects_unknown_fields_and_bad_ranges(self):
        policy = default_policy()
        policy["extra"] = True
        with self.assertRaises(AuditBundleAdmissionError):
            validate_policy(policy)
        policy = default_policy()
        policy["bundle"]["min_proofs"] = 3
        policy["bundle"]["max_proofs"] = 2
        with self.assertRaises(AuditBundleAdmissionError):
            validate_policy(policy)

    def test_policy_loader_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_text('{"version":1,"version":1}')
            with self.assertRaisesRegex(
                AuditBundleAdmissionError,
                "duplicate JSON",
            ):
                load_policy(path)

    def test_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            self.assertEqual(0, main(["init", str(path)]))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, main(["init", str(path)]))

    def test_default_policy_admits_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, report = admit_snapshot(
                Path(temporary),
                default_policy(),
            )
        self.assertTrue(report["admitted"])
        self.assertEqual([], report["violations"])

    def test_default_policy_admits_direct_transition(self):
        with tempfile.TemporaryDirectory() as temporary:
            (
                previous,
                candidate,
                previous_checkpoint,
                candidate_checkpoint,
                manifest,
                bundle,
            ) = make_transition(Path(temporary))
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
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual("AUA001", report["violations"][0]["rule_id"])

    def test_file_and_byte_limits_are_denied(self):
        policy = default_policy()
        policy["bundle"].update(max_files=1, max_bytes=1)
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual(
            ["AUA002", "AUA002"],
            [item["rule_id"] for item in report["violations"]],
        )

    def test_proof_count_bounds_are_denied(self):
        policy = default_policy()
        policy["bundle"]["min_proofs"] = 3
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual("AUA003", report["violations"][0]["rule_id"])

    def test_required_all_sealed_segments_denies_proof_only_bundle(self):
        policy = default_policy()
        policy["bundle"]["sealed_segments"] = "required-all"
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual("AUA004", report["violations"][0]["rule_id"])

    def test_forbidden_sealed_segments_denies_copied_evidence(self):
        policy = default_policy()
        policy["bundle"]["sealed_segments"] = "forbidden"
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint, manifest, bundle = make_sealed(Path(temporary))
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
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual("AUA005", report["violations"][0]["rule_id"])

    def test_candidate_segment_count_bounds_are_denied(self):
        policy = default_policy()
        policy["candidate"]["max_segment_count"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual("AUA006", report["violations"][0]["rule_id"])

    def test_candidate_catalog_allowlist_is_enforced(self):
        policy = default_policy()
        policy["candidate"]["allowed_catalog_ids"] = ["f" * 64]
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual("AUA007", report["violations"][0]["rule_id"])

    def test_required_and_allowed_segment_indexes_are_enforced(self):
        policy = default_policy()
        policy["selection"].update(
            required_segment_indexes=[2],
            allowed_segment_indexes=[1, 2],
        )
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual(
            ["AUA008", "AUA009"],
            [item["rule_id"] for item in report["violations"]],
        )

    def test_required_and_allowed_segment_ids_are_enforced(self):
        policy = default_policy()
        policy["selection"].update(
            required_segment_ids=[f"{2:064x}"],
            allowed_segment_ids=[f"{1:064x}", f"{2:064x}"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            *_, report = admit_snapshot(Path(temporary), policy)
        self.assertEqual(
            ["AUA010", "AUA011"],
            [item["rule_id"] for item in report["violations"]],
        )

    def test_transition_relation_and_direct_predecessor_are_enforced(self):
        policy = default_policy()
        policy["transition"].update(
            allowed_relations=["same"],
            require_direct_predecessor=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            (
                _,
                _,
                previous_checkpoint,
                candidate_checkpoint,
                manifest,
                bundle,
            ) = make_transition(Path(temporary), 2)
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
        policy["transition"].update(
            min_generation_delta=2,
            allowed_previous_catalog_ids=["f" * 64],
        )
        with tempfile.TemporaryDirectory() as temporary:
            (
                _,
                _,
                previous_checkpoint,
                candidate_checkpoint,
                manifest,
                bundle,
            ) = make_transition(Path(temporary))
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
        with tempfile.TemporaryDirectory() as temporary:
            _, checkpoint, manifest, bundle = make_snapshot(Path(temporary))
            (bundle / "extra.txt").write_text("extra")
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
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, checkpoint, manifest, bundle = make_snapshot(root)
            policy = root / "policy.json"
            policy.write_bytes(canonical_json(default_policy()))
            base = [
                "evaluate",
                str(bundle),
                "--policy",
                str(policy),
                "--expected-bundle-id",
                manifest["bundle_id"],
                "--expected-candidate-checkpoint-id",
                checkpoint["checkpoint_id"],
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                admitted = main(base)
            denied_policy = default_policy()
            denied_policy["bundle"]["allowed_types"] = ["transition"]
            policy.write_bytes(canonical_json(denied_policy))
            with contextlib.redirect_stdout(io.StringIO()):
                denied = main(base)
            internal = bundle / "policy.json"
            internal.write_bytes(canonical_json(default_policy()))
            internal_args = list(base)
            internal_args[3] = str(internal)
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                invalid = main(internal_args)
        self.assertEqual((0, 1, 2), (admitted, denied, invalid))
        self.assertIn("AUA016", error.getvalue())


if __name__ == "__main__":
    unittest.main()
