import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_audit import ZERO_HASH
from agent_audit_admission import canonical_json as policy_bytes
from agent_audit_admission import default_policy, evaluate_bundle
from agent_audit_bundle import create_bundle, verify_bundle
from agent_audit_catalog import _build_catalog
from agent_audit_checkpoint import _canonical_bytes as evidence_bytes
from agent_audit_checkpoint import create_checkpoint, create_proof
from agent_audit_consistency import create_consistency_proof
from agent_audit_trust import (
    AuditBundleTrustError,
    _atomic_write,
    append_transition,
    canonical_json,
    create_state,
    load_state,
    main,
    validate_state,
)


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


def catalog(size: int, *, generation: int = 1, previous_catalog_id: str = ZERO_HASH) -> dict:
    entries = []
    previous = ZERO_HASH
    for index in range(1, size + 1):
        item = entry(index, previous)
        entries.append(item)
        previous = item["segment_id"]
    return _build_catalog(
        entries,
        generation=generation,
        previous_catalog_id=previous_catalog_id,
    )


def descendant(previous: dict, size: int, *, generation_delta: int = 1) -> dict:
    entries = [dict(item) for item in previous["segments"]]
    prior = entries[-1]["segment_id"]
    for index in range(len(entries) + 1, size + 1):
        item = entry(index, prior)
        entries.append(item)
        prior = item["segment_id"]
    predecessor = previous["catalog_id"] if generation_delta == 1 else "e" * 64
    return _build_catalog(
        entries,
        generation=previous["generation"] + generation_delta,
        previous_catalog_id=predecessor,
    )


def write_evidence(path: Path, payload: dict) -> None:
    path.write_bytes(evidence_bytes(payload))


def write_policy(path: Path, payload: dict | None = None) -> Path:
    path.write_bytes(policy_bytes(payload or default_policy()))
    return path


def snapshot(root: Path, source: dict | None = None):
    source = source or catalog(1)
    checkpoint = create_checkpoint(source)
    proof = create_proof(source, checkpoint, segment_index=source["segment_count"])
    checkpoint_path = root / "snapshot-checkpoint.json"
    proof_path = root / "snapshot-proof.json"
    write_evidence(checkpoint_path, checkpoint)
    write_evidence(proof_path, proof)
    bundle = root / "snapshot-bundle"
    manifest = create_bundle(
        bundle,
        checkpoint_path,
        checkpoint["checkpoint_id"],
        [proof_path],
    )
    return source, checkpoint, manifest, bundle


def transition(root: Path, previous_catalog: dict, *, size: int = 2, generation_delta: int = 1):
    candidate_catalog = descendant(previous_catalog, size, generation_delta=generation_delta)
    previous_checkpoint = create_checkpoint(previous_catalog)
    candidate_checkpoint = create_checkpoint(candidate_catalog)
    consistency = create_consistency_proof(
        previous_catalog,
        previous_checkpoint,
        candidate_catalog,
        candidate_checkpoint,
    )
    previous_path = root / "previous-checkpoint.json"
    candidate_path = root / "candidate-checkpoint.json"
    consistency_path = root / "consistency.json"
    proof_path = root / "candidate-proof.json"
    write_evidence(previous_path, previous_checkpoint)
    write_evidence(candidate_path, candidate_checkpoint)
    write_evidence(consistency_path, consistency)
    write_evidence(
        proof_path,
        create_proof(
            candidate_catalog,
            candidate_checkpoint,
            segment_index=candidate_catalog["segment_count"],
        ),
    )
    bundle = root / "transition-bundle"
    manifest = create_bundle(
        bundle,
        candidate_path,
        candidate_checkpoint["checkpoint_id"],
        [proof_path],
        previous_checkpoint_path=previous_path,
        expected_previous_checkpoint_id=previous_checkpoint["checkpoint_id"],
        consistency_path=consistency_path,
    )
    return (
        candidate_catalog,
        previous_checkpoint,
        candidate_checkpoint,
        manifest,
        bundle,
    )


def admission(bundle: Path, manifest: dict, checkpoint: dict, policy: dict, previous=None):
    report = evaluate_bundle(
        bundle,
        policy,
        expected_bundle_id=manifest["bundle_id"],
        expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
        expected_previous_checkpoint_id=(previous["checkpoint_id"] if previous else None),
    )
    verified = verify_bundle(
        bundle,
        expected_bundle_id=manifest["bundle_id"],
        expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
        expected_previous_checkpoint_id=(previous["checkpoint_id"] if previous else None),
    )
    return report, verified


def anchor_state(root: Path):
    source, checkpoint, manifest, bundle = snapshot(root)
    report, verified = admission(bundle, manifest, checkpoint, default_policy())
    state = create_state(report, verified)
    return source, checkpoint, manifest, bundle, state


class AuditBundleTrustTests(unittest.TestCase):
    def test_anchor_state_is_deterministic_and_canonical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_, state = anchor_state(root)
            second = validate_state(copy.deepcopy(state))
        self.assertEqual(state, second)
        self.assertEqual(1, state["head"]["sequence"])
        self.assertEqual(64, len(state["state_id"]))
        self.assertEqual("anchor", state["entries"][0]["kind"])

    def test_unknown_state_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            *_, state = anchor_state(Path(temporary))
            state["extra"] = True
            with self.assertRaisesRegex(AuditBundleTrustError, "fields"):
                validate_state(state)

    def test_entry_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            *_, state = anchor_state(Path(temporary))
            state["entries"][0]["evidence"]["generation"] = 9
            with self.assertRaisesRegex(AuditBundleTrustError, "hash"):
                validate_state(state)

    def test_state_head_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            *_, state = anchor_state(Path(temporary))
            state["head"]["segment_count"] += 1
            with self.assertRaisesRegex(AuditBundleTrustError, "head"):
                validate_state(state)

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            path.write_text('{"state_version":1,"state_version":1}\n')
            with self.assertRaisesRegex(AuditBundleTrustError, "duplicate"):
                load_state(path)

    def test_noncanonical_state_serialization_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_, state = anchor_state(root)
            path = root / "state.json"
            path.write_text(json.dumps(state, sort_keys=True) + "\n")
            with self.assertRaisesRegex(AuditBundleTrustError, "canonically"):
                load_state(path)

    def test_atomic_create_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_, state = anchor_state(root)
            path = root / "state.json"
            _atomic_write(path, state, require_absent=True)
            with self.assertRaisesRegex(AuditBundleTrustError, "overwrite"):
                _atomic_write(path, state, require_absent=True)

    def test_state_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}")
            link = root / "state.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(AuditBundleTrustError, "symlink"):
                load_state(link)

    def test_init_requires_snapshot_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = catalog(1)
            _, previous_checkpoint, candidate_checkpoint, manifest, bundle = transition(
                root, previous
            )
            report, verified = admission(
                bundle,
                manifest,
                candidate_checkpoint,
                default_policy(),
                previous_checkpoint,
            )
            with self.assertRaisesRegex(AuditBundleTrustError, "snapshot"):
                create_state(report, verified)

    def test_denied_snapshot_cannot_create_state(self):
        policy = default_policy()
        policy["bundle"]["allowed_types"] = ["transition"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, checkpoint, manifest, bundle = snapshot(root)
            policy_path = write_policy(root / "policy.json", policy)
            state_path = root / "state.json"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "init",
                        str(state_path),
                        str(bundle),
                        "--policy",
                        str(policy_path),
                        "--expected-bundle-id",
                        manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(1, status)
            self.assertFalse(state_path.exists())

    def test_verify_state_and_matching_head_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, bundle, state = anchor_state(root)
            path = root / "state.json"
            _atomic_write(path, state, require_absent=True)
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "verify",
                        str(path),
                        "--expected-state-id",
                        state["state_id"],
                        "--bundle",
                        str(bundle),
                    ]
                )
        self.assertEqual(0, status)

    def test_stale_verify_pin_is_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_, state = anchor_state(root)
            path = root / "state.json"
            _atomic_write(path, state, require_absent=True)
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main(
                    [
                        "verify",
                        str(path),
                        "--expected-state-id",
                        "f" * 64,
                    ]
                )
        self.assertEqual(2, status)
        self.assertIn("ATS003", error.getvalue())

    def test_wrong_head_bundle_is_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_, state = anchor_state(root / "first")
            _, _, _, wrong_bundle = snapshot(root / "second", catalog(2))
            path = root / "state.json"
            _atomic_write(path, state, require_absent=True)
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "verify",
                        str(path),
                        "--expected-state-id",
                        state["state_id"],
                        "--bundle",
                        str(wrong_bundle),
                    ]
                )
        self.assertEqual(2, status)

    def test_admitted_transition_advances_hash_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _, _, state = anchor_state(root / "anchor")
            candidate, previous_checkpoint, candidate_checkpoint, manifest, bundle = transition(
                root / "candidate", source
            )
            report, verified = admission(
                bundle,
                manifest,
                candidate_checkpoint,
                default_policy(),
                previous_checkpoint,
            )
            updated = append_transition(state, report, verified)
        self.assertEqual(2, updated["head"]["sequence"])
        self.assertEqual(candidate["catalog_id"], updated["head"]["catalog_id"])
        self.assertEqual(state["entries"][0]["entry_hash"], updated["entries"][1]["previous_entry_hash"])
        self.assertNotEqual(state["state_id"], updated["state_id"])

    def test_denied_transition_preserves_state_bytes(self):
        policy = default_policy()
        policy["bundle"]["allowed_types"] = ["snapshot"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _, _, state = anchor_state(root / "anchor")
            _, _, candidate_checkpoint, manifest, bundle = transition(root / "candidate", source)
            path = root / "state.json"
            _atomic_write(path, state, require_absent=True)
            before = path.read_bytes()
            policy_path = write_policy(root / "policy.json", policy)
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "advance",
                        str(path),
                        str(bundle),
                        "--policy",
                        str(policy_path),
                        "--expected-state-id",
                        state["state_id"],
                        "--expected-bundle-id",
                        manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        candidate_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(1, status)
            self.assertEqual(before, path.read_bytes())

    def test_previous_head_mismatch_preserves_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _, _, state = anchor_state(root / "anchor")
            unrelated = catalog(1, generation=2, previous_catalog_id="d" * 64)
            _, _, candidate_checkpoint, manifest, bundle = transition(
                root / "candidate", unrelated
            )
            path = root / "state.json"
            _atomic_write(path, state, require_absent=True)
            before = path.read_bytes()
            policy_path = write_policy(root / "policy.json")
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "advance",
                        str(path),
                        str(bundle),
                        "--policy",
                        str(policy_path),
                        "--expected-state-id",
                        state["state_id"],
                        "--expected-bundle-id",
                        manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        candidate_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(2, status)
            self.assertEqual(before, path.read_bytes())
            self.assertNotEqual(source["catalog_id"], unrelated["catalog_id"])

    def test_replayed_candidate_is_denied_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _, _, state = anchor_state(root / "anchor")
            _, previous_checkpoint, candidate_checkpoint, manifest, bundle = transition(
                root / "candidate", source
            )
            report, verified = admission(
                bundle,
                manifest,
                candidate_checkpoint,
                default_policy(),
                previous_checkpoint,
            )
            updated = append_transition(state, report, verified)
            with self.assertRaises(AuditBundleTrustError) as caught:
                append_transition(updated, report, verified)
        self.assertEqual("ATS006", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_stale_advance_pin_preserves_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _, _, state = anchor_state(root / "anchor")
            _, _, candidate_checkpoint, manifest, bundle = transition(root / "candidate", source)
            path = root / "state.json"
            _atomic_write(path, state, require_absent=True)
            before = path.read_bytes()
            policy_path = write_policy(root / "policy.json")
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "advance",
                        str(path),
                        str(bundle),
                        "--policy",
                        str(policy_path),
                        "--expected-state-id",
                        "f" * 64,
                        "--expected-bundle-id",
                        manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        candidate_checkpoint["checkpoint_id"],
                    ]
                )
            self.assertEqual(2, status)
            self.assertEqual(before, path.read_bytes())

    def test_policy_or_state_inside_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, checkpoint, manifest, bundle = snapshot(root)
            policy = write_policy(bundle / "policy.json")
            state = bundle / "state.json"
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main(
                    [
                        "init",
                        str(state),
                        str(bundle),
                        "--policy",
                        str(policy),
                        "--expected-bundle-id",
                        manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        checkpoint["checkpoint_id"],
                    ]
                )
        self.assertEqual(2, status)
        self.assertIn("ATS009", error.getvalue())

    def test_lock_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_, state = anchor_state(root)
            path = root / "state.json"
            target = root / "target.lock"
            target.write_text("")
            (root / "state.json.lock").symlink_to(target)
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = main(
                    [
                        "verify",
                        str(path),
                        "--expected-state-id",
                        state["state_id"],
                    ]
                )
        self.assertEqual(2, status)
        self.assertIn("ATS001", error.getvalue())

    def test_cli_init_advance_verify_and_exit_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, checkpoint, manifest, bundle = snapshot(root / "anchor")
            policy_path = write_policy(root / "policy.json")
            state_path = root / "state.json"
            created_output = io.StringIO()
            with contextlib.redirect_stdout(created_output):
                created = main(
                    [
                        "init",
                        str(state_path),
                        str(bundle),
                        "--policy",
                        str(policy_path),
                        "--expected-bundle-id",
                        manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        checkpoint["checkpoint_id"],
                    ]
                )
            created_report = json.loads(created_output.getvalue())
            _, _, candidate_checkpoint, candidate_manifest, candidate_bundle = transition(
                root / "candidate", source
            )
            advanced_output = io.StringIO()
            with contextlib.redirect_stdout(advanced_output):
                advanced = main(
                    [
                        "advance",
                        str(state_path),
                        str(candidate_bundle),
                        "--policy",
                        str(policy_path),
                        "--expected-state-id",
                        created_report["state_id"],
                        "--expected-bundle-id",
                        candidate_manifest["bundle_id"],
                        "--expected-candidate-checkpoint-id",
                        candidate_checkpoint["checkpoint_id"],
                    ]
                )
            advanced_report = json.loads(advanced_output.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                verified = main(
                    [
                        "verify",
                        str(state_path),
                        "--expected-state-id",
                        advanced_report["state_id"],
                        "--bundle",
                        str(candidate_bundle),
                    ]
                )
        self.assertEqual((0, 0, 0), (created, advanced, verified))
        self.assertTrue(advanced_report["advanced"])
        self.assertEqual(2, advanced_report["head"]["sequence"])


if __name__ == "__main__":
    unittest.main()
