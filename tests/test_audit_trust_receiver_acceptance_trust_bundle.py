import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import agent_audit_trust_receiver_acceptance_bundle as original_bundle
from agent_audit_trust_receiver_acceptance_trust import canonical_json
from agent_audit_trust_receiver_acceptance_trust_bundle import (
    AuditTrustReceiverAcceptanceTrustBundleError,
    CANDIDATE_CHECKPOINT_NAME,
    CONSISTENCY_NAME,
    MANIFEST_NAME,
    adapter_report,
    create_bundle,
    main,
    verify_bundle,
)
from agent_audit_trust_receiver_acceptance_trust_checkpoint import (
    create_checkpoint,
    create_proof,
)
from agent_audit_trust_receiver_acceptance_trust_consistency import (
    create_consistency_proof,
)
from test_audit_trust_receiver_acceptance_trust import h
from test_audit_trust_receiver_acceptance_trust_checkpoint import history


def trust_state(entries: int):
    if entries not in {1, 2, 3}:
        raise ValueError("fixture supports one through three entries")
    return history()[0][entries - 1]


class AcceptanceTrustBundleTests(unittest.TestCase):
    def evidence(self, root: Path, previous_entries=1, candidate_entries=2):
        previous = trust_state(previous_entries)
        candidate = trust_state(candidate_entries)
        previous_cp = create_checkpoint(previous)
        candidate_cp = create_checkpoint(candidate)
        previous_proof = create_proof(
            previous, previous_cp, sequence=previous_cp["entry_count"]
        )
        candidate_proof = create_proof(
            candidate, candidate_cp, sequence=candidate_cp["entry_count"]
        )
        consistency = create_consistency_proof(
            previous, previous_cp, candidate, candidate_cp
        )
        for name, payload in {
            "previous-state.json": previous,
            "candidate-state.json": candidate,
            "previous-checkpoint.json": previous_cp,
            "candidate-checkpoint.json": candidate_cp,
            "previous-proof.json": previous_proof,
            "candidate-proof.json": candidate_proof,
            "consistency.json": consistency,
        }.items():
            (root / name).write_bytes(canonical_json(payload))
        return previous, candidate, previous_cp, candidate_cp

    def assert_rule(self, expected, function):
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustBundleError) as raised:
            function()
        self.assertEqual(expected, raised.exception.rule_id)

    def snapshot_bundle(self, root: Path):
        previous, _candidate, previous_cp, _candidate_cp = self.evidence(root)
        bundle = root / "snapshot-bundle"
        manifest = create_bundle(
            bundle,
            root / "previous-checkpoint.json",
            previous_cp["checkpoint_id"],
            [root / "previous-proof.json"],
        )
        return previous, previous_cp, bundle, manifest

    def transition_bundle(self, root: Path):
        previous, candidate, previous_cp, candidate_cp = self.evidence(root)
        bundle = root / "transition-bundle"
        manifest = create_bundle(
            bundle,
            root / "candidate-checkpoint.json",
            candidate_cp["checkpoint_id"],
            [root / "candidate-proof.json"],
            previous_checkpoint_path=root / "previous-checkpoint.json",
            expected_previous_checkpoint_id=previous_cp["checkpoint_id"],
            consistency_path=root / "consistency.json",
        )
        return previous, candidate, previous_cp, candidate_cp, bundle, manifest

    def test_01_adapter_contract_is_acceptance_trust_specific(self):
        report = adapter_report()
        self.assertEqual("ABB", report["rule_prefix"])
        self.assertEqual(
            "audit-trust-receiver-acceptance-trust-bundle-manifest.json",
            report["manifest_name"],
        )
        self.assertIn("candidate-acceptance-trust-checkpoint", report["file_roles"])
        self.assertIn("acceptance-trust-inclusion-proof", report["file_roles"])

    def test_02_snapshot_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot_bundle(root)
            verified = verify_bundle(
                bundle,
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
            )
            self.assertTrue(verified["valid"])
            self.assertEqual("snapshot", verified["bundle_type"])
            self.assertEqual(1, verified["proof_count"])

    def test_03_transition_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _p, _c, previous_cp, candidate_cp, bundle, manifest = self.transition_bundle(root)
            verified = verify_bundle(
                bundle,
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=candidate_cp["checkpoint_id"],
                expected_previous_checkpoint_id=previous_cp["checkpoint_id"],
            )
            self.assertEqual("transition", verified["bundle_type"])
            self.assertEqual("right-descendant", verified["consistency"]["relation"])

    def test_04_offline_verification_after_loose_evidence_removal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _p, _c, previous_cp, candidate_cp, bundle, manifest = self.transition_bundle(root)
            for path in root.glob("*.json"):
                path.unlink()
            verified = verify_bundle(
                bundle,
                expected_bundle_id=manifest["bundle_id"],
                expected_candidate_checkpoint_id=candidate_cp["checkpoint_id"],
                expected_previous_checkpoint_id=previous_cp["checkpoint_id"],
            )
            self.assertTrue(verified["valid"])

    def test_05_candidate_head_proof_is_mandatory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _previous, candidate, _previous_cp, candidate_cp = self.evidence(root, 1, 3)
            non_head = create_proof(candidate, candidate_cp, sequence=2)
            (root / "non-head.json").write_bytes(canonical_json(non_head))
            self.assert_rule(
                "ABB012",
                lambda: create_bundle(
                    root / "bundle",
                    root / "candidate-checkpoint.json",
                    candidate_cp["checkpoint_id"],
                    [root / "non-head.json"],
                ),
            )

    def test_06_duplicate_proof_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _p, _c, _previous_cp, candidate_cp = self.evidence(root)
            self.assert_rule(
                "ABB007",
                lambda: create_bundle(
                    root / "bundle",
                    root / "candidate-checkpoint.json",
                    candidate_cp["checkpoint_id"],
                    [root / "candidate-proof.json", root / "candidate-proof.json"],
                ),
            )

    def test_07_stale_candidate_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.evidence(root)
            self.assert_rule(
                "ABB003",
                lambda: create_bundle(
                    root / "bundle",
                    root / "candidate-checkpoint.json",
                    h(999901),
                    [root / "candidate-proof.json"],
                ),
            )

    def test_08_stale_bundle_pin_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, _manifest = self.snapshot_bundle(root)
            self.assert_rule(
                "ABB003",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=h(999902),
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                ),
            )

    def test_09_partial_transition_arguments_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _p, _c, previous_cp, candidate_cp = self.evidence(root)
            self.assert_rule(
                "ABB005",
                lambda: create_bundle(
                    root / "bundle",
                    root / "candidate-checkpoint.json",
                    candidate_cp["checkpoint_id"],
                    [root / "candidate-proof.json"],
                    previous_checkpoint_path=root / "previous-checkpoint.json",
                    expected_previous_checkpoint_id=previous_cp["checkpoint_id"],
                ),
            )

    def test_10_checkpoint_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _p, _c, previous_cp, candidate_cp, bundle, manifest = self.transition_bundle(root)
            other = create_checkpoint(trust_state(3))
            (bundle / CANDIDATE_CHECKPOINT_NAME).write_bytes(canonical_json(other))
            self.assert_rule(
                "ABB008",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=candidate_cp["checkpoint_id"],
                    expected_previous_checkpoint_id=previous_cp["checkpoint_id"],
                ),
            )

    def test_11_consistency_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _p, _c, previous_cp, candidate_cp, bundle, manifest = self.transition_bundle(root)
            (bundle / CONSISTENCY_NAME).write_bytes(b"{}\n")
            self.assert_rule(
                "ABB008",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=candidate_cp["checkpoint_id"],
                    expected_previous_checkpoint_id=previous_cp["checkpoint_id"],
                ),
            )

    def test_12_inclusion_proof_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot_bundle(root)
            next((bundle / "proofs").iterdir()).write_bytes(b"{}\n")
            self.assert_rule(
                "ABB008",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                ),
            )

    def test_13_manifest_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot_bundle(root)
            path = bundle / MANIFEST_NAME
            payload = json.loads(path.read_text())
            payload["files"][0]["size"] += 1
            path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
            self.assert_rule(
                "ABB003",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                ),
            )

    def test_14_extra_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot_bundle(root)
            (bundle / "extra.txt").write_text("x")
            self.assert_rule(
                "ABB008",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                ),
            )

    @unittest.skipIf(not hasattr(os, "symlink"), "symlinks unavailable")
    def test_15_symlink_bundle_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot_bundle(root)
            target = bundle / CANDIDATE_CHECKPOINT_NAME
            target.unlink()
            os.symlink(root / "previous-checkpoint.json", target)
            self.assert_rule(
                "ABB001",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                ),
            )

    def test_16_output_is_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, _manifest = self.snapshot_bundle(root)
            before = sorted(path.relative_to(bundle).as_posix() for path in bundle.rglob("*"))
            self.assert_rule(
                "ABB011",
                lambda: create_bundle(
                    bundle,
                    root / "previous-checkpoint.json",
                    checkpoint["checkpoint_id"],
                    [root / "previous-proof.json"],
                ),
            )
            self.assertEqual(before, sorted(path.relative_to(bundle).as_posix() for path in bundle.rglob("*")))

    def test_17_manifest_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot_bundle(root)
            (bundle / MANIFEST_NAME).write_text('{"a":1,"a":2}\n')
            self.assert_rule(
                "ABB002",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                ),
            )

    def test_18_snapshot_rejects_previous_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _state, checkpoint, bundle, manifest = self.snapshot_bundle(root)
            self.assert_rule(
                "ABB005",
                lambda: verify_bundle(
                    bundle,
                    expected_bundle_id=manifest["bundle_id"],
                    expected_candidate_checkpoint_id=checkpoint["checkpoint_id"],
                    expected_previous_checkpoint_id=checkpoint["checkpoint_id"],
                ),
            )

    def test_19_cli_create_and_verify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _p, _c, previous_cp, candidate_cp = self.evidence(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "create", str(root / "bundle"),
                    "--candidate-checkpoint", str(root / "candidate-checkpoint.json"),
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                    "--proof", str(root / "candidate-proof.json"),
                    "--previous-checkpoint", str(root / "previous-checkpoint.json"),
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                    "--consistency-proof", str(root / "consistency.json"),
                ])
            self.assertEqual(0, status)
            bundle_id = json.loads(output.getvalue())["bundle_id"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "verify", str(root / "bundle"),
                    "--expected-bundle-id", bundle_id,
                    "--expected-candidate-checkpoint-id", candidate_cp["checkpoint_id"],
                    "--expected-previous-checkpoint-id", previous_cp["checkpoint_id"],
                ])
            self.assertEqual(0, status)
            self.assertTrue(json.loads(output.getvalue())["valid"])

    def test_20_parent_acceptance_bundle_namespace_is_not_mutated(self):
        self.assertEqual(
            "AAB002", original_bundle.AuditTrustReceiverAcceptanceBundleError("x").rule_id
        )
        self.assertEqual(
            "audit-trust-receiver-acceptance-bundle-manifest.json",
            original_bundle.MANIFEST_NAME,
        )
        self.assertNotEqual(original_bundle.MANIFEST_NAME, adapter_report()["manifest_name"])


if __name__ == "__main__":
    unittest.main()
