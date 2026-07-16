import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_audit_trust_admission import default_policy
from agent_audit_trust_receiver import (
    AuditTrustReceiverError,
    append_transition,
    canonical_json,
    create_state,
    load_state,
    main,
)
from audit_trust_receiver_cases import admitted, receiver_history
from test_audit_trust_admission import make_bundle
from test_audit_trust_consistency import advance, anchor


class AuditTrustReceiverCliTests(unittest.TestCase):
    def test_load_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            path.write_text('{"state_version":1,"state_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(AuditTrustReceiverError, "strict JSON"):
                load_state(path)

    def test_nonadvancing_candidate_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _, _, transition = receiver_history(root)
            report = copy.deepcopy(transition[0])
            verified = copy.deepcopy(transition[1])
            verified["candidate"]["entry_count"] = state["head"]["entry_count"]
            verified["candidate"]["head"]["generation"] = state["head"]["generation"]
            verified["candidate"]["head"]["segment_count"] = state["head"]["segment_count"]
            report["evidence"]["candidate_entry_count"] = state["head"]["entry_count"]
            report["evidence"]["candidate_generation"] = state["head"]["generation"]
            report["evidence"]["candidate_segment_count"] = state["head"]["segment_count"]
            report["evidence"]["entry_delta"] = 1
            report["evidence"]["generation_delta"] = 1
            with self.assertRaises(AuditTrustReceiverError) as raised:
                append_transition(state, report, verified)
        self.assertEqual("ATR008", raised.exception.rule_id)

    def test_old_transition_replay_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, updated, _, transition = receiver_history(Path(temporary))
            with self.assertRaises(AuditTrustReceiverError) as raised:
                append_transition(updated, transition[0], transition[1])
        self.assertEqual("ATR006", raised.exception.rule_id)
        self.assertTrue(raised.exception.denied)

    def test_cli_stale_state_pin_is_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, verified, _, _, _ = admitted(root / "input", anchor())
            state = create_state(report, verified)
            state_path = root / "state.json"
            state_path.write_bytes(canonical_json(state))
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(["verify", str(state_path), "--expected-state-id", "f" * 64])
        self.assertEqual(2, status)

    def test_denied_policy_leaves_state_bytes_unchanged(self):
        retained = anchor()
        candidate = advance(retained)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root / "policy.json"
            policy.write_bytes(canonical_json(default_policy()))
            snapshot = admitted(root / "snapshot", retained)
            transition = admitted(root / "transition", candidate, retained)
            state = create_state(snapshot[0], snapshot[1])
            state_path = root / "receiver.json"
            state_path.write_bytes(canonical_json(state))
            before = state_path.read_bytes()
            denied = default_policy()
            denied["bundle"]["allowed_types"] = ["snapshot"]
            policy.write_bytes(canonical_json(denied))
            args = [
                "advance", str(state_path), str(transition[4]), "--policy", str(policy),
                "--expected-state-id", state["state_id"],
                "--expected-bundle-id", transition[3]["bundle_id"],
                "--expected-candidate-checkpoint-id", transition[2]["candidate"]["checkpoint_id"],
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(args)
            after = state_path.read_bytes()
        self.assertEqual(1, status)
        self.assertEqual(before, after)

    def test_state_and_policy_inside_bundle_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, manifest, bundle = make_bundle(root / "input", anchor())
            with contextlib.redirect_stderr(io.StringIO()):
                status = main([
                    "init", str(bundle / "state.json"), str(bundle),
                    "--policy", str(bundle / "policy.json"),
                    "--expected-bundle-id", manifest["bundle_id"],
                    "--expected-candidate-checkpoint-id", inputs["candidate"]["checkpoint_id"],
                ])
        self.assertEqual(2, status)

    def test_symlink_state_is_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "state.json"
            link.symlink_to(target)
            with self.assertRaises(AuditTrustReceiverError):
                load_state(link)

    def test_verify_can_bind_current_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, verified, _, _, bundle = admitted(root / "input", anchor())
            state = create_state(report, verified)
            path = root / "state.json"
            path.write_bytes(canonical_json(state))
            with contextlib.redirect_stdout(io.StringIO()):
                status = main([
                    "verify", str(path), "--expected-state-id", state["state_id"],
                    "--bundle", str(bundle),
                ])
        self.assertEqual(0, status)

    def test_cli_refuses_receiver_state_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root / "policy.json"
            policy.write_bytes(canonical_json(default_policy()))
            inputs, manifest, bundle = make_bundle(root / "input", anchor())
            state = root / "state.json"
            state.write_text("existing", encoding="utf-8")
            args = [
                "init", str(state), str(bundle), "--policy", str(policy),
                "--expected-bundle-id", manifest["bundle_id"],
                "--expected-candidate-checkpoint-id", inputs["candidate"]["checkpoint_id"],
            ]
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(args)
        self.assertEqual(2, status)

    def test_cli_init_verify_and_advance(self):
        retained = anchor()
        candidate = advance(retained)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root / "policy.json"
            policy.write_bytes(canonical_json(default_policy()))
            snapshot = admitted(root / "snapshot", retained)
            transition = admitted(root / "transition", candidate, retained)
            state_path = root / "receiver.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main([
                    "init", str(state_path), str(snapshot[4]), "--policy", str(policy),
                    "--expected-bundle-id", snapshot[3]["bundle_id"],
                    "--expected-candidate-checkpoint-id", snapshot[2]["candidate"]["checkpoint_id"],
                ]))
            state = load_state(state_path)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main([
                    "verify", str(state_path), "--expected-state-id", state["state_id"]
                ]))
                self.assertEqual(0, main([
                    "advance", str(state_path), str(transition[4]), "--policy", str(policy),
                    "--expected-state-id", state["state_id"],
                    "--expected-bundle-id", transition[3]["bundle_id"],
                    "--expected-candidate-checkpoint-id", transition[2]["candidate"]["checkpoint_id"],
                ]))
            updated = load_state(state_path)
        self.assertEqual(2, len(updated["entries"]))


if __name__ == "__main__":
    unittest.main()
