import copy
import json
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
    validate_state,
)
from audit_trust_receiver_cases import admitted, receiver_history
from test_audit_trust_consistency import advance, anchor


class AuditTrustReceiverCoreTests(unittest.TestCase):
    def test_snapshot_anchor_roundtrip(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, verified, _, _, _ = admitted(Path(temporary), anchor())
            state = create_state(report, verified)
        self.assertEqual(state, validate_state(copy.deepcopy(state)))
        self.assertEqual("anchor", state["entries"][0]["kind"])
        self.assertEqual(verified["candidate"]["checkpoint_id"], state["head"]["checkpoint_id"])

    def test_transition_advances_receiver_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            state, updated, _, transition = receiver_history(Path(temporary))
        self.assertEqual(2, len(updated["entries"]))
        self.assertNotEqual(state["state_id"], updated["state_id"])
        self.assertEqual(transition[2]["candidate"]["checkpoint_id"], updated["head"]["checkpoint_id"])

    def test_state_is_canonical_and_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, verified, _, _, _ = admitted(Path(temporary), anchor())
            first = create_state(report, verified)
            second = create_state(copy.deepcopy(report), copy.deepcopy(verified))
        self.assertEqual(first, second)
        self.assertTrue(canonical_json(first).endswith(b"\n"))

    def test_tampered_entry_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state, _, _, _ = receiver_history(Path(temporary))
        state["entries"][0]["entry_hash"] = "f" * 64
        with self.assertRaisesRegex(AuditTrustReceiverError, "hash"):
            validate_state(state)

    def test_noncanonical_state_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, verified, _, _, _ = admitted(root / "input", anchor())
            state = create_state(report, verified)
            path = root / "state.json"
            path.write_text(json.dumps(state), encoding="utf-8")
            with self.assertRaisesRegex(AuditTrustReceiverError, "canonically"):
                load_state(path)

    def test_anchor_requires_snapshot_handoff(self):
        retained = anchor()
        candidate = advance(retained)
        with tempfile.TemporaryDirectory() as temporary:
            report, verified, _, _, _ = admitted(Path(temporary), candidate, retained)
            with self.assertRaisesRegex(AuditTrustReceiverError, "snapshot") as raised:
                create_state(report, verified)
        self.assertEqual("ATR005", raised.exception.rule_id)

    def test_advance_requires_transition_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, verified, _, _, _ = admitted(root / "anchor", anchor())
            state = create_state(report, verified)
            next_report, next_verified, _, _, _ = admitted(root / "again", anchor(2))
            with self.assertRaisesRegex(AuditTrustReceiverError, "transition") as raised:
                append_transition(state, next_report, next_verified)
        self.assertEqual("ATR005", raised.exception.rule_id)

    def test_previous_head_mismatch_is_denied(self):
        retained = anchor(1)
        candidate = advance(retained)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, verified, _, _, _ = admitted(root / "anchor", anchor(2))
            state = create_state(report, verified)
            transition_report, transition_verified, _, _, _ = admitted(
                root / "transition", candidate, retained
            )
            with self.assertRaises(AuditTrustReceiverError) as raised:
                append_transition(state, transition_report, transition_verified)
        self.assertEqual("ATR006", raised.exception.rule_id)
        self.assertTrue(raised.exception.denied)

    def test_denied_admission_is_rejected(self):
        policy = default_policy()
        policy["bundle"]["allowed_types"] = ["transition"]
        with tempfile.TemporaryDirectory() as temporary:
            report, verified, _, _, _ = admitted(Path(temporary), anchor(), policy=policy)
            with self.assertRaises(AuditTrustReceiverError) as raised:
                create_state(report, verified)
        self.assertEqual("ATR004", raised.exception.rule_id)

    def test_report_identity_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, verified, _, _, _ = admitted(Path(temporary), anchor())
            report["identity"]["candidate_state_id"] = "f" * 64
            with self.assertRaisesRegex(AuditTrustReceiverError, "differs"):
                create_state(report, verified)


if __name__ == "__main__":
    unittest.main()
