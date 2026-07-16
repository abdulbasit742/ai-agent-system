import copy
import unittest

from agent_audit_trust_receiver_acceptance import (
    AuditTrustReceiverAcceptanceError,
    append_transition,
    create_state,
    validate_state,
)


def h(value: int) -> str:
    return f"{value:064x}"


def candidate(base: int, receiver_entries: int, trust_entries: int, generation: int, segments: int):
    return {
        "checkpoint_id": h(base + 1),
        "state_id": h(base + 2),
        "entry_count": receiver_entries,
        "head": {
            "sequence": receiver_entries,
            "entry_hash": h(base + 3),
            "handoff_bundle_id": h(base + 4),
            "checkpoint_id": h(base + 5),
            "state_id": h(base + 6),
            "entry_count": trust_entries,
            "head_bundle_id": h(base + 7),
            "generation": generation,
            "segment_count": segments,
        },
        "merkle_root": h(base + 8),
    }


def verified_snapshot():
    item = candidate(100, 1, 1, 1, 1)
    return {
        "valid": True,
        "bundle_id": h(90),
        "bundle_type": "snapshot",
        "candidate": item,
        "previous": None,
        "consistency": None,
        "files": 4,
        "bytes": 1000,
        "proof_count": 1,
        "head_handoff_bundle_id": item["head"]["handoff_bundle_id"],
    }


def verified_transition(previous=None):
    previous = copy.deepcopy(previous or verified_snapshot()["candidate"])
    item = candidate(200, 2, 2, 2, 2)
    return {
        "valid": True,
        "bundle_id": h(190),
        "bundle_type": "transition",
        "candidate": item,
        "previous": previous,
        "consistency": {"relation": "right-descendant", "consistency_id": h(299)},
        "files": 7,
        "bytes": 2000,
        "proof_count": 1,
        "head_handoff_bundle_id": item["head"]["handoff_bundle_id"],
    }


def report(verified, admitted=True):
    candidate_item = verified["candidate"]
    previous = verified.get("previous")
    head = candidate_item["head"]
    previous_head = previous["head"] if isinstance(previous, dict) else None
    return {
        "admitted": admitted,
        "policy_sha256": h(800),
        "identity": {
            "bundle_id": verified["bundle_id"],
            "bundle_type": verified["bundle_type"],
            "candidate_receiver_checkpoint_id": candidate_item["checkpoint_id"],
            "candidate_receiver_state_id": candidate_item["state_id"],
            "previous_receiver_checkpoint_id": previous["checkpoint_id"] if previous else None,
            "previous_receiver_state_id": previous["state_id"] if previous else None,
        },
        "evidence": {
            "files": verified["files"],
            "bytes": verified["bytes"],
            "proof_count": verified["proof_count"],
            "selected_sequences": [candidate_item["entry_count"]],
            "selected_handoff_ids": [head["handoff_bundle_id"]],
            "candidate_receiver_entries": candidate_item["entry_count"],
            "candidate_trust_entries": head["entry_count"],
            "candidate_generation": head["generation"],
            "candidate_segment_count": head["segment_count"],
            "head_handoff_bundle_id": verified["head_handoff_bundle_id"],
            "receiver_entry_delta": (
                candidate_item["entry_count"] - previous["entry_count"] if previous else None
            ),
            "trust_entry_delta": (
                head["entry_count"] - previous_head["entry_count"] if previous_head else None
            ),
            "generation_delta": (
                head["generation"] - previous_head["generation"] if previous_head else None
            ),
        },
        "violations": [] if admitted else [{"rule_id": "ARA001", "message": "denied"}],
        "decision_id": h(801 if admitted else 802),
    }


class ReceiverAcceptanceTests(unittest.TestCase):
    def anchor(self):
        verified = verified_snapshot()
        return create_state(report(verified), verified)

    def transition(self, state=None, verified=None):
        state = state or self.anchor()
        verified = verified or verified_transition()
        return append_transition(state, report(verified), verified)

    def test_anchor_round_trip(self):
        state = self.anchor()
        self.assertEqual(state, validate_state(state))
        self.assertEqual(1, state["head"]["entry_count"])

    def test_transition_round_trip(self):
        state = self.transition()
        self.assertEqual(state, validate_state(state))
        self.assertEqual(2, len(state["entries"]))

    def test_anchor_requires_snapshot(self):
        verified = verified_transition()
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            create_state(report(verified), verified)

    def test_anchor_requires_admission(self):
        verified = verified_snapshot()
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            create_state(report(verified, admitted=False), verified)

    def test_transition_requires_admission(self):
        verified = verified_transition()
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), report(verified, admitted=False), verified)

    def test_transition_requires_transition_type(self):
        verified = verified_snapshot()
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), report(verified), verified)

    def test_previous_receiver_head_must_match(self):
        verified = verified_transition()
        verified["previous"]["state_id"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), report(verified), verified)

    def test_receiver_entry_count_must_advance(self):
        verified = verified_transition()
        verified["candidate"]["entry_count"] = 1
        verified["candidate"]["head"]["sequence"] = 1
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), report(verified), verified)

    def test_trust_entry_count_must_advance(self):
        verified = verified_transition()
        verified["candidate"]["head"]["entry_count"] = 1
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), report(verified), verified)

    def test_generation_must_advance(self):
        verified = verified_transition()
        verified["candidate"]["head"]["generation"] = 1
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), report(verified), verified)

    def test_segment_count_must_not_decrease(self):
        base = self.anchor()
        verified = verified_transition()
        verified["candidate"]["head"]["segment_count"] = 0
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(base, report(verified), verified)

    def test_duplicate_bundle_is_rejected(self):
        verified = verified_transition()
        verified["bundle_id"] = self.anchor()["head"]["handoff_bundle_id"]
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), report(verified), verified)

    def test_duplicate_checkpoint_is_rejected(self):
        state = self.anchor()
        verified = verified_transition()
        verified["candidate"]["checkpoint_id"] = state["head"]["checkpoint_id"]
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(state, report(verified), verified)

    def test_duplicate_state_is_rejected(self):
        state = self.anchor()
        verified = verified_transition()
        verified["candidate"]["state_id"] = state["head"]["state_id"]
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(state, report(verified), verified)

    def test_entry_hash_tamper_is_rejected(self):
        state = self.anchor()
        state["entries"][0]["entry_hash"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            validate_state(state)

    def test_state_id_tamper_is_rejected(self):
        state = self.anchor()
        state["state_id"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            validate_state(state)

    def test_receiver_delta_must_match(self):
        verified = verified_transition()
        item = report(verified)
        item["evidence"]["receiver_entry_delta"] = 2
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), item, verified)

    def test_trust_delta_must_match(self):
        verified = verified_transition()
        item = report(verified)
        item["evidence"]["trust_entry_delta"] = 2
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            append_transition(self.anchor(), item, verified)

    def test_report_identity_must_match(self):
        verified = verified_snapshot()
        item = report(verified)
        item["identity"]["bundle_id"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            create_state(item, verified)

    def test_report_evidence_must_match(self):
        verified = verified_snapshot()
        item = report(verified)
        item["evidence"]["candidate_generation"] = 2
        with self.assertRaises(AuditTrustReceiverAcceptanceError):
            create_state(item, verified)


if __name__ == "__main__":
    unittest.main()
