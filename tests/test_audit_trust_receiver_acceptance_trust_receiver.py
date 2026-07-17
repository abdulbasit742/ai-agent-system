import copy
import unittest

import agent_audit_trust_receiver_acceptance_trust as acceptance_trust
from agent_audit_trust_receiver_acceptance_trust_receiver import (
    AuditTrustReceiverAcceptanceTrustReceiverError,
    adapter_report,
    append_transition,
    create_state,
    validate_state,
)


def h(value: int) -> str:
    return f"{value:064x}"


def candidate(
    base: int,
    acceptance_trust_entries: int,
    acceptance_entries: int,
    receiver_entries: int,
    trust_entries: int,
    generation: int,
    segments: int,
):
    return {
        "checkpoint_id": h(base + 1),
        "state_id": h(base + 2),
        "entry_count": acceptance_trust_entries,
        "head": {
            "sequence": acceptance_trust_entries,
            "entry_hash": h(base + 3),
            "handoff_bundle_id": h(base + 4),
            "checkpoint_id": h(base + 5),
            "state_id": h(base + 6),
            "entry_count": acceptance_entries,
            "head_receiver_bundle_id": h(base + 7),
            "receiver_checkpoint_id": h(base + 8),
            "receiver_state_id": h(base + 9),
            "receiver_entry_count": receiver_entries,
            "trust_handoff_id": h(base + 10),
            "generation": generation,
            "segment_count": segments,
            "trust_checkpoint_id": h(base + 11),
            "trust_state_id": h(base + 12),
            "trust_entry_count": trust_entries,
        },
        "merkle_root": h(base + 13),
    }


def verified_snapshot():
    item = candidate(100, 1, 1, 1, 1, 1, 1)
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
    }


def verified_transition(previous=None):
    previous = copy.deepcopy(previous or verified_snapshot()["candidate"])
    item = candidate(200, 2, 2, 2, 2, 2, 2)
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
    }


def report(verified, admitted=True):
    item = verified["candidate"]
    previous = verified.get("previous")
    head = item["head"]
    previous_head = previous["head"] if isinstance(previous, dict) else None
    return {
        "admitted": admitted,
        "policy_sha256": h(800),
        "identity": {
            "bundle_id": verified["bundle_id"],
            "bundle_type": verified["bundle_type"],
            "candidate_acceptance_trust_checkpoint_id": item["checkpoint_id"],
            "candidate_acceptance_trust_state_id": item["state_id"],
            "previous_acceptance_trust_checkpoint_id": (
                previous["checkpoint_id"] if previous else None
            ),
            "previous_acceptance_trust_state_id": (
                previous["state_id"] if previous else None
            ),
        },
        "evidence": {
            "files": verified["files"],
            "bytes": verified["bytes"],
            "proof_count": verified["proof_count"],
            "selected_sequences": [item["entry_count"]],
            "selected_acceptance_bundle_ids": [head["handoff_bundle_id"]],
            "candidate_acceptance_trust_entries": item["entry_count"],
            "candidate_acceptance_entries": head["entry_count"],
            "candidate_receiver_entries": head["receiver_entry_count"],
            "candidate_trust_entries": head["trust_entry_count"],
            "candidate_generation": head["generation"],
            "candidate_segment_count": head["segment_count"],
            "head_acceptance_bundle_id": head["handoff_bundle_id"],
            "head_receiver_bundle_id": head["head_receiver_bundle_id"],
            "head_trust_handoff_id": head["trust_handoff_id"],
            "acceptance_trust_entry_delta": (
                item["entry_count"] - previous["entry_count"] if previous else None
            ),
            "acceptance_entry_delta": (
                head["entry_count"] - previous_head["entry_count"]
                if previous_head
                else None
            ),
            "receiver_entry_delta": (
                head["receiver_entry_count"] - previous_head["receiver_entry_count"]
                if previous_head
                else None
            ),
            "trust_entry_delta": (
                head["trust_entry_count"] - previous_head["trust_entry_count"]
                if previous_head
                else None
            ),
            "generation_delta": (
                head["generation"] - previous_head["generation"]
                if previous_head
                else None
            ),
            "segment_delta": (
                head["segment_count"] - previous_head["segment_count"]
                if previous_head
                else None
            ),
        },
        "violations": [] if admitted else [{"rule_id": "ABM001", "message": "denied"}],
        "decision_id": h(801 if admitted else 802),
    }


class AcceptanceTrustReceiverTests(unittest.TestCase):
    def anchor(self):
        verified = verified_snapshot()
        return create_state(report(verified), verified)

    def transition(self, state=None, verified=None):
        state = state or self.anchor()
        verified = verified or verified_transition()
        return append_transition(state, report(verified), verified)

    def test_01_adapter_report_and_namespace_isolation(self):
        details = adapter_report()
        self.assertEqual("ABN", details["rule_prefix"])
        self.assertEqual(
            "agent_audit_trust_receiver_acceptance_trust.py", details["source"]
        )
        self.assertIs(
            acceptance_trust._engine.AuditTrustReceiverError,
            acceptance_trust.AuditTrustReceiverAcceptanceTrustError,
        )
        self.assertNotEqual(
            acceptance_trust.ENTRY_DOMAIN,
            __import__(
                "agent_audit_trust_receiver_acceptance_trust_receiver",
                fromlist=["ENTRY_DOMAIN"],
            ).ENTRY_DOMAIN,
        )

    def test_02_anchor_round_trip(self):
        state = self.anchor()
        self.assertEqual(state, validate_state(state))
        self.assertEqual(1, len(state["entries"]))
        self.assertEqual(1, state["head"]["acceptance_entry_count"])

    def test_03_transition_round_trip(self):
        state = self.transition()
        self.assertEqual(state, validate_state(state))
        self.assertEqual(2, len(state["entries"]))
        self.assertEqual(2, state["head"]["entry_count"])

    def test_04_anchor_requires_snapshot(self):
        verified = verified_transition()
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            create_state(report(verified), verified)
        self.assertEqual("ABN005", caught.exception.rule_id)

    def test_05_anchor_requires_admission(self):
        verified = verified_snapshot()
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            create_state(report(verified, admitted=False), verified)
        self.assertEqual("ABN004", caught.exception.rule_id)
        self.assertTrue(caught.exception.denied)

    def test_06_transition_requires_admission(self):
        verified = verified_transition()
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified, admitted=False), verified)
        self.assertEqual("ABN004", caught.exception.rule_id)

    def test_07_transition_requires_transition_type(self):
        verified = verified_snapshot()
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN005", caught.exception.rule_id)

    def test_08_previous_outer_identity_must_match(self):
        verified = verified_transition()
        verified["previous"]["state_id"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN006", caught.exception.rule_id)

    def test_09_previous_merkle_and_head_hash_must_match(self):
        verified = verified_transition()
        verified["previous"]["merkle_root"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN006", caught.exception.rule_id)
        verified = verified_transition()
        verified["previous"]["head"]["entry_hash"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN006", caught.exception.rule_id)

    def test_10_previous_nested_acceptance_identity_must_match(self):
        for field in ("checkpoint_id", "state_id", "entry_count"):
            with self.subTest(field=field):
                verified = verified_transition()
                verified["previous"]["head"][field] = (
                    999 if field == "entry_count" else h(999)
                )
                with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
                    append_transition(self.anchor(), report(verified), verified)
                self.assertEqual("ABN006", caught.exception.rule_id)

    def test_11_previous_receiver_and_trust_identity_must_match(self):
        fields = (
            "receiver_checkpoint_id",
            "receiver_state_id",
            "receiver_entry_count",
            "trust_checkpoint_id",
            "trust_state_id",
            "trust_entry_count",
        )
        for field in fields:
            with self.subTest(field=field):
                verified = verified_transition()
                verified["previous"]["head"][field] = (
                    999 if field.endswith("_count") else h(999)
                )
                with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
                    append_transition(self.anchor(), report(verified), verified)
                self.assertEqual("ABN006", caught.exception.rule_id)

    def test_12_acceptance_trust_count_must_advance(self):
        verified = verified_transition()
        verified["candidate"]["entry_count"] = 1
        verified["candidate"]["head"]["sequence"] = 1
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN008", caught.exception.rule_id)

    def test_13_acceptance_count_must_advance(self):
        verified = verified_transition()
        verified["candidate"]["head"]["entry_count"] = 1
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN008", caught.exception.rule_id)

    def test_14_receiver_count_must_advance(self):
        verified = verified_transition()
        verified["candidate"]["head"]["receiver_entry_count"] = 1
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN008", caught.exception.rule_id)

    def test_15_trust_count_must_advance(self):
        verified = verified_transition()
        verified["candidate"]["head"]["trust_entry_count"] = 1
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN008", caught.exception.rule_id)

    def test_16_generation_and_segment_rules(self):
        verified = verified_transition()
        verified["candidate"]["head"]["generation"] = 1
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN008", caught.exception.rule_id)
        verified = verified_transition()
        verified["candidate"]["head"]["segment_count"] = 0
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
            append_transition(self.anchor(), report(verified), verified)
        self.assertEqual("ABN008", caught.exception.rule_id)

    def test_17_duplicate_outer_identities_are_rejected(self):
        state = self.anchor()
        mutations = (
            ("bundle_id", state["head"]["handoff_bundle_id"]),
            ("checkpoint_id", state["head"]["checkpoint_id"]),
            ("state_id", state["head"]["state_id"]),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                verified = verified_transition()
                if field == "bundle_id":
                    verified[field] = value
                else:
                    verified["candidate"][field] = value
                with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError) as caught:
                    append_transition(state, report(verified), verified)
                self.assertEqual("ABN007", caught.exception.rule_id)

    def test_18_entry_and_state_hash_tampering_is_rejected(self):
        state = self.anchor()
        state["entries"][0]["entry_hash"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError):
            validate_state(state)
        state = self.anchor()
        state["state_id"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError):
            validate_state(state)

    def test_19_report_identity_and_evidence_must_match(self):
        verified = verified_snapshot()
        item = report(verified)
        item["identity"]["bundle_id"] = h(999)
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError):
            create_state(item, verified)
        item = report(verified)
        item["evidence"]["candidate_acceptance_entries"] = 2
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError):
            create_state(item, verified)

    def test_20_transition_deltas_must_match(self):
        verified = verified_transition()
        keys = (
            "acceptance_trust_entry_delta",
            "acceptance_entry_delta",
            "receiver_entry_delta",
            "trust_entry_delta",
            "generation_delta",
            "segment_delta",
        )
        for key in keys:
            with self.subTest(key=key):
                item = report(verified)
                item["evidence"][key] += 1
                with self.assertRaises(AuditTrustReceiverAcceptanceTrustReceiverError):
                    append_transition(self.anchor(), item, verified)


if __name__ == "__main__":
    unittest.main()
