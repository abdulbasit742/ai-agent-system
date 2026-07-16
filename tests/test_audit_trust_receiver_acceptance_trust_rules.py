import unittest

from agent_audit_trust_receiver_acceptance_trust import (
    AuditTrustReceiverAcceptanceTrustError,
    append_transition,
    create_state,
)
from test_audit_trust_receiver_acceptance_trust import (
    report,
    verified_snapshot,
    verified_transition,
)


class ReceiverAcceptanceTrustRuleTests(unittest.TestCase):
    def test_default_and_admission_rules_use_abt_namespace(self):
        self.assertEqual(
            "ABT002", AuditTrustReceiverAcceptanceTrustError("invalid").rule_id
        )
        verified = verified_snapshot()
        with self.assertRaises(AuditTrustReceiverAcceptanceTrustError) as raised:
            create_state(report(verified, admitted=False), verified)
        self.assertEqual("ABT004", raised.exception.rule_id)
        self.assertTrue(raised.exception.denied)

    def test_transition_schema_stays_compatible_with_inherited_cli(self):
        snapshot = verified_snapshot()
        state = create_state(report(snapshot), snapshot)
        transition = verified_transition(snapshot["candidate"])
        updated = append_transition(state, report(transition), transition)
        self.assertEqual(
            {
                "previous_checkpoint_id",
                "previous_state_id",
                "entry_delta",
                "trust_entry_delta",
                "generation_delta",
            },
            set(updated["entries"][-1]["transition"]),
        )


if __name__ == "__main__":
    unittest.main()
