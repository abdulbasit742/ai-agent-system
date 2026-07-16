import unittest

from agent_audit_trust_receiver_acceptance_trust import (
    AuditTrustReceiverAcceptanceTrustError,
    create_state,
)
from test_audit_trust_receiver_acceptance_trust import report, verified_snapshot


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


if __name__ == "__main__":
    unittest.main()
