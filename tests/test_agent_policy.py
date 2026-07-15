import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from agent_policy import PolicyError, apply_policy, load_policy, policy_template


class AgentPolicyTests(unittest.TestCase):
    def write_policy(self, root: Path, payload: dict) -> Path:
        path = root / ".agent-system-policy.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def finding(self, **updates):
        item = {
            "rule_id": "BAS003",
            "path": "tests/fixtures/token.txt",
            "fingerprint": "a" * 64,
            "severity": "high",
        }
        item.update(updates)
        return item

    def test_valid_policy_suppresses_by_rule_and_glob(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = policy_template()
            policy = load_policy(self.write_policy(Path(directory), payload), today=date(2026, 7, 15))
            active, suppressed = apply_policy([self.finding()], policy)
        self.assertEqual([], active)
        self.assertEqual("example-reviewed-fixture", suppressed[0]["suppression"]["id"])

    def test_fingerprint_must_match_when_present(self):
        payload = policy_template()
        payload["suppressions"][0]["fingerprint"] = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            policy = load_policy(self.write_policy(Path(directory), payload), today=date(2026, 7, 15))
            active, suppressed = apply_policy([self.finding()], policy)
        self.assertEqual(1, len(active))
        self.assertEqual([], suppressed)

    def test_expired_entry_never_suppresses(self):
        payload = policy_template()
        payload["suppressions"][0]["expires"] = "2026-07-14"
        with tempfile.TemporaryDirectory() as directory:
            policy = load_policy(self.write_policy(Path(directory), payload), today=date(2026, 7, 15))
            active, suppressed = apply_policy([self.finding()], policy)
        self.assertEqual(["example-reviewed-fixture"], policy["expired_ids"])
        self.assertEqual(1, len(active))
        self.assertEqual([], suppressed)

    def test_reason_owner_and_expiry_are_required(self):
        for field in ("reason", "owner", "expires"):
            payload = policy_template()
            payload["suppressions"][0].pop(field)
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(PolicyError):
                    load_policy(self.write_policy(Path(directory), payload))

    def test_duplicate_ids_are_rejected(self):
        payload = policy_template()
        payload["suppressions"].append(dict(payload["suppressions"][0]))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(PolicyError, "duplicate"):
                load_policy(self.write_policy(Path(directory), payload))


if __name__ == "__main__":
    unittest.main()
