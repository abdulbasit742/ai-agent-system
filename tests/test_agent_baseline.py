import json
import tempfile
import unittest
from pathlib import Path

import agent_baseline as baseline
from agent_config import default_config
from agent_policy import empty_policy


class AgentBaselineTests(unittest.TestCase):
    def finding(self, **updates):
        item = {
            "fingerprint": "a" * 64,
            "rule_id": "BAS003",
            "severity": "high",
            "path": "legacy/token.txt",
            "line": 4,
            "title": "Provider token",
            "preview": "sk-x…xx",
            "fix": "Rotate it.",
        }
        item.update(updates)
        return item

    def write_baseline(self, root: Path, payload: dict) -> Path:
        path = root / ".agent-system-baseline.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_round_trip_excludes_sensitive_preview_and_fix(self):
        config = default_config()
        policy = empty_policy()
        payload = baseline.build_baseline([self.finding()], config, policy, Path("."))
        serialized = json.dumps(payload)
        self.assertNotIn("sk-x", serialized)
        self.assertNotIn("Rotate it", serialized)
        with tempfile.TemporaryDirectory() as directory:
            loaded = baseline.load_baseline(
                self.write_baseline(Path(directory), payload),
                expected_controls_sha256=baseline.controls_digest(config, policy),
            )
        self.assertEqual(1, len(loaded["findings"]))
        self.assertEqual("BAS003", loaded["findings"][0]["rule_id"])

    def test_classification_is_exact_fingerprint_only(self):
        payload = baseline.build_baseline(
            [self.finding()], default_config(), empty_policy(), Path(".")
        )
        with tempfile.TemporaryDirectory() as directory:
            loaded = baseline.load_baseline(self.write_baseline(Path(directory), payload))
        current = [
            self.finding(),
            self.finding(fingerprint="b" * 64, path="new/token.txt"),
        ]
        new, existing, resolved = baseline.classify_findings(current, loaded)
        self.assertEqual(["new"], [item["baseline_state"] for item in new])
        self.assertEqual(["existing"], [item["baseline_state"] for item in existing])
        self.assertEqual([], resolved)

    def test_moved_finding_is_new_and_old_entry_is_resolved(self):
        payload = baseline.build_baseline(
            [self.finding()], default_config(), empty_policy(), Path(".")
        )
        with tempfile.TemporaryDirectory() as directory:
            loaded = baseline.load_baseline(self.write_baseline(Path(directory), payload))
        moved = [self.finding(fingerprint="c" * 64, line=5)]
        new, existing, resolved = baseline.classify_findings(moved, loaded)
        self.assertEqual(1, len(new))
        self.assertEqual([], existing)
        self.assertEqual(1, len(resolved))

    def test_integrity_hash_rejects_manual_edit(self):
        payload = baseline.build_baseline(
            [self.finding()], default_config(), empty_policy(), Path(".")
        )
        payload["findings"][0]["line"] = 99
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_baseline(Path(directory), payload)
            with self.assertRaisesRegex(baseline.BaselineError, "integrity hash"):
                baseline.load_baseline(path)

    def test_control_scope_mismatch_fails_closed(self):
        config = default_config()
        payload = baseline.build_baseline([self.finding()], config, empty_policy(), Path("."))
        changed = default_config()
        changed["enabled_packs"] = ["core", "boundaries"]
        changed["enabled_rules"] = [rule for rule in changed["enabled_rules"] if not rule.startswith("BAS02")]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_baseline(Path(directory), payload)
            with self.assertRaisesRegex(baseline.BaselineError, "controls do not match"):
                baseline.load_baseline(
                    path,
                    expected_controls_sha256=baseline.controls_digest(changed, empty_policy()),
                )

    def test_policy_change_changes_control_digest(self):
        policy = empty_policy()
        original = baseline.controls_digest(default_config(), policy)
        policy["suppressions"] = [{
            "id": "fixture",
            "owner": "security-team",
            "reason": "Reviewed fixture for baseline digest coverage.",
            "expires": "2099-12-31",
            "rule_id": "BAS003",
            "path": "tests/**",
            "fingerprint": None,
            "expired": False,
        }]
        self.assertNotEqual(original, baseline.controls_digest(default_config(), policy))

    def test_unknown_top_level_fields_are_rejected(self):
        payload = baseline.build_baseline([], default_config(), empty_policy(), Path("."))
        payload["unexpected"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_baseline(Path(directory), payload)
            with self.assertRaisesRegex(baseline.BaselineError, "exactly"):
                baseline.load_baseline(path)


if __name__ == "__main__":
    unittest.main()
