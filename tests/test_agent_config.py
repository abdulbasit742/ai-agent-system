import json
import tempfile
import unittest
from pathlib import Path

from agent_config import ConfigError, config_template, load_config


class AgentConfigTests(unittest.TestCase):
    def write_config(self, root: Path, payload: dict) -> Path:
        path = root / ".agent-system.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_default_template_enables_all_packs(self):
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(self.write_config(Path(directory), config_template()))
        self.assertEqual(["core", "boundaries", "workflows"], config["enabled_packs"])
        self.assertIn("BAS001", config["enabled_rules"])
        self.assertIn("BAS024", config["enabled_rules"])

    def test_optional_pack_can_be_disabled(self):
        payload = config_template()
        payload["enabled_packs"] = ["core", "boundaries"]
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(self.write_config(Path(directory), payload))
        self.assertNotIn("BAS020", config["enabled_rules"])
        self.assertIn("BAS010", config["enabled_rules"])

    def test_non_core_rule_can_be_disabled(self):
        payload = config_template()
        payload["disabled_rules"] = ["bas022"]
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(self.write_config(Path(directory), payload))
        self.assertEqual(["BAS022"], config["disabled_rules"])
        self.assertNotIn("BAS022", config["enabled_rules"])

    def test_core_pack_cannot_be_disabled(self):
        payload = config_template()
        payload["enabled_packs"] = ["boundaries", "workflows"]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigError, "mandatory rule pack"):
                load_config(self.write_config(Path(directory), payload))

    def test_core_rule_cannot_be_disabled(self):
        payload = config_template()
        payload["disabled_rules"] = ["BAS003"]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigError, "mandatory core rule"):
                load_config(self.write_config(Path(directory), payload))

    def test_unknown_pack_and_rule_fail_closed(self):
        for field, value, message in (
            ("enabled_packs", ["core", "unknown"], "unknown rule pack"),
            ("disabled_rules", ["BAS999"], "unknown rule id"),
        ):
            payload = config_template()
            payload[field] = value
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ConfigError, message):
                    load_config(self.write_config(Path(directory), payload))


if __name__ == "__main__":
    unittest.main()
