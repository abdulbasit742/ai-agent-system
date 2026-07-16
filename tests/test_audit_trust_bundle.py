from pathlib import Path

from agent_audit_trust import canonical_json
import audit_trust_bundle_cases as _cases


def _write_json(path: Path, payload: dict) -> None:
    path.write_bytes(canonical_json(payload))


_cases.write_json = _write_json
AuditTrustBundleTests = _cases.AuditTrustBundleTests


if __name__ == "__main__":
    import unittest

    unittest.main()
