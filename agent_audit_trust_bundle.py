#!/usr/bin/env python3
"""Public audit trust handoff bundle interface."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import agent_audit_trust_bundle_core as _core


def _trust_checksums_text(
    records: Iterable[dict[str, Any]], manifest_path: Path
) -> str:
    lines = [f"{record['sha256']}  {record['path']}" for record in records]
    lines.append(f"{_core._sha256_file(manifest_path)}  {_core.MANIFEST_NAME}")
    return "\n".join(sorted(lines)) + "\n"


_core._checksums_text = _trust_checksums_text

from agent_audit_trust_bundle_core import *  # noqa: F401,F403,E402


if __name__ == "__main__":
    raise SystemExit(_core.main())
