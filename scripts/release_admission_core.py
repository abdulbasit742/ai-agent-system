"""Release-admission engine synchronized to the reviewed wheel boundary."""
from __future__ import annotations

if __package__:
    from scripts import release_admission_core_legacy as _legacy
    from scripts.release_admission_core_legacy import *  # noqa: F401,F403
    from scripts.validate_wheel import EXPECTED_MODULES, EXPECTED_SCRIPTS
else:  # Direct execution/import from the scripts directory.
    import release_admission_core_legacy as _legacy
    from release_admission_core_legacy import *  # type: ignore # noqa: F401,F403
    from validate_wheel import EXPECTED_MODULES, EXPECTED_SCRIPTS

_ORIGINAL_DEFAULT_POLICY = _legacy.default_policy


def default_policy():
    """Return policy artifacts sourced from the reviewed wheel validator."""
    policy = _ORIGINAL_DEFAULT_POLICY()
    policy["artifacts"]["modules"] = sorted(EXPECTED_MODULES)
    policy["artifacts"]["console_scripts"] = sorted(EXPECTED_SCRIPTS)
    return policy


# Legacy functions resolve this global at call time, so CLI/init behavior stays synchronized.
_legacy.default_policy = default_policy
