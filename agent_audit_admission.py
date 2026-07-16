#!/usr/bin/env python3
"""Consumer-owned admission policy for verified portable audit evidence bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from agent_audit_bundle import (
    AuditEvidenceBundleError,
    MANIFEST_NAME,
    load_manifest,
    verify_bundle,
)

POLICY_VERSION = 1
MAX_POLICY_BYTES = 1_000_000
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_BUNDLE_TYPES = frozenset({"snapshot", "transition"})
ALLOWED_RELATIONS = frozenset({"same", "right-descendant"})
SEALED_MODES = frozenset({"forbidden", "optional", "required-all"})

POLICY_FIELDS = {"version", "bundle", "candidate", "selection", "transition"}
BUNDLE_FIELDS = {
    "allowed_types",
    "max_files",
    "max_bytes",
    "min_proofs",
    "max_proofs",
    "sealed_segments",
}
CANDIDATE_FIELDS = {
    "min_generation",
    "max_generation",
    "min_segment_count",
    "max_segment_count",
    "allowed_catalog_ids",
}
SELECTION_FIELDS = {
    "required_segment_indexes",
    "allowed_segment_indexes",
    "required_segment_ids",
    "allowed_segment_ids",
}
TRANSITION_FIELDS = {
    "allowed_relations",
    "require_direct_predecessor",
    "min_generation_delta",
    "max_generation_delta",
    "allowed_previous_catalog_ids",
}


class AuditBundleAdmissionError(ValueError):
    """Raised when policy input or bundle evidence cannot be processed safely."""

    def __init__(self, message: str, *, rule_id: str = "AUA000") -> None:
        super().__init__(message)
        self.rule_id = rule_id


class _DuplicateKeyError(ValueError):
    pass


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(validate_policy(policy))).hexdigest()


def _decision_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"audit-bundle-admission-decision-v1\0" + canonical_json(payload)
    ).hexdigest()


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuditBundleAdmissionError(
            f"{label} fields do not match the reviewed schema"
        )
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuditBundleAdmissionError(
            f"{label} must be an integer greater than or equal to {minimum}"
        )
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise AuditBundleAdmissionError(f"{label} must be a boolean")
    return value


def _enum(value: Any, allowed: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise AuditBundleAdmissionError(
            f"{label} must be one of {sorted(allowed)}"
        )
    return value


def _string_list(
    value: Any,
    label: str,
    *,
    allowed: frozenset[str] | None = None,
    hashes: bool = False,
    require_nonempty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or (require_nonempty and not value):
        qualifier = "non-empty " if require_nonempty else ""
        raise AuditBundleAdmissionError(f"{label} must be a {qualifier}array")
    if any(not isinstance(item, str) or not item for item in value):
        raise AuditBundleAdmissionError(
            f"{label} must contain only non-empty strings"
        )
    if value != sorted(value) or len(value) != len(set(value)):
        raise AuditBundleAdmissionError(
            f"{label} must be sorted and contain no duplicates"
        )
    if allowed is not None and any(item not in allowed for item in value):
        raise AuditBundleAdmissionError(f"{label} contains an unsupported value")
    if hashes and any(not HEX_64.fullmatch(item) for item in value):
        raise AuditBundleAdmissionError(
            f"{label} must contain lowercase 64-character hexadecimal IDs"
        )
    return list(value)


def _integer_list(value: Any, label: str) -> list[int]:
    if not isinstance(value, list):
        raise AuditBundleAdmissionError(f"{label} must be an array")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 1
        for item in value
    ):
        raise AuditBundleAdmissionError(
            f"{label} must contain only positive integer indexes"
        )
    if value != sorted(value) or len(value) != len(set(value)):
        raise AuditBundleAdmissionError(
            f"{label} must be sorted and contain no duplicates"
        )
    return list(value)


def default_policy() -> dict[str, Any]:
    return {
        "version": POLICY_VERSION,
        "bundle": {
            "allowed_types": ["snapshot", "transition"],
            "max_files": 1024,
            "max_bytes": 268435456,
            "min_proofs": 1,
            "max_proofs": 128,
            "sealed_segments": "optional",
        },
        "candidate": {
            "min_generation": 1,
            "max_generation": 1000000,
            "min_segment_count": 1,
            "max_segment_count": 1000000,
            "allowed_catalog_ids": [],
        },
        "selection": {
            "required_segment_indexes": [],
            "allowed_segment_indexes": [],
            "required_segment_ids": [],
            "allowed_segment_ids": [],
        },
        "transition": {
            "allowed_relations": ["right-descendant"],
            "require_direct_predecessor": False,
            "min_generation_delta": 1,
            "max_generation_delta": 1000000,
            "allowed_previous_catalog_ids": [],
        },
    }


def validate_policy(value: Any) -> dict[str, Any]:
    root = _exact(value, POLICY_FIELDS, "audit bundle admission policy")
    if root["version"] != POLICY_VERSION:
        raise AuditBundleAdmissionError(
            f"admission policy version must be {POLICY_VERSION}"
        )
    bundle = _exact(root["bundle"], BUNDLE_FIELDS, "bundle policy")
    candidate = _exact(root["candidate"], CANDIDATE_FIELDS, "candidate policy")
    selection = _exact(root["selection"], SELECTION_FIELDS, "selection policy")
    transition = _exact(
        root["transition"], TRANSITION_FIELDS, "transition policy"
    )

    normalized = {
        "version": POLICY_VERSION,
        "bundle": {
            "allowed_types": _string_list(
                bundle["allowed_types"],
                "bundle.allowed_types",
                allowed=ALLOWED_BUNDLE_TYPES,
                require_nonempty=True,
            ),
            "max_files": _integer(bundle["max_files"], "bundle.max_files", 1),
            "max_bytes": _integer(bundle["max_bytes"], "bundle.max_bytes", 1),
            "min_proofs": _integer(bundle["min_proofs"], "bundle.min_proofs", 1),
            "max_proofs": _integer(bundle["max_proofs"], "bundle.max_proofs", 1),
            "sealed_segments": _enum(
                bundle["sealed_segments"],
                SEALED_MODES,
                "bundle.sealed_segments",
            ),
        },
        "candidate": {
            "min_generation": _integer(
                candidate["min_generation"], "candidate.min_generation", 1
            ),
            "max_generation": _integer(
                candidate["max_generation"], "candidate.max_generation", 1
            ),
            "min_segment_count": _integer(
                candidate["min_segment_count"],
                "candidate.min_segment_count",
                1,
            ),
            "max_segment_count": _integer(
                candidate["max_segment_count"],
                "candidate.max_segment_count",
                1,
            ),
            "allowed_catalog_ids": _string_list(
                candidate["allowed_catalog_ids"],
                "candidate.allowed_catalog_ids",
                hashes=True,
            ),
        },
        "selection": {
            "required_segment_indexes": _integer_list(
                selection["required_segment_indexes"],
                "selection.required_segment_indexes",
            ),
            "allowed_segment_indexes": _integer_list(
                selection["allowed_segment_indexes"],
                "selection.allowed_segment_indexes",
            ),
            "required_segment_ids": _string_list(
                selection["required_segment_ids"],
                "selection.required_segment_ids",
                hashes=True,
            ),
            "allowed_segment_ids": _string_list(
                selection["allowed_segment_ids"],
                "selection.allowed_segment_ids",
                hashes=True,
            ),
        },
        "transition": {
            "allowed_relations": _string_list(
                transition["allowed_relations"],
                "transition.allowed_relations",
                allowed=ALLOWED_RELATIONS,
                require_nonempty=True,
            ),
            "require_direct_predecessor": _boolean(
                transition["require_direct_predecessor"],
                "transition.require_direct_predecessor",
            ),
            "min_generation_delta": _integer(
                transition["min_generation_delta"],
                "transition.min_generation_delta",
            ),
            "max_generation_delta": _integer(
                transition["max_generation_delta"],
                "transition.max_generation_delta",
            ),
            "allowed_previous_catalog_ids": _string_list(
                transition["allowed_previous_catalog_ids"],
                "transition.allowed_previous_catalog_ids",
                hashes=True,
            ),
        },
    }

    if normalized["bundle"]["min_proofs"] > normalized["bundle"]["max_proofs"]:
        raise AuditBundleAdmissionError(
            "bundle.min_proofs must not exceed bundle.max_proofs"
        )
    if (
        normalized["candidate"]["min_generation"]
        > normalized["candidate"]["max_generation"]
    ):
        raise AuditBundleAdmissionError(
            "candidate.min_generation must not exceed candidate.max_generation"
        )
    if (
        normalized["candidate"]["min_segment_count"]
        > normalized["candidate"]["max_segment_count"]
    ):
        raise AuditBundleAdmissionError(
            "candidate.min_segment_count must not exceed candidate.max_segment_count"
        )
    if (
        normalized["transition"]["min_generation_delta"]
        > normalized["transition"]["max_generation_delta"]
    ):
        raise AuditBundleAdmissionError(
            "transition.min_generation_delta must not exceed transition.max_generation_delta"
        )

    required_indexes = set(normalized["selection"]["required_segment_indexes"])
    allowed_indexes = set(normalized["selection"]["allowed_segment_indexes"])
    if allowed_indexes and not required_indexes <= allowed_indexes:
        raise AuditBundleAdmissionError(
            "required segment indexes must be a subset of allowed segment indexes"
        )
    required_ids = set(normalized["selection"]["required_segment_ids"])
    allowed_ids = set(normalized["selection"]["allowed_segment_ids"])
    if allowed_ids and not required_ids <= allowed_ids:
        raise AuditBundleAdmissionError(
            "required segment IDs must be a subset of allowed segment IDs"
        )
    return normalized


def load_policy(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditBundleAdmissionError(
            "admission policy must be a regular non-symlink file"
        )
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_POLICY_BYTES:
        raise AuditBundleAdmissionError(
            "admission policy size is outside the reviewed boundary"
        )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        _DuplicateKeyError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise AuditBundleAdmissionError(
            f"admission policy is not strict JSON: {exc}"
        ) from exc
    return validate_policy(payload)


def _safe_write_new(path: Path, payload: dict[str, Any]) -> None:
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise AuditBundleAdmissionError(
            "refusing to overwrite existing admission policy"
        )
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise AuditBundleAdmissionError(
            "admission policy parent must be a regular non-symlink directory"
        )
    with path.open("xb") as handle:
        handle.write(canonical_json(payload))
        handle.flush()
        os.fsync(handle.fileno())


def _deny(
    violations: list[dict[str, Any]],
    rule_id: str,
    message: str,
    **context: Any,
) -> None:
    item: dict[str, Any] = {"rule_id": rule_id, "message": message}
    for key in sorted(context):
        item[key] = context[key]
    violations.append(item)


def evaluate_bundle(
    bundle_dir: Path,
    policy: dict[str, Any],
    *,
    expected_bundle_id: str,
    expected_candidate_checkpoint_id: str,
    expected_previous_checkpoint_id: str | None = None,
) -> dict[str, Any]:
    normalized_policy = validate_policy(policy)
    try:
        verified = verify_bundle(
            Path(bundle_dir),
            expected_bundle_id=expected_bundle_id,
            expected_candidate_checkpoint_id=expected_candidate_checkpoint_id,
            expected_previous_checkpoint_id=expected_previous_checkpoint_id,
        )
        manifest = load_manifest(Path(bundle_dir) / MANIFEST_NAME)
    except AuditEvidenceBundleError as exc:
        raise AuditBundleAdmissionError(
            f"audit evidence bundle verification failed ({exc.rule_id}): {exc}"
        ) from exc

    violations: list[dict[str, Any]] = []
    bundle_policy = normalized_policy["bundle"]
    candidate_policy = normalized_policy["candidate"]
    selection_policy = normalized_policy["selection"]
    transition_policy = normalized_policy["transition"]

    bundle_type = verified["bundle_type"]
    if bundle_type not in bundle_policy["allowed_types"]:
        _deny(
            violations,
            "AUA001",
            "bundle type is not allowed",
            bundle_type=bundle_type,
        )

    if verified["files"] > bundle_policy["max_files"]:
        _deny(
            violations,
            "AUA002",
            "bundle file count exceeds policy",
            actual=verified["files"],
            maximum=bundle_policy["max_files"],
        )
    if verified["bytes"] > bundle_policy["max_bytes"]:
        _deny(
            violations,
            "AUA002",
            "bundle byte count exceeds policy",
            actual=verified["bytes"],
            maximum=bundle_policy["max_bytes"],
        )

    if not (
        bundle_policy["min_proofs"]
        <= verified["proof_count"]
        <= bundle_policy["max_proofs"]
    ):
        _deny(
            violations,
            "AUA003",
            "bundle proof count is outside policy",
            actual=verified["proof_count"],
            minimum=bundle_policy["min_proofs"],
            maximum=bundle_policy["max_proofs"],
        )

    sealed_mode = bundle_policy["sealed_segments"]
    if sealed_mode == "forbidden" and verified["segment_count"] != 0:
        _deny(
            violations,
            "AUA004",
            "sealed segment evidence is forbidden by policy",
            actual=verified["segment_count"],
        )
    if (
        sealed_mode == "required-all"
        and verified["segment_count"] != verified["proof_count"]
    ):
        _deny(
            violations,
            "AUA004",
            "every selected segment must include sealed evidence",
            selected=verified["proof_count"],
            sealed=verified["segment_count"],
        )

    candidate = verified["candidate"]
    if not (
        candidate_policy["min_generation"]
        <= candidate["generation"]
        <= candidate_policy["max_generation"]
    ):
        _deny(
            violations,
            "AUA005",
            "candidate generation is outside policy",
            actual=candidate["generation"],
            minimum=candidate_policy["min_generation"],
            maximum=candidate_policy["max_generation"],
        )
    if not (
        candidate_policy["min_segment_count"]
        <= candidate["segment_count"]
        <= candidate_policy["max_segment_count"]
    ):
        _deny(
            violations,
            "AUA006",
            "candidate segment count is outside policy",
            actual=candidate["segment_count"],
            minimum=candidate_policy["min_segment_count"],
            maximum=candidate_policy["max_segment_count"],
        )
    allowed_candidate_catalogs = set(candidate_policy["allowed_catalog_ids"])
    if (
        allowed_candidate_catalogs
        and candidate["catalog_id"] not in allowed_candidate_catalogs
    ):
        _deny(
            violations,
            "AUA007",
            "candidate catalog ID is not allowed",
            catalog_id=candidate["catalog_id"],
        )

    entries = manifest["entries"]
    selected_indexes = [entry["segment_index"] for entry in entries]
    selected_ids = [entry["segment_id"] for entry in entries]
    sealed_indexes = [
        entry["segment_index"] for entry in entries if entry["segment_included"]
    ]
    selected_index_set = set(selected_indexes)
    selected_id_set = set(selected_ids)

    missing_indexes = sorted(
        set(selection_policy["required_segment_indexes"])
        - selected_index_set
    )
    if missing_indexes:
        _deny(
            violations,
            "AUA008",
            "required segment indexes are missing",
            missing=missing_indexes,
        )
    allowed_indexes = set(selection_policy["allowed_segment_indexes"])
    disallowed_indexes = (
        sorted(selected_index_set - allowed_indexes) if allowed_indexes else []
    )
    if disallowed_indexes:
        _deny(
            violations,
            "AUA009",
            "selected segment indexes are outside the allowlist",
            disallowed=disallowed_indexes,
        )

    missing_ids = sorted(
        set(selection_policy["required_segment_ids"]) - selected_id_set
    )
    if missing_ids:
        _deny(
            violations,
            "AUA010",
            "required segment IDs are missing",
            missing=missing_ids,
        )
    allowed_ids = set(selection_policy["allowed_segment_ids"])
    disallowed_ids = sorted(selected_id_set - allowed_ids) if allowed_ids else []
    if disallowed_ids:
        _deny(
            violations,
            "AUA011",
            "selected segment IDs are outside the allowlist",
            disallowed=disallowed_ids,
        )

    generation_delta: int | None = None
    if bundle_type == "transition":
        consistency = verified["consistency"]
        previous = verified["previous"]
        relation = consistency["relation"]
        if relation not in transition_policy["allowed_relations"]:
            _deny(
                violations,
                "AUA012",
                "transition consistency relation is not allowed",
                relation=relation,
            )
        if (
            transition_policy["require_direct_predecessor"]
            and not consistency["direct_predecessor_verified"]
        ):
            _deny(
                violations,
                "AUA013",
                "transition must verify the direct predecessor",
            )
        generation_delta = candidate["generation"] - previous["generation"]
        if not (
            transition_policy["min_generation_delta"]
            <= generation_delta
            <= transition_policy["max_generation_delta"]
        ):
            _deny(
                violations,
                "AUA014",
                "transition generation delta is outside policy",
                actual=generation_delta,
                minimum=transition_policy["min_generation_delta"],
                maximum=transition_policy["max_generation_delta"],
            )
        allowed_previous = set(
            transition_policy["allowed_previous_catalog_ids"]
        )
        if allowed_previous and previous["catalog_id"] not in allowed_previous:
            _deny(
                violations,
                "AUA015",
                "previous catalog ID is not allowed",
                catalog_id=previous["catalog_id"],
            )

    violations.sort(
        key=lambda item: (
            item["rule_id"],
            json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    )
    identity = {
        "bundle_id": verified["bundle_id"],
        "bundle_type": bundle_type,
        "candidate_checkpoint_id": candidate["checkpoint_id"],
        "candidate_catalog_id": candidate["catalog_id"],
        "previous_checkpoint_id": (
            verified["previous"]["checkpoint_id"]
            if verified["previous"] is not None
            else None
        ),
        "previous_catalog_id": (
            verified["previous"]["catalog_id"]
            if verified["previous"] is not None
            else None
        ),
    }
    core = {
        "admitted": not violations,
        "policy_sha256": policy_sha256(normalized_policy),
        "identity": identity,
        "evidence": {
            "files": verified["files"],
            "bytes": verified["bytes"],
            "proof_count": verified["proof_count"],
            "sealed_segment_count": verified["segment_count"],
            "selected_segment_indexes": selected_indexes,
            "selected_segment_ids": selected_ids,
            "sealed_segment_indexes": sealed_indexes,
            "candidate_generation": candidate["generation"],
            "candidate_segment_count": candidate["segment_count"],
            "generation_delta": generation_delta,
        },
        "violations": violations,
    }
    return {**core, "decision_id": _decision_id(core)}


def _emit(
    payload: dict[str, Any], output_format: str, *, stream: Any = None
) -> None:
    if stream is None:
        stream = sys.stdout
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2), file=stream)
        return
    for key in ("valid", "admitted", "policy_sha256", "decision_id"):
        if key in payload:
            print(f"{key}: {payload[key]}", file=stream)
    identity = payload.get("identity")
    if isinstance(identity, dict):
        for key in (
            "bundle_id",
            "bundle_type",
            "candidate_checkpoint_id",
            "candidate_catalog_id",
            "previous_checkpoint_id",
            "previous_catalog_id",
        ):
            print(f"{key}: {identity.get(key)}", file=stream)
    for violation in payload.get("violations", []):
        print(f"- {violation['rule_id']}: {violation['message']}", file=stream)


def _policy_must_be_external(policy_path: Path, bundle_path: Path) -> None:
    policy = policy_path.resolve()
    bundle = bundle_path.resolve()
    try:
        policy.relative_to(bundle)
    except ValueError:
        return
    raise AuditBundleAdmissionError(
        "consumer admission policy must not be loaded from inside the bundle",
        rule_id="AUA016",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    initialize = subparsers.add_parser("init")
    initialize.add_argument("output", type=Path)
    initialize.add_argument("--format", choices=("json", "text"), default="json")

    validate = subparsers.add_parser("validate")
    validate.add_argument("policy", type=Path)
    validate.add_argument("--format", choices=("json", "text"), default="json")

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("bundle", type=Path)
    evaluate.add_argument("--policy", type=Path, required=True)
    evaluate.add_argument("--expected-bundle-id", required=True)
    evaluate.add_argument("--expected-candidate-checkpoint-id", required=True)
    evaluate.add_argument("--expected-previous-checkpoint-id")
    evaluate.add_argument("--format", choices=("json", "text"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            policy = default_policy()
            _safe_write_new(args.output, policy)
            _emit(
                {
                    "valid": True,
                    "created": str(args.output),
                    "policy_sha256": policy_sha256(policy),
                },
                args.format,
            )
            return 0

        if args.command == "validate":
            policy = load_policy(args.policy)
            _emit(
                {
                    "valid": True,
                    "policy_sha256": policy_sha256(policy),
                    "policy": policy,
                },
                args.format,
            )
            return 0

        _policy_must_be_external(args.policy, args.bundle)
        policy = load_policy(args.policy)
        report = evaluate_bundle(
            args.bundle,
            policy,
            expected_bundle_id=args.expected_bundle_id,
            expected_candidate_checkpoint_id=args.expected_candidate_checkpoint_id,
            expected_previous_checkpoint_id=args.expected_previous_checkpoint_id,
        )
        _emit(report, args.format)
        return 0 if report["admitted"] else 1
    except AuditBundleAdmissionError as exc:
        _emit(
            {
                "valid": False,
                "admitted": False,
                "rule_id": exc.rule_id,
                "error": str(exc),
            },
            getattr(args, "format", "json"),
            stream=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
