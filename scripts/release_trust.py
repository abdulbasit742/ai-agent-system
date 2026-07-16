#!/usr/bin/env python3
"""Maintain a pinned, tamper-evident consumer trust state for verified releases."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - non-POSIX platforms fail closed at write time.
    fcntl = None

try:
    from scripts.release_transition import (
        TransitionError,
        _bundle_summary,
        _numeric_version,
        _policy_outside_bundles,
        default_policy,
        evaluate_bundles,
        load_policy,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from release_transition import (
        TransitionError,
        _bundle_summary,
        _numeric_version,
        _policy_outside_bundles,
        default_policy,
        evaluate_bundles,
        load_policy,
    )

STATE_VERSION = 1
ENTRY_VERSION = 1
ZERO_HASH = "0" * 64
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_STATE_BYTES = 5_000_000
MAX_ENTRIES = 10_000


class TrustStateError(ValueError):
    """Raised when consumer trust state or its pinned inputs are invalid."""


def canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _exact_fields(payload: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise TrustStateError(f"{label} fields do not match the reviewed schema")
    return payload


def _hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise TrustStateError(f"{label} is malformed")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TrustStateError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def _release_identity(summary: Any) -> dict[str, Any]:
    if not isinstance(summary, dict):
        raise TrustStateError("release identity must be an object")
    project = summary.get("project")
    version = summary.get("version")
    if not isinstance(project, str) or not project.strip():
        raise TrustStateError("release project must be a non-empty string")
    try:
        _numeric_version(version)
    except TransitionError as exc:
        raise TrustStateError(str(exc)) from exc
    return {
        "project": project.strip(),
        "version": version,
        "release_id": _hex(summary.get("release_id"), HEX_64, "release id"),
        "source_commit": _hex(summary.get("source_commit"), HEX_40, "source commit"),
        "source_date_epoch": _integer(summary.get("source_date_epoch"), "source date epoch"),
    }


def _entry_payload(
    sequence: int,
    kind: str,
    previous_entry_hash: str,
    release: dict[str, Any],
    transition: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "entry_version": ENTRY_VERSION,
        "sequence": sequence,
        "kind": kind,
        "previous_entry_hash": previous_entry_hash,
        "release": release,
        "transition": transition,
    }


def _seal_entry(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "entry_hash": _sha256(payload)}


def _state_payload(project: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    last = entries[-1]
    release = last["release"]
    return {
        "state_version": STATE_VERSION,
        "project": project,
        "entries": entries,
        "head": {
            "sequence": last["sequence"],
            "entry_hash": last["entry_hash"],
            "release_id": release["release_id"],
            "source_commit": release["source_commit"],
            "version": release["version"],
        },
    }


def _seal_state(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "state_id": _sha256(payload)}


def create_state(anchor_summary: dict[str, Any]) -> dict[str, Any]:
    release = _release_identity(anchor_summary)
    entry = _seal_entry(_entry_payload(1, "anchor", ZERO_HASH, release, None))
    return _seal_state(_state_payload(release["project"], [entry]))


def append_transition(
    state: dict[str, Any],
    candidate_summary: dict[str, Any],
    transition_report: dict[str, Any],
) -> dict[str, Any]:
    normalized = validate_state(state)
    candidate = _release_identity(candidate_summary)
    if candidate["project"] != normalized["project"]:
        raise TrustStateError("candidate project differs from trust state")
    release_ids = {entry["release"]["release_id"] for entry in normalized["entries"]}
    if candidate["release_id"] in release_ids:
        raise TrustStateError("candidate release already exists in trust history")
    if not isinstance(transition_report, dict) or transition_report.get("accepted") is not True:
        raise TrustStateError("only an accepted transition can advance trust state")
    transition_id = _hex(transition_report.get("transition_id"), HEX_64, "transition id")
    policy = transition_report.get("policy")
    if not isinstance(policy, dict):
        raise TrustStateError("transition policy evidence is malformed")
    policy_sha = _hex(policy.get("sha256"), HEX_64, "transition policy sha256")
    previous_release = normalized["entries"][-1]["release"]
    report_previous = transition_report.get("previous")
    report_candidate = transition_report.get("candidate")
    if not isinstance(report_previous, dict) or not isinstance(report_candidate, dict):
        raise TrustStateError("transition release evidence is malformed")
    if report_previous.get("release_id") != previous_release["release_id"]:
        raise TrustStateError("transition does not start from the trust-state head")
    if report_candidate.get("release_id") != candidate["release_id"]:
        raise TrustStateError("transition candidate does not match the release being recorded")
    transition = {
        "previous_release_id": previous_release["release_id"],
        "transition_id": transition_id,
        "policy_sha256": policy_sha,
    }
    entries = list(normalized["entries"])
    entries.append(
        _seal_entry(
            _entry_payload(
                len(entries) + 1,
                "transition",
                entries[-1]["entry_hash"],
                candidate,
                transition,
            )
        )
    )
    return _seal_state(_state_payload(normalized["project"], entries))


def validate_state(payload: Any) -> dict[str, Any]:
    root = _exact_fields(
        payload,
        {"state_version", "project", "entries", "head", "state_id"},
        "trust state",
    )
    if root["state_version"] != STATE_VERSION:
        raise TrustStateError(f"trust state version must be {STATE_VERSION}")
    project = root["project"]
    if not isinstance(project, str) or not project.strip() or project != project.strip():
        raise TrustStateError("trust state project must be a canonical non-empty string")
    entries = root["entries"]
    if not isinstance(entries, list) or not entries:
        raise TrustStateError("trust state must contain at least one entry")
    if len(entries) > MAX_ENTRIES:
        raise TrustStateError("trust state contains too many entries")

    normalized_entries: list[dict[str, Any]] = []
    previous_hash = ZERO_HASH
    previous_release_id: str | None = None
    seen_release_ids: set[str] = set()
    for index, raw_entry in enumerate(entries, 1):
        entry = _exact_fields(
            raw_entry,
            {
                "entry_version",
                "sequence",
                "kind",
                "previous_entry_hash",
                "release",
                "transition",
                "entry_hash",
            },
            f"trust entry {index}",
        )
        if entry["entry_version"] != ENTRY_VERSION:
            raise TrustStateError(f"trust entry {index} version is unsupported")
        if entry["sequence"] != index:
            raise TrustStateError(f"trust entry {index} sequence is not contiguous")
        kind = entry["kind"]
        if kind not in {"anchor", "transition"} or (index == 1) != (kind == "anchor"):
            raise TrustStateError(f"trust entry {index} kind is invalid")
        if entry["previous_entry_hash"] != previous_hash:
            raise TrustStateError(f"trust entry {index} previous hash does not match")
        release = _release_identity(
            _exact_fields(
                entry["release"],
                {"project", "version", "release_id", "source_commit", "source_date_epoch"},
                f"trust entry {index} release",
            )
        )
        if release["project"] != project:
            raise TrustStateError(f"trust entry {index} project differs from state project")
        if release["release_id"] in seen_release_ids:
            raise TrustStateError("trust history contains a duplicate release id")
        seen_release_ids.add(release["release_id"])

        transition = entry["transition"]
        if index == 1:
            if transition is not None:
                raise TrustStateError("anchor trust entry must not contain transition evidence")
        else:
            transition = _exact_fields(
                transition,
                {"previous_release_id", "transition_id", "policy_sha256"},
                f"trust entry {index} transition",
            )
            if transition["previous_release_id"] != previous_release_id:
                raise TrustStateError(f"trust entry {index} previous release does not match history")
            transition = {
                "previous_release_id": _hex(
                    transition["previous_release_id"], HEX_64, "previous release id"
                ),
                "transition_id": _hex(transition["transition_id"], HEX_64, "transition id"),
                "policy_sha256": _hex(
                    transition["policy_sha256"], HEX_64, "transition policy sha256"
                ),
            }

        entry_payload = _entry_payload(index, kind, previous_hash, release, transition)
        entry_hash = _hex(entry["entry_hash"], HEX_64, "entry hash")
        if entry_hash != _sha256(entry_payload):
            raise TrustStateError(f"trust entry {index} hash does not match")
        sealed = {**entry_payload, "entry_hash": entry_hash}
        normalized_entries.append(sealed)
        previous_hash = entry_hash
        previous_release_id = release["release_id"]

    state_payload = _state_payload(project, normalized_entries)
    head = _exact_fields(
        root["head"],
        {"sequence", "entry_hash", "release_id", "source_commit", "version"},
        "trust state head",
    )
    if head != state_payload["head"]:
        raise TrustStateError("trust state head does not match the final history entry")
    state_id = _hex(root["state_id"], HEX_64, "state id")
    if state_id != _sha256(state_payload):
        raise TrustStateError("trust state id does not match canonical state")
    return {**state_payload, "state_id": state_id}


def load_state(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise TrustStateError("trust state must not be a symlink")
    try:
        size = path.stat().st_size
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise TrustStateError(f"trust state not found: {path}") from exc
    except OSError as exc:
        raise TrustStateError(f"unable to read trust state: {path}") from exc
    if size > MAX_STATE_BYTES or len(raw) > MAX_STATE_BYTES:
        raise TrustStateError("trust state exceeds the reviewed size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustStateError("trust state is not valid UTF-8 canonical JSON") from exc
    normalized = validate_state(payload)
    if raw != canonical_json(normalized):
        raise TrustStateError("trust state is not canonically serialized")
    return normalized


def _outside_bundles(path: Path, bundles: list[Path], label: str) -> None:
    resolved = path.resolve()
    for bundle in bundles:
        root = bundle.resolve()
        if resolved == root or root in resolved.parents:
            raise TrustStateError(f"{label} must be consumer-owned and outside release bundles")


@contextmanager
def _state_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    if fcntl is None:
        raise TrustStateError("trust-state locking is unavailable on this platform")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    if lock_path.is_symlink():
        raise TrustStateError("trust-state lock must not be a symlink")
    flags = os.O_CREAT | os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise TrustStateError(f"unable to open trust-state lock: {lock_path}") from exc
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _atomic_write(path: Path, state: dict[str, Any], *, require_absent: bool) -> None:
    if path.is_symlink():
        raise TrustStateError("trust state output must not be a symlink")
    if require_absent and path.exists():
        raise TrustStateError(f"refusing to overwrite existing trust state: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(canonical_json(state))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _matches_release(identity: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(identity.get(key) == expected.get(key) for key in expected)


def _check_expected_anchor(
    summary: dict[str, Any], release_id: str, source_commit: str, version: str
) -> dict[str, Any]:
    identity = _release_identity(summary)
    expected = {
        "release_id": _hex(release_id.lower(), HEX_64, "expected release id"),
        "source_commit": _hex(source_commit.lower(), HEX_40, "expected source commit"),
        "version": version,
    }
    try:
        _numeric_version(version)
    except TransitionError as exc:
        raise TrustStateError(str(exc)) from exc
    if not _matches_release(identity, expected):
        raise TrustStateError("verified release does not match the pinned anchor identity")
    return identity


def _head_identity(state: dict[str, Any]) -> dict[str, Any]:
    return state["entries"][-1]["release"]


def _text(payload: dict[str, Any]) -> str:
    lines = []
    for key in ("valid", "created", "advanced", "state_id", "previous_state_id"):
        if key in payload:
            lines.append(f"{key}: {payload[key]}")
    head = payload.get("head")
    if isinstance(head, dict):
        lines.append(
            f"head: sequence={head['sequence']} version={head['version']} release_id={head['release_id']}"
        )
    transition = payload.get("transition")
    if isinstance(transition, dict):
        lines.append(f"transition_id: {transition.get('transition_id')}")
        for violation in transition.get("violations", []):
            lines.append(f"- {violation['rule_id']}: {violation['message']}")
    for violation in payload.get("violations", []):
        lines.append(f"- {violation['rule_id']}: {violation['message']}")
    return "\n".join(lines)


def _emit(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        print(_text(payload))


def _pin(value: str, pattern: re.Pattern[str], label: str) -> str:
    return _hex(value.lower(), pattern, label)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init")
    init.add_argument("state", type=Path)
    init.add_argument("bundle", type=Path)
    init.add_argument("--expected-release-id", required=True)
    init.add_argument("--expected-source-commit", required=True)
    init.add_argument("--expected-version", required=True)
    init.add_argument("--format", choices=("json", "text"), default="json")

    verify = subparsers.add_parser("verify")
    verify.add_argument("state", type=Path)
    verify.add_argument("--expected-state-id", required=True)
    verify.add_argument("--bundle", type=Path)
    verify.add_argument("--format", choices=("json", "text"), default="json")

    advance = subparsers.add_parser("advance")
    advance.add_argument("state", type=Path)
    advance.add_argument("previous_bundle", type=Path)
    advance.add_argument("candidate_bundle", type=Path)
    advance.add_argument("--policy", required=True, type=Path)
    advance.add_argument("--expected-state-id", required=True)
    advance.add_argument("--expected-candidate-source-commit", required=True)
    advance.add_argument("--expected-candidate-version", required=True)
    advance.add_argument("--expected-candidate-release-id")
    advance.add_argument("--format", choices=("json", "text"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            _outside_bundles(args.state, [args.bundle], "trust state")
            with _state_lock(args.state, exclusive=True):
                if args.state.exists():
                    raise TrustStateError(f"refusing to overwrite existing trust state: {args.state}")
                anchor = _check_expected_anchor(
                    _bundle_summary(args.bundle),
                    args.expected_release_id,
                    args.expected_source_commit,
                    args.expected_version,
                )
                state = create_state(anchor)
                _atomic_write(args.state, state, require_absent=True)
            _emit({"created": str(args.state), "state_id": state["state_id"], "head": state["head"]}, args.format)
            return 0

        expected_state_id = _pin(args.expected_state_id, HEX_64, "expected state id")
        bundles = [args.bundle] if args.command == "verify" and args.bundle else []
        if args.command == "advance":
            bundles = [args.previous_bundle, args.candidate_bundle]
        _outside_bundles(args.state, bundles, "trust state")

        with _state_lock(args.state, exclusive=args.command == "advance"):
            state = load_state(args.state)
            if state["state_id"] != expected_state_id:
                raise TrustStateError("trust state does not match the externally pinned state id")

            if args.command == "verify":
                if args.bundle is not None:
                    bundle_identity = _release_identity(_bundle_summary(args.bundle))
                    if bundle_identity != _head_identity(state):
                        raise TrustStateError("verified bundle does not match the trust-state head")
                _emit({"valid": True, "state_id": state["state_id"], "head": state["head"], "entries": len(state["entries"])}, args.format)
                return 0

            _outside_bundles(args.policy, bundles, "transition policy")
            _policy_outside_bundles(args.policy, bundles)
            policy = load_policy(args.policy)
            previous = _release_identity(_bundle_summary(args.previous_bundle))
            if previous != _head_identity(state):
                raise TrustStateError("previous verified bundle does not match the trust-state head")
            candidate = _release_identity(_bundle_summary(args.candidate_bundle))
            expected_candidate_commit = _pin(
                args.expected_candidate_source_commit, HEX_40, "expected candidate source commit"
            )
            try:
                _numeric_version(args.expected_candidate_version)
            except TransitionError as exc:
                raise TrustStateError(str(exc)) from exc
            expected_candidate_release_id = None
            if args.expected_candidate_release_id is not None:
                expected_candidate_release_id = _pin(
                    args.expected_candidate_release_id, HEX_64, "expected candidate release id"
                )
            report = evaluate_bundles(
                args.previous_bundle,
                args.candidate_bundle,
                policy,
                expected_previous_release_id=state["head"]["release_id"],
                expected_candidate_source_commit=expected_candidate_commit,
                expected_candidate_version=args.expected_candidate_version,
                expected_candidate_release_id=expected_candidate_release_id,
            )
            if not report["accepted"]:
                _emit(
                    {
                        "advanced": False,
                        "state_id": state["state_id"],
                        "head": state["head"],
                        "transition": report,
                        "violations": [
                            {"rule_id": "TST004", "message": "candidate transition was denied"}
                        ],
                    },
                    args.format,
                )
                return 1
            if any(
                entry["release"]["release_id"] == candidate["release_id"]
                for entry in state["entries"]
            ):
                _emit(
                    {
                        "advanced": False,
                        "state_id": state["state_id"],
                        "head": state["head"],
                        "transition": report,
                        "violations": [
                            {"rule_id": "TST003", "message": "candidate release already exists in trust history"}
                        ],
                    },
                    args.format,
                )
                return 1
            updated = append_transition(state, candidate, report)
            _atomic_write(args.state, updated, require_absent=False)
        _emit(
            {
                "advanced": True,
                "previous_state_id": state["state_id"],
                "state_id": updated["state_id"],
                "head": updated["head"],
                "transition": {
                    "transition_id": report["transition_id"],
                    "policy_sha256": report["policy"]["sha256"],
                },
            },
            args.format,
        )
        return 0
    except (OSError, TransitionError, TrustStateError) as exc:
        print(f"Release trust-state error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
