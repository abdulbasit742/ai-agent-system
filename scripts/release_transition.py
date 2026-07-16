#!/usr/bin/env python3
"""Compare verified release bundles and gate unsafe release transitions."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from scripts.release_bundle import MANIFEST_NAME, ReleaseBundleError, verify_bundle
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from release_bundle import MANIFEST_NAME, ReleaseBundleError, verify_bundle

POLICY_VERSION = 1
TRANSITION_VERSION = 1
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class TransitionError(ValueError):
    """Raised when transition policy or release evidence is malformed."""


def canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(policy)).hexdigest()


def _exact_fields(payload: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise TransitionError(f"{label} fields do not match the reviewed schema")
    return payload


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise TransitionError(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TransitionError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def default_policy() -> dict[str, Any]:
    return {
        "version": POLICY_VERSION,
        "identity": {
            "allow_replay": False,
            "allow_same_version_mutation": False,
            "require_source_epoch_increase": True,
        },
        "changes": {
            "allow_module_additions": True,
            "allow_module_removals": False,
            "allow_module_changes": True,
            "allow_console_script_additions": True,
            "allow_console_script_removals": False,
            "max_runtime_dependency_increase": 0,
            "allow_license_changes": False,
        },
    }


def _normalize_policy(payload: Any) -> dict[str, Any]:
    root = _exact_fields(payload, {"version", "identity", "changes"}, "transition policy")
    if root["version"] != POLICY_VERSION:
        raise TransitionError(f"transition policy version must be {POLICY_VERSION}")
    identity = _exact_fields(
        root["identity"],
        {"allow_replay", "allow_same_version_mutation", "require_source_epoch_increase"},
        "identity policy",
    )
    changes = _exact_fields(
        root["changes"],
        {
            "allow_module_additions",
            "allow_module_removals",
            "allow_module_changes",
            "allow_console_script_additions",
            "allow_console_script_removals",
            "max_runtime_dependency_increase",
            "allow_license_changes",
        },
        "change policy",
    )
    return {
        "version": POLICY_VERSION,
        "identity": {
            "allow_replay": _boolean(identity["allow_replay"], "identity.allow_replay"),
            "allow_same_version_mutation": _boolean(
                identity["allow_same_version_mutation"],
                "identity.allow_same_version_mutation",
            ),
            "require_source_epoch_increase": _boolean(
                identity["require_source_epoch_increase"],
                "identity.require_source_epoch_increase",
            ),
        },
        "changes": {
            "allow_module_additions": _boolean(
                changes["allow_module_additions"], "changes.allow_module_additions"
            ),
            "allow_module_removals": _boolean(
                changes["allow_module_removals"], "changes.allow_module_removals"
            ),
            "allow_module_changes": _boolean(
                changes["allow_module_changes"], "changes.allow_module_changes"
            ),
            "allow_console_script_additions": _boolean(
                changes["allow_console_script_additions"],
                "changes.allow_console_script_additions",
            ),
            "allow_console_script_removals": _boolean(
                changes["allow_console_script_removals"],
                "changes.allow_console_script_removals",
            ),
            "max_runtime_dependency_increase": _integer(
                changes["max_runtime_dependency_increase"],
                "changes.max_runtime_dependency_increase",
            ),
            "allow_license_changes": _boolean(
                changes["allow_license_changes"], "changes.allow_license_changes"
            ),
        },
    }


def load_policy(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise TransitionError("transition policy must not be a symlink")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TransitionError(f"transition policy not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise TransitionError(f"invalid transition policy: {path}") from exc
    return _normalize_policy(payload)


def _numeric_version(value: Any) -> tuple[int, ...]:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        raise TransitionError(
            "release transition rollback checks require canonical numeric dot-separated versions"
        )
    parts = value.split(".")
    if any(len(part) > 1 and part.startswith("0") for part in parts):
        raise TransitionError("release versions must not contain leading-zero numeric segments")
    return tuple(int(part) for part in parts)


def _hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise TransitionError(f"{label} is malformed")
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TransitionError(f"unable to read verified {label}: {path.name}") from exc
    if not isinstance(payload, dict):
        raise TransitionError(f"verified {label} root must be an object")
    return payload


def _bundle_summary(bundle_dir: Path) -> dict[str, Any]:
    try:
        verified = verify_bundle(bundle_dir)
    except ReleaseBundleError as exc:
        raise TransitionError(str(exc)) from exc
    directory = bundle_dir.resolve()
    manifest = _load_json(directory / MANIFEST_NAME, "release manifest")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise TransitionError("verified release manifest has no artifacts")

    module_hashes: dict[str, str] = {}
    module_licenses: dict[str, str] = {}
    package_licenses: set[str] = set()
    commands: set[str] = set()
    dependencies: set[int] = set()
    wheel_digests: dict[str, str] = {}

    for record in artifacts:
        if not isinstance(record, dict):
            raise TransitionError("verified release artifact record is malformed")
        filename = record.get("filename")
        digest = record.get("sha256")
        if not isinstance(filename, str) or not isinstance(digest, str):
            raise TransitionError("verified release artifact identity is malformed")
        wheel_digests[filename] = digest
        scripts = record.get("console_scripts")
        runtime_dependencies = record.get("runtime_dependencies")
        if not isinstance(scripts, list) or any(not isinstance(item, str) for item in scripts):
            raise TransitionError("verified console script evidence is malformed")
        if isinstance(runtime_dependencies, bool) or not isinstance(runtime_dependencies, int):
            raise TransitionError("verified runtime dependency evidence is malformed")
        commands.update(scripts)
        dependencies.add(runtime_dependencies)

        evidence = record.get("evidence")
        if not isinstance(evidence, dict) or not isinstance(evidence.get("sbom"), dict):
            raise TransitionError("verified SBOM reference is malformed")
        sbom_name = evidence["sbom"].get("filename")
        if not isinstance(sbom_name, str):
            raise TransitionError("verified SBOM filename is malformed")
        sbom = _load_json(directory / sbom_name, "SBOM")
        packages = sbom.get("packages")
        files = sbom.get("files")
        if not isinstance(packages, list) or len(packages) != 1 or not isinstance(packages[0], dict):
            raise TransitionError("verified SBOM package evidence is malformed")
        package = packages[0]
        for field in ("licenseDeclared", "licenseConcluded"):
            license_id = package.get(field)
            if not isinstance(license_id, str) or not license_id:
                raise TransitionError("verified SBOM package license is malformed")
            package_licenses.add(license_id)
        if not isinstance(files, list):
            raise TransitionError("verified SBOM module evidence is malformed")
        for item in files:
            if not isinstance(item, dict):
                raise TransitionError("verified SBOM module record is malformed")
            name = item.get("fileName")
            license_id = item.get("licenseConcluded")
            checksums = item.get("checksums")
            if not isinstance(name, str) or not isinstance(license_id, str):
                raise TransitionError("verified SBOM module identity is malformed")
            if not isinstance(checksums, list):
                raise TransitionError("verified SBOM module checksums are malformed")
            checksum_map = {
                entry.get("algorithm"): entry.get("checksumValue")
                for entry in checksums
                if isinstance(entry, dict)
            }
            sha256 = checksum_map.get("SHA256")
            if not isinstance(sha256, str) or not HEX_64.fullmatch(sha256):
                raise TransitionError("verified SBOM module SHA-256 is malformed")
            if name in module_hashes and module_hashes[name] != sha256:
                raise TransitionError(f"verified wheels disagree about module bytes: {name}")
            if name in module_licenses and module_licenses[name] != license_id:
                raise TransitionError(f"verified wheels disagree about module license: {name}")
            module_hashes[name] = sha256
            module_licenses[name] = license_id

    if len(dependencies) != 1:
        raise TransitionError("verified artifacts disagree about runtime dependency count")

    version = verified["version"]
    _numeric_version(version)
    return {
        "project": verified["project"],
        "version": version,
        "release_id": _hex(verified["release_id"], HEX_64, "release id"),
        "source_commit": _hex(verified["source_commit"], HEX_40, "source commit"),
        "source_date_epoch": verified["source_date_epoch"],
        "artifacts": dict(sorted(wheel_digests.items())),
        "modules": dict(sorted(module_hashes.items())),
        "module_licenses": dict(sorted(module_licenses.items())),
        "package_licenses": sorted(package_licenses),
        "console_scripts": sorted(commands),
        "runtime_dependencies": next(iter(dependencies)),
    }


def _set_changes(previous: set[str], candidate: set[str]) -> dict[str, list[str]]:
    return {
        "added": sorted(candidate - previous),
        "removed": sorted(previous - candidate),
    }


def _module_changes(previous: dict[str, str], candidate: dict[str, str]) -> dict[str, list[str]]:
    previous_names = set(previous)
    candidate_names = set(candidate)
    return {
        "added": sorted(candidate_names - previous_names),
        "removed": sorted(previous_names - candidate_names),
        "changed": sorted(
            name
            for name in previous_names & candidate_names
            if previous[name] != candidate[name]
        ),
    }


def _violation(rule_id: str, message: str) -> dict[str, str]:
    return {"rule_id": rule_id, "message": message}


def evaluate_summaries(
    previous: dict[str, Any],
    candidate: dict[str, Any],
    policy: dict[str, Any],
    *,
    expected_previous_release_id: str | None = None,
    expected_candidate_source_commit: str | None = None,
    expected_candidate_version: str | None = None,
    expected_candidate_release_id: str | None = None,
) -> dict[str, Any]:
    normalized_policy = _normalize_policy(policy)
    previous_version = _numeric_version(previous.get("version"))
    candidate_version = _numeric_version(candidate.get("version"))
    violations: list[dict[str, str]] = []

    if previous.get("project") != candidate.get("project"):
        violations.append(_violation("TRN001", "candidate project differs from trusted release"))
    if candidate_version < previous_version:
        violations.append(_violation("TRN002", "candidate version is older than trusted release"))

    same_release = candidate.get("release_id") == previous.get("release_id")
    same_version = candidate_version == previous_version
    if same_release and not normalized_policy["identity"]["allow_replay"]:
        violations.append(_violation("TRN003", "candidate release is an exact replay"))
    if (
        same_version
        and not same_release
        and not normalized_policy["identity"]["allow_same_version_mutation"]
    ):
        violations.append(
            _violation("TRN004", "candidate changes release bytes without changing package version")
        )

    previous_epoch = previous.get("source_date_epoch")
    candidate_epoch = candidate.get("source_date_epoch")
    if (
        isinstance(previous_epoch, bool)
        or not isinstance(previous_epoch, int)
        or isinstance(candidate_epoch, bool)
        or not isinstance(candidate_epoch, int)
    ):
        raise TransitionError("release source epochs must be integers")
    if candidate_epoch < previous_epoch:
        violations.append(_violation("TRN005", "candidate source epoch is older than trusted release"))
    elif (
        candidate_epoch == previous_epoch
        and not same_release
        and normalized_policy["identity"]["require_source_epoch_increase"]
    ):
        violations.append(
            _violation("TRN006", "candidate reuses the trusted source epoch for a different release")
        )
    if candidate.get("source_commit") == previous.get("source_commit") and not same_release:
        violations.append(
            _violation("TRN007", "candidate reuses the trusted source commit for different release bytes")
        )

    if expected_previous_release_id is not None and previous.get("release_id") != expected_previous_release_id:
        violations.append(_violation("TRN008", "trusted release does not match expected release id"))
    if (
        expected_candidate_source_commit is not None
        and candidate.get("source_commit") != expected_candidate_source_commit
    ):
        violations.append(_violation("TRN009", "candidate does not match expected source commit"))
    if expected_candidate_version is not None and candidate.get("version") != expected_candidate_version:
        violations.append(_violation("TRN010", "candidate does not match expected package version"))
    if expected_candidate_release_id is not None and candidate.get("release_id") != expected_candidate_release_id:
        violations.append(_violation("TRN011", "candidate does not match expected release id"))

    module_changes = _module_changes(previous.get("modules", {}), candidate.get("modules", {}))
    command_changes = _set_changes(
        set(previous.get("console_scripts", [])), set(candidate.get("console_scripts", []))
    )
    license_changes = _set_changes(
        set(previous.get("package_licenses", [])) | set(previous.get("module_licenses", {}).values()),
        set(candidate.get("package_licenses", [])) | set(candidate.get("module_licenses", {}).values()),
    )
    dependency_delta = candidate.get("runtime_dependencies", 0) - previous.get(
        "runtime_dependencies", 0
    )

    controls = normalized_policy["changes"]
    if module_changes["added"] and not controls["allow_module_additions"]:
        violations.append(_violation("TRN020", "candidate adds runtime modules"))
    if module_changes["removed"] and not controls["allow_module_removals"]:
        violations.append(_violation("TRN021", "candidate removes runtime modules"))
    if module_changes["changed"] and not controls["allow_module_changes"]:
        violations.append(_violation("TRN022", "candidate changes runtime module bytes"))
    if command_changes["added"] and not controls["allow_console_script_additions"]:
        violations.append(_violation("TRN023", "candidate adds console commands"))
    if command_changes["removed"] and not controls["allow_console_script_removals"]:
        violations.append(_violation("TRN024", "candidate removes console commands"))
    if dependency_delta > controls["max_runtime_dependency_increase"]:
        violations.append(_violation("TRN025", "candidate increases runtime dependencies beyond policy"))
    if (license_changes["added"] or license_changes["removed"]) and not controls[
        "allow_license_changes"
    ]:
        violations.append(_violation("TRN026", "candidate changes the reviewed license set"))

    changes = {
        "artifacts": _set_changes(
            set(previous.get("artifacts", {})), set(candidate.get("artifacts", {}))
        ),
        "modules": module_changes,
        "console_scripts": command_changes,
        "licenses": license_changes,
        "runtime_dependencies": {
            "previous": previous.get("runtime_dependencies", 0),
            "candidate": candidate.get("runtime_dependencies", 0),
            "delta": dependency_delta,
        },
    }
    if any(item["rule_id"] in {"TRN002", "TRN005"} for item in violations):
        risk = "rollback"
    elif any(item["rule_id"] == "TRN003" for item in violations):
        risk = "replay"
    elif module_changes["removed"] or command_changes["removed"] or license_changes["added"] or license_changes["removed"] or dependency_delta > 0:
        risk = "breaking"
    elif module_changes["added"] or module_changes["changed"]:
        risk = "code-change"
    elif command_changes["added"]:
        risk = "interface-change"
    else:
        risk = "none"

    violations = sorted(violations, key=lambda item: (item["rule_id"], item["message"]))
    report: dict[str, Any] = {
        "transition_version": TRANSITION_VERSION,
        "accepted": not violations,
        "risk": risk,
        "policy": {
            "version": normalized_policy["version"],
            "sha256": policy_sha256(normalized_policy),
        },
        "previous": {
            "project": previous.get("project"),
            "version": previous.get("version"),
            "release_id": previous.get("release_id"),
            "source_commit": previous.get("source_commit"),
            "source_date_epoch": previous_epoch,
        },
        "candidate": {
            "project": candidate.get("project"),
            "version": candidate.get("version"),
            "release_id": candidate.get("release_id"),
            "source_commit": candidate.get("source_commit"),
            "source_date_epoch": candidate_epoch,
        },
        "expected": {
            "previous_release_id": expected_previous_release_id,
            "candidate_source_commit": expected_candidate_source_commit,
            "candidate_version": expected_candidate_version,
            "candidate_release_id": expected_candidate_release_id,
        },
        "changes": changes,
        "violations": violations,
    }
    report["transition_id"] = hashlib.sha256(canonical_json(report)).hexdigest()
    return report


def evaluate_bundles(
    previous_bundle: Path,
    candidate_bundle: Path,
    policy: dict[str, Any],
    **expected: str | None,
) -> dict[str, Any]:
    previous = _bundle_summary(previous_bundle)
    candidate = _bundle_summary(candidate_bundle)
    return evaluate_summaries(previous, candidate, policy, **expected)


def _policy_outside_bundles(policy_path: Path, bundles: list[Path]) -> None:
    if policy_path.is_symlink():
        raise TransitionError("transition policy must not be a symlink")
    resolved = policy_path.resolve()
    for bundle in bundles:
        root = bundle.resolve()
        if resolved == root or root in resolved.parents:
            raise TransitionError("transition policy must be consumer-owned and outside release bundles")


def _text(report: dict[str, Any]) -> str:
    lines = [
        f"accepted: {'yes' if report['accepted'] else 'no'}",
        f"risk: {report['risk']}",
        f"transition_id: {report['transition_id']}",
        f"previous: {report['previous']['version']} {report['previous']['release_id']}",
        f"candidate: {report['candidate']['version']} {report['candidate']['release_id']}",
    ]
    if report["violations"]:
        lines.append("violations:")
        lines.extend(
            f"- {item['rule_id']}: {item['message']}" for item in report["violations"]
        )
    else:
        lines.append("violations: none")
    for category in ("modules", "console_scripts", "licenses"):
        detail = report["changes"][category]
        lines.append(
            f"{category}: added={detail['added']} removed={detail['removed']}"
            + (f" changed={detail['changed']}" if "changed" in detail else "")
        )
    return "\n".join(lines)


def _emit(report: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(_text(report))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("path", nargs="?", type=Path)
    policy_parser.add_argument("--init", action="store_true")
    policy_parser.add_argument("--force", action="store_true")

    compare = subparsers.add_parser("compare")
    compare.add_argument("previous_bundle", type=Path)
    compare.add_argument("candidate_bundle", type=Path)
    compare.add_argument("--policy", type=Path)
    compare.add_argument("--format", choices=("json", "text"), default="json")

    gate = subparsers.add_parser("gate")
    gate.add_argument("previous_bundle", type=Path)
    gate.add_argument("candidate_bundle", type=Path)
    gate.add_argument("--policy", required=True, type=Path)
    gate.add_argument("--expected-previous-release-id", required=True)
    gate.add_argument("--expected-candidate-source-commit", required=True)
    gate.add_argument("--expected-candidate-version", required=True)
    gate.add_argument("--expected-candidate-release-id")
    gate.add_argument("--format", choices=("json", "text"), default="json")

    args = parser.parse_args(argv)
    try:
        if args.command == "policy":
            path = args.path or Path(".release-transition.json")
            if args.init:
                if path.exists() and not args.force:
                    raise TransitionError(f"refusing to overwrite existing policy: {path}")
                if path.is_symlink():
                    raise TransitionError("transition policy output must not be a symlink")
                path.write_bytes(canonical_json(default_policy()))
                print(json.dumps({"created": str(path), "sha256": policy_sha256(default_policy())}, indent=2))
                return 0
            policy = load_policy(path)
            print(json.dumps({"valid": True, "path": str(path), "sha256": policy_sha256(policy)}, indent=2))
            return 0

        bundles = [args.previous_bundle, args.candidate_bundle]
        if args.policy is not None:
            _policy_outside_bundles(args.policy, bundles)
            policy = load_policy(args.policy)
        else:
            policy = default_policy()

        if args.command == "compare":
            report = evaluate_bundles(args.previous_bundle, args.candidate_bundle, policy)
            _emit(report, args.format)
            return 0

        expected_previous_release_id = _hex(
            args.expected_previous_release_id.lower(), HEX_64, "expected previous release id"
        )
        expected_candidate_source_commit = _hex(
            args.expected_candidate_source_commit.lower(), HEX_40, "expected candidate source commit"
        )
        _numeric_version(args.expected_candidate_version)
        expected_candidate_release_id = None
        if args.expected_candidate_release_id is not None:
            expected_candidate_release_id = _hex(
                args.expected_candidate_release_id.lower(),
                HEX_64,
                "expected candidate release id",
            )
        report = evaluate_bundles(
            args.previous_bundle,
            args.candidate_bundle,
            policy,
            expected_previous_release_id=expected_previous_release_id,
            expected_candidate_source_commit=expected_candidate_source_commit,
            expected_candidate_version=args.expected_candidate_version,
            expected_candidate_release_id=expected_candidate_release_id,
        )
        _emit(report, args.format)
        return 0 if report["accepted"] else 1
    except (OSError, TransitionError) as exc:
        print(f"Release transition error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
