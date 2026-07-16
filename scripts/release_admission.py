#!/usr/bin/env python3
"""Validate release-admission policies and evaluate verified release bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

try:
    from scripts.release_bundle import MANIFEST_NAME, ReleaseBundleError, verify_bundle
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from release_bundle import MANIFEST_NAME, ReleaseBundleError, verify_bundle

POLICY_VERSION = 1
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
LICENSE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
CHECKSUM_ALGORITHMS = frozenset({"SHA1", "SHA256"})


class AdmissionError(ValueError):
    """Raised when admission policy or bundle evidence is malformed."""


def canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(policy)).hexdigest()


def _exact_fields(payload: Any, required: set[str], label: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != required:
        raise AdmissionError(f"{label} fields do not match the reviewed schema")
    return payload


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdmissionError(f"{label} must be a non-empty string")
    return value.strip()


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AdmissionError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise AdmissionError(f"{label} must be a boolean")
    return value


def _string_list(
    value: Any,
    label: str,
    *,
    pattern: re.Pattern[str] | None = None,
    nonempty: bool = True,
) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise AdmissionError(f"{label} must be an array of non-empty strings")
    if nonempty and not value:
        raise AdmissionError(f"{label} must not be empty")
    if value != sorted(value) or len(value) != len(set(value)):
        raise AdmissionError(f"{label} must be sorted and contain no duplicates")
    if pattern is not None and any(not pattern.fullmatch(item) for item in value):
        raise AdmissionError(f"{label} contains an unsafe value")
    return list(value)


def _repository_url(value: Any) -> str:
    repository = _nonempty_string(value, "source.repository").rstrip("/")
    parsed = urlparse(repository)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.params
        or not parsed.path.strip("/")
        or repository.endswith(".git")
    ):
        raise AdmissionError("source.repository must be a canonical HTTPS repository URL without credentials, query, fragment, or .git suffix")
    return repository


def _relative_path(value: Any, label: str) -> str:
    text = _nonempty_string(value, label).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "." in path.parts or text.startswith("/"):
        raise AdmissionError(f"{label} must be a safe repository-relative path")
    if any(not part or not SAFE_TOKEN.fullmatch(part) for part in path.parts):
        raise AdmissionError(f"{label} contains an unsafe path component")
    return path.as_posix()


def load_policy(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdmissionError(f"policy file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(f"invalid admission policy: {path}") from exc

    root = _exact_fields(
        payload,
        {"version", "project", "source", "artifacts", "sbom", "provenance"},
        "admission policy",
    )
    if root["version"] != POLICY_VERSION:
        raise AdmissionError(f"admission policy version must be {POLICY_VERSION}")

    project = _exact_fields(root["project"], {"name", "allowed_versions"}, "project policy")
    source = _exact_fields(root["source"], {"repository"}, "source policy")
    artifacts = _exact_fields(
        root["artifacts"],
        {
            "count",
            "max_size_bytes",
            "modules",
            "console_scripts",
            "max_runtime_dependencies",
        },
        "artifact policy",
    )
    sbom = _exact_fields(
        root["sbom"],
        {
            "spdx_version",
            "data_license",
            "allowed_licenses",
            "required_checksum_algorithms",
            "files_analyzed",
        },
        "SBOM policy",
    )
    provenance = _exact_fields(
        root["provenance"],
        {
            "statement_type",
            "predicate_type",
            "accept_unsigned",
            "builder_workflow",
            "build_definition",
        },
        "provenance policy",
    )

    normalized = {
        "version": POLICY_VERSION,
        "project": {
            "name": _nonempty_string(project["name"], "project.name"),
            "allowed_versions": _string_list(project["allowed_versions"], "project.allowed_versions"),
        },
        "source": {"repository": _repository_url(source["repository"])},
        "artifacts": {
            "count": _integer(artifacts["count"], "artifacts.count", 1),
            "max_size_bytes": _integer(artifacts["max_size_bytes"], "artifacts.max_size_bytes", 1),
            "modules": _string_list(artifacts["modules"], "artifacts.modules", pattern=SAFE_TOKEN),
            "console_scripts": _string_list(
                artifacts["console_scripts"], "artifacts.console_scripts", pattern=SAFE_TOKEN
            ),
            "max_runtime_dependencies": _integer(
                artifacts["max_runtime_dependencies"], "artifacts.max_runtime_dependencies", 0
            ),
        },
        "sbom": {
            "spdx_version": _nonempty_string(sbom["spdx_version"], "sbom.spdx_version"),
            "data_license": _nonempty_string(sbom["data_license"], "sbom.data_license"),
            "allowed_licenses": _string_list(
                sbom["allowed_licenses"], "sbom.allowed_licenses", pattern=LICENSE_ID
            ),
            "required_checksum_algorithms": _string_list(
                sbom["required_checksum_algorithms"], "sbom.required_checksum_algorithms"
            ),
            "files_analyzed": _boolean(sbom["files_analyzed"], "sbom.files_analyzed"),
        },
        "provenance": {
            "statement_type": _nonempty_string(
                provenance["statement_type"], "provenance.statement_type"
            ),
            "predicate_type": _nonempty_string(
                provenance["predicate_type"], "provenance.predicate_type"
            ),
            "accept_unsigned": _boolean(
                provenance["accept_unsigned"], "provenance.accept_unsigned"
            ),
            "builder_workflow": _relative_path(
                provenance["builder_workflow"], "provenance.builder_workflow"
            ),
            "build_definition": _relative_path(
                provenance["build_definition"], "provenance.build_definition"
            ),
        },
    }
    algorithms = set(normalized["sbom"]["required_checksum_algorithms"])
    if not algorithms or not algorithms <= CHECKSUM_ALGORITHMS:
        raise AdmissionError("sbom.required_checksum_algorithms must be a non-empty subset of SHA1 and SHA256")
    if "SHA256" not in algorithms:
        raise AdmissionError("sbom.required_checksum_algorithms must include SHA256")
    return normalized


def default_policy() -> dict[str, Any]:
    return {
        "version": POLICY_VERSION,
        "project": {
            "name": "basit-agent-system",
            "allowed_versions": ["0.1.0"],
        },
        "source": {
            "repository": "https://github.com/abdulbasit742/ai-agent-system",
        },
        "artifacts": {
            "count": 1,
            "max_size_bytes": 1048576,
            "modules": [
                "agent_baseline.py",
                "agent_changed_lines.py",
                "agent_cli.py",
                "agent_config.py",
                "agent_git.py",
                "agent_policy.py",
                "agent_system.py",
                "agent_version.py",
            ],
            "console_scripts": [
                "agent-changed-lines",
                "agent-system",
                "basit-agent",
                "basit-agent-lines",
            ],
            "max_runtime_dependencies": 0,
        },
        "sbom": {
            "spdx_version": "SPDX-2.3",
            "data_license": "CC0-1.0",
            "allowed_licenses": ["MIT"],
            "required_checksum_algorithms": ["SHA1", "SHA256"],
            "files_analyzed": True,
        },
        "provenance": {
            "statement_type": "https://in-toto.io/Statement/v1",
            "predicate_type": "https://slsa.dev/provenance/v1",
            "accept_unsigned": True,
            "builder_workflow": ".github/workflows/ci.yml",
            "build_definition": "docs/reproducible-releases.md",
        },
    }


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(f"unable to read verified {label}: {path.name}") from exc
    if not isinstance(payload, dict):
        raise AdmissionError(f"verified {label} root must be an object")
    return payload


def _commit(value: str) -> str:
    normalized = value.strip().lower()
    if not HEX_40.fullmatch(normalized):
        raise AdmissionError("expected source commit must be an exact 40-character hexadecimal SHA")
    return normalized


def _release_id(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not HEX_64.fullmatch(normalized):
        raise AdmissionError("expected release id must be an exact 64-character hexadecimal digest")
    return normalized


def _violation(items: list[dict[str, str]], rule_id: str, message: str, artifact: str = "") -> None:
    entry = {"rule_id": rule_id, "message": message}
    if artifact:
        entry["artifact"] = artifact
    items.append(entry)


def evaluate_bundle(
    bundle_dir: Path,
    policy: dict[str, Any],
    expected_source_commit: str,
    expected_version: str,
    expected_release_id: str | None = None,
) -> dict[str, Any]:
    commit = _commit(expected_source_commit)
    version = _nonempty_string(expected_version, "expected version")
    release_id = _release_id(expected_release_id)
    try:
        verified = verify_bundle(bundle_dir)
    except ReleaseBundleError as exc:
        raise AdmissionError(f"release bundle verification failed: {exc}") from exc

    directory = bundle_dir.resolve()
    manifest = _read_json(directory / MANIFEST_NAME, "release manifest")
    violations: list[dict[str, str]] = []

    if manifest["project"] != policy["project"]["name"]:
        _violation(violations, "ADM001", "project name is not allowed")
    if manifest["version"] not in policy["project"]["allowed_versions"]:
        _violation(violations, "ADM002", "package version is not in the policy allowlist")
    if manifest["version"] != version:
        _violation(violations, "ADM003", "package version does not match the expected version")
    if manifest["source"]["commit"] != commit:
        _violation(violations, "ADM004", "source commit does not match the expected commit")
    if release_id is not None and manifest["release_id"] != release_id:
        _violation(violations, "ADM005", "release id does not match the expected release id")

    records = manifest["artifacts"]
    if len(records) != policy["artifacts"]["count"]:
        _violation(violations, "ADM010", "artifact count does not match policy")

    repository = policy["source"]["repository"]
    repository_uri = f"git+{repository}.git"
    allowed_licenses = set(policy["sbom"]["allowed_licenses"])
    required_algorithms = set(policy["sbom"]["required_checksum_algorithms"])

    for record in records:
        name = record["filename"]
        if record["size"] > policy["artifacts"]["max_size_bytes"]:
            _violation(violations, "ADM011", "artifact exceeds the maximum allowed size", name)
        if record["runtime_dependencies"] > policy["artifacts"]["max_runtime_dependencies"]:
            _violation(violations, "ADM014", "runtime dependency count exceeds policy", name)

        sbom_path = directory / record["evidence"]["sbom"]["filename"]
        provenance_path = directory / record["evidence"]["provenance"]["filename"]
        sbom = _read_json(sbom_path, "SBOM")
        provenance = _read_json(provenance_path, "provenance")

        files = sbom.get("files", [])
        module_names = sorted(item.get("fileName") for item in files if isinstance(item, dict))
        if module_names != policy["artifacts"]["modules"] or record["modules"] != len(module_names):
            _violation(violations, "ADM012", "module boundary does not match policy", name)

        internal = provenance.get("predicate", {}).get("buildDefinition", {}).get(
            "internalParameters", {}
        )
        if internal.get("consoleScripts") != policy["artifacts"]["console_scripts"]:
            _violation(violations, "ADM013", "console-script boundary does not match policy", name)
        if internal.get("runtimeDependencies") != record["runtime_dependencies"]:
            _violation(violations, "ADM015", "provenance dependency count differs from the artifact", name)

        if sbom.get("spdxVersion") != policy["sbom"]["spdx_version"]:
            _violation(violations, "ADM020", "SPDX version does not match policy", name)
        if sbom.get("dataLicense") != policy["sbom"]["data_license"]:
            _violation(violations, "ADM021", "SBOM data license does not match policy", name)

        packages = sbom.get("packages", [])
        package = packages[0] if isinstance(packages, list) and len(packages) == 1 else {}
        package_licenses = {package.get("licenseDeclared"), package.get("licenseConcluded")}
        file_licenses = {
            item.get("licenseConcluded") for item in files if isinstance(item, dict)
        }
        if None in package_licenses or not package_licenses <= allowed_licenses:
            _violation(violations, "ADM022", "package license is not allowed", name)
        if None in file_licenses or not file_licenses <= allowed_licenses:
            _violation(violations, "ADM023", "module license is not allowed", name)
        if package.get("filesAnalyzed") is not policy["sbom"]["files_analyzed"]:
            _violation(violations, "ADM024", "SBOM filesAnalyzed value does not match policy", name)

        for item in files:
            if not isinstance(item, dict):
                _violation(violations, "ADM025", "SBOM file record is malformed", name)
                continue
            algorithms = {
                checksum.get("algorithm")
                for checksum in item.get("checksums", [])
                if isinstance(checksum, dict)
            }
            if not required_algorithms <= algorithms:
                _violation(
                    violations,
                    "ADM025",
                    f"module {item.get('fileName', '<unknown>')} lacks required checksums",
                    name,
                )

        expected_namespace = f"{repository}/releases/{commit}/sbom/{record['sha256']}"
        expected_source_info = f"Built from {repository_uri}@{commit}"
        if sbom.get("documentNamespace") != expected_namespace or package.get("sourceInfo") != expected_source_info:
            _violation(violations, "ADM026", "SBOM source identity does not match policy", name)

        if provenance.get("_type") != policy["provenance"]["statement_type"]:
            _violation(violations, "ADM030", "provenance statement type does not match policy", name)
        if provenance.get("predicateType") != policy["provenance"]["predicate_type"]:
            _violation(violations, "ADM031", "provenance predicate type does not match policy", name)
        expected_subject = [{"digest": {"sha256": record["sha256"]}, "name": name}]
        if provenance.get("subject") != expected_subject:
            _violation(violations, "ADM032", "provenance subject does not bind the artifact", name)

        build_definition = provenance.get("predicate", {}).get("buildDefinition", {})
        expected_builder = (
            f"{repository}/blob/{commit}/{policy['provenance']['builder_workflow']}"
        )
        expected_build_type = (
            f"{repository}/blob/{commit}/{policy['provenance']['build_definition']}"
        )
        builder = provenance.get("predicate", {}).get("runDetails", {}).get("builder", {}).get("id")
        if builder != expected_builder:
            _violation(violations, "ADM033", "provenance builder identity does not match policy", name)
        if build_definition.get("buildType") != expected_build_type:
            _violation(violations, "ADM034", "provenance build definition does not match policy", name)
        expected_materials = [{"digest": {"sha1": commit}, "uri": f"{repository_uri}@{commit}"}]
        if build_definition.get("resolvedDependencies") != expected_materials:
            _violation(violations, "ADM035", "provenance source material does not match policy", name)
        if not policy["provenance"]["accept_unsigned"]:
            _violation(violations, "ADM036", "policy does not accept unsigned provenance", name)

    violations.sort(key=lambda item: (item["rule_id"], item.get("artifact", ""), item["message"]))
    return {
        "admitted": not violations,
        "policy": {
            "version": policy["version"],
            "sha256": policy_sha256(policy),
        },
        "release": {
            "project": verified["project"],
            "version": verified["version"],
            "release_id": verified["release_id"],
            "source_commit": verified["source_commit"],
            "artifacts": verified["artifacts"],
            "evidence_files": verified["evidence_files"],
        },
        "expected": {
            "version": version,
            "source_commit": commit,
            "release_id": release_id,
        },
        "violations": violations,
    }


def render_text(report: dict[str, Any]) -> str:
    status = "ADMITTED" if report["admitted"] else "DENIED"
    release = report["release"]
    lines = [
        f"{status}: {release['project']} {release['version']}",
        f"release_id: {release['release_id']}",
        f"source_commit: {release['source_commit']}",
        f"policy_sha256: {report['policy']['sha256']}",
    ]
    for violation in report["violations"]:
        scope = f" [{violation['artifact']}]" if "artifact" in violation else ""
        lines.append(f"- {violation['rule_id']}{scope}: {violation['message']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("policy", type=Path)

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("bundle", type=Path)
    evaluate.add_argument("--policy", required=True, type=Path)
    evaluate.add_argument("--expected-source-commit", required=True)
    evaluate.add_argument("--expected-version", required=True)
    evaluate.add_argument("--expected-release-id")
    evaluate.add_argument("--format", choices=["text", "json"], default="text")

    init = subparsers.add_parser("init")
    init.add_argument("path", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            if args.path.exists() or args.path.is_symlink():
                raise AdmissionError(f"refusing to overwrite existing policy path: {args.path}")
            args.path.parent.mkdir(parents=True, exist_ok=True)
            args.path.write_bytes(canonical_json(default_policy()))
            print(f"Created release-admission policy: {args.path}")
            return 0

        policy = load_policy(args.policy)
        if args.command == "validate":
            print(
                json.dumps(
                    {
                        "valid": True,
                        "version": policy["version"],
                        "sha256": policy_sha256(policy),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        report = evaluate_bundle(
            args.bundle,
            policy,
            args.expected_source_commit,
            args.expected_version,
            args.expected_release_id,
        )
    except AdmissionError as exc:
        print(f"Release admission error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else render_text(report))
    return 0 if report["admitted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
