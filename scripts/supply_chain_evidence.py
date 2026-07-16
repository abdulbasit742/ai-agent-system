#!/usr/bin/env python3
"""Create and verify deterministic SPDX SBOM and provenance evidence for wheels."""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.validate_wheel import EXPECTED_MODULES
except ModuleNotFoundError:  # Direct execution/import from the scripts directory.
    from validate_wheel import EXPECTED_MODULES

SPDX_SUFFIX = ".spdx.json"
PROVENANCE_SUFFIX = ".provenance.json"
SPDX_MEDIA_TYPE = "application/spdx+json"
PROVENANCE_MEDIA_TYPE = "application/vnd.in-toto+json"
SPDX_VERSION = "SPDX-2.3"
SPDX_DATA_LICENSE = "CC0-1.0"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
WHEEL_MEDIA_TYPE = "application/vnd.pypa.wheel+zip"
REPOSITORY = "https://github.com/abdulbasit742/ai-agent-system"
REPOSITORY_URI = "git+https://github.com/abdulbasit742/ai-agent-system.git"
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class SupplyChainEvidenceError(ValueError):
    """Raised when generated supply-chain evidence is unsafe or inconsistent."""


def canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _timestamp(epoch: int) -> str:
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError) as exc:
        raise SupplyChainEvidenceError("source date epoch is outside the supported range") from exc


def _source_identity(commit: str, epoch: int) -> tuple[str, int]:
    if not isinstance(commit, str) or not HEX_40.fullmatch(commit):
        raise SupplyChainEvidenceError("source commit must be an exact lowercase 40-character SHA")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise SupplyChainEvidenceError("source date epoch must be a non-negative integer")
    return commit, epoch


def _wheel_identity(summary: dict[str, Any]) -> tuple[str, str, list[str], int]:
    project = summary.get("project")
    version = summary.get("version")
    scripts = summary.get("console_scripts")
    dependencies = summary.get("runtime_dependencies")
    if not isinstance(project, str) or not project:
        raise SupplyChainEvidenceError("wheel project identity is malformed")
    if not isinstance(version, str) or not version:
        raise SupplyChainEvidenceError("wheel version identity is malformed")
    if (
        not isinstance(scripts, list)
        or scripts != sorted(scripts)
        or len(scripts) != len(set(scripts))
        or any(not isinstance(item, str) or not item for item in scripts)
    ):
        raise SupplyChainEvidenceError("wheel console script identity is malformed")
    if dependencies != 0:
        raise SupplyChainEvidenceError("supply-chain evidence requires a dependency-free wheel")
    return project, version, scripts, dependencies


def evidence_names(wheel_name: str) -> dict[str, str]:
    if not isinstance(wheel_name, str) or not SAFE_NAME.fullmatch(wheel_name) or not wheel_name.endswith(".whl"):
        raise SupplyChainEvidenceError("wheel filename is unsafe")
    return {
        "sbom": wheel_name + SPDX_SUFFIX,
        "provenance": wheel_name + PROVENANCE_SUFFIX,
    }


def _module_records(wheel: Path) -> list[dict[str, Any]]:
    try:
        with zipfile.ZipFile(wheel) as archive:
            records = []
            for name in sorted(EXPECTED_MODULES):
                data = archive.read(name)
                records.append(
                    {
                        "name": name,
                        "size": len(data),
                        "sha1": hashlib.sha1(data).hexdigest(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise SupplyChainEvidenceError(f"unable to inspect wheel modules: {wheel}") from exc
    return records


def _spdx_file_id(name: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9.-]", "-", name)
    return "SPDXRef-File-" + normalized


def build_spdx_sbom(
    wheel: Path,
    summary: dict[str, Any],
    source_commit: str,
    source_date_epoch: int,
) -> dict[str, Any]:
    commit, epoch = _source_identity(source_commit, source_date_epoch)
    project, version, _scripts, _dependencies = _wheel_identity(summary)
    wheel_digest = sha256_file(wheel)
    modules = _module_records(wheel)
    verification_code = hashlib.sha1(
        "".join(sorted(item["sha1"] for item in modules)).encode("ascii")
    ).hexdigest()
    files = [
        {
            "SPDXID": _spdx_file_id(item["name"]),
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": item["sha1"]},
                {"algorithm": "SHA256", "checksumValue": item["sha256"]},
            ],
            "copyrightText": "NOASSERTION",
            "fileName": item["name"],
            "fileTypes": ["SOURCE"],
            "licenseConcluded": "MIT",
        }
        for item in modules
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package",
        }
    ] + [
        {
            "spdxElementId": "SPDXRef-Package",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": item["SPDXID"],
        }
        for item in files
    ]
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": _timestamp(epoch),
            "creators": [f"Tool: basit-agent-system/{version}"],
        },
        "dataLicense": SPDX_DATA_LICENSE,
        "documentDescribes": ["SPDXRef-Package"],
        "documentNamespace": f"{REPOSITORY}/releases/{commit}/sbom/{wheel_digest}",
        "files": files,
        "name": f"{project}-{version}-{wheel.name}",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "checksums": [{"algorithm": "SHA256", "checksumValue": wheel_digest}],
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": f"pkg:pypi/{project}@{version}",
                        "referenceType": "purl",
                    }
                ],
                "filesAnalyzed": True,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "name": project,
                "packageFileName": wheel.name,
                "packageVerificationCode": {
                    "packageVerificationCodeValue": verification_code,
                },
                "sourceInfo": f"Built from {REPOSITORY_URI}@{commit}",
                "versionInfo": version,
            }
        ],
        "relationships": relationships,
        "spdxVersion": SPDX_VERSION,
    }


def build_provenance(
    wheel: Path,
    summary: dict[str, Any],
    source_commit: str,
    source_date_epoch: int,
) -> dict[str, Any]:
    commit, epoch = _source_identity(source_commit, source_date_epoch)
    project, version, scripts, dependencies = _wheel_identity(summary)
    wheel_digest = sha256_file(wheel)
    modules = sorted(EXPECTED_MODULES)
    return {
        "_type": IN_TOTO_STATEMENT_V1,
        "predicate": {
            "buildDefinition": {
                "buildType": f"{REPOSITORY}/blob/{commit}/docs/reproducible-releases.md",
                "externalParameters": {
                    "artifact": {"filename": wheel.name, "mediaType": WHEEL_MEDIA_TYPE},
                    "package": {"name": project, "version": version},
                    "sourceDateEpoch": epoch,
                },
                "internalParameters": {
                    "consoleScripts": scripts,
                    "modules": modules,
                    "runtimeDependencies": dependencies,
                },
                "resolvedDependencies": [
                    {
                        "digest": {"sha1": commit},
                        "uri": f"{REPOSITORY_URI}@{commit}",
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": f"{REPOSITORY}/blob/{commit}/.github/workflows/ci.yml",
                },
                "metadata": {
                    "invocationId": f"urn:sha256:{wheel_digest}",
                },
            },
        },
        "predicateType": SLSA_PROVENANCE_V1,
        "subject": [
            {
                "digest": {"sha256": wheel_digest},
                "name": wheel.name,
            }
        ],
    }


def _reference(path: Path, media_type: str) -> dict[str, Any]:
    return {
        "filename": path.name,
        "media_type": media_type,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def create_evidence(
    wheel: Path,
    summary: dict[str, Any],
    source_commit: str,
    source_date_epoch: int,
    destination: Path,
) -> dict[str, dict[str, Any]]:
    names = evidence_names(wheel.name)
    sbom_path = destination / names["sbom"]
    provenance_path = destination / names["provenance"]
    if sbom_path.exists() or provenance_path.exists():
        raise SupplyChainEvidenceError("supply-chain evidence output already exists")
    try:
        sbom_path.write_bytes(
            canonical_json(build_spdx_sbom(wheel, summary, source_commit, source_date_epoch))
        )
        provenance_path.write_bytes(
            canonical_json(build_provenance(wheel, summary, source_commit, source_date_epoch))
        )
    except OSError as exc:
        raise SupplyChainEvidenceError("unable to write supply-chain evidence") from exc
    return {
        "sbom": _reference(sbom_path, SPDX_MEDIA_TYPE),
        "provenance": _reference(provenance_path, PROVENANCE_MEDIA_TYPE),
    }


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SupplyChainEvidenceError(f"missing {label} evidence") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SupplyChainEvidenceError(f"invalid {label} evidence") from exc
    if not isinstance(payload, dict):
        raise SupplyChainEvidenceError(f"{label} evidence root must be an object")
    return payload


def _validate_reference(
    reference: Any,
    expected_name: str,
    expected_media_type: str,
    directory: Path,
) -> Path:
    if not isinstance(reference, dict) or set(reference) != {
        "filename", "media_type", "sha256", "size"
    }:
        raise SupplyChainEvidenceError("evidence reference fields do not match the reviewed schema")
    if reference["filename"] != expected_name or not SAFE_NAME.fullmatch(expected_name):
        raise SupplyChainEvidenceError("evidence filename does not match the reviewed name")
    if reference["media_type"] != expected_media_type:
        raise SupplyChainEvidenceError("evidence media type does not match the reviewed type")
    if not isinstance(reference["sha256"], str) or not HEX_64.fullmatch(reference["sha256"]):
        raise SupplyChainEvidenceError("evidence digest is malformed")
    if isinstance(reference["size"], bool) or not isinstance(reference["size"], int) or reference["size"] < 1:
        raise SupplyChainEvidenceError("evidence size is malformed")
    path = directory / expected_name
    if path.is_symlink() or not path.is_file():
        raise SupplyChainEvidenceError(f"evidence file is missing or unsafe: {expected_name}")
    if sha256_file(path) != reference["sha256"]:
        raise SupplyChainEvidenceError(f"evidence digest mismatch: {expected_name}")
    if path.stat().st_size != reference["size"]:
        raise SupplyChainEvidenceError(f"evidence size mismatch: {expected_name}")
    return path


def verify_evidence(
    directory: Path,
    wheel: Path,
    summary: dict[str, Any],
    source_commit: str,
    source_date_epoch: int,
    evidence: Any,
) -> set[str]:
    if not isinstance(evidence, dict) or set(evidence) != {"sbom", "provenance"}:
        raise SupplyChainEvidenceError("artifact evidence fields do not match the reviewed schema")
    names = evidence_names(wheel.name)
    sbom_path = _validate_reference(
        evidence["sbom"], names["sbom"], SPDX_MEDIA_TYPE, directory
    )
    provenance_path = _validate_reference(
        evidence["provenance"], names["provenance"], PROVENANCE_MEDIA_TYPE, directory
    )
    expected_sbom = build_spdx_sbom(wheel, summary, source_commit, source_date_epoch)
    expected_provenance = build_provenance(wheel, summary, source_commit, source_date_epoch)
    if _load_json(sbom_path, "SBOM") != expected_sbom:
        raise SupplyChainEvidenceError("SBOM evidence does not match the reviewed wheel and source")
    if _load_json(provenance_path, "provenance") != expected_provenance:
        raise SupplyChainEvidenceError("provenance evidence does not match the reviewed wheel and source")
    return {names["sbom"], names["provenance"]}
