#!/usr/bin/env python3
"""Create, compare, and verify deterministic Basit Agent System release bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    from scripts.validate_wheel import WheelValidationError, validate_wheel
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from validate_wheel import WheelValidationError, validate_wheel

MANIFEST_NAME = "release-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
MANIFEST_VERSION = 1
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class ReleaseBundleError(ValueError):
    """Raised when release evidence is incomplete, unsafe, or inconsistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _release_id(payload: dict[str, Any]) -> str:
    core = dict(payload)
    core.pop("release_id", None)
    return hashlib.sha256(_canonical_json(core)).hexdigest()


def _source_commit(value: str) -> str:
    normalized = value.strip().lower()
    if not HEX_40.fullmatch(normalized):
        raise ReleaseBundleError("source commit must be an exact 40-character hexadecimal SHA")
    return normalized


def _source_epoch(value: int | str) -> int:
    try:
        epoch = int(value)
    except (TypeError, ValueError) as exc:
        raise ReleaseBundleError("source date epoch must be an integer") from exc
    if epoch < 0:
        raise ReleaseBundleError("source date epoch must be non-negative")
    return epoch


def _timestamp(epoch: int) -> str:
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError) as exc:
        raise ReleaseBundleError("source date epoch is outside the supported range") from exc


def _safe_artifact(path: Path) -> Path:
    if path.is_symlink():
        raise ReleaseBundleError(f"release artifacts must not be symlinks: {path}")
    if not path.is_file():
        raise ReleaseBundleError(f"release artifact does not exist: {path}")
    if path.suffix != ".whl":
        raise ReleaseBundleError(f"only reviewed wheel artifacts are supported: {path}")
    if not SAFE_NAME.fullmatch(path.name):
        raise ReleaseBundleError(f"unsafe artifact filename: {path.name}")
    return path.resolve()


def _prepare_output(directory: Path) -> Path:
    if directory.is_symlink():
        raise ReleaseBundleError("release output directory must not be a symlink")
    resolved = directory.resolve(strict=False)
    if resolved.exists():
        if not resolved.is_dir():
            raise ReleaseBundleError("release output path must be a directory")
        if any(resolved.iterdir()):
            raise ReleaseBundleError("release output directory must be empty")
    else:
        resolved.mkdir(parents=True)
    return resolved


def _artifact_record(path: Path, wheel_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": path.name,
        "media_type": "application/vnd.pypa.wheel+zip",
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "project": wheel_summary["project"],
        "version": wheel_summary["version"],
        "modules": wheel_summary["modules"],
        "console_scripts": wheel_summary["console_scripts"],
        "runtime_dependencies": wheel_summary["runtime_dependencies"],
    }


def create_bundle(
    wheels: Iterable[Path],
    output_dir: Path,
    source_commit: str,
    source_date_epoch: int | str,
) -> dict[str, Any]:
    artifacts = [_safe_artifact(Path(path)) for path in wheels]
    if not artifacts:
        raise ReleaseBundleError("at least one wheel artifact is required")
    names = [path.name for path in artifacts]
    if len(names) != len(set(names)):
        raise ReleaseBundleError("release artifact filenames must be unique")

    commit = _source_commit(source_commit)
    epoch = _source_epoch(source_date_epoch)
    destination = _prepare_output(output_dir)

    records: list[dict[str, Any]] = []
    try:
        for path in sorted(artifacts, key=lambda item: item.name):
            summary = validate_wheel(path)
            target = destination / path.name
            shutil.copyfile(path, target, follow_symlinks=False)
            records.append(_artifact_record(target, summary))
    except (OSError, WheelValidationError) as exc:
        raise ReleaseBundleError(str(exc)) from exc

    projects = {record["project"] for record in records}
    versions = {record["version"] for record in records}
    if len(projects) != 1 or len(versions) != 1:
        raise ReleaseBundleError("all release artifacts must share one project and version")

    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "project": next(iter(projects)),
        "version": next(iter(versions)),
        "source": {
            "commit": commit,
            "source_date_epoch": epoch,
            "timestamp_utc": _timestamp(epoch),
        },
        "artifacts": records,
    }
    manifest["release_id"] = _release_id(manifest)
    manifest_path = destination / MANIFEST_NAME
    manifest_path.write_bytes(_canonical_json(manifest))

    checksum_lines = [
        f"{record['sha256']}  {record['filename']}" for record in records
    ]
    checksum_lines.append(f"{sha256_file(manifest_path)}  {MANIFEST_NAME}")
    (destination / CHECKSUMS_NAME).write_text(
        "\n".join(sorted(checksum_lines)) + "\n", encoding="utf-8"
    )
    return manifest


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReleaseBundleError(f"missing {MANIFEST_NAME}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseBundleError(f"invalid {MANIFEST_NAME}") from exc
    if not isinstance(payload, dict):
        raise ReleaseBundleError("release manifest root must be an object")
    required = {"manifest_version", "project", "version", "source", "artifacts", "release_id"}
    if set(payload) != required:
        raise ReleaseBundleError("release manifest fields do not match the reviewed schema")
    if payload["manifest_version"] != MANIFEST_VERSION:
        raise ReleaseBundleError("unsupported release manifest version")
    if not HEX_64.fullmatch(str(payload["release_id"])):
        raise ReleaseBundleError("release manifest has an invalid release id")
    if payload["release_id"] != _release_id(payload):
        raise ReleaseBundleError("release manifest integrity check failed")
    return payload


def _load_checksums(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise ReleaseBundleError(f"missing {CHECKSUMS_NAME}") from exc
    except OSError as exc:
        raise ReleaseBundleError(f"unable to read {CHECKSUMS_NAME}") from exc
    checksums: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)", line)
        if not match:
            raise ReleaseBundleError("checksum file contains a malformed line")
        digest, name = match.groups()
        if name in checksums:
            raise ReleaseBundleError("checksum file contains duplicate filenames")
        checksums[name] = digest
    return checksums


def verify_bundle(bundle_dir: Path) -> dict[str, Any]:
    if bundle_dir.is_symlink():
        raise ReleaseBundleError("release bundle directory must not be a symlink")
    directory = bundle_dir.resolve()
    if not directory.is_dir():
        raise ReleaseBundleError("release bundle directory does not exist")

    manifest = _load_manifest(directory / MANIFEST_NAME)
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {
        "commit", "source_date_epoch", "timestamp_utc"
    }:
        raise ReleaseBundleError("release source metadata does not match the reviewed schema")
    commit = _source_commit(str(source["commit"]))
    epoch = _source_epoch(source["source_date_epoch"])
    if source["timestamp_utc"] != _timestamp(epoch):
        raise ReleaseBundleError("release source timestamp does not match source date epoch")

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ReleaseBundleError("release manifest must contain at least one artifact")
    expected_names = {MANIFEST_NAME, CHECKSUMS_NAME}
    seen_names: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            raise ReleaseBundleError("release artifact records must be objects")
        required = {
            "filename", "media_type", "sha256", "size", "project", "version",
            "modules", "console_scripts", "runtime_dependencies",
        }
        if set(record) != required:
            raise ReleaseBundleError("release artifact record fields do not match the reviewed schema")
        name = str(record["filename"])
        if not SAFE_NAME.fullmatch(name) or name in seen_names:
            raise ReleaseBundleError("release artifact filenames are unsafe or duplicated")
        seen_names.add(name)
        expected_names.add(name)
        artifact = directory / name
        if artifact.is_symlink() or not artifact.is_file():
            raise ReleaseBundleError(f"release artifact is missing or unsafe: {name}")
        if sha256_file(artifact) != record["sha256"]:
            raise ReleaseBundleError(f"release artifact digest mismatch: {name}")
        if artifact.stat().st_size != record["size"]:
            raise ReleaseBundleError(f"release artifact size mismatch: {name}")
        try:
            summary = validate_wheel(artifact)
        except WheelValidationError as exc:
            raise ReleaseBundleError(str(exc)) from exc
        expected_summary = {
            "project": record["project"],
            "version": record["version"],
            "modules": record["modules"],
            "console_scripts": record["console_scripts"],
            "runtime_dependencies": record["runtime_dependencies"],
        }
        actual_summary = {key: summary[key] for key in expected_summary}
        if actual_summary != expected_summary:
            raise ReleaseBundleError(f"release artifact metadata mismatch: {name}")
        if record["project"] != manifest["project"] or record["version"] != manifest["version"]:
            raise ReleaseBundleError("release artifact project/version differs from manifest")

    actual_names = {path.name for path in directory.iterdir()}
    if actual_names != expected_names:
        unexpected = sorted(actual_names - expected_names)
        missing = sorted(expected_names - actual_names)
        raise ReleaseBundleError(
            f"release bundle file boundary mismatch; missing={missing}, unexpected={unexpected}"
        )

    checksums = _load_checksums(directory / CHECKSUMS_NAME)
    checksum_targets = expected_names - {CHECKSUMS_NAME}
    if set(checksums) != checksum_targets:
        raise ReleaseBundleError("checksum file targets do not match release bundle")
    for name, expected_digest in checksums.items():
        if sha256_file(directory / name) != expected_digest:
            raise ReleaseBundleError(f"checksum verification failed: {name}")

    return {
        "project": manifest["project"],
        "version": manifest["version"],
        "release_id": manifest["release_id"],
        "source_commit": commit,
        "source_date_epoch": epoch,
        "artifacts": len(artifacts),
        "files": sorted(expected_names),
    }


def compare_wheels(first: Path, second: Path) -> dict[str, Any]:
    left = _safe_artifact(first)
    right = _safe_artifact(second)
    try:
        left_summary = validate_wheel(left)
        right_summary = validate_wheel(right)
    except WheelValidationError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    if left.name != right.name:
        raise ReleaseBundleError("reproducible wheel comparison requires matching filenames")
    if left_summary != right_summary:
        raise ReleaseBundleError("wheel metadata differs between builds")
    left_digest = sha256_file(left)
    right_digest = sha256_file(right)
    if left_digest != right_digest or left.stat().st_size != right.stat().st_size:
        raise ReleaseBundleError("wheel builds are not byte-for-byte reproducible")
    return {
        "wheel": left.name,
        "sha256": left_digest,
        "size": left.stat().st_size,
        "project": left_summary["project"],
        "version": left_summary["version"],
        "reproducible": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--wheel", action="append", required=True, type=Path)
    create.add_argument("--output-dir", required=True, type=Path)
    create.add_argument("--source-commit", required=True)
    create.add_argument("--source-date-epoch", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("bundle_dir", type=Path)

    compare = subparsers.add_parser("compare")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create_bundle(
                args.wheel, args.output_dir, args.source_commit, args.source_date_epoch
            )
        elif args.command == "verify":
            result = verify_bundle(args.bundle_dir)
        else:
            result = compare_wheels(args.first, args.second)
    except ReleaseBundleError as exc:
        print(f"Release bundle error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
