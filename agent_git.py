"""Safe Git change-scope discovery for Basit Agent System."""
from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath
from typing import Any


class GitDiffError(ValueError):
    """Raised when a Git change scope cannot be resolved safely."""


def _run_git(cwd: Path, arguments: list[str], *, binary: bool = False) -> str | bytes:
    command = ["git", "-C", str(cwd), *arguments]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitDiffError("git executable was not found") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        detail = " ".join(detail.split())[:300]
        raise GitDiffError(detail or f"git command failed with exit code {completed.returncode}")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise GitDiffError("git returned a path or reference that is not valid UTF-8") from exc


def _validate_ref(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise GitDiffError(f"{label} must be a non-empty Git reference up to 200 characters")
    if value.startswith("-") or any(character.isspace() or ord(character) == 127 for character in value):
        raise GitDiffError(f"{label} contains unsafe characters")
    return value


def _resolve_commit(repository_root: Path, reference: str, label: str) -> str:
    safe_reference = _validate_ref(reference, label)
    resolved = _run_git(repository_root, ["rev-parse", "--verify", f"{safe_reference}^{{commit}}"])
    if (
        not isinstance(resolved, str)
        or len(resolved) != 40
        or any(character not in "0123456789abcdef" for character in resolved)
    ):
        raise GitDiffError(f"{label} did not resolve to a commit SHA")
    return resolved


def _validated_repo_path(repository_root: Path, raw_path: str) -> Path:
    logical = PurePosixPath(raw_path)
    if not raw_path or logical.is_absolute() or ".." in logical.parts:
        raise GitDiffError(f"git returned an unsafe path: {raw_path!r}")
    candidate = repository_root.joinpath(*logical.parts)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(repository_root)
    except ValueError as exc:
        raise GitDiffError(f"git path escapes the repository through a symlink: {raw_path!r}") from exc
    return candidate


def _relative_to_scan_root(repository_root: Path, scan_root: Path, raw_path: str) -> str | None:
    candidate = _validated_repo_path(repository_root, raw_path)
    try:
        return candidate.relative_to(scan_root).as_posix()
    except ValueError:
        return None


def _parse_name_status(payload: bytes) -> list[tuple[str, str | None, str]]:
    if not payload:
        return []
    tokens = payload.split(b"\0")
    if tokens[-1] == b"":
        tokens.pop()
    decoded: list[str] = []
    for token in tokens:
        try:
            decoded.append(token.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise GitDiffError("git returned a changed path that is not valid UTF-8") from exc

    entries: list[tuple[str, str | None, str]] = []
    index = 0
    while index < len(decoded):
        status = decoded[index]
        index += 1
        if not status or status[0] not in "ACDMRTUXB":
            raise GitDiffError(f"git returned an unsupported change status: {status!r}")
        code = status[0]
        if code in {"R", "C"}:
            if index + 1 >= len(decoded):
                raise GitDiffError("git returned a truncated rename or copy record")
            old_path, path = decoded[index], decoded[index + 1]
            index += 2
            entries.append((status, old_path, path))
        else:
            if index >= len(decoded):
                raise GitDiffError("git returned a truncated change record")
            path = decoded[index]
            index += 1
            entries.append((status, None, path))
    return entries


def changed_scope(scan_path: Path, base_ref: str, head_ref: str = "HEAD") -> dict[str, Any]:
    """Resolve a merge-base Git diff and return a safe scan/baseline path scope."""
    scan_root = scan_path.resolve()
    if not scan_root.exists() or not scan_root.is_dir():
        raise GitDiffError("changed-file scanning requires an existing directory scan path")

    repository_text = _run_git(scan_root, ["rev-parse", "--show-toplevel"])
    if not isinstance(repository_text, str) or not repository_text:
        raise GitDiffError("unable to determine the Git repository root")
    repository_root = Path(repository_text).resolve()
    try:
        scan_root.relative_to(repository_root)
    except ValueError as exc:
        raise GitDiffError("scan path is outside the discovered Git repository") from exc

    base_sha = _resolve_commit(repository_root, base_ref, "base ref")
    head_sha = _resolve_commit(repository_root, head_ref, "head ref")
    try:
        merge_base = _run_git(repository_root, ["merge-base", base_sha, head_sha])
    except GitDiffError as exc:
        raise GitDiffError(
            "unable to determine a merge base; fetch the base and head commit history"
        ) from exc
    if not isinstance(merge_base, str) or len(merge_base) != 40:
        raise GitDiffError("unable to determine a merge base; fetch the required Git history")

    raw = _run_git(
        repository_root,
        [
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            "--diff-filter=ACDMRTUXB",
            merge_base,
            head_sha,
            "--",
        ],
        binary=True,
    )
    assert isinstance(raw, bytes)
    records = _parse_name_status(raw)

    files: list[dict[str, Any]] = []
    scan_paths: set[str] = set()
    baseline_paths: set[str] = set()
    deleted = 0
    renamed = 0

    for status, old_repo_path, repo_path in records:
        code = status[0]
        relative_path = _relative_to_scan_root(repository_root, scan_root, repo_path)
        old_relative = (
            _relative_to_scan_root(repository_root, scan_root, old_repo_path)
            if old_repo_path is not None
            else None
        )
        if relative_path is None and old_relative is None:
            continue

        if code == "D":
            deleted += 1
            if relative_path is not None:
                baseline_paths.add(relative_path)
            files.append({
                "status": status,
                "path": relative_path,
                "old_path": None,
                "current": False,
            })
            continue

        if code == "R":
            renamed += 1
            if old_relative is not None:
                baseline_paths.add(old_relative)
        if relative_path is not None:
            baseline_paths.add(relative_path)

        current = False
        if relative_path is not None:
            candidate = _validated_repo_path(repository_root, repo_path)
            if candidate.is_file():
                scan_paths.add(relative_path)
                current = True
            elif candidate.exists() and not candidate.is_dir():
                raise GitDiffError(f"changed path is not a regular file: {repo_path!r}")

        files.append({
            "status": status,
            "path": relative_path,
            "old_path": old_relative,
            "current": current,
        })

    files.sort(key=lambda item: (item["path"] or item["old_path"] or "", item["status"]))
    return {
        "type": "git-changes",
        "base_ref": base_ref,
        "head_ref": head_ref,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "merge_base_sha": merge_base,
        "changed": len(files),
        "current_files": len(scan_paths),
        "deleted": deleted,
        "renamed": renamed,
        "files": files,
        "_scan_paths": sorted(scan_paths),
        "_baseline_paths": sorted(baseline_paths),
    }


def public_scope(scope: dict[str, Any]) -> dict[str, Any]:
    """Return report-safe scope metadata without internal path sets."""
    return {key: value for key, value in scope.items() if not key.startswith("_")}
