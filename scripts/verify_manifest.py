#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_REPOSITORY_EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".terraform",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "local-private",
    "release",
}
_REPOSITORY_EXCLUDED_NAMES = {
    "MANIFEST.sha256",
    "owner_profile.private.json",
    "OWNER_FORM_FILL_PROFILE.md",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _safe_relative(value: str) -> str:
    relative = PurePosixPath(value)
    unsafe_windows_part = any(
        part.endswith((" ", "."))
        or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
        for part in relative.parts
    )
    if (
        not value
        or relative.is_absolute()
        or ".." in relative.parts
        or "\\" in value
        or ":" in value
        or unsafe_windows_part
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"unsafe manifest path: {value!r}")
    return relative.as_posix()


def _read_sums(path: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2 or _SHA256_RE.fullmatch(parts[0]) is None:
            raise ValueError(f"invalid checksum line {line_number}")
        relative = _safe_relative(parts[1])
        if relative in expected:
            raise ValueError(f"duplicate manifest path: {relative}")
        expected[relative] = parts[0]
    if not expected:
        raise ValueError("checksum manifest is empty")
    return expected


def _verify_files(root: Path, expected: dict[str, str]) -> int:
    resolved_root = root.resolve()
    checked = 0
    for relative, expected_digest in expected.items():
        path = root / relative
        resolved = path.resolve()
        if not resolved.is_relative_to(resolved_root):
            raise ValueError(f"path escapes the verification root: {relative}")
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"MISSING {relative}")
        observed = digest(path)
        if observed != expected_digest:
            raise ValueError(f"MISMATCH {relative}: {observed} != {expected_digest}")
        checked += 1
    return checked


def verify_repository_manifest(root: Path) -> int:
    expected = _read_sums(root / "MANIFEST.sha256")
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError("repository manifest verification requires a Git working tree")
    actual: set[str] = set()
    for raw_relative in completed.stdout.split(b"\0"):
        if not raw_relative:
            continue
        try:
            relative = _safe_relative(raw_relative.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError("tracked repository paths must be UTF-8") from exc
        path = PurePosixPath(relative)
        if any(
            part in _REPOSITORY_EXCLUDED_PARTS or part.endswith(".egg-info")
            for part in path.parts
        ):
            continue
        if path.name in _REPOSITORY_EXCLUDED_NAMES:
            continue
        if path.suffix in {".zip", ".bundle"}:
            continue
        candidate = root / relative
        if candidate.is_symlink():
            raise ValueError(f"tracked repository path must not be a symlink: {relative}")
        actual.add(relative)
    if actual != set(expected):
        raise ValueError(
            "repository manifest inventory mismatch: "
            f"missing={sorted(set(expected) - actual)}, "
            f"unexpected={sorted(actual - set(expected))}"
        )
    return _verify_files(root, expected)


def _declared_package_files(contents: Any) -> dict[str, tuple[str, str]]:
    if not isinstance(contents, dict) or contents.get("schema_version") != 2:
        raise ValueError("PACKAGE_CONTENTS.json has an unsupported schema")
    rows = contents.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("PACKAGE_CONTENTS.json has no file inventory")
    declared: dict[str, tuple[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("PACKAGE_CONTENTS.json file row must be an object")
        path_value = row.get("path")
        relative = _safe_relative(path_value) if isinstance(path_value, str) else ""
        expected_digest = row.get("sha256")
        expected_mode = row.get("mode")
        if not relative or not isinstance(expected_digest, str):
            raise ValueError("PACKAGE_CONTENTS.json file row is incomplete")
        if _SHA256_RE.fullmatch(expected_digest) is None:
            raise ValueError(f"invalid package digest for {relative}")
        if expected_mode not in {"100644", "100755"}:
            raise ValueError(f"invalid package mode for {relative}")
        if relative in declared:
            raise ValueError(f"duplicate package inventory path: {relative}")
        declared[relative] = (expected_digest, expected_mode)
    return declared


def _is_git_worktree_root(root: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return False
    try:
        reported_root = Path(completed.stdout.strip()).resolve()
    except (OSError, RuntimeError):
        return False
    return reported_root == root.resolve()


def _git_index_modes(root: Path) -> dict[str, str]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--stage", "-z"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError("package mode verification requires a readable Git index")
    modes: dict[str, str] = {}
    for raw_entry in completed.stdout.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, _, stage = metadata.decode("ascii").split(" ")
            relative = _safe_relative(raw_path.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Git index contains an invalid package entry") from exc
        if stage != "0":
            raise ValueError(f"Git index contains an unmerged package entry: {relative}")
        modes[relative] = mode
    return modes


def verify_package_manifest(root: Path) -> int:
    sums = _read_sums(root / "PACKAGE_SHA256SUMS.txt")
    contents_path = root / "PACKAGE_CONTENTS.json"
    try:
        contents = json.loads(contents_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("PACKAGE_CONTENTS.json could not be decoded") from exc
    declared_files = _declared_package_files(contents)
    declared = {
        relative: expected_digest
        for relative, (expected_digest, _) in declared_files.items()
    }
    expected_sums = {
        **declared,
        "PACKAGE_CONTENTS.json": digest(contents_path),
    }
    if sums != expected_sums:
        missing = sorted(set(expected_sums) - set(sums))
        unexpected = sorted(set(sums) - set(expected_sums))
        changed = sorted(
            path for path in set(sums) & set(expected_sums) if sums[path] != expected_sums[path]
        )
        raise ValueError(
            "package checksum inventory mismatch: "
            f"missing={missing}, unexpected={unexpected}, changed={changed}"
        )

    expected_actual = set(sums) | {"PACKAGE_SHA256SUMS.txt"}
    actual: set[str] = set()
    git_admin = root / ".git"
    if git_admin.is_symlink():
        raise ValueError("symbolic links are not permitted: .git")
    ignore_git_metadata = git_admin.exists() and _is_git_worktree_root(root)
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if ignore_git_metadata and relative.parts[0] == ".git":
            continue
        if path.is_symlink():
            raise ValueError(f"symbolic links are not permitted: {relative}")
        if path.is_file():
            actual.add(_safe_relative(relative.as_posix()))
    if actual != expected_actual:
        raise ValueError(
            "extracted package inventory mismatch: "
            f"missing={sorted(expected_actual - actual)}, "
            f"unexpected={sorted(actual - expected_actual)}"
        )
    if ignore_git_metadata:
        index_modes = _git_index_modes(root)
        mismatched_modes = sorted(
            relative
            for relative, (_, expected_mode) in declared_files.items()
            if index_modes.get(relative) != expected_mode
        )
        if mismatched_modes:
            raise ValueError(f"package Git mode mismatch: {mismatched_modes}")
    return _verify_files(root, sums)


def verify_available_manifest(root: Path) -> tuple[int, str]:
    """Verify package metadata preferentially, or a repository manifest."""
    package_sums = root / "PACKAGE_SHA256SUMS.txt"
    package_contents = root / "PACKAGE_CONTENTS.json"
    repository_manifest = root / "MANIFEST.sha256"
    if package_sums.exists() or package_contents.exists():
        if not package_sums.is_file() or not package_contents.is_file():
            raise ValueError(
                "package verification requires both PACKAGE_SHA256SUMS.txt "
                "and PACKAGE_CONTENTS.json"
            )
        return (
            verify_package_manifest(root),
            "PACKAGE_SHA256SUMS.txt and exact package inventory",
        )
    if repository_manifest.is_file():
        return verify_repository_manifest(root), "MANIFEST.sha256"
    raise ValueError(
        "no supported checksum manifest found; expected MANIFEST.sha256 or package metadata"
    )


def main() -> None:
    try:
        checked, label = verify_available_manifest(ROOT)
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(f"PASS: {checked} files match {label}")


if __name__ == "__main__":
    main()
