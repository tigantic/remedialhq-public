#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.build_public_release import (
    PRIVATE_ADMIN_PATHS,
    PUBLIC_FILE_PATHS,
    _owner_identity_patterns,
    scan_release_blobs,
)
from scripts.verify_manifest import _declared_package_files, _safe_relative, verify_package_manifest

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_COMPRESSION_RATIO = 500
MAX_TOTAL_COMPRESSION_RATIO = 100


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"command failed: {command[0]}: {detail}")
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _publish_no_replace(temporary: Path, output: Path) -> None:
    try:
        os.link(temporary, output)
    except FileExistsError as exc:
        raise ValueError(f"refusing to overwrite existing bundle: {output}") from exc
    except OSError as exc:
        raise RuntimeError("could not atomically publish the public bundle") from exc


def _safe_member(name: str, prefix: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        path.as_posix() != name
        or path.is_absolute()
        or len(path.parts) < 2
        or path.parts[0] != prefix
    ):
        raise ValueError(f"public ZIP has an invalid member root: {name}")
    raw_relative = PurePosixPath(*path.parts[1:]).as_posix()
    canonical = _safe_relative(raw_relative)
    relative = PurePosixPath(canonical)
    if (
        canonical != raw_relative
        or ".git" in {part.casefold() for part in relative.parts}
        or any(ord(character) == 127 for character in name)
    ):
        raise ValueError(f"public ZIP has an unsafe member path: {name}")
    return relative


def _extract_verified_zip(
    archive_path: Path, destination: Path
) -> tuple[Path, int, dict[str, str]]:
    archive_bytes = archive_path.stat().st_size
    if archive_bytes < 1 or archive_bytes > MAX_ARCHIVE_BYTES:
        raise ValueError("public ZIP size is outside the accepted release bounds")
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_MEMBERS:
            raise ValueError("public ZIP member count is outside the accepted bounds")
        if len({item.filename for item in infos}) != len(infos):
            raise ValueError("public ZIP is empty or contains duplicate members")
        roots = {PurePosixPath(item.filename).parts[0] for item in infos}
        if len(roots) != 1:
            raise ValueError("public ZIP must contain exactly one package root")
        prefix = next(iter(roots))
        if re.fullmatch(r"remedialhq-engine-v[0-9]+\.[0-9]+\.[0-9]+", prefix) is None:
            raise ValueError("public ZIP package root is invalid")
        package_root = destination / prefix
        normalized_paths: set[str] = set()
        modes: dict[str, str] = {}
        planned: list[tuple[zipfile.ZipInfo, PurePosixPath, int]] = []
        total_bytes = 0
        total_compressed = 0
        for info in infos:
            relative = _safe_member(info.filename, prefix)
            mode = info.external_attr >> 16
            if (
                info.is_dir()
                or info.flag_bits & 0x1
                or mode not in {0o100644, 0o100755}
                or stat.S_ISLNK(mode)
            ):
                raise ValueError(
                    f"public ZIP member is not a reviewed regular file: {info.filename}"
                )
            if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"public ZIP member is too large: {info.filename}")
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > MAX_MEMBER_COMPRESSION_RATIO:
                raise ValueError(
                    f"public ZIP member compression ratio is unsafe: {info.filename}"
                )
            normalized = unicodedata.normalize(
                "NFC", relative.as_posix()
            ).casefold()
            if normalized in normalized_paths:
                raise ValueError(
                    f"public ZIP has a normalized path collision: {info.filename}"
                )
            normalized_paths.add(normalized)
            total_bytes += info.file_size
            total_compressed += info.compress_size
            planned.append((info, relative, mode))
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("public ZIP uncompressed size exceeds the accepted bound")
        if total_bytes / max(total_compressed, 1) > MAX_TOTAL_COMPRESSION_RATIO:
            raise ValueError("public ZIP total compression ratio is unsafe")

        for info, relative, mode in planned:
            target = package_root.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info, "r") as source, target.open("xb") as destination_file:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > info.file_size:
                        raise ValueError(
                            f"public ZIP member exceeded its declared size: {info.filename}"
                        )
                    destination_file.write(chunk)
            if written != info.file_size:
                raise ValueError(
                    f"public ZIP member size does not match metadata: {info.filename}"
                )
            target.chmod(stat.S_IMODE(mode))
            modes[relative.as_posix()] = "100755" if mode == 0o100755 else "100644"
        timestamp = datetime(*infos[0].date_time, tzinfo=UTC)
    version = (package_root / "VERSION").read_text(encoding="utf-8").strip()
    if prefix != f"remedialhq-engine-v{version}":
        raise ValueError("public ZIP root and VERSION disagree")
    checked = verify_package_manifest(package_root)
    try:
        contents = json.loads(
            (package_root / "PACKAGE_CONTENTS.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("public ZIP package inventory could not be decoded") from exc
    declared_modes = {
        path: mode for path, (_digest, mode) in _declared_package_files(contents).items()
    }
    declared_modes["PACKAGE_CONTENTS.json"] = "100644"
    declared_modes["PACKAGE_SHA256SUMS.txt"] = "100644"
    if modes != declared_modes:
        raise ValueError("public ZIP executable modes do not match package metadata")
    if checked != len(modes) - 1:
        raise ValueError(
            "trusted public package verification returned an unexpected file count"
        )
    package_metadata = {"PACKAGE_CONTENTS.json", "PACKAGE_SHA256SUMS.txt"}
    source_paths = set(modes) - package_metadata
    approved_paths = set(PUBLIC_FILE_PATHS) - set(PRIVATE_ADMIN_PATHS)
    unexpected_paths = sorted(source_paths - approved_paths)
    if unexpected_paths:
        raise ValueError(
            "public ZIP contains paths outside the trusted public allowlist: "
            + ", ".join(unexpected_paths)
        )
    owner_identity_patterns = _owner_identity_patterns()
    for relative_name in sorted(modes):
        scan_release_blobs(
            {relative_name: (package_root / relative_name).read_bytes()},
            owner_identity_patterns=owner_identity_patterns,
        )
    return package_root, int(timestamp.timestamp()), modes


def _tree_modes(
    repository: Path,
    revision: str = "HEAD",
    *,
    env: dict[str, str] | None = None,
) -> dict[str, str]:
    raw = subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-r", "-z", revision],
        env=env,
        check=True,
        capture_output=True,
    ).stdout
    modes: dict[str, str] = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, object_type, _object_id = metadata.decode("ascii").split(" ")
        path = raw_path.decode("utf-8")
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"public Git tree contains an unsafe entry: {path}")
        modes[path] = mode
    return modes


def build_public_bundle(zip_path: Path, output: Path) -> dict[str, Any]:
    zip_path = zip_path.resolve()
    output = output.resolve()
    if not zip_path.is_file():
        raise ValueError(f"public ZIP does not exist: {zip_path}")
    if output.exists():
        raise ValueError(f"refusing to overwrite existing bundle: {output}")
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required to build the public bundle")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="remedialhq-public-bundle-") as directory:
        temporary_root = Path(directory)
        package_root, source_epoch, source_modes = _extract_verified_zip(
            zip_path, temporary_root
        )
        version = (package_root / "VERSION").read_text(encoding="utf-8").strip()
        tag = f"v{version}"
        git_env = {
            **{
                key: value
                for key, value in os.environ.items()
                if not key.startswith("GIT_")
            },
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
        release_env = {
            **git_env,
            "GIT_AUTHOR_NAME": "ReMediaLHQ Release",
            "GIT_AUTHOR_EMAIL": "support@remedialhq.com",
            "GIT_AUTHOR_DATE": f"{source_epoch} +0000",
            "GIT_COMMITTER_NAME": "ReMediaLHQ Release",
            "GIT_COMMITTER_EMAIL": "support@remedialhq.com",
            "GIT_COMMITTER_DATE": f"{source_epoch} +0000",
        }
        _run(
            [
                git,
                "-c",
                "init.templateDir=",
                "init",
                "--quiet",
                "--initial-branch=main",
            ],
            cwd=package_root,
            env=git_env,
        )
        disabled_hooks = package_root / ".git/disabled-hooks"
        disabled_hooks.mkdir(mode=0o700)
        _run(
            [git, "config", "core.hooksPath", str(disabled_hooks)],
            cwd=package_root,
            env=git_env,
        )
        _run(
            [git, "config", "user.name", "ReMediaLHQ Release"],
            cwd=package_root,
            env=git_env,
        )
        _run(
            [git, "config", "user.email", "support@remedialhq.com"],
            cwd=package_root,
            env=git_env,
        )
        _run([git, "add", "--all"], cwd=package_root, env=git_env)
        non_executable = [
            path for path, mode in source_modes.items() if mode == "100644"
        ]
        executable = [path for path, mode in source_modes.items() if mode == "100755"]
        if non_executable:
            _run(
                [git, "update-index", "--chmod=-x", "--", *non_executable],
                cwd=package_root,
                env=git_env,
            )
        if executable:
            _run(
                [git, "update-index", "--chmod=+x", "--", *executable],
                cwd=package_root,
                env=git_env,
            )
        _run(
            [git, "commit", "--quiet", "-m", f"ReMediaLHQ {tag} public release"],
            cwd=package_root,
            env=release_env,
        )
        _run(
            [git, "tag", "--annotate", tag, "--message", f"ReMediaLHQ {tag}"],
            cwd=package_root,
            env=release_env,
        )
        commit = _run([git, "rev-parse", "HEAD"], cwd=package_root, env=git_env)
        tree = _run(
            [git, "rev-parse", "HEAD^{tree}"], cwd=package_root, env=git_env
        )
        tag_object = _run(
            [git, "rev-parse", f"{tag}^{{tag}}"], cwd=package_root, env=git_env
        )
        parent_row = _run(
            [git, "rev-list", "--parents", "-n", "1", "HEAD"],
            cwd=package_root,
            env=git_env,
        )
        if len(parent_row.split()) != 1:
            raise ValueError("public release commit must be parentless")
        committed_modes = _tree_modes(package_root, env=git_env)
        if committed_modes != source_modes:
            mismatches = sorted(
                path
                for path in set(committed_modes) | set(source_modes)
                if committed_modes.get(path) != source_modes.get(path)
            )
            raise ValueError(
                "public Git tree executable modes are incomplete: "
                + ", ".join(mismatches)
            )

        with tempfile.NamedTemporaryFile(
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_bundle = Path(handle.name)
        temporary_bundle.unlink()
        try:
            _run(
                [git, "bundle", "create", str(temporary_bundle), "--all"],
                cwd=package_root,
                env=git_env,
            )
            _run(
                [git, "bundle", "verify", str(temporary_bundle)],
                cwd=package_root,
                env=git_env,
            )
            checkout = temporary_root / "checkout"
            _run(
                [git, "clone", "--quiet", str(temporary_bundle), str(checkout)],
                env=git_env,
            )
            if (
                _run(
                    [git, "branch", "--show-current"], cwd=checkout, env=git_env
                )
                != "main"
            ):
                raise ValueError("public bundle does not clone to main")
            if (
                _run(
                    [git, "rev-list", "--count", "HEAD"], cwd=checkout, env=git_env
                )
                != "1"
            ):
                raise ValueError("public bundle history is not a single commit")
            _run(
                [git, "fsck", "--strict", "--no-dangling"],
                cwd=checkout,
                env=git_env,
            )
            if _tree_modes(checkout, env=git_env) != source_modes:
                raise ValueError("public bundle checkout modes do not match the ZIP")
            for relative in source_modes:
                if (checkout / relative).read_bytes() != (package_root / relative).read_bytes():
                    raise ValueError(f"public bundle checkout differs from ZIP: {relative}")
            _publish_no_replace(temporary_bundle, output)
        finally:
            temporary_bundle.unlink(missing_ok=True)

    return {
        "status": "PASS",
        "release": tag,
        "output": str(output),
        "bytes": output.stat().st_size,
        "sha256": _sha256(output),
        "public_commit": commit,
        "public_tree": tree,
        "public_tag_object": tag_object,
        "history": "ONE_PARENTLESS_SANITIZED_COMMIT",
        "default_branch": "main",
        "files": len(source_modes),
        "executable_files": sum(mode == "100755" for mode in source_modes.values()),
        "bundle_verification": "PASS",
        "strict_fsck": "PASS",
        "zip_byte_and_mode_match": "PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="build a sanitized one-commit public Git bundle from a verified ZIP"
    )
    parser.add_argument("--zip", required=True, dest="zip_path")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = build_public_bundle(Path(args.zip_path), Path(args.output))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
