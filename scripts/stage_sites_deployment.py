#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SITE_ROOT_RELATIVE = Path("site")
WORKER_SOURCE_PATHS = (
    Path("infra/sites/worker.ts"),
    Path("infra/sites/vite-env.d.ts"),
)
SOURCE_PATHSPECS = (SITE_ROOT_RELATIVE, *WORKER_SOURCE_PATHS)
HOSTING_CONTROL_FILE_NAMES = {"_headers", "_redirects"}
HOSTING_CONTROL_FILES = {Path(name) for name in HOSTING_CONTROL_FILE_NAMES}
STAGING_MANIFEST_RELATIVE = Path(".openai/remedialhq-staging-manifest.json")
STAGING_TEMP_PREFIX = ".remedialhq-stage-"


class ManualRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class CanonicalSiteSnapshot:
    commit: str
    sha256: str
    files: Mapping[Path, bytes]


def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"canonical site Git inspection failed: {detail or arguments[0]}")
    return completed.stdout


def _assert_regular_source(root: Path, relative: Path) -> Path:
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"canonical site input must not be a symbolic link: {relative}")
    if not current.is_file():
        raise ValueError(f"canonical site input must be a regular file: {relative}")
    return current


def _snapshot_digest(files: Mapping[Path, bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(b"remedialhq-canonical-site-v1\0")
    for relative in sorted(files, key=lambda item: item.as_posix()):
        encoded_path = relative.as_posix().encode("utf-8")
        content = files[relative]
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def canonical_site_snapshot(source_root: str | Path = ROOT) -> CanonicalSiteSnapshot:
    root = Path(source_root).resolve()
    repository_root = Path(
        _git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    ).resolve()
    if repository_root != root:
        raise ValueError("canonical site source must be the repository root")

    pathspecs = [path.as_posix() for path in SOURCE_PATHSPECS]
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--",
        *pathspecs,
    )
    untracked = _git(
        root,
        "ls-files",
        "--others",
        "-z",
        "--",
        *pathspecs,
    )
    if status or untracked:
        raise ValueError("canonical site inputs contain uncommitted or untracked changes")

    commit = _git(root, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    listed = _git(
        root,
        "ls-tree",
        "-r",
        "--name-only",
        "-z",
        "HEAD",
        "--",
        *pathspecs,
    )
    relative_paths = sorted(
        (Path(value.decode("utf-8")) for value in listed.split(b"\0") if value),
        key=lambda item: item.as_posix(),
    )
    required = {
        Path("site/index.html"),
        Path("site/404.html"),
        Path("site/creator-desk.html"),
        *WORKER_SOURCE_PATHS,
    }
    missing = sorted(path.as_posix() for path in required - set(relative_paths))
    if missing:
        raise ValueError(f"canonical site commit is missing required inputs: {missing}")

    files: dict[Path, bytes] = {}
    for relative in relative_paths:
        source = _assert_regular_source(root, relative)
        working_content = source.read_bytes()
        committed_content = _git(root, "show", f"HEAD:{relative.as_posix()}")
        if working_content != committed_content:
            raise ValueError(f"canonical site input differs from the current commit: {relative}")
        files[relative] = committed_content
    return CanonicalSiteSnapshot(
        commit=commit,
        sha256=_snapshot_digest(files),
        files=files,
    )


def _hosting_project_id(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("destination hosting configuration must be a regular file")
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("destination hosting configuration is not readable JSON") from exc
    if not isinstance(value, dict):
        raise TypeError("destination hosting configuration must be an object")
    project_id = value.get("project_id")
    if not isinstance(project_id, str) or not project_id.strip():
        raise ValueError("destination hosting configuration has no project_id")
    return project_id


def _assert_safe_tree(path: Path, *, target_root: Path) -> None:
    if not path.resolve().is_relative_to(target_root):
        raise ValueError(f"deployment destination is outside the Sites project: {path}")
    if path.is_symlink():
        raise ValueError(f"deployment destination must not be a symbolic link: {path}")
    if not path.exists():
        return
    if not path.is_dir():
        raise ValueError(f"deployment tree must be a directory: {path}")
    pending = [path]
    while pending:
        directory = pending.pop()
        for child in directory.iterdir():
            if child.is_symlink():
                raise ValueError(
                    f"deployment destination must not contain symbolic links: {child}"
                )
            if child.is_dir():
                pending.append(child)
            elif not child.is_file():
                raise ValueError(
                    f"deployment destination contains a non-regular entry: {child}"
                )


def _clear_tree(path: Path, *, target_root: Path) -> None:
    _assert_safe_tree(path, target_root=target_root)
    path.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []
    directories: list[Path] = []
    pending = [path]
    while pending:
        directory = pending.pop()
        for child in directory.iterdir():
            if child.is_symlink():
                raise ValueError(
                    f"deployment destination must not contain symbolic links: {child}"
                )
            if child.is_dir():
                directories.append(child)
                pending.append(child)
            elif child.is_file():
                files.append(child)
            else:
                raise ValueError(
                    f"deployment destination contains a non-regular entry: {child}"
                )
    for file_path in files:
        file_path.unlink()
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        directory.rmdir()


def _write_file(content: bytes, destination: Path, *, target_root: Path) -> None:
    if not destination.parent.resolve().is_relative_to(target_root):
        raise ValueError(f"deployment destination is unsafe: {destination}")
    current = target_root
    for part in destination.relative_to(target_root).parts[:-1]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"deployment destination is unsafe: {destination}")
    if destination.is_symlink():
        raise ValueError(f"deployment destination is unsafe: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)


def _mirror_tree(
    desired: Mapping[Path, bytes],
    destination: Path,
    *,
    target_root: Path,
) -> None:
    _clear_tree(destination, target_root=target_root)
    for relative in sorted(desired, key=lambda item: item.as_posix()):
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"deployment-relative path is unsafe: {relative}")
        _write_file(desired[relative], destination / relative, target_root=target_root)


def _replace_path(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _transactional_install(
    *,
    target: Path,
    stage_root: Path,
    replacements: tuple[tuple[Path, Path, str], ...],
) -> None:
    backup_root = stage_root / "backup"
    failed_root = stage_root / "failed"
    backup_root.mkdir()
    installed: list[tuple[Path, Path, str]] = []
    backed_up: list[tuple[Path, Path, str]] = []
    try:
        for staged, destination, label in replacements:
            if not staged.exists() or staged.is_symlink():
                raise ValueError(f"staged deployment input is unsafe: {staged}")
            if not destination.parent.resolve().is_relative_to(target):
                raise ValueError(f"deployment destination is unsafe: {destination}")
            backup = backup_root / label
            if destination.exists() or destination.is_symlink():
                if destination.is_symlink():
                    raise ValueError(
                        f"deployment destination must not be a symbolic link: {destination}"
                    )
                backup.parent.mkdir(parents=True, exist_ok=True)
                _replace_path(destination, backup)
                backed_up.append((backup, destination, label))
            _replace_path(staged, destination)
            installed.append((destination, failed_root / label, label))
    except Exception as exc:
        rollback_errors: list[str] = []
        for destination, failed, _label in reversed(installed):
            try:
                failed.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    _replace_path(destination, failed)
            except OSError as rollback_exc:  # pragma: no cover - catastrophic OS error
                rollback_errors.append(str(rollback_exc))
        for backup, destination, _label in reversed(backed_up):
            try:
                if backup.exists() or backup.is_symlink():
                    _replace_path(backup, destination)
            except OSError as rollback_exc:  # pragma: no cover - catastrophic OS error
                rollback_errors.append(str(rollback_exc))
        if rollback_errors:
            detail = "; ".join(rollback_errors)
            raise ManualRecoveryRequired(
                f"deployment install failed and rollback needs manual recovery in "
                f"{stage_root}: {detail}"
            ) from exc
        raise RuntimeError("deployment install failed; previous staging restored") from exc


def stage_sites_deployment(
    destination: str | Path,
    *,
    source_root: str | Path = ROOT,
) -> dict[str, Any]:
    destination_path = Path(destination)
    if destination_path.is_symlink():
        raise ValueError("destination must not be a symbolic link")
    target = destination_path.resolve()
    source = Path(source_root).resolve()
    if target == source or not target.is_dir():
        raise ValueError("destination must be an existing Sites project directory")
    hosting_path = target / ".openai/hosting.json"
    package_path = target / "package.json"
    if package_path.is_symlink() or not package_path.is_file():
        raise ValueError("destination is missing package.json")
    project_id = _hosting_project_id(hosting_path)

    snapshot = canonical_site_snapshot(source)
    site_files = {
        path.relative_to(SITE_ROOT_RELATIVE): content
        for path, content in snapshot.files.items()
        if path.is_relative_to(SITE_ROOT_RELATIVE)
    }
    html_sources = {
        path: content
        for path, content in site_files.items()
        if path.suffix.casefold() == ".html"
    }
    nested_html = sorted(
        path.as_posix() for path in html_sources if path.parent != Path(".")
    )
    if nested_html:
        raise ValueError(f"canonical HTML documents must be top-level: {nested_html}")
    if Path("index.html") not in html_sources or Path("404.html") not in html_sources:
        raise ValueError("canonical site has no required index and 404 documents")

    public_assets = {
        path: content
        for path, content in site_files.items()
        if path.suffix.casefold() != ".html"
        and path.name not in HOSTING_CONTROL_FILE_NAMES
    }
    worker_files = {
        Path("index.ts"): snapshot.files[Path("infra/sites/worker.ts")],
        Path("vite-env.d.ts"): snapshot.files[Path("infra/sites/vite-env.d.ts")],
        **{
            Path("documents", path.name): content
            for path, content in html_sources.items()
        },
    }
    public_root = target / "public"
    worker_root = target / "worker"
    manifest_path = target / STAGING_MANIFEST_RELATIVE
    _assert_safe_tree(public_root, target_root=target)
    _assert_safe_tree(worker_root, target_root=target)
    if manifest_path.is_symlink():
        raise ValueError("deployment staging manifest must not be a symbolic link")

    result = {
        "status": "PASS",
        "project_id": project_id,
        "destination": str(target),
        "source_commit": snapshot.commit,
        "canonical_site_sha256": snapshot.sha256,
        "canonical_file_count": len(snapshot.files),
        "bundled_documents": len(html_sources),
        "public_assets": len(public_assets),
        "direct_public_documents": 0,
    }
    stage_root = Path(tempfile.mkdtemp(prefix=STAGING_TEMP_PREFIX, dir=target))
    cleanup_stage = True
    try:
        next_root = stage_root / "next"
        staged_public = next_root / "public"
        staged_worker = next_root / "worker"
        staged_manifest = next_root / "manifest.json"
        next_root.mkdir()
        _mirror_tree(public_assets, staged_public, target_root=target)
        _mirror_tree(worker_files, staged_worker, target_root=target)

        direct_documents = sorted(
            path.relative_to(staged_public).as_posix()
            for path in staged_public.rglob("*.html")
        )
        if direct_documents:
            raise ValueError(
                f"public directory still contains HTML documents: {direct_documents}"
            )
        _write_file(
            (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            staged_manifest,
            target_root=target,
        )
        _transactional_install(
            target=target,
            stage_root=stage_root,
            replacements=(
                (staged_public, public_root, "public"),
                (staged_worker, worker_root, "worker"),
                (staged_manifest, manifest_path, "manifest.json"),
            ),
        )
    except ManualRecoveryRequired:
        cleanup_stage = False
        raise
    finally:
        if cleanup_stage and stage_root.exists():
            shutil.rmtree(stage_root)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="stage committed ReMediaLHQ site inputs into an existing Sites checkout"
    )
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    print(json.dumps(stage_sites_deployment(args.destination), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
