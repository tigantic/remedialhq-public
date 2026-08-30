from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import stage_sites_deployment as staging
from scripts.stage_sites_deployment import ROOT, stage_sites_deployment


def _run_git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
    )


def _git_bytes(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
    ).stdout


def _make_source_repository(parent: Path) -> Path:
    source = parent / "source"
    shutil.copytree(ROOT / "site", source / "site")
    (source / "infra/sites").mkdir(parents=True)
    for name in ("worker.ts", "vite-env.d.ts"):
        shutil.copy2(ROOT / f"infra/sites/{name}", source / f"infra/sites/{name}")
    _run_git(source, "init", "-q")
    _run_git(source, "config", "user.email", "test@example.invalid")
    _run_git(source, "config", "user.name", "Test")
    _run_git(source, "add", "site", "infra/sites")
    _run_git(source, "commit", "-q", "-m", "site fixture")
    return source


def _make_destination(parent: Path) -> Path:
    target = parent / "target"
    (target / ".openai").mkdir(parents=True)
    (target / "public").mkdir()
    (target / "worker").mkdir()
    (target / ".openai/hosting.json").write_text(
        json.dumps({"project_id": "project_test"}), encoding="utf-8"
    )
    (target / "package.json").write_text("{}\n", encoding="utf-8")
    return target


def _tree_snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


class SitesStagingTests(unittest.TestCase):
    def test_stages_committed_documents_and_exact_public_asset_mirror(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            (target / "public/data").mkdir()
            (target / "public/data/stale.json").write_text("{}\n", encoding="utf-8")
            (target / "public/stale.json").write_text("{}\n", encoding="utf-8")
            (target / "public/images").mkdir()
            (target / "public/images/stale.png").write_bytes(b"stale")
            (target / "public/archive").mkdir()
            (target / "public/archive/nested.html").write_text(
                "stale\n", encoding="utf-8"
            )
            (target / "public/_redirects").write_text("stale\n", encoding="utf-8")
            (target / "worker/documents/legacy").mkdir(parents=True)
            (target / "worker/documents/legacy/nested.html").write_text(
                "stale\n", encoding="utf-8"
            )
            (target / "worker/legacy.ts").write_text("stale\n", encoding="utf-8")

            result = stage_sites_deployment(target, source_root=source)

            canonical_documents = sorted(path.name for path in (source / "site").glob("*.html"))
            staged_documents = sorted(
                path.name for path in (target / "worker/documents").glob("*.html")
            )
            expected_assets = sorted(
                path.relative_to(source / "site").as_posix()
                for path in (source / "site").rglob("*")
                if path.is_file()
                and path.suffix.casefold() != ".html"
                and path.name not in {"_headers", "_redirects"}
            )
            staged_assets = sorted(
                path.relative_to(target / "public").as_posix()
                for path in (target / "public").rglob("*")
                if path.is_file()
            )
            expected_worker_files = sorted(
                ["index.ts", "vite-env.d.ts"]
                + [f"documents/{name}" for name in canonical_documents]
            )
            staged_worker_files = sorted(
                path.relative_to(target / "worker").as_posix()
                for path in (target / "worker").rglob("*")
                if path.is_file()
            )
            self.assertEqual(staged_documents, canonical_documents)
            self.assertEqual(staged_assets, expected_assets)
            self.assertEqual(staged_worker_files, expected_worker_files)
            self.assertEqual(result["bundled_documents"], len(canonical_documents))
            self.assertEqual(result["direct_public_documents"], 0)
            self.assertFalse(any((target / "public").rglob("*.html")))
            self.assertFalse((target / "public/data/stale.json").exists())
            self.assertFalse((target / "public/stale.json").exists())
            self.assertFalse((target / "public/images/stale.png").exists())
            self.assertFalse((target / "public/_headers").exists())
            self.assertFalse((target / "public/_redirects").exists())
            self.assertFalse((target / "worker/documents/legacy").exists())
            self.assertFalse((target / "worker/legacy.ts").exists())
            self.assertEqual(
                (target / "worker/index.ts").read_bytes(),
                _git_bytes(source, "show", "HEAD:infra/sites/worker.ts"),
            )
            manifest = json.loads(
                (target / ".openai/remedialhq-staging-manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["project_id"], "project_test")
            self.assertEqual(manifest["source_commit"], result["source_commit"])
            self.assertEqual(
                manifest["canonical_site_sha256"], result["canonical_site_sha256"]
            )
            self.assertEqual(
                manifest["canonical_file_count"], result["canonical_file_count"]
            )
            self.assertFalse(
                any(path.name.startswith(staging.STAGING_TEMP_PREFIX) for path in target.iterdir())
            )

    def test_write_failure_leaves_previous_destination_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            (target / "public/previous.json").write_text("public\n", encoding="utf-8")
            (target / "worker/previous.ts").write_text("worker\n", encoding="utf-8")
            (target / ".openai/remedialhq-staging-manifest.json").write_text(
                "previous\n", encoding="utf-8"
            )
            before = _tree_snapshot(target)
            original_write = staging._write_file
            writes = 0

            def interrupted_write(
                content: bytes,
                destination: Path,
                *,
                target_root: Path,
            ) -> None:
                nonlocal writes
                writes += 1
                if writes == 2:
                    raise OSError("injected staging write failure")
                original_write(content, destination, target_root=target_root)

            with (
                mock.patch.object(
                    staging, "_write_file", side_effect=interrupted_write
                ),
                self.assertRaisesRegex(OSError, "injected staging write failure"),
            ):
                stage_sites_deployment(target, source_root=source)

            self.assertEqual(_tree_snapshot(target), before)
            self.assertFalse(
                any(path.name.startswith(staging.STAGING_TEMP_PREFIX) for path in target.iterdir())
            )

    def test_swap_failure_rolls_back_both_trees_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            (target / "public/previous.json").write_text("public\n", encoding="utf-8")
            (target / "worker/previous.ts").write_text("worker\n", encoding="utf-8")
            (target / ".openai/remedialhq-staging-manifest.json").write_text(
                "previous\n", encoding="utf-8"
            )
            before = _tree_snapshot(target)
            replacements = 0

            def interrupted_replace(source_path: Path, destination_path: Path) -> None:
                nonlocal replacements
                replacements += 1
                if replacements == 4:
                    raise OSError("injected swap failure")
                os.replace(source_path, destination_path)

            with (
                mock.patch.object(
                    staging, "_replace_path", side_effect=interrupted_replace
                ),
                self.assertRaisesRegex(RuntimeError, "previous staging restored"),
            ):
                stage_sites_deployment(target, source_root=source)

            self.assertEqual(_tree_snapshot(target), before)
            self.assertFalse(
                any(path.name.startswith(staging.STAGING_TEMP_PREFIX) for path in target.iterdir())
            )

    def test_rejects_destination_without_project_identity(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            (target / ".openai/hosting.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "project_id"):
                stage_sites_deployment(target, source_root=source)

    def test_rejects_linked_document_directory(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            outside = temporary_root / "outside"
            outside.mkdir()
            (target / "worker/documents").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symbolic links"):
                stage_sites_deployment(target, source_root=source)

    def test_rejects_untracked_canonical_site_input(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            (target / "public/sentinel.json").write_text("kept\n", encoding="utf-8")
            (source / "site/untracked.json").write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "uncommitted or untracked"):
                stage_sites_deployment(target, source_root=source)
            self.assertEqual(
                (target / "public/sentinel.json").read_text(encoding="utf-8"),
                "kept\n",
            )

    def test_rejects_ignored_untracked_canonical_site_input(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            (source / ".gitignore").write_text(
                "site/private.json\n", encoding="utf-8"
            )
            _run_git(source, "add", ".gitignore")
            _run_git(source, "commit", "-q", "-m", "ignore private fixture")
            (source / "site/private.json").write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "uncommitted or untracked"):
                stage_sites_deployment(target, source_root=source)

    def test_rejects_dirty_canonical_site_input(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            with (source / "site/app.js").open("a", encoding="utf-8") as handle:
                handle.write("\n// dirty\n")

            with self.assertRaisesRegex(ValueError, "uncommitted or untracked"):
                stage_sites_deployment(target, source_root=source)

    def test_rejects_dirty_worker_source_input(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            with (source / "infra/sites/worker.ts").open("a", encoding="utf-8") as handle:
                handle.write("\n// dirty\n")

            with self.assertRaisesRegex(ValueError, "uncommitted or untracked"):
                stage_sites_deployment(target, source_root=source)

    def test_rejects_linked_public_asset_without_touching_link_target(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            target = _make_destination(temporary_root)
            outside = temporary_root / "outside.json"
            outside.write_text("outside\n", encoding="utf-8")
            (target / "public/linked.json").symlink_to(outside)

            with self.assertRaisesRegex(ValueError, "symbolic links"):
                stage_sites_deployment(target, source_root=source)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")


if __name__ == "__main__":
    unittest.main()
