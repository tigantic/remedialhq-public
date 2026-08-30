from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import build_public_bundle


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _info(name: str, mode: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 8, 30, 4, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = int(mode, 8) << 16
    return info


def _write_package(
    path: Path,
    files: dict[str, tuple[bytes, str]],
    *,
    version: str = "9.9.9",
) -> None:
    prefix = f"remedialhq-engine-v{version}"
    rows = [
        {"path": name, "mode": mode, "sha256": _digest(data), "bytes": len(data)}
        for name, (data, mode) in sorted(files.items())
    ]
    contents = (
        json.dumps(
            {
                "schema_version": 2,
                "release": f"v{version}",
                "files": rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    sums = [f"{row['sha256']}  {row['path']}" for row in rows]
    sums.append(f"{_digest(contents)}  PACKAGE_CONTENTS.json")
    sums_data = ("\n".join(sums) + "\n").encode()
    members = {
        **files,
        "PACKAGE_CONTENTS.json": (contents, "100644"),
        "PACKAGE_SHA256SUMS.txt": (sums_data, "100644"),
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, (data, mode) in members.items():
            archive.writestr(_info(f"{prefix}/{name}", mode), data)


class PublicBundleTests(unittest.TestCase):
    def test_in_archive_verifier_is_never_executed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            sentinel = root / "untrusted-verifier-ran"
            verifier = (
                "from pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('unsafe')\n"
                "print('PASS: forged')\n"
            ).encode()
            archive = root / "public.zip"
            _write_package(
                archive,
                {
                    "VERSION": (b"9.9.9\n", "100644"),
                    "scripts/verify_manifest.py": (verifier, "100755"),
                },
            )

            result = build_public_bundle.build_public_bundle(
                archive, root / "public.bundle"
            )

            self.assertEqual(result["status"], "PASS")
            self.assertFalse(sentinel.exists())

    def test_git_metadata_and_hooks_are_rejected_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            sentinel = root / "hook-ran"
            hook = f"#!/bin/sh\ntouch {sentinel}\n".encode()
            archive = root / "hook.zip"
            _write_package(
                archive,
                {
                    "VERSION": (b"9.9.9\n", "100644"),
                    ".git/hooks/pre-commit": (hook, "100755"),
                },
            )

            with self.assertRaisesRegex(ValueError, "unsafe member path"):
                build_public_bundle.build_public_bundle(
                    archive, root / "public.bundle"
                )
            self.assertFalse(sentinel.exists())

    def test_member_size_limit_is_checked_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            archive = root / "large.zip"
            _write_package(archive, {"VERSION": (b"9.9.9\n", "100644")})

            with (
                patch.object(build_public_bundle, "MAX_MEMBER_BYTES", 1),
                self.assertRaisesRegex(ValueError, "member is too large"),
            ):
                build_public_bundle.build_public_bundle(
                    archive, root / "public.bundle"
                )

    def test_high_compression_ratio_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            archive = root / "ratio.zip"
            _write_package(
                archive,
                {
                    "VERSION": (b"9.9.9\n", "100644"),
                    "zeros.bin": (b"0" * (1024 * 1024), "100644"),
                },
            )

            with self.assertRaisesRegex(ValueError, "compression ratio is unsafe"):
                build_public_bundle.build_public_bundle(
                    archive, root / "public.bundle"
                )

    def test_normalized_path_collisions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            archive = root / "collision.zip"
            _write_package(
                archive,
                {
                    "VERSION": (b"9.9.9\n", "100644"),
                    "README.md": (b"one\n", "100644"),
                    "readme.md": (b"two\n", "100644"),
                },
            )

            with self.assertRaisesRegex(ValueError, "normalized path collision"):
                build_public_bundle.build_public_bundle(
                    archive, root / "public.bundle"
                )

    def test_hostile_git_environment_is_removed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            archive = root / "public.zip"
            bundle = root / "public.bundle"
            sentinel = root / "hostile-hook-ran"
            redirected_git = root / "redirected-git"
            hooks = root / "hostile-hooks"
            hooks.mkdir()
            hook = hooks / "pre-commit"
            hook.write_text(f"#!/bin/sh\ntouch {sentinel}\n", encoding="utf-8")
            hook.chmod(0o755)
            _write_package(archive, {"VERSION": (b"9.9.9\n", "100644")})
            hostile = {
                "GIT_DIR": str(redirected_git),
                "GIT_WORK_TREE": str(root),
                "GIT_INDEX_FILE": str(root / "hostile-index"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.hooksPath",
                "GIT_CONFIG_VALUE_0": str(hooks),
                "GIT_AUTHOR_NAME": "Private Owner",
                "GIT_AUTHOR_EMAIL": "private@example.invalid",
                "GIT_COMMITTER_NAME": "Private Owner",
                "GIT_COMMITTER_EMAIL": "private@example.invalid",
            }

            with patch.dict(os.environ, hostile):
                result = build_public_bundle.build_public_bundle(archive, bundle)

            self.assertEqual(result["status"], "PASS")
            self.assertFalse(sentinel.exists())
            self.assertFalse(redirected_git.exists())
            checkout = root / "checkout"
            subprocess.run(
                ["git", "clone", "--quiet", str(bundle), str(checkout)], check=True
            )
            identity = subprocess.run(
                ["git", "-C", str(checkout), "show", "-s", "--format=%an%n%ae"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("ReMediaLHQ Release", identity)
            self.assertIn("support@remedialhq.com", identity)
            self.assertNotIn("Private Owner", identity)
            self.assertNotIn("private@example.invalid", identity)

    def test_final_publish_never_overwrites_a_racing_target(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            archive = root / "public.zip"
            bundle = root / "public.bundle"
            _write_package(archive, {"VERSION": (b"9.9.9\n", "100644")})

            def collide(_source: Path, destination: Path) -> None:
                Path(destination).write_bytes(b"competitor")
                raise FileExistsError

            with (
                patch.object(os, "link", side_effect=collide),
                self.assertRaisesRegex(ValueError, "refusing to overwrite"),
            ):
                build_public_bundle.build_public_bundle(archive, bundle)

            self.assertEqual(bundle.read_bytes(), b"competitor")

    def test_private_paths_and_credential_patterns_never_enter_bundle(self) -> None:
        cases = (
            (
                "private_path",
                "local-private/owner_profile.private.json",
                b'{"owner": "private"}\n',
                "outside the trusted public allowlist",
            ),
            (
                "credential",
                "README.md",
                b"representative=sk_live_" + (b"Z" * 24) + b"\n",
                "credential-pattern scan failed",
            ),
        )
        for label, relative, content, expected_error in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                dir="/tmp"
            ) as directory:
                root = Path(directory)
                archive = root / "private.zip"
                _write_package(
                    archive,
                    {
                        "VERSION": (b"9.9.9\n", "100644"),
                        relative: (content, "100644"),
                    },
                )

                with self.assertRaisesRegex(ValueError, expected_error):
                    build_public_bundle.build_public_bundle(
                        archive, root / "public.bundle"
                    )
                self.assertFalse((root / "public.bundle").exists())


if __name__ == "__main__":
    unittest.main()
