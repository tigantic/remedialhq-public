from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from scripts import build_public_release as release


class PublicReleaseBuilderTests(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    root: Path

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self._git("init", "-q")
        self._git("config", "user.name", "Release Test")
        self._git("config", "user.email", "release-test@example.invalid")
        self._write("VERSION", "1.2.3\n")
        self._write("README.md", "committed readme\n")
        self._commit("base")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _write(self, relative: str, value: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
        return path

    def _commit(self, message: str) -> None:
        self._git("add", "--all")
        self._git("commit", "-q", "-m", message)

    def _build(
        self,
        name: str = "public.zip",
        *,
        allow_generated_evidence_diffs: bool = False,
    ) -> tuple[Path, dict[str, object]]:
        output = self.root / name
        with patch.object(release, "ROOT", self.root):
            result = release.build_release(
                output,
                allow_generated_evidence_diffs=allow_generated_evidence_diffs,
            )
        return output, result

    def test_default_rejects_dirty_safe_source_even_when_not_package_eligible(self) -> None:
        self._write("docs/uncommitted.pem", "not packaged\n")
        self._git("add", "docs/uncommitted.pem")
        with self.assertRaisesRegex(ValueError, "not committed"):
            self._build()

    def test_post_validation_mode_rejects_dirty_private_root_input(self) -> None:
        self._write("Makefile", "package:\n\t@echo committed\n")
        self._commit("add private release command")
        self._write("Makefile", "package:\n\t@echo dirty\n")

        with self.assertRaisesRegex(ValueError, "Makefile"):
            self._build(allow_generated_evidence_diffs=True)

    def test_post_validation_mode_packages_exact_head_blobs(self) -> None:
        self._write("BUILD_REPORT.md", "committed evidence\n")
        self._commit("add build report")
        self._write("BUILD_REPORT.md", "new validation evidence\n")
        self._git("add", "BUILD_REPORT.md")

        with self.assertRaisesRegex(ValueError, "not committed"):
            self._build("strict.zip")
        output, result = self._build(
            "post-validation.zip",
            allow_generated_evidence_diffs=True,
        )

        prefix = "remedialhq-engine-v1.2.3"
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(
                archive.read(f"{prefix}/BUILD_REPORT.md"),
                b"committed evidence\n",
            )
        self.assertEqual(
            result["allowed_generated_evidence_diffs"],
            ["BUILD_REPORT.md"],
        )

    def test_post_validation_mode_is_a_closed_diff_allowlist(self) -> None:
        self._write("artifacts/validation/unit-tests.txt", "new evidence\n")
        self._build("allowed.zip", allow_generated_evidence_diffs=True)

        self._write("artifacts/validation/surprise.txt", "not an approved output\n")
        with self.assertRaisesRegex(ValueError, "surprise.txt"):
            self._build("rejected.zip", allow_generated_evidence_diffs=True)

        self._write("README.md", "dirty product source\n")
        with self.assertRaisesRegex(ValueError, "README.md"):
            self._build("source-rejected.zip", allow_generated_evidence_diffs=True)

    def test_archive_membership_uses_exact_public_file_allowlist(self) -> None:
        self._write("docs/00_EXECUTIVE_DIRECTIVE.md", "public directive\n")
        self._write("scripts/bootstrap_gcp.sh", "#!/bin/sh\nexit 0\n")
        os.chmod(self.root / "scripts/bootstrap_gcp.sh", 0o755)
        self._write("artifacts/launch/short-001-storyboard.json", "{}\n")
        self._write("docs/unreviewed.md", "not on the public file allowlist\n")
        self._write("scripts/unreviewed.sh", "#!/bin/sh\nexit 1\n")
        self._write("artifacts/launch/held-draft.txt", "held\n")
        self._write("artifacts/demo/run-report.json", "{}\n")
        self._write("artifacts/validation/unit-tests.txt", "PASS\n")
        self._write("artifacts/red-team/generated-draft-adjudication.json", "{}\n")
        self._write("artifacts/private/random.txt", "nonpublic\n")
        self._commit("archive membership")

        output, _ = self._build()
        prefix = "remedialhq-engine-v1.2.3"
        expected = {
            f"{prefix}/README.md",
            f"{prefix}/VERSION",
            f"{prefix}/docs/00_EXECUTIVE_DIRECTIVE.md",
            f"{prefix}/scripts/bootstrap_gcp.sh",
            f"{prefix}/artifacts/launch/short-001-storyboard.json",
            f"{prefix}/PACKAGE_CONTENTS.json",
            f"{prefix}/PACKAGE_SHA256SUMS.txt",
        }
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(set(archive.namelist()), expected)
            self.assertEqual(archive.testzip(), None)
            for info in archive.infolist():
                self.assertFalse(info.filename.endswith("/"))
                self.assertTrue(stat.S_ISREG(info.external_attr >> 16))
            contents = json.loads(
                archive.read(f"{prefix}/PACKAGE_CONTENTS.json")
            )
        privacy = contents["privacy_boundary"]
        self.assertNotIn("credentials_included", privacy)
        self.assertEqual(
            privacy["credential_pattern_scan"]["scope"],
            "every included blob",
        )
        self.assertEqual(
            privacy["credential_pattern_scan"]["assurance"],
            "BEST_EFFORT_PATTERN_MATCHING",
        )
        self.assertEqual(
            privacy["credential_pattern_scan"]["status"],
            "BEST_EFFORT_PASS",
        )
        self.assertIn(
            "not comprehensive proof",
            privacy["credential_pattern_scan"]["meaning"],
        )
        self.assertEqual(
            privacy["artifact_selection"],
            "closed public file allowlist",
        )
        self.assertEqual(
            privacy["owner_identity_pattern_scan"]["status"],
            "NOT_CONFIGURED",
        )
        self.assertEqual(
            privacy["owner_identity_pattern_scan"]["assurance"],
            "NO_PRIVATE_IDENTITY_INPUT",
        )
        self.assertIn(
            "not configured",
            privacy["owner_identity_pattern_scan"]["meaning"],
        )
        self.assertEqual(
            {row["path"] for row in contents["files"]},
            {
                "README.md",
                "VERSION",
                "docs/00_EXECUTIVE_DIRECTIVE.md",
                "scripts/bootstrap_gcp.sh",
                "artifacts/launch/short-001-storyboard.json",
            },
        )

    def test_extracted_archive_verifies_its_checksums_and_exact_inventory(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        self._write(
            "scripts/verify_manifest.py",
            (project_root / "scripts/verify_manifest.py").read_bytes(),
        )
        self._commit("add package verifier")
        output, _ = self._build()

        extract_root = self.root / "extracted"
        with zipfile.ZipFile(output) as archive:
            archive.extractall(extract_root)
        package_root = extract_root / "remedialhq-engine-v1.2.3"
        subprocess.run(
            ["git", "init", "-q", str(package_root)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(package_root), "add", "--all"],
            check=True,
            capture_output=True,
        )
        completed = subprocess.run(
            [sys.executable, "scripts/verify_manifest.py"],
            cwd=package_root,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("PACKAGE_SHA256SUMS.txt and exact package inventory", completed.stdout)

        subprocess.run(
            ["git", "-C", str(package_root), "update-index", "--chmod=+x", "README.md"],
            check=True,
            capture_output=True,
        )
        mode_rejected = subprocess.run(
            [sys.executable, "scripts/verify_manifest.py"],
            cwd=package_root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(mode_rejected.returncode, 0)
        self.assertIn("Git mode mismatch", mode_rejected.stderr)
        subprocess.run(
            ["git", "-C", str(package_root), "update-index", "--chmod=-x", "README.md"],
            check=True,
            capture_output=True,
        )

        nested_git_payload = package_root / "nested" / ".git" / "payload"
        nested_git_payload.parent.mkdir(parents=True)
        nested_git_payload.write_text("not clone metadata\n", encoding="utf-8")
        nested_rejected = subprocess.run(
            [sys.executable, "scripts/verify_manifest.py"],
            cwd=package_root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(nested_rejected.returncode, 0)
        self.assertIn("nested/.git/payload", nested_rejected.stderr)
        nested_git_payload.unlink()
        nested_git_payload.parent.rmdir()
        nested_git_payload.parent.parent.rmdir()

        (package_root / "unexpected.txt").write_text("not declared\n", encoding="utf-8")
        rejected = subprocess.run(
            [sys.executable, "scripts/verify_manifest.py"],
            cwd=package_root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("unexpected.txt", rejected.stderr)

    def test_rejects_committed_symbolic_link_mode(self) -> None:
        (self.root / "docs").mkdir()
        os.symlink("../README.md", self.root / "docs/00_EXECUTIVE_DIRECTIVE.md")
        self._commit("add symlink")
        with self.assertRaisesRegex(ValueError, "regular file"):
            self._build()

    def test_rejects_committed_gitlink_mode(self) -> None:
        commit = self._git("rev-parse", "HEAD")
        self._git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{commit},docs/00_EXECUTIVE_DIRECTIVE.md",
        )
        self._git("commit", "-q", "-m", "add gitlink")
        with (
            patch.object(release, "ROOT", self.root),
            self.assertRaisesRegex(ValueError, "regular file"),
        ):
            release.head_entries()

    def test_scans_every_blob_for_representative_credential_families(self) -> None:
        cases = {
            "cloudflare-token": b"cf" + b"ut_" + (b"A" * 32),
            "cloudflare-key": b"cf" + b"k_" + (b"B" * 32),
            "cloudflare-raw-env": b"CLOUDFLARE_API_TOKEN=" + (b"C" * 40),
            "github": b"gh" + b"p_" + (b"D" * 36),
            "openai": b"sk" + b"-proj-" + (b"E" * 32),
            "aws": b"AK" + b"IA" + (b"F" * 16),
            "stripe-secret": b"sk" + b"_live_" + (b"G" * 24),
            "stripe-restricted": b"rk" + b"_live_" + (b"H" * 24),
            "google": b"AI" + b"za" + (b"K" * 35),
            "jwt": b"eyJ" + (b"a" * 12) + b"." + (b"b" * 12) + b"." + (b"c" * 12),
            "generic": b"api" + b'_key = "' + (b"I" * 24) + b'"',
            "private-key": b"-----BEGIN " + b"PRIVATE KEY-----",
        }
        for label, payload in cases.items():
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, "credential-pattern"),
            ):
                release.scan_release_blobs({"docs/opaque.bin": payload})

    def test_binary_blob_is_scanned_during_archive_build(self) -> None:
        payload = b"binary\x00" + b"gh" + b"p_" + (b"J" * 36)
        self._write("brand/favicon.png", payload)
        self._commit("add binary payload")
        with self.assertRaisesRegex(ValueError, "credential-pattern"):
            self._build()

    def test_extensionless_blob_is_scanned_during_archive_build(self) -> None:
        payload = b"header\x00" + b"sk" + b"_live_" + (b"L" * 24)
        self._write("site/_headers", payload)
        self._commit("add extensionless payload")
        with self.assertRaisesRegex(ValueError, "credential-pattern"):
            self._build()

    def test_empty_example_secret_assignments_are_not_credentials(self) -> None:
        release.scan_release_blobs(
            {
                ".env.example": (
                    b"SERVICE_API_KEY=\n"
                    b"SERVICE_CLIENT_SECRET_FILE=\n"
                    b"PUBLISHING_ENABLED=false\n"
                )
            }
        )

    def test_scanner_and_its_tests_do_not_trigger_their_own_patterns(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        builder_source = (project_root / "scripts/build_public_release.py").read_bytes()
        self.assertNotIn(b"_OWNER_GIVEN_NAME", builder_source)
        self.assertNotIn(b"OWNER_IDENTITY_PATTERNS", builder_source)
        release.scan_release_blobs(
            {
                "scripts/build_public_release.py": builder_source,
                "tests/test_public_release.py": Path(__file__).read_bytes(),
            }
        )

    def test_missing_private_inventory_has_no_identity_patterns(self) -> None:
        with patch.object(release, "ROOT", self.root):
            self.assertEqual(release._owner_identity_patterns(), ())

    def test_malformed_committed_private_inventory_is_rejected(self) -> None:
        self._write("ops/account_inventory.json", "not JSON\n")
        self._commit("add malformed private inventory")
        with patch.object(release, "ROOT", self.root), self.assertRaisesRegex(
            ValueError,
            "committed private account inventory is invalid",
        ):
            release._owner_identity_patterns()

    def test_rejects_owner_identity_in_any_public_blob(self) -> None:
        inventory = {
            "owner": {"display_name": "Mara Kline"},
            "google": {
                "root_email": "mara@brand.example",
                "bootstrap_email": "launch-owner@example.invalid",
                "workspace_admin_email": "workspace-admin@brand.example",
                "gcp_project_id": "example-project-123456",
                "gcp_billing_account_id": "ABCDEF-123456-ABCDEF",
            },
        }
        self._write("ops/account_inventory.json", json.dumps(inventory))
        self._commit("add synthetic private inventory")
        with patch.object(release, "ROOT", self.root):
            identity_patterns = release._owner_identity_patterns()
        cases = {
            "legal-name": b"Mara Kline",
            "given-name": b"Mara",
            "case-insensitive-token": b"scope_for_mArA",
            "root-mailbox": b"mara@brand.example",
            "bootstrap-mailbox": b"launch-owner@example.invalid",
            "workspace-admin-mailbox": b"workspace-admin@brand.example",
            "cloud-project-id": b"example-project-123456",
            "cloud-billing-id": b"ABCDEF-123456-ABCDEF",
        }
        for label, payload in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError, "owner-identity"
            ):
                release.scan_release_blobs(
                    {"README.md": payload},
                    owner_identity_patterns=identity_patterns,
                )
        release.scan_release_blobs(
            {"README.md": b"launch-owner and an unrelated Kline"},
            owner_identity_patterns=identity_patterns,
        )

    def test_private_administrative_paths_never_enter_public_archive(self) -> None:
        self._write(
            "ops/account_inventory.json",
            b'{"owner":{"display_name":"Mara Kline"}}\n',
        )
        self._write("README.md", "public-safe readme\n")
        self._commit("add private administrative fixture")

        output, _ = self._build()
        with zipfile.ZipFile(output) as archive:
            names = set(archive.namelist())

        self.assertNotIn(
            "remedialhq-engine-v1.2.3/ops/account_inventory.json",
            names,
        )

    def test_public_evidence_dependencies_and_private_validation_boundary(self) -> None:
        public_dependencies = {
            "src/remedialhq/payment_evidence.py",
            "src/remedialhq/delivery_evidence.py",
            "scripts/check_google_artifact_analysis.py",
            "tests/test_payment_evidence.py",
            "tests/test_delivery_evidence.py",
            "tests/test_google_artifact_analysis.py",
        }
        private_validation = {
            "scripts/validate_release.py",
            "scripts/check_release_evidence.py",
            "tests/test_execution.py",
            "tests/test_release_integrity.py",
        }

        self.assertTrue(public_dependencies <= release.PUBLIC_FILE_PATHS)
        self.assertTrue(private_validation <= release.PRIVATE_ADMIN_PATHS)
        self.assertTrue(public_dependencies.isdisjoint(release.PRIVATE_ADMIN_PATHS))
        self.assertFalse(private_validation & {
            path
            for path in release.PUBLIC_FILE_PATHS
            if release._public_package_path(PurePosixPath(path))
        })

    def test_public_document_links_and_commands_are_package_closed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        included = {
            path
            for path in release.PUBLIC_FILE_PATHS
            if release._public_package_path(PurePosixPath(path))
            and (root / path).is_file()
        }
        self.assertTrue({"BOOTSTRAP.md", "START_HERE.md", "Makefile"}.isdisjoint(included))
        for relative in sorted(included):
            if not relative.endswith(".md"):
                continue
            text = (root / relative).read_text(encoding="utf-8")
            for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", text):
                target = match.group(1).strip("<>").split("#", 1)[0].split("?", 1)[0]
                if not target or re.match(
                    r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE
                ):
                    continue
                parts: list[str] = []
                for part in (PurePosixPath(relative).parent / target).parts:
                    if part in {"", "."}:
                        continue
                    if part == "..":
                        if not parts:
                            self.fail(f"{relative} links outside the package: {target}")
                        parts.pop()
                    else:
                        parts.append(part)
                resolved = "/".join(parts)
                self.assertTrue(
                    resolved in included
                    or any(path.startswith(f"{resolved.rstrip('/')}/") for path in included),
                    f"{relative} links to an excluded or missing path: {target}",
                )
            for candidate in re.findall(
                r"`((?:\.github|artifacts|brand|config|content|data|docs|infra|ops|"
                r"scripts|site|src|tests)/[A-Za-z0-9_./-]+)`",
                text,
            ):
                candidate = candidate.rstrip("/.,:;")
                if not (root / candidate).exists():
                    continue
                self.assertTrue(
                    candidate in included
                    or any(path.startswith(f"{candidate.rstrip('/')}/") for path in included),
                    f"{relative} names an excluded repository path: {candidate}",
                )

        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertLess(
            readme.index("git clone ../remedialhq-engine-v"),
            readme.index("python scripts/verify_manifest.py"),
        )
        self.assertLess(
            readme.index("python scripts/verify_manifest.py"),
            readme.index("python -m venv"),
        )
        self.assertIn("python -m venv ../remedialhq-venv", readme)
        for script in re.findall(r"python (scripts/[A-Za-z0-9_.-]+\.py)", readme):
            self.assertIn(script, included)

    def test_rejects_local_workstation_and_home_paths(self) -> None:
        cases = {
            "windows": b"C:" + b"\\Users\\operator\\Desktop\\file.txt",
            "wsl": b"/mnt/" + b"c/" + b"Users/operator/Documents/file.txt",
            "linux": b"/" + b"home/" + b"operator/project/file.txt",
            "macos": b"/" + b"Users/" + b"operator/project/file.txt",
            "windows-workspace": b"D:" + b"\\workspaces\\private\\file.txt",
            "posix-workspace": b"/" + b"workspace/private/file.txt",
        }
        for label, payload in cases.items():
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, "local-path"),
            ):
                release.scan_release_blobs({"docs/opaque.bin": payload})

    def test_rejects_current_home_and_release_workspace_paths(self) -> None:
        home_payload = (Path.home() / "private" / "file.txt").as_posix().encode()
        with self.assertRaisesRegex(ValueError, "current user home path"):
            release.scan_release_blobs({"README.md": home_payload})

        self._write(
            "README.md",
            f"generated from {(self.root / 'private' / 'source.txt').as_posix()}\n",
        )
        self._commit("add workspace leak")
        with self.assertRaisesRegex(ValueError, "current release workspace path"):
            self._build()


class PublicReleaseWorkflowTests(unittest.TestCase):
    def test_make_package_requires_committed_evidence_and_never_runs_validation(self) -> None:
        make = shutil.which("make")
        if make is None:
            self.skipTest("make is not available")

        project_root = Path(__file__).resolve().parents[1]
        if not (project_root / "Makefile").is_file():
            self.skipTest("private release Makefile is not distributed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copy2(project_root / "Makefile", root / "Makefile")
            shutil.copy2(
                project_root / "scripts/build_public_release.py",
                root / "scripts/build_public_release.py",
            )
            (root / "scripts/validate_release.py").write_text(
                "from pathlib import Path\n"
                "root = Path(__file__).resolve().parents[1]\n"
                "(root / 'BUILD_REPORT.md').write_text("
                "'fresh validation evidence\\n', encoding='utf-8')\n",
                encoding="utf-8",
            )
            (root / "scripts/check_release_evidence.py").write_text(
                "from pathlib import Path\n"
                "import subprocess\n"
                "root = Path(__file__).resolve().parents[1]\n"
                "result = subprocess.run([\n"
                "    'git', '-C', str(root), 'diff', '--quiet', '--', 'BUILD_REPORT.md'\n"
                "])\n"
                "raise SystemExit(result.returncode)\n",
                encoding="utf-8",
            )
            (root / "VERSION").write_text("1.2.3\n", encoding="utf-8")
            (root / "README.md").write_text("committed source\n", encoding="utf-8")
            (root / "BUILD_REPORT.md").write_text(
                "committed evidence\n", encoding="utf-8"
            )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Release Test"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "release-test@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(["git", "add", "--all"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "clean fixture"],
                cwd=root,
                check=True,
            )
            output = root / "release/workflow.zip"
            subprocess.run(
                [
                    make,
                    "package",
                    f"PYTHON={sys.executable}",
                    f"PACKAGE_OUTPUT={output}",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )

            prefix = "remedialhq-engine-v1.2.3"
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(
                    archive.read(f"{prefix}/BUILD_REPORT.md"),
                    b"committed evidence\n",
                )
                contents = json.loads(
                    archive.read(f"{prefix}/PACKAGE_CONTENTS.json")
                )
            self.assertNotIn("git_commit", contents)
            self.assertRegex(contents["source_snapshot_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(contents["source_policy"], "exact blobs from committed HEAD")
            self.assertEqual(
                (root / "BUILD_REPORT.md").read_text(encoding="utf-8"),
                "committed evidence\n",
            )

            ci_output = root / "release/ci-workflow.zip"
            subprocess.run(
                [
                    make,
                    "package-exact-head",
                    f"PYTHON={sys.executable}",
                    f"PACKAGE_OUTPUT={ci_output}",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            with zipfile.ZipFile(ci_output) as archive:
                self.assertEqual(
                    archive.read(f"{prefix}/BUILD_REPORT.md"),
                    b"committed evidence\n",
                )

            subprocess.run(
                [sys.executable, "scripts/validate_release.py"],
                cwd=root,
                check=True,
            )
            stale = subprocess.run(
                [
                    make,
                    "package",
                    f"PYTHON={sys.executable}",
                    f"PACKAGE_OUTPUT={root / 'release/stale.zip'}",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(stale.returncode, 0)
            subprocess.run(
                ["git", "add", "BUILD_REPORT.md"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-q", "-m", "commit fresh evidence"],
                cwd=root,
                check=True,
            )

            (root / "site").mkdir()
            (root / "site/untracked.js").write_text(
                "console.log('dirty');\n", encoding="utf-8"
            )
            rejected = subprocess.run(
                [
                    make,
                    "package-exact-head",
                    f"PYTHON={sys.executable}",
                    f"PACKAGE_OUTPUT={root / 'release/rejected.zip'}",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("site/untracked.js", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
