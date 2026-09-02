from __future__ import annotations

import hashlib
import json
import unittest
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath

from remedialhq.auth import DEFAULT_YOUTUBE_SCOPES
from remedialhq.canonical import sha256_json
from remedialhq.youtube_channel_setup import YOUTUBE_CHANNEL_SETUP_SCOPE
from scripts.build_public_release import _owner_identity_patterns, scan_release_blobs

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "ops/YOUTUBE_API_COMPLIANCE_EVIDENCE_MANIFEST.json"
PACKAGE_PATH = ROOT / "ops/YOUTUBE_API_COMPLIANCE_PACKAGE.md"
POLICY_PATHS = (
    ROOT / "site/privacy.html",
    ROOT / "site/terms.html",
    ROOT / "site/data-deletion.html",
)
YOUTUBE_TERMS = "https://www.youtube.com/t/terms"
GOOGLE_PRIVACY = "https://policies.google.com/privacy"
GOOGLE_PERMISSIONS = "https://security.google.com/settings/security/permissions"


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        if tag == "a" and attributes.get("href"):
            self.hrefs.append(str(attributes["href"]))


class YouTubeApiComplianceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policies = {
            path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
            for path in POLICY_PATHS
        }
        cls.package = PACKAGE_PATH.read_text(encoding="utf-8")
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_every_policy_discloses_api_scopes_links_and_lifecycle(self) -> None:
        required_lifecycle_copy = (
            "YouTube API Services",
            "refresh",
            "revoke",
            "within seven calendar days",
            "within 30 calendar days",
            "does not delete",
        )
        for path, document in self.policies.items():
            with self.subTest(path=path):
                parser = _LinkParser()
                parser.feed(document)
                self.assertIn(YOUTUBE_TERMS, parser.hrefs)
                self.assertIn(GOOGLE_PRIVACY, parser.hrefs)
                self.assertIn(GOOGLE_PERMISSIONS, parser.hrefs)
                for scope in (*DEFAULT_YOUTUBE_SCOPES, YOUTUBE_CHANNEL_SETUP_SCOPE):
                    self.assertIn(scope, document)
                for copy in required_lifecycle_copy:
                    self.assertIn(copy.casefold(), document.casefold())

    def test_privacy_policy_enumerates_data_use_and_sharing(self) -> None:
        privacy = self.policies["site/privacy.html"]
        for copy in (
            "OAuth grant details and credentials",
            "authorized channel ID, title, and URL",
            "video IDs, titles, descriptions, tags, category",
            "YouTube Analytics dimensions, metrics, and reports",
            "does not ask for or store a YouTube password",
            "does not sell or rent YouTube API data",
            "agents expressly approved by that user",
        ):
            with self.subTest(copy=copy):
                self.assertIn(copy, privacy)

    def test_terms_bind_connected_features_and_preserve_final_control(self) -> None:
        terms = self.policies["site/terms.html"]
        self.assertIn("you also agree to be bound by", terms)
        self.assertIn("retains final control over each YouTube upload", terms)
        self.assertIn("defaults the workflow to private", terms)
        self.assertIn("separate publication authority", terms)

    def test_deletion_page_distinguishes_local_and_youtube_deletion(self) -> None:
        deletion = self.policies["site/data-deletion.html"]
        self.assertIn("stops API use", deletion)
        self.assertIn("deletes the locally stored credential", deletion)
        self.assertIn("To remove a video or other data from YouTube", deletion)
        self.assertIn("does not permit ReMediaLHQ to retain YouTube API data", deletion)

    def test_manifest_sources_are_complete_digest_bound_regular_files(self) -> None:
        expected_paths = [
            "SECURITY.md",
            "config/publication_authority.json",
            "ops/YOUTUBE_API_COMPLIANCE_PACKAGE.md",
            "ops/YOUTUBE_CHANNEL_SETUP.md",
            "site/data-deletion.html",
            "site/privacy.html",
            "site/terms.html",
            "src/remedialhq/auth.py",
            "src/remedialhq/cli.py",
            "src/remedialhq/phases.py",
            "src/remedialhq/publishers/youtube.py",
            "src/remedialhq/youtube_channel_setup.py",
            "src/remedialhq/youtube_upload_control.py",
            "src/remedialhq/youtube_verification.py",
            "tests/test_auth.py",
            "tests/test_phases.py",
            "tests/test_youtube_api_compliance.py",
            "tests/test_youtube_adapter.py",
            "tests/test_youtube_channel_setup.py",
            "tests/test_youtube_upload_control.py",
            "tests/test_youtube_verification.py",
        ]
        rows = self.manifest["evidence_files"]
        self.assertEqual([row["path"] for row in rows], expected_paths)
        self.assertEqual(len({row["path"] for row in rows}), len(rows))

        for row in rows:
            with self.subTest(path=row["path"]):
                relative = PurePosixPath(row["path"])
                self.assertFalse(relative.is_absolute())
                self.assertNotIn("..", relative.parts)
                path = ROOT.joinpath(*relative.parts)
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                payload = path.read_bytes()
                self.assertEqual(row["bytes"], len(payload))
                self.assertEqual(row["sha256"], hashlib.sha256(payload).hexdigest())

    def test_manifest_has_canonical_self_digest(self) -> None:
        body = dict(self.manifest)
        recorded_digest = body.pop("manifest_sha256")
        self.assertEqual(recorded_digest, sha256_json(body))

    def test_manifest_matches_scope_authority_and_public_routes(self) -> None:
        self.assertEqual(
            self.manifest["schema_version"],
            "remedialhq.youtube-api-compliance-evidence.v1",
        )
        self.assertEqual(self.manifest["task_id"], "RMH-114")
        self.assertEqual(self.manifest["oauth_scopes"], list(DEFAULT_YOUTUBE_SCOPES))
        self.assertEqual(
            self.manifest["channel_setup_oauth_scopes"],
            [YOUTUBE_CHANNEL_SETUP_SCOPE],
        )
        self.assertFalse(self.manifest["contains_owner_secrets"])

        authority = json.loads(
            (ROOT / "config/publication_authority.json").read_text(encoding="utf-8")
        )
        snapshot = self.manifest["authority_snapshot"]
        self.assertEqual(snapshot["authority_status"], authority["authority_status"])
        self.assertEqual(
            snapshot["global_publication_enabled"],
            authority["global_publication_enabled"],
        )
        self.assertEqual(snapshot["youtube"], authority["platforms"]["youtube"])
        self.assertEqual(
            self.manifest["public_policy_routes"],
            {
                "data_deletion": {
                    "source": "site/data-deletion.html",
                    "url": "https://remedialhq.com/data-deletion",
                },
                "privacy": {
                    "source": "site/privacy.html",
                    "url": "https://remedialhq.com/privacy",
                },
                "terms": {
                    "source": "site/terms.html",
                    "url": "https://remedialhq.com/terms",
                },
            },
        )

    def test_manifest_keeps_soak_and_submission_evidence_pending(self) -> None:
        pending = {
            row["evidence_id"]: row for row in self.manifest["pending_evidence"]
        }
        deployment = pending["UPDATED_POLICY_DEPLOYMENT_READBACK"]
        self.assertEqual(deployment["status"], "VERIFIED")
        self.assertEqual(deployment["sites_version"], 19)
        self.assertEqual(
            deployment["evidence_form"],
            "SANITIZED_INLINE_DEPLOYMENT_READBACK_SUMMARY",
        )
        self.assertIsNone(deployment["artifact"])
        self.assertEqual(
            deployment["canonical_site_sha256"],
            "1443f5afcc6c9a85469112f54964e325307ed2e067f0859e8464ea90691b0936",
        )
        self.assertIn("Updated public policies are deployed and read back", self.package)

        soak = pending["RMH-113_PRIVATE_UNLISTED_SOAK"]
        self.assertEqual(soak["status"], "PENDING")
        self.assertEqual(soak["task_status"], "TODO")
        self.assertEqual(soak["readiness"], "WAITING")
        self.assertIsNone(soak["artifact"])

        submission = pending["YOUTUBE_API_COMPLIANCE_AUDIT_SUBMISSION"]
        self.assertEqual(submission["status"], "PENDING_OWNER_ACTION")
        self.assertIsNone(submission["artifact"])
        self.assertIn("Not submitted", self.package)
        self.assertIn("RMH-113 private and unlisted soak evidence is pending", self.package)

    def test_owner_oauth_requires_source_and_scope_bound_policy_acceptance(self) -> None:
        self.assertIn("youtube-policy-acceptance", self.package)
        self.assertIn("Implemented and tested; live owner evidence pending", self.package)
        self.assertNotIn(
            "OAuth flow does not present or record acceptance",
            self.package,
        )

    def test_upload_requires_exact_preview_and_single_use_confirmation(self) -> None:
        for copy in (
            "preview-youtube-upload",
            "confirm-youtube-upload",
            "exact preview SHA-256",
            "single-use consumption record",
            "Reusing a consumed confirmation is rejected",
        ):
            with self.subTest(copy=copy):
                self.assertIn(copy, self.package)
        snapshot = self.manifest["authority_snapshot"]
        self.assertFalse(snapshot["global_publication_enabled"])
        self.assertFalse(snapshot["youtube"]["private_upload_authorized"])
        self.assertFalse(snapshot["youtube"]["visible_upload_authorized"])

    def test_package_and_public_policies_do_not_expose_owner_credentials(self) -> None:
        public_documents = {
            "ops/YOUTUBE_API_COMPLIANCE_PACKAGE.md": self.package.encode("utf-8"),
            **{
                path: document.encode("utf-8")
                for path, document in self.policies.items()
            },
        }
        scan_release_blobs(
            public_documents,
            owner_identity_patterns=_owner_identity_patterns(),
        )
        public_material = b"\n".join(public_documents.values()).decode().casefold()
        for prohibited in (
            '"access_token"',
            '"refresh_token"',
            '"client_secret"',
            "ya29.",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, public_material)


if __name__ == "__main__":
    unittest.main()
