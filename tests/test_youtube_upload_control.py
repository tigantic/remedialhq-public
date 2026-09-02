from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest import mock

from remedialhq.canonical import sha256_json
from remedialhq.cli import _confirm_youtube_upload, _parser, _preview_youtube_upload
from remedialhq.models import Asset, ContentPackage, RightsStatus
from remedialhq.youtube_upload_control import (
    YOUTUBE_UPLOAD_CONFIRMATION_SCHEMA,
    YOUTUBE_UPLOAD_CONSUMPTION_SCHEMA,
    YOUTUBE_UPLOAD_PREVIEW_SCHEMA,
    YouTubeUploadControlError,
    claim_youtube_upload_authorization,
    create_youtube_upload_preview,
    load_youtube_upload_authorization,
    record_youtube_upload_confirmation,
)

CHANNEL_ID = "UCaaaaaaaaaaaaaaaaaaaaaa"
CREATED_AT = datetime(2026, 9, 2, 15, 0, tzinfo=UTC)


class YouTubeUploadControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.base = Path(self.temporary.name)
        self.root = self.base / "repository"
        self.private = self.base / "private"
        self.root.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        self.video = self.root / "video.mp4"
        self.thumbnail = self.root / "thumbnail.png"
        self.video.write_bytes(b"reviewed-video")
        self.thumbnail.write_bytes(b"reviewed-thumbnail")
        self.package = self._package()
        self.preview_path = self.private / "preview.json"
        self.confirmation_path = self.private / "confirmation.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _package(self) -> ContentPackage:
        return ContentPackage(
            package_id="PKG-UPLOAD-1-YOUTUBE",
            title="Exact reviewed title",
            body="Exact reviewed description.",
            platform="youtube",
            claim_ids=["CLM-1"],
            assets=[
                Asset(
                    "AST-VIDEO",
                    "video.mp4",
                    RightsStatus.ORIGINAL_GENERATED,
                    sha256=hashlib.sha256(self.video.read_bytes()).hexdigest(),
                ),
                Asset(
                    "AST-THUMB",
                    "thumbnail.png",
                    RightsStatus.ORIGINAL_GENERATED,
                    sha256=hashlib.sha256(self.thumbnail.read_bytes()).hexdigest(),
                ),
            ],
            disclosures={"independence"},
            metadata={
                "tags": ["analysis", "reviewed"],
                "youtube_category_id": "20",
                "youtube_contains_synthetic_media": True,
                "notify_subscribers": False,
            },
        )

    def _preview(self):
        return create_youtube_upload_preview(
            self.package,
            repository_root=self.root,
            output_path=self.preview_path,
            media_path=self.video,
            thumbnail_path=self.thumbnail,
            expected_channel_id=CHANNEL_ID,
            privacy_status="private",
            created_at=CREATED_AT,
        )

    def _confirm(self, preview_sha256: str):
        return record_youtube_upload_confirmation(
            self.preview_path,
            self.confirmation_path,
            repository_root=self.root,
            confirm_preview_sha256=preview_sha256,
            confirmed_at=CREATED_AT + timedelta(seconds=1),
        )

    def _authorization(self):
        return load_youtube_upload_authorization(
            self.package,
            repository_root=self.root,
            preview_path=self.preview_path,
            confirmation_path=self.confirmation_path,
            media_path=self.video,
            thumbnail_path=self.thumbnail,
            expected_channel_id=CHANNEL_ID,
            privacy_status="private",
        )

    def test_preview_binds_every_upload_field_and_exact_bytes(self) -> None:
        artifact = self._preview()

        self.assertEqual(artifact.payload["schema_version"], YOUTUBE_UPLOAD_PREVIEW_SCHEMA)
        self.assertEqual(artifact.payload["privacy_status"], "private")
        self.assertEqual(
            artifact.payload["target_channel"],
            {
                "channel_id": CHANNEL_ID,
                "channel_url": f"https://www.youtube.com/channel/{CHANNEL_ID}",
            },
        )
        self.assertEqual(
            artifact.payload["package"]["sha256"],
            sha256_json(self.package.to_dict()),
        )
        self.assertEqual(
            artifact.payload["video"]["sha256"],
            hashlib.sha256(self.video.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            artifact.payload["thumbnail"]["sha256"],
            hashlib.sha256(self.thumbnail.read_bytes()).hexdigest(),
        )
        metadata = artifact.payload["metadata"]
        self.assertEqual(metadata["body"]["status"]["privacyStatus"], "private")
        self.assertIs(metadata["body"]["status"]["selfDeclaredMadeForKids"], False)
        self.assertIs(metadata["body"]["status"]["containsSyntheticMedia"], True)
        self.assertIs(metadata["notifySubscribers"], False)
        self.assertIn("REMEDIALHQ_ID=PKG-UPLOAD-1-YOUTUBE:", metadata["body"]["snippet"]["description"])
        self.assertEqual(artifact.payload["metadata_sha256"], sha256_json(metadata))
        self.assertEqual(artifact.sha256, hashlib.sha256(self.preview_path.read_bytes()).hexdigest())
        if os.name == "posix":
            self.assertEqual(self.preview_path.stat().st_mode & 0o777, 0o600)

    def test_confirmation_requires_the_exact_displayed_preview_digest(self) -> None:
        preview = self._preview()
        with self.assertRaisesRegex(YouTubeUploadControlError, "does not match"):
            self._confirm("0" * 64)

        confirmation = self._confirm(preview.sha256)
        self.assertEqual(
            confirmation.payload["schema_version"], YOUTUBE_UPLOAD_CONFIRMATION_SCHEMA
        )
        self.assertEqual(confirmation.payload["preview_sha256"], preview.sha256)
        self.assertEqual(
            confirmation.payload["consent"],
            {
                "exact_upload_reviewed": True,
                "one_time_upload_authorized": True,
            },
        )

    def test_current_metadata_and_asset_bytes_must_still_match(self) -> None:
        preview = self._preview()
        self._confirm(preview.sha256)
        changed = self._package()
        changed.metadata["notify_subscribers"] = True
        with self.assertRaisesRegex(YouTubeUploadControlError, "current package"):
            load_youtube_upload_authorization(
                changed,
                repository_root=self.root,
                preview_path=self.preview_path,
                confirmation_path=self.confirmation_path,
                media_path=self.video,
                thumbnail_path=self.thumbnail,
                expected_channel_id=CHANNEL_ID,
                privacy_status="private",
            )

        self.video.write_bytes(b"changed-after-confirmation")
        with self.assertRaisesRegex(YouTubeUploadControlError, "reviewed SHA-256"):
            self._authorization()

    def test_channel_or_privacy_drift_is_rejected(self) -> None:
        preview = self._preview()
        self._confirm(preview.sha256)
        with self.assertRaisesRegex(YouTubeUploadControlError, "target_channel"):
            load_youtube_upload_authorization(
                self.package,
                repository_root=self.root,
                preview_path=self.preview_path,
                confirmation_path=self.confirmation_path,
                media_path=self.video,
                thumbnail_path=self.thumbnail,
                expected_channel_id="UCbbbbbbbbbbbbbbbbbbbbbb",
                privacy_status="private",
            )
        with self.assertRaisesRegex(YouTubeUploadControlError, "privacy_status"):
            load_youtube_upload_authorization(
                self.package,
                repository_root=self.root,
                preview_path=self.preview_path,
                confirmation_path=self.confirmation_path,
                media_path=self.video,
                thumbnail_path=self.thumbnail,
                expected_channel_id=CHANNEL_ID,
                privacy_status="unlisted",
            )

    def test_confirmation_is_atomically_consumed_once(self) -> None:
        preview = self._preview()
        self._confirm(preview.sha256)
        authorization = self._authorization()

        claimed = claim_youtube_upload_authorization(
            authorization,
            self.package,
            expected_channel_id=CHANNEL_ID,
            privacy_status="private",
            claimed_at=CREATED_AT + timedelta(seconds=2),
        )
        consumption = json.loads(authorization.consumption_path.read_text(encoding="utf-8"))
        self.assertEqual(
            consumption["schema_version"], YOUTUBE_UPLOAD_CONSUMPTION_SCHEMA
        )
        self.assertEqual(
            claimed.consumption_sha256,
            hashlib.sha256(authorization.consumption_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            authorization.consumption_path,
            self.private / f"{preview.sha256}.consumed.json",
        )
        if os.name == "posix":
            self.assertEqual(authorization.consumption_path.stat().st_mode & 0o777, 0o600)
        claimed.close()
        with self.assertRaisesRegex(YouTubeUploadControlError, "already been consumed"):
            claim_youtube_upload_authorization(
                authorization,
                self.package,
                expected_channel_id=CHANNEL_ID,
                privacy_status="private",
            )

    def test_confirmation_alias_cannot_create_a_second_consumption_scope(self) -> None:
        preview = self._preview()
        self._confirm(preview.sha256)
        alias = self.private / "confirmation-alias.json"
        os.link(self.confirmation_path, alias)
        original = self._authorization()
        claimed = claim_youtube_upload_authorization(
            original,
            self.package,
            expected_channel_id=CHANNEL_ID,
            privacy_status="private",
        )
        claimed.close()

        with self.assertRaisesRegex(YouTubeUploadControlError, "already been consumed"):
            load_youtube_upload_authorization(
                self.package,
                repository_root=self.root,
                preview_path=self.preview_path,
                confirmation_path=alias,
                media_path=self.video,
                thumbnail_path=self.thumbnail,
                expected_channel_id=CHANNEL_ID,
                privacy_status="private",
            )

    def test_copied_confirmation_cannot_create_a_second_consumption_scope(self) -> None:
        preview = self._preview()
        self._confirm(preview.sha256)
        copied = self.private / "confirmation-copy.json"
        shutil.copyfile(self.confirmation_path, copied)
        copied.chmod(0o600)
        claimed = claim_youtube_upload_authorization(
            self._authorization(),
            self.package,
            expected_channel_id=CHANNEL_ID,
            privacy_status="private",
        )
        claimed.close()

        with self.assertRaisesRegex(YouTubeUploadControlError, "already been consumed"):
            load_youtube_upload_authorization(
                self.package,
                repository_root=self.root,
                preview_path=self.preview_path,
                confirmation_path=copied,
                media_path=self.video,
                thumbnail_path=self.thumbnail,
                expected_channel_id=CHANNEL_ID,
                privacy_status="private",
            )

    def test_preview_binds_one_canonical_consumption_directory(self) -> None:
        consumption_directory = self.base / "canonical-consumptions"
        artifact = create_youtube_upload_preview(
            self.package,
            repository_root=self.root,
            output_path=self.preview_path,
            media_path=self.video,
            thumbnail_path=self.thumbnail,
            expected_channel_id=CHANNEL_ID,
            privacy_status="private",
            consumption_directory=consumption_directory,
            created_at=CREATED_AT,
        )
        self.assertEqual(
            artifact.payload["consumption"],
            {"directory": str(consumption_directory)},
        )
        if os.name == "posix":
            self.assertEqual(consumption_directory.stat().st_mode & 0o777, 0o700)

    def test_claim_pins_verified_bytes_and_preview_request(self) -> None:
        preview = self._preview()
        self._confirm(preview.sha256)
        authorization = self._authorization()
        claimed = claim_youtube_upload_authorization(
            authorization,
            self.package,
            expected_channel_id=CHANNEL_ID,
            privacy_status="private",
        )
        try:
            self.video.write_bytes(b"changed-path-video")
            self.thumbnail.write_bytes(b"changed-path-thumbnail")
            self.package.metadata["notify_subscribers"] = True
            self.assertEqual(claimed.media.read(), b"reviewed-video")
            self.assertEqual(claimed.thumbnail.read(), b"reviewed-thumbnail")
            self.assertIs(claimed.request_payload()["notifySubscribers"], False)
        finally:
            claimed.close()

    def test_preview_and_confirmation_cannot_be_stored_in_repository(self) -> None:
        with self.assertRaisesRegex(YouTubeUploadControlError, "outside the repository"):
            create_youtube_upload_preview(
                self.package,
                repository_root=self.root,
                output_path=self.root / "preview.json",
                media_path=self.video,
                thumbnail_path=self.thumbnail,
                expected_channel_id=CHANNEL_ID,
            )
        preview = self._preview()
        with self.assertRaisesRegex(YouTubeUploadControlError, "outside the repository"):
            record_youtube_upload_confirmation(
                self.preview_path,
                self.root / "confirmation.json",
                repository_root=self.root,
                confirm_preview_sha256=preview.sha256,
            )

    def test_cli_preview_and_confirmation_are_offline_only(self) -> None:
        preview_args = _parser().parse_args(
            [
                "preview-youtube-upload",
                "--root",
                str(self.root),
                "--media",
                str(self.video),
                "--thumbnail",
                str(self.thumbnail),
                "--expected-channel-id",
                CHANNEL_ID,
                "--preview-output",
                str(self.preview_path),
            ]
        )
        output = StringIO()
        with (
            mock.patch(
                "remedialhq.cli._youtube_upload_package", return_value=self.package
            ),
            mock.patch(
                "remedialhq.cli.load_youtube_credentials",
                side_effect=AssertionError("preview must not load credentials"),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(_preview_youtube_upload(preview_args), 0)
        preview_sha256 = json.loads(output.getvalue())["sha256"]

        confirmation_args = _parser().parse_args(
            [
                "confirm-youtube-upload",
                "--root",
                str(self.root),
                "--preview",
                str(self.preview_path),
                "--confirmation-output",
                str(self.confirmation_path),
                "--confirm-preview-sha256",
                preview_sha256,
            ]
        )
        with redirect_stdout(StringIO()):
            self.assertEqual(_confirm_youtube_upload(confirmation_args), 0)
        self.assertTrue(self.confirmation_path.is_file())


if __name__ == "__main__":
    unittest.main()
