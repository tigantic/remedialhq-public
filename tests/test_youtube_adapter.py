import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from remedialhq.models import Asset, ContentPackage, RightsStatus
from remedialhq.publishers.youtube import (
    MAX_DESCRIPTION_LENGTH,
    ResumableUploadError,
    YouTubePublisher,
    _description,
    _execute_resumable_upload,
)


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status


class _HttpError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.resp = _Response(status)


class _Request:
    def __init__(self, values):
        self.values = iter(values)

    def next_chunk(self):
        value = next(self.values)
        if isinstance(value, BaseException):
            raise value
        return None, value


def _package(body: str = "A useful independent analysis.") -> ContentPackage:
    return ContentPackage(
        package_id="PKG-TEST-1-YOUTUBE",
        title="Evidence-led launch analysis",
        body=body,
        platform="youtube",
        claim_ids=["CLM-1"],
        disclosures={"independence"},
        metadata={},
    )


class YouTubeAdapterTests(unittest.TestCase):
    def test_visible_upload_requires_separate_authority(self) -> None:
        with self.assertRaises(PermissionError):
            YouTubePublisher(object(), "video.mp4", privacy_status="public")
        publisher = YouTubePublisher(
            object(),
            "video.mp4",
            privacy_status="unlisted",
            public_publication_authorized=True,
        )
        self.assertEqual(publisher.privacy_status, "unlisted")

    def test_description_is_bounded_and_contains_identity(self) -> None:
        value = _description(_package("x" * 8_000))
        self.assertLessEqual(len(value), MAX_DESCRIPTION_LENGTH)
        self.assertIn("Independent editorial coverage", value)
        self.assertIn("REMEDIALHQ_ID=PKG-TEST-1-YOUTUBE:", value)

    def test_resumable_retry_then_success(self) -> None:
        delays = []
        request = _Request([_HttpError(503), None, {"id": "video-7"}])
        response = _execute_resumable_upload(
            request,
            max_retries=2,
            sleeper=delays.append,
            jitter=lambda: 0.0,
        )
        self.assertEqual(response["id"], "video-7")
        self.assertEqual(delays, [1.0])

    def test_retry_exhaustion_fails_closed(self) -> None:
        request = _Request([_HttpError(500), _HttpError(503)])
        with self.assertRaises(ResumableUploadError):
            _execute_resumable_upload(
                request,
                max_retries=1,
                sleeper=lambda _: None,
                jitter=lambda: 0.0,
            )

    def test_non_retriable_error_is_not_hidden(self) -> None:
        request = _Request([_HttpError(403)])
        with self.assertRaises(_HttpError):
            _execute_resumable_upload(request, sleeper=lambda _: None)

    def test_upload_bytes_and_storyboard_must_match_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            video = root / "video.mp4"
            video.write_bytes(b"reviewed-video")
            storyboard = root / "storyboard.json"
            storyboard.write_text(
                json.dumps(
                    [
                        {
                            "scene": 1,
                            "hero": "82 DAYS",
                            "sub": "Currently scheduled launch",
                            "claim_ids": ["CLM-1"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            package = _package()
            package.assets = [
                Asset(
                    "AST-VIDEO",
                    "video.mp4",
                    RightsStatus.ORIGINAL_GENERATED,
                    sha256=hashlib.sha256(video.read_bytes()).hexdigest(),
                )
            ]
            package.metadata["media_review"] = {
                "asset_id": "AST-VIDEO",
                "storyboard_path": "storyboard.json",
                "storyboard_sha256": hashlib.sha256(storyboard.read_bytes()).hexdigest(),
            }
            publisher = YouTubePublisher(object(), video, asset_root=root)
            publisher._validate_declared_assets(package)

            video.write_bytes(b"changed-after-review")
            with self.assertRaisesRegex(PermissionError, "reviewed sha256"):
                publisher._validate_declared_assets(package)


if __name__ == "__main__":
    unittest.main()
