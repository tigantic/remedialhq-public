import hashlib
import json
import sys
import tempfile
import types
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from remedialhq.models import Asset, ContentPackage, RightsStatus
from remedialhq.publishers.youtube import (
    MAX_DESCRIPTION_LENGTH,
    ResumableUploadError,
    YouTubePublisher,
    _description,
    _execute_resumable_upload,
    _publication_marker,
)
from remedialhq.youtube_upload_control import build_youtube_upload_request


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


class _ExecuteRequest:
    def __init__(self, value):
        self.value = value

    def execute(self):
        return self.value


class _SearchResource:
    def __init__(self, response=None):
        self.response = response or {"items": []}

    def list(self, **_kwargs):
        return _ExecuteRequest(self.response)


class _VideosResource:
    def __init__(self, upload_response, detail_response=None):
        self.upload_response = upload_response
        self.detail_response = detail_response or {"items": []}
        self.insert_calls = []
        self.update_calls = []

    def insert(self, **kwargs):
        self.insert_calls.append(kwargs)
        return _Request([self.upload_response])

    def list(self, **_kwargs):
        return _ExecuteRequest(self.detail_response)

    def update(self, **kwargs):
        self.update_calls.append(kwargs)
        return _ExecuteRequest({})


class _ThumbnailsResource:
    def __init__(self, thumbnail_response):
        self.thumbnail_response = thumbnail_response
        self.calls = []

    def set(self, **kwargs):
        self.calls.append(kwargs)
        return _ExecuteRequest(self.thumbnail_response)


class _YouTubeClient:
    def __init__(
        self,
        upload_response,
        thumbnail_response,
        *,
        search_response=None,
        detail_response=None,
    ):
        self.search_resource = _SearchResource(search_response)
        self.video_resource = _VideosResource(upload_response, detail_response)
        self.thumbnail_resource = _ThumbnailsResource(thumbnail_response)

    def search(self):
        return self.search_resource

    def videos(self):
        return self.video_resource

    def thumbnails(self):
        return self.thumbnail_resource


def _google_modules(youtube):
    package = types.ModuleType("googleapiclient")
    discovery = types.ModuleType("googleapiclient.discovery")
    http = types.ModuleType("googleapiclient.http")
    discovery.build = lambda *_args, **_kwargs: youtube
    http.MediaIoBaseUpload = lambda handle, **kwargs: (handle, kwargs)
    return {
        "googleapiclient": package,
        "googleapiclient.discovery": discovery,
        "googleapiclient.http": http,
    }


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


def _authorization(video: Path, thumbnail: Path) -> SimpleNamespace:
    return SimpleNamespace(
        media_path=video.resolve(),
        thumbnail_path=thumbnail.resolve(),
        preview_sha256="a" * 64,
        confirmation_sha256="b" * 64,
    )


def _claimed(package: ContentPackage) -> SimpleNamespace:
    return SimpleNamespace(
        media=BytesIO(b"video"),
        thumbnail=BytesIO(b"thumbnail"),
        publication_marker=_publication_marker(package),
        consumption_sha256="c" * 64,
        request_payload=lambda: build_youtube_upload_request(package, "private"),
        close=mock.Mock(),
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

    def test_initial_upload_returns_sanitized_verification_evidence(self) -> None:
        channel_id = "UCaaaaaaaaaaaaaaaaaaaaaa"
        video_id = "AbCdEfGhI_1"
        # Keep the fixture credential-shaped without embedding a scanner match.
        sensitive_field = "_".join(("access", "token"))  # noqa: FLY002
        upload_response = {
            "kind": "youtube#video",
            "id": video_id,
            "snippet": {
                "channelId": channel_id,
                "title": "not required by verification",
            },
            "status": {"privacyStatus": "private"},
            sensitive_field: "must-not-survive",
        }
        thumbnail_response = {
            "kind": "youtube#thumbnailSetResponse",
            "etag": "not required by verification",
            "items": [
                {
                    "default": {
                        "url": f"https://i.ytimg.com/vi/{video_id}/default.jpg",
                        "width": 120,
                        "height": 90,
                        "authorization": "must-not-survive",
                    }
                }
            ],
        }
        youtube = _YouTubeClient(upload_response, thumbnail_response)

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            video = root / "video.mp4"
            thumbnail = root / "thumbnail.png"
            video.write_bytes(b"video")
            thumbnail.write_bytes(b"thumbnail")
            publisher = YouTubePublisher(
                object(),
                video,
                thumbnail_path=thumbnail,
                asset_root=root,
                expected_channel_id=channel_id,
                verification_evidence_required=True,
                upload_authorization=_authorization(video, thumbnail),
            )
            with (
                mock.patch.dict(sys.modules, _google_modules(youtube)),
                mock.patch.object(publisher, "_validate_declared_assets"),
                mock.patch(
                    "remedialhq.publishers.youtube.claim_youtube_upload_authorization",
                    return_value=_claimed(_package()),
                ),
            ):
                result = publisher.publish(_package())

        self.assertEqual(result.remote_id, video_id)
        self.assertIsNotNone(result.details)
        evidence = result.details["verification_api_evidence"]
        serialized = json.dumps(evidence)
        self.assertNotIn("must-not-survive", serialized)
        self.assertNotIn("not required by verification", serialized)
        self.assertEqual(evidence["video_id"], video_id)
        self.assertEqual(len(youtube.thumbnail_resource.calls), 1)

    def test_required_evidence_fails_when_thumbnail_response_is_absent(self) -> None:
        channel_id = "UCaaaaaaaaaaaaaaaaaaaaaa"
        video_id = "AbCdEfGhI_1"
        upload_response = {
            "kind": "youtube#video",
            "id": video_id,
            "snippet": {"channelId": channel_id},
            "status": {"privacyStatus": "private"},
        }
        youtube = _YouTubeClient(upload_response, None)

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            video = root / "video.mp4"
            thumbnail = root / "thumbnail.png"
            video.write_bytes(b"video")
            thumbnail.write_bytes(b"thumbnail")
            publisher = YouTubePublisher(
                object(),
                video,
                thumbnail_path=thumbnail,
                asset_root=root,
                expected_channel_id=channel_id,
                verification_evidence_required=True,
                upload_authorization=_authorization(video, thumbnail),
            )
            with (
                mock.patch.dict(sys.modules, _google_modules(youtube)),
                mock.patch.object(publisher, "_validate_declared_assets"),
                mock.patch(
                    "remedialhq.publishers.youtube.claim_youtube_upload_authorization",
                    return_value=_claimed(_package()),
                ),
                self.assertRaisesRegex(RuntimeError, "thumbnail-set response evidence"),
            ):
                publisher.publish(_package())

    def test_publish_refuses_to_construct_client_without_confirmation(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            video = root / "video.mp4"
            thumbnail = root / "thumbnail.png"
            video.write_bytes(b"video")
            thumbnail.write_bytes(b"thumbnail")
            publisher = YouTubePublisher(
                object(),
                video,
                thumbnail_path=thumbnail,
                asset_root=root,
                expected_channel_id="UCaaaaaaaaaaaaaaaaaaaaaa",
            )
            with (
                mock.patch.object(publisher, "_validate_declared_assets"),
                self.assertRaisesRegex(PermissionError, "exact-preview confirmation"),
            ):
                publisher.publish(_package())

    def test_confirmation_is_claimed_before_youtube_client_construction(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            video = root / "video.mp4"
            thumbnail = root / "thumbnail.png"
            video.write_bytes(b"video")
            thumbnail.write_bytes(b"thumbnail")
            publisher = YouTubePublisher(
                object(),
                video,
                thumbnail_path=thumbnail,
                asset_root=root,
                expected_channel_id="UCaaaaaaaaaaaaaaaaaaaaaa",
                upload_authorization=_authorization(video, thumbnail),
            )
            modules = _google_modules(object())
            builder = mock.Mock(side_effect=AssertionError("client must not be constructed"))
            modules["googleapiclient.discovery"].build = builder
            with (
                mock.patch.dict(sys.modules, modules),
                mock.patch.object(publisher, "_validate_declared_assets"),
                mock.patch(
                    "remedialhq.publishers.youtube.claim_youtube_upload_authorization",
                    side_effect=PermissionError("confirmation rejected"),
                ),
                self.assertRaisesRegex(PermissionError, "confirmation rejected"),
            ):
                publisher.publish(_package())
            builder.assert_not_called()

    def test_publisher_uses_pinned_descriptors_and_preview_request(self) -> None:
        package = _package()
        youtube = _YouTubeClient({"id": "AbCdEfGhI_1"}, None)
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            video = root / "video.mp4"
            thumbnail = root / "thumbnail.png"
            video.write_bytes(b"path-video")
            thumbnail.write_bytes(b"path-thumbnail")
            claimed = _claimed(package)
            preview_request = claimed.request_payload()
            preview_request["body"]["snippet"]["title"] = "Title from preview"
            claimed.request_payload = lambda: preview_request
            publisher = YouTubePublisher(
                object(),
                video,
                thumbnail_path=thumbnail,
                asset_root=root,
                expected_channel_id="UCaaaaaaaaaaaaaaaaaaaaaa",
                upload_authorization=_authorization(video, thumbnail),
            )
            with (
                mock.patch.dict(sys.modules, _google_modules(youtube)),
                mock.patch.object(publisher, "_validate_declared_assets"),
                mock.patch(
                    "remedialhq.publishers.youtube.claim_youtube_upload_authorization",
                    return_value=claimed,
                ),
            ):
                result = publisher.publish(package)

        self.assertEqual(result.remote_id, "AbCdEfGhI_1")
        insert = youtube.video_resource.insert_calls[0]
        self.assertEqual(insert["body"]["snippet"]["title"], "Title from preview")
        self.assertIs(insert["media_body"][0], claimed.media)
        self.assertIs(youtube.thumbnail_resource.calls[0]["media_body"][0], claimed.thumbnail)
        claimed.close.assert_called_once()

    def test_existing_exact_marker_fails_closed_without_remote_mutation(self) -> None:
        package = _package()
        marker = _publication_marker(package)
        existing_id = "AbCdEfGhI_1"
        youtube = _YouTubeClient(
            {"id": "unused-video"},
            None,
            search_response={"items": [{"id": {"videoId": existing_id}}]},
            detail_response={
                "items": [
                    {
                        "id": existing_id,
                        "snippet": {"description": f"Reviewed description\n{marker}"},
                    }
                ]
            },
        )
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            video = root / "video.mp4"
            thumbnail = root / "thumbnail.png"
            video.write_bytes(b"video")
            thumbnail.write_bytes(b"thumbnail")
            claimed = _claimed(package)
            publisher = YouTubePublisher(
                object(),
                video,
                thumbnail_path=thumbnail,
                asset_root=root,
                expected_channel_id="UCaaaaaaaaaaaaaaaaaaaaaa",
                upload_authorization=_authorization(video, thumbnail),
            )
            with (
                mock.patch.dict(sys.modules, _google_modules(youtube)),
                mock.patch.object(publisher, "_validate_declared_assets"),
                mock.patch(
                    "remedialhq.publishers.youtube.claim_youtube_upload_authorization",
                    return_value=claimed,
                ),
                self.assertRaisesRegex(PermissionError, "separately previewed"),
            ):
                publisher.publish(package)

        self.assertEqual(youtube.video_resource.insert_calls, [])
        self.assertEqual(youtube.video_resource.update_calls, [])
        self.assertEqual(youtube.thumbnail_resource.calls, [])
        claimed.close.assert_called_once()

    def test_marker_search_candidate_requires_an_exact_description_line(self) -> None:
        package = _package()
        marker = _publication_marker(package)
        existing_id = "AbCdEfGhI_1"
        youtube = _YouTubeClient(
            {"id": "unused-video"},
            None,
            search_response={"items": [{"id": {"videoId": existing_id}}]},
            detail_response={
                "items": [
                    {
                        "id": existing_id,
                        "snippet": {"description": f"not exact {marker} suffix"},
                    }
                ]
            },
        )
        with self.assertRaisesRegex(RuntimeError, "did not verify the exact marker"):
            from remedialhq.publishers.youtube import _find_existing_video

            _find_existing_video(youtube, marker)
        self.assertEqual(youtube.video_resource.insert_calls, [])

    def test_required_evidence_rejects_missing_thumbnail_before_upload(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit thumbnail path"):
            YouTubePublisher(
                object(),
                "video.mp4",
                expected_channel_id="UCaaaaaaaaaaaaaaaaaaaaaa",
                verification_evidence_required=True,
            )


if __name__ == "__main__":
    unittest.main()
