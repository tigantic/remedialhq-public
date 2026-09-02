from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from collections.abc import Callable, Mapping
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from remedialhq.auth import YOUTUBE_ANALYTICS_SCOPE, YOUTUBE_READ_SCOPE
from remedialhq.cli import _parser, _publish_youtube, _verify_youtube
from remedialhq.models import ContentPackage
from remedialhq.publishers.base import PublishResult
from remedialhq.youtube_verification import (
    UPLOAD_API_EVIDENCE_SCHEMA,
    VERIFICATION_FIXTURE_SCHEMA,
    GoogleYouTubeVerificationTransport,
    YouTubeProcessingTimeout,
    YouTubeVerificationError,
    YouTubeVerificationResult,
    build_upload_api_evidence,
    load_upload_api_evidence,
    verify_youtube_post_upload,
    write_private_upload_api_evidence,
)

VIDEO_ID = "AbCdEfGhI_1"
CHANNEL_ID = "UCbbbbbbbbbbbbbbbbbbbbbb"
OTHER_CHANNEL_ID = "UCaaaaaaaaaaaaaaaaaaaaaa"
START_DATE = "2026-08-01"
END_DATE = "2026-09-01"


def api_evidence() -> dict[str, object]:
    return {
        "schema_version": UPLOAD_API_EVIDENCE_SCHEMA,
        "video_id": VIDEO_ID,
        "upload_response": {
            "kind": "youtube#video",
            "id": VIDEO_ID,
            "snippet": {"channelId": CHANNEL_ID},
            "status": {"privacyStatus": "private"},
        },
        "thumbnail_set": {
            "video_id": VIDEO_ID,
            "response": {
                "kind": "youtube#thumbnailSetResponse",
                "items": [
                    {
                        "default": {
                            "url": f"https://i.ytimg.com/vi/{VIDEO_ID}/default.jpg",
                            "width": 120,
                            "height": 90,
                        },
                        "high": {
                            "url": f"https://i.ytimg.com/vi/{VIDEO_ID}/hqdefault.jpg",
                            "width": 480,
                            "height": 360,
                        },
                    }
                ],
            },
        },
    }


def channel_response(channel_id: str = CHANNEL_ID) -> dict[str, object]:
    return {"kind": "youtube#channelListResponse", "items": [{"id": channel_id}]}


def video_response(
    *,
    channel_id: str = CHANNEL_ID,
    privacy: str = "private",
    upload_status: str = "processed",
    processing_status: str = "succeeded",
) -> dict[str, object]:
    return {
        "kind": "youtube#videoListResponse",
        "items": [
            {
                "id": VIDEO_ID,
                "snippet": {"channelId": channel_id},
                "status": {
                    "privacyStatus": privacy,
                    "uploadStatus": upload_status,
                },
                "processingDetails": {"processingStatus": processing_status},
            }
        ],
    }


def analytics_response(
    *,
    rows: list[list[object]] | None = None,
) -> dict[str, object]:
    return {
        "kind": "youtubeAnalytics#resultTable",
        "columnHeaders": [
            {"name": "video", "columnType": "DIMENSION", "dataType": "STRING"},
            {"name": "views", "columnType": "METRIC", "dataType": "INTEGER"},
            {
                "name": "estimatedMinutesWatched",
                "columnType": "METRIC",
                "dataType": "FLOAT",
            },
        ],
        "rows": rows if rows is not None else [[VIDEO_ID, 0, 0.0]],
    }


class FakeReadTransport:
    def __init__(
        self,
        *,
        channel: Mapping[str, object] | None = None,
        videos: list[Mapping[str, object]] | None = None,
        analytics: Mapping[str, object] | None = None,
    ) -> None:
        self.channel = channel or channel_response()
        self.videos = videos or [video_response()]
        self.analytics = analytics or analytics_response()
        self.calls: list[object] = []
        self.video_index = 0

    def read_authorized_channel(self) -> Mapping[str, object]:
        self.calls.append("channel")
        return self.channel

    def read_video(self, video_id: str) -> Mapping[str, object]:
        self.calls.append(("video", video_id))
        response = self.videos[self.video_index]
        self.video_index += 1
        return response

    def read_analytics(
        self,
        video_id: str,
        start_date: str,
        end_date: str,
    ) -> Mapping[str, object]:
        self.calls.append(("analytics", video_id, start_date, end_date))
        return self.analytics


class FakeExecutableRequest:
    def __init__(self, response: Mapping[str, object]) -> None:
        self.response = response

    def execute(self) -> Mapping[str, object]:
        return self.response


class FakeGoogleResource:
    def __init__(
        self,
        name: str,
        calls: list[tuple[str, dict[str, object]]],
        response: Mapping[str, object],
    ) -> None:
        self.name = name
        self.calls = calls
        self.response = response

    def list(self, **kwargs: object) -> FakeExecutableRequest:
        self.calls.append((f"{self.name}.list", kwargs))
        return FakeExecutableRequest(self.response)

    def query(self, **kwargs: object) -> FakeExecutableRequest:
        self.calls.append((f"{self.name}.query", kwargs))
        return FakeExecutableRequest(self.response)


class FakeGoogleYouTubeClient:
    def __init__(self, calls: list[tuple[str, dict[str, object]]]) -> None:
        self.calls = calls

    def channels(self) -> FakeGoogleResource:
        return FakeGoogleResource("channels", self.calls, channel_response())

    def videos(self) -> FakeGoogleResource:
        return FakeGoogleResource("videos", self.calls, video_response())


class FakeGoogleAnalyticsClient:
    def __init__(self, calls: list[tuple[str, dict[str, object]]]) -> None:
        self.calls = calls

    def reports(self) -> FakeGoogleResource:
        return FakeGoogleResource("reports", self.calls, analytics_response())


def no_sleep(_seconds: float) -> None:
    return None


def verify(
    transport: FakeReadTransport,
    *,
    evidence: Mapping[str, object] | None = None,
    max_attempts: int = 3,
    interval: float = 0.0,
    sleeper: Callable[[float], None] = no_sleep,
) -> YouTubeVerificationResult:
    return verify_youtube_post_upload(
        transport,
        evidence or api_evidence(),
        video_id=VIDEO_ID,
        expected_channel_id=CHANNEL_ID,
        expected_privacy_status="private",
        analytics_start_date=START_DATE,
        analytics_end_date=END_DATE,
        max_processing_attempts=max_attempts,
        poll_interval_seconds=interval,
        sleeper=sleeper,
    )


def fixture_document(
    *,
    videos: list[Mapping[str, object]] | None = None,
    analytics: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": VERIFICATION_FIXTURE_SCHEMA,
        "channel_response": channel_response(),
        "video_responses": videos or [video_response()],
        "analytics_response": analytics or analytics_response(),
    }


class YouTubeVerificationTests(unittest.TestCase):
    def test_google_transport_exposes_only_read_list_and_query_calls(self) -> None:
        api_calls: list[tuple[str, dict[str, object]]] = []
        builder_calls: list[tuple[str, str, dict[str, object]]] = []
        youtube = FakeGoogleYouTubeClient(api_calls)
        analytics = FakeGoogleAnalyticsClient(api_calls)

        def builder(name: str, version: str, **kwargs: object) -> object:
            builder_calls.append((name, version, kwargs))
            return youtube if name == "youtube" else analytics

        credentials = object()
        transport = GoogleYouTubeVerificationTransport.from_credentials(
            credentials,
            builder=builder,
        )
        transport.read_authorized_channel()
        transport.read_video(VIDEO_ID)
        transport.read_analytics(VIDEO_ID, START_DATE, END_DATE)

        self.assertEqual(
            [(name, version) for name, version, _kwargs in builder_calls],
            [("youtube", "v3"), ("youtubeAnalytics", "v2")],
        )
        self.assertTrue(
            all(call[2]["credentials"] is credentials for call in builder_calls)
        )
        self.assertEqual(
            [name for name, _kwargs in api_calls],
            ["channels.list", "videos.list", "reports.query"],
        )
        self.assertEqual(api_calls[1][1]["id"], VIDEO_ID)
        self.assertEqual(api_calls[2][1]["filters"], f"video=={VIDEO_ID}")

    def test_google_transport_cannot_be_constructed_without_credentials(self) -> None:
        with self.assertRaisesRegex(YouTubeVerificationError, "credentials are required"):
            GoogleYouTubeVerificationTransport.from_credentials(None, builder=mock.Mock())

    def test_pass_verifies_evidence_processing_identity_privacy_and_analytics(self) -> None:
        delays: list[float] = []
        transport = FakeReadTransport(
            videos=[
                video_response(upload_status="uploaded", processing_status="processing"),
                video_response(),
            ]
        )

        result = verify(transport, interval=1.25, sleeper=delays.append)

        self.assertEqual(result.video_id, VIDEO_ID)
        self.assertEqual(result.channel_id, CHANNEL_ID)
        self.assertEqual(result.processing_attempts, 2)
        self.assertEqual(result.thumbnail_variants, 2)
        self.assertEqual(result.views, 0)
        self.assertEqual(result.estimated_minutes_watched, 0.0)
        self.assertEqual(delays, [1.25])
        self.assertEqual(
            transport.calls,
            [
                "channel",
                ("video", VIDEO_ID),
                ("video", VIDEO_ID),
                ("analytics", VIDEO_ID, START_DATE, END_DATE),
            ],
        )
        self.assertEqual(result.to_dict()["status"], "PASS")

    def test_terminal_processing_failure_fails_without_analytics_read(self) -> None:
        transport = FakeReadTransport(
            videos=[
                video_response(upload_status="uploaded", processing_status="failed")
            ]
        )

        with self.assertRaisesRegex(YouTubeVerificationError, "terminal state failed"):
            verify(transport)

        self.assertNotIn(
            ("analytics", VIDEO_ID, START_DATE, END_DATE),
            transport.calls,
        )

    def test_processing_polling_is_bounded_and_times_out(self) -> None:
        delays: list[float] = []
        pending = video_response(upload_status="uploaded", processing_status="processing")
        transport = FakeReadTransport(videos=[pending, pending])

        with self.assertRaisesRegex(YouTubeProcessingTimeout, "2 read attempts"):
            verify(transport, max_attempts=2, interval=0.5, sleeper=delays.append)

        self.assertEqual(delays, [0.5])
        self.assertEqual(transport.video_index, 2)

    def test_authorized_channel_must_match_exact_expected_channel(self) -> None:
        transport = FakeReadTransport(channel=channel_response(OTHER_CHANNEL_ID))

        with self.assertRaisesRegex(YouTubeVerificationError, "exact expected channel"):
            verify(transport)

        self.assertEqual(transport.calls, ["channel"])

    def test_video_channel_and_privacy_must_match(self) -> None:
        cases = (
            (video_response(channel_id=OTHER_CHANNEL_ID), "different YouTube channel"),
            (video_response(privacy="unlisted"), "privacy state"),
        )
        for response, message in cases:
            with self.subTest(message=message):
                transport = FakeReadTransport(videos=[response])
                with self.assertRaisesRegex(YouTubeVerificationError, message):
                    verify(transport)

    def test_missing_analytics_row_fails_closed(self) -> None:
        transport = FakeReadTransport(analytics=analytics_response(rows=[]))

        with self.assertRaisesRegex(YouTubeVerificationError, "exactly one row"):
            verify(transport)

    def test_upload_and_thumbnail_response_evidence_are_required_before_reads(self) -> None:
        wrong_upload = api_evidence()
        upload = wrong_upload["upload_response"]
        assert isinstance(upload, dict)
        upload["id"] = "ZyXwVuTsR_2"

        missing_thumbnail = api_evidence()
        thumbnail_set = missing_thumbnail["thumbnail_set"]
        assert isinstance(thumbnail_set, dict)
        response = thumbnail_set["response"]
        assert isinstance(response, dict)
        response["items"] = []

        for evidence, message in (
            (wrong_upload, "upload response video ID"),
            (missing_thumbnail, "exactly one thumbnail resource"),
        ):
            with self.subTest(message=message):
                transport = FakeReadTransport()
                with self.assertRaisesRegex(YouTubeVerificationError, message):
                    verify(transport, evidence=evidence)
                self.assertEqual(transport.calls, [])

    def test_evidence_builder_sanitizes_and_private_writer_is_create_only(self) -> None:
        raw = api_evidence()
        upload = raw["upload_response"]
        thumbnail_set = raw["thumbnail_set"]
        assert isinstance(upload, dict)
        assert isinstance(thumbnail_set, dict)
        thumbnail = thumbnail_set["response"]
        assert isinstance(thumbnail, dict)
        upload["access_token"] = "must-not-survive"
        snippet = upload["snippet"]
        assert isinstance(snippet, dict)
        snippet["description"] = "must-not-survive"
        thumbnail["authorization"] = "must-not-survive"

        evidence = build_upload_api_evidence(
            upload,
            thumbnail,
            video_id=VIDEO_ID,
            expected_channel_id=CHANNEL_ID,
            expected_privacy_status="private",
        )

        self.assertNotIn("must-not-survive", json.dumps(evidence))
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "youtube-upload-evidence.json"
            digest = write_private_upload_api_evidence(
                path,
                evidence,
                video_id=VIDEO_ID,
                expected_channel_id=CHANNEL_ID,
                expected_privacy_status="private",
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(load_upload_api_evidence(path), evidence)
            with self.assertRaisesRegex(YouTubeVerificationError, "already exists"):
                write_private_upload_api_evidence(
                    path,
                    evidence,
                    video_id=VIDEO_ID,
                    expected_channel_id=CHANNEL_ID,
                    expected_privacy_status="private",
                )

    def test_poll_limits_are_validated_before_any_transport_read(self) -> None:
        transport = FakeReadTransport()

        with self.assertRaisesRegex(YouTubeVerificationError, "between 1 and 60"):
            verify(transport, max_attempts=61)

        self.assertEqual(transport.calls, [])


class YouTubeVerificationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temporary.name)
        self.evidence_path = self.root / "api-evidence.json"
        self.fixture_path = self.root / "readback-fixture.json"
        self.evidence_path.write_text(json.dumps(api_evidence()), encoding="utf-8")
        self.fixture_path.write_text(json.dumps(fixture_document()), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self, mode: list[str]) -> list[str]:
        return [
            "verify-youtube",
            "--video-id",
            VIDEO_ID,
            "--expected-channel-id",
            CHANNEL_ID,
            "--api-evidence",
            str(self.evidence_path),
            "--analytics-start-date",
            START_DATE,
            "--analytics-end-date",
            END_DATE,
            *mode,
        ]

    def test_offline_fixture_cli_never_loads_credentials_or_builds_live_client(self) -> None:
        args = _parser().parse_args(self.arguments(["--fixture", str(self.fixture_path)]))
        loader = mock.Mock(side_effect=AssertionError("credentials must not load"))
        builder = mock.Mock(side_effect=AssertionError("live client must not build"))
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = _verify_youtube(
                args,
                credentials_loader=loader,
                transport_builder=builder,
                sleeper=lambda _seconds: None,
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["status"], "PASS")
        loader.assert_not_called()
        builder.assert_not_called()

    def test_live_cli_requires_token_before_any_client_is_built(self) -> None:
        args = _parser().parse_args(self.arguments(["--live-readback"]))
        loader = mock.Mock()
        builder = mock.Mock()
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            exit_code = _verify_youtube(
                args,
                credentials_loader=loader,
                transport_builder=builder,
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(
            stderr.getvalue(),
            "YouTube post-upload verification rejected\n",
        )
        loader.assert_not_called()
        builder.assert_not_called()

    def test_live_cli_rejects_malformed_explicit_video_id_before_credentials(self) -> None:
        arguments = self.arguments(["--live-readback", "--token-file", "token.json"])
        arguments[arguments.index(VIDEO_ID)] = "not-a-video"
        args = _parser().parse_args(arguments)
        loader = mock.Mock()

        with redirect_stderr(io.StringIO()):
            exit_code = _verify_youtube(args, credentials_loader=loader)

        self.assertEqual(exit_code, 2)
        loader.assert_not_called()

    def test_fixture_cli_rejects_token_to_preserve_offline_boundary(self) -> None:
        args = _parser().parse_args(
            self.arguments(
                ["--fixture", str(self.fixture_path), "--token-file", "token.json"]
            )
        )
        loader = mock.Mock()

        with redirect_stderr(io.StringIO()):
            exit_code = _verify_youtube(args, credentials_loader=loader)

        self.assertEqual(exit_code, 2)
        loader.assert_not_called()

    def test_explicit_live_mode_uses_only_read_scopes_and_injected_transport(self) -> None:
        args = _parser().parse_args(
            self.arguments(["--live-readback", "--token-file", "token.json"])
        )
        credentials = object()
        loader = mock.Mock(return_value=credentials)
        transport = FakeReadTransport()
        builder = mock.Mock(return_value=transport)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            exit_code = _verify_youtube(
                args,
                credentials_loader=loader,
                transport_builder=builder,
                sleeper=lambda _seconds: None,
            )

        self.assertEqual(exit_code, 0)
        loader.assert_called_once_with(
            "token.json",
            scopes=(YOUTUBE_READ_SCOPE, YOUTUBE_ANALYTICS_SCOPE),
            persist_refresh=False,
        )
        builder.assert_called_once_with(credentials)

    def test_publish_cli_creates_private_sanitized_evidence_for_verifier(self) -> None:
        config = self.root / "config"
        config.mkdir()
        (config / "publication_authority.json").write_text(
            json.dumps(
                {
                    "global_publication_enabled": False,
                    "platforms": {
                        "youtube": {
                            "private_upload_authorized": True,
                            "visible_upload_authorized": False,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        output_path = self.root / "private" / "youtube-upload-evidence.json"
        package = ContentPackage(
            package_id="PKG-YOUTUBE-PRIVATE",
            title="Private upload",
            body="Evidence-bound private upload.",
            platform="youtube",
            claim_ids=["CLM-1"],
            disclosures={"independence"},
        )
        publisher = mock.Mock()
        publisher.publish.return_value = PublishResult(
            platform="youtube",
            package_id=package.package_id,
            status="PUBLISHED_PRIVATE",
            remote_id=VIDEO_ID,
            remote_url=f"https://www.youtube.com/watch?v={VIDEO_ID}",
            details={
                "thumbnail_set": True,
                "verification_api_evidence": api_evidence(),
            },
        )
        args = _parser().parse_args(
            [
                "publish-youtube",
                "--root",
                str(self.root),
                "--token-file",
                "token.json",
                "--media",
                "video.mp4",
                "--thumbnail",
                "thumbnail.png",
                "--expected-channel-id",
                CHANNEL_ID,
                "--preview",
                "preview.json",
                "--confirmation",
                "confirmation.json",
                "--verification-evidence-output",
                str(output_path),
            ]
        )
        stdout = io.StringIO()

        with (
            mock.patch(
                "remedialhq.cli.build_content_packages",
                return_value=[package],
            ),
            mock.patch(
                "remedialhq.cli.load_claims",
                return_value=[SimpleNamespace(claim_id="CLM-1")],
            ),
            mock.patch(
                "remedialhq.cli.evaluate",
                return_value=SimpleNamespace(decision=SimpleNamespace(value="PASS")),
            ),
            mock.patch("remedialhq.cli.load_youtube_credentials", return_value=object()),
            mock.patch(
                "remedialhq.cli.resolve_youtube_channel",
                return_value={"channel_id": CHANNEL_ID},
            ),
            mock.patch(
                "remedialhq.cli.load_youtube_upload_authorization",
                return_value=SimpleNamespace(
                    media_path=(self.root / "video.mp4").resolve(),
                    thumbnail_path=(self.root / "thumbnail.png").resolve(),
                ),
            ),
            mock.patch("remedialhq.cli.YouTubePublisher", return_value=publisher) as factory,
            redirect_stdout(stdout),
        ):
            exit_code = _publish_youtube(args)

        self.assertEqual(exit_code, 0)
        self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(load_upload_api_evidence(output_path), api_evidence())
        printed = json.loads(stdout.getvalue())
        self.assertNotIn("verification_api_evidence", printed["details"])
        self.assertEqual(
            printed["details"]["verification_evidence"]["path"],
            str(output_path),
        )
        self.assertRegex(
            printed["details"]["verification_evidence"]["sha256"],
            r"^[0-9a-f]{64}$",
        )
        factory.assert_called_once()
        self.assertEqual(factory.call_args.kwargs["expected_channel_id"], CHANNEL_ID)
        self.assertTrue(factory.call_args.kwargs["verification_evidence_required"])
        self.assertIsNotNone(factory.call_args.kwargs["upload_authorization"])

    def test_publish_parser_requires_thumbnail_and_evidence_output(self) -> None:
        base = [
            "publish-youtube",
            "--token-file",
            "token.json",
            "--media",
            "video.mp4",
            "--expected-channel-id",
            CHANNEL_ID,
        ]
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            _parser().parse_args(base)


if __name__ == "__main__":
    unittest.main()
