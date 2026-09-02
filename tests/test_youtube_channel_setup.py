from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from remedialhq.cli import _authorize, _parser, _setup_youtube_channel
from remedialhq.youtube_channel_setup import (
    CURRENT_WATERMARK_RELATIVE_PATH,
    CURRENT_WATERMARK_SHA256,
    INITIAL_PRIVATE_PLAYLISTS,
    REMEDIALHQ_CHANNEL_ID,
    YOUTUBE_CHANNEL_SETUP_SCOPE,
    GoogleYouTubeChannelSetupTransport,
    YouTubeChannelSetupError,
    build_youtube_channel_setup_plan,
    execute_youtube_channel_setup,
)


class FakeTransport:
    def __init__(
        self,
        *,
        channel_id: str = REMEDIALHQ_CHANNEL_ID,
        playlists: list[dict[str, object]] | None = None,
    ) -> None:
        self.channel_id = channel_id
        self.playlists = playlists or []
        self.created: list[str] = []
        self.watermarks: list[tuple[str, Path]] = []

    def read_authorized_channel(self) -> dict[str, object]:
        return {"items": [{"id": self.channel_id}]}

    def list_owned_playlists(self) -> list[dict[str, object]]:
        return self.playlists

    def create_private_playlist(self, title: str) -> dict[str, object]:
        self.created.append(title)
        return {
            "id": f"PL{len(self.created):022d}",
            "snippet": {"title": title},
            "status": {"privacyStatus": "private"},
        }

    def set_offset_zero_watermark(self, channel_id: str, path: Path) -> None:
        self.watermarks.append((channel_id, path))


class ExecuteRequest:
    def __init__(self, value: object) -> None:
        self.value = value

    def execute(self) -> object:
        return self.value


class RecordingResource:
    def __init__(self, name: str, calls: list[tuple[str, dict[str, object]]]) -> None:
        self.name = name
        self.calls = calls

    def list(self, **kwargs: object) -> ExecuteRequest:
        self.calls.append((f"{self.name}.list", kwargs))
        if self.name == "channels":
            return ExecuteRequest({"items": [{"id": REMEDIALHQ_CHANNEL_ID}]})
        return ExecuteRequest({"items": []})

    def insert(self, **kwargs: object) -> ExecuteRequest:
        self.calls.append((f"{self.name}.insert", kwargs))
        body = kwargs["body"]
        assert isinstance(body, dict)
        snippet = body["snippet"]
        assert isinstance(snippet, dict)
        return ExecuteRequest(
            {
                "id": "PL0000000000000000000001",
                "snippet": {"title": snippet["title"]},
                "status": {"privacyStatus": "private"},
            }
        )

    def set(self, **kwargs: object) -> ExecuteRequest:
        self.calls.append((f"{self.name}.set", kwargs))
        return ExecuteRequest(None)


class RecordingYouTubeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self._channels = RecordingResource("channels", self.calls)
        self._playlists = RecordingResource("playlists", self.calls)
        self._watermarks = RecordingResource("watermarks", self.calls)

    def channels(self) -> RecordingResource:
        return self._channels

    def playlists(self) -> RecordingResource:
        return self._playlists

    def watermarks(self) -> RecordingResource:
        return self._watermarks

    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"forbidden YouTube setup resource: {name}")


class YouTubeChannelSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.base = Path(self.temporary.name)
        self.root = self.base / "repository"
        watermark = self.root / CURRENT_WATERMARK_RELATIVE_PATH
        watermark.parent.mkdir(parents=True)
        source = Path(__file__).resolve().parents[1] / CURRENT_WATERMARK_RELATIVE_PATH
        shutil.copyfile(source, watermark)
        self.token = self.base / "owner-token.json"
        self.token.write_text("{}\n", encoding="utf-8")
        os.chmod(self.token, 0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self, *, live: bool = False) -> list[str]:
        values = [
            "setup-youtube-channel",
            "--root",
            str(self.root),
            "--token-file",
            str(self.token),
            "--expected-channel-id",
            REMEDIALHQ_CHANNEL_ID,
            "--watermark",
            CURRENT_WATERMARK_RELATIVE_PATH.as_posix(),
            "--watermark-sha256",
            CURRENT_WATERMARK_SHA256,
        ]
        if live:
            values.append("--live")
        return values

    def plan(self):
        return build_youtube_channel_setup_plan(
            root=self.root,
            token_file=self.token,
            expected_channel_id=REMEDIALHQ_CHANNEL_ID,
            watermark_path=CURRENT_WATERMARK_RELATIVE_PATH,
            watermark_sha256=CURRENT_WATERMARK_SHA256,
        )

    def test_plan_contains_only_fixed_watermark_and_exact_private_playlists(self) -> None:
        document = self.plan().to_dict()

        self.assertEqual(document["status"], "PLAN_ONLY_OFFLINE")
        self.assertFalse(document["network_used"])
        self.assertEqual(
            [item["title"] for item in document["playlists"]],
            list(INITIAL_PRIVATE_PLAYLISTS),
        )
        self.assertTrue(all(item["privacy_status"] == "private" for item in document["playlists"]))
        self.assertEqual(document["watermark"]["sha256"], CURRENT_WATERMARK_SHA256)
        self.assertEqual(document["watermark"]["requested_display"], "ENTIRE_VIDEO")
        self.assertFalse(document["watermark"]["entire_video_api_verifiable"])
        self.assertEqual(
            document["excluded_mutations"],
            [
                "avatar",
                "banner",
                "public_description",
                "upload_defaults",
                "business_contact",
                "publication_authority",
            ],
        )

    def test_plan_mode_is_default_and_never_loads_credentials(self) -> None:
        args = _parser().parse_args(self.arguments())
        loader = mock.Mock(side_effect=AssertionError("credentials must not load"))
        builder = mock.Mock(side_effect=AssertionError("transport must not build"))
        stdout = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            result = _setup_youtube_channel(
                args,
                credentials_loader=loader,
                transport_builder=builder,
            )

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "PLAN_ONLY_OFFLINE")
        loader.assert_not_called()
        builder.assert_not_called()

    def test_plan_mode_does_not_require_token_to_exist(self) -> None:
        missing_token = self.base / "not-created-yet.json"
        arguments = self.arguments()
        arguments[arguments.index("--token-file") + 1] = str(missing_token)
        args = _parser().parse_args(arguments)
        stdout = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            result = _setup_youtube_channel(args)

        self.assertEqual(result, 0)
        document = json.loads(stdout.getvalue())
        self.assertEqual(document["status"], "PLAN_ONLY_OFFLINE")
        self.assertFalse(missing_token.exists())

    def test_plan_mode_does_not_require_token_argument(self) -> None:
        arguments = self.arguments()
        token_index = arguments.index("--token-file")
        del arguments[token_index : token_index + 2]
        args = _parser().parse_args(arguments)
        stdout = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            result = _setup_youtube_channel(args)

        self.assertEqual(result, 0)
        document = json.loads(stdout.getvalue())
        self.assertEqual(document["status"], "PLAN_ONLY_OFFLINE")
        self.assertFalse(document["token"]["provided"])

    def test_live_mode_requires_token_argument(self) -> None:
        arguments = self.arguments(live=True)
        token_index = arguments.index("--token-file")
        del arguments[token_index : token_index + 2]
        args = _parser().parse_args(arguments)
        loader = mock.Mock()

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = _setup_youtube_channel(args, credentials_loader=loader)

        self.assertEqual(result, 2)
        loader.assert_not_called()

    def test_live_mode_requires_token_to_exist(self) -> None:
        missing_token = self.base / "not-created-yet.json"
        arguments = self.arguments(live=True)
        arguments[arguments.index("--token-file") + 1] = str(missing_token)
        args = _parser().parse_args(arguments)
        loader = mock.Mock()

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = _setup_youtube_channel(args, credentials_loader=loader)

        self.assertEqual(result, 2)
        loader.assert_not_called()

    def test_channel_setup_authorization_requests_only_its_explicit_scope(self) -> None:
        args = _parser().parse_args(
            [
                "auth",
                "youtube",
                "--client-secrets",
                "client.json",
                "--token-output",
                "token.json",
                "--policy-acceptance",
                "/tmp/youtube-channel-policy-acceptance.json",
                "--channel-setup",
            ]
        )
        with (
            mock.patch(
                "remedialhq.cli.authorize_youtube",
                return_value={"channel_id": REMEDIALHQ_CHANNEL_ID},
            ) as authorize,
            redirect_stdout(io.StringIO()),
        ):
            result = _authorize(args)

        self.assertEqual(result, 0)
        authorize.assert_called_once_with(
            "client.json",
            "token.json",
            policy_acceptance="/tmp/youtube-channel-policy-acceptance.json",
            repository_root=".",
            open_browser=True,
            scopes=(YOUTUBE_CHANNEL_SETUP_SCOPE,),
        )

    def test_invalid_channel_or_watermark_rejects_before_credentials(self) -> None:
        invalid_arguments = [
            ("--expected-channel-id", "UCaaaaaaaaaaaaaaaaaaaaaa"),
            ("--watermark-sha256", "0" * 64),
            ("--watermark", "brand/video-watermark.png"),
        ]
        for flag, value in invalid_arguments:
            with self.subTest(flag=flag):
                arguments = self.arguments(live=True)
                arguments[arguments.index(flag) + 1] = value
                args = _parser().parse_args(arguments)
                loader = mock.Mock()
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    result = _setup_youtube_channel(args, credentials_loader=loader)
                self.assertEqual(result, 2)
                loader.assert_not_called()

    def test_channel_mismatch_has_zero_mutations(self) -> None:
        transport = FakeTransport(channel_id="UCaaaaaaaaaaaaaaaaaaaaaa")

        with self.assertRaisesRegex(YouTubeChannelSetupError, "exact expected channel"):
            execute_youtube_channel_setup(self.plan(), transport)

        self.assertEqual(transport.created, [])
        self.assertEqual(transport.watermarks, [])

    def test_blank_channel_creates_only_seven_private_playlists_and_watermark(self) -> None:
        transport = FakeTransport()

        result = execute_youtube_channel_setup(self.plan(), transport)

        self.assertEqual(transport.created, list(INITIAL_PRIVATE_PLAYLISTS))
        self.assertEqual(result.created_playlists, INITIAL_PRIVATE_PLAYLISTS)
        self.assertEqual(result.existing_playlists, ())
        self.assertEqual(
            transport.watermarks,
            [(REMEDIALHQ_CHANNEL_ID, self.plan().watermark_path)],
        )

    def test_existing_private_playlists_are_not_duplicated(self) -> None:
        playlists = [
            {
                "id": f"PL{index:022d}",
                "snippet": {"title": title},
                "status": {"privacyStatus": "private"},
            }
            for index, title in enumerate(INITIAL_PRIVATE_PLAYLISTS, 1)
        ]
        transport = FakeTransport(playlists=playlists)

        result = execute_youtube_channel_setup(self.plan(), transport)

        self.assertEqual(transport.created, [])
        self.assertEqual(result.existing_playlists, INITIAL_PRIVATE_PLAYLISTS)
        self.assertEqual(len(transport.watermarks), 1)

    def test_duplicate_or_visible_exact_playlist_fails_before_all_mutations(self) -> None:
        title = INITIAL_PRIVATE_PLAYLISTS[0]
        fixtures = [
            [
                {"snippet": {"title": title}, "status": {"privacyStatus": "private"}},
                {"snippet": {"title": title}, "status": {"privacyStatus": "private"}},
            ],
            [{"snippet": {"title": title}, "status": {"privacyStatus": "public"}}],
        ]
        for playlists in fixtures:
            with self.subTest(playlists=playlists):
                transport = FakeTransport(playlists=playlists)
                with self.assertRaises(YouTubeChannelSetupError):
                    execute_youtube_channel_setup(self.plan(), transport)
                self.assertEqual(transport.created, [])
                self.assertEqual(transport.watermarks, [])

    def test_live_cli_uses_only_setup_scope_and_sanitized_output(self) -> None:
        args = _parser().parse_args(self.arguments(live=True))
        credentials = object()
        loader = mock.Mock(return_value=credentials)
        transport = FakeTransport()
        builder = mock.Mock(return_value=transport)
        stdout = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            result = _setup_youtube_channel(
                args,
                credentials_loader=loader,
                transport_builder=builder,
            )

        self.assertEqual(result, 0)
        loader.assert_called_once_with(
            str(self.token),
            scopes=(YOUTUBE_CHANNEL_SETUP_SCOPE,),
            persist_refresh=False,
        )
        builder.assert_called_once_with(credentials)
        output = stdout.getvalue()
        printed = json.loads(output)
        self.assertEqual(
            printed["status"],
            "APPLIED_WITH_STUDIO_VERIFICATION_REQUIRED",
        )
        self.assertFalse(printed["task_completion_claimed"])
        self.assertFalse(printed["watermark"]["entire_video_verified"])
        self.assertNotIn(str(self.token), output)

    def test_google_transport_calls_only_allowed_resources_with_fixed_bodies(self) -> None:
        client = RecordingYouTubeClient()
        uploads: list[tuple[str, dict[str, object]]] = []

        def upload_factory(path: str, **kwargs: object) -> tuple[str, dict[str, object]]:
            uploads.append((path, kwargs))
            return path, kwargs

        transport = GoogleYouTubeChannelSetupTransport(
            client,
            media_upload_factory=upload_factory,
        )
        self.assertEqual(
            transport.read_authorized_channel()["items"],
            [{"id": REMEDIALHQ_CHANNEL_ID}],
        )
        self.assertEqual(transport.list_owned_playlists(), ())
        created = transport.create_private_playlist(INITIAL_PRIVATE_PLAYLISTS[0])
        self.assertEqual(created["status"], {"privacyStatus": "private"})
        transport.set_offset_zero_watermark(
            REMEDIALHQ_CHANNEL_ID,
            self.plan().watermark_path,
        )

        call_names = [name for name, _kwargs in client.calls]
        self.assertEqual(
            call_names,
            ["channels.list", "playlists.list", "playlists.insert", "watermarks.set"],
        )
        insert_body = client.calls[2][1]["body"]
        self.assertEqual(
            insert_body,
            {
                "snippet": {"title": INITIAL_PRIVATE_PLAYLISTS[0]},
                "status": {"privacyStatus": "private"},
            },
        )
        watermark_call = client.calls[3][1]
        self.assertEqual(watermark_call["channelId"], REMEDIALHQ_CHANNEL_ID)
        self.assertEqual(
            watermark_call["body"],
            {
                "timing": {"type": "offsetFromStart", "offsetMs": 0},
                "position": {"type": "corner", "cornerPosition": "topRight"},
                "targetChannelId": REMEDIALHQ_CHANNEL_ID,
            },
        )
        self.assertEqual(
            uploads,
            [
                (
                    str(self.plan().watermark_path),
                    {"mimetype": "image/png", "resumable": False},
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
