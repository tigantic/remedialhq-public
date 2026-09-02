from __future__ import annotations

import hashlib
import os
import re
import stat
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

YOUTUBE_CHANNEL_SETUP_SCOPE = "https://www.googleapis.com/auth/youtube.force-ssl"
CHANNEL_SETUP_PLAN_SCHEMA = "remedialhq.youtube-channel-setup-plan.v1"
CHANNEL_SETUP_RESULT_SCHEMA = "remedialhq.youtube-channel-setup-result.v1"

REMEDIALHQ_CHANNEL_ID = "UCm6r0Dl4So4COH00U1qCE2w"
CURRENT_WATERMARK_RELATIVE_PATH = Path("brand/youtube-video-watermark-current.png")
CURRENT_WATERMARK_SHA256 = (
    "8ad2b256526c26101a98f5caeedce8434da6da3ecbf1311a642c544e464ff118"
)
CURRENT_WATERMARK_DIMENSIONS = (150, 150)

INITIAL_PRIVATE_PLAYLISTS = (
    "GTA VI Confirmed",
    "GTA VI Observed",
    "GTA VI Reports",
    "GTA VI Analysis",
    "GTA VI Guides",
    "GTA VI Shorts",
    "ReMediaLHQ Investigations",
)

_CHANNEL_ID_RE = re.compile(r"^UC[A-Za-z0-9_-]{22}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_EXCLUDED_MUTATIONS = (
    "avatar",
    "banner",
    "public_description",
    "upload_defaults",
    "business_contact",
    "publication_authority",
)


class YouTubeChannelSetupError(RuntimeError):
    """Raised when the fixed channel setup cannot be applied safely."""


class YouTubeChannelSetupTransport(Protocol):
    """The complete network mutation surface for the fixed channel setup."""

    def read_authorized_channel(self) -> Mapping[str, object]: ...

    def list_owned_playlists(self) -> Sequence[Mapping[str, object]]: ...

    def create_private_playlist(self, title: str) -> Mapping[str, object]: ...

    def set_offset_zero_watermark(
        self,
        channel_id: str,
        watermark_path: Path,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class YouTubeChannelSetupPlan:
    root: Path
    token_file: Path | None
    expected_channel_id: str
    watermark_path: Path
    watermark_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": CHANNEL_SETUP_PLAN_SCHEMA,
            "status": "PLAN_ONLY_OFFLINE",
            "network_used": False,
            "token": {
                "provided": self.token_file is not None,
                "loaded": False,
                "path_disclosed": False,
            },
            "expected_channel_id": self.expected_channel_id,
            "watermark": {
                "path": CURRENT_WATERMARK_RELATIVE_PATH.as_posix(),
                "sha256": self.watermark_sha256,
                "dimensions": list(CURRENT_WATERMARK_DIMENSIONS),
                "requested_display": "ENTIRE_VIDEO",
                "entire_video_api_verifiable": False,
                "api_timing": {
                    "type": "offsetFromStart",
                    "offsetMs": 0,
                    "durationMs": "PROVIDER_DEFAULT",
                },
            },
            "playlists": [
                {"title": title, "privacy_status": "private"}
                for title in INITIAL_PRIVATE_PLAYLISTS
            ],
            "live_mutations": [
                "create missing exact private playlists",
                "set the reviewed watermark at offset zero with provider-default duration",
            ],
            "excluded_mutations": list(_EXCLUDED_MUTATIONS),
        }


@dataclass(frozen=True, slots=True)
class YouTubeChannelSetupResult:
    channel_id: str
    created_playlists: tuple[str, ...]
    existing_playlists: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": CHANNEL_SETUP_RESULT_SCHEMA,
            "status": "APPLIED_WITH_STUDIO_VERIFICATION_REQUIRED",
            "task_completion_claimed": False,
            "channel_id": self.channel_id,
            "playlist_privacy_status": "private",
            "created_playlists": list(self.created_playlists),
            "existing_playlists": list(self.existing_playlists),
            "watermark": {
                "path": CURRENT_WATERMARK_RELATIVE_PATH.as_posix(),
                "sha256": CURRENT_WATERMARK_SHA256,
                "api_timing": "OFFSET_ZERO_PROVIDER_DEFAULT_DURATION",
                "entire_video_verified": False,
                "status": "API_ACCEPTED_NOT_READ_BACK",
                "studio_follow_up_required": True,
            },
            "excluded_mutations": list(_EXCLUDED_MUTATIONS),
        }


class GoogleYouTubeChannelSetupTransport:
    """YouTube Data API adapter limited to channel identity, playlists, and watermark."""

    def __init__(
        self,
        youtube_client: Any,
        *,
        media_upload_factory: Callable[..., Any],
    ) -> None:
        self._youtube = youtube_client
        self._media_upload_factory = media_upload_factory

    @classmethod
    def from_credentials(
        cls,
        credentials: object,
        *,
        builder: Callable[..., Any] | None = None,
        media_upload_factory: Callable[..., Any] | None = None,
    ) -> GoogleYouTubeChannelSetupTransport:
        if credentials is None:
            raise YouTubeChannelSetupError(
                "credentials are required to construct a live channel setup transport"
            )
        active_builder = builder
        active_upload_factory = media_upload_factory
        if active_builder is None or active_upload_factory is None:
            try:
                from googleapiclient.discovery import build
                from googleapiclient.http import MediaFileUpload
            except ImportError as exc:  # pragma: no cover - optional integration
                raise YouTubeChannelSetupError(
                    "install remedialhq-engine[youtube] for live channel setup"
                ) from exc
            active_builder = active_builder or build
            active_upload_factory = active_upload_factory or MediaFileUpload
        youtube = active_builder(
            "youtube",
            "v3",
            credentials=credentials,
            cache_discovery=False,
        )
        return cls(youtube, media_upload_factory=active_upload_factory)

    def read_authorized_channel(self) -> Mapping[str, object]:
        response = (
            self._youtube.channels()
            .list(part="id", mine=True, maxResults=1)
            .execute()
        )
        return _mapping_response(response, "authorized channel")

    def list_owned_playlists(self) -> Sequence[Mapping[str, object]]:
        playlists: list[Mapping[str, object]] = []
        page_token: str | None = None
        seen_page_tokens: set[str] = set()
        while True:
            request_args: dict[str, object] = {
                "part": "id,snippet,status",
                "mine": True,
                "maxResults": 50,
            }
            if page_token:
                request_args["pageToken"] = page_token
            response = _mapping_response(
                self._youtube.playlists().list(**request_args).execute(),
                "owned playlists",
            )
            items = response.get("items", [])
            if not isinstance(items, Sequence) or isinstance(
                items, (str, bytes, bytearray)
            ):
                raise YouTubeChannelSetupError("owned playlist response items must be a list")
            for item in items:
                if not isinstance(item, Mapping):
                    raise YouTubeChannelSetupError(
                        "owned playlist response contained a non-object item"
                    )
                playlists.append(cast(Mapping[str, object], item))
            raw_next_token = response.get("nextPageToken")
            if raw_next_token is None:
                return tuple(playlists)
            if not isinstance(raw_next_token, str) or not raw_next_token.strip():
                raise YouTubeChannelSetupError(
                    "owned playlist response has an invalid next page token"
                )
            if raw_next_token in seen_page_tokens:
                raise YouTubeChannelSetupError(
                    "owned playlist response repeated a page token"
                )
            seen_page_tokens.add(raw_next_token)
            page_token = raw_next_token

    def create_private_playlist(self, title: str) -> Mapping[str, object]:
        response = (
            self._youtube.playlists()
            .insert(
                part="snippet,status",
                body={
                    "snippet": {"title": title},
                    "status": {"privacyStatus": "private"},
                },
            )
            .execute()
        )
        return _mapping_response(response, f"created playlist {title}")

    def set_offset_zero_watermark(
        self,
        channel_id: str,
        watermark_path: Path,
    ) -> None:
        self._youtube.watermarks().set(
            channelId=channel_id,
            body={
                "timing": {
                    "type": "offsetFromStart",
                    "offsetMs": 0,
                },
                "position": {
                    "type": "corner",
                    "cornerPosition": "topRight",
                },
                "targetChannelId": channel_id,
            },
            media_body=self._media_upload_factory(
                str(watermark_path),
                mimetype="image/png",
                resumable=False,
            ),
        ).execute()


def build_youtube_channel_setup_plan(
    *,
    root: str | Path,
    token_file: str | Path | None,
    expected_channel_id: str,
    watermark_path: str | Path,
    watermark_sha256: str,
    require_token_file: bool = True,
) -> YouTubeChannelSetupPlan:
    resolved_root = Path(root).expanduser().resolve()
    if not resolved_root.is_dir():
        raise YouTubeChannelSetupError("repository root does not exist")

    if not _CHANNEL_ID_RE.fullmatch(expected_channel_id):
        raise YouTubeChannelSetupError(
            "expected channel ID must be an explicit 24-character YouTube channel ID"
        )
    if expected_channel_id != REMEDIALHQ_CHANNEL_ID:
        raise YouTubeChannelSetupError(
            "expected channel ID does not match the recorded ReMediaLHQ channel"
        )

    resolved_token: Path | None = None
    if token_file is not None:
        supplied_token = Path(token_file).expanduser()
        if supplied_token.is_symlink():
            raise YouTubeChannelSetupError("owner token file cannot be a symbolic link")
        resolved_token = supplied_token.resolve()
        if resolved_token.is_relative_to(resolved_root):
            raise YouTubeChannelSetupError("owner token must be stored outside the repository")
    if require_token_file:
        if resolved_token is None:
            raise YouTubeChannelSetupError("live setup requires an explicit owner token file")
        if not resolved_token.is_file():
            raise YouTubeChannelSetupError("explicit owner token file does not exist")
        if os.name == "posix":
            mode = stat.S_IMODE(resolved_token.stat().st_mode)
            if mode & 0o077:
                raise YouTubeChannelSetupError(
                    "owner token file must use owner-only permissions"
                )

    supplied_watermark = Path(watermark_path).expanduser()
    if not supplied_watermark.is_absolute():
        supplied_watermark = resolved_root / supplied_watermark
    if supplied_watermark.is_symlink():
        raise YouTubeChannelSetupError("reviewed watermark cannot be a symbolic link")
    resolved_watermark = supplied_watermark.resolve()
    expected_watermark = (resolved_root / CURRENT_WATERMARK_RELATIVE_PATH).resolve()
    if resolved_watermark != expected_watermark:
        raise YouTubeChannelSetupError(
            "watermark path must be the reviewed current-orange repository asset"
        )
    if not resolved_watermark.is_file():
        raise YouTubeChannelSetupError("reviewed watermark must be a regular file")

    normalized_digest = watermark_sha256.casefold()
    if not _SHA256_RE.fullmatch(normalized_digest):
        raise YouTubeChannelSetupError("watermark SHA-256 is malformed")
    if normalized_digest != CURRENT_WATERMARK_SHA256:
        raise YouTubeChannelSetupError(
            "watermark SHA-256 does not match the reviewed current-orange asset"
        )
    actual_digest = hashlib.sha256(resolved_watermark.read_bytes()).hexdigest()
    if actual_digest != normalized_digest:
        raise YouTubeChannelSetupError("watermark file does not match its reviewed SHA-256")
    _validate_watermark_png(resolved_watermark)

    return YouTubeChannelSetupPlan(
        root=resolved_root,
        token_file=resolved_token,
        expected_channel_id=expected_channel_id,
        watermark_path=resolved_watermark,
        watermark_sha256=normalized_digest,
    )


def execute_youtube_channel_setup(
    plan: YouTubeChannelSetupPlan,
    transport: YouTubeChannelSetupTransport,
) -> YouTubeChannelSetupResult:
    actual_digest = hashlib.sha256(plan.watermark_path.read_bytes()).hexdigest()
    if actual_digest != plan.watermark_sha256:
        raise YouTubeChannelSetupError(
            "reviewed watermark changed after the offline plan was constructed"
        )
    _validate_watermark_png(plan.watermark_path)
    channel_id = _authorized_channel_id(transport.read_authorized_channel())
    if channel_id != plan.expected_channel_id:
        raise YouTubeChannelSetupError(
            "authorized YouTube channel does not match the exact expected channel ID"
        )

    existing_by_title = _owned_playlists_by_title(transport.list_owned_playlists())
    existing: list[str] = []
    missing: list[str] = []
    for title in INITIAL_PRIVATE_PLAYLISTS:
        matches = existing_by_title.get(title, ())
        if len(matches) > 1:
            raise YouTubeChannelSetupError(
                f"multiple owned playlists already use the exact title {title!r}"
            )
        if not matches:
            missing.append(title)
            continue
        if matches[0] != "private":
            raise YouTubeChannelSetupError(
                f"existing exact playlist {title!r} is not private"
            )
        existing.append(title)

    created: list[str] = []
    for title in missing:
        response = transport.create_private_playlist(title)
        _validate_created_playlist(response, title)
        created.append(title)

    transport.set_offset_zero_watermark(channel_id, plan.watermark_path)
    return YouTubeChannelSetupResult(
        channel_id=channel_id,
        created_playlists=tuple(created),
        existing_playlists=tuple(existing),
    )


def _validate_watermark_png(path: Path) -> None:
    header = path.read_bytes()[:24]
    if len(header) != 24 or header[:8] != _PNG_SIGNATURE or header[12:16] != b"IHDR":
        raise YouTubeChannelSetupError("reviewed watermark is not a supported PNG")
    dimensions = struct.unpack(">II", header[16:24])
    if dimensions != CURRENT_WATERMARK_DIMENSIONS:
        raise YouTubeChannelSetupError("reviewed watermark must be exactly 150 by 150 pixels")


def _mapping_response(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise YouTubeChannelSetupError(f"{label} response must be an object")
    return cast(Mapping[str, object], value)


def _authorized_channel_id(response: Mapping[str, object]) -> str:
    items = response.get("items", [])
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        raise YouTubeChannelSetupError("authorized channel response items must be a list")
    if len(items) != 1 or not isinstance(items[0], Mapping):
        raise YouTubeChannelSetupError("expected exactly one authorized YouTube channel")
    channel_id = str(items[0].get("id", "")).strip()
    if not _CHANNEL_ID_RE.fullmatch(channel_id):
        raise YouTubeChannelSetupError("authorized channel response has no valid channel ID")
    return channel_id


def _owned_playlists_by_title(
    playlists: Sequence[Mapping[str, object]],
) -> dict[str, tuple[str, ...]]:
    collected: dict[str, list[str]] = {}
    for playlist in playlists:
        snippet = playlist.get("snippet")
        status = playlist.get("status")
        if not isinstance(snippet, Mapping) or not isinstance(status, Mapping):
            raise YouTubeChannelSetupError(
                "owned playlist response is missing snippet or status"
            )
        title = str(snippet.get("title", ""))
        privacy = str(status.get("privacyStatus", ""))
        if title in INITIAL_PRIVATE_PLAYLISTS:
            collected.setdefault(title, []).append(privacy)
    return {title: tuple(values) for title, values in collected.items()}


def _validate_created_playlist(response: Mapping[str, object], expected_title: str) -> None:
    playlist_id = str(response.get("id", "")).strip()
    snippet = response.get("snippet")
    status = response.get("status")
    if not playlist_id:
        raise YouTubeChannelSetupError("created playlist response has no playlist ID")
    if not isinstance(snippet, Mapping) or snippet.get("title") != expected_title:
        raise YouTubeChannelSetupError("created playlist response title does not match request")
    if not isinstance(status, Mapping) or status.get("privacyStatus") != "private":
        raise YouTubeChannelSetupError("created playlist response is not private")
