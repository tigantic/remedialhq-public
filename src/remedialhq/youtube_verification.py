from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, NoReturn, Protocol, cast

UPLOAD_API_EVIDENCE_SCHEMA = "remedialhq.youtube-upload-api-evidence.v1"
VERIFICATION_FIXTURE_SCHEMA = "remedialhq.youtube-verification-fixture.v1"
VERIFICATION_RESULT_SCHEMA = "remedialhq.youtube-post-upload-verification.v1"
MAX_JSON_DOCUMENT_BYTES = 1_000_000
MAX_PROCESSING_ATTEMPTS = 60
MAX_POLL_INTERVAL_SECONDS = 300.0

_VIDEO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
_CHANNEL_ID_RE = re.compile(r"^UC[A-Za-z0-9_-]{22}$")
_PRIVACY_STATES = frozenset({"private", "unlisted", "public"})
_FAILED_UPLOAD_STATES = frozenset({"deleted", "failed", "rejected"})
_FAILED_PROCESSING_STATES = frozenset({"failed", "terminated"})


class YouTubeVerificationError(RuntimeError):
    """Raised when post-upload evidence cannot be verified exactly."""


class YouTubeProcessingTimeout(YouTubeVerificationError):
    """Raised when a video does not finish processing within the fixed poll budget."""


class YouTubeVerificationTransport(Protocol):
    """The complete read-only surface used by the post-upload verifier."""

    def read_authorized_channel(self) -> Mapping[str, object]: ...

    def read_video(self, video_id: str) -> Mapping[str, object]: ...

    def read_analytics(
        self,
        video_id: str,
        start_date: str,
        end_date: str,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class YouTubeVerificationResult:
    video_id: str
    channel_id: str
    privacy_status: str
    processing_attempts: int
    upload_status: str
    processing_status: str
    thumbnail_variants: int
    analytics_start_date: str
    analytics_end_date: str
    views: int
    estimated_minutes_watched: float

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": VERIFICATION_RESULT_SCHEMA,
            "status": "PASS",
            "video_id": self.video_id,
            "channel_id": self.channel_id,
            "privacy_status": self.privacy_status,
            "processing": {
                "attempts": self.processing_attempts,
                "upload_status": self.upload_status,
                "processing_status": self.processing_status,
            },
            "api_response_evidence": {
                "upload_response": "PASS",
                "thumbnail_set_response": "PASS",
                "thumbnail_variants": self.thumbnail_variants,
            },
            "analytics": {
                "start_date": self.analytics_start_date,
                "end_date": self.analytics_end_date,
                "views": self.views,
                "estimated_minutes_watched": self.estimated_minutes_watched,
            },
        }


@dataclass(frozen=True, slots=True)
class _ApiEvidenceSummary:
    thumbnail_variants: int


@dataclass(frozen=True, slots=True)
class _VideoState:
    upload_status: str
    processing_status: str


class FixtureYouTubeVerificationTransport:
    """Replay exact read-response fixtures without credentials or network access."""

    def __init__(self, fixture: Mapping[str, object]) -> None:
        _require_exact_fields(
            fixture,
            {
                "schema_version",
                "channel_response",
                "video_responses",
                "analytics_response",
            },
            "verification fixture",
        )
        if fixture["schema_version"] != VERIFICATION_FIXTURE_SCHEMA:
            raise YouTubeVerificationError("unsupported YouTube verification fixture schema")
        channel_response = fixture["channel_response"]
        video_responses = fixture["video_responses"]
        analytics_response = fixture["analytics_response"]
        if not isinstance(channel_response, Mapping):
            raise YouTubeVerificationError("fixture channel response must be an object")
        if not isinstance(video_responses, Sequence) or isinstance(
            video_responses, (str, bytes, bytearray)
        ):
            raise YouTubeVerificationError("fixture video responses must be a list")
        if not video_responses or not all(
            isinstance(response, Mapping) for response in video_responses
        ):
            raise YouTubeVerificationError(
                "fixture must contain at least one object-shaped video response"
            )
        if not isinstance(analytics_response, Mapping):
            raise YouTubeVerificationError("fixture Analytics response must be an object")
        self._channel_response = cast(Mapping[str, object], channel_response)
        self._video_responses = tuple(
            cast(Mapping[str, object], response) for response in video_responses
        )
        self._analytics_response = cast(Mapping[str, object], analytics_response)
        self._video_index = 0

    @classmethod
    def from_file(cls, path: str | Path) -> FixtureYouTubeVerificationTransport:
        return cls(load_json_object(path, label="verification fixture"))

    def read_authorized_channel(self) -> Mapping[str, object]:
        return self._channel_response

    def read_video(self, video_id: str) -> Mapping[str, object]:
        del video_id
        if self._video_index >= len(self._video_responses):
            raise YouTubeVerificationError("verification fixture exhausted video responses")
        response = self._video_responses[self._video_index]
        self._video_index += 1
        return response

    def read_analytics(
        self,
        video_id: str,
        start_date: str,
        end_date: str,
    ) -> Mapping[str, object]:
        del video_id, start_date, end_date
        return self._analytics_response


class GoogleYouTubeVerificationTransport:
    """Read-only YouTube Data and Analytics API adapter.

    Only ``list`` and ``query`` methods are reachable through this adapter. It has no
    upload, update, thumbnail-set, delete, or publication method.
    """

    def __init__(self, youtube_client: Any, analytics_client: Any) -> None:
        self._youtube = youtube_client
        self._analytics = analytics_client

    @classmethod
    def from_credentials(
        cls,
        credentials: object,
        *,
        builder: Callable[..., Any] | None = None,
    ) -> GoogleYouTubeVerificationTransport:
        if credentials is None:
            raise YouTubeVerificationError(
                "credentials are required to construct a live readback transport"
            )
        active_builder = builder
        if active_builder is None:
            try:
                from googleapiclient.discovery import build
            except ImportError as exc:  # pragma: no cover - optional integration
                raise YouTubeVerificationError(
                    "install remedialhq-engine[youtube] for live readback"
                ) from exc
            active_builder = build
        youtube = active_builder(
            "youtube",
            "v3",
            credentials=credentials,
            cache_discovery=False,
        )
        analytics = active_builder(
            "youtubeAnalytics",
            "v2",
            credentials=credentials,
            cache_discovery=False,
        )
        return cls(youtube, analytics)

    def read_authorized_channel(self) -> Mapping[str, object]:
        response = (
            self._youtube.channels()
            .list(part="id", mine=True, maxResults=1)
            .execute()
        )
        return _mapping_response(response, "authorized channel")

    def read_video(self, video_id: str) -> Mapping[str, object]:
        response = (
            self._youtube.videos()
            .list(
                part="id,snippet,status,processingDetails",
                id=video_id,
                maxResults=1,
            )
            .execute()
        )
        return _mapping_response(response, "video")

    def read_analytics(
        self,
        video_id: str,
        start_date: str,
        end_date: str,
    ) -> Mapping[str, object]:
        response = (
            self._analytics.reports()
            .query(
                ids="channel==MINE",
                startDate=start_date,
                endDate=end_date,
                metrics="views,estimatedMinutesWatched",
                dimensions="video",
                filters=f"video=={video_id}",
                maxResults=1,
            )
            .execute()
        )
        return _mapping_response(response, "Analytics")


def validate_youtube_verification_inputs(
    *,
    video_id: str,
    expected_channel_id: str,
    expected_privacy_status: str,
    analytics_start_date: str,
    analytics_end_date: str,
    max_processing_attempts: int,
    poll_interval_seconds: float,
) -> None:
    if not _VIDEO_ID_RE.fullmatch(video_id):
        raise YouTubeVerificationError(
            "video ID must be an explicit 11-character YouTube video ID"
        )
    if not _CHANNEL_ID_RE.fullmatch(expected_channel_id):
        raise YouTubeVerificationError(
            "expected channel ID must be an explicit 24-character YouTube channel ID"
        )
    if expected_privacy_status not in _PRIVACY_STATES:
        raise YouTubeVerificationError("invalid expected YouTube privacy state")
    start = _parse_date(analytics_start_date, "Analytics start date")
    end = _parse_date(analytics_end_date, "Analytics end date")
    if start > end:
        raise YouTubeVerificationError("Analytics start date cannot follow end date")
    if isinstance(max_processing_attempts, bool) or not isinstance(
        max_processing_attempts, int
    ):
        raise YouTubeVerificationError("processing attempt limit must be an integer")
    if not 1 <= max_processing_attempts <= MAX_PROCESSING_ATTEMPTS:
        raise YouTubeVerificationError(
            f"processing attempt limit must be between 1 and {MAX_PROCESSING_ATTEMPTS}"
        )
    if isinstance(poll_interval_seconds, bool) or not isinstance(
        poll_interval_seconds, (int, float)
    ):
        raise YouTubeVerificationError("processing poll interval must be numeric")
    interval = float(poll_interval_seconds)
    if not math.isfinite(interval) or not 0 <= interval <= MAX_POLL_INTERVAL_SECONDS:
        raise YouTubeVerificationError(
            "processing poll interval is outside the supported bounded range"
        )


def validate_upload_api_evidence(
    evidence: Mapping[str, object],
    *,
    video_id: str,
    expected_channel_id: str,
    expected_privacy_status: str,
) -> int:
    """Validate upload and thumbnail-set responses before any live read is attempted."""
    summary = _validate_upload_api_evidence(
        evidence,
        video_id=video_id,
        expected_channel_id=expected_channel_id,
        expected_privacy_status=expected_privacy_status,
    )
    return summary.thumbnail_variants


def build_upload_api_evidence(
    upload_response: Mapping[str, object],
    thumbnail_response: Mapping[str, object],
    *,
    video_id: str,
    expected_channel_id: str,
    expected_privacy_status: str,
) -> dict[str, object]:
    """Create the exact verifier envelope while discarding unrelated API fields."""
    upload_snippet = _required_mapping(upload_response, "snippet", "upload response")
    upload_status = _required_mapping(upload_response, "status", "upload response")
    raw_items = thumbnail_response.get("items")
    if not isinstance(raw_items, Sequence) or isinstance(
        raw_items, (str, bytes, bytearray)
    ):
        raise YouTubeVerificationError("thumbnail response items must be a list")
    if len(raw_items) != 1 or not isinstance(raw_items[0], Mapping):
        raise YouTubeVerificationError(
            "thumbnail response must contain exactly one thumbnail resource"
        )
    raw_thumbnail_resource = cast(Mapping[str, object], raw_items[0])
    thumbnail_resource: dict[str, object] = {}
    for name in ("default", "medium", "high", "standard", "maxres"):
        raw_variant = raw_thumbnail_resource.get(name)
        if raw_variant is None:
            continue
        if not isinstance(raw_variant, Mapping):
            raise YouTubeVerificationError("thumbnail response variant must be an object")
        thumbnail_resource[name] = {
            "url": raw_variant.get("url"),
            "width": raw_variant.get("width"),
            "height": raw_variant.get("height"),
        }
    evidence: dict[str, object] = {
        "schema_version": UPLOAD_API_EVIDENCE_SCHEMA,
        "video_id": video_id,
        "upload_response": {
            "kind": upload_response.get("kind"),
            "id": upload_response.get("id"),
            "snippet": {"channelId": upload_snippet.get("channelId")},
            "status": {"privacyStatus": upload_status.get("privacyStatus")},
        },
        "thumbnail_set": {
            "video_id": video_id,
            "response": {
                "kind": thumbnail_response.get("kind"),
                "items": [thumbnail_resource],
            },
        },
    }
    validate_upload_api_evidence(
        evidence,
        video_id=video_id,
        expected_channel_id=expected_channel_id,
        expected_privacy_status=expected_privacy_status,
    )
    return evidence


def prepare_private_upload_api_evidence_output(path: str | Path) -> Path:
    """Preflight a create-only private evidence destination before an upload starts."""
    destination = Path(os.path.abspath(Path(path).expanduser()))
    _reject_symlink_ancestors(destination)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise YouTubeVerificationError(
            "upload API evidence parent directory could not be created"
        ) from exc
    _reject_symlink_ancestors(destination)
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise YouTubeVerificationError(
            "upload API evidence destination could not be inspected"
        ) from exc
    else:
        raise YouTubeVerificationError(
            "upload API evidence destination already exists"
        )
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".permission-probe",
    )
    probe = Path(temporary_name)
    try:
        os.close(descriptor)
        os.chmod(probe, 0o600)
        if os.name == "posix" and probe.stat().st_mode & 0o777 != 0o600:
            raise YouTubeVerificationError(
                "upload API evidence destination cannot enforce mode 0600"
            )
    finally:
        probe.unlink(missing_ok=True)
    return destination


def write_private_upload_api_evidence(
    path: str | Path,
    evidence: Mapping[str, object],
    *,
    video_id: str,
    expected_channel_id: str,
    expected_privacy_status: str,
) -> str:
    """Create one atomic owner-private evidence artifact and return its byte digest."""
    validate_upload_api_evidence(
        evidence,
        video_id=video_id,
        expected_channel_id=expected_channel_id,
        expected_privacy_status=expected_privacy_status,
    )
    destination = prepare_private_upload_api_evidence_output(path)
    payload = (
        json.dumps(
            evidence,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    created_destination = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise YouTubeVerificationError(
                "upload API evidence destination already exists"
            ) from exc
        except OSError as exc:
            raise YouTubeVerificationError(
                "upload API evidence could not be created atomically"
            ) from exc
        created_destination = True
        if os.name == "posix" and destination.stat().st_mode & 0o777 != 0o600:
            raise YouTubeVerificationError(
                "upload API evidence destination cannot enforce mode 0600"
            )
    except Exception:
        if created_destination:
            destination.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(payload).hexdigest()


def verify_youtube_post_upload(
    transport: YouTubeVerificationTransport,
    api_evidence: Mapping[str, object],
    *,
    video_id: str,
    expected_channel_id: str,
    expected_privacy_status: str,
    analytics_start_date: str,
    analytics_end_date: str,
    max_processing_attempts: int = 12,
    poll_interval_seconds: float = 5.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> YouTubeVerificationResult:
    """Verify one existing upload without exposing any mutation-capable operation."""
    validate_youtube_verification_inputs(
        video_id=video_id,
        expected_channel_id=expected_channel_id,
        expected_privacy_status=expected_privacy_status,
        analytics_start_date=analytics_start_date,
        analytics_end_date=analytics_end_date,
        max_processing_attempts=max_processing_attempts,
        poll_interval_seconds=poll_interval_seconds,
    )
    evidence_summary = _validate_upload_api_evidence(
        api_evidence,
        video_id=video_id,
        expected_channel_id=expected_channel_id,
        expected_privacy_status=expected_privacy_status,
    )

    channel_response = _transport_read(
        "authorized channel", transport.read_authorized_channel
    )
    channel = _single_api_item(channel_response, "authorized channel")
    channel_id = _required_string(channel, "id", "authorized channel")
    if channel_id != expected_channel_id:
        raise YouTubeVerificationError(
            "authorized YouTube channel does not match the exact expected channel ID"
        )

    final_state: _VideoState | None = None
    attempts = 0
    for attempt in range(1, max_processing_attempts + 1):
        attempts = attempt
        video_response = _transport_read(
            "video", lambda: transport.read_video(video_id)
        )
        video = _single_api_item(video_response, "video")
        final_state = _validate_video_state(
            video,
            video_id=video_id,
            expected_channel_id=expected_channel_id,
            expected_privacy_status=expected_privacy_status,
        )
        if (
            final_state.upload_status == "processed"
            and final_state.processing_status == "succeeded"
        ):
            break
        if attempt < max_processing_attempts:
            sleeper(float(poll_interval_seconds))
    else:
        raise YouTubeProcessingTimeout(
            f"video processing did not complete within {max_processing_attempts} read attempts"
        )
    if final_state is None:  # pragma: no cover - loop bounds are validated above
        raise AssertionError("processing poll did not execute")

    analytics_response = _transport_read(
        "Analytics",
        lambda: transport.read_analytics(
            video_id,
            analytics_start_date,
            analytics_end_date,
        ),
    )
    views, minutes = _validate_analytics(analytics_response, video_id=video_id)
    return YouTubeVerificationResult(
        video_id=video_id,
        channel_id=channel_id,
        privacy_status=expected_privacy_status,
        processing_attempts=attempts,
        upload_status=final_state.upload_status,
        processing_status=final_state.processing_status,
        thumbnail_variants=evidence_summary.thumbnail_variants,
        analytics_start_date=analytics_start_date,
        analytics_end_date=analytics_end_date,
        views=views,
        estimated_minutes_watched=minutes,
    )


def load_upload_api_evidence(path: str | Path) -> dict[str, object]:
    return load_json_object(path, label="upload API evidence")


def load_json_object(path: str | Path, *, label: str) -> dict[str, object]:
    source = Path(path).expanduser()
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise YouTubeVerificationError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise YouTubeVerificationError(f"{label} must be a regular non-symlink file")
    if metadata.st_size > MAX_JSON_DOCUMENT_BYTES:
        raise YouTubeVerificationError(f"{label} exceeds the size limit")
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise YouTubeVerificationError(f"{label} could not be read") from exc
    if len(raw) > MAX_JSON_DOCUMENT_BYTES:
        raise YouTubeVerificationError(f"{label} exceeds the size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise YouTubeVerificationError(f"{label} is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except (json.JSONDecodeError, YouTubeVerificationError) as exc:
        raise YouTubeVerificationError(f"{label} is not valid strict JSON") from exc
    if not isinstance(value, dict):
        raise YouTubeVerificationError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _validate_upload_api_evidence(
    evidence: Mapping[str, object],
    *,
    video_id: str,
    expected_channel_id: str,
    expected_privacy_status: str,
) -> _ApiEvidenceSummary:
    _require_exact_fields(
        evidence,
        {"schema_version", "video_id", "upload_response", "thumbnail_set"},
        "upload API evidence",
    )
    if evidence["schema_version"] != UPLOAD_API_EVIDENCE_SCHEMA:
        raise YouTubeVerificationError("unsupported upload API evidence schema")
    if evidence["video_id"] != video_id:
        raise YouTubeVerificationError("upload API evidence is bound to another video")

    upload_response = _required_mapping(
        evidence, "upload_response", "upload API evidence"
    )
    if upload_response.get("kind") != "youtube#video":
        raise YouTubeVerificationError("upload response is not a YouTube video resource")
    if upload_response.get("id") != video_id:
        raise YouTubeVerificationError("upload response video ID does not match")
    upload_snippet = _required_mapping(upload_response, "snippet", "upload response")
    if upload_snippet.get("channelId") != expected_channel_id:
        raise YouTubeVerificationError("upload response channel ID does not match")
    upload_status = _required_mapping(upload_response, "status", "upload response")
    if upload_status.get("privacyStatus") != expected_privacy_status:
        raise YouTubeVerificationError("upload response privacy state does not match")

    thumbnail_set = _required_mapping(evidence, "thumbnail_set", "upload API evidence")
    _require_exact_fields(thumbnail_set, {"video_id", "response"}, "thumbnail evidence")
    if thumbnail_set["video_id"] != video_id:
        raise YouTubeVerificationError("thumbnail request evidence is bound to another video")
    thumbnail_response = _required_mapping(
        thumbnail_set, "response", "thumbnail evidence"
    )
    if thumbnail_response.get("kind") != "youtube#thumbnailSetResponse":
        raise YouTubeVerificationError("thumbnail response kind is not verifiable")
    items = thumbnail_response.get("items")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        raise YouTubeVerificationError("thumbnail response items must be a list")
    if len(items) != 1 or not isinstance(items[0], Mapping):
        raise YouTubeVerificationError(
            "thumbnail response must contain exactly one thumbnail resource"
        )
    thumbnail_resource = cast(Mapping[str, object], items[0])
    variants = 0
    for name in ("default", "medium", "high", "standard", "maxres"):
        candidate = thumbnail_resource.get(name)
        if candidate is None:
            continue
        if not isinstance(candidate, Mapping):
            raise YouTubeVerificationError("thumbnail response variant must be an object")
        url = candidate.get("url")
        width = candidate.get("width")
        height = candidate.get("height")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise YouTubeVerificationError("thumbnail response variant has no HTTPS URL")
        if (
            isinstance(width, bool)
            or not isinstance(width, int)
            or width <= 0
            or isinstance(height, bool)
            or not isinstance(height, int)
            or height <= 0
        ):
            raise YouTubeVerificationError("thumbnail response variant has invalid dimensions")
        variants += 1
    if variants == 0:
        raise YouTubeVerificationError("thumbnail response contains no usable variants")
    return _ApiEvidenceSummary(thumbnail_variants=variants)


def _validate_video_state(
    video: Mapping[str, object],
    *,
    video_id: str,
    expected_channel_id: str,
    expected_privacy_status: str,
) -> _VideoState:
    if _required_string(video, "id", "video response") != video_id:
        raise YouTubeVerificationError("video readback returned a different video ID")
    snippet = _required_mapping(video, "snippet", "video response")
    if snippet.get("channelId") != expected_channel_id:
        raise YouTubeVerificationError("video belongs to a different YouTube channel")
    status = _required_mapping(video, "status", "video response")
    privacy = _required_string(status, "privacyStatus", "video status")
    if privacy != expected_privacy_status:
        raise YouTubeVerificationError("video privacy state does not match the expected state")
    upload_status = _required_string(status, "uploadStatus", "video status")
    processing = _required_mapping(video, "processingDetails", "video response")
    processing_status = _required_string(
        processing, "processingStatus", "video processing details"
    )
    if upload_status in _FAILED_UPLOAD_STATES:
        raise YouTubeVerificationError(f"video upload entered terminal state {upload_status}")
    if processing_status in _FAILED_PROCESSING_STATES:
        raise YouTubeVerificationError(
            f"video processing entered terminal state {processing_status}"
        )
    if upload_status not in {"uploaded", "processed"}:
        raise YouTubeVerificationError("video upload state is not recognized")
    if processing_status not in {"processing", "succeeded"}:
        raise YouTubeVerificationError("video processing state is not recognized")
    if upload_status == "uploaded" and processing_status == "succeeded":
        raise YouTubeVerificationError("video readback contains inconsistent processing state")
    return _VideoState(
        upload_status=upload_status,
        processing_status=processing_status,
    )


def _validate_analytics(
    response: Mapping[str, object],
    *,
    video_id: str,
) -> tuple[int, float]:
    if response.get("kind") != "youtubeAnalytics#resultTable":
        raise YouTubeVerificationError("Analytics readback is not a result table")
    raw_headers = response.get("columnHeaders")
    if not isinstance(raw_headers, Sequence) or isinstance(
        raw_headers, (str, bytes, bytearray)
    ):
        raise YouTubeVerificationError("Analytics column headers are missing")
    headers: list[str] = []
    for raw_header in raw_headers:
        if not isinstance(raw_header, Mapping):
            raise YouTubeVerificationError("Analytics column header is not an object")
        name = raw_header.get("name")
        if not isinstance(name, str) or not name:
            raise YouTubeVerificationError("Analytics column header has no name")
        if name in headers:
            raise YouTubeVerificationError("Analytics readback has duplicate columns")
        headers.append(name)
    required_columns = {"video", "views", "estimatedMinutesWatched"}
    if not required_columns.issubset(headers):
        raise YouTubeVerificationError("Analytics readback is missing required columns")
    raw_rows = response.get("rows")
    if not isinstance(raw_rows, Sequence) or isinstance(raw_rows, (str, bytes, bytearray)):
        raise YouTubeVerificationError("Analytics readback contains no rows")
    matching_rows: list[Sequence[object]] = []
    video_index = headers.index("video")
    for raw_row in raw_rows:
        if not isinstance(raw_row, Sequence) or isinstance(
            raw_row, (str, bytes, bytearray)
        ):
            raise YouTubeVerificationError("Analytics row is not a list")
        if len(raw_row) != len(headers):
            raise YouTubeVerificationError("Analytics row does not match its headers")
        if raw_row[video_index] == video_id:
            matching_rows.append(cast(Sequence[object], raw_row))
    if len(matching_rows) != 1:
        raise YouTubeVerificationError(
            "Analytics readback must contain exactly one row for the expected video"
        )
    row = matching_rows[0]
    views_value = row[headers.index("views")]
    minutes_value = row[headers.index("estimatedMinutesWatched")]
    if isinstance(views_value, bool) or not isinstance(views_value, int) or views_value < 0:
        raise YouTubeVerificationError("Analytics views value is invalid")
    if isinstance(minutes_value, bool) or not isinstance(minutes_value, (int, float)):
        raise YouTubeVerificationError("Analytics watch-time value is invalid")
    minutes = float(minutes_value)
    if not math.isfinite(minutes) or minutes < 0:
        raise YouTubeVerificationError("Analytics watch-time value is invalid")
    return views_value, minutes


def _mapping_response(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise YouTubeVerificationError(f"{label} API response was not an object")
    return cast(Mapping[str, object], value)


def _transport_read(
    label: str,
    reader: Callable[[], Mapping[str, object]],
) -> Mapping[str, object]:
    try:
        return _mapping_response(reader(), label)
    except YouTubeVerificationError:
        raise
    except Exception as exc:
        raise YouTubeVerificationError(f"{label} readback failed") from exc


def _single_api_item(
    response: Mapping[str, object],
    label: str,
) -> Mapping[str, object]:
    items = response.get("items")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        raise YouTubeVerificationError(f"{label} response items are missing")
    if len(items) != 1 or not isinstance(items[0], Mapping):
        raise YouTubeVerificationError(
            f"{label} response must contain exactly one resource"
        )
    return cast(Mapping[str, object], items[0])


def _required_mapping(
    value: Mapping[str, object],
    key: str,
    label: str,
) -> Mapping[str, object]:
    item = value.get(key)
    if not isinstance(item, Mapping):
        raise YouTubeVerificationError(f"{label} field {key} must be an object")
    return cast(Mapping[str, object], item)


def _required_string(value: Mapping[str, object], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise YouTubeVerificationError(f"{label} field {key} must be a non-empty string")
    return item


def _require_exact_fields(
    value: Mapping[str, object],
    expected: set[str],
    label: str,
) -> None:
    if set(value) != expected:
        raise YouTubeVerificationError(f"{label} fields do not match the supported schema")


def _parse_date(value: str, label: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise YouTubeVerificationError(f"{label} must use YYYY-MM-DD") from exc
    if parsed.isoformat() != value:
        raise YouTubeVerificationError(f"{label} must use canonical YYYY-MM-DD")
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise YouTubeVerificationError("JSON document contains duplicate fields")
        value[key] = item
    return value


def _reject_non_json_number(value: str) -> NoReturn:
    del value
    raise YouTubeVerificationError("JSON document contains a non-JSON number")


def _reject_symlink_ancestors(path: Path) -> None:
    for ancestor in (path.parent, *path.parents):
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise YouTubeVerificationError(
                "upload API evidence path could not be inspected"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise YouTubeVerificationError(
                "upload API evidence path cannot contain symlink ancestors"
            )
