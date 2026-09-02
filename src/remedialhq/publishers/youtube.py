from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Any

from ..models import ContentPackage
from ..youtube_upload_control import (
    YouTubeUploadAuthorization,
    claim_youtube_upload_authorization,
    publication_marker,
    youtube_description,
)
from ..youtube_verification import build_upload_api_evidence
from .base import Publisher, PublishResult

RETRIABLE_STATUS_CODES = frozenset({500, 502, 503, 504})
MAX_DESCRIPTION_LENGTH = 5_000


class ResumableUploadError(RuntimeError):
    """Raised after bounded resumable-upload recovery is exhausted."""


def _publication_marker(package: ContentPackage) -> str:
    return publication_marker(package)


def _description(package: ContentPackage) -> str:
    return youtube_description(package, maximum_length=MAX_DESCRIPTION_LENGTH)


def _find_existing_video(youtube: Any, marker: str) -> str | None:
    """Find only an owned video whose full description has the exact marker line."""
    response = (
        youtube.search()
        .list(part="id", forMine=True, type="video", q=marker, maxResults=5)
        .execute()
    )
    items = response.get("items", []) if isinstance(response, dict) else []
    video_ids = sorted(
        {
            str(item.get("id", {}).get("videoId", "")).strip()
            for item in items
            if isinstance(item, dict) and isinstance(item.get("id"), dict)
        }
        - {""}
    )
    candidate_ids = video_ids
    if not candidate_ids:
        return None
    response = (
        youtube.videos()
        .list(
            part="id,snippet",
            id=",".join(candidate_ids),
            maxResults=len(candidate_ids),
        )
        .execute()
    )
    items = response.get("items", []) if isinstance(response, dict) else []
    if not isinstance(items, list) or len(items) != len(candidate_ids):
        raise RuntimeError("publication marker search candidates could not be verified")
    exact_ids: list[str] = []
    returned_ids: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise RuntimeError("publication marker search candidate is invalid")  # noqa: TRY004
        video_id = str(item.get("id", "")).strip()
        snippet = item.get("snippet")
        if video_id not in candidate_ids or video_id in returned_ids:
            raise RuntimeError("publication marker search candidate identity is invalid")
        returned_ids.add(video_id)
        if not isinstance(snippet, dict):
            raise RuntimeError("publication marker search candidate has no snippet")  # noqa: TRY004
        description = snippet.get("description")
        if not isinstance(description, str):
            raise RuntimeError("publication marker search candidate has no description")  # noqa: TRY004
        if marker in {line.strip() for line in description.splitlines()}:
            exact_ids.append(video_id)
    if set(candidate_ids) != returned_ids or not exact_ids:
        raise RuntimeError("publication marker search result did not verify the exact marker")
    if len(exact_ids) != 1:
        raise RuntimeError(f"publication marker resolved to multiple videos: {exact_ids}")
    return exact_ids[0]


def _status_code(exc: BaseException) -> int | None:
    response = getattr(exc, "resp", None)
    status = getattr(response, "status", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _is_retriable(exc: BaseException) -> bool:
    status = _status_code(exc)
    return status in RETRIABLE_STATUS_CODES or isinstance(
        exc, (ConnectionError, OSError, TimeoutError)
    )


def _execute_resumable_upload(
    request: Any,
    *,
    max_retries: int = 6,
    sleeper: Callable[[float], None] = time.sleep,
    jitter: Callable[[], float] = random.random,
) -> dict[str, Any]:
    """Execute a resumable upload with bounded exponential backoff.

    The helper is dependency-free so retry behavior can be tested without loading the
    optional Google API client. A terminal response must contain a video identity.
    """
    if max_retries < 0:
        raise ValueError("max_retries cannot be negative")
    retries = 0
    while True:
        try:
            _, response = request.next_chunk()
            if response is None:
                continue
            if not isinstance(response, dict) or not response.get("id"):
                raise ResumableUploadError("YouTube returned no video identity")
            return response
        except Exception as exc:
            if not _is_retriable(exc):
                raise
            if retries >= max_retries:
                raise ResumableUploadError(
                    f"resumable upload failed after {retries + 1} attempts"
                ) from exc
            delay = min(60.0, (2**retries) + jitter())
            sleeper(delay)
            retries += 1


class YouTubePublisher(Publisher):
    """Optional YouTube Data API adapter with fail-closed publication authority.

    The adapter defaults to private, requires a separate authority for any externally
    visible privacy state, uses resumable uploads, and embeds a deterministic package
    marker for later reconciliation. Install the ``youtube`` optional dependency first.
    """

    def __init__(
        self,
        credentials: Any,
        media_path: str | Path,
        *,
        privacy_status: str = "private",
        public_publication_authorized: bool = False,
        max_retries: int = 6,
        thumbnail_path: str | Path | None = None,
        asset_root: str | Path = ".",
        expected_channel_id: str | None = None,
        verification_evidence_required: bool = False,
        upload_authorization: YouTubeUploadAuthorization | None = None,
    ) -> None:
        if privacy_status not in {"private", "unlisted", "public"}:
            raise ValueError("invalid privacy_status")
        if privacy_status != "private" and not public_publication_authorized:
            raise PermissionError(
                "unlisted/public upload requires explicit public publication authority"
            )
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if verification_evidence_required and thumbnail_path is None:
            raise ValueError(
                "verification evidence requires an explicit thumbnail path before upload"
            )
        if verification_evidence_required and not expected_channel_id:
            raise ValueError(
                "verification evidence requires an explicit expected channel ID"
            )
        self.credentials = credentials
        self.media_path = Path(media_path).resolve()
        self.privacy_status = privacy_status
        self.max_retries = max_retries
        self.thumbnail_path = Path(thumbnail_path).resolve() if thumbnail_path else None
        self.asset_root = Path(asset_root).resolve()
        self.expected_channel_id = expected_channel_id
        self.verification_evidence_required = verification_evidence_required
        self.upload_authorization = upload_authorization

    def _validate_declared_assets(self, package: ContentPackage) -> None:
        declared = {}
        for asset in package.assets:
            path = (self.asset_root / asset.path).resolve()
            if not path.is_relative_to(self.asset_root):
                raise PermissionError(f"asset {asset.asset_id} escapes the reviewed asset root")
            declared[path] = asset
        if self.media_path not in declared:
            raise PermissionError("upload media is not declared in the gated package assets")
        if self.thumbnail_path is not None and self.thumbnail_path not in declared:
            raise PermissionError("upload thumbnail is not declared in the gated package assets")
        selected = [self.media_path]
        if self.thumbnail_path is not None:
            selected.append(self.thumbnail_path)
        for path in selected:
            asset = declared[path]
            if not asset.sha256:
                raise PermissionError(f"upload asset {asset.asset_id} has no reviewed sha256")
            if not path.is_file():
                raise FileNotFoundError(path)
            digest = sha256(path.read_bytes()).hexdigest()
            if digest != asset.sha256:
                raise PermissionError(
                    f"upload asset {asset.asset_id} does not match its reviewed sha256"
                )
        media_asset = declared[self.media_path]
        review = package.metadata.get("media_review")
        if not isinstance(review, dict) or review.get("asset_id") != media_asset.asset_id:
            raise PermissionError("upload media has no matching storyboard review record")
        storyboard_path = (
            self.asset_root / str(review.get("storyboard_path", ""))
        ).resolve()
        if not storyboard_path.is_relative_to(self.asset_root) or not storyboard_path.is_file():
            raise PermissionError("reviewed storyboard is missing or outside the asset root")
        storyboard_digest = sha256(storyboard_path.read_bytes()).hexdigest()
        if storyboard_digest != review.get("storyboard_sha256"):
            raise PermissionError("storyboard does not match its reviewed sha256")
        storyboard = json.loads(storyboard_path.read_text(encoding="utf-8"))
        if not isinstance(storyboard, list) or not storyboard:
            raise PermissionError("reviewed storyboard must contain scenes")
        allowed_claim_ids = set(package.claim_ids)
        trigger_terms = ("gta", "rockstar", "official", "launch", "search")
        for index, scene in enumerate(storyboard, 1):
            if not isinstance(scene, dict):
                raise PermissionError(f"storyboard scene {index} is not an object")
            claim_ids = {str(item) for item in scene.get("claim_ids", [])}
            if not claim_ids.issubset(allowed_claim_ids):
                raise PermissionError(f"storyboard scene {index} binds unknown package claims")
            text = " ".join(str(scene.get(key, "")) for key in ("kicker", "hero", "sub"))
            requires_claim = any(character.isdigit() for character in text) or any(
                term in text.casefold() for term in trigger_terms
            )
            if requires_claim and not claim_ids:
                raise PermissionError(f"storyboard scene {index} has an unbound factual signal")

    def publish(self, package: ContentPackage) -> PublishResult:
        if package.platform.casefold() != "youtube":
            raise ValueError("YouTubePublisher received a non-YouTube package")
        self._validate_declared_assets(package)
        if not self.media_path.is_file():
            raise FileNotFoundError(self.media_path)
        if self.thumbnail_path is not None and not self.thumbnail_path.is_file():
            raise FileNotFoundError(self.thumbnail_path)
        if self.upload_authorization is None:
            raise PermissionError(
                "YouTube upload requires an unconsumed exact-preview confirmation"
            )
        if not self.expected_channel_id:
            raise PermissionError("YouTube upload requires an exact expected channel ID")
        if self.upload_authorization.media_path != self.media_path:
            raise PermissionError("YouTube upload authorization is bound to another video")
        if self.thumbnail_path is None or (
            self.upload_authorization.thumbnail_path != self.thumbnail_path
        ):
            raise PermissionError("YouTube upload authorization is bound to another thumbnail")
        try:
            from googleapiclient.discovery import build
            from googleapiclient.http import MediaIoBaseUpload
        except ImportError as exc:  # pragma: no cover - optional integration
            raise RuntimeError("install remedialhq-engine[youtube]") from exc

        claimed = claim_youtube_upload_authorization(
            self.upload_authorization,
            package,
            expected_channel_id=self.expected_channel_id,
            privacy_status=self.privacy_status,
        )
        try:
            youtube = build(
                "youtube", "v3", credentials=self.credentials, cache_discovery=False
            )
            marker = claimed.publication_marker
            upload_request = claimed.request_payload()
            existing_video_id = _find_existing_video(youtube, marker)
            if existing_video_id:
                raise PermissionError(
                    "an existing exact-marker upload requires a separately previewed "
                    "remote reconciliation operation"
                )

            request = youtube.videos().insert(
                part="snippet,status",
                body=upload_request["body"],
                notifySubscribers=upload_request["notifySubscribers"],
                media_body=MediaIoBaseUpload(
                    claimed.media,
                    mimetype="video/mp4",
                    chunksize=8 * 1024 * 1024,
                    resumable=True,
                ),
            )
            response = _execute_resumable_upload(request, max_retries=self.max_retries)
            video_id = str(response["id"])

            thumbnail_set = False
            thumbnail_response: dict[str, Any] | None = None
            raw_thumbnail_response = youtube.thumbnails().set(
                videoId=video_id,
                media_body=MediaIoBaseUpload(
                    claimed.thumbnail,
                    mimetype="image/png",
                    resumable=False,
                ),
            ).execute()
            if isinstance(raw_thumbnail_response, dict):
                thumbnail_response = raw_thumbnail_response
            thumbnail_set = True

            verification_evidence: dict[str, object] | None = None
            if thumbnail_response is not None and self.expected_channel_id:
                verification_evidence = build_upload_api_evidence(
                    response,
                    thumbnail_response,
                    video_id=video_id,
                    expected_channel_id=self.expected_channel_id,
                    expected_privacy_status=self.privacy_status,
                )
            if self.verification_evidence_required and verification_evidence is None:
                raise RuntimeError(
                    "YouTube did not return the required thumbnail-set response evidence"
                )

            return PublishResult(
                platform="youtube",
                package_id=package.package_id,
                status=f"PUBLISHED_{self.privacy_status.upper()}",
                remote_id=video_id,
                remote_url=f"https://www.youtube.com/watch?v={video_id}",
                details={
                    "api": "YouTube Data API v3",
                    "privacy_status": self.privacy_status,
                    "publication_marker": marker,
                    "thumbnail_set": thumbnail_set,
                    "reconciled": False,
                    "upload_preview_sha256": self.upload_authorization.preview_sha256,
                    "upload_confirmation_sha256": (
                        self.upload_authorization.confirmation_sha256
                    ),
                    "upload_confirmation_consumption_sha256": (
                        claimed.consumption_sha256
                    ),
                    **(
                        {"verification_api_evidence": verification_evidence}
                        if verification_evidence is not None
                        else {}
                    ),
                },
            )
        finally:
            claimed.close()
