from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Any

from ..canonical import sha256_json
from ..models import ContentPackage
from .base import Publisher, PublishResult

RETRIABLE_STATUS_CODES = frozenset({500, 502, 503, 504})
MAX_DESCRIPTION_LENGTH = 5_000


class ResumableUploadError(RuntimeError):
    """Raised after bounded resumable-upload recovery is exhausted."""


def _publication_marker(package: ContentPackage) -> str:
    digest = sha256_json(package.to_dict())[:20]
    return f"REMEDIALHQ_ID={package.package_id}:{digest}"


def _description(package: ContentPackage) -> str:
    configured = package.metadata.get("youtube_description")
    source = str(configured) if configured else package.body
    marker = _publication_marker(package)
    independence = (
        "Independent editorial coverage. Not affiliated with or endorsed by "
        "Rockstar Games or Take-Two Interactive."
    )
    suffix = f"\n\n{independence}\n{marker}"
    available = MAX_DESCRIPTION_LENGTH - len(suffix)
    if available < 1:
        raise ValueError("publication metadata exceeds YouTube description capacity")
    body = source.strip()
    if len(body) > available:
        body = body[: max(0, available - 1)].rstrip() + "…"
    return body + suffix


def _find_existing_video(youtube: Any, marker: str) -> str | None:
    """Resolve a prior upload after an ambiguous response or process restart."""
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
    if len(video_ids) > 1:
        raise RuntimeError(f"publication marker resolved to multiple videos: {video_ids}")
    return video_ids[0] if video_ids else None


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
    ) -> None:
        if privacy_status not in {"private", "unlisted", "public"}:
            raise ValueError("invalid privacy_status")
        if privacy_status != "private" and not public_publication_authorized:
            raise PermissionError(
                "unlisted/public upload requires explicit public publication authority"
            )
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        self.credentials = credentials
        self.media_path = Path(media_path).resolve()
        self.privacy_status = privacy_status
        self.max_retries = max_retries
        self.thumbnail_path = Path(thumbnail_path).resolve() if thumbnail_path else None
        self.asset_root = Path(asset_root).resolve()

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
        try:
            from googleapiclient.discovery import build
            from googleapiclient.http import MediaFileUpload
        except ImportError as exc:  # pragma: no cover - optional integration
            raise RuntimeError("install remedialhq-engine[youtube]") from exc

        youtube = build("youtube", "v3", credentials=self.credentials, cache_discovery=False)
        marker = _publication_marker(package)
        existing_video_id = _find_existing_video(youtube, marker)
        if existing_video_id:
            status_response = (
                youtube.videos()
                .list(part="status", id=existing_video_id)
                .execute()
            )
            status_items = (
                status_response.get("items", [])
                if isinstance(status_response, dict)
                else []
            )
            if len(status_items) != 1 or not isinstance(status_items[0], dict):
                raise RuntimeError("reconciled video status could not be resolved")
            current_status = dict(status_items[0].get("status", {}))
            privacy_reconciled = current_status.get("privacyStatus") != self.privacy_status
            if privacy_reconciled:
                current_status["privacyStatus"] = self.privacy_status
                youtube.videos().update(
                    part="status",
                    body={"id": existing_video_id, "status": current_status},
                ).execute()
            thumbnail_set = False
            if self.thumbnail_path is not None:
                youtube.thumbnails().set(
                    videoId=existing_video_id,
                    media_body=MediaFileUpload(str(self.thumbnail_path), resumable=False),
                ).execute()
                thumbnail_set = True
            return PublishResult(
                platform="youtube",
                package_id=package.package_id,
                status="RECONCILED_EXISTING",
                remote_id=existing_video_id,
                remote_url=f"https://www.youtube.com/watch?v={existing_video_id}",
                details={
                    "api": "YouTube Data API v3",
                    "publication_marker": marker,
                    "reconciled": True,
                    "privacy_status": self.privacy_status,
                    "privacy_reconciled": privacy_reconciled,
                    "thumbnail_set": thumbnail_set,
                },
            )
        configured_tags = [
            str(item)[:500] for item in package.metadata.get("tags", [])
        ][:499]
        body = {
            "snippet": {
                "title": package.title[:100],
                "description": _description(package),
                "categoryId": str(package.metadata.get("youtube_category_id", "20")),
                "tags": [*configured_tags, marker],
            },
            "status": {
                "privacyStatus": self.privacy_status,
                "selfDeclaredMadeForKids": False,
                "containsSyntheticMedia": bool(
                    package.metadata.get("youtube_contains_synthetic_media", True)
                ),
            },
        }
        request = youtube.videos().insert(
            part="snippet,status",
            body=body,
            notifySubscribers=bool(package.metadata.get("notify_subscribers", False)),
            media_body=MediaFileUpload(
                str(self.media_path),
                chunksize=8 * 1024 * 1024,
                resumable=True,
            ),
        )
        response = _execute_resumable_upload(request, max_retries=self.max_retries)
        video_id = str(response["id"])

        thumbnail_set = False
        if self.thumbnail_path is not None:
            youtube.thumbnails().set(
                videoId=video_id,
                media_body=MediaFileUpload(str(self.thumbnail_path), resumable=False),
            ).execute()
            thumbnail_set = True

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
            },
        )
