from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Self

from .canonical import canonical_json, sha256_json
from .models import Asset, ContentPackage

YOUTUBE_UPLOAD_PREVIEW_SCHEMA = "remedialhq.youtube-upload-preview.v1"
YOUTUBE_UPLOAD_CONFIRMATION_SCHEMA = "remedialhq.youtube-upload-confirmation.v1"
YOUTUBE_UPLOAD_CONSUMPTION_SCHEMA = "remedialhq.youtube-upload-consumption.v1"
MAX_UPLOAD_CONTROL_BYTES = 262_144

_CHANNEL_ID_RE = re.compile(r"^UC[A-Za-z0-9_-]{22}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PRIVACY_STATES = frozenset({"private", "unlisted", "public"})


class YouTubeUploadControlError(RuntimeError):
    """Raised when an upload lacks an exact, single-use owner confirmation."""


@dataclass(frozen=True, slots=True)
class YouTubeUploadArtifact:
    path: Path
    sha256: str
    payload: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "document": self.payload,
        }


@dataclass(frozen=True, slots=True)
class YouTubeUploadAuthorization:
    repository_root: Path
    preview_path: Path
    preview_sha256: str
    confirmation_path: Path
    confirmation_sha256: str
    consumption_directory: Path
    channel_id: str
    privacy_status: str
    package_sha256: str
    video_sha256: str
    video_bytes: int
    thumbnail_sha256: str
    thumbnail_bytes: int
    metadata_sha256: str
    request_json: str
    publication_marker: str
    media_path: Path
    thumbnail_path: Path

    @property
    def consumption_path(self) -> Path:
        return self.consumption_directory / f"{self.preview_sha256}.consumed.json"


@dataclass(slots=True)
class ClaimedYouTubeUpload:
    media: BinaryIO
    thumbnail: BinaryIO
    request_json: str
    publication_marker: str
    consumption_sha256: str

    def request_payload(self) -> dict[str, object]:
        value = json.loads(self.request_json)
        if not isinstance(value, dict):  # pragma: no cover - constructed internally
            raise YouTubeUploadControlError("claimed upload request is invalid")
        return value

    def close(self) -> None:
        self.media.close()
        self.thumbnail.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def publication_marker(package: ContentPackage) -> str:
    digest = sha256_json(package.to_dict())[:20]
    return f"REMEDIALHQ_ID={package.package_id}:{digest}"


def youtube_description(package: ContentPackage, *, maximum_length: int = 5_000) -> str:
    configured = package.metadata.get("youtube_description")
    source = str(configured) if configured else package.body
    marker = publication_marker(package)
    independence = (
        "Independent editorial coverage. Not affiliated with or endorsed by "
        "Rockstar Games or Take-Two Interactive."
    )
    suffix = f"\n\n{independence}\n{marker}"
    available = maximum_length - len(suffix)
    if available < 1:
        raise YouTubeUploadControlError(
            "publication metadata exceeds YouTube description capacity"
        )
    body = source.strip()
    if len(body) > available:
        body = body[: max(0, available - 1)].rstrip() + "…"
    return body + suffix


def build_youtube_upload_request(
    package: ContentPackage,
    privacy_status: str,
) -> dict[str, object]:
    _validate_privacy(privacy_status)
    raw_tags = package.metadata.get("tags", [])
    if not isinstance(raw_tags, list):
        raise YouTubeUploadControlError("YouTube tags must be a list")
    configured_tags = [str(item)[:500] for item in raw_tags][:499]
    marker = publication_marker(package)
    request: dict[str, object] = {
        "body": {
            "snippet": {
                "title": package.title[:100],
                "description": youtube_description(package),
                "categoryId": str(package.metadata.get("youtube_category_id", "20")),
                "tags": [*configured_tags, marker],
            },
            "status": {
                "privacyStatus": privacy_status,
                "selfDeclaredMadeForKids": False,
                "containsSyntheticMedia": bool(
                    package.metadata.get("youtube_contains_synthetic_media", True)
                ),
            },
        },
        "notifySubscribers": bool(package.metadata.get("notify_subscribers", False)),
    }
    _validate_request_metadata(request, privacy_status=privacy_status)
    return request


def create_youtube_upload_preview(
    package: ContentPackage,
    *,
    repository_root: str | Path,
    output_path: str | Path,
    media_path: str | Path,
    thumbnail_path: str | Path,
    expected_channel_id: str,
    privacy_status: str = "private",
    consumption_directory: str | Path | None = None,
    created_at: datetime | None = None,
) -> YouTubeUploadArtifact:
    """Create an immutable owner-private rendering of every upload input."""
    root = _repository_root(repository_root)
    channel_id = _validate_channel_id(expected_channel_id)
    _validate_privacy(privacy_status)
    media, media_asset = _resolve_reviewed_asset(root, package, media_path, "video")
    thumbnail, thumbnail_asset = _resolve_reviewed_asset(
        root, package, thumbnail_path, "thumbnail"
    )
    output_absolute = Path(os.path.abspath(Path(output_path).expanduser()))
    consumption_root = _prepare_private_directory(
        consumption_directory or output_absolute.parent,
        repository_root=root,
        label="YouTube upload consumption",
    )
    metadata = build_youtube_upload_request(package, privacy_status)
    payload: dict[str, object] = {
        "schema_version": YOUTUBE_UPLOAD_PREVIEW_SCHEMA,
        "created_at": _utc_timestamp(created_at),
        "status": "AWAITING_EXPRESS_CONFIRMATION",
        "target_channel": {
            "channel_id": channel_id,
            "channel_url": f"https://www.youtube.com/channel/{channel_id}",
        },
        "privacy_status": privacy_status,
        "package": {
            "package_id": package.package_id,
            "sha256": sha256_json(package.to_dict()),
        },
        "video": _asset_binding(media_asset, media),
        "thumbnail": _asset_binding(thumbnail_asset, thumbnail),
        "consumption": {"directory": str(consumption_root)},
        "metadata": metadata,
        "metadata_sha256": sha256_json(metadata),
    }
    destination, encoded = _write_private_json_create_only(
        output_path,
        payload,
        repository_root=root,
        label="YouTube upload preview",
    )
    return YouTubeUploadArtifact(
        path=destination,
        sha256=hashlib.sha256(encoded).hexdigest(),
        payload=payload,
    )


def record_youtube_upload_confirmation(
    preview_path: str | Path,
    output_path: str | Path,
    *,
    repository_root: str | Path,
    confirm_preview_sha256: str,
    confirmed_at: datetime | None = None,
) -> YouTubeUploadArtifact:
    """Record express confirmation of the exact immutable preview digest."""
    root = _repository_root(repository_root)
    if _DIGEST_RE.fullmatch(confirm_preview_sha256) is None:
        raise YouTubeUploadControlError(
            "express confirmation requires the exact lowercase preview SHA-256"
        )
    _, preview_bytes = _read_private_file(
        preview_path,
        repository_root=root,
        label="YouTube upload preview",
    )
    preview_sha256 = hashlib.sha256(preview_bytes).hexdigest()
    if preview_sha256 != confirm_preview_sha256:
        raise YouTubeUploadControlError(
            "express confirmation does not match the exact upload preview"
        )
    preview = _load_preview(preview_bytes)
    preview_consumption = _mapping(preview["consumption"], "preview consumption")
    _validate_bound_private_directory(
        preview_consumption["directory"],
        repository_root=root,
        label="YouTube upload consumption",
    )
    bindings = _preview_bindings(preview)
    payload: dict[str, object] = {
        "schema_version": YOUTUBE_UPLOAD_CONFIRMATION_SCHEMA,
        "confirmed_at": _utc_timestamp(confirmed_at),
        "status": "CONFIRMED_ONCE",
        "preview_sha256": preview_sha256,
        "bindings": bindings,
        "consent": {
            "exact_upload_reviewed": True,
            "one_time_upload_authorized": True,
        },
    }
    _validate_confirmation_time(payload["confirmed_at"], preview["created_at"])
    destination, encoded = _write_private_json_create_only(
        output_path,
        payload,
        repository_root=root,
        label="YouTube upload confirmation",
    )
    return YouTubeUploadArtifact(
        path=destination,
        sha256=hashlib.sha256(encoded).hexdigest(),
        payload=payload,
    )


def load_youtube_upload_authorization(
    package: ContentPackage,
    *,
    repository_root: str | Path,
    preview_path: str | Path,
    confirmation_path: str | Path,
    media_path: str | Path,
    thumbnail_path: str | Path,
    expected_channel_id: str,
    privacy_status: str,
) -> YouTubeUploadAuthorization:
    """Validate an unconsumed confirmation against the exact current upload."""
    root = _repository_root(repository_root)
    preview_source, preview_bytes = _read_private_file(
        preview_path,
        repository_root=root,
        label="YouTube upload preview",
    )
    confirmation_source, confirmation_bytes = _read_private_file(
        confirmation_path,
        repository_root=root,
        label="YouTube upload confirmation",
    )
    preview = _load_preview(preview_bytes)
    confirmation = _load_confirmation(confirmation_bytes)
    preview_sha256 = hashlib.sha256(preview_bytes).hexdigest()
    confirmation_sha256 = hashlib.sha256(confirmation_bytes).hexdigest()
    if confirmation["preview_sha256"] != preview_sha256:
        raise YouTubeUploadControlError(
            "YouTube upload confirmation is bound to another preview"
        )
    if confirmation["bindings"] != _preview_bindings(preview):
        raise YouTubeUploadControlError(
            "YouTube upload confirmation bindings do not match the preview"
        )
    _validate_confirmation_time(confirmation["confirmed_at"], preview["created_at"])
    consumption = _mapping(preview["consumption"], "preview consumption")
    consumption_directory = _validate_bound_private_directory(
        consumption["directory"],
        repository_root=root,
        label="YouTube upload consumption",
    )
    consumption_path = consumption_directory / f"{preview_sha256}.consumed.json"
    if consumption_path.exists():
        raise YouTubeUploadControlError(
            "YouTube upload confirmation has already been consumed"
        )

    media, media_asset = _resolve_reviewed_asset(root, package, media_path, "video")
    thumbnail, thumbnail_asset = _resolve_reviewed_asset(
        root, package, thumbnail_path, "thumbnail"
    )
    current_metadata = build_youtube_upload_request(package, privacy_status)
    expected_preview = {
        "target_channel": {
            "channel_id": _validate_channel_id(expected_channel_id),
            "channel_url": (
                "https://www.youtube.com/channel/"
                f"{_validate_channel_id(expected_channel_id)}"
            ),
        },
        "privacy_status": _validate_privacy(privacy_status),
        "package": {
            "package_id": package.package_id,
            "sha256": sha256_json(package.to_dict()),
        },
        "video": _asset_binding(media_asset, media),
        "thumbnail": _asset_binding(thumbnail_asset, thumbnail),
        "consumption": {"directory": str(consumption_directory)},
        "metadata": current_metadata,
        "metadata_sha256": sha256_json(current_metadata),
    }
    for key, expected in expected_preview.items():
        if preview[key] != expected:
            raise YouTubeUploadControlError(
                f"YouTube upload preview no longer matches the current {key}"
            )
    bindings = _preview_bindings(preview)
    video_binding = _mapping(preview["video"], "preview video")
    thumbnail_binding = _mapping(preview["thumbnail"], "preview thumbnail")
    request_json = canonical_json(_mapping(preview["metadata"], "preview metadata"))
    marker = publication_marker(package)
    return YouTubeUploadAuthorization(
        repository_root=root,
        preview_path=preview_source,
        preview_sha256=preview_sha256,
        confirmation_path=confirmation_source,
        confirmation_sha256=confirmation_sha256,
        consumption_directory=consumption_directory,
        channel_id=str(bindings["channel_id"]),
        privacy_status=str(bindings["privacy_status"]),
        package_sha256=str(bindings["package_sha256"]),
        video_sha256=str(bindings["video_sha256"]),
        video_bytes=_positive_int(video_binding["bytes"], "preview video bytes"),
        thumbnail_sha256=str(bindings["thumbnail_sha256"]),
        thumbnail_bytes=_positive_int(
            thumbnail_binding["bytes"], "preview thumbnail bytes"
        ),
        metadata_sha256=str(bindings["metadata_sha256"]),
        request_json=request_json,
        publication_marker=marker,
        media_path=media,
        thumbnail_path=thumbnail,
    )


def claim_youtube_upload_authorization(
    authorization: YouTubeUploadAuthorization,
    package: ContentPackage,
    *,
    expected_channel_id: str,
    privacy_status: str,
    claimed_at: datetime | None = None,
) -> ClaimedYouTubeUpload:
    """Pin exact bytes and atomically consume a preview-scoped confirmation."""
    current = load_youtube_upload_authorization(
        package,
        repository_root=authorization.repository_root,
        preview_path=authorization.preview_path,
        confirmation_path=authorization.confirmation_path,
        media_path=authorization.media_path,
        thumbnail_path=authorization.thumbnail_path,
        expected_channel_id=expected_channel_id,
        privacy_status=privacy_status,
    )
    if current != authorization:
        raise YouTubeUploadControlError("YouTube upload authorization changed before use")
    media = _snapshot_verified_file(
        authorization.media_path,
        expected_sha256=authorization.video_sha256,
        expected_bytes=authorization.video_bytes,
        label="YouTube upload video",
    )
    thumbnail: BinaryIO | None = None
    try:
        thumbnail = _snapshot_verified_file(
            authorization.thumbnail_path,
            expected_sha256=authorization.thumbnail_sha256,
            expected_bytes=authorization.thumbnail_bytes,
            label="YouTube upload thumbnail",
        )
        payload: dict[str, object] = {
            "schema_version": YOUTUBE_UPLOAD_CONSUMPTION_SCHEMA,
            "consumed_at": _utc_timestamp(claimed_at),
            "status": "CONSUMED",
            "preview_sha256": authorization.preview_sha256,
            "confirmation_sha256": authorization.confirmation_sha256,
            "bindings": {
                "channel_id": authorization.channel_id,
                "privacy_status": authorization.privacy_status,
                "package_sha256": authorization.package_sha256,
                "video_sha256": authorization.video_sha256,
                "thumbnail_sha256": authorization.thumbnail_sha256,
                "metadata_sha256": authorization.metadata_sha256,
                "consumption_directory": str(authorization.consumption_directory),
            },
        }
        _, encoded = _write_private_json_create_only(
            authorization.consumption_path,
            payload,
            repository_root=authorization.repository_root,
            label="YouTube upload confirmation consumption",
        )
        return ClaimedYouTubeUpload(
            media=media,
            thumbnail=thumbnail,
            request_json=authorization.request_json,
            publication_marker=authorization.publication_marker,
            consumption_sha256=hashlib.sha256(encoded).hexdigest(),
        )
    except Exception:
        media.close()
        if thumbnail is not None:
            thumbnail.close()
        raise


def _preview_bindings(preview: Mapping[str, object]) -> dict[str, object]:
    target = _mapping(preview["target_channel"], "preview target channel")
    package = _mapping(preview["package"], "preview package")
    video = _mapping(preview["video"], "preview video")
    thumbnail = _mapping(preview["thumbnail"], "preview thumbnail")
    consumption = _mapping(preview["consumption"], "preview consumption")
    return {
        "channel_id": target["channel_id"],
        "privacy_status": preview["privacy_status"],
        "package_sha256": package["sha256"],
        "video_sha256": video["sha256"],
        "thumbnail_sha256": thumbnail["sha256"],
        "metadata_sha256": preview["metadata_sha256"],
        "consumption_directory": consumption["directory"],
    }


def _load_preview(data: bytes) -> dict[str, object]:
    value = _strict_json_object(data, "YouTube upload preview")
    _require_exact_fields(
        value,
        {
            "schema_version",
            "created_at",
            "status",
            "target_channel",
            "privacy_status",
            "package",
            "video",
            "thumbnail",
            "consumption",
            "metadata",
            "metadata_sha256",
        },
        "YouTube upload preview",
    )
    if value["schema_version"] != YOUTUBE_UPLOAD_PREVIEW_SCHEMA:
        raise YouTubeUploadControlError("unsupported YouTube upload preview schema")
    if value["status"] != "AWAITING_EXPRESS_CONFIRMATION":
        raise YouTubeUploadControlError("YouTube upload preview status is invalid")
    _parse_utc_timestamp(value["created_at"], "preview created_at")
    target = _mapping(value["target_channel"], "preview target channel")
    _require_exact_fields(target, {"channel_id", "channel_url"}, "preview target channel")
    channel_id = _validate_channel_id(target["channel_id"])
    if target["channel_url"] != f"https://www.youtube.com/channel/{channel_id}":
        raise YouTubeUploadControlError("preview channel URL does not match its channel ID")
    _validate_privacy(value["privacy_status"])
    package = _mapping(value["package"], "preview package")
    _require_exact_fields(package, {"package_id", "sha256"}, "preview package")
    if not isinstance(package["package_id"], str) or not package["package_id"]:
        raise YouTubeUploadControlError("preview package ID is invalid")
    _digest(package["sha256"], "preview package SHA-256")
    for label in ("video", "thumbnail"):
        asset = _mapping(value[label], f"preview {label}")
        _require_exact_fields(
            asset,
            {"asset_id", "declared_path", "sha256", "bytes"},
            f"preview {label}",
        )
        if not isinstance(asset["asset_id"], str) or not asset["asset_id"]:
            raise YouTubeUploadControlError(f"preview {label} asset ID is invalid")
        if not isinstance(asset["declared_path"], str) or not asset["declared_path"]:
            raise YouTubeUploadControlError(f"preview {label} path is invalid")
        _digest(asset["sha256"], f"preview {label} SHA-256")
        if not isinstance(asset["bytes"], int) or isinstance(asset["bytes"], bool):
            raise YouTubeUploadControlError(f"preview {label} byte count is invalid")
        if asset["bytes"] < 1:
            raise YouTubeUploadControlError(f"preview {label} byte count is invalid")
    consumption = _mapping(value["consumption"], "preview consumption")
    _require_exact_fields(consumption, {"directory"}, "preview consumption")
    consumption_value = consumption["directory"]
    if not isinstance(consumption_value, str) or not Path(consumption_value).is_absolute():
        raise YouTubeUploadControlError("preview consumption directory is invalid")
    if str(Path(consumption_value)) != consumption_value:
        raise YouTubeUploadControlError("preview consumption directory is not canonical")
    metadata = _mapping(value["metadata"], "preview metadata")
    _validate_request_metadata(metadata, privacy_status=str(value["privacy_status"]))
    metadata_sha256 = _digest(value["metadata_sha256"], "preview metadata SHA-256")
    if metadata_sha256 != sha256_json(metadata):
        raise YouTubeUploadControlError("preview metadata SHA-256 does not match")
    return value


def _load_confirmation(data: bytes) -> dict[str, object]:
    value = _strict_json_object(data, "YouTube upload confirmation")
    _require_exact_fields(
        value,
        {
            "schema_version",
            "confirmed_at",
            "status",
            "preview_sha256",
            "bindings",
            "consent",
        },
        "YouTube upload confirmation",
    )
    if value["schema_version"] != YOUTUBE_UPLOAD_CONFIRMATION_SCHEMA:
        raise YouTubeUploadControlError("unsupported YouTube upload confirmation schema")
    if value["status"] != "CONFIRMED_ONCE":
        raise YouTubeUploadControlError("YouTube upload confirmation status is invalid")
    _parse_utc_timestamp(value["confirmed_at"], "confirmation confirmed_at")
    _digest(value["preview_sha256"], "confirmation preview SHA-256")
    bindings = _mapping(value["bindings"], "confirmation bindings")
    _require_exact_fields(
        bindings,
        {
            "channel_id",
            "privacy_status",
            "package_sha256",
            "video_sha256",
            "thumbnail_sha256",
            "metadata_sha256",
            "consumption_directory",
        },
        "confirmation bindings",
    )
    _validate_channel_id(bindings["channel_id"])
    _validate_privacy(bindings["privacy_status"])
    for key in (
        "package_sha256",
        "video_sha256",
        "thumbnail_sha256",
        "metadata_sha256",
    ):
        _digest(bindings[key], f"confirmation {key}")
    consumption_directory = bindings["consumption_directory"]
    if not isinstance(consumption_directory, str) or not Path(
        consumption_directory
    ).is_absolute():
        raise YouTubeUploadControlError(
            "confirmation consumption directory is invalid"
        )
    if str(Path(consumption_directory)) != consumption_directory:
        raise YouTubeUploadControlError(
            "confirmation consumption directory is not canonical"
        )
    consent = _mapping(value["consent"], "confirmation consent")
    _require_exact_fields(
        consent,
        {"exact_upload_reviewed", "one_time_upload_authorized"},
        "confirmation consent",
    )
    if consent != {
        "exact_upload_reviewed": True,
        "one_time_upload_authorized": True,
    }:
        raise YouTubeUploadControlError("YouTube upload confirmation is incomplete")
    return value


def _validate_request_metadata(
    metadata: Mapping[str, object], *, privacy_status: str
) -> None:
    _require_exact_fields(metadata, {"body", "notifySubscribers"}, "preview metadata")
    if not isinstance(metadata["notifySubscribers"], bool):
        raise YouTubeUploadControlError("preview notification declaration is invalid")
    body = _mapping(metadata["body"], "preview request body")
    _require_exact_fields(body, {"snippet", "status"}, "preview request body")
    snippet = _mapping(body["snippet"], "preview snippet")
    _require_exact_fields(
        snippet, {"title", "description", "categoryId", "tags"}, "preview snippet"
    )
    for key in ("title", "description", "categoryId"):
        if not isinstance(snippet[key], str) or not snippet[key]:
            raise YouTubeUploadControlError(f"preview metadata {key} is invalid")
    if len(str(snippet["title"])) > 100 or len(str(snippet["description"])) > 5_000:
        raise YouTubeUploadControlError("preview title or description exceeds YouTube limits")
    if not isinstance(snippet["tags"], list) or not all(
        isinstance(tag, str) and tag for tag in snippet["tags"]
    ):
        raise YouTubeUploadControlError("preview tags are invalid")
    status_value = _mapping(body["status"], "preview status declarations")
    _require_exact_fields(
        status_value,
        {"privacyStatus", "selfDeclaredMadeForKids", "containsSyntheticMedia"},
        "preview status declarations",
    )
    if status_value["privacyStatus"] != privacy_status:
        raise YouTubeUploadControlError("preview privacy declaration does not match")
    if status_value["selfDeclaredMadeForKids"] is not False:
        raise YouTubeUploadControlError("preview made-for-kids declaration is invalid")
    if not isinstance(status_value["containsSyntheticMedia"], bool):
        raise YouTubeUploadControlError("preview synthetic-media declaration is invalid")


def _resolve_reviewed_asset(
    root: Path,
    package: ContentPackage,
    selected_path: str | Path,
    label: str,
) -> tuple[Path, Asset]:
    candidate = Path(selected_path).expanduser()
    selected_candidate = Path(
        os.path.abspath(root / candidate if not candidate.is_absolute() else candidate)
    )
    _reject_symlink_ancestors(selected_candidate)
    if selected_candidate.is_symlink():
        raise YouTubeUploadControlError(f"selected {label} cannot be a symbolic link")
    selected = selected_candidate.resolve()
    if not selected.is_relative_to(root):
        raise YouTubeUploadControlError(f"selected {label} is outside the repository")
    matching: list[Asset] = []
    for asset in package.assets:
        declared_candidate = Path(os.path.abspath(root / asset.path))
        _reject_symlink_ancestors(declared_candidate)
        if declared_candidate.is_symlink():
            raise YouTubeUploadControlError(
                f"declared asset {asset.asset_id} cannot be a symbolic link"
            )
        declared = declared_candidate.resolve()
        if not declared.is_relative_to(root):
            raise YouTubeUploadControlError(
                f"declared asset {asset.asset_id} escapes the repository"
            )
        if declared == selected:
            matching.append(asset)
    if len(matching) != 1:
        raise YouTubeUploadControlError(
            f"selected {label} must match exactly one declared package asset"
        )
    asset = matching[0]
    if asset.sha256 is None:
        raise YouTubeUploadControlError(
            f"selected {label} asset has no reviewed SHA-256"
        )
    _digest(asset.sha256, f"selected {label} reviewed SHA-256")
    try:
        metadata = selected.lstat()
    except OSError as exc:
        raise YouTubeUploadControlError(f"selected {label} is unavailable") from exc
    if selected.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise YouTubeUploadControlError(f"selected {label} must be a regular file")
    digest = hashlib.sha256(selected.read_bytes()).hexdigest()
    if digest != asset.sha256:
        raise YouTubeUploadControlError(
            f"selected {label} does not match its reviewed SHA-256"
        )
    return selected, asset


def _asset_binding(asset: Asset, path: Path) -> dict[str, object]:
    return {
        "asset_id": asset.asset_id,
        "declared_path": asset.path,
        "sha256": asset.sha256,
        "bytes": path.stat().st_size,
    }


def _snapshot_verified_file(
    path: Path,
    *,
    expected_sha256: str,
    expected_bytes: int,
    label: str,
) -> BinaryIO:
    """Copy one verified regular file into an unlinked descriptor-backed snapshot."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise YouTubeUploadControlError(f"{label} could not be opened safely") from exc
    snapshot = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115 - caller owns snapshot
    digest = hashlib.sha256()
    byte_count = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise YouTubeUploadControlError(f"{label} must be a regular file")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
                snapshot.write(chunk)
        if byte_count != expected_bytes or digest.hexdigest() != expected_sha256:
            raise YouTubeUploadControlError(
                f"{label} changed after the exact upload preview"
            )
        snapshot.flush()
        snapshot.seek(0)
        return snapshot
    except Exception:
        snapshot.close()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _prepare_private_directory(
    path: str | Path,
    *,
    repository_root: Path,
    label: str,
) -> Path:
    directory = Path(os.path.abspath(Path(path).expanduser()))
    if directory.is_relative_to(repository_root):
        raise YouTubeUploadControlError(f"{label} directory must remain outside the repository")
    _reject_symlink_ancestors(directory)
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise YouTubeUploadControlError(f"{label} directory cannot be created") from exc
    return _validate_bound_private_directory(
        str(directory),
        repository_root=repository_root,
        label=label,
    )


def _validate_bound_private_directory(
    value: object,
    *,
    repository_root: Path,
    label: str,
) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise YouTubeUploadControlError(f"{label} directory is invalid")
    directory = Path(value)
    if str(directory) != value:
        raise YouTubeUploadControlError(f"{label} directory is not canonical")
    if directory.is_relative_to(repository_root):
        raise YouTubeUploadControlError(f"{label} directory must remain outside the repository")
    _reject_symlink_ancestors(directory)
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise YouTubeUploadControlError(f"{label} directory is unavailable") from exc
    if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise YouTubeUploadControlError(f"{label} directory must be real")
    if os.name == "posix" and metadata.st_mode & 0o777 != 0o700:
        raise YouTubeUploadControlError(f"{label} directory must use mode 0700")
    return directory


def _repository_root(value: str | Path) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_symlink():
        raise YouTubeUploadControlError("repository root must be a real directory")
    root = candidate.resolve()
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise YouTubeUploadControlError("repository root is unavailable") from exc
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise YouTubeUploadControlError("repository root must be a real directory")
    return root


def _read_private_file(
    path: str | Path,
    *,
    repository_root: Path,
    label: str,
) -> tuple[Path, bytes]:
    candidate = Path(os.path.abspath(Path(path).expanduser()))
    _reject_symlink_ancestors(candidate)
    if candidate.is_relative_to(repository_root):
        raise YouTubeUploadControlError(f"{label} must remain outside the repository")
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise YouTubeUploadControlError(f"{label} is unavailable") from exc
    if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise YouTubeUploadControlError(f"{label} must be a regular file")
    if os.name == "posix" and metadata.st_mode & 0o777 != 0o600:
        raise YouTubeUploadControlError(f"{label} must use mode 0600")
    if metadata.st_size > MAX_UPLOAD_CONTROL_BYTES:
        raise YouTubeUploadControlError(f"{label} is too large")
    try:
        data = candidate.read_bytes()
    except OSError as exc:
        raise YouTubeUploadControlError(f"{label} is unreadable") from exc
    if len(data) > MAX_UPLOAD_CONTROL_BYTES:
        raise YouTubeUploadControlError(f"{label} is too large")
    return candidate, data


def _write_private_json_create_only(
    path: str | Path,
    payload: Mapping[str, object],
    *,
    repository_root: Path,
    label: str,
) -> tuple[Path, bytes]:
    destination = Path(os.path.abspath(Path(path).expanduser()))
    if destination.is_relative_to(repository_root):
        raise YouTubeUploadControlError(f"{label} must remain outside the repository")
    _reject_symlink_ancestors(destination)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise YouTubeUploadControlError(f"{label} directory cannot be created") from exc
    _reject_symlink_ancestors(destination)
    parent_metadata = destination.parent.lstat()
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise YouTubeUploadControlError(f"{label} directory must be real")
    if os.name == "posix" and parent_metadata.st_mode & 0o777 != 0o700:
        raise YouTubeUploadControlError(f"{label} directory must use mode 0700")
    encoded = (
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_UPLOAD_CONTROL_BYTES:
        raise YouTubeUploadControlError(f"{label} is too large")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError as exc:
        raise YouTubeUploadControlError(f"{label} already exists") from exc
    except OSError as exc:
        raise YouTubeUploadControlError(f"{label} cannot be created") from exc
    completed = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix" and destination.stat().st_mode & 0o777 != 0o600:
            raise YouTubeUploadControlError(f"{label} cannot enforce mode 0600")
        completed = True
    finally:
        if not completed:
            destination.unlink(missing_ok=True)
    return destination, encoded


def _strict_json_object(data: bytes, label: str) -> dict[str, object]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise YouTubeUploadControlError(f"{label} contains a duplicate field")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=object_pairs)
    except YouTubeUploadControlError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise YouTubeUploadControlError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise YouTubeUploadControlError(f"{label} must be a JSON object")
    return value


def _reject_symlink_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise YouTubeUploadControlError(
                "owner-private upload-control path could not be inspected"
            ) from exc
        else:
            if stat.S_ISLNK(metadata.st_mode):
                raise YouTubeUploadControlError(
                    "owner-private upload-control path cannot traverse a symbolic link"
                )
        if current == current.parent:
            break
        current = current.parent


def _validate_channel_id(value: object) -> str:
    if not isinstance(value, str) or _CHANNEL_ID_RE.fullmatch(value) is None:
        raise YouTubeUploadControlError("expected channel ID is invalid")
    return value


def _validate_privacy(value: object) -> str:
    if not isinstance(value, str) or value not in _PRIVACY_STATES:
        raise YouTubeUploadControlError("YouTube privacy state is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise YouTubeUploadControlError(f"{label} is invalid")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise YouTubeUploadControlError(f"{label} is invalid")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise YouTubeUploadControlError(f"{label} must be an object")
    return value


def _require_exact_fields(
    value: Mapping[str, object], expected: set[str], label: str
) -> None:
    if set(value) != expected:
        raise YouTubeUploadControlError(f"{label} fields do not match the supported schema")


def _utc_timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise YouTubeUploadControlError("upload-control timestamp must include a timezone")
    normalized = current.astimezone(UTC).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _parse_utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise YouTubeUploadControlError(f"{label} must use UTC")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise YouTubeUploadControlError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise YouTubeUploadControlError(f"{label} must use whole UTC seconds")
    return parsed


def _validate_confirmation_time(confirmed: object, created: object) -> None:
    confirmed_at = _parse_utc_timestamp(confirmed, "confirmation confirmed_at")
    created_at = _parse_utc_timestamp(created, "preview created_at")
    if confirmed_at < created_at:
        raise YouTubeUploadControlError("confirmation predates the upload preview")
