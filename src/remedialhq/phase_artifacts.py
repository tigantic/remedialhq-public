from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, cast

from .canonical import sha256_bytes
from .idempotency import event_key
from .source_registry import validate_source_id

ARTIFACT_TYPE = "SOURCE_SNAPSHOT_SET"
MANIFEST_SCHEMA = "remedialhq.phase-artifact.v1"
REFERENCE_SCHEMA = "remedialhq.phase-artifact-ref.v1"
DEFAULT_PREFIX = "phase-artifacts/v1/collect"
MAX_FILES = 128
MAX_FILE_BYTES = 4_100_000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1_000_000
MAX_TRAVERSAL_ENTRIES = MAX_FILES * 4

SNAPSHOT_SUMMARY_FIELDS = {
    "source_id",
    "retrieved_at",
    "sha256",
    "bytes",
    "content_type",
}
SNAPSHOT_METADATA_FIELDS = {
    "source_id",
    "canonical_url",
    "status",
    "content_type",
    "etag",
    "last_modified",
    "retrieved_at",
    "rights_posture",
    "sha256",
    "bytes",
}


class ArtifactError(ValueError):
    """Base error for an invalid, unavailable, or unsafe phase artifact."""


class ArtifactConflict(ArtifactError):
    """Raised when an immutable artifact path already contains different bytes."""


class ArtifactIntegrityError(ArtifactError):
    """Raised when stored bytes fail strict manifest verification."""


class ArtifactUnavailableError(ArtifactError):
    """Raised when transient storage or filesystem access prevents a safe decision."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactIntegrityError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _invalid_constant(value: str) -> None:
    raise ArtifactIntegrityError(f"invalid JSON number: {value}")


def _decode_json(data: bytes, name: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data,
            object_pairs_hook=_strict_object,
            parse_constant=_invalid_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactIntegrityError(f"{name} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ArtifactIntegrityError(f"{name} must be a JSON object")
    return cast(dict[str, Any], value)


def _canonical(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactIntegrityError("artifact contains a non-canonical JSON value") from exc
    return text.encode("utf-8")


def _require_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ArtifactIntegrityError(f"{name} fields do not match the supported schema")


def _text(value: object, name: str, *, maximum_bytes: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum_bytes:
        raise ArtifactIntegrityError(f"{name} must contain 1 through {maximum_bytes} UTF-8 bytes")
    return value


def _digest(value: object, name: str = "sha256") -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ArtifactIntegrityError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ArtifactIntegrityError(f"{name} must be an integer of at least {minimum}")
    return value


def _cloud_generation(value: object, name: str) -> int:
    try:
        generation = int(cast(Any, value))
    except (TypeError, ValueError) as exc:
        raise ArtifactIntegrityError(f"{name} has no valid generation") from exc
    if generation < 1:
        raise ArtifactIntegrityError(f"{name} has no valid generation")
    return generation


def _source_id(value: object) -> str:
    try:
        return validate_source_id(value)
    except ValueError as exc:
        raise ArtifactIntegrityError("snapshot source_id is not canonical") from exc


def _snapshot_summaries(phase_result: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    details = phase_result.get("details")
    if not isinstance(details, dict):
        raise ArtifactIntegrityError("manifest phase_result details must be an object")
    _require_keys(
        details,
        {"mode", "source_registry_sha256", "snapshots"},
        "manifest phase_result details",
    )
    if details["mode"] != "NETWORK_SNAPSHOT":
        raise ArtifactIntegrityError("collect artifact requires NETWORK_SNAPSHOT details")
    _digest(details["source_registry_sha256"], "source_registry_sha256")
    snapshots = details["snapshots"]
    if not isinstance(snapshots, list) or not snapshots:
        raise ArtifactIntegrityError("NETWORK_SNAPSHOT details require snapshots")
    if len(snapshots) > MAX_FILES // 2:
        raise ArtifactIntegrityError("snapshot summary count exceeds the artifact limit")

    normalized: list[dict[str, Any]] = []
    for value in snapshots:
        if not isinstance(value, dict):
            raise ArtifactIntegrityError("snapshot summary must be an object")
        summary = cast(dict[str, Any], value)
        _require_keys(summary, SNAPSHOT_SUMMARY_FIELDS, "snapshot summary")
        source_id = _source_id(summary["source_id"])
        retrieved_at = _text(summary["retrieved_at"], "snapshot retrieved_at", maximum_bytes=128)
        digest = _digest(summary["sha256"], "snapshot sha256")
        size = _integer(summary["bytes"], "snapshot bytes")
        if size > MAX_FILE_BYTES:
            raise ArtifactIntegrityError("snapshot body exceeds the per-file size limit")
        content_type = _text(
            summary["content_type"],
            "snapshot content_type",
            maximum_bytes=255,
        )
        normalized.append(
            {
                "source_id": source_id,
                "retrieved_at": retrieved_at,
                "sha256": digest,
                "bytes": size,
                "content_type": content_type,
            }
        )

    source_ids = [str(item["source_id"]) for item in normalized]
    if source_ids != sorted(source_ids) or len(source_ids) != len(set(source_ids)):
        raise ArtifactIntegrityError("snapshot summaries must be sorted by unique source_id")
    if snapshots != normalized:
        raise ArtifactIntegrityError("snapshot summaries must use exact normalized values")
    return tuple(normalized)


def _relative_path(value: object) -> str:
    path_text = _text(value, "artifact file path", maximum_bytes=1024)
    if "\\" in path_text:
        raise ArtifactIntegrityError("artifact file path must use POSIX separators")
    path = PurePosixPath(path_text)
    if (
        path.is_absolute()
        or path_text != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ArtifactIntegrityError("artifact file path is not a safe normalized relative path")
    return path_text


def _prefix(value: str) -> str:
    normalized = value.strip("/")
    if not normalized or any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError("artifact prefix must be a normalized object prefix")
    return normalized


def _event_prefix(prefix: str, event_id: str) -> str:
    return f"{_prefix(prefix)}/{event_key(_text(event_id, 'event_id'))}"


def _manifest_object(prefix: str, event_id: str) -> str:
    return f"{_event_prefix(prefix, event_id)}/manifest.json"


def _file_object(prefix: str, event_id: str, digest: str) -> str:
    return f"{_event_prefix(prefix, event_id)}/files/{_digest(digest)}"


@dataclass(frozen=True, slots=True)
class PhaseArtifactFile:
    path: str
    object: str
    generation: int
    sha256: str
    bytes: int
    content_type: str

    def __post_init__(self) -> None:
        _relative_path(self.path)
        _text(self.object, "artifact object", maximum_bytes=1024)
        if self.object.startswith("/") or ".." in self.object.split("/"):
            raise ArtifactIntegrityError("artifact object is not normalized")
        _integer(self.generation, "artifact generation", minimum=1)
        _digest(self.sha256)
        _integer(self.bytes, "artifact bytes", minimum=0)
        if self.bytes > MAX_FILE_BYTES:
            raise ArtifactIntegrityError("artifact file exceeds the per-file size limit")
        _text(self.content_type, "content_type", maximum_bytes=255)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "object": self.object,
            "generation": self.generation,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "content_type": self.content_type,
        }

    @classmethod
    def from_dict(cls, value: Any) -> PhaseArtifactFile:
        if not isinstance(value, dict):
            raise ArtifactIntegrityError("artifact file entry must be an object")
        typed = cast(dict[str, Any], value)
        _require_keys(
            typed,
            {"path", "object", "generation", "sha256", "bytes", "content_type"},
            "artifact file entry",
        )
        return cls(
            path=typed["path"],
            object=typed["object"],
            generation=typed["generation"],
            sha256=typed["sha256"],
            bytes=typed["bytes"],
            content_type=typed["content_type"],
        )


def _validate_manifest_file_coherence(
    files: tuple[PhaseArtifactFile, ...],
    snapshots: tuple[dict[str, Any], ...],
) -> None:
    by_path = {entry.path: entry for entry in files}
    expected_paths: set[str] = set()
    for summary in snapshots:
        source_id = str(summary["source_id"])
        digest = str(summary["sha256"])
        directory = PurePosixPath(source_id, digest)
        metadata_path = (directory / "metadata.json").as_posix()
        metadata = by_path.get(metadata_path)
        if metadata is None or metadata.content_type != "application/json":
            raise ArtifactIntegrityError(
                "each snapshot must contain one JSON metadata manifest entry"
            )
        candidates = [
            entry
            for entry in files
            if PurePosixPath(entry.path).parent == directory
            and PurePosixPath(entry.path).name != "metadata.json"
        ]
        if len(candidates) != 1:
            raise ArtifactIntegrityError("each snapshot must contain exactly one body entry")
        body = candidates[0]
        body_name = PurePosixPath(body.path).name
        if not body_name.startswith("body.") or body_name == "body.":
            raise ArtifactIntegrityError("snapshot body entry must use a body.* filename")
        if (
            body.sha256 != summary["sha256"]
            or body.bytes != summary["bytes"]
            or body.content_type != summary["content_type"]
        ):
            raise ArtifactIntegrityError("snapshot body entry does not match its summary")
        expected_paths.update({metadata_path, body.path})
    if set(by_path) != expected_paths:
        raise ArtifactIntegrityError("artifact files do not exactly match snapshot summaries")


@dataclass(frozen=True, slots=True)
class PhaseArtifactManifest:
    event_id: str
    root_event_id: str
    created_at: str
    phase_result: dict[str, Any]
    files: tuple[PhaseArtifactFile, ...]
    parent_manifest_sha256: str | None = None
    schema_version: str = MANIFEST_SCHEMA
    artifact_type: str = ARTIFACT_TYPE
    phase: str = "collect"

    def __post_init__(self) -> None:
        if self.schema_version != MANIFEST_SCHEMA or self.artifact_type != ARTIFACT_TYPE:
            raise ArtifactIntegrityError("phase artifact manifest schema or type is unsupported")
        if self.phase != "collect":
            raise ArtifactIntegrityError("source snapshot artifacts must come from collect")
        _text(self.event_id, "event_id")
        _text(self.root_event_id, "root_event_id")
        if self.event_id != self.root_event_id:
            raise ArtifactIntegrityError("collect artifact must start its own root event")
        _text(self.created_at, "created_at", maximum_bytes=128)
        if self.parent_manifest_sha256 is not None:
            raise ArtifactIntegrityError(
                "collect snapshot artifacts cannot name a parent manifest"
            )
        if not isinstance(self.phase_result, dict):
            raise ArtifactIntegrityError("phase_result must be an object")
        _require_keys(
            self.phase_result,
            {"phase", "status", "occurred_at", "details"},
            "phase_result",
        )
        if (
            self.phase_result["phase"] != "collect"
            or self.phase_result["status"] != "PASS"
            or self.phase_result["occurred_at"] != self.created_at
            or not isinstance(self.phase_result["details"], dict)
        ):
            raise ArtifactIntegrityError("manifest phase_result is not a matching collect PASS")
        snapshots = _snapshot_summaries(self.phase_result)
        if not self.files or len(self.files) > MAX_FILES:
            raise ArtifactIntegrityError("artifact must contain a bounded nonempty file set")
        paths = [entry.path for entry in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ArtifactIntegrityError("artifact file paths must be sorted and unique")
        if sum(entry.bytes for entry in self.files) > MAX_TOTAL_BYTES:
            raise ArtifactIntegrityError("artifact exceeds the total file size limit")
        _validate_manifest_file_coherence(self.files, snapshots)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "phase": self.phase,
            "event_id": self.event_id,
            "root_event_id": self.root_event_id,
            "created_at": self.created_at,
            "parent_manifest_sha256": self.parent_manifest_sha256,
            "phase_result": self.phase_result,
            "files": [entry.to_dict() for entry in self.files],
        }

    @classmethod
    def from_bytes(cls, data: bytes) -> PhaseArtifactManifest:
        if not data or len(data) > MAX_MANIFEST_BYTES:
            raise ArtifactIntegrityError("artifact manifest is empty or oversized")
        value = _decode_json(data, "artifact manifest")
        _require_keys(
            value,
            {
                "schema_version",
                "artifact_type",
                "phase",
                "event_id",
                "root_event_id",
                "created_at",
                "parent_manifest_sha256",
                "phase_result",
                "files",
            },
            "artifact manifest",
        )
        files_value = value["files"]
        if not isinstance(files_value, list):
            raise ArtifactIntegrityError("artifact files must be an array")
        manifest = cls(
            schema_version=value["schema_version"],
            artifact_type=value["artifact_type"],
            phase=value["phase"],
            event_id=value["event_id"],
            root_event_id=value["root_event_id"],
            created_at=value["created_at"],
            parent_manifest_sha256=value["parent_manifest_sha256"],
            phase_result=value["phase_result"],
            files=tuple(PhaseArtifactFile.from_dict(entry) for entry in files_value),
        )
        if data != manifest.to_bytes():
            raise ArtifactIntegrityError("artifact manifest is not canonical JSON")
        return manifest

    def to_bytes(self) -> bytes:
        data = _canonical(self.to_dict())
        if not data or len(data) > MAX_MANIFEST_BYTES:
            raise ArtifactIntegrityError("artifact manifest is empty or oversized")
        return data


@dataclass(frozen=True, slots=True)
class PhaseArtifactRef:
    bucket: str
    manifest_object: str
    manifest_generation: int
    manifest_sha256: str
    manifest_bytes: int
    event_id: str
    root_event_id: str
    schema_version: str = REFERENCE_SCHEMA
    artifact_type: str = ARTIFACT_TYPE
    phase: str = "collect"

    def __post_init__(self) -> None:
        if self.schema_version != REFERENCE_SCHEMA or self.artifact_type != ARTIFACT_TYPE:
            raise ArtifactIntegrityError("phase artifact reference schema or type is unsupported")
        if self.phase != "collect":
            raise ArtifactIntegrityError("source snapshot reference must come from collect")
        _text(self.bucket, "artifact bucket", maximum_bytes=255)
        _text(self.manifest_object, "manifest_object", maximum_bytes=1024)
        if self.manifest_object.startswith("/") or ".." in self.manifest_object.split("/"):
            raise ArtifactIntegrityError("manifest_object is not normalized")
        _integer(self.manifest_generation, "manifest_generation", minimum=1)
        _digest(self.manifest_sha256, "manifest_sha256")
        _integer(self.manifest_bytes, "manifest_bytes", minimum=1)
        if self.manifest_bytes > MAX_MANIFEST_BYTES:
            raise ArtifactIntegrityError("artifact manifest reference is oversized")
        _text(self.event_id, "event_id")
        _text(self.root_event_id, "root_event_id")
        if self.event_id != self.root_event_id:
            raise ArtifactIntegrityError("collect reference must start its own root event")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "phase": self.phase,
            "event_id": self.event_id,
            "root_event_id": self.root_event_id,
            "bucket": self.bucket,
            "manifest_object": self.manifest_object,
            "manifest_generation": self.manifest_generation,
            "manifest_sha256": self.manifest_sha256,
            "manifest_bytes": self.manifest_bytes,
        }

    @classmethod
    def from_dict(cls, value: object) -> PhaseArtifactRef:
        if not isinstance(value, dict):
            raise ArtifactIntegrityError("phase artifact reference must be an object")
        typed = cast(dict[str, Any], value)
        _require_keys(
            typed,
            {
                "schema_version",
                "artifact_type",
                "phase",
                "event_id",
                "root_event_id",
                "bucket",
                "manifest_object",
                "manifest_generation",
                "manifest_sha256",
                "manifest_bytes",
            },
            "phase artifact reference",
        )
        return cls(
            schema_version=typed["schema_version"],
            artifact_type=typed["artifact_type"],
            phase=typed["phase"],
            event_id=typed["event_id"],
            root_event_id=typed["root_event_id"],
            bucket=typed["bucket"],
            manifest_object=typed["manifest_object"],
            manifest_generation=typed["manifest_generation"],
            manifest_sha256=typed["manifest_sha256"],
            manifest_bytes=typed["manifest_bytes"],
        )


class PhaseArtifactStore(Protocol):
    def commit(
        self,
        event_id: str,
        root_event_id: str,
        source: Path,
        phase_result: dict[str, Any],
    ) -> PhaseArtifactRef: ...

    def find(self, event_id: str, root_event_id: str) -> PhaseArtifactRef | None: ...

    def read_manifest(self, reference: PhaseArtifactRef) -> PhaseArtifactManifest: ...

    def materialize(self, reference: PhaseArtifactRef, destination: Path) -> PhaseArtifactManifest: ...


def _absolute_path(path: str | Path) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(path)))
    except OSError as exc:
        raise ArtifactUnavailableError("artifact path could not be resolved") from exc
    except (TypeError, ValueError) as exc:
        raise ArtifactIntegrityError("artifact path is invalid") from exc


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _directory_components(path: Path) -> list[Path]:
    absolute = _absolute_path(path)
    anchor = Path(absolute.anchor)
    components = [anchor]
    current = anchor
    for part in absolute.parts[1:]:
        current /= part
        components.append(current)
    return components


def _ensure_real_directory(path: str | Path, name: str) -> Path:
    absolute = _absolute_path(path)
    for component in _directory_components(absolute):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            try:
                component.mkdir(mode=0o750)
                metadata = component.lstat()
            except OSError as exc:
                raise ArtifactUnavailableError(f"{name} could not be created safely") from exc
        except OSError as exc:
            raise ArtifactUnavailableError(f"{name} could not be inspected safely") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ArtifactIntegrityError(f"{name} must not use symbolic-link directories")
    return absolute


def _existing_real_directory(path: str | Path, name: str) -> Path:
    absolute = _absolute_path(path)
    for component in _directory_components(absolute):
        try:
            metadata = component.lstat()
        except OSError as exc:
            raise ArtifactUnavailableError(f"{name} could not be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ArtifactIntegrityError(f"{name} must be a real directory")
    return absolute


def _reject_symlink_ancestors(path: Path, name: str) -> None:
    for ancestor in reversed(_absolute_path(path).parents):
        try:
            metadata = ancestor.lstat()
        except OSError as exc:
            raise ArtifactUnavailableError(f"{name} path ancestors are unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ArtifactIntegrityError(f"{name} path ancestors must be real directories")


def _read_descriptor_bounded(descriptor: int, maximum: int, name: str) -> bytes:
    chunks: list[bytes] = []
    bytes_read = 0
    while bytes_read <= maximum:
        try:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - bytes_read))
        except OSError as exc:
            raise ArtifactUnavailableError(f"{name} could not be read") from exc
        if not chunk:
            break
        chunks.append(chunk)
        bytes_read += len(chunk)
    if bytes_read > maximum:
        raise ArtifactIntegrityError(f"{name} exceeds its size limit")
    return b"".join(chunks)


def read_bounded_regular_file(
    path: str | Path,
    *,
    maximum: int,
    name: str = "file",
) -> bytes:
    """Read one stable regular file without following symbolic links."""
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
        raise ValueError("maximum must be a nonnegative integer")
    path_value = _absolute_path(path)
    _reject_symlink_ancestors(path_value, name)
    try:
        before = path_value.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ArtifactUnavailableError(f"{name} could not be inspected") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > maximum
    ):
        raise ArtifactIntegrityError(f"{name} must be a bounded regular non-symlink file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path_value, flags)
    except OSError as exc:
        raise ArtifactUnavailableError(f"{name} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _file_snapshot(opened) != _file_snapshot(before):
            raise ArtifactIntegrityError(f"{name} changed before it was opened")
        data = _read_descriptor_bounded(descriptor, maximum, name)
        after = os.fstat(descriptor)
        try:
            current = path_value.lstat()
        except OSError as exc:
            raise ArtifactIntegrityError(f"{name} changed during its bounded read") from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or _file_snapshot(opened) != _file_snapshot(after)
            or _file_snapshot(after) != _file_snapshot(current)
            or len(data) != after.st_size
        ):
            raise ArtifactIntegrityError(f"{name} changed during its bounded read")
        return data
    finally:
        os.close(descriptor)


def _walk_source_files(source: Path) -> dict[str, bytes]:
    root = _existing_real_directory(source, "artifact source")
    pending = [root]
    discovered: dict[str, bytes] = {}
    entries_seen = 0
    total_bytes = 0
    while pending:
        directory = _existing_real_directory(pending.pop(), "artifact source directory")
        try:
            with os.scandir(directory) as iterator:
                names: list[str] = []
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > MAX_TRAVERSAL_ENTRIES:
                        raise ArtifactIntegrityError("artifact source traversal exceeds its limit")
                    names.append(entry.name)
        except ArtifactIntegrityError:
            raise
        except OSError as exc:
            raise ArtifactUnavailableError(
                "artifact source could not be traversed safely"
            ) from exc
        for name in sorted(names, reverse=True):
            path = directory / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise ArtifactUnavailableError(
                    "artifact source entry could not be inspected"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise ArtifactIntegrityError("artifact source cannot contain symbolic links")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ArtifactIntegrityError("artifact source can contain only files and directories")
            if len(discovered) >= MAX_FILES:
                raise ArtifactIntegrityError("artifact source file count exceeds its limit")
            relative = _relative_path(path.relative_to(root).as_posix())
            remaining = MAX_TOTAL_BYTES - total_bytes
            data = read_bounded_regular_file(
                path,
                maximum=min(MAX_FILE_BYTES, remaining),
                name="artifact source file",
            )
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ArtifactIntegrityError("artifact source exceeds the total size limit")
            discovered[relative] = data
    if not discovered:
        raise ArtifactIntegrityError("artifact source must contain files")
    return discovered


def _validate_snapshot_payloads(
    phase_result: dict[str, Any],
    payloads: dict[str, bytes],
) -> dict[str, str]:
    snapshots = _snapshot_summaries(phase_result)
    content_types: dict[str, str] = {}
    expected_paths: set[str] = set()
    for summary in snapshots:
        source_id = str(summary["source_id"])
        digest = str(summary["sha256"])
        directory = PurePosixPath(source_id, digest)
        metadata_path = (directory / "metadata.json").as_posix()
        matching = [
            path for path in payloads if PurePosixPath(path).parent == directory
        ]
        body_paths = [path for path in matching if PurePosixPath(path).name != "metadata.json"]
        if len(matching) != 2 or len(body_paths) != 1:
            raise ArtifactIntegrityError(
                "snapshot payload must contain exactly one metadata and one body file"
            )
        body_path = body_paths[0]
        body_name = PurePosixPath(body_path).name
        if metadata_path not in payloads or not body_name.startswith("body.") or body_name == "body.":
            raise ArtifactIntegrityError("snapshot payload paths do not match their summary")
        metadata = _decode_json(payloads[metadata_path], "snapshot metadata")
        _require_keys(metadata, SNAPSHOT_METADATA_FIELDS, "snapshot metadata")
        metadata_size = _integer(metadata["bytes"], "snapshot metadata bytes")
        metadata_status = _integer(metadata["status"], "snapshot metadata status")
        if (
            metadata["source_id"] != source_id
            or metadata["retrieved_at"] != summary["retrieved_at"]
            or metadata["sha256"] != digest
            or metadata_size != summary["bytes"]
            or metadata["content_type"] != summary["content_type"]
        ):
            raise ArtifactIntegrityError("snapshot metadata does not match its summary")
        if (
            not isinstance(metadata["canonical_url"], str)
            or not metadata["canonical_url"]
            or metadata_status != 200
            or not isinstance(metadata["rights_posture"], str)
            or not metadata["rights_posture"]
            or metadata["etag"] is not None
            and not isinstance(metadata["etag"], str)
            or metadata["last_modified"] is not None
            and not isinstance(metadata["last_modified"], str)
        ):
            raise ArtifactIntegrityError("snapshot metadata types are invalid")
        body = payloads[body_path]
        if len(body) != summary["bytes"] or sha256_bytes(body) != digest:
            raise ArtifactIntegrityError("snapshot body does not match its summary")
        content_types[metadata_path] = "application/json"
        content_types[body_path] = str(summary["content_type"])
        expected_paths.update({metadata_path, body_path})
    if set(payloads) != expected_paths:
        raise ArtifactIntegrityError("artifact source contains files outside the snapshot summaries")
    return content_types


def _source_files(
    source: Path,
    phase_result: dict[str, Any],
) -> list[tuple[str, bytes, str]]:
    payloads = _walk_source_files(source)
    content_types = _validate_snapshot_payloads(phase_result, payloads)
    return [
        (path, payloads[path], content_types[path])
        for path in sorted(payloads)
    ]


def _validate_reference(
    reference: PhaseArtifactRef,
    *,
    bucket: str,
    prefix: str,
) -> None:
    if reference.bucket != bucket:
        raise ArtifactIntegrityError("artifact reference names a different configured bucket")
    if reference.manifest_object != _manifest_object(prefix, reference.event_id):
        raise ArtifactIntegrityError("manifest object does not match its event identity")


def _validate_manifest(reference: PhaseArtifactRef, data: bytes) -> PhaseArtifactManifest:
    if len(data) != reference.manifest_bytes or sha256_bytes(data) != reference.manifest_sha256:
        raise ArtifactIntegrityError("manifest bytes do not match their immutable reference")
    manifest = PhaseArtifactManifest.from_bytes(data)
    if manifest.event_id != reference.event_id or manifest.root_event_id != reference.root_event_id:
        raise ArtifactIntegrityError("manifest lineage does not match its reference")
    return manifest


def _write_exclusive(path: Path, data: bytes) -> None:
    path = _absolute_path(path)
    parent = _ensure_real_directory(path.parent, "artifact object parent")
    temporary = parent / f".{path.name}.tmp-{secrets.token_hex(16)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(temporary, flags, 0o640)
    except OSError as exc:
        raise ArtifactUnavailableError(
            "artifact temporary object could not be created"
        ) from exc
    published = False
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise ArtifactUnavailableError(
                    "artifact temporary object write did not progress"
                )
            offset += written
        os.fsync(descriptor)
        temporary_metadata = os.fstat(descriptor)
        try:
            os.link(temporary, path, follow_symlinks=False)
            published = True
        except FileExistsError:
            existing = read_bounded_regular_file(
                path,
                maximum=max(MAX_FILE_BYTES, MAX_MANIFEST_BYTES),
                name="existing artifact object",
            )
            if existing != data:
                raise ArtifactConflict(
                    "immutable artifact object already contains different bytes"
                )
            return
        except OSError as exc:
            raise ArtifactUnavailableError(
                "artifact object could not be published atomically"
            ) from exc
        published_metadata = path.lstat()
        if (
            not stat.S_ISREG(published_metadata.st_mode)
            or _file_identity(published_metadata) != _file_identity(temporary_metadata)
        ):
            if (
                published_metadata.st_dev,
                published_metadata.st_ino,
            ) == (temporary_metadata.st_dev, temporary_metadata.st_ino):
                try:
                    path.unlink()
                except OSError:
                    pass
            raise ArtifactIntegrityError("published artifact object changed during handoff")
        try:
            parent_descriptor = os.open(
                parent,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            raise ArtifactUnavailableError(
                "artifact parent could not be synchronized"
            ) from exc
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            if not published:
                raise ArtifactUnavailableError(
                    "artifact temporary object could not be removed"
                ) from exc


def _require_absent(path: Path, name: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ArtifactUnavailableError(f"{name} could not be inspected safely") from exc
    raise ArtifactIntegrityError(f"{name} must not already exist")


def _new_staging_directory(destination: Path) -> Path:
    parent = _ensure_real_directory(destination.parent, "artifact destination parent")
    for _attempt in range(16):
        staging = parent / f".{destination.name}.tmp-{secrets.token_hex(16)}"
        try:
            staging.mkdir(mode=0o750)
            return staging
        except FileExistsError:
            continue
        except OSError as exc:
            raise ArtifactUnavailableError(
                "artifact staging directory could not be created"
            ) from exc
    raise ArtifactUnavailableError("artifact staging directory name could not be reserved")


def _remove_staging_directory(staging: Path) -> None:
    try:
        metadata = staging.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ArtifactUnavailableError(
            "artifact staging directory could not be inspected"
        ) from exc
    try:
        if stat.S_ISLNK(metadata.st_mode):
            staging.unlink()
        elif stat.S_ISDIR(metadata.st_mode):
            shutil.rmtree(staging)
        else:
            staging.unlink()
    except OSError as exc:
        raise ArtifactUnavailableError("artifact staging directory could not be removed") from exc


def _publish_staging_directory(staging: Path, destination: Path) -> None:
    _require_absent(destination, "artifact destination")
    try:
        os.rename(staging, destination)
    except FileExistsError as exc:
        raise ArtifactIntegrityError("artifact destination appeared during handoff") from exc
    except OSError as exc:
        raise ArtifactUnavailableError(
            "artifact destination could not be published atomically"
        ) from exc


def _materialize_atomically(
    manifest: PhaseArtifactManifest,
    destination: Path,
    read_entry: Callable[[PhaseArtifactFile], bytes],
) -> None:
    destination = _absolute_path(destination)
    _require_absent(destination, "artifact destination")
    staging = _new_staging_directory(destination)
    published = False
    try:
        payloads: dict[str, bytes] = {}
        total_bytes = 0
        for entry in manifest.files:
            data = read_entry(entry)
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ArtifactIntegrityError("materialized artifact exceeds its total size limit")
            if len(data) != entry.bytes or sha256_bytes(data) != entry.sha256:
                raise ArtifactIntegrityError("artifact file bytes do not match the manifest")
            payloads[entry.path] = data
            _write_exclusive(
                staging.joinpath(*PurePosixPath(entry.path).parts),
                data,
            )
        _validate_snapshot_payloads(manifest.phase_result, payloads)
        _publish_staging_directory(staging, destination)
        published = True
    finally:
        if not published:
            _remove_staging_directory(staging)


class LocalPhaseArtifactStore:
    """Create-only local artifact store used for tests and single-host development."""

    def __init__(self, root: str | Path, *, prefix: str = DEFAULT_PREFIX) -> None:
        self.root = _ensure_real_directory(root, "local artifact root")
        self.prefix = _prefix(prefix)
        self.bucket = f"local-{sha256_bytes(str(self.root).encode('utf-8'))[:32]}"

    def _path(self, object_name: str) -> Path:
        if "\\" in object_name:
            raise ArtifactIntegrityError("local artifact object must use POSIX separators")
        relative = PurePosixPath(object_name)
        if (
            relative.is_absolute()
            or object_name != relative.as_posix()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ArtifactIntegrityError("local artifact object is not a safe relative path")
        _existing_real_directory(self.root, "local artifact root")
        path = self.root.joinpath(*relative.parts)
        return path

    def _read(self, object_name: str, *, maximum: int) -> bytes:
        path = self._path(object_name)
        return read_bounded_regular_file(
            path,
            maximum=maximum,
            name="artifact object",
        )

    def commit(
        self,
        event_id: str,
        root_event_id: str,
        source: Path,
        phase_result: dict[str, Any],
    ) -> PhaseArtifactRef:
        event_id = _text(event_id, "event_id")
        root_event_id = _text(root_event_id, "root_event_id")
        entries: list[PhaseArtifactFile] = []
        for relative, data, content_type in _source_files(source, phase_result):
            digest = sha256_bytes(data)
            object_name = _file_object(self.prefix, event_id, digest)
            _write_exclusive(self._path(object_name), data)
            entries.append(
                PhaseArtifactFile(relative, object_name, 1, digest, len(data), content_type)
            )
        manifest = PhaseArtifactManifest(
            event_id=event_id,
            root_event_id=root_event_id,
            created_at=_text(
                phase_result.get("occurred_at"),
                "phase_result occurred_at",
                maximum_bytes=128,
            ),
            phase_result=phase_result,
            files=tuple(sorted(entries, key=lambda entry: entry.path)),
        )
        data = manifest.to_bytes()
        object_name = _manifest_object(self.prefix, event_id)
        _write_exclusive(self._path(object_name), data)
        return PhaseArtifactRef(
            bucket=self.bucket,
            manifest_object=object_name,
            manifest_generation=1,
            manifest_sha256=sha256_bytes(data),
            manifest_bytes=len(data),
            event_id=event_id,
            root_event_id=root_event_id,
        )

    def find(self, event_id: str, root_event_id: str) -> PhaseArtifactRef | None:
        object_name = _manifest_object(self.prefix, event_id)
        try:
            data = self._read(object_name, maximum=MAX_MANIFEST_BYTES)
        except FileNotFoundError:
            return None
        manifest = PhaseArtifactManifest.from_bytes(data)
        if manifest.event_id != event_id or manifest.root_event_id != root_event_id:
            raise ArtifactIntegrityError("committed manifest belongs to a different event chain")
        return PhaseArtifactRef(
            bucket=self.bucket,
            manifest_object=object_name,
            manifest_generation=1,
            manifest_sha256=sha256_bytes(data),
            manifest_bytes=len(data),
            event_id=event_id,
            root_event_id=root_event_id,
        )

    def read_manifest(self, reference: PhaseArtifactRef) -> PhaseArtifactManifest:
        _validate_reference(reference, bucket=self.bucket, prefix=self.prefix)
        if reference.manifest_generation != 1:
            raise ArtifactIntegrityError("local artifact generation must be 1")
        try:
            data = self._read(reference.manifest_object, maximum=MAX_MANIFEST_BYTES)
        except FileNotFoundError as exc:
            raise ArtifactIntegrityError(
                "generation-pinned local manifest is unavailable"
            ) from exc
        return _validate_manifest(reference, data)

    def materialize(self, reference: PhaseArtifactRef, destination: Path) -> PhaseArtifactManifest:
        manifest = self.read_manifest(reference)

        def read_entry(entry: PhaseArtifactFile) -> bytes:
            expected = _file_object(self.prefix, reference.event_id, entry.sha256)
            if entry.object != expected or entry.generation != 1:
                raise ArtifactIntegrityError("artifact file object does not match its digest")
            try:
                return self._read(entry.object, maximum=MAX_FILE_BYTES)
            except FileNotFoundError as exc:
                raise ArtifactIntegrityError(
                    "generation-pinned local artifact file is unavailable"
                ) from exc

        _materialize_atomically(manifest, destination, read_entry)
        return manifest


class GCSPhaseArtifactStore:
    """Generation-pinned, create-only source snapshot artifacts in Cloud Storage."""

    def __init__(self, bucket_name: str, *, prefix: str = DEFAULT_PREFIX) -> None:
        if not bucket_name or "/" in bucket_name:
            raise ValueError("artifact bucket name is invalid")
        try:
            from google.cloud.storage import Client
        except ImportError as exc:  # pragma: no cover - cloud-only dependency
            raise RuntimeError("google-cloud-storage is required for GCS artifacts") from exc
        self.bucket = Client().bucket(bucket_name)
        self.bucket_name = bucket_name
        self.prefix = _prefix(prefix)

    def _create(self, object_name: str, data: bytes, content_type: str) -> int:
        try:
            from google.api_core.exceptions import NotFound, PreconditionFailed
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("google-api-core is required for GCS artifacts") from exc
        blob = self.bucket.blob(object_name)
        try:
            blob.upload_from_string(
                data,
                content_type=content_type,
                if_generation_match=0,
            )
            if blob.generation is None:
                try:
                    blob.reload()
                except NotFound as exc:
                    raise ArtifactUnavailableError(
                        "created GCS artifact disappeared before generation recovery"
                    ) from exc
            return _cloud_generation(blob.generation, "created GCS artifact")
        except PreconditionFailed:
            try:
                blob.reload()
                generation = _cloud_generation(blob.generation, "existing GCS artifact")
                existing = blob.download_as_bytes(if_generation_match=generation)
            except NotFound as exc:
                raise ArtifactUnavailableError(
                    "existing GCS artifact disappeared during conflict recovery"
                ) from exc
            if existing != data:
                raise ArtifactConflict("immutable GCS artifact already contains different bytes")
            return generation

    def _read_generation(self, object_name: str, generation: int) -> bytes:
        try:
            from google.api_core.exceptions import NotFound, PreconditionFailed
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("google-api-core is required for GCS artifacts") from exc
        blob = self.bucket.blob(object_name, generation=generation)
        try:
            return cast(
                bytes,
                blob.download_as_bytes(if_generation_match=generation),
            )
        except (NotFound, PreconditionFailed) as exc:
            raise ArtifactIntegrityError(
                "generation-pinned GCS artifact is unavailable or changed"
            ) from exc

    def commit(
        self,
        event_id: str,
        root_event_id: str,
        source: Path,
        phase_result: dict[str, Any],
    ) -> PhaseArtifactRef:
        event_id = _text(event_id, "event_id")
        root_event_id = _text(root_event_id, "root_event_id")
        entries: list[PhaseArtifactFile] = []
        for relative, data, content_type in _source_files(source, phase_result):
            digest = sha256_bytes(data)
            object_name = _file_object(self.prefix, event_id, digest)
            generation = self._create(object_name, data, content_type)
            entries.append(
                PhaseArtifactFile(
                    relative,
                    object_name,
                    generation,
                    digest,
                    len(data),
                    content_type,
                )
            )
        manifest = PhaseArtifactManifest(
            event_id=event_id,
            root_event_id=root_event_id,
            created_at=_text(
                phase_result.get("occurred_at"),
                "phase_result occurred_at",
                maximum_bytes=128,
            ),
            phase_result=phase_result,
            files=tuple(sorted(entries, key=lambda entry: entry.path)),
        )
        data = manifest.to_bytes()
        object_name = _manifest_object(self.prefix, event_id)
        generation = self._create(object_name, data, "application/json")
        return PhaseArtifactRef(
            bucket=self.bucket_name,
            manifest_object=object_name,
            manifest_generation=generation,
            manifest_sha256=sha256_bytes(data),
            manifest_bytes=len(data),
            event_id=event_id,
            root_event_id=root_event_id,
        )

    def find(self, event_id: str, root_event_id: str) -> PhaseArtifactRef | None:
        try:
            from google.api_core.exceptions import NotFound, PreconditionFailed
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("google-api-core is required for GCS artifacts") from exc
        object_name = _manifest_object(self.prefix, event_id)
        blob = self.bucket.blob(object_name)
        try:
            blob.reload()
        except NotFound:
            return None
        try:
            generation = _cloud_generation(blob.generation, "observed GCS manifest")
            data = blob.download_as_bytes(if_generation_match=generation)
        except (NotFound, PreconditionFailed) as exc:
            raise ArtifactIntegrityError(
                "GCS manifest changed after its generation was observed"
            ) from exc
        manifest = PhaseArtifactManifest.from_bytes(data)
        if manifest.event_id != event_id or manifest.root_event_id != root_event_id:
            raise ArtifactIntegrityError("committed manifest belongs to a different event chain")
        return PhaseArtifactRef(
            bucket=self.bucket_name,
            manifest_object=object_name,
            manifest_generation=generation,
            manifest_sha256=sha256_bytes(data),
            manifest_bytes=len(data),
            event_id=event_id,
            root_event_id=root_event_id,
        )

    def read_manifest(self, reference: PhaseArtifactRef) -> PhaseArtifactManifest:
        _validate_reference(reference, bucket=self.bucket_name, prefix=self.prefix)
        data = self._read_generation(
            reference.manifest_object,
            reference.manifest_generation,
        )
        return _validate_manifest(reference, data)

    def materialize(self, reference: PhaseArtifactRef, destination: Path) -> PhaseArtifactManifest:
        manifest = self.read_manifest(reference)

        def read_entry(entry: PhaseArtifactFile) -> bytes:
            expected = _file_object(self.prefix, reference.event_id, entry.sha256)
            if entry.object != expected:
                raise ArtifactIntegrityError("artifact file object does not match its digest")
            return self._read_generation(entry.object, entry.generation)

        _materialize_atomically(manifest, destination, read_entry)
        return manifest
