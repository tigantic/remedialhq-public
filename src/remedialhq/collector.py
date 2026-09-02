from __future__ import annotations

import json
import mimetypes
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from .canonical import sha256_bytes
from .source_registry import SourceSpec, validate_source_id


class CollectionError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise CollectionError(f"redirect blocked ({code}) to {newurl}")


@dataclass(frozen=True, slots=True)
class Snapshot:
    source_id: str
    retrieved_at: str
    sha256: str
    bytes: int
    content_type: str
    body_path: str
    metadata_path: str

    def to_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "retrieved_at": self.retrieved_at,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "content_type": self.content_type,
            "body_path": self.body_path,
            "metadata_path": self.metadata_path,
        }

    def to_portable_dict(self) -> dict[str, object]:
        """Return immutable snapshot facts without instance-local filesystem paths."""
        return {
            "source_id": self.source_id,
            "retrieved_at": self.retrieved_at,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "content_type": self.content_type,
        }


class TextSnapshotCollector:
    ALLOWED_TYPES: ClassVar[set[str]] = {
        "text/html",
        "text/plain",
        "application/json",
        "application/ld+json",
        "application/xml",
        "text/xml",
    }

    def __init__(self, output_dir: str | Path, *, max_bytes: int = 4_000_000) -> None:
        self.output_dir = Path(output_dir)
        self.max_bytes = max_bytes
        self._opener = urllib.request.build_opener(_NoRedirect)

    def collect(self, source: SourceSpec) -> Snapshot:
        source_id = validate_source_id(source.source_id)
        if not source.allowed:
            raise PermissionError(source_id)
        request = urllib.request.Request(
            source.url,
            headers={
                "User-Agent": "ReMediaLHQBot/0.2 (+independent editorial source monitor)",
                "Accept": "text/html,application/json,application/xml,text/plain;q=0.9,*/*;q=0.1",
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                content_type = response.headers.get_content_type().casefold()
                if content_type not in self.ALLOWED_TYPES:
                    raise CollectionError(f"unsupported content type: {content_type}")
                declared = response.headers.get("Content-Length")
                if declared and int(declared) > self.max_bytes:
                    raise CollectionError("declared body exceeds collection limit")
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise CollectionError("body exceeds collection limit")
                metadata = {
                    "source_id": source.source_id,
                    "canonical_url": source.url,
                    "status": int(response.status),
                    "content_type": content_type,
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                    "retrieved_at": datetime.now(UTC).isoformat(),
                    "rights_posture": source.asset_rights,
                }
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise CollectionError(f"collection failed for {source_id}: {exc}") from exc

        digest = sha256_bytes(body)
        suffix = mimetypes.guess_extension(content_type) or ".bin"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_root = self.output_dir.resolve()
        source_directory = self.output_dir / source_id
        if source_directory.is_symlink():
            raise CollectionError("source snapshot directory must not be a symbolic link")
        source_directory.mkdir(exist_ok=True)
        if source_directory.resolve().parent != output_root:
            raise CollectionError("source snapshot directory escaped the output root")
        directory = source_directory / digest
        if directory.is_symlink():
            raise CollectionError("snapshot digest directory must not be a symbolic link")
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.resolve().relative_to(output_root)
        except ValueError as exc:
            raise CollectionError("snapshot directory escaped the output root") from exc
        body_path = directory / f"body{suffix}"
        metadata_path = directory / "metadata.json"
        self._write_file(body_path, body)
        metadata["sha256"] = digest
        metadata["bytes"] = len(body)
        self._write_file(
            metadata_path,
            (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        return Snapshot(
            source_id=source_id,
            retrieved_at=str(metadata["retrieved_at"]),
            sha256=digest,
            bytes=len(body),
            content_type=content_type,
            body_path=str(body_path),
            metadata_path=str(metadata_path),
        )

    @staticmethod
    def _write_file(path: Path, value: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o640)
        except OSError as exc:
            raise CollectionError(f"snapshot file could not be opened safely: {path.name}") from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
