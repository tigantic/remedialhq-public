from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")


def validate_source_id(value: object) -> str:
    """Return one canonical source ID that is safe for paths and public records."""
    if not isinstance(value, str) or SOURCE_ID_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "source ID must contain 1 through 64 lowercase ASCII letters, digits, or hyphens"
        )
    return value


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field} must be a JSON boolean")
    return value


@dataclass(frozen=True, slots=True)
class SourceSpec:
    source_id: str
    name: str
    url: str
    tier: str
    collection: str
    asset_rights: str
    poll_minutes: int
    allowed: bool

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").casefold()


class SourceRegistry:
    def __init__(self, specs: list[SourceSpec], prohibited_patterns: list[str]) -> None:
        self.specs = specs
        self.prohibited_patterns = tuple(pattern.casefold() for pattern in prohibited_patterns)
        ids = [validate_source_id(item.source_id) for item in specs]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate source IDs")

    @classmethod
    def load(cls, path: str | Path) -> SourceRegistry:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if value.get("default_policy") != "deny":
            raise ValueError("source registry must be default-deny")
        specs = [
            SourceSpec(
                source_id=validate_source_id(row["id"]),
                name=str(row["name"]),
                url=str(row["url"]),
                tier=str(row["tier"]),
                collection=str(row["collection"]),
                asset_rights=str(row["asset_rights"]),
                poll_minutes=int(row["poll_minutes"]),
                allowed=_strict_bool(row["allowed"], f"source {row['id']} allowed"),
            )
            for row in value["sources"]
        ]
        for spec in specs:
            parts = urlsplit(spec.url)
            if not parts.hostname or parts.scheme not in {"connected", "https"}:
                raise ValueError(
                    f"source {spec.source_id} must use an approved absolute URL"
                )
            if parts.scheme == "connected" and (
                spec.collection != "connected_provider_snapshot"
                or spec.poll_minutes != 0
            ):
                raise ValueError(
                    f"connected source {spec.source_id} must be a non-polled provider snapshot"
                )
        return cls(specs, [str(item) for item in value.get("prohibited_patterns", [])])

    def allowed(self) -> list[SourceSpec]:
        return [spec for spec in self.specs if spec.allowed]

    def network_sources(self) -> list[SourceSpec]:
        return [spec for spec in self.allowed() if urlsplit(spec.url).scheme == "https"]

    def by_id(self, source_id: str) -> SourceSpec:
        for spec in self.specs:
            if spec.source_id == source_id and spec.allowed:
                return spec
        raise KeyError(source_id)

    def authorize_url(self, url: str) -> SourceSpec:
        candidate = urlsplit(url)
        if candidate.scheme not in {"connected", "https"} or not candidate.hostname:
            raise PermissionError("only approved absolute source URLs are eligible")
        normalized = url.rstrip("/")
        for spec in self.allowed():
            if normalized == spec.url.rstrip("/"):
                return spec
        raise PermissionError("URL is not present in the default-deny source registry")
