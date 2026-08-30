from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any

from ..models import ContentPackage


@dataclass(frozen=True, slots=True)
class PublishResult:
    platform: str
    package_id: str
    status: str
    remote_id: str | None = None
    remote_url: str | None = None
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Publisher(ABC):
    @abstractmethod
    def publish(self, package: ContentPackage) -> PublishResult:
        raise NotImplementedError
