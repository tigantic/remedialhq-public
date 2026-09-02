from __future__ import annotations

import json
from pathlib import Path

from ..canonical import sha256_json
from ..models import ContentPackage
from .base import Publisher, PublishResult


class DryRunPublisher(Publisher):
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def publish(self, package: ContentPackage) -> PublishResult:
        payload = package.to_dict()
        digest = sha256_json(payload)
        path = self.output_dir / f"{package.package_id}-{package.platform}.publish.json"
        envelope = {
            "mode": "DRY_RUN",
            "publish_blocked": True,
            "reason": "No owner-controlled live credential was supplied.",
            "digest": digest,
            "package": payload,
        }
        path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return PublishResult(
            platform=package.platform,
            package_id=package.package_id,
            status="STAGED_PRIVATE",
            remote_id=None,
            remote_url=None,
            details={"path": str(path), "sha256": digest},
        )
