from __future__ import annotations

import html
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256_bytes
from .models import Claim, ContentPackage


@dataclass(frozen=True, slots=True)
class RenderArtifact:
    path: str
    media_type: str
    sha256: str
    bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "media_type": self.media_type,
            "sha256": self.sha256,
            "bytes": self.bytes,
        }


def _write(path: Path, payload: bytes, media_type: str) -> RenderArtifact:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return RenderArtifact(
        path=str(path),
        media_type=media_type,
        sha256=sha256_bytes(payload),
        bytes=len(payload),
    )


def render_claim_cards(
    claims: Iterable[Claim],
    output_path: str | Path,
    *,
    title: str = "GTA VI CLAIM LEDGER",
) -> RenderArtifact:
    claim_list = list(claims)
    width = 1600
    card_height = 150
    margin = 90
    height = 190 + max(1, len(claim_list)) * card_height + 70
    palette = {
        "CONFIRMED": "#B8FF3D",
        "OBSERVED": "#2FD7FF",
        "REPORTED": "#FFB020",
        "INFERRED": "#A58BFF",
        "PENDING": "#859087",
        "REJECTED": "#FF5A63",
    }
    rows: list[str] = []
    for index, claim in enumerate(claim_list):
        y = 185 + index * card_height
        state = claim.state.value
        color = palette[state]
        proposition = html.escape(claim.public_wording)
        claim_id = html.escape(claim.claim_id)
        source_text = html.escape(" · ".join(claim.source_ids))
        rows.append(
            f'''<g transform="translate({margin},{y})">
              <rect width="{width - margin * 2}" height="118" rx="22" fill="#111713" stroke="#263129"/>
              <rect width="12" height="118" rx="6" fill="{color}"/>
              <text x="38" y="40" fill="{color}" font-family="Inter,Arial,sans-serif" font-size="24" font-weight="800">{state}</text>
              <text x="38" y="76" fill="#F2F7F3" font-family="Inter,Arial,sans-serif" font-size="25" font-weight="650">{proposition}</text>
              <text x="38" y="102" fill="#829087" font-family="Inter,Arial,sans-serif" font-size="16">{claim_id} · {source_text}</text>
            </g>'''
        )
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#050706"/><stop offset="1" stop-color="#111713"/>
        </linearGradient>
        <pattern id="grid" width="44" height="44" patternUnits="userSpaceOnUse">
          <path d="M44 0H0V44" fill="none" stroke="#182019" stroke-width="1"/>
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#bg)"/>
      <rect width="100%" height="100%" fill="url(#grid)" opacity=".55"/>
      <text x="{margin}" y="80" fill="#B8FF3D" font-family="Inter,Arial,sans-serif" font-size="24" font-weight="800" letter-spacing="5">ReMediaLHQ</text>
      <text x="{margin}" y="136" fill="#F2F7F3" font-family="Inter,Arial,sans-serif" font-size="46" font-weight="900">{html.escape(title)}</text>
      {''.join(rows)}
      <text x="{margin}" y="{height - 30}" fill="#829087" font-family="Inter,Arial,sans-serif" font-size="16">Independent editorial analysis · Signal Over Hype.</text>
    </svg>'''
    return _write(Path(output_path), svg.encode("utf-8"), "image/svg+xml")


def render_package_manifest(
    package: ContentPackage,
    claims: Iterable[Claim],
    output_path: str | Path,
) -> RenderArtifact:
    by_id = {claim.claim_id: claim for claim in claims}
    payload = {
        "schema_version": 1,
        "package": package.to_dict(),
        "claim_bindings": [by_id[claim_id].to_dict() for claim_id in package.claim_ids],
        "render_contract": {
            "visual_source_policy": "ORIGINAL_ASSETS_ONLY",
            "captions_required": True,
            "independence_notice_required": True,
            "source_links_required": True,
        },
    }
    raw = (json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    return _write(Path(output_path), raw, "application/json")
