from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .models import Claim, ClaimState
from .source_registry import SourceRegistry

SOURCE_TIERS = frozenset(
    {
        "AUDIENCE_RESEARCH_PROVIDER",
        "FIRST_PARTY",
        "FIRST_PARTY_CORPORATE",
        "FIRST_PARTY_POLICY",
        "FIRST_PARTY_TECHNICAL",
        "FIRST_PARTY_VISUAL",
    }
)
CONFIRMATION_TIERS = frozenset(
    {
        "FIRST_PARTY",
        "FIRST_PARTY_CORPORATE",
        "FIRST_PARTY_POLICY",
        "FIRST_PARTY_TECHNICAL",
    }
)
RIGHTS_STATUSES = frozenset(
    {
        "DATA_FACTS_ONLY",
        "NO_COMMERCIAL_REUPLOAD_BY_DEFAULT",
        "TEXT_FACTS_ONLY",
    }
)


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field} must be a JSON boolean")
    return value


def _enumerated_text(value: object, field: str, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is not supported")
    return value


@dataclass(frozen=True, slots=True)
class SourceRecord:
    source_id: str
    publisher: str
    title: str
    url: str
    source_tier: str
    rights_status: str
    prohibited: bool
    retrieved_at: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> SourceRecord:
        if "prohibited" not in value:
            raise ValueError("source prohibited classification is required")
        return cls(
            source_id=str(value["source_id"]),
            publisher=str(value["publisher"]),
            title=str(value["title"]),
            url=str(value["url"]),
            source_tier=_enumerated_text(
                value["source_tier"], "source tier", SOURCE_TIERS
            ),
            rights_status=_enumerated_text(
                value["rights_status"], "source rights status", RIGHTS_STATUSES
            ),
            prohibited=_strict_bool(
                value["prohibited"], f"source {value.get('source_id')} prohibited"
            ),
            retrieved_at=str(value["retrieved_at"]) if value.get("retrieved_at") else None,
        )


def load_sources(path: str | Path) -> list[SourceRecord]:
    records: list[SourceRecord] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(SourceRecord.from_dict(json.loads(line)))
    return records


def validate_source_bindings(
    claims: list[Claim],
    sources: list[SourceRecord],
    *,
    registry: SourceRegistry,
) -> list[dict[str, object]]:
    issues: list[dict[str, object]] = []
    source_ids = [source.source_id for source in sources]
    duplicate_sources = sorted({item for item in source_ids if source_ids.count(item) > 1})
    if duplicate_sources:
        issues.append({"type": "duplicate_source_ids", "source_ids": duplicate_sources})

    source_map = {source.source_id: source for source in sources}
    for source in sources:
        if source.source_tier not in SOURCE_TIERS:
            issues.append(
                {
                    "type": "unsupported_source_tier",
                    "source_id": source.source_id,
                    "source_tier": source.source_tier,
                }
            )
        if source.rights_status not in RIGHTS_STATUSES:
            issues.append(
                {
                    "type": "unsupported_rights_status",
                    "source_id": source.source_id,
                    "rights_status": source.rights_status,
                }
            )
        parsed = urlsplit(source.url)
        if parsed.scheme not in {"https", "connected"}:
            issues.append(
                {"type": "invalid_source_scheme", "source_id": source.source_id, "url": source.url}
            )
        if parsed.scheme == "https" and not parsed.hostname:
            issues.append(
                {"type": "invalid_source_url", "source_id": source.source_id, "url": source.url}
            )
        if parsed.scheme == "connected" and source.source_tier != "AUDIENCE_RESEARCH_PROVIDER":
            issues.append(
                {
                    "type": "connected_source_tier_mismatch",
                    "source_id": source.source_id,
                    "source_tier": source.source_tier,
                }
            )
        if parsed.scheme == "https" and source.source_tier == "AUDIENCE_RESEARCH_PROVIDER":
            issues.append(
                {
                    "type": "provider_source_scheme_mismatch",
                    "source_id": source.source_id,
                    "url": source.url,
                }
            )
        if parsed.scheme in {"connected", "https"} and parsed.hostname:
            try:
                registry_source = registry.authorize_url(source.url)
            except PermissionError:
                issues.append(
                    {
                        "type": "source_not_in_default_deny_registry",
                        "source_id": source.source_id,
                        "url": source.url,
                    }
                )
            else:
                if registry_source.tier != source.source_tier:
                    issues.append(
                        {
                            "type": "source_registry_tier_mismatch",
                            "source_id": source.source_id,
                            "source_tier": source.source_tier,
                            "registry_tier": registry_source.tier,
                        }
                    )
                if registry_source.asset_rights != source.rights_status:
                    issues.append(
                        {
                            "type": "source_registry_rights_mismatch",
                            "source_id": source.source_id,
                            "rights_status": source.rights_status,
                            "registry_rights_status": registry_source.asset_rights,
                        }
                    )

    for claim in claims:
        missing = sorted(set(claim.source_ids) - set(source_map))
        prohibited = sorted(
            source_id
            for source_id in claim.source_ids
            if source_id in source_map and source_map[source_id].prohibited
        )
        if missing:
            issues.append({"type": "missing_sources", "claim_id": claim.claim_id, "source_ids": missing})
        if prohibited:
            issues.append(
                {"type": "prohibited_source_binding", "claim_id": claim.claim_id, "source_ids": prohibited}
            )
        bound = [source_map[source_id] for source_id in claim.source_ids if source_id in source_map]
        tiers = {source.source_tier for source in bound}
        if claim.state == ClaimState.CONFIRMED and not tiers.intersection(
            CONFIRMATION_TIERS
        ):
            issues.append(
                {
                    "type": "confirmed_without_first_party_source",
                    "claim_id": claim.claim_id,
                    "source_tiers": sorted(tiers),
                }
            )
        if claim.state == ClaimState.OBSERVED and "FIRST_PARTY_VISUAL" not in tiers:
            issues.append(
                {
                    "type": "observation_without_first_party_visual",
                    "claim_id": claim.claim_id,
                    "source_tiers": sorted(tiers),
                }
            )
    return issues
