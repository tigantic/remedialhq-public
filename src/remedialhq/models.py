from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")


def _machine_identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(
            f"{field_name} must contain 1 through 128 ASCII letters, digits, dots, hyphens, "
            "or underscores and must begin and end with a letter or digit"
        )
    return value


class ClaimState(StrEnum):
    CONFIRMED = "CONFIRMED"
    OBSERVED = "OBSERVED"
    REPORTED = "REPORTED"
    INFERRED = "INFERRED"
    PENDING = "PENDING"
    REJECTED = "REJECTED"


class RightsStatus(StrEnum):
    OWNED = "OWNED"
    ORIGINAL_GENERATED = "ORIGINAL_GENERATED"
    LICENSED_COMMERCIAL = "LICENSED_COMMERCIAL"
    PUBLIC_DOMAIN = "PUBLIC_DOMAIN"
    EDITORIAL_REVIEW_REQUIRED = "EDITORIAL_REVIEW_REQUIRED"
    NONCOMMERCIAL_ONLY = "NONCOMMERCIAL_ONLY"
    UNKNOWN = "UNKNOWN"
    PROHIBITED_LEAK = "PROHIBITED_LEAK"


class Decision(StrEnum):
    PASS = "PASS"
    HOLD = "HOLD"
    REJECT = "REJECT"


@dataclass(frozen=True, slots=True)
class Claim:
    claim_id: str
    proposition: str
    state: ClaimState
    confidence: float
    source_ids: tuple[str, ...]
    public_wording: str
    entities: tuple[str, ...] = ()
    observed_at: str | None = None

    def __post_init__(self) -> None:
        _machine_identifier(self.claim_id, "claim_id")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not self.source_ids:
            raise ValueError("claim must have at least one source")
        for source_id in self.source_ids:
            _machine_identifier(source_id, "source_ids")
        if len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("source_ids must be unique")

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["state"] = self.state.value
        out["source_ids"] = list(self.source_ids)
        out["entities"] = list(self.entities)
        return out

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Claim:
        return cls(
            claim_id=str(value["claim_id"]),
            proposition=str(value["proposition"]),
            state=ClaimState(str(value["state"])),
            confidence=float(value["confidence"]),
            source_ids=tuple(str(x) for x in value["source_ids"]),
            public_wording=str(value["public_wording"]),
            entities=tuple(str(x) for x in value.get("entities", [])),
            observed_at=value.get("observed_at"),
        )


@dataclass(frozen=True, slots=True)
class Asset:
    asset_id: str
    path: str
    rights_status: RightsStatus
    source_id: str | None = None
    license_scope: str | None = None
    sha256: str | None = None

    def __post_init__(self) -> None:
        _machine_identifier(self.asset_id, "asset_id")
        if self.source_id is not None:
            _machine_identifier(self.source_id, "source_id")
        if self.sha256 is not None and (
            len(self.sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise ValueError("asset sha256 must be a lowercase hexadecimal digest")

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["rights_status"] = self.rights_status.value
        return out


@dataclass(slots=True)
class ContentPackage:
    package_id: str
    title: str
    body: str
    platform: str
    claim_ids: list[str]
    assets: list[Asset] = field(default_factory=list)
    disclosures: set[str] = field(default_factory=set)
    originality_score: float = 0.0
    recent_similarity: float = 1.0
    rights_risk: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _machine_identifier(self.package_id, "package_id")
        _machine_identifier(self.platform, "platform")
        text_fields = {
            "title": self.title,
            "body": self.body,
        }
        for name, value in text_fields.items():
            if not value.strip():
                raise ValueError(f"{name} cannot be empty")
        if not self.claim_ids:
            raise ValueError("claim_ids cannot be empty")
        for claim_id in self.claim_ids:
            _machine_identifier(claim_id, "claim_ids")
        if len(set(self.claim_ids)) != len(self.claim_ids):
            raise ValueError("claim_ids must be unique")
        risk_fields = {
            "originality_score": self.originality_score,
            "recent_similarity": self.recent_similarity,
            "rights_risk": self.rights_risk,
        }
        for name, risk_value in risk_fields.items():
            if not math.isfinite(risk_value) or not 0.0 <= risk_value <= 1.0:
                raise ValueError(f"{name} must be a finite value between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "title": self.title,
            "body": self.body,
            "platform": self.platform,
            "claim_ids": self.claim_ids,
            "assets": [asset.to_dict() for asset in self.assets],
            "disclosures": sorted(self.disclosures),
            "originality_score": self.originality_score,
            "recent_similarity": self.recent_similarity,
            "rights_risk": self.rights_risk,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class GateFinding:
    gate: str
    decision: Decision
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["decision"] = self.decision.value
        return out


@dataclass(frozen=True, slots=True)
class GateReport:
    decision: Decision
    findings: tuple[GateFinding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "findings": [finding.to_dict() for finding in self.findings],
        }
