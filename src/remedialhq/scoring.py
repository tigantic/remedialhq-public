from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True, slots=True)
class OpportunitySignals:
    demand: float
    momentum: float
    competition_advantage: float
    evidence_readiness: float
    originality_headroom: float
    revenue_intent: float
    shelf_life: float
    rights_risk: float

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if not 0 <= value <= 1:
                raise ValueError(f"{item.name} must be within [0, 1]")


def score(signals: OpportunitySignals) -> float:
    raw = (
        0.24 * signals.demand
        + 0.18 * signals.momentum
        + 0.12 * signals.competition_advantage
        + 0.16 * signals.evidence_readiness
        + 0.12 * signals.originality_headroom
        + 0.10 * signals.revenue_intent
        + 0.08 * signals.shelf_life
        - 0.20 * signals.rights_risk
    )
    return round(max(0.0, min(1.0, raw)), 4)
