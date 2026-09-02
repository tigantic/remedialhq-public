#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from remedialhq.gates import evaluate
from remedialhq.models import Asset, ContentPackage, RightsStatus
from remedialhq.pipeline import load_claims

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/red-team/generated-draft-adjudication.json"

UNBOUND_ASSERTIONS = [
    "Pre-orders went live on June 25, 2026.",
    "Rockstar called an August 2026 leak wave heartbreaking.",
    "The Extended Look premiered on Netflix.",
    "Targeting police-car tires is an effective tactic.",
    "The game has Standard and Ultimate editions at stated prices.",
    "Leonida is approximately three times the size of Red Dead Redemption 2's map.",
    "Vice City is approximately twice the size of Los Santos.",
    "The romantic relationship between Jason and Lucia is player-driven.",
    "A livestreamed abduction appears in official footage.",
    "The latest leaked build establishes additional gameplay details."
]


def main() -> None:
    claims = load_claims(ROOT / "data/claims/seed_claims.jsonl")
    blocks = [
        {"block_id": f"UNBOUND-{index:02d}", "text": text, "factual": True, "claim_ids": []}
        for index, text in enumerate(UNBOUND_ASSERTIONS, 1)
    ]
    package = ContentPackage(
        package_id="QUARANTINE-VIDIQ-DRAFT-001",
        title="GTA VI: What Rockstar Actually Confirmed - and What It Did Not",
        body="\n".join(UNBOUND_ASSERTIONS),
        platform="youtube",
        claim_ids=["CLM-0001"],
        assets=[Asset("AST-Q-1", "original-graphics-only", RightsStatus.ORIGINAL_GENERATED)],
        disclosures={"independence"},
        originality_score=0.9,
        recent_similarity=0.1,
        rights_risk=0.02,
        metadata={
            "title_claim_ids": ["CLM-0001", "CLM-0002", "CLM-0003", "CLM-0004"],
            "content_blocks": blocks,
            "generator_job_id": "job_86d48348-3e31-4ad1-8b60-f50981866764",
        },
    )
    report = evaluate(package, claims)
    payload = {
        "schema_version": 1,
        "draft_source": "connected vidIQ script generator",
        "generator_job_id": package.metadata["generator_job_id"],
        "disposition": report.decision.value,
        "publication_permitted": False,
        "unbound_assertions": UNBOUND_ASSERTIONS,
        "gate_report": report.to_dict(),
        "rebuild_instruction": "Regenerate exclusively from structured claim blocks; do not paraphrase unbound assertions into the next draft.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"disposition": report.decision.value, "unbound": len(UNBOUND_ASSERTIONS), "output": str(OUT)}, indent=2))


if __name__ == "__main__":
    main()
