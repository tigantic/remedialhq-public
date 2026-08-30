from __future__ import annotations

import re
from collections.abc import Iterable

from .models import (
    Claim,
    ClaimState,
    ContentPackage,
    Decision,
    GateFinding,
    GateReport,
    RightsStatus,
)

PUBLISHABLE_STATES = {
    ClaimState.CONFIRMED,
    ClaimState.OBSERVED,
    ClaimState.REPORTED,
    ClaimState.INFERRED,
}
COMMERCIAL_RIGHTS = {
    RightsStatus.OWNED,
    RightsStatus.ORIGINAL_GENERATED,
    RightsStatus.LICENSED_COMMERCIAL,
    RightsStatus.PUBLIC_DOMAIN,
}
CERTAINTY_TERMS = {"confirmed", "official", "guaranteed", "proven", "definitely"}
OBSERVED_MARKERS = {"appear", "appears", "depict", "depicts", "observed", "shows", "visible"}
REPORTED_MARKERS = {"according", "estimate", "estimated", "report", "reported", "reports", "snapshot"}
INFERRED_MARKERS = {"could", "infer", "inferred", "likely", "may", "might", "suggest", "suggests"}
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9]+(?:[.’'_-][A-Za-z0-9]+)*")
NUMBER_PATTERN = re.compile(r"(?<![A-Za-z0-9])\d+(?:[.,]\d+)*(?:%|x)?", re.IGNORECASE)
NONFACTUAL_KINDS = {"editorial_method", "product_method", "close"}
APPROVED_NONFACTUAL_TEMPLATES = {
    "ReMediaLHQ separates published evidence from interpretation before either reaches a script. Each material claim receives a visible state so an observation or hypothesis cannot silently become a confirmed fact.",
    "This desk starts with one line in the ground: every GTA VI claim gets a state. Confirmed. Observed. Reported. Inferred.",
    "A current source state is not a promise that marketing material can never change. When authoritative information changes, the record changes without erasing its prior state.",
    "Observed is different from confirmed. An official presentation may visibly depict behavior without explaining the system behind it or promising final shipping behavior.",
    "Reported means an accountable third party owns the claim. Inferred means the desk is connecting evidence into a hypothesis. Both can be useful when their state stays visible.",
    "That boundary forces a stronger creative system: original diagrams, timelines, claim cards, structured dossiers, technical explanations, searchable answers, and visible corrections.",
    "Every public item resolves to claim IDs. A claim has sources, a state, a confidence boundary, related entities, and a history.",
    "No fake certainty. No invisible corrections. No dependence on stolen material. Subscribe for the state changes, not the recycled hype. Before the hype becomes history, we build the record.",
}
TITLE_EDITORIAL_WORDS = {
    "actually", "analysis", "confirmed", "did", "evidence", "explained", "how",
    "definitely", "guaranteed", "latest", "not", "observed", "official", "proven",
    "reported", "says", "show", "shows", "state", "update", "what", "why",
}
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "for", "from",
    "had", "has", "have", "in", "into", "is", "it", "its", "not", "of", "on", "or",
    "that", "the", "their", "this", "to", "was", "were", "will", "with", "without",
}


def _words(value: str) -> set[str]:
    return {
        token.casefold().replace("’", "'")
        for token in TOKEN_PATTERN.findall(value)
        if token.casefold() not in STOPWORDS and len(token) > 1
    }


def _numbers(value: str) -> set[str]:
    return {match.casefold().replace(",", "") for match in NUMBER_PATTERN.findall(value)}


def _evidence_gate(package: ContentPackage, claims: dict[str, Claim]) -> GateFinding:
    duplicate_ids = sorted({item for item in package.claim_ids if package.claim_ids.count(item) > 1})
    missing = sorted(set(package.claim_ids) - set(claims))
    blocked = sorted(
        claim_id
        for claim_id in package.claim_ids
        if claim_id in claims and claims[claim_id].state not in PUBLISHABLE_STATES
    )
    if duplicate_ids or missing or blocked:
        return GateFinding(
            "evidence",
            Decision.HOLD,
            "package contains duplicate, missing, or non-publishable claims",
            {"duplicates": duplicate_ids, "missing": missing, "blocked": blocked},
        )
    return GateFinding("evidence", Decision.PASS, "all claims exist and are publishable")


def _lineage_gate(package: ContentPackage, claims: dict[str, Claim]) -> GateFinding:
    blocks = package.metadata.get("content_blocks")
    if not isinstance(blocks, list) or not blocks:
        return GateFinding(
            "lineage", Decision.HOLD,
            "structured content blocks are required for sentence-level lineage",
        )
    malformed: list[str] = []
    unknown: dict[str, list[str]] = {}
    bound: set[str] = set()
    factual_count = 0
    bound_factual_count = 0
    unsupported_nonfactual: list[str] = []
    rendered_blocks: list[str] = []
    for index, block in enumerate(blocks):
        block_id = (
            str(block.get("block_id", f"index-{index}"))
            if isinstance(block, dict)
            else f"index-{index}"
        )
        if (
            not isinstance(block, dict)
            or not isinstance(block.get("text"), str)
            or not block["text"].strip()
        ):
            malformed.append(block_id)
            continue
        rendered_blocks.append(str(block["text"]).strip())
        block_claim_ids = [str(item) for item in block.get("claim_ids", [])]
        bad = sorted(set(block_claim_ids) - set(claims))
        if bad:
            unknown[block_id] = bad
        bound.update(block_claim_ids)
        if bool(block.get("factual")):
            factual_count += 1
            if block_claim_ids and not bad:
                bound_factual_count += 1
            else:
                malformed.append(block_id)
        else:
            kind = str(block.get("kind", ""))
            if (
                kind not in NONFACTUAL_KINDS
                or str(block["text"]).strip() not in APPROVED_NONFACTUAL_TEMPLATES
                or block_claim_ids
            ):
                unsupported_nonfactual.append(block_id)
    package_claims = set(package.claim_ids)
    unbound_package_claims = sorted(package_claims - bound)
    extra_bound_claims = sorted(bound - package_claims)
    unsourced_rate = 0.0 if factual_count == 0 else 1 - (bound_factual_count / factual_count)
    normalized_body = " ".join(package.body.split())
    normalized_blocks = " ".join("\n\n".join(rendered_blocks).split())
    body_mismatch = normalized_body != normalized_blocks
    if (
        malformed
        or unknown
        or unbound_package_claims
        or extra_bound_claims
        or unsupported_nonfactual
        or body_mismatch
        or unsourced_rate > 0.05
    ):
        return GateFinding(
            "lineage", Decision.HOLD,
            "content blocks fail factual lineage requirements",
            {
                "malformed_or_unbound_blocks": sorted(set(malformed)),
                "unknown_claims": unknown,
                "unbound_package_claims": unbound_package_claims,
                "extra_bound_claims": extra_bound_claims,
                "unsupported_nonfactual_blocks": sorted(unsupported_nonfactual),
                "body_matches_structured_blocks": not body_mismatch,
                "unsourced_sentence_rate": round(unsourced_rate, 4),
            },
        )
    return GateFinding(
        "lineage", Decision.PASS,
        "all factual content blocks are bound to known package claims",
        {
            "factual_blocks": factual_count,
            "body_matches_structured_blocks": True,
            "unsourced_sentence_rate": round(unsourced_rate, 4),
        },
    )


def _fact_alignment_gate(package: ContentPackage, claims: dict[str, Claim]) -> GateFinding:
    blocks = package.metadata.get("content_blocks")
    if not isinstance(blocks, list):
        return GateFinding("fact_alignment", Decision.HOLD, "structured blocks are unavailable")
    weak_alignment: dict[str, float] = {}
    invented_numbers: dict[str, list[str]] = {}
    framing_failures: dict[str, list[str]] = {}
    unapproved_wording: list[str] = []
    checked = 0
    for index, block in enumerate(blocks):
        if not isinstance(block, dict) or not bool(block.get("factual")):
            continue
        checked += 1
        block_id = str(block.get("block_id", f"index-{index}"))
        block_claim_ids = [str(item) for item in block.get("claim_ids", []) if str(item) in claims]
        if not block_claim_ids:
            continue
        bound_claims = [claims[item] for item in block_claim_ids]
        reviewed_wording = " ".join(claim.public_wording.strip() for claim in bound_claims)
        if " ".join(str(block["text"]).split()) != " ".join(reviewed_wording.split()):
            unapproved_wording.append(block_id)
        reference = " ".join(
            f"{claim.proposition} {claim.public_wording} {' '.join(claim.entities)}"
            for claim in bound_claims
        )
        block_words = _words(str(block["text"]))
        reference_words = _words(reference)
        overlap = len(block_words & reference_words) / max(1, len(block_words))
        if overlap < 0.35:
            weak_alignment[block_id] = round(overlap, 4)

        extra_numbers = sorted(_numbers(str(block["text"])) - _numbers(reference))
        if extra_numbers:
            invented_numbers[block_id] = extra_numbers

        words = _words(str(block["text"]))
        missing_markers: list[str] = []
        states = {claim.state for claim in bound_claims}
        if ClaimState.OBSERVED in states and not words.intersection(OBSERVED_MARKERS):
            missing_markers.append("OBSERVED")
        if ClaimState.REPORTED in states and not words.intersection(REPORTED_MARKERS):
            missing_markers.append("REPORTED")
        inferred_claims = [claim for claim in bound_claims if claim.state == ClaimState.INFERRED]
        derived_exact = (
            str(block.get("kind")) == "derived_fact"
            and inferred_claims
            and all(claim.confidence >= 0.99 for claim in inferred_claims)
        )
        if inferred_claims and not derived_exact and not words.intersection(INFERRED_MARKERS):
            missing_markers.append("INFERRED")
        if missing_markers:
            framing_failures[block_id] = missing_markers

    if unapproved_wording or weak_alignment or invented_numbers or framing_failures:
        return GateFinding(
            "fact_alignment",
            Decision.HOLD,
            "factual language is not sufficiently aligned with its bound claim records",
            {
                "weak_lexical_alignment": weak_alignment,
                "not_exact_reviewed_public_wording": sorted(unapproved_wording),
                "numbers_absent_from_bound_claims": invented_numbers,
                "missing_state_language": framing_failures,
            },
        )
    return GateFinding(
        "fact_alignment",
        Decision.PASS,
        "factual blocks align with bound propositions, numbers, and state language",
        {"factual_blocks_checked": checked},
    )


def _title_strength_gate(package: ContentPackage, claims: dict[str, Claim]) -> GateFinding:
    title = package.title.casefold()
    terms = sorted(term for term in CERTAINTY_TERMS if term in title)
    raw_title_claim_ids = package.metadata.get("title_claim_ids", [])
    title_claim_ids = (
        [str(item) for item in raw_title_claim_ids]
        if isinstance(raw_title_claim_ids, list)
        else []
    )
    unknown = sorted(set(title_claim_ids) - set(claims))
    nonconfirmed = sorted(
        claim_id
        for claim_id in title_claim_ids
        if claim_id in claims and claims[claim_id].state != ClaimState.CONFIRMED
    )
    bound_claims = [claims[item] for item in title_claim_ids if item in claims]
    reference = " ".join(
        f"{claim.proposition} {claim.public_wording} {' '.join(claim.entities)}"
        for claim in bound_claims
    )
    unexplained_words = sorted(_words(package.title) - _words(reference) - TITLE_EDITORIAL_WORDS)
    unexplained_numbers = sorted(_numbers(package.title) - _numbers(reference))
    certainty_without_confirmation = bool(terms and nonconfirmed)
    if (
        not title_claim_ids
        or unknown
        or certainty_without_confirmation
        or unexplained_words
        or unexplained_numbers
    ):
        return GateFinding(
            "title_strength", Decision.HOLD,
            "title language is not fully explained by its explicit evidence set",
            {
                "terms": terms,
                "title_claim_ids": title_claim_ids,
                "unknown": unknown,
                "nonconfirmed_certainty_claims": nonconfirmed if terms else [],
                "unexplained_words": unexplained_words,
                "unexplained_numbers": unexplained_numbers,
            },
        )
    return GateFinding(
        "title_strength",
        Decision.PASS,
        "title language is aligned to its explicit evidence set",
        {"terms": terms, "title_claim_ids": title_claim_ids},
    )


def _rights_gate(package: ContentPackage) -> GateFinding:
    asset_ids = [asset.asset_id for asset in package.assets]
    duplicates = sorted({item for item in asset_ids if asset_ids.count(item) > 1})
    blocked = [
        {"asset_id": asset.asset_id, "rights_status": asset.rights_status.value}
        for asset in package.assets
        if asset.rights_status not in COMMERCIAL_RIGHTS
    ]
    leaked = any(row["rights_status"] == RightsStatus.PROHIBITED_LEAK.value for row in blocked)
    if duplicates or blocked or package.rights_risk > 0.15:
        return GateFinding(
            "rights", Decision.REJECT if leaked else Decision.HOLD,
            "asset identity, rights, or aggregate rights risk exceeds policy",
            {
                "duplicate_asset_ids": duplicates,
                "blocked_assets": blocked,
                "rights_risk": package.rights_risk,
            },
        )
    return GateFinding("rights", Decision.PASS, "all assets have commercial authority")


def _originality_gate(package: ContentPackage) -> GateFinding:
    if package.originality_score < 0.80 or package.recent_similarity > 0.78:
        return GateFinding(
            "originality", Decision.HOLD,
            "originality or repetition threshold failed",
            {
                "originality_score": package.originality_score,
                "recent_similarity": package.recent_similarity,
            },
        )
    return GateFinding("originality", Decision.PASS, "originality and repetition pass")


def _disclosure_gate(package: ContentPackage) -> GateFinding:
    required = {"independence"}
    if package.metadata.get("affiliate"):
        required.add("affiliate")
    if package.metadata.get("sponsored"):
        required.add("sponsorship")
    missing = sorted(required - package.disclosures)
    if missing:
        return GateFinding(
            "disclosure", Decision.HOLD,
            "required disclosures are missing", {"missing": missing},
        )
    return GateFinding("disclosure", Decision.PASS, "required disclosures are present")


def evaluate(package: ContentPackage, claims: Iterable[Claim]) -> GateReport:
    claim_map = {claim.claim_id: claim for claim in claims}
    findings = (
        _evidence_gate(package, claim_map),
        _lineage_gate(package, claim_map),
        _fact_alignment_gate(package, claim_map),
        _title_strength_gate(package, claim_map),
        _rights_gate(package),
        _originality_gate(package),
        _disclosure_gate(package),
    )
    if any(finding.decision == Decision.REJECT for finding in findings):
        decision = Decision.REJECT
    elif any(finding.decision == Decision.HOLD for finding in findings):
        decision = Decision.HOLD
    else:
        decision = Decision.PASS
    return GateReport(decision=decision, findings=findings)
