#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CLAIMS_SOURCE = ROOT / "data/claims/seed_claims.jsonl"
SOURCES_SOURCE = ROOT / "data/sources/seed_sources.jsonl"
SITE_DATA = ROOT / "site/data"


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TypeError(f"{path}:{line_number} must contain a JSON object")
            records.append(value)
    return records


def main() -> None:
    claims = _load_jsonl(CLAIMS_SOURCE)
    sources = _load_jsonl(SOURCES_SOURCE)

    claim_ids = [str(item["claim_id"]) for item in claims]
    source_ids = [str(item["source_id"]) for item in sources]
    if len(claim_ids) != len(set(claim_ids)):
        raise ValueError("duplicate claim IDs")
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("duplicate source IDs")

    known_sources = set(source_ids)
    for claim in claims:
        raw_source_ids = claim.get("source_ids", [])
        if not isinstance(raw_source_ids, list):
            raise TypeError(f"claim {claim['claim_id']} source_ids must be a list")
        unknown = sorted({str(item) for item in raw_source_ids} - known_sources)
        if unknown:
            raise ValueError(f"claim {claim['claim_id']} references unknown sources: {unknown}")

    public_claims = [
        {
            "claim_id": claim["claim_id"],
            "proposition": claim["public_wording"],
            "state": claim["state"],
            "source_ids": claim.get("source_ids", []),
            "entities": claim.get("entities", []),
            "public_wording": claim["public_wording"],
            "observed_at": claim.get("observed_at"),
        }
        for claim in claims
    ]

    public_sources: list[dict[str, object]] = []
    for source in sources:
        url = str(source.get("url", ""))
        scheme = urlsplit(url).scheme.casefold()
        public_sources.append(
            {
                "source_id": source["source_id"],
                "publisher": source["publisher"],
                "title": source["title"],
                "source_tier": source["source_tier"],
                "retrieved_at": source["retrieved_at"],
                "href": url if scheme == "https" else None,
            }
        )

    SITE_DATA.mkdir(parents=True, exist_ok=True)
    (SITE_DATA / "claims.json").write_text(
        json.dumps(public_claims, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (SITE_DATA / "sources.json").write_text(
        json.dumps(public_sources, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    manifest = {
        "claims": len(claims),
        "sources": len(sources),
        "publishable_claims": sum(
            str(item.get("state")) not in {"PENDING", "REJECTED"} for item in claims
        ),
        "outputs": ["/data/claims.json", "/data/sources.json"],
    }
    (SITE_DATA / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"synced {manifest['claims']} claims and {manifest['sources']} sources "
        f"({manifest['publishable_claims']} publishable)"
    )


if __name__ == "__main__":
    main()
