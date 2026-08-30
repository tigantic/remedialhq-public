from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, cast

from .gates import evaluate
from .ledger import HashLedger
from .models import Asset, Claim, ContentPackage, Decision, RightsStatus
from .publishers.dry_run import DryRunPublisher
from .renderer import render_claim_cards, render_package_manifest


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return cast(dict[str, Any], value)


def load_claims(path: Path) -> list[Claim]:
    claims: list[Claim] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                claims.append(Claim.from_dict(json.loads(line)))
    return claims


def _load_launch_package(root: Path) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    payload = load_json(root / "content/launch/publish-package-001.json")
    structured = load_json(root / "content/launch/episode-001.structured.json")
    blocks = [dict(item) for item in structured["blocks"]]
    body = "\n\n".join(str(block["text"]) for block in blocks) + "\n"
    return payload, body, blocks


def _asset_from_dict(value: dict[str, Any]) -> Asset:
    return Asset(
        asset_id=str(value["asset_id"]),
        path=str(value["path"]),
        rights_status=RightsStatus(str(value["rights_status"])),
        source_id=value.get("source_id"),
        license_scope=value.get("license_scope"),
        sha256=value.get("sha256"),
    )


def build_content_packages(root: Path) -> list[ContentPackage]:
    payload, body, blocks = _load_launch_package(root)
    assets = [_asset_from_dict(item) for item in payload.get("assets", [])]
    claim_ids = [str(item) for item in payload["claim_ids"]]
    disclosures = {str(item) for item in payload.get("disclosures", [])}
    metadata: dict[str, Any] = {
        "independent": True,
        "affiliate": False,
        "sponsored": False,
        "tags": ["GTA VI", "GTA 6", "Rockstar Games", "gaming analysis"],
        "content_blocks": blocks,
        "lineage_mode": "strict",
        "title_claim_ids": [str(item) for item in payload.get("title_claim_ids", [])],
        "originality_method": "declared_seed_for_dry_run",
        "media_review": payload.get("media_review"),
    }
    return [
        ContentPackage(
            package_id=f"{payload['package_id']}-{platform.upper()}",
            platform=str(platform),
            title=str(payload["title"]),
            body=body,
            claim_ids=claim_ids,
            assets=assets,
            disclosures=disclosures,
            originality_score=float(payload["originality_score"]),
            recent_similarity=float(payload["recent_similarity"]),
            rights_risk=float(payload["rights_risk"]),
            metadata=metadata,
        )
        for platform in payload["platforms"]
    ]


def run_demo(root: str | Path, output: str | Path) -> dict[str, Any]:
    root_path = Path(root).resolve()
    output_path = Path(output).resolve()
    if output_path == root_path:
        raise ValueError("demo output cannot be the project root")
    if output_path == Path(output_path.anchor):
        raise ValueError("demo output cannot be a filesystem root")
    sentinel = output_path / ".remedialhq-demo-output"
    if output_path.exists():
        if not output_path.is_dir():
            raise ValueError("demo output must be a directory")
        children = list(output_path.iterdir())
        if children and (
            not sentinel.is_file()
            or sentinel.read_text(encoding="utf-8") != "remedialhq-demo-output-v1\n"
        ):
            raise ValueError(
                "refusing to clear an existing directory without the ReMediaLHQ demo sentinel"
            )
        for child in children:
            if child == sentinel:
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        output_path.mkdir(parents=True)
    sentinel.write_text("remedialhq-demo-output-v1\n", encoding="utf-8")

    claims = load_claims(root_path / "data/claims/seed_claims.jsonl")
    claim_map = {claim.claim_id: claim for claim in claims}
    packages = build_content_packages(root_path)
    ledger = HashLedger(output_path / "ledger.jsonl")
    publisher = DryRunPublisher(output_path / "publish")
    package_results: list[dict[str, Any]] = []

    ledger.append("RUN_OPENED", {"mode": "DRY_RUN", "package_count": len(packages)})
    for package in packages:
        bound_claims = [claim_map[claim_id] for claim_id in package.claim_ids]
        ledger.append(
            "PACKAGE_COMPILED",
            {"package_id": package.package_id, "platform": package.platform},
        )
        report = evaluate(package, bound_claims)
        ledger.append(
            "GATE_DECISION",
            {"package_id": package.package_id, "report": report.to_dict()},
        )
        row: dict[str, Any] = {
            "package_id": package.package_id,
            "platform": package.platform,
            "gate": report.to_dict(),
        }
        if report.decision == Decision.PASS:
            manifest = render_package_manifest(
                package,
                bound_claims,
                output_path / "render" / f"{package.package_id}.manifest.json",
            )
            publish_result = publisher.publish(package)
            ledger.append(
                "PUBLISH_STAGED",
                {"package_id": package.package_id, "result": publish_result.to_dict()},
            )
            row["render"] = manifest.to_dict()
            row["publish"] = publish_result.to_dict()
        else:
            ledger.append(
                "PACKAGE_HELD",
                {"package_id": package.package_id, "decision": report.decision.value},
            )
        package_results.append(row)

    publishable_claims = [
        claim for claim in claims if claim.claim_id in set(packages[0].claim_ids)
    ]
    cards = render_claim_cards(
        publishable_claims,
        output_path / "render" / "launch-claim-cards.svg",
        title="LAUNCH CLAIM LEDGER",
    )
    ledger.append("RUN_CLOSED", {"claim_card_sha256": cards.sha256})
    verified, message = ledger.verify()
    report_payload = {
        "schema_version": 1,
        "mode": "DRY_RUN",
        "ledger_verified": verified,
        "ledger_message": message,
        "ledger_head": ledger.head,
        "packages": package_results,
        "claim_cards": cards.to_dict(),
    }
    (output_path / "run-report.json").write_text(
        json.dumps(report_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report_payload
