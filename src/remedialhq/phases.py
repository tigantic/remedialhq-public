from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .auth import AuthorizationError, load_youtube_credentials, resolve_youtube_channel
from .collector import TextSnapshotCollector
from .gates import evaluate
from .pipeline import build_content_packages, load_claims
from .provenance import load_sources, validate_source_bindings
from .publishers.youtube import YouTubePublisher
from .source_registry import SourceRegistry

PHASE_ORDER = ("collect", "reconcile", "compile", "gate", "publish", "measure")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.casefold() in {"1", "true", "yes", "on"}


def _configured_path(root: Path, name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_absolute() else (root / path).resolve()


def _publish_youtube(root: Path, package: Any) -> dict[str, Any]:
    if not _env_bool("YOUTUBE_LIVE_ADAPTER_ENABLED"):
        raise AuthorizationError("YOUTUBE_LIVE_ADAPTER_ENABLED is false")
    token_file = _configured_path(root, "YOUTUBE_TOKEN_FILE")
    media_path = _configured_path(root, "YOUTUBE_MEDIA_PATH")
    thumbnail_path = _configured_path(root, "YOUTUBE_THUMBNAIL_PATH")
    if token_file is None:
        raise AuthorizationError("YOUTUBE_TOKEN_FILE is required")
    if media_path is None:
        raise AuthorizationError("YOUTUBE_MEDIA_PATH is required")
    expected_channel_id = os.environ.get("YOUTUBE_EXPECTED_CHANNEL_ID", "").strip()
    if not expected_channel_id:
        raise AuthorizationError("YOUTUBE_EXPECTED_CHANNEL_ID is required")
    privacy = os.environ.get("YOUTUBE_PRIVACY_STATUS", "private").casefold()
    visible_authorized = _env_bool("YOUTUBE_VISIBLE_PUBLICATION_AUTHORIZED")
    authority = json.loads(
        (root / "config/publication_authority.json").read_text(encoding="utf-8")
    )
    youtube_authority = authority.get("platforms", {}).get("youtube", {})
    if not youtube_authority.get("private_upload_authorized"):
        raise AuthorizationError("repository authority does not permit a private YouTube upload")
    if privacy != "private" and not (
        authority.get("global_publication_enabled")
        and youtube_authority.get("visible_upload_authorized")
    ):
        raise AuthorizationError("repository authority does not permit a visible YouTube upload")
    credentials = load_youtube_credentials(token_file, persist_refresh=False)
    channel = resolve_youtube_channel(credentials)
    if channel["channel_id"] != expected_channel_id:
        raise AuthorizationError(
            "authorized YouTube channel does not match YOUTUBE_EXPECTED_CHANNEL_ID"
        )
    publisher = YouTubePublisher(
        credentials,
        media_path,
        privacy_status=privacy,
        public_publication_authorized=visible_authorized,
        thumbnail_path=thumbnail_path,
        asset_root=root,
    )
    return publisher.publish(package).to_dict()
NEXT_PHASE = {phase: PHASE_ORDER[index + 1] if index + 1 < len(PHASE_ORDER) else None for index, phase in enumerate(PHASE_ORDER)}


@dataclass(frozen=True, slots=True)
class PhaseResult:
    phase: str
    status: str
    occurred_at: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"phase": self.phase, "status": self.status, "occurred_at": self.occurred_at, "details": self.details}


def _write_result(output: Path, result: PhaseResult) -> PhaseResult:
    output.mkdir(parents=True, exist_ok=True)
    (output / f"phase-{result.phase}.json").write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def run_phase(phase: str, root: str | Path, output: str | Path) -> PhaseResult:
    if phase not in PHASE_ORDER:
        raise ValueError(f"unknown phase: {phase}")
    root_path = Path(root).resolve()
    output_path = Path(output).resolve()
    now = datetime.now(UTC).isoformat()

    if phase == "collect":
        registry = SourceRegistry.load(root_path / "config/sources.json")
        if os.environ.get("ENABLE_NETWORK_COLLECTION", "false").casefold() != "true":
            return _write_result(output_path, PhaseResult(
                phase, "PASS", now,
                {"mode": "REGISTRY_VALIDATION", "authorized_sources": [spec.source_id for spec in registry.allowed()]},
            ))
        collector = TextSnapshotCollector(output_path / "snapshots")
        snapshots = [
            collector.collect(spec).to_dict() for spec in registry.network_sources()
        ]
        return _write_result(output_path, PhaseResult(phase, "PASS", now, {"snapshots": snapshots}))

    claims = load_claims(root_path / "data/claims/seed_claims.jsonl")
    if phase == "reconcile":
        ids = [claim.claim_id for claim in claims]
        if len(ids) != len(set(ids)):
            return _write_result(output_path, PhaseResult(phase, "REJECT", now, {"reason": "duplicate claim IDs"}))
        sources = load_sources(root_path / "data/sources/seed_sources.jsonl")
        registry = SourceRegistry.load(root_path / "config/sources.json")
        source_issues = validate_source_bindings(claims, sources, registry=registry)
        if source_issues:
            return _write_result(output_path, PhaseResult(
                phase, "REJECT", now,
                {"reason": "claim-to-source provenance failed", "issues": source_issues},
            ))
        return _write_result(output_path, PhaseResult(
            phase, "PASS", now,
            {
                "claims": len(claims),
                "sources": len(sources),
                "publishable": sum(c.state.value not in {"PENDING", "REJECTED"} for c in claims),
                "provenance_issues": 0,
            },
        ))

    packages = build_content_packages(root_path)
    if phase == "compile":
        manifest = [package.to_dict() for package in packages]
        (output_path / "compiled-packages.json").parent.mkdir(parents=True, exist_ok=True)
        (output_path / "compiled-packages.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return _write_result(output_path, PhaseResult(phase, "PASS", now, {"packages": len(packages)}))

    claim_map = {claim.claim_id: claim for claim in claims}
    reports: list[dict[str, Any]] = []
    for package in packages:
        bound = [claim_map[claim_id] for claim_id in package.claim_ids]
        reports.append({"package_id": package.package_id, "report": evaluate(package, bound).to_dict()})
    if phase == "gate":
        decision = "PASS" if all(row["report"]["decision"] == "PASS" for row in reports) else "HOLD"
        (output_path / "gate-reports.json").parent.mkdir(parents=True, exist_ok=True)
        (output_path / "gate-reports.json").write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")
        return _write_result(output_path, PhaseResult(phase, decision, now, {"reports": reports}))

    if phase == "publish":
        if not _env_bool("PUBLISHING_ENABLED"):
            return _write_result(output_path, PhaseResult(
                phase, "HOLD", now,
                {"reason": "global publication switch is false", "packages_staged": len(packages)},
            ))

        requested = {
            value.strip().casefold()
            for value in os.environ.get("PUBLISH_TARGETS", "youtube").split(",")
            if value.strip()
        }
        selected = [package for package in packages if package.platform.casefold() in requested]
        if not selected:
            return _write_result(output_path, PhaseResult(
                phase, "HOLD", now,
                {"reason": "no compiled package matches PUBLISH_TARGETS", "targets": sorted(requested)},
            ))

        publish_results: list[dict[str, Any]] = []
        held: list[dict[str, str]] = []
        for package in selected:
            bound = [claim_map[claim_id] for claim_id in package.claim_ids]
            gate_report = evaluate(package, bound)
            if gate_report.decision.value != "PASS":
                held.append({"package_id": package.package_id, "reason": "content gates did not pass"})
                continue
            if package.platform.casefold() != "youtube":
                held.append({
                    "package_id": package.package_id,
                    "reason": f"live adapter is not implemented for {package.platform}",
                })
                continue
            try:
                publish_results.append(_publish_youtube(root_path, package))
            except (AuthorizationError, FileNotFoundError, PermissionError, ValueError) as exc:
                held.append({
                    "package_id": package.package_id,
                    "reason": f"{type(exc).__name__}: {exc}",
                })

        details = {
            "targets": sorted(requested),
            "published": publish_results,
            "held": held,
        }
        (output_path / "publish-results.json").write_text(
            json.dumps(details, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        status = "PASS" if publish_results and not held else "HOLD"
        return _write_result(output_path, PhaseResult(phase, status, now, details))

    queue_path = root_path / "content/queue/seed_queue_summary.json"
    queue_summary = json.loads(queue_path.read_text(encoding="utf-8"))
    return _write_result(output_path, PhaseResult(
        phase, "PASS", now,
        {"opportunities": queue_summary["count"], "immediate": len(queue_summary["immediate"]), "note": "live platform telemetry not connected"},
    ))
