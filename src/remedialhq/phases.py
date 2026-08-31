from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .auth import AuthorizationError, load_youtube_credentials, resolve_youtube_channel
from .canonical import sha256_bytes
from .collector import TextSnapshotCollector
from .gates import evaluate
from .phase_artifacts import (
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    ArtifactUnavailableError,
    read_bounded_regular_file,
)
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

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PhaseResult:
        if set(value) != {"phase", "status", "occurred_at", "details"}:
            raise ValueError("phase result fields do not match the supported schema")
        if not isinstance(value.get("details"), dict):
            raise TypeError("phase result details must be a JSON object")
        return cls(
            phase=str(value["phase"]),
            status=str(value["status"]),
            occurred_at=str(value["occurred_at"]),
            details=dict(value["details"]),
        )


def _write_result(output: Path, result: PhaseResult) -> PhaseResult:
    output.mkdir(parents=True, exist_ok=True)
    (output / f"phase-{result.phase}.json").write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def _strict_json_object(data: bytes) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("snapshot metadata contains a duplicate JSON field")
            value[key] = item
        return value

    def invalid_constant(value: str) -> None:
        raise ValueError(f"snapshot metadata contains an invalid JSON number: {value}")

    value = json.loads(
        data,
        object_pairs_hook=object_pairs,
        parse_constant=invalid_constant,
    )
    if not isinstance(value, dict):
        raise TypeError("snapshot metadata must be a JSON object")
    return value


def _validate_snapshot_set(snapshot_root: Path, registry: SourceRegistry) -> list[dict[str, Any]]:
    if snapshot_root.is_symlink() or not snapshot_root.is_dir():
        raise ValueError("materialized snapshot set is not a real directory")
    expected = {spec.source_id: spec for spec in registry.network_sources()}
    if not expected:
        raise ValueError("network collection has no authorized HTTPS sources")
    summaries: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    for metadata_path in sorted(snapshot_root.glob("*/*/metadata.json")):
        metadata_bytes = read_bounded_regular_file(
            metadata_path,
            maximum=MAX_FILE_BYTES,
            name="snapshot metadata",
        )
        total_bytes += len(metadata_bytes)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("snapshot set exceeds the total size limit")
        metadata = _strict_json_object(metadata_bytes)
        required = {
            "source_id",
            "canonical_url",
            "status",
            "content_type",
            "etag",
            "last_modified",
            "retrieved_at",
            "rights_posture",
            "sha256",
            "bytes",
        }
        if not isinstance(metadata, dict) or set(metadata) != required:
            raise ValueError("snapshot metadata fields do not match the collector schema")
        source_id = str(metadata["source_id"])
        if source_id in seen or source_id not in expected:
            raise ValueError("snapshot source is duplicate or not registry-authorized")
        spec = expected[source_id]
        digest = str(metadata["sha256"])
        if metadata_path.parent.name != digest or metadata_path.parent.parent.name != source_id:
            raise ValueError("snapshot path does not match its source and digest")
        siblings = sorted(metadata_path.parent.iterdir())
        if any(path.is_symlink() or not path.is_file() for path in siblings):
            raise ValueError("snapshot directory entries must be regular files")
        body_paths = [path for path in siblings if path.name != "metadata.json"]
        if len(siblings) != 2 or len(body_paths) != 1:
            raise ValueError("snapshot directory must contain one body and one metadata file")
        body_path = body_paths[0]
        body = read_bounded_regular_file(
            body_path,
            maximum=MAX_FILE_BYTES,
            name="snapshot body",
        )
        total_bytes += len(body)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("snapshot set exceeds the total size limit")
        size = metadata["bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size != len(body):
            raise ValueError("snapshot byte count does not match its body")
        if sha256_bytes(body) != digest:
            raise ValueError("snapshot digest does not match its body")
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(metadata["retrieved_at"], str)
            or not metadata["retrieved_at"]
            or not isinstance(metadata["content_type"], str)
            or metadata["etag"] is not None
            and not isinstance(metadata["etag"], str)
            or metadata["last_modified"] is not None
            and not isinstance(metadata["last_modified"], str)
            or isinstance(metadata["status"], bool)
            or not isinstance(metadata["status"], int)
        ):
            raise ValueError("snapshot metadata types or digest are invalid")
        if (
            metadata["canonical_url"] != spec.url
            or metadata["rights_posture"] != spec.asset_rights
            or metadata["status"] != 200
            or metadata["content_type"] not in TextSnapshotCollector.ALLOWED_TYPES
        ):
            raise ValueError("snapshot metadata does not match its authorized source")
        summaries.append(
            {
                "source_id": source_id,
                "retrieved_at": str(metadata["retrieved_at"]),
                "sha256": digest,
                "bytes": size,
                "content_type": str(metadata["content_type"]),
            }
        )
        seen.add(source_id)
    if seen != set(expected):
        raise ValueError("snapshot set does not contain every authorized HTTPS source exactly once")
    all_files: list[Path] = []
    for index, path in enumerate(snapshot_root.rglob("*"), start=1):
        if index > 512:
            raise ValueError("snapshot tree contains too many entries")
        if path.is_symlink():
            raise ValueError("snapshot tree cannot contain symbolic links")
        if path.is_file():
            all_files.append(path)
        elif not path.is_dir():
            raise ValueError("snapshot tree contains an unsupported entry type")
    if len(all_files) != len(summaries) * 2:
        raise ValueError("snapshot set contains unrecognized files")
    return summaries


def run_phase(
    phase: str,
    root: str | Path,
    output: str | Path,
    *,
    upstream_snapshot_dir: str | Path | None = None,
    upstream_registry_sha256: str | None = None,
) -> PhaseResult:
    if phase not in PHASE_ORDER:
        raise ValueError(f"unknown phase: {phase}")
    root_path = Path(root).resolve()
    output_path = Path(output).resolve()
    now = datetime.now(UTC).isoformat()

    if phase == "collect":
        registry_path = root_path / "config/sources.json"
        registry_bytes = read_bounded_regular_file(
            registry_path,
            maximum=MAX_FILE_BYTES,
            name="source registry",
        )
        registry = SourceRegistry.load(registry_path)
        if os.environ.get("ENABLE_NETWORK_COLLECTION", "false").casefold() != "true":
            return _write_result(output_path, PhaseResult(
                phase, "PASS", now,
                {"mode": "REGISTRY_VALIDATION", "authorized_sources": [spec.source_id for spec in registry.allowed()]},
            ))
        collector = TextSnapshotCollector(output_path / "snapshots")
        network_sources = sorted(
            registry.network_sources(),
            key=lambda spec: spec.source_id,
        )
        if not network_sources:
            return _write_result(
                output_path,
                PhaseResult(
                    phase,
                    "REJECT",
                    now,
                    {"reason": "network collection has no authorized HTTPS sources"},
                ),
            )
        snapshots = [collector.collect(spec) for spec in network_sources]
        return _write_result(
            output_path,
            PhaseResult(
                phase,
                "PASS",
                now,
                {
                    "mode": "NETWORK_SNAPSHOT",
                    "source_registry_sha256": sha256_bytes(registry_bytes),
                    "snapshots": [snapshot.to_portable_dict() for snapshot in snapshots],
                },
            ),
        )

    if phase == "reconcile":
        if _env_bool("ENABLE_NETWORK_COLLECTION"):
            if upstream_snapshot_dir is None:
                return _write_result(
                    output_path,
                    PhaseResult(
                        phase,
                        "REJECT",
                        now,
                        {"reason": "immutable collect artifact is required in network mode"},
                    ),
                )
            registry_path = root_path / "config/sources.json"
            try:
                registry_bytes = read_bounded_regular_file(
                    registry_path,
                    maximum=MAX_FILE_BYTES,
                    name="source registry",
                )
                if upstream_registry_sha256 != sha256_bytes(registry_bytes):
                    raise ValueError("collect artifact source registry does not match this release")
                verified_snapshots = _validate_snapshot_set(
                    Path(upstream_snapshot_dir),
                    SourceRegistry.load(registry_path),
                )
            except ArtifactUnavailableError:
                raise
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                return _write_result(
                    output_path,
                    PhaseResult(
                        phase,
                        "REJECT",
                        now,
                        {
                            "reason": "immutable collect artifact failed validation",
                            "error": type(exc).__name__,
                        },
                    ),
                )
            return _write_result(
                output_path,
                PhaseResult(
                    phase,
                    "HOLD",
                    now,
                    {
                        "reason": "live_claim_extraction_not_implemented",
                        "snapshots_verified": len(verified_snapshots),
                    },
                    ),
                )
        claims = load_claims(root_path / "data/claims/seed_claims.jsonl")
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

    claims = load_claims(root_path / "data/claims/seed_claims.jsonl")
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
