from __future__ import annotations

import json
import os
import secrets
import stat
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .canonical import sha256_bytes, sha256_json
from .models import Claim, ClaimState
from .pilots import PilotOrder, PilotOrderState, load_verified_order_manifest
from .pipeline import load_claims
from .provenance import SourceRecord, load_sources, validate_source_bindings
from .source_registry import SourceRegistry

PUBLISHABLE_STATES = frozenset(
    {ClaimState.CONFIRMED, ClaimState.OBSERVED, ClaimState.REPORTED, ClaimState.INFERRED}
)
STATE_ORDER = (
    ClaimState.CONFIRMED,
    ClaimState.OBSERVED,
    ClaimState.REPORTED,
    ClaimState.INFERRED,
)


def _absolute_unresolved(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _prepare_private_destination(path: Path, label: str) -> None:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    if path.parent.is_symlink():
        raise ValueError(f"{label} parent must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not path.is_file():
        raise ValueError(f"{label} must be a regular file path")


def _stage_private_bytes(path: Path, data: bytes, label: str) -> Path:
    """Create and fsync one owner-only temporary file beside its destination."""
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = -1
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(temporary, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            if (
                os.name == "posix"
                and stat.S_IMODE(os.fstat(handle.fileno()).st_mode) != 0o600
            ):
                raise OSError(f"{label} permissions could not be restricted to 0600")
        return temporary
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _private_backup(path: Path) -> Path:
    """Create a restricted hard-link backup without replacing an existing path."""
    while True:
        backup = path.with_name(f".{path.name}.{secrets.token_hex(8)}.bak")
        try:
            os.link(path, backup, follow_symlinks=False)
        except FileExistsError:
            continue
        try:
            os.chmod(backup, 0o600)
        except OSError:
            backup.unlink(missing_ok=True)
            raise
        return backup


def _write_private_files(files: Iterable[tuple[Path, bytes, str]]) -> None:
    """Stage a private file set, then replace it with rollback on commit failure."""
    rows = tuple(files)
    destinations = [path for path, _, _ in rows]
    if len(destinations) != len(set(destinations)):
        raise ValueError("private output destinations must be different files")
    for path, _, label in rows:
        _prepare_private_destination(path, label)

    staged: dict[Path, Path] = {}
    backups: dict[Path, Path] = {}
    committed: list[Path] = []
    try:
        for path, data, label in rows:
            staged[path] = _stage_private_bytes(path, data, label)
        for path in destinations:
            if path.exists():
                backups[path] = _private_backup(path)
        try:
            for path in destinations:
                os.replace(staged[path], path)
                committed.append(path)
        except BaseException as commit_error:
            rollback_error: OSError | None = None
            for path in reversed(committed):
                try:
                    backup = backups.get(path)
                    if backup is None:
                        path.unlink(missing_ok=True)
                    else:
                        os.replace(backup, path)
                        backups.pop(path, None)
                except OSError as exc:
                    rollback_error = exc
            if rollback_error is not None:
                raise OSError("private output rollback failed") from commit_error
            raise
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
        for backup in backups.values():
            backup.unlink(missing_ok=True)


def _selected_claims(claims: list[Claim], claim_ids: Iterable[str]) -> list[Claim]:
    requested = tuple(dict.fromkeys(str(value).strip() for value in claim_ids if str(value).strip()))
    if not requested:
        raise ValueError("at least one claim ID is required")
    claim_map = {claim.claim_id: claim for claim in claims}
    unknown = sorted(set(requested) - set(claim_map))
    if unknown:
        raise ValueError(f"unknown claim IDs: {unknown}")
    blocked = [
        claim_id for claim_id in requested if claim_map[claim_id].state not in PUBLISHABLE_STATES
    ]
    if blocked:
        raise ValueError(f"non-publishable claim IDs: {blocked}")
    return [claim_map[claim_id] for claim_id in requested]


def _display_text(value: object, field: str, *, maximum: int) -> str:
    normalized = " ".join(str(value).replace("\u2014", "-").split())
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    if len(normalized) > maximum:
        raise ValueError(f"{field} must be no more than {maximum} characters")
    return normalized


def _source_line(source: SourceRecord) -> str:
    publisher = _display_text(source.publisher, "source publisher", maximum=200)
    source_title = _display_text(source.title, "source title", maximum=500)
    label = f"{publisher} - {source_title} ({source.source_id})"
    if source.url.startswith("https://"):
        return f"- [{label}]({source.url}) · {source.source_tier}"
    return f"- {label} · {source.source_tier} · internal provider snapshot"


def _scoped_claim_ids(
    claim_ids: Iterable[str] | None,
    order: PilotOrder | None,
) -> tuple[str, ...]:
    requested = tuple(claim_ids or ())
    if order is None:
        return requested
    allowed_states = {
        PilotOrderState.FULFILLMENT_STARTED,
        PilotOrderState.ARTIFACT_COMPLETED,
        PilotOrderState.DELIVERED,
    }
    if order.state not in allowed_states:
        raise ValueError(
            "order manifest must contain a fulfillment-started or delivered order"
        )
    if requested and requested != order.claim_ids:
        raise ValueError("claim IDs must exactly match the confirmed order scope")
    return order.claim_ids


def _provenance_manifest_bytes(
    *,
    artifact_sha256: str,
    order: PilotOrder | None,
    claim_ids: list[str],
    source_ids: list[str],
) -> tuple[str, bytes]:
    scope: dict[str, object] | None = None
    if order is not None:
        scope = {
            "order_id": order.order_id,
            "scope_ref": order.scope_ref,
            "state": order.state.value,
            "deadline": order.deadline,
            "terms_version": order.terms_version,
        }
    body: dict[str, object] = {
        "schema_version": 1,
        "artifact": {
            "media_type": "text/markdown",
            "sha256": artifact_sha256,
        },
        "scope": scope,
        "claim_ids": claim_ids,
        "source_ids": source_ids,
    }
    manifest_sha256 = sha256_json(body)
    envelope = {**body, "manifest_sha256": manifest_sha256}
    encoded = (
        json.dumps(envelope, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode(
        "utf-8"
    )
    return manifest_sha256, encoded


def build_creator_brief(
    root: str | Path,
    output: str | Path,
    *,
    title: str,
    claim_ids: Iterable[str] | None = None,
    angles: Iterable[str] = (),
    audience: str = "gaming creators",
    order_manifest: str | Path | None = None,
    pilot_ledger: str | Path | None = None,
    manifest_output: str | Path | None = None,
) -> dict[str, Any]:
    """Render a deterministic, source-linked research brief for a creator pilot."""
    root_path = Path(root).resolve()
    output_path = _absolute_unresolved(output)
    title_text = _display_text(title, "title", maximum=200)
    audience_text = _display_text(audience, "audience", maximum=200)
    if order_manifest is not None and pilot_ledger is None:
        raise ValueError("pilot ledger is required with an order manifest")
    if order_manifest is None and pilot_ledger is not None:
        raise ValueError("order manifest is required with a pilot ledger")
    order = (
        load_verified_order_manifest(order_manifest, pilot_ledger)
        if order_manifest is not None and pilot_ledger is not None
        else None
    )
    scoped_claim_ids = _scoped_claim_ids(claim_ids, order)
    claims = load_claims(root_path / "data/claims/seed_claims.jsonl")
    sources = load_sources(root_path / "data/sources/seed_sources.jsonl")
    registry = SourceRegistry.load(root_path / "config/sources.json")
    issues = validate_source_bindings(claims, sources, registry=registry)
    if issues:
        raise ValueError(f"source validation failed: {issues}")

    selected = _selected_claims(claims, scoped_claim_ids)
    source_map = {source.source_id: source for source in sources}
    source_ids = tuple(
        dict.fromkeys(source_id for claim in selected for source_id in claim.source_ids)
    )
    selected_sources = [source_map[source_id] for source_id in source_ids]
    checked_dates = sorted(
        {
            source.retrieved_at[:10]
            for source in selected_sources
            if source.retrieved_at and len(source.retrieved_at) >= 10
        }
    )
    checked_at = checked_dates[-1] if checked_dates else "not recorded"

    selected_entities = {entity.casefold() for claim in selected for entity in claim.entities}
    held = [
        claim
        for claim in claims
        if claim.state in {ClaimState.PENDING, ClaimState.REJECTED}
        and selected_entities.intersection(entity.casefold() for entity in claim.entities)
    ]
    normalized_angles = tuple(
        dict.fromkeys(
            _display_text(value, "angle", maximum=500)
            for value in angles
            if str(value).strip()
        )
    )

    grouped: dict[ClaimState, list[Claim]] = defaultdict(list)
    for claim in selected:
        grouped[claim.state].append(claim)

    lines = [
        f"# {title_text}",
        "",
        f"**Audience:** {audience_text}  ",
        f"**Last evidence check:** {checked_at}  ",
        "**Product:** ReMediaLHQ Creator Signal Desk sample",
        "",
        "## Safe-to-say evidence",
        "",
    ]
    for state in STATE_ORDER:
        state_claims = grouped.get(state, [])
        if not state_claims:
            continue
        lines.extend([f"### {state.value.title()}", ""])
        for claim in state_claims:
            lines.append(
                f"- {claim.public_wording} `[{claim.claim_id}; {', '.join(claim.source_ids)}]`"
            )
        lines.append("")

    lines.extend(
        [
            "## Ready-to-develop angles",
            "",
            "These are editorial pitches, not additional factual claims. Recheck the linked evidence before publication.",
            "",
        ]
    )
    if normalized_angles:
        lines.extend(f"{index}. {angle}" for index, angle in enumerate(normalized_angles, 1))
    else:
        lines.append("- Add creator-specific angles after reviewing the channel, audience, and format.")

    lines.extend(["", "## Do not overstate", ""])
    if held:
        lines.extend(
            f"- {claim.public_wording} `[{claim.claim_id}; {claim.state.value}]`" for claim in held
        )
    else:
        lines.append(
            "- Do not convert an observed or inferred point into a confirmed feature, date, or performance promise."
        )

    lines.extend(["", "## Source pack", ""])
    lines.extend(_source_line(source) for source in selected_sources)
    lines.extend(
        [
            "",
            "## Use boundary",
            "",
            "This brief supplies original summaries, claim states, and source links. It does not license third-party footage, artwork, music, trademarks, or other media. ReMediaLHQ is independent and is not affiliated with or endorsed by Rockstar Games or Take-Two Interactive.",
            "",
        ]
    )

    encoded = ("\n".join(lines).replace("\u2014", "-") + "\n").encode("utf-8")
    provenance_path = (
        _absolute_unresolved(manifest_output)
        if manifest_output is not None
        else output_path.with_suffix(output_path.suffix + ".provenance.json")
    )
    if provenance_path == output_path:
        raise ValueError("brief output and provenance manifest must be different files")
    protected_inputs = {
        _absolute_unresolved(value)
        for value in (order_manifest, pilot_ledger)
        if value is not None
    }
    if output_path in protected_inputs or provenance_path in protected_inputs:
        raise ValueError("brief outputs must not overwrite the order manifest or pilot ledger")
    artifact_sha256 = sha256_bytes(encoded)
    provenance_sha256, provenance_data = _provenance_manifest_bytes(
        artifact_sha256=artifact_sha256,
        order=order,
        claim_ids=[claim.claim_id for claim in selected],
        source_ids=list(source_ids),
    )
    _write_private_files(
        (
            (output_path, encoded, "brief output"),
            (provenance_path, provenance_data, "provenance manifest"),
        )
    )
    return {
        "output": str(output_path),
        "provenance_manifest": str(provenance_path),
        "artifact_sha256": artifact_sha256,
        "provenance_sha256": provenance_sha256,
        "title": title_text,
        "checked_at": checked_at,
        "claim_ids": [claim.claim_id for claim in selected],
        "source_ids": list(source_ids),
        "held_claim_ids": [claim.claim_id for claim in held],
        "angles": len(normalized_angles),
    }
