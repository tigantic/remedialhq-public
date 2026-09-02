from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from .contact_evidence import (
    MAX_PRIVATE_FILE_BYTES,
    ContactEvidenceError,
    read_private_file,
)


class OutreachDraftError(ValueError):
    """Raised when private campaign sources cannot produce safe draft packets."""


DRAFT_SCHEMA_VERSION: Final = "remedialhq.outreach-drafts.v2"
SALES_ANGLE_SCHEMA_VERSION: Final = "remedialhq.sales-angles.v1"
OWNER_PROFILE_SCHEMA_VERSION: Final = 1
SAMPLE_URL: Final = "https://remedialhq.com/sample-creator-brief"
SUPPORT_EMAIL: Final = "support@remedialhq.com"
_CHANNELS: Final = {
    "BUSINESS_EMAIL",
    "CONTACT_FORM",
    "SOCIAL_DM",
    "OTHER_PUBLIC_BUSINESS_CHANNEL",
}
_ANGLE_FIELDS: Final = {"prospect_id", "queue_position", "customer_facing_angle"}
_INTERNAL_PITCH_LANGUAGE: Final = re.compile(
    r"\b(?:eviden\w*|verif\w*|validat\w*|unresolved|claims?|audit\w*|"
    r"correction\w*|sourc\w*|citat\w*|provenance|attribut\w*|substantiat\w*|"
    r"corroborat\w*|cross[ -]?check\w*|fact[ -]?check\w*|confidence label|"
    r"infer\w*|confirm\w*|proof|defensible|safe headline)\b",
    re.IGNORECASE,
)
_EMAIL_LIKE: Final = re.compile(
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
    re.IGNORECASE,
)
_URL_OR_DOMAIN_LIKE: Final = re.compile(
    r"(?:\b(?:https?://|www\.|mailto:)|"
    r"\b[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+\b)",
    re.IGNORECASE,
)
_PHONE_LIKE: Final = re.compile(
    r"(?<!\d)(?:\+?1[ .()-]*)?(?:\(?\d{3}\)?[ .-]*)\d{3}[ .-]*\d{4}(?!\d)"
)
_POSTAL_ADDRESS_LIKE: Final = re.compile(
    r"\b\d{1,6}\s+[A-Z0-9][A-Z0-9 .'-]{1,80}\s"
    r"(?:STREET|ST|ROAD|RD|AVENUE|AVE|BOULEVARD|BLVD|DRIVE|DR|LANE|LN|"
    r"COURT|CT|WAY|PARKWAY|PKWY)\b",
    re.IGNORECASE,
)
_OWNER_PROFILE_FIELDS: Final = {
    "schema_version",
    "classification",
    "reported_at",
    "legal_name",
    "birthdate",
    "address",
    "phone_e164",
    "phone_display",
    "root_google_email",
    "domain",
    "youtube_handle",
    "brand",
}
_OWNER_ADDRESS_FIELDS: Final = {"line1", "city", "state", "postal_code", "country"}


def _object(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise OutreachDraftError(f"{field_name} must be an object")
    result = dict(value)
    if any(not isinstance(key, str) for key in result):
        raise OutreachDraftError(f"{field_name} keys must be strings")
    return result


def _array(value: object, field_name: str) -> list[object]:
    if not isinstance(value, list):
        raise OutreachDraftError(f"{field_name} must be an array")
    return value


def _text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OutreachDraftError(f"{field_name} must be a non-empty string")
    normalized = value.replace("\u2014", " - ").replace("\u2013", "-")
    normalized = " ".join(normalized.split())
    if any(ord(character) < 32 for character in normalized):
        raise OutreachDraftError(f"{field_name} contains a control character")
    return normalized


def _integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise OutreachDraftError(f"{field_name} must be an integer")
    return value


def _read_json(path: Path) -> dict[str, object]:
    return _read_json_with_digest(path)[0]


def _read_json_with_digest(path: Path) -> tuple[dict[str, object], str]:
    try:
        raw = read_private_file(path, maximum_bytes=MAX_PRIVATE_FILE_BYTES)
        value: object = json.loads(raw.decode("utf-8"))
    except (
        ContactEvidenceError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise OutreachDraftError(f"could not read valid JSON from {path}") from exc
    return _object(value, str(path)), hashlib.sha256(raw).hexdigest()


def _owner_identity_terms(path: Path) -> tuple[tuple[str, ...], str, str]:
    document, digest = _read_json_with_digest(path)
    if set(document) != _OWNER_PROFILE_FIELDS:
        raise OutreachDraftError("owner profile has missing or unknown fields")
    if document.get("schema_version") != OWNER_PROFILE_SCHEMA_VERSION:
        raise OutreachDraftError("owner profile schema is not supported")
    legal_name = _text(document.get("legal_name"), "owner profile legal_name")
    birthdate = _text(document.get("birthdate"), "owner profile birthdate")
    root_email = _text(document.get("root_google_email"), "owner profile root_google_email")
    phone_e164 = _text(document.get("phone_e164"), "owner profile phone_e164")
    phone_display = _text(document.get("phone_display"), "owner profile phone_display")
    address = _object(document.get("address"), "owner profile address")
    if set(address) != _OWNER_ADDRESS_FIELDS:
        raise OutreachDraftError("owner profile address has missing or unknown fields")

    birthdate_digits = "".join(character for character in birthdate if character.isdigit())
    birthdate_variants = {birthdate, birthdate_digits}
    if len(birthdate_digits) == 8:
        birthdate_variants.add(
            birthdate_digits[4:6] + birthdate_digits[6:8] + birthdate_digits[:4]
        )

    candidates = {
        legal_name,
        *birthdate_variants,
        root_email,
        phone_e164,
        phone_display,
        *legal_name.split(),
    }
    for field in ("line1", "city", "postal_code"):
        candidates.add(_text(address.get(field), f"owner profile address.{field}"))
    postal_footer = "\n".join(
        (
            _text(address.get("line1"), "owner profile address.line1"),
            (
                f'{_text(address.get("city"), "owner profile address.city")}, '
                f'{_text(address.get("state"), "owner profile address.state")} '
                f'{_text(address.get("postal_code"), "owner profile address.postal_code")}'
            ),
            _text(address.get("country"), "owner profile address.country"),
        )
    )
    normalized = tuple(
        sorted(
            {
                " ".join(candidate.casefold().split())
                for candidate in candidates
                if len("".join(character for character in candidate if character.isalnum())) >= 3
            },
            key=lambda item: (-len(item), item),
        )
    )
    return normalized, digest, postal_footer


def _contains_owner_identity(angle: str, terms: Sequence[str]) -> bool:
    normalized_angle = " ".join(angle.casefold().split())
    compact_digits = "".join(character for character in angle if character.isdigit())
    for term in terms:
        if term in normalized_angle:
            return True
        term_digits = "".join(character for character in term if character.isdigit())
        if len(term_digits) >= 5 and term_digits in compact_digits:
            return True
    return False


def _sales_angles(
    path: Path,
    *,
    campaign_ref: str,
    expected_count: int,
    prohibited_identity_terms: Sequence[str],
) -> tuple[dict[str, tuple[int, str]], str]:
    document, digest = _read_json_with_digest(path)
    if set(document) != {
        "schema_version",
        "campaign_ref",
        "generated_at",
        "prospect_count",
        "privacy_boundary",
        "angles",
    }:
        raise OutreachDraftError("sales angle packet has missing or unknown fields")
    if document.get("schema_version") != SALES_ANGLE_SCHEMA_VERSION:
        raise OutreachDraftError("sales angle packet schema is not supported")
    if document.get("campaign_ref") != campaign_ref:
        raise OutreachDraftError("sales angle packet campaign does not match the cohort")
    if document.get("prospect_count") != expected_count:
        raise OutreachDraftError("sales angle packet count does not match the cohort")
    _text(document.get("generated_at"), "sales angles generated_at")
    _text(document.get("privacy_boundary"), "sales angles privacy_boundary")
    records = _array(document.get("angles"), "angles")
    if len(records) != expected_count:
        raise OutreachDraftError("sales angle packet does not contain the expected records")

    result: dict[str, tuple[int, str]] = {}
    normalized_angles: set[str] = set()
    for index, raw_record in enumerate(records, start=1):
        record = _object(raw_record, "angles[]")
        if set(record) != _ANGLE_FIELDS:
            raise OutreachDraftError("sales angle record has missing or unknown fields")
        prospect_id = _text(record.get("prospect_id"), "angles[].prospect_id")
        position = _integer(record.get("queue_position"), "angles[].queue_position")
        if position != index:
            raise OutreachDraftError("sales angle positions must be contiguous and ordered")
        angle = _text(
            record.get("customer_facing_angle"),
            "angles[].customer_facing_angle",
        )
        word_count = len(angle.split())
        if not 8 <= word_count <= 28:
            raise OutreachDraftError("customer-facing angle must contain 8 through 28 words")
        if angle[-1] not in ".!?":
            raise OutreachDraftError("customer-facing angle must end with punctuation")
        if _INTERNAL_PITCH_LANGUAGE.search(angle):
            raise OutreachDraftError("customer-facing angle contains internal pitch language")
        if (
            _EMAIL_LIKE.search(angle)
            or _URL_OR_DOMAIN_LIKE.search(angle)
            or _PHONE_LIKE.search(angle)
            or _POSTAL_ADDRESS_LIKE.search(angle)
            or _contains_owner_identity(angle, prohibited_identity_terms)
        ):
            raise OutreachDraftError("customer-facing angle contains prohibited identity data")
        normalized = angle.casefold()
        if prospect_id in result or normalized in normalized_angles:
            raise OutreachDraftError("sales angle packet contains a duplicate")
        result[prospect_id] = (position, angle)
        normalized_angles.add(normalized)
    return result, digest


def _atomic_private_write(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    if parent_mode != 0o700:
        raise OutreachDraftError(
            f"private output directory must have mode 0700, found {parent_mode:04o}"
        )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
        path.chmod(0o600)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _qualifying_work(record: dict[str, object]) -> tuple[str, str]:
    for key in ("qualifying_gta_vi_item", "qualifying_work"):
        if key not in record:
            continue
        work = _object(record[key], key)
        return _text(work.get("title"), f"{key}.title"), _text(
            work.get("url"), f"{key}.url"
        )
    raise OutreachDraftError("prospect has no qualifying work")


def _sample_insight(record: dict[str, object]) -> tuple[str, list[str]]:
    if "personalized_sample_insight" in record:
        value = record["personalized_sample_insight"]
        if isinstance(value, Mapping):
            insight = _object(value, "personalized_sample_insight")
            source_values = insight.get("source_urls", [])
            sources = [
                _text(item, "personalized_sample_insight.source_urls[]")
                for item in _array(source_values, "personalized_sample_insight.source_urls")
            ]
            return _text(insight.get("text"), "personalized_sample_insight.text"), sources
        return _text(value, "personalized_sample_insight"), []
    return _text(record.get("sample_insight"), "sample_insight"), []


def _short_subject(title: str) -> str:
    prefix = "GTA VI follow-up idea: "
    limit = 78 - len(prefix)
    if len(title) <= limit:
        return f"{prefix}{title}"
    shortened = title[: limit - 3].rsplit(" ", 1)[0].rstrip(" ,:;-")
    return f"{prefix}{shortened}..."


def _greeting(name: str, segment: str, *, editorial_team: bool) -> str:
    if editorial_team or segment in {"NEWSLETTER", "PODCAST"} or any(
        marker in name.lower()
        for marker in ("media", "gamer", "gaming", "chronicle", "informer", "ign")
    ):
        return f"Hi {name} team,"
    return f"Hi {name},"


def _email_body(
    name: str,
    segment: str,
    title: str,
    angle: str,
    *,
    editorial_team: bool,
) -> str:
    return "\n\n".join(
        (
            _greeting(name, segment, editorial_team=editorial_team),
            (
                f'Your recent GTA VI piece, "{title}," made me think of a useful next piece: '
                f"{angle}"
            ),
            (
                "I run ReMediaL HQ, a research desk for creators covering GTA VI. The $99 "
                "founding pilot gives you 14 days of support on one active story: what changed, "
                "three angles worth using, and one rumor checked before you publish."
            ),
            f"Here is the sample: {SAMPLE_URL}",
            (
                "If you have a GTA VI piece in progress, send the topic and deadline. If this is "
                "not useful, reply no and I will not follow up."
            ),
            f"ReMediaL HQ\n{SUPPORT_EMAIL}",
        )
    )


def _dm_body(name: str, title: str, angle: str) -> str:
    return (
        f'Hi {name}, your GTA VI piece, "{title}," made me think of a useful next piece: '
        f"{angle} I run ReMediaL HQ, a research desk for creators covering GTA VI. The "
        f"$99 founding pilot gives you 14 days of support on one active story. Sample: "
        f"{SAMPLE_URL} If you have a piece in progress, send the topic and deadline. If "
        "this is not useful, say no and I will not follow up."
    )


def _draft(
    cohort_record: dict[str, object],
    source_record: dict[str, object],
    customer_facing_angle: str,
    prohibited_identity_terms: Sequence[str],
    postal_footer: str,
) -> dict[str, object]:
    prospect_id = _text(cohort_record.get("prospect_id"), "prospect_id")
    name = _text(cohort_record.get("prospect_name"), "prospect_name")
    queue_position = _integer(cohort_record.get("queue_position"), "queue_position")
    planned_date = _text(cohort_record.get("planned_contact_date"), "planned_contact_date")
    channel = _text(cohort_record.get("channel"), "channel")
    if channel not in _CHANNELS:
        raise OutreachDraftError(f"unsupported channel for {prospect_id}")
    segment = _text(cohort_record.get("segment"), "segment")
    route = _object(cohort_record.get("public_business_route"), "public_business_route")
    route_url = _text(route.get("url"), "public_business_route.url")
    title, work_url = _qualifying_work(source_record)
    insight, insight_sources = _sample_insight(source_record)
    hypothesis = _text(
        source_record.get("specific_upcoming_piece_hypothesis"),
        "specific_upcoming_piece_hypothesis",
    )
    source_type_value = source_record.get("prospect_type")
    source_type = (
        _text(source_type_value, "prospect_type") if source_type_value is not None else ""
    )
    editorial_team = source_type in {
        "CONSOLE_EDITORIAL_TEAM",
        "GAMING_EDITORIAL_TEAM",
        "INDEPENDENT_PUBLICATION",
    }
    subject = _short_subject(title)
    body_without_postal_footer = (
        _dm_body(name, title, customer_facing_angle)
        if channel == "SOCIAL_DM"
        else _email_body(
            name,
            segment,
            title,
            customer_facing_angle,
            editorial_team=editorial_team,
        )
    )
    if "\u2014" in subject or "\u2014" in body_without_postal_footer:
        raise OutreachDraftError("generated copy contains an em dash")
    if _contains_owner_identity(subject, prohibited_identity_terms) or _contains_owner_identity(
        body_without_postal_footer, prohibited_identity_terms
    ):
        raise OutreachDraftError("generated customer-facing copy contains owner identity data")
    body = (
        body_without_postal_footer
        if channel == "SOCIAL_DM"
        else f"{body_without_postal_footer}\n{postal_footer}"
    )
    return {
        "prospect_id": prospect_id,
        "queue_position": queue_position,
        "planned_contact_date": planned_date,
        "prospect_name": name,
        "segment": segment,
        "channel": channel,
        "public_business_route": route_url,
        "subject": subject,
        "body": body,
        "recent_work": {"title": title, "url": work_url},
        "fit_hypothesis": hypothesis,
        "customer_facing_angle": customer_facing_angle,
        "research_note": insight,
        "insight_source_urls": sorted(set(insight_sources)),
        "draft_status": "READY_FOR_SEND_DAY_RECHECK",
        "send_requirements": [
            "Reverify the public business route on the planned contact date.",
            "Record a CLEAR suppression check less than 24 hours before contact.",
            "Confirm the private sender profile adds the approved commercial postal footer.",
            "Send only through the planned public business channel.",
            "Record contact only after the message was actually sent.",
        ],
    }


def build_draft_packet(
    cohort_path: Path,
    batch_paths: Sequence[Path],
    angle_path: Path,
    owner_profile_path: Path,
    *,
    expected_count: int = 50,
    generated_at: str | None = None,
) -> dict[str, object]:
    cohort = _read_json(cohort_path)
    cohort_records = _array(cohort.get("prospects"), "prospects")
    if len(cohort_records) != expected_count:
        raise OutreachDraftError(
            f"cohort must contain {expected_count} prospects, found {len(cohort_records)}"
        )
    campaign_ref = _text(cohort.get("campaign_ref"), "campaign_ref")
    prohibited_identity_terms, owner_profile_sha256, postal_footer = _owner_identity_terms(
        owner_profile_path
    )
    sales_angles, sales_angles_sha256 = _sales_angles(
        angle_path,
        campaign_ref=campaign_ref,
        expected_count=expected_count,
        prohibited_identity_terms=prohibited_identity_terms,
    )
    source_index: dict[tuple[str, str], dict[str, object]] = {}
    for batch_path in batch_paths:
        batch = _read_json(batch_path)
        for raw_record in _array(batch.get("prospects"), f"{batch_path}.prospects"):
            record = _object(raw_record, f"{batch_path}.prospects[]")
            name = _text(record.get("prospect_name"), "prospect_name")
            key = (batch_path.name, name)
            if key in source_index:
                raise OutreachDraftError(f"duplicate source record for {name}")
            source_index[key] = record

    drafts: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_positions: set[int] = set()
    for raw_cohort_record in cohort_records:
        cohort_record = _object(raw_cohort_record, "prospects[]")
        prospect_id = _text(cohort_record.get("prospect_id"), "prospect_id")
        name = _text(cohort_record.get("prospect_name"), "prospect_name")
        batch_name = _text(cohort_record.get("source_batch"), "source_batch")
        position = _integer(cohort_record.get("queue_position"), "queue_position")
        if prospect_id in seen_ids or position in seen_positions:
            raise OutreachDraftError("cohort contains a duplicate ID or queue position")
        seen_ids.add(prospect_id)
        seen_positions.add(position)
        try:
            source_record = source_index[(batch_name, name)]
        except KeyError as exc:
            raise OutreachDraftError(f"missing source record for {name}") from exc
        try:
            angle_position, customer_facing_angle = sales_angles[prospect_id]
        except KeyError as exc:
            raise OutreachDraftError(
                f"missing customer-facing angle for {prospect_id}"
            ) from exc
        if angle_position != position:
            raise OutreachDraftError("sales angle queue position does not match the cohort")
        drafts.append(
            _draft(
                cohort_record,
                source_record,
                customer_facing_angle,
                prohibited_identity_terms,
                postal_footer,
            )
        )

    drafts.sort(key=lambda item: _integer(item["queue_position"], "queue_position"))
    if seen_positions != set(range(1, expected_count + 1)):
        raise OutreachDraftError("queue positions must be contiguous")
    timestamp = generated_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    daily_counts: dict[str, int] = {}
    for draft in drafts:
        planned_date = str(draft["planned_contact_date"])
        daily_counts[planned_date] = daily_counts.get(planned_date, 0) + 1
    return {
        "schema_version": DRAFT_SCHEMA_VERSION,
        "generated_at": timestamp,
        "campaign_ref": campaign_ref,
        "sales_angles_sha256": sales_angles_sha256,
        "owner_profile_sha256": owner_profile_sha256,
        "postal_footer_sha256": hashlib.sha256(postal_footer.encode("utf-8")).hexdigest(),
        "postal_footer_included_for_email": True,
        "outreach_sent": False,
        "prospect_count": len(drafts),
        "daily_counts": dict(sorted(daily_counts.items())),
        "privacy_boundary": (
            "Identity-bearing owner-private campaign artifact. Keep at mode 0600 outside Git."
        ),
        "drafts": drafts,
    }


def render_markdown(packet: dict[str, object]) -> str:
    drafts = _array(packet.get("drafts"), "drafts")
    lines = [
        "# Creator Signal Desk Private Outreach Packet",
        "",
        "Owner-private. Drafts only. No message was sent by generation.",
        "",
    ]
    for raw_draft in drafts:
        draft = _object(raw_draft, "drafts[]")
        lines.extend(
            (
                f"## {draft['queue_position']}. {draft['prospect_name']}",
                "",
                f"- Planned date: {draft['planned_contact_date']}",
                f"- Channel: {draft['channel']}",
                f"- Route: {draft['public_business_route']}",
                f"- Subject: {draft['subject']}",
                "",
                str(draft["body"]),
                "",
            )
        )
    return "\n".join(lines).rstrip() + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="build owner-private outreach drafts")
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument("--batch", required=True, action="append", type=Path)
    parser.add_argument("--angles", required=True, type=Path)
    parser.add_argument("--owner-profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--markdown-output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    packet = build_draft_packet(
        arguments.cohort,
        arguments.batch,
        arguments.angles,
        arguments.owner_profile,
    )
    _atomic_private_write(
        arguments.output,
        json.dumps(packet, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
    )
    if arguments.markdown_output is not None:
        _atomic_private_write(arguments.markdown_output, render_markdown(packet))
    print(
        json.dumps(
            {
                "drafts": packet["prospect_count"],
                "outreach_sent": False,
                "output": str(arguments.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
