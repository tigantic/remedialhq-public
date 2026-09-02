from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import html
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .contact_evidence import (
    MAX_PRIVATE_FILE_BYTES,
    ContactEvidenceError,
    private_file_sha256,
    read_private_file,
)
from .outreach import OutreachPlan
from .pilots import PILOT_LEDGER_SCHEMA_VERSION, PilotLedger, SuppressionStatus

SCHEMA_VERSION = "remedialhq.campaign-preflight.v3"
SENDER_SCHEMA_VERSION = "remedialhq.sender-profile-preflight.v2"
MAX_SENDER_PREFLIGHT_AGE_HOURS = 24
MAX_ROUTE_EVIDENCE_AGE_HOURS = 24 * 7
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROSPECT_ID_RE = re.compile(r"^prs_[0-9a-f]{32}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ROUTE_SCHEMA_VERSION = "remedialhq.resolved-routes.v3"
_ROUTE_VALIDATION = "CREATOR_PUBLISHED_BUSINESS_INQUIRY_ADDRESS"
_ROUTE_EVIDENCE_SCHEMA_VERSION = "remedialhq.route-evidence.v1"
_ROUTE_EVIDENCE_VALIDATION = "REPRODUCIBLE_CREATOR_PUBLISHED_BUSINESS_INQUIRY_ADDRESS"
_SALES_ANGLE_SCHEMA_VERSION = "remedialhq.sales-angles.v1"
_ROUTE_ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_date",
        "created_at",
        "privacy",
        "cohort_record_count",
        "verified_route_count",
        "channel_compatible_route_count",
        "channel_amendment_candidate_count",
        "unresolved_count",
        "send_authorized_now",
        "routes",
        "unresolved",
    }
)
_ROUTE_FIELDS = frozenset(
    {
        "prospect_id",
        "public_business_email",
        "evidence_url",
        "creator_link_source_url",
        "observed_at",
        "evidence_sha256",
        "evidence_artifact_path",
        "evidence_artifact_sha256",
        "validation",
        "campaign_channel",
        "channel_compatible",
        "channel_blocker",
    }
)
_ROUTE_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_date",
        "capture_method",
        "captured_source_byte_count",
        "captured_source_sha256",
        "cohort_public_business_route_url_sha256",
        "creator_link_source_url",
        "evidence_url",
        "imported_campaign_channel",
        "observed_at",
        "prospect_id",
        "published_address",
        "source_excerpt",
        "source_excerpt_sha256",
        "transport_excerpt_base64",
        "transport_excerpt_byte_count",
        "transport_excerpt_sha256",
        "validation",
    }
)
_CAPTURE_METHOD_FIELDS = frozenset(
    {
        "capture_url",
        "http_status",
        "kind",
        "request_authentication",
        "response_content_type",
        "steps",
    }
)
_CAPTURE_STEPS = {
    "HTML_META_DESCRIPTION": (
        "decode official response bytes as UTF-8 with replacement",
        "parse HTML meta description content",
        "HTML-unescape the content value",
        "select the minimal substring containing the address and business label",
    ),
    "JSON_STRING_LITERAL": (
        "decode official response bytes as UTF-8 with replacement",
        "parse a JSON string literal from the official response",
        "select the minimal substring containing the address and business label",
    ),
    "HTML_LITERAL_CONTEXT": (
        "decode official response bytes as UTF-8 with replacement",
        "HTML-unescape text and unescape JSON forward slashes",
        "select the minimal literal substring containing the address and business label",
    ),
    "CLOUDFLARE_DATA_CFEMAIL_XOR": (
        "locate the data-cfemail hexadecimal transport attribute",
        "XOR every encoded byte with the first decoded key byte",
        "insert the decoded address beside the exact transport token",
        "select the minimal substring containing the address and business label",
    ),
}
_SALES_ANGLE_ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_ref",
        "generated_at",
        "prospect_count",
        "privacy_boundary",
        "angles",
    }
)
_SALES_ANGLE_FIELDS = frozenset({"prospect_id", "queue_position", "customer_facing_angle"})
_FOOTER_SOURCE_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_ref",
        "checked_at",
        "commercial_postal_address_present",
        "owner_profile_path",
        "owner_profile_sha256",
        "privacy_boundary",
    }
)
_OWNER_PROFILE_FIELDS = frozenset(
    {
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
)
_OWNER_ADDRESS_FIELDS = frozenset({"line1", "city", "state", "postal_code", "country"})
_BUSINESS_CONTEXT_RE = re.compile(
    r"\b(?:business|biz|sales|contact|editorial|press|partnerships?|"
    r"advertising|e-?mail|inquiries|enquiries)\b",
    re.IGNORECASE,
)
_CFEMAIL_RE = re.compile(r"data-cfemail=[\"']?([0-9a-fA-F]+)")
_UNRESOLVED_ROUTE_FIELDS = frozenset(
    {"prospect_id", "campaign_channel", "blocker_code", "observed_at"}
)
_ROUTE_BLOCKERS = frozenset(
    {
        "AUTHENTICATED_YOUTUBE_REQUIRED",
        "NO_EXPLICIT_BUSINESS_INQUIRY_EMAIL_FOUND",
        "NO_EXPLICIT_PUBLIC_BUSINESS_EMAIL",
        "BUSINESS_PURPOSE_NOT_EXPLICIT",
        "BUSINESS_ROUTE_IS_CONTACT_FORM_ONLY",
        "EMAIL_NOT_LABELED_FOR_BUSINESS_INQUIRIES",
        "DUPLICATE_SHARED_TEAM_INBOX",
    }
)
_SENDER_CAPABILITY_CHECK = (
    "gmail.list_labels plus self-addressed sender and external support-route delivery tests"
)
_SENDER_REQUIREMENT = (
    "Use the verified ReMediaL HQ display name on the authorized primary branded mailbox "
    "and the verified support reply route. Do not claim the support address as a Gmail "
    "send-as alias until Google authorizes it."
)
_POSTAL_FOOTER_REQUIREMENT = (
    "Confirm the private sender profile adds the approved commercial postal footer."
)


class CampaignPreflightError(ValueError):
    """Raised when the private campaign packet is not safe to use."""


def run_preflight(
    private_dir: str | Path,
    *,
    as_of: str | None = None,
) -> dict[str, object]:
    """Validate the private campaign packet and return aggregate facts only."""
    root = Path(private_dir)
    observed_at = _as_of_timestamp(as_of)
    paths = {
        "plan": root / "outreach/creator-desk-plan.json",
        "cohort": root / "outreach/qualified-prospect-cohort.json",
        "drafts": root / "outreach/creator-desk-drafts.json",
        "sales_angles": root / "outreach/creator-desk-sales-angles.json",
        "footer_source": root / "outreach/sender-footer-source.json",
        "owner_profile": root / "owner/owner_profile.private.json",
        "readiness": root / "outreach/september-03-batch-readiness.json",
        "sender_profile": root / "outreach/sender-profile-preflight-2026-09-02.json",
        "ledger": root / "pilot-events.jsonl",
        "ledger_lock": root / ".pilot-events.jsonl.lock",
    }
    json_names = (
        "plan",
        "cohort",
        "drafts",
        "sales_angles",
        "footer_source",
        "owner_profile",
        "readiness",
        "sender_profile",
    )
    json_files = {name: _private_json_with_digest(paths[name]) for name in json_names}
    digests = {name: value[1] for name, value in json_files.items()}
    for name in ("ledger", "ledger_lock"):
        digests[name] = private_file_sha256(paths[name], maximum_bytes=MAX_PRIVATE_FILE_BYTES)
    documents = {name: value[0] for name, value in json_files.items()}
    plan = OutreachPlan.from_dict(documents["plan"])
    if not plan.is_complete:
        raise CampaignPreflightError("outreach plan is not complete")

    cohort = documents["cohort"]
    drafts = documents["drafts"]
    sales_angles = documents["sales_angles"]
    footer_source = documents["footer_source"]
    owner_profile = documents["owner_profile"]
    readiness = documents["readiness"]
    sender = documents["sender_profile"]
    _require(
        cohort.get("schema_version") == "remedialhq.qualified-prospect-cohort.v1",
        "cohort schema is not supported",
    )
    _require(
        drafts.get("schema_version") == "remedialhq.outreach-drafts.v2",
        "draft schema is not supported",
    )
    _require(
        readiness.get("schema_version") == "remedialhq.outreach-readiness.v1",
        "readiness schema is not supported",
    )

    campaign_ref = plan.campaign_ref
    for name, document in (
        ("cohort", cohort),
        ("drafts", drafts),
        ("readiness", readiness),
        ("sender", sender),
    ):
        _require(
            document.get("campaign_ref") == campaign_ref, f"{name} campaign does not match the plan"
        )
    for name, document in (
        ("cohort", cohort),
        ("drafts", drafts),
        ("readiness", readiness),
        ("sender", sender),
    ):
        _require(document.get("outreach_sent") is False, f"{name} falsely reports outreach")

    plan_ids = [item.prospect_id for item in plan.prospects]
    cohort_ids = _ordered_ids(cohort, "prospects")
    draft_ids = _ordered_ids(drafts, "drafts")
    _require(
        plan_ids == cohort_ids == draft_ids,
        "plan, cohort, and drafts do not have the same ordered prospects",
    )
    _require(cohort.get("prospect_count") == 50, "cohort must declare exactly 50 prospects")
    _require(drafts.get("prospect_count") == 50, "draft packet must declare exactly 50 prospects")
    cohort_route_urls = _cohort_public_route_urls(cohort, plan_ids)
    _validate_sales_angles(
        plan,
        sales_angles,
        drafts,
        expected_digest=digests["sales_angles"],
        observed_at=observed_at,
    )
    postal_footer_digest = _validate_owner_profile_binding(
        root,
        plan,
        footer_source,
        owner_profile,
        drafts,
        owner_profile_digest=digests["owner_profile"],
        observed_at=observed_at,
    )

    route_dates = sorted({item.planned_contact_date for item in plan.prospects})
    route_paths = {
        contact_date: root / f"outreach/resolved-routes-{contact_date}.json"
        for contact_date in route_dates
    }
    route_files = {
        contact_date: _private_json_with_digest(path) for contact_date, path in route_paths.items()
    }
    route_digests = {contact_date: value[1] for contact_date, value in route_files.items()}
    route_report = _validate_resolved_routes(
        plan,
        {contact_date: value[0] for contact_date, value in route_files.items()},
        cohort_route_urls=cohort_route_urls,
        evidence_directory=root / "outreach/route-evidence",
        observed_at=observed_at,
    )

    integrity = _object(readiness.get("campaign_integrity"), "campaign_integrity")
    summary = _object(readiness.get("summary"), "summary")
    _require(integrity.get("prospect_count") == 50, "readiness prospect count is not 50")
    _require(summary.get("planned_records") == 10, "first send-day batch is not exactly 10")
    _require(integrity.get("contacts_recorded") == 0, "readiness report already records contact")
    _require(integrity.get("plan_file_sha256") == digests["plan"], "readiness plan digest is stale")
    _require(
        integrity.get("cohort_file_sha256") == digests["cohort"], "readiness cohort digest is stale"
    )
    _require(
        integrity.get("draft_packet_sha256") == digests["drafts"], "readiness draft digest is stale"
    )

    sender_checked_at = _validate_sender(sender)
    sender_age = observed_at - sender_checked_at
    _require(
        timedelta(0) <= sender_age <= timedelta(hours=MAX_SENDER_PREFLIGHT_AGE_HOURS),
        "branded sender capability check is missing, future-dated, or stale",
    )

    ledger = PilotLedger(paths["ledger"])
    verified, verification_message = ledger.verify()
    _require(verified, "pilot ledger hash chain is invalid")
    metrics = ledger.metrics()
    _require(metrics.prospects == 50, "pilot ledger does not contain the 50-prospect campaign")
    local_date = (observed_at + timedelta(minutes=plan.utc_offset_minutes)).date()
    campaign_day_two = datetime.fromisoformat(plan.campaign_start).date() + timedelta(days=1)
    if local_date <= campaign_day_two:
        _require(metrics.contacted == 0, "contact was recorded before campaign day 3")
    queue = ledger.outreach_queue(as_of=observed_at.isoformat())
    fresh_clear_checks = sum(item.suppression_status is SuppressionStatus.CLEAR for item in queue)
    contacts_with_verified_evidence = sum(
        item.contacted_at is not None and item.contact_evidence_status == "VERIFIED"
        for item in queue
    )
    _require(
        contacts_with_verified_evidence == metrics.contacted,
        "one or more campaign contacts lack verified post-send evidence",
    )
    contact_allowed_now = sum(item.contact_allowed for item in queue)

    first_send_date = min(item.planned_contact_date for item in plan.prospects)
    first_batch_size = sum(item.planned_contact_date == first_send_date for item in plan.prospects)
    _require(first_batch_size == 10, "first send-day batch is not exactly 10")
    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at": observed_at.isoformat().replace("+00:00", "Z"),
        "status": "PASS_PREPARED_NOT_SEND_AUTHORIZED",
        "send_authorized_now": False,
        "outreach_sent_by_preflight": False,
        "private_storage": {
            "files_checked": (
                len(paths)
                + len(route_paths)
                + _integer(route_report["evidence_artifacts"], "evidence_artifacts")
            ),
            "all_files_mode_0600": True,
            "route_evidence_directory_mode_0700": True,
        },
        "packet": {
            "prospects": len(plan.prospects),
            "drafts": len(draft_ids),
            "first_send_date": first_send_date,
            "first_send_day_records": first_batch_size,
            "ordered_crosswalk_matches": True,
            "readiness_hashes_current": True,
            "sales_angle_binding_matches": True,
            "sales_angles_sha256": digests["sales_angles"],
            "owner_profile_binding_matches": True,
            "owner_profile_sha256": digests["owner_profile"],
            "required_postal_footer_sha256": postal_footer_digest,
            "postal_footer_body_binding_matches": True,
        },
        "sender": {
            "branded_account_match": True,
            "callable_read_verified": True,
            "explicit_connection_pin_required": True,
            "connection_reference_stored_only_as_sha256": True,
            "sender_profile_evidence_sha256": digests["sender_profile"],
            "capability_check_age_minutes": round(sender_age.total_seconds() / 60, 1),
        },
        "suppression": {
            "fresh_clear_checks_recorded": fresh_clear_checks,
            "contact_allowed_now": contact_allowed_now,
            "freshness_hours": 24,
            "evidence_observed_at_required": True,
        },
        "routes": {
            **route_report,
            "file_sha256": dict(sorted(route_digests.items())),
        },
        "ledger": {
            "schema_version": PILOT_LEDGER_SCHEMA_VERSION,
            "verification": verification_message,
            "records_contacted": metrics.contacted,
            "contacts_with_verified_post_send_evidence": contacts_with_verified_evidence,
            "false_contacts_detected": 0,
        },
        "post_send_contract": {
            "provider_confirmed_send_required": True,
            "redacted_provider_evidence_required": True,
            "exact_sender_profile_digest_required": True,
            "latest_suppression_digest_required": True,
            "exact_postal_footer_digest_required": True,
            "record_within_minutes": 15,
            "record_before_send_allowed": False,
        },
    }


def _validate_sender(document: Mapping[str, object]) -> datetime:
    _require(
        document.get("schema_version") == SENDER_SCHEMA_VERSION,
        "sender preflight schema is not supported",
    )
    sender_identity = _object(document.get("sender_identity"), "sender_identity")
    connection = _object(document.get("gmail_connection"), "gmail_connection")
    _require(
        sender_identity.get("status") == "CALLABLE_VERIFIED",
        "branded sender was not callably verified",
    )
    _require(
        sender_identity.get("authenticated_account_match") is True,
        "Gmail account does not match the required branded sender",
    )
    sender_digests = (
        _digest(sender_identity.get("required_sender_sha256"), "required_sender_sha256"),
        _digest(
            sender_identity.get("required_from_header_sha256"),
            "required_from_header_sha256",
        ),
        _digest(
            sender_identity.get("required_reply_to_sha256"),
            "required_reply_to_sha256",
        ),
    )
    _require(
        len(set(sender_digests)) == len(sender_digests),
        "sender identity digests must be distinct",
    )
    _require(
        sender_identity.get("display_name_verified") is True,
        "branded display name was not verified",
    )
    _require(
        sender_identity.get("support_reply_route_verified") is True,
        "support Reply-To route was not verified",
    )
    _require(
        sender_identity.get("support_send_as_alias_verified") is False,
        "sender profile must not claim the unsupported send-as alias",
    )
    _require(
        sender_identity.get("requirement") == _SENDER_REQUIREMENT,
        "sender profile requirement is not supported",
    )
    _require(
        connection.get("status") == "CALLABLE_VERIFIED", "Gmail connection is not callably verified"
    )
    _require(
        connection.get("selection_mode") == "EXPLICIT_PIN_REQUIRED",
        "Gmail connection selection is not fail-closed",
    )
    _digest(connection.get("selected_connection_ref_sha256"), "selected_connection_ref_sha256")
    _require(
        connection.get("raw_connection_ref_retained_here") is False,
        "raw Gmail connection reference must not be retained",
    )
    capability_check = connection.get("capability_check")
    _require(
        capability_check == _SENDER_CAPABILITY_CHECK,
        "Gmail capability check is not supported",
    )
    _require(
        connection.get("capability_check_succeeded") is True,
        "Gmail capability check did not succeed",
    )
    _require(
        connection.get("connection_changed") is False, "preflight must not change Gmail connections"
    )
    return _required_timestamp(document.get("checked_at"), "sender checked_at")


def _cohort_public_route_urls(
    cohort: Mapping[str, object],
    expected_ids: Sequence[str],
) -> dict[str, str]:
    records = _list(cohort.get("prospects"), "prospects")
    _require(
        len(records) == len(expected_ids),
        "cohort route crosswalk does not match the campaign",
    )
    result: dict[str, str] = {}
    for index, (raw_record, expected_id) in enumerate(
        zip(records, expected_ids, strict=True), start=1
    ):
        record = _object(raw_record, f"prospects[{index}]")
        _require(
            record.get("prospect_id") == expected_id,
            "cohort route crosswalk is not in plan order",
        )
        public_route = _object(
            record.get("public_business_route"),
            f"prospects[{index}].public_business_route",
        )
        result[expected_id] = _https_url(
            public_route.get("url"),
            f"prospects[{index}].public_business_route.url",
        )
    return result


def _validate_sales_angles(
    plan: OutreachPlan,
    document: Mapping[str, object],
    drafts: Mapping[str, object],
    *,
    expected_digest: str,
    observed_at: datetime,
) -> None:
    packet = _object(document, "sales angles")
    _exact_fields(packet, _SALES_ANGLE_ROOT_FIELDS, "sales angle packet")
    _require(
        packet.get("schema_version") == _SALES_ANGLE_SCHEMA_VERSION,
        "sales angle packet schema is not supported",
    )
    _require(
        packet.get("campaign_ref") == plan.campaign_ref,
        "sales angle packet campaign does not match the plan",
    )
    _fresh_route_timestamp(
        packet.get("generated_at"),
        "sales angle generated_at",
        observed_at,
    )
    _nonempty_text(packet.get("privacy_boundary"), "sales angle privacy boundary")
    _exact_count(
        packet.get("prospect_count"),
        len(plan.prospects),
        "sales angle prospect_count",
    )
    _require(
        drafts.get("sales_angles_sha256") == expected_digest,
        "draft packet sales angle digest is stale",
    )
    angles = _list(packet.get("angles"), "angles")
    draft_records = _list(drafts.get("drafts"), "drafts")
    _require(
        len(angles) == len(plan.prospects) == len(draft_records),
        "sales angle records do not cover the campaign",
    )

    normalized_angles: set[str] = set()
    for index, (prospect, raw_angle, raw_draft) in enumerate(
        zip(plan.prospects, angles, draft_records, strict=True), start=1
    ):
        angle = _object(raw_angle, f"angles[{index}]")
        _exact_fields(angle, _SALES_ANGLE_FIELDS, "sales angle")
        _require(
            angle.get("prospect_id") == prospect.prospect_id,
            "sales angle prospect does not match the ordered plan",
        )
        _exact_count(
            angle.get("queue_position"),
            prospect.queue_position,
            "sales angle queue_position",
        )
        copy = _nonempty_text(
            angle.get("customer_facing_angle"),
            "customer_facing_angle",
        )
        _require(
            8 <= len(copy.split()) <= 28,
            "customer-facing angle must contain 8 through 28 words",
        )
        normalized = copy.casefold()
        _require(
            normalized not in normalized_angles,
            "sales angle packet contains duplicate customer copy",
        )
        normalized_angles.add(normalized)

        draft = _object(raw_draft, f"drafts[{index}]")
        _require(
            draft.get("prospect_id") == prospect.prospect_id
            and draft.get("queue_position") == prospect.queue_position
            and draft.get("customer_facing_angle") == copy,
            "draft copy is not bound to the exact sales angle record",
        )


def _validate_owner_profile_binding(
    private_root: Path,
    plan: OutreachPlan,
    footer_source: Mapping[str, object],
    owner_profile: Mapping[str, object],
    drafts: Mapping[str, object],
    *,
    owner_profile_digest: str,
    observed_at: datetime,
) -> str:
    footer = _object(footer_source, "sender footer source")
    _exact_fields(footer, _FOOTER_SOURCE_FIELDS, "sender footer source")
    _require(
        footer.get("schema_version") == "remedialhq.sender-footer-source.v1",
        "sender footer source schema is not supported",
    )
    _require(
        footer.get("campaign_ref") == plan.campaign_ref,
        "sender footer source campaign does not match the plan",
    )
    checked_at = _required_timestamp(
        footer.get("checked_at"),
        "sender footer checked_at",
    )
    age = observed_at - checked_at
    _require(
        timedelta(0) <= age <= timedelta(hours=MAX_SENDER_PREFLIGHT_AGE_HOURS),
        "sender footer source is future-dated or stale",
    )
    _require(
        footer.get("commercial_postal_address_present") is True,
        "sender footer source does not attest a commercial postal address",
    )
    _nonempty_text(footer.get("privacy_boundary"), "sender footer privacy boundary")
    expected_owner_path = private_root.absolute() / "owner/owner_profile.private.json"
    _require(
        footer.get("owner_profile_path") == os.fspath(expected_owner_path),
        "sender footer source does not select the exact private owner profile",
    )
    _require(
        footer.get("owner_profile_sha256") == owner_profile_digest,
        "sender footer source owner profile digest is stale",
    )
    _require(
        drafts.get("owner_profile_sha256") == owner_profile_digest,
        "draft packet owner profile digest is stale",
    )

    profile = _object(owner_profile, "owner profile")
    _exact_fields(profile, _OWNER_PROFILE_FIELDS, "owner profile")
    _exact_count(profile.get("schema_version"), 1, "owner profile schema_version")
    _require(
        profile.get("classification") == "LOCAL_PRIVATE_DO_NOT_COMMIT",
        "owner profile classification is not private",
    )
    _required_timestamp(profile.get("reported_at"), "owner profile reported_at")
    for field_name in (
        "legal_name",
        "birthdate",
        "phone_e164",
        "phone_display",
        "root_google_email",
        "domain",
        "youtube_handle",
        "brand",
    ):
        _nonempty_text(profile.get(field_name), f"owner profile {field_name}")
    address = _object(profile.get("address"), "owner profile address")
    _exact_fields(address, _OWNER_ADDRESS_FIELDS, "owner profile address")
    for field_name in _OWNER_ADDRESS_FIELDS:
        _nonempty_text(address.get(field_name), f"owner profile address.{field_name}")
    canonical_footer = "\n".join(
        (
            str(address["line1"]),
            f"{address['city']}, {address['state']} {address['postal_code']}",
            str(address["country"]),
        )
    )
    postal_footer_digest = hashlib.sha256(canonical_footer.encode("utf-8")).hexdigest()
    _require(
        drafts.get("postal_footer_sha256") == postal_footer_digest,
        "draft packet postal footer digest is stale",
    )
    _require(
        drafts.get("postal_footer_included_for_email") is True,
        "draft packet does not require the postal footer in email copy",
    )

    draft_records = _list(drafts.get("drafts"), "drafts")
    _require(
        len(draft_records) == len(plan.prospects),
        "draft packet does not cover the postal-footer contract",
    )
    for prospect, raw_draft in zip(plan.prospects, draft_records, strict=True):
        draft = _object(raw_draft, "drafts[]")
        requirements = _list(draft.get("send_requirements"), "draft send_requirements")
        channel = _nonempty_text(draft.get("channel"), "draft channel")
        body = _verbatim_text(draft.get("body"), "draft body")
        _require(
            draft.get("prospect_id") == prospect.prospect_id
            and channel == prospect.channel
            and _POSTAL_FOOTER_REQUIREMENT in requirements,
            "draft is not bound to the send-time postal-footer requirement",
        )
        if channel == "SOCIAL_DM":
            _require(
                canonical_footer not in body,
                "social DM copy must not include the email postal footer",
            )
        else:
            _require(
                body.endswith(f"\n{canonical_footer}") and body.count(canonical_footer) == 1,
                "email-style draft body is not bound to the exact postal footer",
            )
    return postal_footer_digest


def _validate_resolved_routes(
    plan: OutreachPlan,
    documents: Mapping[str, Mapping[str, object]],
    *,
    cohort_route_urls: Mapping[str, str],
    evidence_directory: Path,
    observed_at: datetime,
) -> dict[str, object]:
    planned_by_id = {
        item.prospect_id: (item.planned_contact_date, item.channel) for item in plan.prospects
    }
    planned_by_date: dict[str, set[str]] = {}
    for prospect_id, (contact_date, _) in planned_by_id.items():
        planned_by_date.setdefault(contact_date, set()).add(prospect_id)
    _require(
        set(documents) == set(planned_by_date),
        "resolved route files do not match the planned contact dates",
    )
    _require(
        set(cohort_route_urls) == set(planned_by_id),
        "cohort route URL crosswalk does not cover the campaign",
    )
    evidence_files = _private_directory_entries(evidence_directory)

    all_ids: set[str] = set()
    normalized_emails: set[str] = set()
    referenced_evidence: set[Path] = set()
    daily: dict[str, dict[str, int]] = {}
    verified_total = 0
    compatible_total = 0
    amendment_total = 0
    unresolved_total = 0
    for contact_date in sorted(planned_by_date):
        document = _object(documents[contact_date], f"routes[{contact_date}]")
        _exact_fields(document, _ROUTE_ROOT_FIELDS, "resolved route document")
        _require(
            document.get("schema_version") == _ROUTE_SCHEMA_VERSION,
            "resolved route schema is not supported",
        )
        _require(
            document.get("campaign_date") == contact_date,
            "resolved route campaign date does not match its file",
        )
        _fresh_route_timestamp(
            document.get("created_at"),
            "route file created_at",
            observed_at,
        )
        _nonempty_text(document.get("privacy"), "route privacy boundary")
        routes = _list(document.get("routes"), "routes")
        unresolved = _list(document.get("unresolved"), "unresolved")
        expected_count = len(planned_by_date[contact_date])
        _exact_count(
            document.get("cohort_record_count"),
            expected_count,
            "cohort_record_count",
        )
        _exact_count(
            document.get("verified_route_count"),
            len(routes),
            "verified_route_count",
        )
        _exact_count(
            document.get("unresolved_count"),
            len(unresolved),
            "unresolved_count",
        )
        _exact_count(
            document.get("send_authorized_now"),
            0,
            "send_authorized_now",
        )

        date_ids: set[str] = set()
        compatible_count = 0
        amendment_count = 0
        for raw_route in routes:
            route = _object(raw_route, "routes[]")
            _exact_fields(route, _ROUTE_FIELDS, "resolved route")
            prospect_id = _route_prospect(
                route,
                planned_by_id,
                contact_date,
                date_ids,
            )
            campaign_channel = _nonempty_text(
                route.get("campaign_channel"),
                "campaign_channel",
            )
            _require(
                campaign_channel == planned_by_id[prospect_id][1],
                "resolved route campaign channel does not match the imported plan",
            )
            email = _nonempty_text(
                route.get("public_business_email"),
                "public_business_email",
            )
            _require(
                _EMAIL_RE.fullmatch(email) is not None,
                "resolved route has an invalid business email",
            )
            normalized_email = email.casefold()
            _require(
                normalized_email not in normalized_emails,
                "resolved route files contain a duplicate business destination",
            )
            normalized_emails.add(normalized_email)
            _https_url(route.get("evidence_url"), "evidence_url")
            _https_url(
                route.get("creator_link_source_url"),
                "creator_link_source_url",
            )
            _fresh_route_timestamp(
                route.get("observed_at"),
                "route observed_at",
                observed_at,
            )
            _digest(route.get("evidence_sha256"), "evidence_sha256")
            _validate_route_evidence(
                route,
                contact_date=contact_date,
                cohort_route_url=cohort_route_urls[prospect_id],
                evidence_directory=evidence_directory,
                available_files=evidence_files,
                referenced_files=referenced_evidence,
                observed_at=observed_at,
            )
            _require(
                route.get("validation") == _ROUTE_VALIDATION,
                "resolved route validation is not supported",
            )
            if route.get("channel_compatible") is True:
                _require(
                    campaign_channel == "BUSINESS_EMAIL" and route.get("channel_blocker") is None,
                    "channel-compatible route does not match BUSINESS_EMAIL",
                )
                compatible_count += 1
            else:
                _require(
                    route.get("channel_compatible") is False
                    and campaign_channel != "BUSINESS_EMAIL"
                    and route.get("channel_blocker") == "CAMPAIGN_CHANNEL_AMENDMENT_REQUIRED",
                    "channel-incompatible route is not safely blocked",
                )
                amendment_count += 1

        for raw_unresolved in unresolved:
            item = _object(raw_unresolved, "unresolved[]")
            _exact_fields(item, _UNRESOLVED_ROUTE_FIELDS, "unresolved route")
            prospect_id = _route_prospect(
                item,
                planned_by_id,
                contact_date,
                date_ids,
            )
            _require(
                item.get("campaign_channel") == planned_by_id[prospect_id][1],
                "unresolved route channel does not match the imported plan",
            )
            _require(
                item.get("blocker_code") in _ROUTE_BLOCKERS,
                "unresolved route blocker is not supported",
            )
            _fresh_route_timestamp(
                item.get("observed_at"),
                "unresolved route observed_at",
                observed_at,
            )

        _require(
            date_ids == planned_by_date[contact_date],
            "resolved route file does not cover its complete planned cohort",
        )
        _exact_count(
            document.get("channel_compatible_route_count"),
            compatible_count,
            "channel_compatible_route_count",
        )
        _exact_count(
            document.get("channel_amendment_candidate_count"),
            amendment_count,
            "channel_amendment_candidate_count",
        )
        all_ids.update(date_ids)
        verified_total += len(routes)
        compatible_total += compatible_count
        amendment_total += amendment_count
        unresolved_total += len(unresolved)
        daily[contact_date] = {
            "verified": len(routes),
            "channel_compatible": compatible_count,
            "channel_amendment_candidates": amendment_count,
            "unresolved": len(unresolved),
        }

    _require(
        all_ids == set(planned_by_id),
        "resolved route files do not cover the complete campaign cohort",
    )
    _require(
        _private_directory_entries(evidence_directory) == evidence_files,
        "route evidence directory changed during validation",
    )
    _require(
        referenced_evidence == evidence_files,
        "route evidence directory has missing, duplicate, or unreferenced artifacts",
    )
    return {
        "schema_version": _ROUTE_SCHEMA_VERSION,
        "evidence_schema_version": _ROUTE_EVIDENCE_SCHEMA_VERSION,
        "evidence_artifacts": len(referenced_evidence),
        "evidence_directory_mode_0700": True,
        "source_excerpt_digests_verified": True,
        "transport_excerpt_digests_verified": True,
        "published_business_routes_reproduced_from_transport": True,
        "captured_source_digest_inclusion_proof": False,
        "captured_source_metadata_is_attestation_only": True,
        "verified": verified_total,
        "unique_destinations": len(normalized_emails),
        "channel_compatible": compatible_total,
        "channel_amendment_candidates": amendment_total,
        "unresolved": unresolved_total,
        "send_authorized_now": False,
        "daily": daily,
    }


def _validate_route_evidence(
    route: Mapping[str, object],
    *,
    contact_date: str,
    cohort_route_url: str,
    evidence_directory: Path,
    available_files: set[Path],
    referenced_files: set[Path],
    observed_at: datetime,
) -> None:
    prospect_id = str(route["prospect_id"])
    expected_path = evidence_directory.absolute() / f"{prospect_id}.json"
    artifact_path_value = _nonempty_text(
        route.get("evidence_artifact_path"),
        "evidence_artifact_path",
    )
    _require(
        artifact_path_value == os.fspath(expected_path),
        "route evidence artifact path is not the exact private cohort path",
    )
    artifact_path = Path(artifact_path_value)
    _require(
        artifact_path in available_files,
        "route evidence artifact is not present in the private evidence directory",
    )
    _require(
        artifact_path not in referenced_files,
        "route evidence artifact is referenced more than once",
    )
    referenced_files.add(artifact_path)

    expected_artifact_digest = _digest(
        route.get("evidence_artifact_sha256"),
        "evidence_artifact_sha256",
    )
    try:
        raw_artifact = read_private_file(
            artifact_path,
            maximum_bytes=MAX_PRIVATE_FILE_BYTES,
        )
    except (ContactEvidenceError, OSError):
        raise CampaignPreflightError(
            "route evidence artifact failed private-file controls"
        ) from None
    _require(
        hashlib.sha256(raw_artifact).hexdigest() == expected_artifact_digest,
        "route evidence artifact digest does not match the route index",
    )
    artifact = _parse_private_json(raw_artifact)
    _exact_fields(artifact, _ROUTE_EVIDENCE_FIELDS, "route evidence artifact")
    _require(
        artifact.get("schema_version") == _ROUTE_EVIDENCE_SCHEMA_VERSION,
        "route evidence artifact schema is not supported",
    )
    _require(
        artifact.get("validation") == _ROUTE_EVIDENCE_VALIDATION,
        "route evidence validation is not supported",
    )

    exact_bindings = {
        "campaign_date": contact_date,
        "prospect_id": route["prospect_id"],
        "published_address": route["public_business_email"],
        "evidence_url": route["evidence_url"],
        "creator_link_source_url": route["creator_link_source_url"],
        "observed_at": route["observed_at"],
        "imported_campaign_channel": route["campaign_channel"],
    }
    for field_name, expected in exact_bindings.items():
        _require(
            artifact.get(field_name) == expected,
            f"route evidence {field_name} does not match the route index",
        )
    _fresh_route_timestamp(
        artifact.get("observed_at"),
        "route evidence observed_at",
        observed_at,
    )
    cohort_route_digest = hashlib.sha256(cohort_route_url.encode("utf-8")).hexdigest()
    _require(
        artifact.get("cohort_public_business_route_url_sha256") == cohort_route_digest,
        "route evidence is not bound to the cohort business-route URL",
    )

    address = _nonempty_text(artifact.get("published_address"), "published_address")
    _require(
        _EMAIL_RE.fullmatch(address) is not None,
        "route evidence has an invalid published address",
    )
    source_excerpt = _verbatim_text(
        artifact.get("source_excerpt"),
        "source_excerpt",
    )
    _require(
        address.casefold() in source_excerpt.casefold(),
        "source excerpt does not contain the published address",
    )
    _require(
        _BUSINESS_CONTEXT_RE.search(source_excerpt) is not None,
        "source excerpt does not include a business-contact label",
    )
    source_excerpt_digest = hashlib.sha256(source_excerpt.encode("utf-8")).hexdigest()
    _require(
        artifact.get("source_excerpt_sha256") == source_excerpt_digest,
        "source excerpt digest is not reproducible",
    )
    _require(
        route.get("evidence_sha256") == source_excerpt_digest,
        "route evidence digest is not bound to the source excerpt",
    )

    transport_value = _nonempty_text(
        artifact.get("transport_excerpt_base64"),
        "transport_excerpt_base64",
    )
    try:
        transport = base64.b64decode(transport_value, validate=True)
    except (binascii.Error, ValueError):
        raise CampaignPreflightError("transport excerpt is not canonical base64") from None
    _require(bool(transport), "transport excerpt must not be empty")
    _exact_count(
        artifact.get("transport_excerpt_byte_count"),
        len(transport),
        "transport_excerpt_byte_count",
    )
    _require(
        artifact.get("transport_excerpt_sha256") == hashlib.sha256(transport).hexdigest(),
        "transport excerpt digest is not reproducible",
    )
    captured_byte_count = artifact.get("captured_source_byte_count")
    _require(
        type(captured_byte_count) is int and captured_byte_count >= len(transport),
        "captured source byte count is smaller than its transport excerpt",
    )
    _digest(artifact.get("captured_source_sha256"), "captured_source_sha256")

    capture = _object(artifact.get("capture_method"), "capture_method")
    _exact_fields(capture, _CAPTURE_METHOD_FIELDS, "capture method")
    capture_url = _https_url(capture.get("capture_url"), "capture_url")
    evidence_url = str(route["evidence_url"])
    _require(
        _capture_url_matches(capture_url, evidence_url),
        "capture URL does not match the indexed evidence URL",
    )
    _exact_count(capture.get("http_status"), 200, "capture http_status")
    _require(
        capture.get("request_authentication") == "NONE",
        "route evidence must come from an unauthenticated public request",
    )
    response_content_type = _nonempty_text(
        capture.get("response_content_type"),
        "response_content_type",
    )
    _require(
        response_content_type.casefold().startswith("text/html"),
        "route evidence response must be HTML",
    )
    kind = _nonempty_text(capture.get("kind"), "capture kind")
    _require(
        kind in _CAPTURE_STEPS,
        "route evidence extraction kind is not supported",
    )
    steps = _list(capture.get("steps"), "capture steps")
    _require(
        tuple(steps) == _CAPTURE_STEPS[kind],
        "route evidence extraction steps do not match the declared kind",
    )
    _require(
        _transport_reproduces_source(
            kind,
            transport,
            address=address,
            source_excerpt=source_excerpt,
        ),
        "transport excerpt does not reproduce the published business route",
    )


def _capture_url_matches(capture_url: str, evidence_url: str) -> bool:
    if capture_url == evidence_url:
        return True
    capture = urlsplit(capture_url)
    evidence = urlsplit(evidence_url)
    interchangeable_hosts = {"x.com", "twitter.com", "www.x.com", "www.twitter.com"}
    return (
        capture.hostname in interchangeable_hosts
        and evidence.hostname in interchangeable_hosts
        and capture.path == evidence.path
        and capture.query == evidence.query
        and capture.fragment == evidence.fragment
    )


def _transport_reproduces_source(
    kind: str,
    transport: bytes,
    *,
    address: str,
    source_excerpt: str,
) -> bool:
    text = transport.decode("utf-8", errors="replace")
    address_folded = address.casefold()
    if kind == "HTML_META_DESCRIPTION":
        parser = _DescriptionParser()
        parser.feed(text)
        return any(
            source_excerpt in html.unescape(description)
            and address_folded in html.unescape(description).casefold()
            for description in parser.descriptions
        )
    if kind == "HTML_LITERAL_CONTEXT":
        decoded = html.unescape(text).replace(r"\/", "/")
        return source_excerpt in decoded and address_folded in decoded.casefold()
    if kind == "JSON_STRING_LITERAL":
        return any(
            address_folded in value.casefold()
            and _BUSINESS_CONTEXT_RE.search(unquote(value)) is not None
            for value in _decoded_json_strings(text)
        )
    if kind == "CLOUDFLARE_DATA_CFEMAIL_XOR":
        for match in _CFEMAIL_RE.finditer(text):
            encoded = match.group(1)
            if len(encoded) < 4 or len(encoded) % 2:
                continue
            try:
                payload = bytes.fromhex(encoded)
                decoded = bytes(byte ^ payload[0] for byte in payload[1:]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if decoded.casefold() != address_folded:
                continue
            insert_at = match.end(1)
            if text[insert_at : insert_at + 1] in {'"', "'"}:
                insert_at += 1
            reconstructed = html.unescape(f"{text[:insert_at]} {decoded}{text[insert_at:]}")
            if source_excerpt in reconstructed:
                return True
        return False
    return False


def _decoded_json_strings(text: str) -> list[str]:
    result: list[str] = []
    decoder = json.JSONDecoder()
    for index, character in enumerate(text[:-1]):
        if character != '"':
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except (json.JSONDecodeError, UnicodeError):
            continue
        if isinstance(value, str):
            result.append(value)
    return result


class _DescriptionParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.descriptions: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.casefold() != "meta":
            return
        values = {key.casefold(): value for key, value in attrs if key and value is not None}
        descriptor = values.get("name", values.get("property", "")).casefold()
        if descriptor in {"description", "og:description", "twitter:description"}:
            content = values.get("content")
            if content is not None:
                self.descriptions.append(content)


def _private_directory_entries(directory: Path) -> set[Path]:
    expected = directory.absolute()
    _reject_symlink_ancestors(expected)
    try:
        before = os.lstat(expected)
    except OSError:
        raise CampaignPreflightError("route evidence directory is unavailable") from None
    _require(
        not stat.S_ISLNK(before.st_mode) and stat.S_ISDIR(before.st_mode),
        "route evidence path must be a regular directory",
    )
    _require(
        stat.S_IMODE(before.st_mode) == 0o700,
        "route evidence directory must have mode 0700",
    )
    try:
        entries = {path.absolute() for path in expected.iterdir()}
        after = os.lstat(expected)
    except OSError:
        raise CampaignPreflightError("route evidence directory changed while listing") from None
    _require(
        _directory_snapshot(before) == _directory_snapshot(after),
        "route evidence directory changed while listing",
    )
    for entry in entries:
        try:
            metadata = os.lstat(entry)
        except OSError:
            raise CampaignPreflightError(
                "route evidence directory contains an unavailable entry"
            ) from None
        _require(
            not stat.S_ISLNK(metadata.st_mode)
            and stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and entry.suffix == ".json",
            "route evidence directory entries must be 0600 regular JSON files",
        )
    return entries


def _reject_symlink_ancestors(path: Path) -> None:
    for ancestor in reversed(path.parents):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            raise CampaignPreflightError("route evidence path is unavailable") from None
        _require(
            not stat.S_ISLNK(metadata.st_mode),
            "route evidence path must not use symlink ancestors",
        )


def _directory_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_mtime_ns,
    )


def _route_prospect(
    item: Mapping[str, object],
    planned_by_id: Mapping[str, tuple[str, str]],
    contact_date: str,
    date_ids: set[str],
) -> str:
    prospect_id = _nonempty_text(item.get("prospect_id"), "prospect_id")
    _require(
        _PROSPECT_ID_RE.fullmatch(prospect_id) is not None,
        "resolved route has an invalid opaque prospect ID",
    )
    _require(
        prospect_id in planned_by_id and planned_by_id[prospect_id][0] == contact_date,
        "resolved route prospect does not match the planned date",
    )
    _require(
        prospect_id not in date_ids,
        "resolved route file contains a duplicate prospect",
    )
    date_ids.add(prospect_id)
    return prospect_id


def _exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    field_name: str,
) -> None:
    _require(set(value) == set(expected), f"{field_name} has missing or unknown fields")


def _exact_count(value: object, expected: int, field_name: str) -> None:
    _require(
        type(value) is int and value == expected,
        f"{field_name} does not match the resolved route records",
    )


def _integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise CampaignPreflightError(f"{field_name} must be an integer")
    return value


def _list(value: object, field_name: str) -> list[object]:
    if not isinstance(value, list):
        raise CampaignPreflightError(f"{field_name} must be an array")
    return value


def _nonempty_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise CampaignPreflightError(f"{field_name} must be non-empty normalized text")
    return value


def _verbatim_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise CampaignPreflightError(f"{field_name} must be non-empty text")
    return value


def _https_url(value: object, field_name: str) -> str:
    url = _nonempty_text(value, field_name)
    parsed = urlsplit(url)
    _require(
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None,
        f"{field_name} must be an HTTPS URL without credentials",
    )
    return url


def _private_json(path: Path) -> dict[str, object]:
    raw = read_private_file(path, maximum_bytes=MAX_PRIVATE_FILE_BYTES)
    return _parse_private_json(raw)


def _private_json_with_digest(path: Path) -> tuple[dict[str, object], str]:
    raw = read_private_file(path, maximum_bytes=MAX_PRIVATE_FILE_BYTES)
    return _parse_private_json(raw), hashlib.sha256(raw).hexdigest()


def _parse_private_json(raw: bytes) -> dict[str, object]:
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (CampaignPreflightError, json.JSONDecodeError, UnicodeError):
        raise CampaignPreflightError("private campaign file is not valid strict JSON") from None
    return _object(document, "private campaign file")


def _ordered_ids(document: Mapping[str, object], field_name: str) -> list[str]:
    records = document.get(field_name)
    if not isinstance(records, list):
        raise CampaignPreflightError(f"{field_name} must be an array")
    result: list[str] = []
    for record in records:
        item = _object(record, field_name)
        prospect_id = item.get("prospect_id")
        if not isinstance(prospect_id, str):
            raise CampaignPreflightError(f"{field_name} has an invalid opaque ID")
        result.append(prospect_id)
    return result


def _object(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CampaignPreflightError(f"{field_name} must be an object")
    return dict(value)


def _digest(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CampaignPreflightError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _as_of_timestamp(value: object | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    return _required_timestamp(value, "as_of")


def _required_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise CampaignPreflightError(f"{field_name} must be a timezone-aware ISO value")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise CampaignPreflightError(f"{field_name} must be a valid ISO value") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CampaignPreflightError(f"{field_name} must include a timezone")
    return parsed.astimezone(UTC)


def _fresh_route_timestamp(
    value: object,
    field_name: str,
    observed_at: datetime,
) -> datetime:
    timestamp = _required_timestamp(value, field_name)
    age = observed_at - timestamp
    _require(
        timedelta(0) <= age <= timedelta(hours=MAX_ROUTE_EVIDENCE_AGE_HOURS),
        f"{field_name} is future-dated or stale",
    )
    return timestamp


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CampaignPreflightError("private campaign file contains duplicate fields")
        result[key] = value
    return result


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignPreflightError(message)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the owner-private campaign packet without sending outreach."
    )
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--as-of")
    args = parser.parse_args(argv)
    report = run_preflight(args.private_dir, as_of=args.as_of)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
