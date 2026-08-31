from __future__ import annotations

import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Final

from .canonical import sha256_json


class OutreachPlanError(ValueError):
    """Raised when an outreach plan violates the private import contract."""


OUTREACH_PLAN_SCHEMA_VERSION: Final = "remedialhq.outreach-plan.v1"
OUTREACH_TARGET_CONTACTS: Final = 50
OUTREACH_DAILY_CONTACT_LIMIT: Final = 10
OUTREACH_WINDOW_START_DAY: Final = 3
OUTREACH_WINDOW_END_DAY: Final = 7
OUTREACH_PLAN_MAX_BYTES: Final = 256 * 1024
SUPPRESSION_CLEAR_HOURS: Final = 24

_CAMPAIGN_REF_RE: Final = re.compile(r"^cmp_[0-9a-f]{32}$")
_PROSPECT_ID_RE: Final = re.compile(r"^prs_[0-9a-f]{32}$")
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_SEGMENTS: Final = {
    "GAMING_CREATOR",
    "ENTERTAINMENT_CREATOR",
    "NEWSLETTER",
    "PODCAST",
}
_CHANNELS: Final = {
    "BUSINESS_EMAIL",
    "CONTACT_FORM",
    "SOCIAL_DM",
    "OTHER_PUBLIC_BUSINESS_CHANNEL",
}
_ROOT_KEYS: Final = {
    "schema_version",
    "campaign_ref",
    "campaign_start",
    "campaign_end",
    "utc_offset_minutes",
    "daily_contact_limit",
    "controls",
    "prospects",
}
_CONTROL_KEYS: Final = {
    "sender_identification_ready",
    "sending_domain_authenticated",
    "postal_address_requirement_reviewed",
    "opt_out_process_ready",
    "evidence_sha256",
}
_PROSPECT_KEYS: Final = {
    "prospect_id",
    "queue_position",
    "segment",
    "channel",
    "planned_contact_date",
    "publishes_original_analysis",
    "specific_upcoming_piece",
    "public_business_channel_verified",
    "qualification_evidence_sha256",
    "recent_work_reference_sha256",
    "sample_insight_sha256",
}


def _fields(
    value: object,
    expected: set[str],
    field_name: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise OutreachPlanError(f"{field_name} must be an object")
    data = dict(value)
    if any(not isinstance(key, str) for key in data):
        raise OutreachPlanError(f"{field_name} keys must be strings")
    missing = expected - set(data)
    unexpected = set(data) - expected
    if missing:
        raise OutreachPlanError(
            f"{field_name} is missing fields: {', '.join(sorted(missing))}"
        )
    if unexpected:
        raise OutreachPlanError(f"{field_name} contains unexpected fields")
    return data


def _fixed_string(value: object, expected: str, field_name: str) -> str:
    if value != expected:
        raise OutreachPlanError(f"{field_name} must equal {expected}")
    return expected


def _pattern_string(
    value: object,
    pattern: re.Pattern[str],
    field_name: str,
) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise OutreachPlanError(f"{field_name} has an invalid format")
    return value


def _enum_string(value: object, allowed: set[str], field_name: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise OutreachPlanError(f"{field_name} is not supported")
    return value


def _canonical_date(value: object, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 10:
        raise OutreachPlanError(f"{field_name} must be a canonical ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise OutreachPlanError(f"{field_name} must be a canonical ISO date") from exc
    if parsed.isoformat() != value:
        raise OutreachPlanError(f"{field_name} must be a canonical ISO date")
    return value


def _integer(value: object, field_name: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OutreachPlanError(
            f"{field_name} must be an integer from {minimum} through {maximum}"
        )
    return value


def _required_true(value: object, field_name: str) -> bool:
    if value is not True:
        raise OutreachPlanError(f"{field_name} must be true")
    return True


def _sha256(value: object, field_name: str) -> str:
    return _pattern_string(value, _SHA256_RE, field_name)


@dataclass(frozen=True, slots=True)
class OutreachControls:
    sender_identification_ready: bool
    sending_domain_authenticated: bool
    postal_address_requirement_reviewed: bool
    opt_out_process_ready: bool
    evidence_sha256: str

    @classmethod
    def from_dict(cls, value: object) -> OutreachControls:
        data = _fields(value, _CONTROL_KEYS, "controls")
        return cls(
            sender_identification_ready=_required_true(
                data["sender_identification_ready"],
                "controls.sender_identification_ready",
            ),
            sending_domain_authenticated=_required_true(
                data["sending_domain_authenticated"],
                "controls.sending_domain_authenticated",
            ),
            postal_address_requirement_reviewed=_required_true(
                data["postal_address_requirement_reviewed"],
                "controls.postal_address_requirement_reviewed",
            ),
            opt_out_process_ready=_required_true(
                data["opt_out_process_ready"],
                "controls.opt_out_process_ready",
            ),
            evidence_sha256=_sha256(
                data["evidence_sha256"],
                "controls.evidence_sha256",
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "sender_identification_ready": self.sender_identification_ready,
            "sending_domain_authenticated": self.sending_domain_authenticated,
            "postal_address_requirement_reviewed": (
                self.postal_address_requirement_reviewed
            ),
            "opt_out_process_ready": self.opt_out_process_ready,
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True, slots=True)
class OutreachProspect:
    prospect_id: str
    queue_position: int
    segment: str
    channel: str
    planned_contact_date: str
    publishes_original_analysis: bool
    specific_upcoming_piece: bool
    public_business_channel_verified: bool
    qualification_evidence_sha256: str
    recent_work_reference_sha256: str
    sample_insight_sha256: str

    @classmethod
    def from_dict(cls, value: object, position: int) -> OutreachProspect:
        data = _fields(value, _PROSPECT_KEYS, f"prospects[{position}]")
        return cls(
            prospect_id=_pattern_string(
                data["prospect_id"],
                _PROSPECT_ID_RE,
                f"prospects[{position}].prospect_id",
            ),
            queue_position=_integer(
                data["queue_position"],
                f"prospects[{position}].queue_position",
                minimum=1,
                maximum=OUTREACH_TARGET_CONTACTS,
            ),
            segment=_enum_string(
                data["segment"],
                _SEGMENTS,
                f"prospects[{position}].segment",
            ),
            channel=_enum_string(
                data["channel"],
                _CHANNELS,
                f"prospects[{position}].channel",
            ),
            planned_contact_date=_canonical_date(
                data["planned_contact_date"],
                f"prospects[{position}].planned_contact_date",
            ),
            publishes_original_analysis=_required_true(
                data["publishes_original_analysis"],
                f"prospects[{position}].publishes_original_analysis",
            ),
            specific_upcoming_piece=_required_true(
                data["specific_upcoming_piece"],
                f"prospects[{position}].specific_upcoming_piece",
            ),
            public_business_channel_verified=_required_true(
                data["public_business_channel_verified"],
                f"prospects[{position}].public_business_channel_verified",
            ),
            qualification_evidence_sha256=_sha256(
                data["qualification_evidence_sha256"],
                f"prospects[{position}].qualification_evidence_sha256",
            ),
            recent_work_reference_sha256=_sha256(
                data["recent_work_reference_sha256"],
                f"prospects[{position}].recent_work_reference_sha256",
            ),
            sample_insight_sha256=_sha256(
                data["sample_insight_sha256"],
                f"prospects[{position}].sample_insight_sha256",
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "prospect_id": self.prospect_id,
            "queue_position": self.queue_position,
            "segment": self.segment,
            "channel": self.channel,
            "planned_contact_date": self.planned_contact_date,
            "publishes_original_analysis": self.publishes_original_analysis,
            "specific_upcoming_piece": self.specific_upcoming_piece,
            "public_business_channel_verified": self.public_business_channel_verified,
            "qualification_evidence_sha256": self.qualification_evidence_sha256,
            "recent_work_reference_sha256": self.recent_work_reference_sha256,
            "sample_insight_sha256": self.sample_insight_sha256,
        }


@dataclass(frozen=True, slots=True)
class OutreachPlan:
    schema_version: str
    campaign_ref: str
    campaign_start: str
    campaign_end: str
    utc_offset_minutes: int
    daily_contact_limit: int
    controls: OutreachControls
    prospects: tuple[OutreachProspect, ...]

    @classmethod
    def from_dict(cls, value: object) -> OutreachPlan:
        data = _fields(value, _ROOT_KEYS, "outreach plan")
        schema_version = _fixed_string(
            data["schema_version"],
            OUTREACH_PLAN_SCHEMA_VERSION,
            "schema_version",
        )
        campaign_ref = _pattern_string(
            data["campaign_ref"],
            _CAMPAIGN_REF_RE,
            "campaign_ref",
        )
        campaign_start = _canonical_date(data["campaign_start"], "campaign_start")
        campaign_end = _canonical_date(data["campaign_end"], "campaign_end")
        start_date = date.fromisoformat(campaign_start)
        end_date = date.fromisoformat(campaign_end)
        if end_date != start_date + timedelta(days=13):
            raise OutreachPlanError("campaign_end must close a 14-calendar-day campaign")
        utc_offset_minutes = _integer(
            data["utc_offset_minutes"],
            "utc_offset_minutes",
            minimum=-720,
            maximum=840,
        )
        daily_contact_limit = _integer(
            data["daily_contact_limit"],
            "daily_contact_limit",
            minimum=OUTREACH_DAILY_CONTACT_LIMIT,
            maximum=OUTREACH_DAILY_CONTACT_LIMIT,
        )
        controls = OutreachControls.from_dict(data["controls"])
        raw_prospects = data["prospects"]
        if not isinstance(raw_prospects, list) or not (
            1 <= len(raw_prospects) <= OUTREACH_TARGET_CONTACTS
        ):
            raise OutreachPlanError("prospects must contain from 1 through 50 entries")
        prospects = tuple(
            OutreachProspect.from_dict(item, position)
            for position, item in enumerate(raw_prospects)
        )
        cls._validate_cohort(prospects, start_date, controls.evidence_sha256)
        return cls(
            schema_version=schema_version,
            campaign_ref=campaign_ref,
            campaign_start=campaign_start,
            campaign_end=campaign_end,
            utc_offset_minutes=utc_offset_minutes,
            daily_contact_limit=daily_contact_limit,
            controls=controls,
            prospects=prospects,
        )

    @staticmethod
    def _validate_cohort(
        prospects: tuple[OutreachProspect, ...],
        campaign_start: date,
        controls_evidence_sha256: str,
    ) -> None:
        prospect_ids = [item.prospect_id for item in prospects]
        if len(set(prospect_ids)) != len(prospect_ids):
            raise OutreachPlanError("prospect_id values must be unique")
        positions = {item.queue_position for item in prospects}
        if positions != set(range(1, len(prospects) + 1)):
            raise OutreachPlanError("queue_position values must be contiguous from 1")

        first_contact_date = campaign_start + timedelta(
            days=OUTREACH_WINDOW_START_DAY - 1
        )
        last_contact_date = campaign_start + timedelta(
            days=OUTREACH_WINDOW_END_DAY - 1
        )
        contact_counts = Counter(item.planned_contact_date for item in prospects)
        for item in prospects:
            planned = date.fromisoformat(item.planned_contact_date)
            if not first_contact_date <= planned <= last_contact_date:
                raise OutreachPlanError(
                    "planned_contact_date must fall on campaign day 3 through day 7"
                )
        if any(count > OUTREACH_DAILY_CONTACT_LIMIT for count in contact_counts.values()):
            raise OutreachPlanError("a planned contact date exceeds the 10-contact limit")

        evidence_digests = [controls_evidence_sha256]
        for item in prospects:
            evidence_digests.extend(
                (
                    item.qualification_evidence_sha256,
                    item.recent_work_reference_sha256,
                    item.sample_insight_sha256,
                )
            )
        if len(set(evidence_digests)) != len(evidence_digests):
            raise OutreachPlanError("every imported evidence digest must be unique")

    @property
    def is_complete(self) -> bool:
        if len(self.prospects) != OUTREACH_TARGET_CONTACTS:
            return False
        start_date = date.fromisoformat(self.campaign_start)
        expected_dates = {
            (start_date + timedelta(days=offset)).isoformat()
            for offset in range(
                OUTREACH_WINDOW_START_DAY - 1,
                OUTREACH_WINDOW_END_DAY,
            )
        }
        counts = Counter(item.planned_contact_date for item in self.prospects)
        return counts == {
            contact_date: OUTREACH_DAILY_CONTACT_LIMIT
            for contact_date in expected_dates
        }

    @property
    def sha256(self) -> str:
        return sha256_json(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "campaign_ref": self.campaign_ref,
            "campaign_start": self.campaign_start,
            "campaign_end": self.campaign_end,
            "utc_offset_minutes": self.utc_offset_minutes,
            "daily_contact_limit": self.daily_contact_limit,
            "controls": self.controls.to_dict(),
            "prospects": [item.to_dict() for item in self.prospects],
        }

    def validation_report(self) -> dict[str, object]:
        daily_counts = Counter(item.planned_contact_date for item in self.prospects)
        return {
            "schema_version": self.schema_version,
            "campaign_ref": self.campaign_ref,
            "campaign_start": self.campaign_start,
            "campaign_end": self.campaign_end,
            "prospects": len(self.prospects),
            "daily_contact_counts": dict(sorted(daily_counts.items())),
            "plan_complete": self.is_complete,
            "plan_sha256": self.sha256,
            "controls_attested": True,
            "identity_fields_accepted": False,
            "evidence_artifacts_verified": False,
            "outreach_sent": False,
            "rmh_107_may_be_marked_complete": False,
            "completion_boundary": (
                "Validation does not verify identities or evidence bodies, send outreach, "
                "or complete RMH-107."
            ),
        }


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OutreachPlanError("outreach plan contains duplicate JSON keys")
        result[key] = value
    return result


def load_outreach_plan(path: str | Path) -> OutreachPlan:
    """Load a strict, privacy-minimized outreach plan from a regular local file."""
    source = os.fspath(path)
    _reject_symlink_ancestors(source)
    try:
        before = os.lstat(source)
    except (OSError, TypeError, ValueError):
        before = None
    if before is None:
        raise OutreachPlanError("outreach plan must be a readable regular file")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OutreachPlanError("outreach plan must be a readable regular file")
    if before.st_size > OUTREACH_PLAN_MAX_BYTES:
        raise OutreachPlanError("outreach plan exceeds the 256 KiB size limit")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(source, flags)
    except (OSError, TypeError, ValueError):
        descriptor = None
    if descriptor is None:
        raise OutreachPlanError("outreach plan must be a readable regular file")

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OutreachPlanError("outreach plan must be a stable regular file")
        if _file_snapshot(before) != _file_snapshot(opened):
            raise OutreachPlanError("outreach plan changed while opening")
        if opened.st_size > OUTREACH_PLAN_MAX_BYTES:
            raise OutreachPlanError("outreach plan exceeds the 256 KiB size limit")
        raw = _read_bounded(descriptor)
        after = os.fstat(descriptor)
        if _file_snapshot(opened) != _file_snapshot(after) or len(raw) != after.st_size:
            raise OutreachPlanError("outreach plan changed while reading")
        try:
            current = os.lstat(source)
        except (OSError, TypeError, ValueError):
            current = None
        if (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or _file_snapshot(current) != _file_snapshot(after)
        ):
            raise OutreachPlanError("outreach plan changed while reading")
    except OSError:
        raise OutreachPlanError("outreach plan could not be read") from None
    finally:
        os.close(descriptor)
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OutreachPlanError("outreach plan must contain valid UTF-8 JSON") from exc
    return OutreachPlan.from_dict(document)


def _reject_symlink_ancestors(path: str) -> None:
    try:
        ancestors = Path(path).absolute().parents
    except (OSError, TypeError, ValueError):
        raise OutreachPlanError("outreach plan must be a readable regular file") from None
    for ancestor in reversed(ancestors):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            metadata = None
        if metadata is None:
            raise OutreachPlanError("outreach plan must be a readable regular file")
        if stat.S_ISLNK(metadata.st_mode):
            raise OutreachPlanError(
                "outreach plan paths must not use symbolic-link ancestors"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise OutreachPlanError("outreach plan path ancestors must be directories")


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    bytes_read = 0
    while bytes_read <= OUTREACH_PLAN_MAX_BYTES:
        chunk = os.read(
            descriptor,
            min(8_192, OUTREACH_PLAN_MAX_BYTES + 1 - bytes_read),
        )
        if not chunk:
            break
        chunks.append(chunk)
        bytes_read += len(chunk)
    if bytes_read > OUTREACH_PLAN_MAX_BYTES:
        raise OutreachPlanError("outreach plan exceeds the 256 KiB size limit")
    return b"".join(chunks)


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
