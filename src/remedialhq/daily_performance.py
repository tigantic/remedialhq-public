from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, NoReturn, TypeGuard, TypeVar

SCHEMA_VERSION: Final = "remedialhq.daily-performance.v1"
REPORT_SCHEMA_VERSION: Final = "remedialhq.calendar-performance-reconciliation.v1"
MAX_DOCUMENT_BYTES: Final = 65_536
MAX_CALENDAR_BYTES: Final = 262_144
MAX_AUTHORITY_BYTES: Final = 32_768
MAX_RECORDS_PER_DOCUMENT: Final = 82
MAX_METRICS_PER_RECORD: Final = 16
MAX_METRIC_VALUE: Final = 1_000_000_000_000
CALENDAR_LENGTH: Final = 82
_EnumT = TypeVar("_EnumT", bound=StrEnum)


class DailyPerformanceError(ValueError):
    """Raised when offline performance evidence cannot be trusted."""


class PublicationResult(StrEnum):
    PUBLISHED = "PUBLISHED"
    NOT_PUBLISHED = "NOT_PUBLISHED"
    BLOCKED = "BLOCKED"


class BlockReason(StrEnum):
    PUBLICATION_AUTHORITY_DISABLED = "PUBLICATION_AUTHORITY_DISABLED"
    CALENDAR_STATE_NOT_EXECUTABLE = "CALENDAR_STATE_NOT_EXECUTABLE"
    ASSET_NOT_READY = "ASSET_NOT_READY"
    POLICY_GATE_FAILED = "POLICY_GATE_FAILED"
    SOURCE_EVIDENCE_UNAVAILABLE = "SOURCE_EVIDENCE_UNAVAILABLE"


class SourceKind(StrEnum):
    PLATFORM_ANALYTICS_EXPORT = "PLATFORM_ANALYTICS_EXPORT"
    SITE_ANALYTICS_EXPORT = "SITE_ANALYTICS_EXPORT"
    LOCAL_PUBLICATION_LOG = "LOCAL_PUBLICATION_LOG"


class MetricName(StrEnum):
    IMPRESSIONS = "IMPRESSIONS"
    SESSIONS = "SESSIONS"
    INTENT_SESSIONS = "INTENT_SESSIONS"
    VIEWS = "VIEWS"
    QUALIFIED_VIEWS = "QUALIFIED_VIEWS"
    QUALIFIED_WATCH_SECONDS = "QUALIFIED_WATCH_SECONDS"
    RETURNING_VIEWERS = "RETURNING_VIEWERS"
    CLICKS = "CLICKS"
    NEWSLETTER_OPT_INS = "NEWSLETTER_OPT_INS"
    AFFILIATE_REVENUE_CENTS = "AFFILIATE_REVENUE_CENTS"
    SPONSOR_REVENUE_CENTS = "SPONSOR_REVENUE_CENTS"
    AD_REVENUE_CENTS = "AD_REVENUE_CENTS"
    PRODUCTION_MINUTES = "PRODUCTION_MINUTES"
    PRODUCTION_COST_CENTS = "PRODUCTION_COST_CENTS"
    COMPUTE_COST_CENTS = "COMPUTE_COST_CENTS"
    CORRECTIONS = "CORRECTIONS"


class ReconciliationStatus(StrEnum):
    RECONCILED = "RECONCILED"
    MISSED = "MISSED"
    BLOCKED = "BLOCKED"


_TOP_LEVEL_FIELDS: Final = frozenset(
    {"schema_version", "performance_date", "calendar_sha256", "records"}
)
_RECORD_FIELDS: Final = frozenset(
    {
        "record_id",
        "day_number",
        "calendar_date",
        "opportunity_id",
        "observed_at",
        "publication_result",
        "block_reason",
        "source",
        "metrics",
    }
)
_SOURCE_FIELDS: Final = frozenset(
    {"kind", "artifact_sha256", "record_sha256"}
)
_METRIC_FIELDS: Final = frozenset({"metric", "value"})
_CALENDAR_FIELDS: Final = frozenset(
    {
        "day_number",
        "date",
        "weekday",
        "opportunity_id",
        "title",
        "franchise",
        "primary_format",
        "output_bundle",
        "evidence_floor",
        "rights_strategy",
        "monetization_lane",
        "publication_state",
        "primary_publish_time_et",
        "vertical_publish_time_et",
        "success_metric",
    }
)
_CALENDAR_STATES: Final = frozenset(
    {"PLANNED", "LAUNCH_NOW", "HOLD_UNTIL_EVIDENCE"}
)
_EXPECTED_SUCCESS_METRIC: Final = (
    "qualified_viewer_value and contribution per production dollar"
)

_RECORD_ID_RE: Final = re.compile(r"^prf_[0-9a-f]{32}$")
_OPPORTUNITY_ID_RE: Final = re.compile(r"^OPP-[0-9]{4}$")
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_DATE_RE: Final = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_TIME_RE: Final = re.compile(r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
_RFC3339_RE: Final = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
_EMAIL_RE: Final = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE
)
_URL_RE: Final = re.compile(r"(?:https?://|www\.)", re.IGNORECASE)
_PHONE_RE: Final = re.compile(r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)")
_PERSONAL_NAME_RE: Final = re.compile(
    r"^[A-Z][a-z]{1,30}(?:[ '-][A-Z][a-z]{1,30}){1,3}$"
)
_PLATFORM_IDENTIFIER_RE: Final = re.compile(
    r"(?<![A-Za-z0-9])(?:UC[A-Za-z0-9_-]{20,}|@[-A-Za-z0-9_.]{2,}|"
    r"(?:video|channel|user|customer|account)[_-]?id\s*[:=])",
    re.IGNORECASE,
)
_SECRET_PATTERNS: Final = (
    re.compile(r"\b(?:sk|rk|pk)_(?:test|live)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE),
    re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_FORBIDDEN_FIELD_NAMES: Final = frozenset(
    {
        "account",
        "account_id",
        "address",
        "authorization",
        "channel",
        "channel_id",
        "customer",
        "email",
        "handle",
        "ip",
        "name",
        "notes",
        "phone",
        "profile",
        "raw",
        "raw_payload",
        "token",
        "url",
        "user",
        "user_id",
        "username",
        "video_id",
    }
)


@dataclass(frozen=True, slots=True)
class PerformanceSource:
    kind: SourceKind
    artifact_sha256: str
    record_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "artifact_sha256": self.artifact_sha256,
            "record_sha256": self.record_sha256,
        }


@dataclass(frozen=True, slots=True)
class PerformanceMetric:
    name: MetricName
    value: int

    def to_dict(self) -> dict[str, object]:
        return {"metric": self.name.value, "value": self.value}


@dataclass(frozen=True, slots=True)
class DailyPerformanceRecord:
    record_id: str
    day_number: int
    calendar_date: str
    opportunity_id: str
    observed_at: str
    publication_result: PublicationResult
    block_reason: BlockReason | None
    source: PerformanceSource
    metrics: tuple[PerformanceMetric, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "day_number": self.day_number,
            "calendar_date": self.calendar_date,
            "opportunity_id": self.opportunity_id,
            "observed_at": self.observed_at,
            "publication_result": self.publication_result.value,
            "block_reason": (
                None if self.block_reason is None else self.block_reason.value
            ),
            "source": self.source.to_dict(),
            "metrics": [metric.to_dict() for metric in self.metrics],
        }


@dataclass(frozen=True, slots=True)
class DailyPerformanceBatch:
    performance_date: str
    calendar_sha256: str
    records: tuple[DailyPerformanceRecord, ...]
    evidence_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "performance_date": self.performance_date,
            "calendar_sha256": self.calendar_sha256,
            "records": [record.to_dict() for record in self.records],
        }


@dataclass(frozen=True, slots=True)
class CalendarRow:
    day_number: int
    calendar_date: str
    weekday: str
    opportunity_id: str
    publication_state: str


@dataclass(frozen=True, slots=True)
class CalendarSnapshot:
    rows: tuple[CalendarRow, ...]
    sha256: str

    def by_opportunity(self) -> dict[str, CalendarRow]:
        return {row.opportunity_id: row for row in self.rows}


@dataclass(frozen=True, slots=True)
class ReconciliationIssue:
    day_number: int
    scheduled_date: str
    opportunity_id: str
    calendar_state: str
    status: ReconciliationStatus
    reason: str
    feedback_record_id: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "day_number": self.day_number,
            "scheduled_date": self.scheduled_date,
            "opportunity_id": self.opportunity_id,
            "calendar_state": self.calendar_state,
            "status": self.status.value,
            "reason": self.reason,
            "feedback_record_id": self.feedback_record_id,
        }


@dataclass(frozen=True, slots=True)
class CalendarReconciliationReport:
    as_of_date: str
    calendar_sha256: str
    global_publication_enabled: bool
    feedback_records: int
    due_rows: int
    future_rows: int
    reconciled_rows: int
    missed_rows: int
    blocked_rows: int
    issues: tuple[ReconciliationIssue, ...]

    @property
    def clear(self) -> bool:
        return self.missed_rows == 0 and self.blocked_rows == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "as_of_date": self.as_of_date,
            "calendar_sha256": self.calendar_sha256,
            "global_publication_enabled": self.global_publication_enabled,
            "outcome": "CLEAR" if self.clear else "ACTION_REQUIRED",
            "summary": {
                "calendar_rows": self.due_rows + self.future_rows,
                "feedback_records": self.feedback_records,
                "due_rows": self.due_rows,
                "future_rows": self.future_rows,
                "reconciled_rows": self.reconciled_rows,
                "missed_rows": self.missed_rows,
                "blocked_rows": self.blocked_rows,
            },
            "safeguards": {
                "offline_only": True,
                "publication_performed": False,
                "calendar_content_changed": False,
                "calendar_dates_changed": False,
            },
            "issues": [issue.to_dict() for issue in self.issues],
        }


def build_daily_performance(
    document: Mapping[str, object],
    *,
    calendar: CalendarSnapshot,
    global_publication_enabled: bool,
    evidence_bytes: bytes | None = None,
) -> DailyPerformanceBatch:
    """Validate one bounded daily batch against the exact immutable calendar."""
    if type(global_publication_enabled) is not bool:
        raise DailyPerformanceError("global publication authority must be a JSON boolean")
    _scan_non_identifying(document)
    _strict_keys(document, _TOP_LEVEL_FIELDS, "daily performance document")
    _exact_string(document["schema_version"], SCHEMA_VERSION, "schema_version")
    performance_date = _parse_date(document["performance_date"], "performance_date")
    calendar_sha256 = _sha256(document["calendar_sha256"], "calendar_sha256")
    if not hmac.compare_digest(calendar_sha256, calendar.sha256):
        raise DailyPerformanceError("calendar_sha256 does not match the calendar source")

    raw_records = document["records"]
    if not _is_sequence(raw_records):
        raise DailyPerformanceError("records must be a JSON array")
    if not 1 <= len(raw_records) <= MAX_RECORDS_PER_DOCUMENT:
        raise DailyPerformanceError(
            f"records must contain 1 through {MAX_RECORDS_PER_DOCUMENT} items"
        )

    calendar_by_opportunity = calendar.by_opportunity()
    records: list[DailyPerformanceRecord] = []
    record_ids: set[str] = set()
    calendar_keys: set[tuple[int, str]] = set()
    source_record_hashes: set[str] = set()
    for raw_record in raw_records:
        imported_record = _build_record(
            raw_record,
            performance_date=performance_date,
            calendar_by_opportunity=calendar_by_opportunity,
            global_publication_enabled=global_publication_enabled,
        )
        calendar_key = (imported_record.day_number, imported_record.opportunity_id)
        if imported_record.record_id in record_ids or calendar_key in calendar_keys:
            raise DailyPerformanceError("daily performance contains duplicate records")
        if imported_record.source.record_sha256 in source_record_hashes:
            raise DailyPerformanceError(
                "daily performance reuses one source record for multiple calendar rows"
            )
        record_ids.add(imported_record.record_id)
        calendar_keys.add(calendar_key)
        source_record_hashes.add(imported_record.source.record_sha256)
        records.append(imported_record)

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "performance_date": performance_date,
        "calendar_sha256": calendar_sha256,
        "records": [record.to_dict() for record in records],
    }
    canonical_bytes = _canonical_json(normalized).encode("utf-8")
    source_bytes = canonical_bytes if evidence_bytes is None else evidence_bytes
    return DailyPerformanceBatch(
        performance_date=performance_date,
        calendar_sha256=calendar_sha256,
        records=tuple(records),
        evidence_sha256=hashlib.sha256(source_bytes).hexdigest(),
    )


def parse_daily_performance(
    text: str,
    *,
    calendar: CalendarSnapshot,
    global_publication_enabled: bool,
) -> DailyPerformanceBatch:
    """Parse strict UTF-8 JSON and import one offline daily performance batch."""
    if not isinstance(text, str):
        raise TypeError("daily performance evidence must be JSON text")
    try:
        evidence_bytes = text.encode("utf-8")
    except UnicodeError:
        raise DailyPerformanceError(
            "daily performance evidence must be valid UTF-8"
        ) from None
    if len(evidence_bytes) > MAX_DOCUMENT_BYTES:
        raise DailyPerformanceError("daily performance evidence exceeds the size limit")
    document = _parse_json(text, "daily performance evidence")
    if not isinstance(document, Mapping):
        raise DailyPerformanceError("daily performance evidence must be a JSON object")
    return build_daily_performance(
        document,
        calendar=calendar,
        global_publication_enabled=global_publication_enabled,
        evidence_bytes=evidence_bytes,
    )


def load_daily_performance(
    path: str | Path,
    *,
    calendar: CalendarSnapshot,
    global_publication_enabled: bool,
) -> DailyPerformanceBatch:
    """Load one stable, bounded regular file without following symbolic links."""
    data = _load_stable_file(path, MAX_DOCUMENT_BYTES, "daily performance evidence")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DailyPerformanceError(
            "daily performance evidence must be UTF-8"
        ) from None
    return parse_daily_performance(
        text,
        calendar=calendar,
        global_publication_enabled=global_publication_enabled,
    )


def load_prelaunch_calendar(path: str | Path) -> CalendarSnapshot:
    """Load and validate the fixed 82-day calendar without mutating it."""
    data = _load_stable_file(path, MAX_CALENDAR_BYTES, "pre-launch calendar")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DailyPerformanceError("pre-launch calendar must be UTF-8") from None
    document = _parse_json(text, "pre-launch calendar")
    if not _is_sequence(document) or len(document) != CALENDAR_LENGTH:
        raise DailyPerformanceError(
            f"pre-launch calendar must contain exactly {CALENDAR_LENGTH} rows"
        )

    rows: list[CalendarRow] = []
    opportunity_ids: set[str] = set()
    previous_date: date | None = None
    for index, raw_row in enumerate(document, start=1):
        if not isinstance(raw_row, Mapping):
            raise DailyPerformanceError("calendar rows must be JSON objects")
        _strict_keys(raw_row, _CALENDAR_FIELDS, "calendar row")
        day_number = _bounded_int(raw_row["day_number"], "day_number", 1, CALENDAR_LENGTH)
        if day_number != index:
            raise DailyPerformanceError("calendar day numbers must be ordered and contiguous")
        calendar_date = _parse_date(raw_row["date"], "calendar date")
        parsed_date = date.fromisoformat(calendar_date)
        if previous_date is not None and parsed_date != previous_date + timedelta(days=1):
            raise DailyPerformanceError("calendar dates must be ordered and contiguous")
        previous_date = parsed_date
        weekday = _bounded_string(raw_row["weekday"], "weekday", 3, 9)
        if weekday != parsed_date.strftime("%A"):
            raise DailyPerformanceError("calendar weekday does not match its date")
        opportunity_id = _match(
            raw_row["opportunity_id"], _OPPORTUNITY_ID_RE, "opportunity_id"
        )
        if opportunity_id in opportunity_ids:
            raise DailyPerformanceError("calendar opportunity IDs must be unique")
        opportunity_ids.add(opportunity_id)
        publication_state = _bounded_string(
            raw_row["publication_state"], "publication_state", 1, 32
        )
        if publication_state not in _CALENDAR_STATES:
            raise DailyPerformanceError("calendar publication_state is not supported")
        _validate_calendar_descriptive_fields(raw_row)
        rows.append(
            CalendarRow(
                day_number=day_number,
                calendar_date=calendar_date,
                weekday=weekday,
                opportunity_id=opportunity_id,
                publication_state=publication_state,
            )
        )
    return CalendarSnapshot(rows=tuple(rows), sha256=hashlib.sha256(data).hexdigest())


def load_global_publication_authority(path: str | Path) -> bool:
    """Read the sole global publication switch and fail closed on ambiguity."""
    data = _load_stable_file(path, MAX_AUTHORITY_BYTES, "publication authority")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DailyPerformanceError("publication authority must be UTF-8") from None
    document = _parse_json(text, "publication authority")
    if not isinstance(document, Mapping):
        raise DailyPerformanceError("publication authority must be a JSON object")
    enabled = document.get("global_publication_enabled")
    if type(enabled) is not bool:
        raise DailyPerformanceError(
            "global_publication_enabled must be a JSON boolean"
        )
    return enabled


def reconcile_calendar(
    calendar: CalendarSnapshot,
    batches: Sequence[DailyPerformanceBatch],
    *,
    as_of_date: str,
    global_publication_enabled: bool,
) -> CalendarReconciliationReport:
    """Reconcile due rows offline; this function has no publication or write path."""
    normalized_as_of = _parse_date(as_of_date, "as_of_date")
    if type(global_publication_enabled) is not bool:
        raise DailyPerformanceError("global publication authority must be a JSON boolean")

    records: dict[str, DailyPerformanceRecord] = {}
    record_ids: set[str] = set()
    source_record_hashes: set[str] = set()
    for batch in batches:
        if not isinstance(batch, DailyPerformanceBatch):
            raise DailyPerformanceError("reconciliation batches are invalid")
        if not hmac.compare_digest(batch.calendar_sha256, calendar.sha256):
            raise DailyPerformanceError("performance batch does not match the calendar source")
        if batch.performance_date > normalized_as_of:
            raise DailyPerformanceError("performance batch is later than --as-of")
        for record in batch.records:
            if (
                record.record_id in record_ids
                or record.opportunity_id in records
                or record.source.record_sha256 in source_record_hashes
            ):
                raise DailyPerformanceError("duplicate performance records across daily batches")
            record_ids.add(record.record_id)
            source_record_hashes.add(record.source.record_sha256)
            records[record.opportunity_id] = record

    issues: list[ReconciliationIssue] = []
    due_rows = 0
    future_rows = 0
    reconciled_rows = 0
    missed_rows = 0
    blocked_rows = 0
    for row in calendar.rows:
        if row.calendar_date > normalized_as_of:
            future_rows += 1
            if row.opportunity_id in records:
                raise DailyPerformanceError("performance record precedes its calendar date")
            continue
        due_rows += 1
        row_record = records.get(row.opportunity_id)
        status: ReconciliationStatus
        reason: str
        feedback_record_id: str | None = None
        if row_record is not None:
            feedback_record_id = row_record.record_id
            if row_record.publication_result is PublicationResult.PUBLISHED:
                status = ReconciliationStatus.RECONCILED
                reason = "VALIDATED_DAILY_PERFORMANCE"
                reconciled_rows += 1
            elif row_record.publication_result is PublicationResult.NOT_PUBLISHED:
                status = ReconciliationStatus.MISSED
                reason = "REPORTED_NOT_PUBLISHED"
                missed_rows += 1
            else:
                assert row_record.block_reason is not None
                status = ReconciliationStatus.BLOCKED
                reason = row_record.block_reason.value
                blocked_rows += 1
        elif row.publication_state != "LAUNCH_NOW":
            status = ReconciliationStatus.BLOCKED
            reason = "CALENDAR_STATE_NOT_EXECUTABLE"
            blocked_rows += 1
        elif not global_publication_enabled:
            status = ReconciliationStatus.BLOCKED
            reason = "PUBLICATION_AUTHORITY_DISABLED"
            blocked_rows += 1
        else:
            status = ReconciliationStatus.MISSED
            reason = "NO_DAILY_PERFORMANCE_RECORD"
            missed_rows += 1

        if status is not ReconciliationStatus.RECONCILED:
            issues.append(
                ReconciliationIssue(
                    day_number=row.day_number,
                    scheduled_date=row.calendar_date,
                    opportunity_id=row.opportunity_id,
                    calendar_state=row.publication_state,
                    status=status,
                    reason=reason,
                    feedback_record_id=feedback_record_id,
                )
            )

    unknown_records = set(records) - {row.opportunity_id for row in calendar.rows}
    if unknown_records:
        raise DailyPerformanceError("performance records do not match calendar rows")
    return CalendarReconciliationReport(
        as_of_date=normalized_as_of,
        calendar_sha256=calendar.sha256,
        global_publication_enabled=global_publication_enabled,
        feedback_records=len(records),
        due_rows=due_rows,
        future_rows=future_rows,
        reconciled_rows=reconciled_rows,
        missed_rows=missed_rows,
        blocked_rows=blocked_rows,
        issues=tuple(issues),
    )


def reconcile_performance_files(
    *,
    calendar_path: str | Path,
    authority_path: str | Path,
    feedback_paths: Sequence[str | Path],
    as_of_date: str,
) -> CalendarReconciliationReport:
    """Load all inputs and produce one entirely offline calendar report."""
    calendar = load_prelaunch_calendar(calendar_path)
    global_publication_enabled = load_global_publication_authority(authority_path)
    batches = tuple(
        load_daily_performance(
            path,
            calendar=calendar,
            global_publication_enabled=global_publication_enabled,
        )
        for path in feedback_paths
    )
    return reconcile_calendar(
        calendar,
        batches,
        as_of_date=as_of_date,
        global_publication_enabled=global_publication_enabled,
    )


def _build_record(
    value: object,
    *,
    performance_date: str,
    calendar_by_opportunity: Mapping[str, CalendarRow],
    global_publication_enabled: bool,
) -> DailyPerformanceRecord:
    if not isinstance(value, Mapping):
        raise DailyPerformanceError("performance records must be JSON objects")
    _strict_keys(value, _RECORD_FIELDS, "performance record")
    record_id = _match(value["record_id"], _RECORD_ID_RE, "record_id")
    day_number = _bounded_int(value["day_number"], "day_number", 1, CALENDAR_LENGTH)
    calendar_date = _parse_date(value["calendar_date"], "calendar_date")
    if calendar_date != performance_date:
        raise DailyPerformanceError(
            "calendar_date must match the daily performance_date"
        )
    opportunity_id = _match(
        value["opportunity_id"], _OPPORTUNITY_ID_RE, "opportunity_id"
    )
    calendar_row = calendar_by_opportunity.get(opportunity_id)
    if calendar_row is None:
        raise DailyPerformanceError("opportunity_id is absent from the calendar source")
    if (
        calendar_row.day_number != day_number
        or calendar_row.calendar_date != calendar_date
    ):
        raise DailyPerformanceError("performance record does not match its calendar row")
    observed_at = _normalize_timestamp(value["observed_at"], "observed_at")
    if value["observed_at"] != observed_at:
        raise DailyPerformanceError("observed_at must be normalized to UTC")
    if observed_at[:10] < calendar_date:
        raise DailyPerformanceError("observed_at cannot precede the calendar date")

    result = _enum_value(value["publication_result"], PublicationResult, "publication_result")
    assert isinstance(result, PublicationResult)
    block_reason: BlockReason | None
    if value["block_reason"] is None:
        block_reason = None
    else:
        parsed_reason = _enum_value(value["block_reason"], BlockReason, "block_reason")
        assert isinstance(parsed_reason, BlockReason)
        block_reason = parsed_reason
    source = _build_source(value["source"])
    metrics = _build_metrics(value["metrics"])
    _validate_result(
        result,
        block_reason,
        metrics,
        calendar_state=calendar_row.publication_state,
        global_publication_enabled=global_publication_enabled,
    )
    return DailyPerformanceRecord(
        record_id=record_id,
        day_number=day_number,
        calendar_date=calendar_date,
        opportunity_id=opportunity_id,
        observed_at=observed_at,
        publication_result=result,
        block_reason=block_reason,
        source=source,
        metrics=metrics,
    )


def _build_source(value: object) -> PerformanceSource:
    if not isinstance(value, Mapping):
        raise DailyPerformanceError("source must be a JSON object")
    _strict_keys(value, _SOURCE_FIELDS, "source")
    kind = _enum_value(value["kind"], SourceKind, "source kind")
    assert isinstance(kind, SourceKind)
    artifact_sha256 = _sha256(value["artifact_sha256"], "artifact_sha256")
    record_sha256 = _sha256(value["record_sha256"], "record_sha256")
    return PerformanceSource(
        kind=kind,
        artifact_sha256=artifact_sha256,
        record_sha256=record_sha256,
    )


def _build_metrics(value: object) -> tuple[PerformanceMetric, ...]:
    if not _is_sequence(value):
        raise DailyPerformanceError("metrics must be a JSON array")
    if len(value) > MAX_METRICS_PER_RECORD:
        raise DailyPerformanceError(
            f"metrics cannot exceed {MAX_METRICS_PER_RECORD} items"
        )
    metrics: list[PerformanceMetric] = []
    names: set[MetricName] = set()
    for raw_metric in value:
        if not isinstance(raw_metric, Mapping):
            raise DailyPerformanceError("metrics must contain JSON objects")
        _strict_keys(raw_metric, _METRIC_FIELDS, "metric")
        name = _enum_value(raw_metric["metric"], MetricName, "metric name")
        assert isinstance(name, MetricName)
        if name in names:
            raise DailyPerformanceError("metric names must be unique within a record")
        names.add(name)
        metric_value = _bounded_int(
            raw_metric["value"], "metric value", 0, MAX_METRIC_VALUE
        )
        metrics.append(PerformanceMetric(name=name, value=metric_value))
    return tuple(metrics)


def _validate_result(
    result: PublicationResult,
    block_reason: BlockReason | None,
    metrics: tuple[PerformanceMetric, ...],
    *,
    calendar_state: str,
    global_publication_enabled: bool,
) -> None:
    if result is PublicationResult.PUBLISHED:
        if block_reason is not None or not metrics:
            raise DailyPerformanceError(
                "PUBLISHED records require metrics and cannot have a block reason"
            )
        if calendar_state != "LAUNCH_NOW":
            raise DailyPerformanceError(
                "PUBLISHED record is blocked by the immutable calendar state"
            )
        if not global_publication_enabled:
            raise DailyPerformanceError(
                "PUBLISHED record is blocked by global publication authority"
            )
        return
    if metrics:
        raise DailyPerformanceError("non-published records cannot claim performance metrics")
    if result is PublicationResult.NOT_PUBLISHED:
        if block_reason is not None:
            raise DailyPerformanceError("NOT_PUBLISHED records cannot have a block reason")
        if calendar_state != "LAUNCH_NOW" or not global_publication_enabled:
            raise DailyPerformanceError(
                "NOT_PUBLISHED record contradicts calendar or publication authority"
            )
        return
    if block_reason is None:
        raise DailyPerformanceError("BLOCKED records require an enumerated block reason")
    if calendar_state != "LAUNCH_NOW":
        expected = BlockReason.CALENDAR_STATE_NOT_EXECUTABLE
    elif not global_publication_enabled:
        expected = BlockReason.PUBLICATION_AUTHORITY_DISABLED
    else:
        if block_reason in {
            BlockReason.CALENDAR_STATE_NOT_EXECUTABLE,
            BlockReason.PUBLICATION_AUTHORITY_DISABLED,
        }:
            raise DailyPerformanceError("BLOCKED reason contradicts active publication controls")
        return
    if block_reason is not expected:
        raise DailyPerformanceError("BLOCKED reason contradicts publication controls")


def _validate_calendar_descriptive_fields(row: Mapping[str, object]) -> None:
    for field in (
        "title",
        "franchise",
        "primary_format",
        "output_bundle",
        "evidence_floor",
        "rights_strategy",
        "monetization_lane",
    ):
        _bounded_string(row[field], field, 1, 500)
    for field in ("primary_publish_time_et", "vertical_publish_time_et"):
        _match(row[field], _TIME_RE, field)
    _exact_string(row["success_metric"], _EXPECTED_SUCCESS_METRIC, "success_metric")


def _parse_json(text: str, label: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except DailyPerformanceError:
        raise
    except (json.JSONDecodeError, UnicodeError):
        raise DailyPerformanceError(f"{label} is not valid JSON") from None


def _load_stable_file(path: str | Path, maximum: int, label: str) -> bytes:
    path_value = os.fspath(path)
    _reject_symlink_ancestors(path_value, label)
    try:
        before = os.lstat(path_value)
    except (OSError, TypeError, ValueError):
        raise DailyPerformanceError(f"{label} file is unavailable") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise DailyPerformanceError(f"{label} must be a regular non-symlink file")
    if before.st_size > maximum:
        raise DailyPerformanceError(f"{label} exceeds the size limit")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path_value, flags)
    except (OSError, TypeError, ValueError):
        raise DailyPerformanceError(f"{label} file cannot be opened") from None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _file_snapshot(before) != _file_snapshot(opened):
            raise DailyPerformanceError(f"{label} file changed while opening")
        data = _read_bounded(descriptor, maximum, label)
        after = os.fstat(descriptor)
        if _file_snapshot(opened) != _file_snapshot(after) or len(data) != after.st_size:
            raise DailyPerformanceError(f"{label} file changed while reading")
        try:
            current = os.lstat(path_value)
        except (OSError, TypeError, ValueError):
            current = None
        if (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or _file_snapshot(current) != _file_snapshot(after)
        ):
            raise DailyPerformanceError(f"{label} file changed while reading")
    except OSError:
        raise DailyPerformanceError(f"{label} file cannot be read") from None
    finally:
        os.close(descriptor)
    return data


def _read_bounded(descriptor: int, maximum: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= maximum:
        chunk = os.read(descriptor, min(8192, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > maximum:
        raise DailyPerformanceError(f"{label} exceeds the size limit")
    return b"".join(chunks)


def _reject_symlink_ancestors(path: str, label: str) -> None:
    try:
        ancestors = Path(path).absolute().parents
    except (OSError, TypeError, ValueError):
        raise DailyPerformanceError(f"{label} file is unavailable") from None
    for ancestor in reversed(ancestors):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise DailyPerformanceError(f"{label} path must not traverse symlinks")


def _scan_non_identifying(
    value: object,
    depth: int = 0,
    active: set[int] | None = None,
) -> None:
    if depth > 8:
        raise DailyPerformanceError("daily performance evidence is nested too deeply")
    active_ids = active if active is not None else set()
    if isinstance(value, Mapping):
        object_id = id(value)
        if object_id in active_ids:
            raise DailyPerformanceError("daily performance evidence cannot contain cycles")
        active_ids.add(object_id)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise DailyPerformanceError(
                        "daily performance field names must be strings"
                    )
                if key.casefold() in _FORBIDDEN_FIELD_NAMES:
                    raise DailyPerformanceError(
                        "daily performance evidence contains an identifying or raw field"
                    )
                _scan_non_identifying(item, depth + 1, active_ids)
        finally:
            active_ids.remove(object_id)
        return
    if _is_sequence(value):
        object_id = id(value)
        if object_id in active_ids:
            raise DailyPerformanceError("daily performance evidence cannot contain cycles")
        active_ids.add(object_id)
        try:
            for item in value:
                _scan_non_identifying(item, depth + 1, active_ids)
        finally:
            active_ids.remove(object_id)
        return
    if isinstance(value, str) and (
        _EMAIL_RE.search(value)
        or _URL_RE.search(value)
        or _PHONE_RE.search(value)
        or _PERSONAL_NAME_RE.fullmatch(value)
        or _PLATFORM_IDENTIFIER_RE.search(value)
        or any(pattern.search(value) for pattern in _SECRET_PATTERNS)
    ):
        raise DailyPerformanceError(
            "daily performance evidence contains identifying or secret data"
        )


def _strict_keys(
    value: Mapping[str, object], expected: frozenset[str], label: str
) -> None:
    if any(not isinstance(key, str) for key in value) or set(value) != set(expected):
        raise DailyPerformanceError(f"{label} has missing or unknown fields")


def _exact_string(value: object, expected: str, field: str) -> str:
    if not isinstance(value, str) or not hmac.compare_digest(value, expected):
        raise DailyPerformanceError(f"{field} must use the required fixed value")
    return value


def _bounded_string(
    value: object, field: str, minimum: int, maximum: int
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise DailyPerformanceError(
            f"{field} must contain {minimum} through {maximum} characters"
        )
    return value


def _match(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DailyPerformanceError(f"{field} is invalid")
    return value


def _sha256(value: object, field: str) -> str:
    return _match(value, _SHA256_RE, field)


def _parse_date(value: object, field: str) -> str:
    if not isinstance(value, str) or _DATE_RE.fullmatch(value) is None:
        raise DailyPerformanceError(f"{field} must be an ISO 8601 date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise DailyPerformanceError(f"{field} must be an ISO 8601 date") from None
    if parsed.isoformat() != value:
        raise DailyPerformanceError(f"{field} must be a normalized ISO 8601 date")
    return value


def _normalize_timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) > 40 or _RFC3339_RE.fullmatch(value) is None:
        raise DailyPerformanceError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise DailyPerformanceError(f"{field} must be an RFC 3339 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DailyPerformanceError(f"{field} must include a timezone")
    normalized = parsed.astimezone(UTC)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _bounded_int(value: object, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DailyPerformanceError(
            f"{field} must be an integer from {minimum} through {maximum}"
        )
    return value


def _enum_value(
    value: object,
    enum_type: type[_EnumT],
    field: str,
) -> _EnumT:
    if not isinstance(value, str):
        raise DailyPerformanceError(f"{field} is not supported")
    try:
        return enum_type(value)
    except ValueError:
        raise DailyPerformanceError(f"{field} is not supported") from None


def _is_sequence(value: object) -> TypeGuard[Sequence[object]]:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DailyPerformanceError(
                "daily performance input contains duplicate JSON fields"
            )
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> NoReturn:
    del value
    raise DailyPerformanceError("daily performance input contains a non-JSON number")


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
