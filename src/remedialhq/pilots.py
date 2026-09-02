from __future__ import annotations

import hmac
import importlib
import json
import os
import re
import secrets
import stat
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from .canonical import sha256_json
from .contact_evidence import (
    ContactEvidence,
    ContactEvidenceError,
    build_contact_evidence,
)
from .delivery_evidence import (
    DeliveryEvidence,
    DeliveryEvidenceError,
    DeliveryMethod,
    build_delivery_evidence,
)
from .ledger import HashLedger, LedgerError
from .outreach import (
    OUTREACH_WINDOW_END_DAY,
    SUPPRESSION_CLEAR_HOURS,
    OutreachPlan,
    OutreachPlanError,
)
from .payment_evidence import (
    EXPECTED_AMOUNT_CENTS,
    LivePaymentEvidence,
    PaymentEvidenceError,
    PaymentEvidenceEvent,
    build_live_payment_evidence,
)
from .pilot_reconciliation import (
    SCHEMA_VERSION as PILOT_RECONCILIATION_SCHEMA_VERSION,
)
from .pilot_reconciliation import (
    PilotSlotReconciliation,
    PriorPilotLedgerSnapshot,
)


class PilotLedgerError(RuntimeError):
    """Base error for paid-pilot ledger operations."""


class PilotStorageSecurityError(PilotLedgerError):
    """Raised when owner-private ledger storage is not exactly mode 0600."""


class PilotReplayError(PilotLedgerError):
    """Raised when an existing pilot ledger cannot be trusted."""


class PilotValidationError(ValueError):
    """Raised when a proposed pilot event violates schema or workflow rules."""


class PilotManifestError(PilotLedgerError):
    """Raised when an order manifest is malformed or fails its integrity check."""


class PilotEventType(StrEnum):
    PILOT_LEDGER_INITIALIZED = "PILOT_LEDGER_INITIALIZED"
    OUTREACH_PLAN_IMPORTED = "OUTREACH_PLAN_IMPORTED"
    OUTREACH_PLAN_AMENDED = "OUTREACH_PLAN_AMENDED"
    PROSPECT_ADDED = "PROSPECT_ADDED"
    SUPPRESSION_CHECKED = "SUPPRESSION_CHECKED"
    CONTACTED = "CONTACTED"
    REPLIED = "REPLIED"
    SAMPLE_REQUESTED = "SAMPLE_REQUESTED"
    SCOPE_CONFIRMED = "SCOPE_CONFIRMED"
    SCOPE_AMENDED = "SCOPE_AMENDED"
    CUSTOMER_ACCEPTANCE_RECORDED = "CUSTOMER_ACCEPTANCE_RECORDED"
    CHECKOUT_SENT = "CHECKOUT_SENT"
    PURCHASED = "PURCHASED"
    ORDER_ACCEPTED = "ORDER_ACCEPTED"
    ORDER_REJECTED = "ORDER_REJECTED"
    CANCELLATION_REQUESTED = "CANCELLATION_REQUESTED"
    OPTED_OUT = "OPTED_OUT"
    OWNER_TIME_RECORDED = "OWNER_TIME_RECORDED"
    RISK_INCIDENT_RECORDED = "RISK_INCIDENT_RECORDED"
    FULFILLMENT_STARTED = "FULFILLMENT_STARTED"
    ARTIFACT_COMPLETED = "ARTIFACT_COMPLETED"
    DELIVERED = "DELIVERED"
    FEEDBACK_RECORDED = "FEEDBACK_RECORDED"
    REFUNDED = "REFUNDED"


class ProspectSegment(StrEnum):
    GAMING_CREATOR = "GAMING_CREATOR"
    ENTERTAINMENT_CREATOR = "ENTERTAINMENT_CREATOR"
    NEWSLETTER = "NEWSLETTER"
    PODCAST = "PODCAST"


class ContactChannel(StrEnum):
    BUSINESS_EMAIL = "BUSINESS_EMAIL"
    CONTACT_FORM = "CONTACT_FORM"
    SOCIAL_DM = "SOCIAL_DM"
    OTHER_PUBLIC_BUSINESS_CHANNEL = "OTHER_PUBLIC_BUSINESS_CHANNEL"


class ReplyOutcome(StrEnum):
    INTERESTED = "INTERESTED"
    DECLINED = "DECLINED"
    NOT_NOW = "NOT_NOW"
    NOT_FIT = "NOT_FIT"


class SuppressionStatus(StrEnum):
    RECHECK_REQUIRED = "RECHECK_REQUIRED"
    CLEAR = "CLEAR"
    OPTED_OUT = "OPTED_OUT"


class OutreachCadenceStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    RECHECK_SUPPRESSION = "RECHECK_SUPPRESSION"
    READY = "READY"
    CONTACTED = "CONTACTED"
    OUTCOME_RECORDED = "OUTCOME_RECORDED"
    SUPPRESSED = "SUPPRESSED"


class OwnerTimeCategory(StrEnum):
    OUTREACH = "OUTREACH"
    SAMPLE = "SAMPLE"
    FULFILLMENT = "FULFILLMENT"
    ADMIN = "ADMIN"


class RiskKind(StrEnum):
    SOURCE_RIGHTS = "SOURCE_RIGHTS"
    DISCLOSURE = "DISCLOSURE"
    PAYMENT_IDENTITY = "PAYMENT_IDENTITY"
    REFUND_HANDLING = "REFUND_HANDLING"
    SENSITIVE_DATA = "SENSITIVE_DATA"
    MISREPRESENTATION_REQUEST = "MISREPRESENTATION_REQUEST"
    OTHER_COMPLIANCE = "OTHER_COMPLIANCE"


class RiskSeverity(StrEnum):
    MATERIAL = "MATERIAL"
    CRITICAL = "CRITICAL"


class FeedbackOutcome(StrEnum):
    SAVED_TIME = "SAVED_TIME"
    CHANGED_WORDING = "CHANGED_WORDING"
    PREVENTED_ERROR = "PREVENTED_ERROR"
    CREATED_USABLE_ANGLE = "CREATED_USABLE_ANGLE"
    NONE_REPORTED = "NONE_REPORTED"


class PaymentMode(StrEnum):
    LIVE = "LIVE"
    TEST = "TEST"


class DecisionGate(StrEnum):
    COLLECT_MORE_DATA = "COLLECT_MORE_DATA"
    QUALIFICATION_PLAN_REQUIRED = "QUALIFICATION_PLAN_REQUIRED"
    CONTINUE_AND_REPRICE = "CONTINUE_AND_REPRICE"
    REVISE_OFFER_OR_TARGET = "REVISE_OFFER_OR_TARGET"
    STOP_THIS_MOTION = "STOP_THIS_MOTION"
    PAUSE_IMMEDIATELY = "PAUSE_IMMEDIATELY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class PilotOrderState(StrEnum):
    PURCHASED = "PURCHASED"
    ORDER_ACCEPTED = "ORDER_ACCEPTED"
    ORDER_REJECTED = "ORDER_REJECTED"
    FULFILLMENT_STARTED = "FULFILLMENT_STARTED"
    ARTIFACT_COMPLETED = "ARTIFACT_COMPLETED"
    DELIVERED = "DELIVERED"
    CANCELLATION_REQUESTED = "CANCELLATION_REQUESTED"
    REFUNDED = "REFUNDED"


class OpaqueIdKind(StrEnum):
    RECONCILIATION = "rec"
    CAMPAIGN = "cmp"
    PROSPECT = "prs"
    CHECKOUT = "chk"
    ORDER = "ord"
    PAYMENT = "pay"
    SCOPE = "scp"
    CUSTOMER_ACCEPTANCE = "cac"
    ORDER_ACCEPTANCE = "oac"
    ORDER_REJECTION = "orj"
    CANCELLATION = "can"
    REFUND = "rfd"
    DELIVERY = "dlv"
    TIME_ENTRY = "tim"
    INCIDENT = "inc"
    FEEDBACK = "fbk"


FOUNDING_PRICE_CENTS: Final = 9_900
FOUNDING_PURCHASE_LIMIT: Final = 5
DECISION_GATE_CONTACTS: Final = 50
PILOT_LEDGER_SCHEMA_VERSION: Final = 5
CONTACT_EVIDENCE_MAX_RECORDING_DELAY_MINUTES: Final = 15
_PILOT_LEDGER_READABLE_SCHEMA_VERSIONS: Final = frozenset({3, 4, 5})
_PILOT_LEDGER_SCHEMA_3_EVENT_TYPES: Final = frozenset(
    {
        PilotEventType.PILOT_LEDGER_INITIALIZED,
        PilotEventType.PROSPECT_ADDED,
        PilotEventType.CONTACTED,
        PilotEventType.REPLIED,
        PilotEventType.SAMPLE_REQUESTED,
        PilotEventType.SCOPE_CONFIRMED,
        PilotEventType.SCOPE_AMENDED,
        PilotEventType.CUSTOMER_ACCEPTANCE_RECORDED,
        PilotEventType.CHECKOUT_SENT,
        PilotEventType.PURCHASED,
        PilotEventType.ORDER_ACCEPTED,
        PilotEventType.ORDER_REJECTED,
        PilotEventType.CANCELLATION_REQUESTED,
        PilotEventType.OPTED_OUT,
        PilotEventType.OWNER_TIME_RECORDED,
        PilotEventType.RISK_INCIDENT_RECORDED,
        PilotEventType.FULFILLMENT_STARTED,
        PilotEventType.ARTIFACT_COMPLETED,
        PilotEventType.DELIVERED,
        PilotEventType.FEEDBACK_RECORDED,
        PilotEventType.REFUNDED,
    }
)
ORDER_MANIFEST_SCHEMA_VERSION: Final = 5
_OPAQUE_ID_RE: Final = re.compile(
    r"^(?P<prefix>rec|cmp|prs|chk|ord|pay|scp|cac|oac|orj|can|rfd|dlv|tim|inc|fbk)_"
    r"(?P<token>[0-9a-f]{32}|[0-9a-f]{64})$"
)
_CLAIM_ID_RE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*$")
_TERMS_VERSION_RE: Final = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_LEDGER_KEYS: Final = {
    "index",
    "occurred_at",
    "event_type",
    "payload",
    "previous_hash",
    "hash",
}
_MANIFEST_KEYS: Final = {
    "schema_version",
    "ledger_head_sha256",
    "order",
    "manifest_sha256",
}
_ORDER_MANIFEST_KEYS: Final = {
    "prospect_id",
    "checkout_ref",
    "checkout_occurred_at",
    "order_id",
    "payment_ref",
    "scope_ref",
    "customer_acceptance_ref",
    "customer_acceptance_evidence_sha256",
    "payment_mode",
    "provider_purchase_sha256",
    "payment_evidence_sha256",
    "payment_evidence_artifact_sha256",
    "payment_evidence_observed_at",
    "order_acceptance_ref",
    "order_acceptance_evidence_sha256",
    "order_rejection_ref",
    "cancellation_ref",
    "refund_ref",
    "refund_evidence_sha256",
    "refund_evidence_artifact_sha256",
    "refund_evidence_observed_at",
    "state",
    "claim_ids",
    "amount_cents",
    "tax_amount_cents",
    "gross_amount_cents",
    "refunded_amount_cents",
    "fee_cents",
    "currency",
    "deadline",
    "terms_version",
    "deliverable_sha256",
    "artifact_completed_at",
    "delivery_ref",
    "delivery_method",
    "delivery_evidence_sha256",
    "delivery_evidence_artifact_sha256",
    "delivery_evidence_observed_at",
}
_FCNTL = importlib.import_module("fcntl") if os.name == "posix" else None
_MSVCRT = importlib.import_module("msvcrt") if os.name == "nt" else None


def _stat_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def new_opaque_id(kind: OpaqueIdKind | str) -> str:
    """Create an identifier that cannot carry names, addresses, or other free-form data."""
    try:
        prefix = OpaqueIdKind(kind).value
    except ValueError as exc:
        raise PilotValidationError("unsupported opaque identifier kind") from exc
    return f"{prefix}_{secrets.token_hex(16)}"


@dataclass(slots=True)
class _ProspectState:
    segment: ProspectSegment
    queue_position: int | None = None
    planned_contact_date: str | None = None
    planned_channel: ContactChannel | None = None
    qualification_evidence_sha256: str | None = None
    recent_work_reference_sha256: str | None = None
    sample_insight_sha256: str | None = None
    suppression_status: SuppressionStatus = SuppressionStatus.RECHECK_REQUIRED
    suppression_checked_at: datetime | None = None
    suppression_evidence_sha256: str | None = None
    contacted: bool = False
    contacted_at: datetime | None = None
    contact_evidence_sha256: str | None = None
    sender_profile_evidence_sha256: str | None = None
    message_copy_sha256: str | None = None
    provider_send_evidence_sha256: str | None = None
    provider_message_sha256: str | None = None
    reply_outcome: ReplyOutcome | None = None
    sample_requested: bool = False
    checkout_ref: str | None = None
    checkout_occurred_at: datetime | None = None
    customer_acceptance_ref: str | None = None
    customer_acceptance_evidence_sha256: str | None = None
    order_id: str | None = None
    payment_ref: str | None = None
    payment_mode: PaymentMode | None = None
    provider_purchase_sha256: str | None = None
    payment_evidence_sha256: str | None = None
    payment_evidence_artifact_sha256: str | None = None
    payment_evidence_observed_at: datetime | None = None
    purchase_amount_cents: int = 0
    tax_amount_cents: int = 0
    gross_amount_cents: int = 0
    refunded_amount_cents: int | None = None
    payment_fee_cents: int = 0
    scope_ref: str | None = None
    scope_revision: int = 0
    deadline: str | None = None
    terms_version: str | None = None
    claim_ids: tuple[str, ...] = ()
    order_acceptance_ref: str | None = None
    order_acceptance_evidence_sha256: str | None = None
    order_rejection_ref: str | None = None
    cancellation_ref: str | None = None
    opted_out: bool = False
    fulfillment_started: bool = False
    artifact_completed: bool = False
    artifact_completed_at: datetime | None = None
    delivered: bool = False
    deliverable_sha256: str | None = None
    delivery_ref: str | None = None
    delivery_method: DeliveryMethod | None = None
    delivery_evidence_sha256: str | None = None
    delivery_evidence_artifact_sha256: str | None = None
    delivery_evidence_observed_at: datetime | None = None
    feedback_recorded: bool = False
    refunded: bool = False
    refund_ref: str | None = None
    refund_evidence_sha256: str | None = None
    refund_evidence_artifact_sha256: str | None = None
    refund_evidence_observed_at: datetime | None = None


@dataclass(slots=True)
class _PilotState:
    schema_version: int | None = None
    prospects: dict[str, _ProspectState] = field(default_factory=dict)
    outreach_plan: OutreachPlan | None = None
    claimed_identifiers: set[str] = field(default_factory=set)
    event_count: int = 0
    owner_minutes: int = 0
    owner_minutes_by_category: dict[OwnerTimeCategory, int] = field(default_factory=dict)
    risk_incidents: int = 0
    last_occurred_at: datetime | None = None
    head_sha256: str = HashLedger.GENESIS
    prior_consumed_slots: int = 0
    reconciled_provider_purchase_sha256s: tuple[str, ...] = ()
    provider_purchase_sha256s: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class PilotMetrics:
    prior_consumed_slots: int
    remaining_founding_slots: int
    prospects: int
    contacted: int
    replies: int
    sample_requests: int
    customer_acceptances: int
    checkouts_sent: int
    purchases: int
    scopes_confirmed: int
    orders_accepted: int
    orders_rejected: int
    cancellation_requests: int
    refunds: int
    active_orders: int
    deliveries: int
    feedback_responses: int
    opt_outs: int
    risk_incidents: int
    booked_revenue_cents: int
    refunded_revenue_cents: int
    payment_fees_cents: int
    net_cash_cents: int
    owner_minutes: int
    owner_hours: float
    reply_rate: float
    sample_request_rate: float
    purchase_rate: float
    refund_rate: float
    decision_gate: DecisionGate


@dataclass(frozen=True, slots=True)
class OutreachQueueEntry:
    campaign_ref: str
    prospect_id: str
    queue_position: int
    segment: ProspectSegment
    channel: ContactChannel
    planned_contact_date: str
    qualification_status: str
    suppression_status: SuppressionStatus
    suppression_checked_at: str | None
    contacted_at: str | None
    contact_evidence_status: str
    cadence_status: OutreachCadenceStatus
    outcome: str
    next_action: str
    contact_allowed: bool


@dataclass(frozen=True, slots=True)
class PilotOrder:
    prospect_id: str
    checkout_ref: str
    checkout_occurred_at: str
    order_id: str
    payment_ref: str
    scope_ref: str
    customer_acceptance_ref: str
    customer_acceptance_evidence_sha256: str
    payment_mode: PaymentMode
    provider_purchase_sha256: str | None
    payment_evidence_sha256: str
    payment_evidence_artifact_sha256: str
    payment_evidence_observed_at: str
    order_acceptance_ref: str | None
    order_acceptance_evidence_sha256: str | None
    order_rejection_ref: str | None
    cancellation_ref: str | None
    refund_ref: str | None
    refund_evidence_sha256: str | None
    refund_evidence_artifact_sha256: str | None
    refund_evidence_observed_at: str | None
    state: PilotOrderState
    claim_ids: tuple[str, ...]
    amount_cents: int
    tax_amount_cents: int
    gross_amount_cents: int
    refunded_amount_cents: int | None
    fee_cents: int
    currency: str
    deadline: str
    terms_version: str
    deliverable_sha256: str | None
    artifact_completed_at: str | None
    delivery_ref: str | None
    delivery_method: DeliveryMethod | None
    delivery_evidence_sha256: str | None
    delivery_evidence_artifact_sha256: str | None
    delivery_evidence_observed_at: str | None


class PilotLedger:
    """Privacy-minimized operations ledger for the five-slot founding pilot.

    The ledger accepts only enumerated facts, integer amounts, and opaque identifiers.
    It intentionally has no field that can hold a name, address, message, URL, or note.
    Existing records are hash-verified and semantically replayed before every append.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        allow_insecure_test_storage: bool = False,
    ) -> None:
        self._configure(
            path,
            allow_insecure_test_storage=allow_insecure_test_storage,
        )
        if not self.path.exists():
            raise PilotReplayError("pilot ledger does not exist; initialize schema version 5 first")
        self._ledger = HashLedger(self.path, mode=0o600)
        try:
            with self._process_lock():
                self._secure_file()
                self._replay()
        except Exception:
            self._unlink_created_file(
                self._lock_path,
                self._created_lock_identity,
            )
            raise

    def _configure(
        self,
        path: str | Path,
        *,
        allow_insecure_test_storage: bool,
    ) -> None:
        if type(allow_insecure_test_storage) is not bool:
            raise TypeError("allow_insecure_test_storage must be a bool")
        self.path = Path(path)
        self.insecure_test_storage_override = allow_insecure_test_storage
        self.private_mode_enforced = False
        self.storage_security_status = (
            "INSECURE_TEST_OVERRIDE" if allow_insecure_test_storage else "ENFORCED"
        )
        self.ledger_mode: str | None = None
        self.lock_mode: str | None = None
        self._guard = threading.RLock()
        self._lock_path = self.path.with_name(f".{self.path.name}.lock")
        self._created_ledger_identity: tuple[int, int] | None = None
        self._created_lock_identity: tuple[int, int] | None = None
        self._assert_safe_ancestors(self.path)

    @classmethod
    def initialize(
        cls,
        path: str | Path,
        *,
        reconciliation_evidence: PilotSlotReconciliation,
        prior_ledger: str | Path | None = None,
        allow_insecure_test_storage: bool = False,
    ) -> PilotLedger:
        """Create schema 5 from validated, lineage-bound reconciliation evidence."""
        instance = cls.__new__(cls)
        instance._configure(
            path,
            allow_insecure_test_storage=allow_insecure_test_storage,
        )
        if not isinstance(reconciliation_evidence, PilotSlotReconciliation):
            raise PilotValidationError(
                "initialization requires validated pilot-slot reconciliation evidence"
            )
        verified_prior = (
            None
            if prior_ledger is None
            else cls.prior_ledger_snapshot(
                prior_ledger,
                allow_insecure_test_storage=allow_insecure_test_storage,
            )
        )
        if reconciliation_evidence.prior_ledger != verified_prior:
            raise PilotValidationError(
                "reconciliation evidence does not match the verified prior ledger"
            )
        slots = reconciliation_evidence.lifetime_consumed_slots
        evidence_digest = cls._sha256_digest(
            reconciliation_evidence.evidence_sha256,
            "reconciliation_evidence_sha256",
        )
        record_digest = cls._sha256_digest(
            reconciliation_evidence.record_sha256,
            "reconciliation_record_sha256",
        )
        prior_head = (
            None
            if reconciliation_evidence.prior_ledger is None
            else reconciliation_evidence.prior_ledger.ledger_head_sha256
        )
        instance._ledger = HashLedger(instance.path, mode=0o600)
        try:
            with instance._process_lock():
                if instance.path.exists():
                    raise PilotValidationError("pilot ledger already exists")
                instance._secure_file()
                payload: dict[str, object] = {
                    "schema_version": PILOT_LEDGER_SCHEMA_VERSION,
                    "prior_consumed_slots": slots,
                    "reconciliation_schema_version": PILOT_RECONCILIATION_SCHEMA_VERSION,
                    "reconciliation_ref": reconciliation_evidence.reconciliation_ref,
                    "reconciliation_evidence_sha256": evidence_digest,
                    "reconciliation_record_sha256": record_digest,
                    "reconciled_provider_purchase_sha256s": list(
                        reconciliation_evidence.payment_provider.provider_purchase_sha256s
                    ),
                }
                if prior_head is not None:
                    payload["prior_ledger_head_sha256"] = prior_head
                instance._ledger.append(
                    PilotEventType.PILOT_LEDGER_INITIALIZED,
                    payload,
                    occurred_at="1970-01-01T00:00:00+00:00",
                )
                instance._secure_file()
                instance._replay()
        except Exception:
            instance._cleanup_failed_initialization()
            raise
        return instance

    @classmethod
    def reconcile_prior_ledger(
        cls,
        path: str | Path,
        *,
        allow_insecure_test_storage: bool = False,
    ) -> tuple[int, str]:
        """Verify a prior ledger and conservatively count consumed founding slots."""
        snapshot = cls.prior_ledger_snapshot(
            path,
            allow_insecure_test_storage=allow_insecure_test_storage,
        )
        return snapshot.lifetime_consumed_slots, snapshot.ledger_head_sha256

    @classmethod
    def prior_ledger_snapshot(
        cls,
        path: str | Path,
        *,
        allow_insecure_test_storage: bool = False,
    ) -> PriorPilotLedgerSnapshot:
        """Derive exact migration facts from one verified prior ledger."""
        source = Path(path)
        security = cls.__new__(cls)
        security._configure(
            source,
            allow_insecure_test_storage=allow_insecure_test_storage,
        )
        if source.is_symlink() or not source.is_file():
            raise PilotReplayError("prior pilot ledger must be a regular file")
        security._ledger = HashLedger(source, mode=0o600)
        try:
            with security._process_lock():
                try:
                    records = cls._read_stable_prior_records(source)
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise PilotReplayError("prior pilot ledger could not be decoded") from exc
        except Exception:
            security._unlink_created_file(
                security._lock_path,
                security._created_lock_identity,
            )
            raise
        if not records:
            raise PilotReplayError("prior pilot ledger is empty")
        previous_hash = HashLedger.GENESIS
        for index, record in enumerate(records):
            if not isinstance(record, dict) or set(record) != _LEDGER_KEYS:
                raise PilotReplayError("prior pilot ledger record fields are invalid")
            if record.get("index") != index or record.get("previous_hash") != previous_hash:
                raise PilotReplayError("prior pilot ledger chain is invalid")
            claimed_hash = record.get("hash")
            if not isinstance(claimed_hash, str) or _SHA256_RE.fullmatch(claimed_hash) is None:
                raise PilotReplayError("prior pilot ledger hash is invalid")
            body = {key: value for key, value in record.items() if key != "hash"}
            if not hmac.compare_digest(claimed_hash, sha256_json(body)):
                raise PilotReplayError("prior pilot ledger hash is invalid")
            previous_hash = claimed_hash
        first_payload = records[0].get("payload")
        schema_version = (
            first_payload.get("schema_version")
            if records[0].get("event_type") == PilotEventType.PILOT_LEDGER_INITIALIZED.value
            and isinstance(first_payload, dict)
            else None
        )
        if type(schema_version) is not int:
            raise PilotReplayError("prior pilot ledger must declare an integer schema version")
        if schema_version in _PILOT_LEDGER_READABLE_SCHEMA_VERSIONS:
            prior = cls(
                source,
                allow_insecure_test_storage=allow_insecure_test_storage,
            )
            with prior._guard, prior._process_lock():
                prior_state = prior._replay()
                if prior_state.head_sha256 != previous_hash:
                    raise PilotReplayError("prior pilot ledger changed while reconciling")
                purchase_records = tuple(
                    record
                    for record in records
                    if record.get("event_type") == PilotEventType.PURCHASED.value
                )
                purchase_event_sha256s = tuple(str(record["hash"]) for record in purchase_records)
                purchase_evidence_artifact_sha256s = tuple(
                    str(record["payload"]["payment_evidence_artifact_sha256"])
                    for record in purchase_records
                )
                direct_provider_purchase_sha256s = (
                    tuple(
                        str(record["payload"]["provider_purchase_sha256"])
                        for record in purchase_records
                    )
                    if schema_version == PILOT_LEDGER_SCHEMA_VERSION
                    else ()
                )
                provider_purchase_sha256s = (
                    *prior_state.reconciled_provider_purchase_sha256s,
                    *direct_provider_purchase_sha256s,
                )
                purchases = sum(
                    prospect.order_id is not None for prospect in prior_state.prospects.values()
                )
                if len(purchase_event_sha256s) != purchases:
                    raise PilotReplayError("prior pilot ledger purchase records are contradictory")
                consumed_slots = prior_state.prior_consumed_slots + len(purchase_event_sha256s)
                if consumed_slots > FOUNDING_PURCHASE_LIMIT:
                    raise PilotReplayError("prior pilot ledger exceeds the five-slot limit")
                if schema_version < PILOT_LEDGER_SCHEMA_VERSION and consumed_slots:
                    raise PilotReplayError(
                        "nonzero schema 1 through 4 prior ledgers lack verified "
                        "provider purchase bindings"
                    )
                if len(provider_purchase_sha256s) != consumed_slots:
                    raise PilotReplayError(
                        "prior pilot ledger provider purchase bindings are contradictory"
                    )
                return PriorPilotLedgerSnapshot(
                    ledger_schema_version=schema_version,
                    ledger_head_sha256=prior_state.head_sha256,
                    inherited_consumed_slots=prior_state.prior_consumed_slots,
                    purchase_event_sha256s=purchase_event_sha256s,
                    purchase_evidence_artifact_sha256s=(purchase_evidence_artifact_sha256s),
                    provider_purchase_sha256s=provider_purchase_sha256s,
                )
        if schema_version not in {1, 2}:
            raise PilotReplayError("prior pilot ledger must use schema version 1, 2, 3, 4, or 5")
        purchase_event_sha256s = tuple(
            str(record["hash"])
            for record in records
            if record.get("event_type") == PilotEventType.PURCHASED.value
        )
        if len(purchase_event_sha256s) > FOUNDING_PURCHASE_LIMIT:
            raise PilotReplayError("prior pilot ledger exceeds the five-slot limit")
        if purchase_event_sha256s:
            raise PilotReplayError(
                "nonzero schema 1 through 4 prior ledgers lack verified provider purchase bindings"
            )
        try:
            with security._process_lock():
                current_records = cls._read_stable_prior_records(source)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PilotReplayError("prior pilot ledger could not be rechecked") from exc
        if current_records != records:
            raise PilotReplayError("prior pilot ledger changed while reconciling")
        return PriorPilotLedgerSnapshot(
            ledger_schema_version=schema_version,
            ledger_head_sha256=previous_hash,
            inherited_consumed_slots=0,
            purchase_event_sha256s=purchase_event_sha256s,
            purchase_evidence_artifact_sha256s=(),
            provider_purchase_sha256s=(),
        )

    def record(
        self,
        event_type: PilotEventType | str,
        payload: Mapping[str, object],
        *,
        occurred_at: str | None = None,
        payment_evidence: LivePaymentEvidence | None = None,
        delivery_evidence: DeliveryEvidence | None = None,
        contact_evidence: ContactEvidence | None = None,
    ) -> dict[str, Any]:
        """Validate and append one event, returning the underlying hash-ledger record."""
        with self._guard, self._process_lock():
            state = self._replay()
            self._require_writable_schema(state)
            event = self._event_type(event_type)
            timestamp = self._normalize_timestamp(occurred_at)
            if state.last_occurred_at is not None and timestamp < state.last_occurred_at:
                raise PilotValidationError("occurred_at cannot move backward")
            evidence_bound_payload = self._bind_payment_evidence(
                event,
                payload,
                payment_evidence,
            )
            contact_bound_payload = self._bind_contact_evidence(
                event,
                evidence_bound_payload,
                contact_evidence,
            )
            fully_bound_payload = self._bind_delivery_evidence(
                event,
                contact_bound_payload,
                delivery_evidence,
            )
            normalized_payload = self._apply_event(
                state,
                event,
                fully_bound_payload,
                occurred_at=timestamp,
            )
            record = self._ledger.append(
                event.value,
                normalized_payload,
                occurred_at=timestamp.isoformat(),
            )
            self._secure_file()
            return record

    @classmethod
    def _bind_contact_evidence(
        cls,
        event: PilotEventType,
        payload: Mapping[str, object],
        evidence: ContactEvidence | None,
    ) -> Mapping[str, object]:
        if event is not PilotEventType.CONTACTED:
            if evidence is not None:
                raise PilotValidationError(
                    "contact evidence is allowed only for a contact event"
                )
            return payload
        data = cls._fields(payload, {"prospect_id", "channel"})
        if evidence is None:
            return data
        try:
            validated = build_contact_evidence(
                evidence.to_dict(),
                expected_prospect_id=str(data["prospect_id"]),
                expected_channel=str(data["channel"]),
                expected_sender_profile_evidence_sha256=(
                    evidence.sender_profile_evidence_sha256
                ),
            )
        except (ContactEvidenceError, RuntimeError, TypeError, ValueError) as exc:
            raise PilotValidationError("post-send contact evidence is invalid") from exc
        return {
            **data,
            "contact_evidence_sha256": validated.sha256,
            "sender_profile_evidence_sha256": (
                validated.sender_profile_evidence_sha256
            ),
            "suppression_evidence_sha256": validated.suppression_evidence_sha256,
            "message_copy_sha256": validated.message_copy_sha256,
            "provider_send_evidence_sha256": (
                validated.provider_send_evidence_sha256
            ),
            "provider_message_sha256": validated.provider_message_sha256,
            "contact_evidence_observed_at": validated.observed_at,
        }

    @classmethod
    def _bind_payment_evidence(
        cls,
        event: PilotEventType,
        payload: Mapping[str, object],
        evidence: LivePaymentEvidence | None,
    ) -> Mapping[str, object]:
        evidence_events = {PilotEventType.PURCHASED, PilotEventType.REFUNDED}
        if event not in evidence_events:
            if evidence is not None:
                raise PilotValidationError(
                    "live payment evidence is allowed only for purchases and refunds"
                )
            return payload
        if evidence is None:
            raise PilotValidationError(
                "purchase and refund events require validated live payment evidence"
            )
        required = (
            {"prospect_id", "order_id", "fee_cents"}
            if event is PilotEventType.PURCHASED
            else {"prospect_id", "order_id"}
        )
        data = cls._fields(payload, required)
        expected_order_id = cls._opaque_id(data["order_id"], OpaqueIdKind.ORDER, "order_id")
        try:
            validated = build_live_payment_evidence(
                evidence.to_dict(),
                expected_order_id=expected_order_id,
            )
        except (PaymentEvidenceError, RuntimeError, TypeError, ValueError) as exc:
            raise PilotValidationError("live payment evidence is invalid") from exc
        if event is PilotEventType.PURCHASED:
            if validated.event_type is not PaymentEvidenceEvent.PAYMENT_CAPTURED:
                raise PilotValidationError("purchase requires PAYMENT_CAPTURED evidence")
            return {
                **data,
                "payment_ref": validated.provider_ref,
                "payment_mode": PaymentMode.LIVE.value,
                "provider_purchase_sha256": validated.provider_purchase_sha256,
                "payment_evidence_sha256": validated.sha256,
                "payment_evidence_artifact_sha256": validated.artifact_sha256,
                "payment_evidence_observed_at": validated.observed_at,
                "amount_cents": EXPECTED_AMOUNT_CENTS,
                "tax_amount_cents": validated.tax_amount_cents,
                "gross_amount_cents": validated.gross_amount_cents,
            }
        if validated.event_type is not PaymentEvidenceEvent.FULL_REFUND:
            raise PilotValidationError("refund requires FULL_REFUND evidence")
        if validated.original_payment_ref is None or validated.refunded_amount_cents is None:
            raise PilotValidationError("full refund evidence is incomplete")
        return {
            **data,
            "refund_ref": validated.provider_ref,
            "original_payment_ref": validated.original_payment_ref,
            "provider_purchase_sha256": validated.provider_purchase_sha256,
            "refund_evidence_sha256": validated.sha256,
            "refund_evidence_artifact_sha256": validated.artifact_sha256,
            "refund_evidence_observed_at": validated.observed_at,
            "amount_cents": EXPECTED_AMOUNT_CENTS,
            "tax_amount_cents": validated.tax_amount_cents,
            "gross_amount_cents": validated.gross_amount_cents,
            "refunded_amount_cents": validated.refunded_amount_cents,
        }

    @classmethod
    def _bind_delivery_evidence(
        cls,
        event: PilotEventType,
        payload: Mapping[str, object],
        evidence: DeliveryEvidence | None,
    ) -> Mapping[str, object]:
        if event is not PilotEventType.DELIVERED:
            if evidence is not None:
                raise PilotValidationError("delivery evidence is allowed only for a delivery event")
            return payload
        if evidence is None:
            raise PilotValidationError("delivery requires validated external delivery evidence")
        data = cls._fields(payload, {"prospect_id", "order_id"})
        expected_order_id = cls._opaque_id(data["order_id"], OpaqueIdKind.ORDER, "order_id")
        try:
            validated = build_delivery_evidence(
                evidence.to_dict(),
                expected_order_id=expected_order_id,
                expected_artifact_sha256=evidence.artifact_sha256,
            )
        except (DeliveryEvidenceError, RuntimeError, TypeError, ValueError) as exc:
            raise PilotValidationError("external delivery evidence is invalid") from exc
        return {
            **data,
            "delivery_ref": validated.delivery_ref,
            "delivery_method": validated.delivery_method.value,
            "deliverable_sha256": validated.artifact_sha256,
            "delivery_evidence_sha256": validated.sha256,
            "delivery_evidence_artifact_sha256": (validated.evidence_artifact_sha256),
            "delivery_evidence_observed_at": validated.observed_at,
        }

    def metrics(self) -> PilotMetrics:
        """Replay the trusted ledger and return aggregate funnel and gate metrics."""
        with self._guard, self._process_lock():
            return self._metrics(self._replay())

    def import_outreach_plan(
        self,
        plan: OutreachPlan,
        *,
        occurred_at: str | None = None,
    ) -> dict[str, object]:
        """Import one complete qualified cohort as a single hash-chained event."""
        if not isinstance(plan, OutreachPlan):
            raise PilotValidationError("plan must be a validated outreach plan")
        if not plan.is_complete:
            raise PilotValidationError(
                "outreach import requires exactly 50 prospects, with 10 on each contact day"
            )
        payload = {**plan.to_dict(), "plan_sha256": plan.sha256}
        with self._guard, self._process_lock():
            state = self._replay()
            self._require_writable_schema(state)
            timestamp = self._normalize_timestamp(occurred_at)
            if state.last_occurred_at is not None and timestamp < state.last_occurred_at:
                raise PilotValidationError("occurred_at cannot move backward")
            normalized = self._apply_event(
                state,
                PilotEventType.OUTREACH_PLAN_IMPORTED,
                payload,
                occurred_at=timestamp,
            )
            record = self._ledger.append(
                PilotEventType.OUTREACH_PLAN_IMPORTED.value,
                normalized,
                occurred_at=timestamp.isoformat(),
            )
            self._secure_file()
        return {
            "campaign_ref": plan.campaign_ref,
            "event_hash": str(record["hash"]),
            "plan_sha256": plan.sha256,
            "prospects_imported": len(plan.prospects),
            "outreach_sent": False,
            "rmh_107_may_be_marked_complete": False,
        }

    def amend_outreach_plan(
        self,
        plan: OutreachPlan,
        *,
        occurred_at: str | None = None,
    ) -> dict[str, object]:
        """Replace one pre-contact suppressed candidate with a qualified candidate."""
        if not isinstance(plan, OutreachPlan):
            raise PilotValidationError("plan must be a validated outreach plan")
        if not plan.is_complete:
            raise PilotValidationError(
                "outreach amendment requires exactly 50 prospects, with 10 on each contact day"
            )
        with self._guard, self._process_lock():
            state = self._replay()
            self._require_writable_schema(state)
            if state.outreach_plan is None:
                raise PilotValidationError("an outreach plan must be imported before amendment")
            timestamp = self._normalize_timestamp(occurred_at)
            if state.last_occurred_at is not None and timestamp < state.last_occurred_at:
                raise PilotValidationError("occurred_at cannot move backward")
            payload = {
                **plan.to_dict(),
                "plan_sha256": plan.sha256,
                "supersedes_plan_sha256": state.outreach_plan.sha256,
            }
            normalized = self._apply_event(
                state,
                PilotEventType.OUTREACH_PLAN_AMENDED,
                payload,
                occurred_at=timestamp,
            )
            record = self._ledger.append(
                PilotEventType.OUTREACH_PLAN_AMENDED.value,
                normalized,
                occurred_at=timestamp.isoformat(),
            )
            self._secure_file()
        return {
            "campaign_ref": plan.campaign_ref,
            "event_hash": str(record["hash"]),
            "plan_sha256": plan.sha256,
            "prospects_active": len(plan.prospects),
            "outreach_sent": False,
            "rmh_107_may_be_marked_complete": False,
        }

    def outreach_queue(
        self,
        *,
        as_of: str | None = None,
    ) -> tuple[OutreachQueueEntry, ...]:
        """Return the private campaign queue without names, addresses, messages, or URLs."""
        observed_at = self._normalize_timestamp(as_of)
        with self._guard, self._process_lock():
            state = self._replay()
            if state.outreach_plan is None:
                raise PilotValidationError("no outreach plan has been imported")
            active_prospect_ids = (entry.prospect_id for entry in state.outreach_plan.prospects)
            entries = (
                self._project_outreach_entry(
                    state,
                    prospect_id,
                    state.prospects[prospect_id],
                    observed_at,
                )
                for prospect_id in active_prospect_ids
            )
            return tuple(sorted(entries, key=lambda item: item.queue_position))

    def order(self, order_id: str) -> PilotOrder:
        """Return the privacy-minimized projection for one founding order."""
        normalized_order_id = self._opaque_id(order_id, OpaqueIdKind.ORDER, "order_id")
        with self._guard, self._process_lock():
            state = self._replay()
            for prospect_id, prospect in state.prospects.items():
                if prospect.order_id == normalized_order_id:
                    return self._project_order(prospect_id, prospect)
        raise PilotValidationError("order_id is unknown")

    def orders(self) -> tuple[PilotOrder, ...]:
        """Return all founding order projections in deterministic order-ID order."""
        with self._guard, self._process_lock():
            state = self._replay()
            projected = (
                self._project_order(prospect_id, prospect)
                for prospect_id, prospect in state.prospects.items()
                if prospect.order_id is not None
            )
            return tuple(sorted(projected, key=lambda item: item.order_id))

    def verify(self) -> tuple[bool, str]:
        """Verify both the hash chain and every pilot workflow transition."""
        with self._guard, self._process_lock():
            state = self._replay()
            return True, f"verified {state.event_count} pilot events"

    @property
    def head(self) -> str:
        """Return the verified current ledger head digest."""
        with self._guard, self._process_lock():
            return self._replay().head_sha256

    def order_at_head(self, order_id: str, ledger_head_sha256: str) -> PilotOrder:
        """Return one order only when the supplied digest is the verified current head."""
        normalized_order_id = self._opaque_id(order_id, OpaqueIdKind.ORDER, "order_id")
        normalized_head = self._sha256_digest(ledger_head_sha256, "ledger_head_sha256")
        with self._guard, self._process_lock():
            state = self._replay()
            if not hmac.compare_digest(state.head_sha256, normalized_head):
                raise PilotValidationError(
                    "ledger_head_sha256 does not match the current pilot ledger head"
                )
            for prospect_id, prospect in state.prospects.items():
                if prospect.order_id == normalized_order_id:
                    return self._project_order(prospect_id, prospect)
        raise PilotValidationError("order_id is unknown")

    def contains_event_hash(self, digest: str) -> bool:
        """Return whether a verified event chain contains one exact digest."""
        normalized = self._sha256_digest(digest, "ledger_head_sha256")
        with self._guard, self._process_lock():
            self._replay()
            return any(
                isinstance(record.get("hash"), str)
                and hmac.compare_digest(str(record["hash"]), normalized)
                for record in self._ledger.iter_events()
            )

    def storage_security(self) -> dict[str, object]:
        """Return a freshly verified, privacy-safe storage security report."""
        with self._guard, self._process_lock():
            return {
                "private_mode_enforced": self.private_mode_enforced,
                "storage_security_status": self.storage_security_status,
                "ledger_mode": self.ledger_mode,
                "lock_mode": self.lock_mode,
                "insecure_test_storage_override": self.insecure_test_storage_override,
            }

    @staticmethod
    def _assert_safe_ancestors(path: Path) -> None:
        absolute = path.absolute()
        for ancestor in reversed(absolute.parents):
            if ancestor.is_symlink():
                raise PilotLedgerError("owner-private paths must not use symbolic-link ancestors")

    @contextmanager
    def _process_lock(self) -> Iterator[None]:
        self._assert_safe_ancestors(self._lock_path)
        if self._lock_path.is_symlink():
            raise PilotLedgerError("pilot lock must not be a symbolic link")
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        if os.name == "nt":
            flags |= getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(
                self._lock_path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            created_lock_status = os.fstat(descriptor)
            self._created_lock_identity = (
                created_lock_status.st_dev,
                created_lock_status.st_ino,
            )
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
        except FileExistsError:
            try:
                descriptor = os.open(self._lock_path, flags)
            except OSError as exc:
                raise PilotLedgerError("could not open the pilot process lock") from exc
        except OSError as exc:
            raise PilotLedgerError("could not open the pilot process lock") from exc
        locked = False
        try:
            self._check_lock_descriptor(descriptor)
            if _FCNTL is not None:
                _FCNTL.flock(descriptor, _FCNTL.LOCK_EX)
            elif _MSVCRT is not None:
                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                    os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                _MSVCRT.locking(descriptor, _MSVCRT.LK_LOCK, 1)
            else:  # pragma: no cover - unsupported operating system
                raise PilotLedgerError(
                    "cross-process pilot locking is unavailable on this platform"
                )
            locked = True
            self._check_lock_descriptor(descriptor)
            if self.path.exists():
                self._check_ledger_file()
            yield
            if self.path.exists():
                self._check_ledger_file()
            self._check_lock_descriptor(descriptor)
        finally:
            if locked:
                if _FCNTL is not None:
                    _FCNTL.flock(descriptor, _FCNTL.LOCK_UN)
                elif _MSVCRT is not None:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    _MSVCRT.locking(descriptor, _MSVCRT.LK_UNLCK, 1)
            os.close(descriptor)

    def _secure_file(self) -> None:
        self._assert_safe_ancestors(self.path)
        if self.path.is_symlink():
            raise PilotLedgerError("pilot ledger must not be a symbolic link")
        if not self.path.exists():
            try:
                descriptor = os.open(
                    self.path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except OSError as exc:
                raise PilotLedgerError("could not create pilot ledger securely") from exc
            try:
                created_ledger_status = os.fstat(descriptor)
                self._created_ledger_identity = (
                    created_ledger_status.st_dev,
                    created_ledger_status.st_ino,
                )
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        self._check_ledger_file()

    def _check_ledger_file(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise PilotLedgerError("could not open pilot ledger securely") from exc
        try:
            file_status = os.fstat(descriptor)
            if not stat.S_ISREG(file_status.st_mode):
                raise PilotLedgerError("pilot ledger path must be a regular file")
            mode = stat.S_IMODE(file_status.st_mode)
        except OSError as exc:
            raise PilotLedgerError("could not inspect pilot ledger permissions") from exc
        finally:
            os.close(descriptor)
        self._record_storage_mode("ledger", mode)

    def _check_lock_descriptor(self, descriptor: int) -> None:
        try:
            file_status = os.fstat(descriptor)
        except OSError as exc:
            raise PilotLedgerError("could not inspect pilot lock permissions") from exc
        if not stat.S_ISREG(file_status.st_mode):
            raise PilotLedgerError("pilot lock path must be a regular file")
        self._record_storage_mode("lock", stat.S_IMODE(file_status.st_mode))

    def _record_storage_mode(self, kind: str, mode: int) -> None:
        rendered = f"{mode:04o}"
        if kind == "ledger":
            self.ledger_mode = rendered
        elif kind == "lock":
            self.lock_mode = rendered
        else:  # pragma: no cover - internal invariant
            raise RuntimeError(f"unsupported storage kind: {kind}")
        self.private_mode_enforced = self.ledger_mode == "0600" and self.lock_mode == "0600"
        if mode != 0o600 and not self.insecure_test_storage_override:
            raise PilotStorageSecurityError(
                f"pilot {kind} permissions could not be restricted to 0600 "
                f"(observed {rendered}). Use an owner-only filesystem that enforces "
                "POSIX permissions. Under WSL, use a path under /home, not /mnt/c. "
                "The insecure-storage override is only for synthetic, non-sensitive "
                "tests."
            )

    def _cleanup_failed_initialization(self) -> None:
        self._unlink_created_file(
            self.path,
            self._created_ledger_identity,
        )
        self._unlink_created_file(
            self._lock_path,
            self._created_lock_identity,
        )

    @staticmethod
    def _unlink_created_file(
        path: Path,
        identity: tuple[int, int] | None,
    ) -> None:
        if identity is None:
            return
        try:
            current = os.lstat(path)
            if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
                path.unlink()
        except OSError:
            pass

    @staticmethod
    def _read_stable_prior_records(path: Path) -> list[dict[str, Any]]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PilotReplayError("prior pilot ledger must be a regular file")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                records = [json.loads(line) for line in handle if line.strip()]
                after_read = os.fstat(handle.fileno())
            try:
                current = os.lstat(path)
            except OSError:
                current = None
            if (
                _stat_snapshot(metadata) != _stat_snapshot(after_read)
                or current is None
                or not stat.S_ISREG(current.st_mode)
                or _stat_snapshot(current) != _stat_snapshot(after_read)
            ):
                raise PilotReplayError("prior pilot ledger changed while reading")
            return records
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _replay(self) -> _PilotState:
        try:
            records = list(self._ledger.iter_events())
        except (LedgerError, OSError, TypeError, ValueError) as exc:
            raise PilotReplayError("pilot ledger could not be decoded") from exc
        if not records:
            raise PilotReplayError("pilot ledger is empty")
        try:
            verified, message = self._ledger.verify()
        except (LedgerError, OSError, AttributeError, KeyError, TypeError, ValueError) as exc:
            raise PilotReplayError("pilot ledger integrity check failed") from exc
        if not verified:
            raise PilotReplayError(f"pilot ledger integrity check failed: {message}")

        state = _PilotState()
        for position, record in enumerate(records):
            if position == 0 and isinstance(record, dict):
                payload = record.get("payload")
                legacy_schema = (
                    payload.get("schema_version")
                    if record.get("event_type") == PilotEventType.PILOT_LEDGER_INITIALIZED.value
                    and isinstance(payload, dict)
                    else None
                )
                if legacy_schema in {1, 2}:
                    raise PilotReplayError(
                        f"legacy pilot ledger schema version {legacy_schema} is read-only; "
                        "initialize schema version 5 with strict lifetime-slot reconciliation"
                    )
            try:
                if not isinstance(record, dict) or set(record) != _LEDGER_KEYS:
                    raise PilotValidationError("ledger record fields are invalid")
                event = self._event_type(record["event_type"])
                payload = record["payload"]
                if not isinstance(payload, dict):
                    raise PilotValidationError("event payload must be an object")
                timestamp = self._normalize_timestamp(record["occurred_at"])
                if state.last_occurred_at is not None and timestamp < state.last_occurred_at:
                    raise PilotValidationError("occurred_at cannot move backward")
                self._apply_event(
                    state,
                    event,
                    payload,
                    occurred_at=timestamp,
                )
                state.last_occurred_at = timestamp
                state.event_count += 1
            except (PilotValidationError, TypeError, ValueError) as exc:
                raise PilotReplayError(f"invalid pilot event at index {position}") from exc
        state.head_sha256 = str(records[-1]["hash"])
        return state

    @staticmethod
    def _event_type(value: object) -> PilotEventType:
        if not isinstance(value, str):
            raise PilotValidationError("event_type must be a supported string")
        try:
            return PilotEventType(value)
        except ValueError as exc:
            raise PilotValidationError("event_type is not supported") from exc

    @staticmethod
    def _require_writable_schema(state: _PilotState) -> None:
        if state.schema_version != PILOT_LEDGER_SCHEMA_VERSION:
            raise PilotValidationError(
                f"pilot ledger schema version {state.schema_version} is read-only; "
                f"initialize schema version {PILOT_LEDGER_SCHEMA_VERSION} with "
                "lifetime-slot reconciliation"
            )

    @staticmethod
    def _normalize_timestamp(value: object | None) -> datetime:
        if value is None:
            return datetime.now(UTC)
        if not isinstance(value, str) or not value or len(value) > 40:
            raise PilotValidationError("occurred_at must be a timezone-aware ISO timestamp")
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise PilotValidationError(
                "occurred_at must be a timezone-aware ISO timestamp"
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise PilotValidationError("occurred_at must include a timezone")
        return parsed.astimezone(UTC)

    @staticmethod
    def _fields(
        payload: Mapping[str, object],
        required: set[str],
        optional: set[str] | None = None,
    ) -> dict[str, object]:
        if not isinstance(payload, Mapping):
            raise PilotValidationError("event payload must be an object")
        data = dict(payload)
        if any(not isinstance(key, str) for key in data):
            raise PilotValidationError("event payload keys must be strings")
        permitted = required | (optional or set())
        missing = required - set(data)
        unexpected = set(data) - permitted
        if missing:
            raise PilotValidationError(f"missing required fields: {', '.join(sorted(missing))}")
        if unexpected:
            raise PilotValidationError("unexpected fields are not permitted")
        return data

    @staticmethod
    def _opaque_id(value: object, kind: OpaqueIdKind, field_name: str) -> str:
        if not isinstance(value, str):
            raise PilotValidationError(f"{field_name} must be an opaque identifier")
        matched = _OPAQUE_ID_RE.fullmatch(value)
        if matched is None or matched.group("prefix") != kind.value:
            raise PilotValidationError(f"{field_name} must be an opaque {kind.value} identifier")
        return value

    @staticmethod
    def _enum(value: object, enum_type: type[StrEnum], field_name: str) -> StrEnum:
        if not isinstance(value, str):
            raise PilotValidationError(f"{field_name} must be an enumerated string")
        try:
            return enum_type(value)
        except ValueError as exc:
            raise PilotValidationError(f"{field_name} is not supported") from exc

    @staticmethod
    def _integer(value: object, field_name: str, *, minimum: int, maximum: int) -> int:
        if type(value) is not int or not minimum <= value <= maximum:
            raise PilotValidationError(
                f"{field_name} must be an integer from {minimum} through {maximum}"
            )
        return value

    @classmethod
    def _deadline(cls, value: object) -> str:
        if not isinstance(value, str):
            raise PilotValidationError("deadline must be an ISO date or aware timestamp")
        if len(value) == 10:
            try:
                parsed_date = date.fromisoformat(value)
            except ValueError as exc:
                raise PilotValidationError(
                    "deadline must be an ISO date or aware timestamp"
                ) from exc
            if parsed_date.isoformat() != value:
                raise PilotValidationError("deadline must use canonical ISO date form")
            return value
        return cls._normalize_timestamp(value).isoformat()

    @staticmethod
    def _machine_safe(value: object, pattern: re.Pattern[str], field_name: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 64:
            raise PilotValidationError(f"{field_name} must be a machine-safe identifier")
        if pattern.fullmatch(value) is None:
            raise PilotValidationError(f"{field_name} must be a machine-safe identifier")
        return value

    @staticmethod
    def _sha256_digest(value: object, field_name: str) -> str:
        if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
            raise PilotValidationError(f"{field_name} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _claim(state: _PilotState, identifier: str, field_name: str) -> None:
        if identifier in state.claimed_identifiers:
            raise PilotValidationError(f"{field_name} must be unique")
        state.claimed_identifiers.add(identifier)

    @staticmethod
    def _claim_provider_purchase(state: _PilotState, digest: str) -> None:
        if digest in state.provider_purchase_sha256s:
            raise PilotValidationError("provider_purchase_sha256 must be unique")
        state.provider_purchase_sha256s.add(digest)

    def _prospect(self, state: _PilotState, value: object) -> tuple[str, _ProspectState]:
        prospect_id = self._opaque_id(value, OpaqueIdKind.PROSPECT, "prospect_id")
        try:
            return prospect_id, state.prospects[prospect_id]
        except KeyError as exc:
            raise PilotValidationError("prospect must be added before this event") from exc

    def _apply_event(
        self,
        state: _PilotState,
        event: PilotEventType,
        payload: Mapping[str, object],
        *,
        occurred_at: datetime,
    ) -> dict[str, object]:
        if event is PilotEventType.PILOT_LEDGER_INITIALIZED:
            raw_schema_version = payload.get("schema_version")
            if raw_schema_version == PILOT_LEDGER_SCHEMA_VERSION:
                data = self._fields(
                    payload,
                    {
                        "schema_version",
                        "prior_consumed_slots",
                        "reconciliation_schema_version",
                        "reconciliation_ref",
                        "reconciliation_evidence_sha256",
                        "reconciliation_record_sha256",
                        "reconciled_provider_purchase_sha256s",
                    },
                    {"prior_ledger_head_sha256"},
                )
            else:
                data = self._fields(
                    payload,
                    {
                        "schema_version",
                        "prior_consumed_slots",
                        "reconciliation_evidence_sha256",
                    },
                    {"prior_ledger_head_sha256"},
                )
            schema_version = self._integer(
                data["schema_version"],
                "schema_version",
                minimum=min(_PILOT_LEDGER_READABLE_SCHEMA_VERSIONS),
                maximum=PILOT_LEDGER_SCHEMA_VERSION,
            )
            if (
                state.event_count != 0
                or state.schema_version is not None
                or state.prospects
                or state.claimed_identifiers
            ):
                raise PilotValidationError("ledger initialization must be the first event")
            prior_consumed_slots = self._integer(
                data["prior_consumed_slots"],
                "prior_consumed_slots",
                minimum=0,
                maximum=FOUNDING_PURCHASE_LIMIT,
            )
            reconciliation_evidence_sha256 = self._sha256_digest(
                data["reconciliation_evidence_sha256"],
                "reconciliation_evidence_sha256",
            )
            reconciliation_schema_version: str | None = None
            reconciliation_ref: str | None = None
            reconciliation_record_sha256: str | None = None
            reconciled_provider_purchase_sha256s: tuple[str, ...] = ()
            if schema_version == PILOT_LEDGER_SCHEMA_VERSION:
                reconciliation_schema_version = self._machine_safe(
                    data["reconciliation_schema_version"],
                    re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$"),
                    "reconciliation_schema_version",
                )
                if reconciliation_schema_version != PILOT_RECONCILIATION_SCHEMA_VERSION:
                    raise PilotValidationError("reconciliation_schema_version is not supported")
                reconciliation_ref = self._machine_safe(
                    data["reconciliation_ref"],
                    re.compile(r"^rec_[0-9a-f]{32}$"),
                    "reconciliation_ref",
                )
                reconciliation_record_sha256 = self._sha256_digest(
                    data["reconciliation_record_sha256"],
                    "reconciliation_record_sha256",
                )
                raw_provider_purchase_sha256s = data["reconciled_provider_purchase_sha256s"]
                if not isinstance(raw_provider_purchase_sha256s, list):
                    raise PilotValidationError(
                        "reconciled_provider_purchase_sha256s must be an array"
                    )
                reconciled_provider_purchase_sha256s = tuple(
                    self._sha256_digest(item, "reconciled_provider_purchase_sha256s")
                    for item in raw_provider_purchase_sha256s
                )
                if len(set(reconciled_provider_purchase_sha256s)) != len(
                    reconciled_provider_purchase_sha256s
                ):
                    raise PilotValidationError(
                        "reconciled provider purchase digests must be unique"
                    )
                if len(reconciled_provider_purchase_sha256s) != prior_consumed_slots:
                    raise PilotValidationError(
                        "prior consumed slots require exact provider purchase bindings"
                    )
            prior_head_value = data.get("prior_ledger_head_sha256")
            prior_ledger_head_sha256 = (
                None
                if prior_head_value is None
                else self._sha256_digest(
                    prior_head_value,
                    "prior_ledger_head_sha256",
                )
            )
            if (
                schema_version < PILOT_LEDGER_SCHEMA_VERSION
                and prior_consumed_slots > 0
                and prior_ledger_head_sha256 is None
            ):
                raise PilotValidationError(
                    "prior consumed slots require a prior ledger head digest"
                )
            if (
                schema_version == 3
                and prior_consumed_slots == 0
                and prior_ledger_head_sha256 is not None
            ):
                raise PilotValidationError(
                    "schema version 3 cannot record a prior ledger head with zero slots"
                )
            state.schema_version = schema_version
            state.prior_consumed_slots = prior_consumed_slots
            state.reconciled_provider_purchase_sha256s = reconciled_provider_purchase_sha256s
            state.provider_purchase_sha256s.update(reconciled_provider_purchase_sha256s)
            normalized: dict[str, object] = {
                "schema_version": schema_version,
                "prior_consumed_slots": prior_consumed_slots,
                "reconciliation_evidence_sha256": reconciliation_evidence_sha256,
            }
            if schema_version == PILOT_LEDGER_SCHEMA_VERSION:
                assert reconciliation_schema_version is not None
                assert reconciliation_ref is not None
                assert reconciliation_record_sha256 is not None
                normalized.update(
                    {
                        "reconciliation_schema_version": reconciliation_schema_version,
                        "reconciliation_ref": reconciliation_ref,
                        "reconciliation_record_sha256": reconciliation_record_sha256,
                        "reconciled_provider_purchase_sha256s": list(
                            reconciled_provider_purchase_sha256s
                        ),
                    }
                )
            if prior_ledger_head_sha256 is not None:
                normalized["prior_ledger_head_sha256"] = prior_ledger_head_sha256
            return normalized

        if state.schema_version is None:
            raise PilotValidationError("ledger initialization must be the first event")
        if state.schema_version == 3 and event not in _PILOT_LEDGER_SCHEMA_3_EVENT_TYPES:
            raise PilotValidationError(
                f"{event.value} is not supported by pilot ledger schema version 3"
            )

        if event is PilotEventType.OUTREACH_PLAN_IMPORTED:
            expected_fields = {
                "schema_version",
                "campaign_ref",
                "campaign_start",
                "campaign_end",
                "utc_offset_minutes",
                "daily_contact_limit",
                "controls",
                "prospects",
                "plan_sha256",
            }
            data = self._fields(payload, expected_fields)
            plan_payload = {key: value for key, value in data.items() if key != "plan_sha256"}
            try:
                plan = OutreachPlan.from_dict(plan_payload)
            except OutreachPlanError as exc:
                raise PilotValidationError("outreach plan is invalid") from exc
            if not plan.is_complete:
                raise PilotValidationError("outreach import requires a complete 50-prospect plan")
            plan_sha256 = self._sha256_digest(data["plan_sha256"], "plan_sha256")
            if not hmac.compare_digest(plan_sha256, plan.sha256):
                raise PilotValidationError("plan_sha256 does not match the outreach plan")
            if state.event_count != 1 or state.prospects or state.outreach_plan is not None:
                raise PilotValidationError(
                    "outreach plan must be imported immediately after ledger initialization"
                )
            imported_local_date = self._local_date(
                occurred_at,
                plan.utc_offset_minutes,
            )
            if imported_local_date > date.fromisoformat(plan.campaign_start) + timedelta(days=1):
                raise PilotValidationError(
                    "outreach plan must be imported no later than campaign day 2"
                )
            self._claim(state, plan.campaign_ref, "campaign_ref")
            self._claim(state, plan_sha256, "plan_sha256")
            self._claim(
                state,
                plan.controls.evidence_sha256,
                "controls.evidence_sha256",
            )
            for entry in plan.prospects:
                prospect_id = self._opaque_id(
                    entry.prospect_id,
                    OpaqueIdKind.PROSPECT,
                    "prospect_id",
                )
                segment_value = self._enum(entry.segment, ProspectSegment, "segment")
                channel_value = self._enum(entry.channel, ContactChannel, "channel")
                self._claim(state, prospect_id, "prospect_id")
                for field_name, digest in (
                    (
                        "qualification_evidence_sha256",
                        entry.qualification_evidence_sha256,
                    ),
                    (
                        "recent_work_reference_sha256",
                        entry.recent_work_reference_sha256,
                    ),
                    ("sample_insight_sha256", entry.sample_insight_sha256),
                ):
                    self._claim(state, digest, field_name)
                state.prospects[prospect_id] = _ProspectState(
                    segment=ProspectSegment(segment_value),
                    queue_position=entry.queue_position,
                    planned_contact_date=entry.planned_contact_date,
                    planned_channel=ContactChannel(channel_value),
                    qualification_evidence_sha256=(entry.qualification_evidence_sha256),
                    recent_work_reference_sha256=(entry.recent_work_reference_sha256),
                    sample_insight_sha256=entry.sample_insight_sha256,
                )
            state.outreach_plan = plan
            return {**plan.to_dict(), "plan_sha256": plan_sha256}

        if event is PilotEventType.OUTREACH_PLAN_AMENDED:
            expected_fields = {
                "schema_version",
                "campaign_ref",
                "campaign_start",
                "campaign_end",
                "utc_offset_minutes",
                "daily_contact_limit",
                "controls",
                "prospects",
                "plan_sha256",
                "supersedes_plan_sha256",
            }
            data = self._fields(payload, expected_fields)
            plan_payload = {
                key: value
                for key, value in data.items()
                if key not in {"plan_sha256", "supersedes_plan_sha256"}
            }
            try:
                plan = OutreachPlan.from_dict(plan_payload)
            except OutreachPlanError as exc:
                raise PilotValidationError("outreach plan amendment is invalid") from exc
            if not plan.is_complete:
                raise PilotValidationError(
                    "outreach amendment requires a complete 50-prospect plan"
                )
            current = state.outreach_plan
            if current is None:
                raise PilotValidationError("an outreach plan must be imported before amendment")
            supersedes_plan_sha256 = self._sha256_digest(
                data["supersedes_plan_sha256"],
                "supersedes_plan_sha256",
            )
            if not hmac.compare_digest(supersedes_plan_sha256, current.sha256):
                raise PilotValidationError(
                    "supersedes_plan_sha256 does not match the active outreach plan"
                )
            plan_sha256 = self._sha256_digest(data["plan_sha256"], "plan_sha256")
            if not hmac.compare_digest(plan_sha256, plan.sha256):
                raise PilotValidationError("plan_sha256 does not match the outreach plan")

            current_document = current.to_dict()
            amended_document = plan.to_dict()
            current_contract = {
                key: value for key, value in current_document.items() if key != "prospects"
            }
            amended_contract = {
                key: value for key, value in amended_document.items() if key != "prospects"
            }
            if current_contract != amended_contract:
                raise PilotValidationError(
                    "outreach amendment cannot change campaign controls or dates"
                )
            current_by_position = {item.queue_position: item for item in current.prospects}
            amended_by_position = {item.queue_position: item for item in plan.prospects}
            changed = [
                (current_by_position[position], amended_by_position[position])
                for position in sorted(current_by_position)
                if current_by_position[position] != amended_by_position[position]
            ]
            if len(changed) != 1:
                raise PilotValidationError("outreach amendment must replace exactly one prospect")
            replaced_entry, replacement_entry = changed[0]
            if replaced_entry.prospect_id == replacement_entry.prospect_id:
                raise PilotValidationError("outreach amendment requires a new opaque prospect ID")
            if replaced_entry.planned_contact_date != replacement_entry.planned_contact_date:
                raise PilotValidationError("replacement must retain the planned contact date")
            replaced = state.prospects.get(replaced_entry.prospect_id)
            if replaced is None or not replaced.opted_out or replaced.contacted:
                raise PilotValidationError(
                    "only an opted-out prospect that was not contacted may be replaced"
                )
            amended_local_date = self._local_date(
                occurred_at,
                current.utc_offset_minutes,
            )
            if amended_local_date > date.fromisoformat(replaced_entry.planned_contact_date):
                raise PilotValidationError(
                    "an opted-out prospect must be replaced no later than its planned date"
                )

            replacement_id = self._opaque_id(
                replacement_entry.prospect_id,
                OpaqueIdKind.PROSPECT,
                "prospect_id",
            )
            segment_value = self._enum(
                replacement_entry.segment,
                ProspectSegment,
                "segment",
            )
            channel_value = self._enum(
                replacement_entry.channel,
                ContactChannel,
                "channel",
            )
            self._claim(state, plan_sha256, "plan_sha256")
            self._claim(state, replacement_id, "prospect_id")
            for field_name, digest in (
                (
                    "qualification_evidence_sha256",
                    replacement_entry.qualification_evidence_sha256,
                ),
                (
                    "recent_work_reference_sha256",
                    replacement_entry.recent_work_reference_sha256,
                ),
                ("sample_insight_sha256", replacement_entry.sample_insight_sha256),
            ):
                self._claim(state, digest, field_name)
            state.prospects[replacement_id] = _ProspectState(
                segment=ProspectSegment(segment_value),
                queue_position=replacement_entry.queue_position,
                planned_contact_date=replacement_entry.planned_contact_date,
                planned_channel=ContactChannel(channel_value),
                qualification_evidence_sha256=(replacement_entry.qualification_evidence_sha256),
                recent_work_reference_sha256=(replacement_entry.recent_work_reference_sha256),
                sample_insight_sha256=replacement_entry.sample_insight_sha256,
            )
            state.outreach_plan = plan
            return {
                **plan.to_dict(),
                "plan_sha256": plan_sha256,
                "supersedes_plan_sha256": supersedes_plan_sha256,
            }

        if event is PilotEventType.PROSPECT_ADDED:
            if state.outreach_plan is not None:
                raise PilotValidationError(
                    "manual prospects cannot be added after an outreach plan import"
                )
            data = self._fields(payload, {"prospect_id", "segment"})
            prospect_id = self._opaque_id(data["prospect_id"], OpaqueIdKind.PROSPECT, "prospect_id")
            segment = self._enum(data["segment"], ProspectSegment, "segment")
            self._claim(state, prospect_id, "prospect_id")
            state.prospects[prospect_id] = _ProspectState(ProspectSegment(segment))
            return {"prospect_id": prospect_id, "segment": segment.value}

        if event is PilotEventType.RISK_INCIDENT_RECORDED:
            data = self._fields(
                payload,
                {"incident_id", "kind", "severity"},
                {"prospect_id"},
            )
            incident_id = self._opaque_id(data["incident_id"], OpaqueIdKind.INCIDENT, "incident_id")
            kind = self._enum(data["kind"], RiskKind, "kind")
            severity = self._enum(data["severity"], RiskSeverity, "severity")
            incident_payload: dict[str, object] = {
                "incident_id": incident_id,
                "kind": kind.value,
                "severity": severity.value,
            }
            if "prospect_id" in data:
                incident_prospect_id, _ = self._prospect(state, data["prospect_id"])
                incident_payload["prospect_id"] = incident_prospect_id
            self._claim(state, incident_id, "incident_id")
            state.risk_incidents += 1
            return incident_payload

        if not isinstance(payload, Mapping) or "prospect_id" not in payload:
            raise PilotValidationError("missing required fields: prospect_id")
        prospect_id, prospect = self._prospect(state, payload["prospect_id"])
        if prospect.order_rejection_ref is not None and event not in {
            PilotEventType.REFUNDED,
            PilotEventType.OPTED_OUT,
            PilotEventType.SUPPRESSION_CHECKED,
            PilotEventType.OWNER_TIME_RECORDED,
        }:
            raise PilotValidationError(
                "a rejected order allows only refund, suppression, and bookkeeping events"
            )

        if event is PilotEventType.SUPPRESSION_CHECKED:
            data = self._fields(
                payload,
                {"prospect_id", "status", "evidence_sha256"},
                {"evidence_observed_at"},
            )
            if state.outreach_plan is None or prospect.queue_position is None:
                raise PilotValidationError("suppression checks require an imported outreach plan")
            status_value = self._enum(
                data["status"],
                SuppressionStatus,
                "status",
            )
            status = SuppressionStatus(status_value)
            if status is SuppressionStatus.RECHECK_REQUIRED:
                raise PilotValidationError("RECHECK_REQUIRED is a derived queue state")
            if prospect.opted_out and status is not SuppressionStatus.OPTED_OUT:
                raise PilotValidationError("an opt-out cannot be cleared")
            if prospect.contacted and status is SuppressionStatus.CLEAR:
                raise PilotValidationError(
                    "a clear suppression check must be recorded before contact"
                )
            evidence_sha256 = self._sha256_digest(
                data["evidence_sha256"],
                "evidence_sha256",
            )
            if state.outreach_plan is not None and "evidence_observed_at" not in data:
                raise PilotValidationError(
                    "campaign suppression checks require evidence_observed_at"
                )
            evidence_observed_at = self._normalize_timestamp(
                data.get("evidence_observed_at", occurred_at.isoformat())
            )
            evidence_age = occurred_at - evidence_observed_at
            if not timedelta(0) <= evidence_age <= timedelta(
                hours=SUPPRESSION_CLEAR_HOURS
            ):
                raise PilotValidationError(
                    "suppression evidence must be observed in the prior 24 hours"
                )
            self._claim(state, evidence_sha256, "evidence_sha256")
            prospect.suppression_status = status
            prospect.suppression_checked_at = evidence_observed_at
            prospect.suppression_evidence_sha256 = evidence_sha256
            if status is SuppressionStatus.OPTED_OUT:
                prospect.opted_out = True
            normalized_suppression: dict[str, object] = {
                "prospect_id": prospect_id,
                "status": status.value,
                "evidence_sha256": evidence_sha256,
            }
            if "evidence_observed_at" in data:
                normalized_suppression["evidence_observed_at"] = (
                    evidence_observed_at.isoformat()
                )
            return normalized_suppression

        if event is PilotEventType.CONTACTED:
            evidence_fields = {
                "contact_evidence_sha256",
                "sender_profile_evidence_sha256",
                "suppression_evidence_sha256",
                "message_copy_sha256",
                "provider_send_evidence_sha256",
                "provider_message_sha256",
                "contact_evidence_observed_at",
            }
            data = self._fields(payload, {"prospect_id", "channel"}, evidence_fields)
            if prospect.opted_out:
                raise PilotValidationError("contact is suppressed after opt-out")
            if prospect.contacted:
                raise PilotValidationError("prospect has already been contacted")
            channel = self._enum(data["channel"], ContactChannel, "channel")
            if state.outreach_plan is not None:
                plan = state.outreach_plan
                if (
                    prospect.queue_position is None
                    or prospect.planned_contact_date is None
                    or prospect.planned_channel is None
                ):
                    raise PilotValidationError(
                        "contact requires a prospect from the imported outreach plan"
                    )
                if ContactChannel(channel) is not prospect.planned_channel:
                    raise PilotValidationError(
                        "contact channel must match the imported outreach plan"
                    )
                contact_date = self._local_date(
                    occurred_at,
                    plan.utc_offset_minutes,
                )
                if contact_date < date.fromisoformat(prospect.planned_contact_date):
                    raise PilotValidationError(
                        "contact cannot occur before its planned contact date"
                    )
                contact_window_end = date.fromisoformat(plan.campaign_start) + timedelta(
                    days=OUTREACH_WINDOW_END_DAY - 1
                )
                if contact_date > contact_window_end:
                    raise PilotValidationError(
                        "contact cannot occur after the campaign day-7 outreach window"
                    )
                if not self._suppression_is_fresh(prospect, occurred_at):
                    raise PilotValidationError(
                        "contact requires a clear suppression check from the prior 24 hours"
                    )
                contacts_today = sum(
                    item.contacted_at is not None
                    and self._local_date(
                        item.contacted_at,
                        plan.utc_offset_minutes,
                    )
                    == contact_date
                    for item in state.prospects.values()
                )
                if contacts_today >= plan.daily_contact_limit:
                    raise PilotValidationError("daily contact limit has already been reached")
                missing_evidence = evidence_fields - set(data)
                if missing_evidence:
                    raise PilotValidationError(
                        "campaign contact requires validated post-send contact evidence"
                    )
                suppression_evidence_sha256 = self._sha256_digest(
                    data["suppression_evidence_sha256"],
                    "suppression_evidence_sha256",
                )
                if prospect.suppression_evidence_sha256 is None or not hmac.compare_digest(
                    suppression_evidence_sha256,
                    prospect.suppression_evidence_sha256,
                ):
                    raise PilotValidationError(
                        "contact evidence does not match the latest suppression check"
                    )
                contact_evidence_observed_at = self._normalize_timestamp(
                    data["contact_evidence_observed_at"]
                )
                recording_delay = occurred_at - contact_evidence_observed_at
                if not timedelta(0) <= recording_delay <= timedelta(
                    minutes=CONTACT_EVIDENCE_MAX_RECORDING_DELAY_MINUTES
                ):
                    raise PilotValidationError(
                        "contact must be recorded within 15 minutes after provider send evidence"
                    )
                contact_evidence_sha256 = self._sha256_digest(
                    data["contact_evidence_sha256"],
                    "contact_evidence_sha256",
                )
                sender_profile_evidence_sha256 = self._sha256_digest(
                    data["sender_profile_evidence_sha256"],
                    "sender_profile_evidence_sha256",
                )
                message_copy_sha256 = self._sha256_digest(
                    data["message_copy_sha256"],
                    "message_copy_sha256",
                )
                provider_send_evidence_sha256 = self._sha256_digest(
                    data["provider_send_evidence_sha256"],
                    "provider_send_evidence_sha256",
                )
                provider_message_sha256 = self._sha256_digest(
                    data["provider_message_sha256"],
                    "provider_message_sha256",
                )
                for field_name, digest in (
                    ("contact_evidence_sha256", contact_evidence_sha256),
                    ("message_copy_sha256", message_copy_sha256),
                    ("provider_send_evidence_sha256", provider_send_evidence_sha256),
                    ("provider_message_sha256", provider_message_sha256),
                ):
                    self._claim(state, digest, field_name)
                prospect.contact_evidence_sha256 = contact_evidence_sha256
                prospect.sender_profile_evidence_sha256 = (
                    sender_profile_evidence_sha256
                )
                prospect.message_copy_sha256 = message_copy_sha256
                prospect.provider_send_evidence_sha256 = (
                    provider_send_evidence_sha256
                )
                prospect.provider_message_sha256 = provider_message_sha256
            prospect.contacted = True
            prospect.contacted_at = occurred_at
            normalized_contact: dict[str, object] = {
                "prospect_id": prospect_id,
                "channel": channel.value,
            }
            for field_name in sorted(evidence_fields):
                if field_name in data:
                    normalized_contact[field_name] = data[field_name]
            return normalized_contact

        if event is PilotEventType.REPLIED:
            data = self._fields(payload, {"prospect_id", "outcome"})
            if prospect.opted_out:
                raise PilotValidationError("funnel events are suppressed after opt-out")
            if not prospect.contacted:
                raise PilotValidationError("reply requires a prior contact")
            if prospect.reply_outcome is not None:
                raise PilotValidationError("reply has already been recorded")
            outcome = self._enum(data["outcome"], ReplyOutcome, "outcome")
            prospect.reply_outcome = ReplyOutcome(outcome)
            return {"prospect_id": prospect_id, "outcome": outcome.value}

        if event is PilotEventType.SAMPLE_REQUESTED:
            self._fields(payload, {"prospect_id"})
            if prospect.opted_out:
                raise PilotValidationError("funnel events are suppressed after opt-out")
            if prospect.reply_outcome is not ReplyOutcome.INTERESTED:
                raise PilotValidationError("sample request requires an interested reply")
            if prospect.sample_requested:
                raise PilotValidationError("sample request has already been recorded")
            prospect.sample_requested = True
            return {"prospect_id": prospect_id}

        if event is PilotEventType.SCOPE_CONFIRMED:
            data = self._fields(
                payload,
                {"prospect_id", "scope_ref", "deadline", "terms_version", "claim_ids"},
            )
            if prospect.opted_out:
                raise PilotValidationError("funnel events are suppressed after opt-out")
            if not prospect.sample_requested:
                raise PilotValidationError("scope confirmation requires a prior sample request")
            if prospect.checkout_ref is not None:
                raise PilotValidationError("scope must be confirmed before checkout")
            if prospect.scope_ref is not None:
                raise PilotValidationError("scope has already been confirmed")
            scope_ref = self._opaque_id(data["scope_ref"], OpaqueIdKind.SCOPE, "scope_ref")
            deadline = self._deadline(data["deadline"])
            terms_version = self._machine_safe(
                data["terms_version"], _TERMS_VERSION_RE, "terms_version"
            )
            raw_claim_ids = data["claim_ids"]
            if not isinstance(raw_claim_ids, list) or not 1 <= len(raw_claim_ids) <= 100:
                raise PilotValidationError("claim_ids must contain from 1 through 100 IDs")
            claim_ids = tuple(
                self._machine_safe(item, _CLAIM_ID_RE, "claim_ids") for item in raw_claim_ids
            )
            if len(set(claim_ids)) != len(claim_ids):
                raise PilotValidationError("claim_ids must be unique")
            self._claim(state, scope_ref, "scope_ref")
            prospect.scope_ref = scope_ref
            prospect.scope_revision = 1
            prospect.deadline = deadline
            prospect.terms_version = terms_version
            prospect.claim_ids = claim_ids
            return {
                "prospect_id": prospect_id,
                "scope_ref": scope_ref,
                "deadline": deadline,
                "terms_version": terms_version,
                "claim_ids": list(claim_ids),
            }

        if event is PilotEventType.SCOPE_AMENDED:
            data = self._fields(
                payload,
                {
                    "prospect_id",
                    "supersedes_scope_ref",
                    "scope_ref",
                    "deadline",
                    "terms_version",
                    "claim_ids",
                },
            )
            if prospect.scope_ref is None:
                raise PilotValidationError("scope amendment requires an active scope")
            if prospect.fulfillment_started:
                raise PilotValidationError("scope cannot be amended after fulfillment starts")
            if prospect.cancellation_ref is not None:
                raise PilotValidationError("scope cannot be amended after cancellation")
            if prospect.refunded:
                raise PilotValidationError("scope cannot be amended after refund")
            supersedes_scope_ref = self._opaque_id(
                data["supersedes_scope_ref"],
                OpaqueIdKind.SCOPE,
                "supersedes_scope_ref",
            )
            if supersedes_scope_ref != prospect.scope_ref:
                raise PilotValidationError("supersedes_scope_ref does not match the active scope")
            scope_ref = self._opaque_id(
                data["scope_ref"],
                OpaqueIdKind.SCOPE,
                "scope_ref",
            )
            deadline = self._deadline(data["deadline"])
            terms_version = self._machine_safe(
                data["terms_version"], _TERMS_VERSION_RE, "terms_version"
            )
            raw_claim_ids = data["claim_ids"]
            if not isinstance(raw_claim_ids, list) or not 1 <= len(raw_claim_ids) <= 100:
                raise PilotValidationError("claim_ids must contain from 1 through 100 IDs")
            claim_ids = tuple(
                self._machine_safe(item, _CLAIM_ID_RE, "claim_ids") for item in raw_claim_ids
            )
            if len(set(claim_ids)) != len(claim_ids):
                raise PilotValidationError("claim_ids must be unique")
            self._claim(state, scope_ref, "scope_ref")
            prospect.scope_ref = scope_ref
            prospect.scope_revision += 1
            prospect.deadline = deadline
            prospect.terms_version = terms_version
            prospect.claim_ids = claim_ids
            prospect.customer_acceptance_ref = None
            prospect.customer_acceptance_evidence_sha256 = None
            prospect.order_acceptance_ref = None
            prospect.order_acceptance_evidence_sha256 = None
            return {
                "prospect_id": prospect_id,
                "supersedes_scope_ref": supersedes_scope_ref,
                "scope_ref": scope_ref,
                "deadline": deadline,
                "terms_version": terms_version,
                "claim_ids": list(claim_ids),
            }

        if event is PilotEventType.CUSTOMER_ACCEPTANCE_RECORDED:
            data = self._fields(
                payload,
                {
                    "prospect_id",
                    "scope_ref",
                    "customer_acceptance_ref",
                    "acceptance_evidence_sha256",
                },
            )
            if prospect.opted_out:
                raise PilotValidationError("funnel events are suppressed after opt-out")
            if prospect.scope_ref is None:
                raise PilotValidationError(
                    "written customer acceptance requires confirmed pre-payment scope"
                )
            scope_ref = self._opaque_id(
                data["scope_ref"],
                OpaqueIdKind.SCOPE,
                "scope_ref",
            )
            if scope_ref != prospect.scope_ref:
                raise PilotValidationError("customer acceptance does not match the active scope")
            if prospect.checkout_ref is not None and prospect.scope_revision == 1:
                raise PilotValidationError("written customer acceptance must precede checkout")
            if prospect.customer_acceptance_ref is not None:
                raise PilotValidationError("written customer acceptance is already recorded")
            acceptance_ref = self._opaque_id(
                data["customer_acceptance_ref"],
                OpaqueIdKind.CUSTOMER_ACCEPTANCE,
                "customer_acceptance_ref",
            )
            evidence_sha256 = self._sha256_digest(
                data["acceptance_evidence_sha256"], "acceptance_evidence_sha256"
            )
            self._claim(state, acceptance_ref, "customer_acceptance_ref")
            prospect.customer_acceptance_ref = acceptance_ref
            prospect.customer_acceptance_evidence_sha256 = evidence_sha256
            return {
                "prospect_id": prospect_id,
                "scope_ref": scope_ref,
                "customer_acceptance_ref": acceptance_ref,
                "acceptance_evidence_sha256": evidence_sha256,
            }

        if event is PilotEventType.CHECKOUT_SENT:
            data = self._fields(payload, {"prospect_id", "checkout_ref"})
            if prospect.opted_out:
                raise PilotValidationError("checkout contact is suppressed after opt-out")
            if prospect.scope_ref is None:
                raise PilotValidationError("checkout requires confirmed pre-payment scope")
            if prospect.customer_acceptance_ref is None:
                raise PilotValidationError("checkout requires written customer acceptance")
            if prospect.checkout_ref is not None:
                raise PilotValidationError("checkout has already been sent")
            checkout_ref = self._opaque_id(
                data["checkout_ref"], OpaqueIdKind.CHECKOUT, "checkout_ref"
            )
            self._claim(state, checkout_ref, "checkout_ref")
            prospect.checkout_ref = checkout_ref
            prospect.checkout_occurred_at = occurred_at
            return {"prospect_id": prospect_id, "checkout_ref": checkout_ref}

        if event is PilotEventType.PURCHASED:
            purchase_fields = {
                "prospect_id",
                "order_id",
                "payment_ref",
                "payment_mode",
                "payment_evidence_sha256",
                "payment_evidence_artifact_sha256",
                "payment_evidence_observed_at",
                "amount_cents",
                "fee_cents",
            }
            if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION:
                purchase_fields.update(
                    {
                        "provider_purchase_sha256",
                        "tax_amount_cents",
                        "gross_amount_cents",
                    }
                )
            data = self._fields(payload, purchase_fields)
            if prospect.checkout_ref is None:
                raise PilotValidationError("purchase requires a prior checkout")
            if prospect.customer_acceptance_ref is None:
                raise PilotValidationError("purchase requires acceptance of the active scope")
            if prospect.order_id is not None:
                raise PilotValidationError("prospect already has a founding purchase")
            purchases = sum(item.order_id is not None for item in state.prospects.values())
            if state.prior_consumed_slots + purchases >= FOUNDING_PURCHASE_LIMIT:
                raise PilotValidationError("all five founding purchase slots are filled")
            order_id = self._opaque_id(data["order_id"], OpaqueIdKind.ORDER, "order_id")
            payment_ref = self._opaque_id(data["payment_ref"], OpaqueIdKind.PAYMENT, "payment_ref")
            payment_mode_value = self._enum(data["payment_mode"], PaymentMode, "payment_mode")
            payment_mode = PaymentMode(payment_mode_value)
            if payment_mode is not PaymentMode.LIVE:
                raise PilotValidationError("TEST purchases cannot enter the live revenue ledger")
            provider_purchase_sha256 = (
                self._sha256_digest(
                    data["provider_purchase_sha256"],
                    "provider_purchase_sha256",
                )
                if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION
                else None
            )
            payment_evidence_sha256 = self._sha256_digest(
                data["payment_evidence_sha256"], "payment_evidence_sha256"
            )
            payment_evidence_artifact_sha256 = self._sha256_digest(
                data["payment_evidence_artifact_sha256"],
                "payment_evidence_artifact_sha256",
            )
            payment_evidence_observed_at = self._normalize_timestamp(
                data["payment_evidence_observed_at"]
            )
            if prospect.checkout_occurred_at is None:
                raise PilotValidationError("purchase checkout chronology is incomplete")
            if payment_evidence_observed_at < prospect.checkout_occurred_at:
                raise PilotValidationError("payment evidence must be observed at or after checkout")
            if payment_evidence_observed_at > occurred_at:
                raise PilotValidationError(
                    "payment evidence cannot be observed after the purchase event"
                )
            amount_cents = self._integer(
                data["amount_cents"],
                "amount_cents",
                minimum=FOUNDING_PRICE_CENTS,
                maximum=FOUNDING_PRICE_CENTS,
            )
            tax_amount_cents = (
                self._integer(
                    data["tax_amount_cents"],
                    "tax_amount_cents",
                    minimum=0,
                    maximum=2**63 - 1 - amount_cents,
                )
                if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION
                else 0
            )
            gross_amount_cents = (
                self._integer(
                    data["gross_amount_cents"],
                    "gross_amount_cents",
                    minimum=amount_cents + tax_amount_cents,
                    maximum=amount_cents + tax_amount_cents,
                )
                if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION
                else amount_cents
            )
            fee_cents = self._integer(
                data["fee_cents"], "fee_cents", minimum=0, maximum=amount_cents
            )
            self._claim(state, order_id, "order_id")
            self._claim(state, payment_ref, "payment_ref")
            self._claim(
                state,
                payment_evidence_sha256,
                "payment_evidence_sha256",
            )
            self._claim(
                state,
                payment_evidence_artifact_sha256,
                "payment_evidence_artifact_sha256",
            )
            if provider_purchase_sha256 is not None:
                self._claim_provider_purchase(state, provider_purchase_sha256)
            prospect.order_id = order_id
            prospect.payment_ref = payment_ref
            prospect.payment_mode = payment_mode
            prospect.provider_purchase_sha256 = provider_purchase_sha256
            prospect.payment_evidence_sha256 = payment_evidence_sha256
            prospect.payment_evidence_artifact_sha256 = payment_evidence_artifact_sha256
            prospect.payment_evidence_observed_at = payment_evidence_observed_at
            prospect.purchase_amount_cents = amount_cents
            prospect.tax_amount_cents = tax_amount_cents
            prospect.gross_amount_cents = gross_amount_cents
            prospect.payment_fee_cents = fee_cents
            normalized_purchase: dict[str, object] = {
                "prospect_id": prospect_id,
                "order_id": order_id,
                "payment_ref": payment_ref,
                "payment_mode": payment_mode.value,
                "payment_evidence_sha256": payment_evidence_sha256,
                "payment_evidence_artifact_sha256": (payment_evidence_artifact_sha256),
                "payment_evidence_observed_at": (payment_evidence_observed_at.isoformat()),
                "amount_cents": amount_cents,
                "fee_cents": fee_cents,
            }
            if provider_purchase_sha256 is not None:
                normalized_purchase.update(
                    {
                        "provider_purchase_sha256": provider_purchase_sha256,
                        "tax_amount_cents": tax_amount_cents,
                        "gross_amount_cents": gross_amount_cents,
                    }
                )
            return normalized_purchase

        if event is PilotEventType.ORDER_ACCEPTED:
            data = self._fields(
                payload,
                {
                    "prospect_id",
                    "scope_ref",
                    "order_acceptance_ref",
                    "acceptance_evidence_sha256",
                },
            )
            if prospect.order_id is None:
                raise PilotValidationError("order acceptance requires a prior live purchase")
            if prospect.order_rejection_ref is not None:
                raise PilotValidationError("a rejected order cannot be accepted")
            if prospect.cancellation_ref is not None:
                raise PilotValidationError("a cancelled order cannot be accepted")
            if prospect.refunded:
                raise PilotValidationError("a refunded order cannot be accepted")
            if prospect.order_acceptance_ref is not None:
                raise PilotValidationError("order has already been accepted")
            if prospect.scope_ref is None:
                raise PilotValidationError("order acceptance requires an active scope")
            scope_ref = self._opaque_id(
                data["scope_ref"],
                OpaqueIdKind.SCOPE,
                "scope_ref",
            )
            if scope_ref != prospect.scope_ref:
                raise PilotValidationError("order acceptance does not match the active scope")
            acceptance_ref = self._opaque_id(
                data["order_acceptance_ref"],
                OpaqueIdKind.ORDER_ACCEPTANCE,
                "order_acceptance_ref",
            )
            evidence_sha256 = self._sha256_digest(
                data["acceptance_evidence_sha256"], "acceptance_evidence_sha256"
            )
            self._claim(state, acceptance_ref, "order_acceptance_ref")
            prospect.order_acceptance_ref = acceptance_ref
            prospect.order_acceptance_evidence_sha256 = evidence_sha256
            return {
                "prospect_id": prospect_id,
                "scope_ref": scope_ref,
                "order_acceptance_ref": acceptance_ref,
                "acceptance_evidence_sha256": evidence_sha256,
            }

        if event is PilotEventType.ORDER_REJECTED:
            data = self._fields(payload, {"prospect_id", "order_rejection_ref"})
            if prospect.order_id is None:
                raise PilotValidationError("order rejection requires a prior live purchase")
            if prospect.order_acceptance_ref is not None:
                raise PilotValidationError("an accepted order cannot be rejected")
            if prospect.cancellation_ref is not None:
                raise PilotValidationError("a cancelled order cannot be rejected")
            if prospect.refunded:
                raise PilotValidationError("a refunded order cannot be rejected")
            if prospect.order_rejection_ref is not None:
                raise PilotValidationError("order has already been rejected")
            rejection_ref = self._opaque_id(
                data["order_rejection_ref"],
                OpaqueIdKind.ORDER_REJECTION,
                "order_rejection_ref",
            )
            self._claim(state, rejection_ref, "order_rejection_ref")
            prospect.order_rejection_ref = rejection_ref
            return {
                "prospect_id": prospect_id,
                "order_rejection_ref": rejection_ref,
            }

        if event is PilotEventType.CANCELLATION_REQUESTED:
            data = self._fields(payload, {"prospect_id", "cancellation_ref"})
            if prospect.order_id is None:
                raise PilotValidationError("cancellation requires a prior live purchase")
            if prospect.order_rejection_ref is not None:
                raise PilotValidationError("a rejected order can only be refunded")
            if prospect.refunded:
                raise PilotValidationError("a refunded order cannot be cancelled")
            if prospect.cancellation_ref is not None:
                raise PilotValidationError("cancellation has already been recorded")
            cancellation_ref = self._opaque_id(
                data["cancellation_ref"],
                OpaqueIdKind.CANCELLATION,
                "cancellation_ref",
            )
            self._claim(state, cancellation_ref, "cancellation_ref")
            prospect.cancellation_ref = cancellation_ref
            return {
                "prospect_id": prospect_id,
                "cancellation_ref": cancellation_ref,
            }

        if event is PilotEventType.OPTED_OUT:
            data = self._fields(
                payload,
                {"prospect_id"},
                (
                    {"evidence_sha256"}
                    if state.schema_version in {4, PILOT_LEDGER_SCHEMA_VERSION}
                    else None
                ),
            )
            if prospect.opted_out:
                raise PilotValidationError("opt-out has already been recorded")
            evidence_value = data.get("evidence_sha256")
            if state.outreach_plan is not None and evidence_value is None:
                raise PilotValidationError("campaign opt-out requires a redacted evidence digest")
            opt_out_evidence_sha256 = (
                None
                if evidence_value is None
                else self._sha256_digest(evidence_value, "evidence_sha256")
            )
            if opt_out_evidence_sha256 is not None:
                self._claim(state, opt_out_evidence_sha256, "evidence_sha256")
            prospect.opted_out = True
            prospect.suppression_status = SuppressionStatus.OPTED_OUT
            prospect.suppression_checked_at = occurred_at
            prospect.suppression_evidence_sha256 = opt_out_evidence_sha256
            normalized_opt_out: dict[str, object] = {"prospect_id": prospect_id}
            if opt_out_evidence_sha256 is not None:
                normalized_opt_out["evidence_sha256"] = opt_out_evidence_sha256
            return normalized_opt_out

        if event is PilotEventType.OWNER_TIME_RECORDED:
            data = self._fields(payload, {"prospect_id", "time_entry_id", "category", "minutes"})
            time_entry_id = self._opaque_id(
                data["time_entry_id"], OpaqueIdKind.TIME_ENTRY, "time_entry_id"
            )
            category_value = self._enum(data["category"], OwnerTimeCategory, "category")
            category = OwnerTimeCategory(category_value)
            minutes = self._integer(data["minutes"], "minutes", minimum=1, maximum=1_440)
            if category is OwnerTimeCategory.SAMPLE and not prospect.sample_requested:
                raise PilotValidationError("sample time requires a prior sample request")
            if category is OwnerTimeCategory.FULFILLMENT:
                if prospect.order_acceptance_ref is None:
                    raise PilotValidationError(
                        "fulfillment time requires post-payment order acceptance"
                    )
                if not prospect.fulfillment_started:
                    raise PilotValidationError("fulfillment time requires fulfillment to start")
                if prospect.cancellation_ref is not None:
                    raise PilotValidationError("fulfillment time is blocked after cancellation")
                if prospect.refunded:
                    raise PilotValidationError("refunded work cannot record fulfillment time")
            self._claim(state, time_entry_id, "time_entry_id")
            state.owner_minutes += minutes
            state.owner_minutes_by_category[category] = (
                state.owner_minutes_by_category.get(category, 0) + minutes
            )
            return {
                "prospect_id": prospect_id,
                "time_entry_id": time_entry_id,
                "category": category.value,
                "minutes": minutes,
            }

        if event is PilotEventType.FULFILLMENT_STARTED:
            self._fields(payload, {"prospect_id"})
            if prospect.order_id is None:
                raise PilotValidationError("fulfillment requires a prior purchase")
            if prospect.order_acceptance_ref is None:
                raise PilotValidationError("fulfillment requires post-payment order acceptance")
            if prospect.cancellation_ref is not None:
                raise PilotValidationError("fulfillment is blocked after cancellation")
            if prospect.refunded:
                raise PilotValidationError("refunded work cannot enter fulfillment")
            if prospect.fulfillment_started:
                raise PilotValidationError("fulfillment has already started")
            prospect.fulfillment_started = True
            return {"prospect_id": prospect_id}

        if event is PilotEventType.ARTIFACT_COMPLETED:
            data = self._fields(payload, {"prospect_id", "deliverable_sha256"})
            if not prospect.fulfillment_started:
                raise PilotValidationError("artifact completion requires fulfillment to start")
            if prospect.cancellation_ref is not None:
                raise PilotValidationError("artifact completion is blocked after cancellation")
            if prospect.refunded:
                raise PilotValidationError("refunded work cannot be completed")
            if prospect.artifact_completed:
                raise PilotValidationError("artifact completion has already been recorded")
            deliverable_sha256 = self._sha256_digest(
                data["deliverable_sha256"], "deliverable_sha256"
            )
            prospect.artifact_completed = True
            prospect.artifact_completed_at = occurred_at
            prospect.deliverable_sha256 = deliverable_sha256
            return {
                "prospect_id": prospect_id,
                "deliverable_sha256": deliverable_sha256,
            }

        if event is PilotEventType.DELIVERED:
            data = self._fields(
                payload,
                {
                    "prospect_id",
                    "order_id",
                    "delivery_ref",
                    "delivery_method",
                    "deliverable_sha256",
                    "delivery_evidence_sha256",
                    "delivery_evidence_artifact_sha256",
                    "delivery_evidence_observed_at",
                },
            )
            if not prospect.artifact_completed or prospect.deliverable_sha256 is None:
                raise PilotValidationError("delivery requires a completed artifact")
            if prospect.cancellation_ref is not None:
                raise PilotValidationError("delivery is blocked after cancellation")
            if prospect.refunded:
                raise PilotValidationError("refunded work cannot be delivered")
            if prospect.delivered:
                raise PilotValidationError("delivery has already been recorded")
            order_id = self._opaque_id(data["order_id"], OpaqueIdKind.ORDER, "order_id")
            if order_id != prospect.order_id:
                raise PilotValidationError("delivery order_id does not match the purchase")
            delivery_ref = self._opaque_id(
                data["delivery_ref"], OpaqueIdKind.DELIVERY, "delivery_ref"
            )
            delivery_method_value = self._enum(
                data["delivery_method"], DeliveryMethod, "delivery_method"
            )
            delivery_method = DeliveryMethod(delivery_method_value)
            deliverable_sha256 = self._sha256_digest(
                data["deliverable_sha256"], "deliverable_sha256"
            )
            if not hmac.compare_digest(
                deliverable_sha256,
                prospect.deliverable_sha256,
            ):
                raise PilotValidationError(
                    "delivery evidence does not match the completed artifact"
                )
            delivery_evidence_sha256 = self._sha256_digest(
                data["delivery_evidence_sha256"],
                "delivery_evidence_sha256",
            )
            delivery_evidence_artifact_sha256 = self._sha256_digest(
                data["delivery_evidence_artifact_sha256"],
                "delivery_evidence_artifact_sha256",
            )
            if hmac.compare_digest(
                delivery_evidence_artifact_sha256,
                deliverable_sha256,
            ):
                raise PilotValidationError(
                    "delivery evidence artifact must differ from the delivered artifact"
                )
            delivery_evidence_observed_at = self._normalize_timestamp(
                data["delivery_evidence_observed_at"]
            )
            if prospect.artifact_completed_at is None:
                raise PilotValidationError("delivery artifact chronology is incomplete")
            if delivery_evidence_observed_at < prospect.artifact_completed_at:
                raise PilotValidationError(
                    "delivery evidence must be observed at or after artifact completion"
                )
            if delivery_evidence_observed_at > occurred_at:
                raise PilotValidationError(
                    "delivery evidence cannot be observed after the delivery event"
                )
            self._claim(state, delivery_ref, "delivery_ref")
            self._claim(
                state,
                delivery_evidence_sha256,
                "delivery_evidence_sha256",
            )
            self._claim(
                state,
                delivery_evidence_artifact_sha256,
                "delivery_evidence_artifact_sha256",
            )
            prospect.delivered = True
            prospect.delivery_ref = delivery_ref
            prospect.delivery_method = delivery_method
            prospect.delivery_evidence_sha256 = delivery_evidence_sha256
            prospect.delivery_evidence_artifact_sha256 = delivery_evidence_artifact_sha256
            prospect.delivery_evidence_observed_at = delivery_evidence_observed_at
            return {
                "prospect_id": prospect_id,
                "order_id": order_id,
                "delivery_ref": delivery_ref,
                "delivery_method": delivery_method.value,
                "deliverable_sha256": deliverable_sha256,
                "delivery_evidence_sha256": delivery_evidence_sha256,
                "delivery_evidence_artifact_sha256": (delivery_evidence_artifact_sha256),
                "delivery_evidence_observed_at": (delivery_evidence_observed_at.isoformat()),
            }

        if event is PilotEventType.FEEDBACK_RECORDED:
            data = self._fields(payload, {"prospect_id", "feedback_id", "outcomes"})
            if not prospect.delivered:
                raise PilotValidationError("feedback requires a prior delivery")
            if prospect.feedback_recorded:
                raise PilotValidationError("feedback has already been recorded")
            feedback_id = self._opaque_id(data["feedback_id"], OpaqueIdKind.FEEDBACK, "feedback_id")
            raw_outcomes = data["outcomes"]
            if not isinstance(raw_outcomes, list) or not raw_outcomes:
                raise PilotValidationError("outcomes must be a non-empty list")
            outcomes: list[str] = []
            for raw_outcome in raw_outcomes:
                outcome = self._enum(raw_outcome, FeedbackOutcome, "outcomes")
                outcomes.append(outcome.value)
            if len(set(outcomes)) != len(outcomes):
                raise PilotValidationError("feedback outcomes must be unique")
            if FeedbackOutcome.NONE_REPORTED.value in outcomes and len(outcomes) != 1:
                raise PilotValidationError("NONE_REPORTED cannot be combined with another outcome")
            self._claim(state, feedback_id, "feedback_id")
            prospect.feedback_recorded = True
            return {
                "prospect_id": prospect_id,
                "feedback_id": feedback_id,
                "outcomes": outcomes,
            }

        if event is PilotEventType.REFUNDED:
            refund_fields = {
                "prospect_id",
                "order_id",
                "refund_ref",
                "original_payment_ref",
                "refund_evidence_sha256",
                "refund_evidence_artifact_sha256",
                "refund_evidence_observed_at",
                "amount_cents",
            }
            if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION:
                refund_fields.update(
                    {
                        "provider_purchase_sha256",
                        "tax_amount_cents",
                        "gross_amount_cents",
                        "refunded_amount_cents",
                    }
                )
            data = self._fields(payload, refund_fields)
            if prospect.order_id is None:
                raise PilotValidationError("refund requires a prior purchase")
            order_id = self._opaque_id(data["order_id"], OpaqueIdKind.ORDER, "order_id")
            if order_id != prospect.order_id:
                raise PilotValidationError("refund order_id does not match the purchase")
            if prospect.refunded:
                raise PilotValidationError("purchase has already been refunded")
            original_payment_ref = self._opaque_id(
                data["original_payment_ref"],
                OpaqueIdKind.PAYMENT,
                "original_payment_ref",
            )
            if original_payment_ref != prospect.payment_ref:
                raise PilotValidationError("refund evidence does not match the original payment")
            provider_purchase_sha256 = (
                self._sha256_digest(
                    data["provider_purchase_sha256"],
                    "provider_purchase_sha256",
                )
                if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION
                else None
            )
            if provider_purchase_sha256 != prospect.provider_purchase_sha256:
                raise PilotValidationError("refund evidence does not match the provider purchase")
            refund_ref = self._opaque_id(data["refund_ref"], OpaqueIdKind.REFUND, "refund_ref")
            refund_evidence_sha256 = self._sha256_digest(
                data["refund_evidence_sha256"],
                "refund_evidence_sha256",
            )
            refund_evidence_artifact_sha256 = self._sha256_digest(
                data["refund_evidence_artifact_sha256"],
                "refund_evidence_artifact_sha256",
            )
            refund_evidence_observed_at = self._normalize_timestamp(
                data["refund_evidence_observed_at"]
            )
            if prospect.payment_evidence_observed_at is None:
                raise PilotValidationError("refund payment chronology is incomplete")
            if refund_evidence_observed_at < prospect.payment_evidence_observed_at:
                raise PilotValidationError(
                    "refund evidence must be observed at or after payment capture"
                )
            if refund_evidence_observed_at > occurred_at:
                raise PilotValidationError(
                    "refund evidence cannot be observed after the refund event"
                )
            amount_cents = self._integer(
                data["amount_cents"],
                "amount_cents",
                minimum=prospect.purchase_amount_cents,
                maximum=prospect.purchase_amount_cents,
            )
            tax_amount_cents = (
                self._integer(
                    data["tax_amount_cents"],
                    "tax_amount_cents",
                    minimum=prospect.tax_amount_cents,
                    maximum=prospect.tax_amount_cents,
                )
                if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION
                else 0
            )
            gross_amount_cents = (
                self._integer(
                    data["gross_amount_cents"],
                    "gross_amount_cents",
                    minimum=prospect.gross_amount_cents,
                    maximum=prospect.gross_amount_cents,
                )
                if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION
                else amount_cents
            )
            refunded_amount_cents = (
                self._integer(
                    data["refunded_amount_cents"],
                    "refunded_amount_cents",
                    minimum=gross_amount_cents,
                    maximum=gross_amount_cents,
                )
                if state.schema_version == PILOT_LEDGER_SCHEMA_VERSION
                else amount_cents
            )
            self._claim(state, refund_ref, "refund_ref")
            self._claim(
                state,
                refund_evidence_sha256,
                "refund_evidence_sha256",
            )
            self._claim(
                state,
                refund_evidence_artifact_sha256,
                "refund_evidence_artifact_sha256",
            )
            prospect.refunded = True
            prospect.refunded_amount_cents = refunded_amount_cents
            prospect.refund_ref = refund_ref
            prospect.refund_evidence_sha256 = refund_evidence_sha256
            prospect.refund_evidence_artifact_sha256 = refund_evidence_artifact_sha256
            prospect.refund_evidence_observed_at = refund_evidence_observed_at
            normalized_refund: dict[str, object] = {
                "prospect_id": prospect_id,
                "order_id": order_id,
                "refund_ref": refund_ref,
                "original_payment_ref": original_payment_ref,
                "refund_evidence_sha256": refund_evidence_sha256,
                "refund_evidence_artifact_sha256": (refund_evidence_artifact_sha256),
                "refund_evidence_observed_at": refund_evidence_observed_at.isoformat(),
                "amount_cents": amount_cents,
            }
            if provider_purchase_sha256 is not None:
                normalized_refund.update(
                    {
                        "provider_purchase_sha256": provider_purchase_sha256,
                        "tax_amount_cents": tax_amount_cents,
                        "gross_amount_cents": gross_amount_cents,
                        "refunded_amount_cents": refunded_amount_cents,
                    }
                )
            return normalized_refund

        raise PilotValidationError("event_type is not supported")

    @staticmethod
    def _local_date(value: datetime, utc_offset_minutes: int) -> date:
        return (value + timedelta(minutes=utc_offset_minutes)).date()

    @staticmethod
    def _suppression_is_fresh(
        prospect: _ProspectState,
        observed_at: datetime,
    ) -> bool:
        checked_at = prospect.suppression_checked_at
        if prospect.suppression_status is not SuppressionStatus.CLEAR or checked_at is None:
            return False
        age = observed_at - checked_at
        return timedelta(0) <= age <= timedelta(hours=SUPPRESSION_CLEAR_HOURS)

    def _project_outreach_entry(
        self,
        state: _PilotState,
        prospect_id: str,
        prospect: _ProspectState,
        observed_at: datetime,
    ) -> OutreachQueueEntry:
        plan = state.outreach_plan
        if (
            plan is None
            or prospect.queue_position is None
            or prospect.planned_contact_date is None
            or prospect.planned_channel is None
            or prospect.qualification_evidence_sha256 is None
            or prospect.recent_work_reference_sha256 is None
            or prospect.sample_insight_sha256 is None
        ):
            raise PilotReplayError("outreach queue projection is incomplete")
        local_date = self._local_date(observed_at, plan.utc_offset_minutes)
        planned_date = date.fromisoformat(prospect.planned_contact_date)
        contact_window_end = date.fromisoformat(plan.campaign_start) + timedelta(
            days=OUTREACH_WINDOW_END_DAY - 1
        )
        contacts_today = sum(
            item.contacted_at is not None
            and self._local_date(item.contacted_at, plan.utc_offset_minutes) == local_date
            for item in state.prospects.values()
        )
        contact_allowed = (
            not prospect.contacted
            and not prospect.opted_out
            and planned_date <= local_date <= contact_window_end
            and self._suppression_is_fresh(prospect, observed_at)
            and contacts_today < plan.daily_contact_limit
        )

        if prospect.opted_out:
            cadence_status = OutreachCadenceStatus.SUPPRESSED
            outcome = "OPTED_OUT"
            next_action = "STOP_CONTACT"
        elif prospect.contacted:
            cadence_status = (
                OutreachCadenceStatus.CONTACTED
                if prospect.reply_outcome is None
                else OutreachCadenceStatus.OUTCOME_RECORDED
            )
            if prospect.order_id is not None:
                outcome = "PURCHASED"
                next_action = "CONTINUE_ORDER_WORKFLOW"
            elif prospect.checkout_ref is not None:
                outcome = "CHECKOUT_SENT"
                next_action = "WAIT_FOR_PURCHASE_OUTCOME"
            elif prospect.sample_requested:
                outcome = "SAMPLE_REQUESTED"
                next_action = "CONTINUE_FIT_AND_SCOPE_WORKFLOW"
            elif prospect.reply_outcome is ReplyOutcome.INTERESTED:
                outcome = ReplyOutcome.INTERESTED.value
                next_action = "REVIEW_SAMPLE_REQUEST"
            elif prospect.reply_outcome is not None:
                outcome = prospect.reply_outcome.value
                next_action = "STOP_CONTACT"
            else:
                outcome = "AWAITING_REPLY"
                next_action = "WAIT_FOR_REPLY_OR_OPT_OUT"
        elif local_date < planned_date:
            cadence_status = OutreachCadenceStatus.SCHEDULED
            outcome = "NOT_CONTACTED"
            next_action = "WAIT_FOR_PLANNED_DATE"
        elif local_date > contact_window_end:
            cadence_status = OutreachCadenceStatus.OUTCOME_RECORDED
            outcome = "NOT_CONTACTED"
            next_action = "STOP_CONTACT"
        elif contacts_today >= plan.daily_contact_limit:
            outcome = "NOT_CONTACTED"
            if local_date == contact_window_end:
                cadence_status = OutreachCadenceStatus.OUTCOME_RECORDED
                next_action = "STOP_CONTACT"
            else:
                cadence_status = OutreachCadenceStatus.SCHEDULED
                next_action = "WAIT_FOR_NEXT_CONTACT_DAY"
        elif not self._suppression_is_fresh(prospect, observed_at):
            cadence_status = OutreachCadenceStatus.RECHECK_SUPPRESSION
            outcome = "NOT_CONTACTED"
            next_action = "RECORD_SUPPRESSION_CHECK"
        else:
            cadence_status = OutreachCadenceStatus.READY
            outcome = "NOT_CONTACTED"
            next_action = "RECORD_PERSONALIZED_CONTACT"

        return OutreachQueueEntry(
            campaign_ref=plan.campaign_ref,
            prospect_id=prospect_id,
            queue_position=prospect.queue_position,
            segment=prospect.segment,
            channel=prospect.planned_channel,
            planned_contact_date=prospect.planned_contact_date,
            qualification_status="ATTESTED_BY_IMPORT",
            suppression_status=prospect.suppression_status,
            suppression_checked_at=(
                None
                if prospect.suppression_checked_at is None
                else prospect.suppression_checked_at.isoformat()
            ),
            contacted_at=(
                None if prospect.contacted_at is None else prospect.contacted_at.isoformat()
            ),
            contact_evidence_status=(
                "VERIFIED"
                if prospect.contacted and prospect.contact_evidence_sha256 is not None
                else "NOT_RECORDED"
            ),
            cadence_status=cadence_status,
            outcome=outcome,
            next_action=next_action,
            contact_allowed=contact_allowed,
        )

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        if denominator == 0:
            return 0.0
        return round(numerator / denominator, 4)

    @staticmethod
    def _project_order(prospect_id: str, prospect: _ProspectState) -> PilotOrder:
        if (
            prospect.checkout_ref is None
            or prospect.checkout_occurred_at is None
            or prospect.order_id is None
            or prospect.payment_ref is None
            or prospect.scope_ref is None
            or prospect.customer_acceptance_ref is None
            or prospect.customer_acceptance_evidence_sha256 is None
            or prospect.payment_mode is None
            or prospect.payment_evidence_sha256 is None
            or prospect.payment_evidence_artifact_sha256 is None
            or prospect.payment_evidence_observed_at is None
            or prospect.deadline is None
            or prospect.terms_version is None
        ):
            raise PilotReplayError("purchased order projection is incomplete")
        if prospect.refunded:
            lifecycle = PilotOrderState.REFUNDED
        elif prospect.cancellation_ref is not None:
            lifecycle = PilotOrderState.CANCELLATION_REQUESTED
        elif prospect.order_rejection_ref is not None:
            lifecycle = PilotOrderState.ORDER_REJECTED
        elif prospect.delivered:
            lifecycle = PilotOrderState.DELIVERED
        elif prospect.artifact_completed:
            lifecycle = PilotOrderState.ARTIFACT_COMPLETED
        elif prospect.fulfillment_started:
            lifecycle = PilotOrderState.FULFILLMENT_STARTED
        elif prospect.order_acceptance_ref is not None:
            lifecycle = PilotOrderState.ORDER_ACCEPTED
        else:
            lifecycle = PilotOrderState.PURCHASED
        return PilotOrder(
            prospect_id=prospect_id,
            checkout_ref=prospect.checkout_ref,
            checkout_occurred_at=prospect.checkout_occurred_at.isoformat(),
            order_id=prospect.order_id,
            payment_ref=prospect.payment_ref,
            scope_ref=prospect.scope_ref,
            customer_acceptance_ref=prospect.customer_acceptance_ref,
            customer_acceptance_evidence_sha256=(prospect.customer_acceptance_evidence_sha256),
            payment_mode=prospect.payment_mode,
            provider_purchase_sha256=prospect.provider_purchase_sha256,
            payment_evidence_sha256=prospect.payment_evidence_sha256,
            payment_evidence_artifact_sha256=(prospect.payment_evidence_artifact_sha256),
            payment_evidence_observed_at=(prospect.payment_evidence_observed_at.isoformat()),
            order_acceptance_ref=prospect.order_acceptance_ref,
            order_acceptance_evidence_sha256=(prospect.order_acceptance_evidence_sha256),
            order_rejection_ref=prospect.order_rejection_ref,
            cancellation_ref=prospect.cancellation_ref,
            refund_ref=prospect.refund_ref,
            refund_evidence_sha256=prospect.refund_evidence_sha256,
            refund_evidence_artifact_sha256=(prospect.refund_evidence_artifact_sha256),
            refund_evidence_observed_at=(
                None
                if prospect.refund_evidence_observed_at is None
                else prospect.refund_evidence_observed_at.isoformat()
            ),
            state=lifecycle,
            claim_ids=prospect.claim_ids,
            amount_cents=prospect.purchase_amount_cents,
            tax_amount_cents=prospect.tax_amount_cents,
            gross_amount_cents=prospect.gross_amount_cents,
            refunded_amount_cents=prospect.refunded_amount_cents,
            fee_cents=prospect.payment_fee_cents,
            currency="USD",
            deadline=prospect.deadline,
            terms_version=prospect.terms_version,
            deliverable_sha256=prospect.deliverable_sha256,
            artifact_completed_at=(
                None
                if prospect.artifact_completed_at is None
                else prospect.artifact_completed_at.isoformat()
            ),
            delivery_ref=prospect.delivery_ref,
            delivery_method=prospect.delivery_method,
            delivery_evidence_sha256=prospect.delivery_evidence_sha256,
            delivery_evidence_artifact_sha256=(prospect.delivery_evidence_artifact_sha256),
            delivery_evidence_observed_at=(
                None
                if prospect.delivery_evidence_observed_at is None
                else prospect.delivery_evidence_observed_at.isoformat()
            ),
        )

    def _metrics(self, state: _PilotState) -> PilotMetrics:
        prospects = list(state.prospects.values())
        active_prospect_count = (
            len(state.outreach_plan.prospects)
            if state.outreach_plan is not None
            else len(prospects)
        )
        contacted = sum(item.contacted for item in prospects)
        replies = sum(item.reply_outcome is not None for item in prospects)
        sample_requests = sum(item.sample_requested for item in prospects)
        customer_acceptances = sum(item.customer_acceptance_ref is not None for item in prospects)
        checkouts_sent = sum(item.checkout_ref is not None for item in prospects)
        purchases = sum(item.order_id is not None for item in prospects)
        scopes_confirmed = sum(item.scope_ref is not None for item in prospects)
        orders_accepted = sum(item.order_acceptance_ref is not None for item in prospects)
        orders_rejected = sum(item.order_rejection_ref is not None for item in prospects)
        cancellation_requests = sum(item.cancellation_ref is not None for item in prospects)
        refunds = sum(item.refunded for item in prospects)
        deliveries = sum(item.delivered for item in prospects)
        feedback_responses = sum(item.feedback_recorded for item in prospects)
        opt_outs = sum(item.opted_out for item in prospects)
        booked_revenue_cents = sum(item.purchase_amount_cents for item in prospects)
        refunded_revenue_cents = sum(
            item.purchase_amount_cents for item in prospects if item.refunded
        )
        payment_fees_cents = sum(item.payment_fee_cents for item in prospects)
        decision_gate = self._decision_gate(
            contacted=contacted,
            replies=replies,
            purchases=purchases,
            refunds=refunds,
            risk_incidents=state.risk_incidents,
            outreach_plan_imported=state.outreach_plan is not None,
            qualified_outreach_required=(state.schema_version in {4, PILOT_LEDGER_SCHEMA_VERSION}),
        )
        return PilotMetrics(
            prior_consumed_slots=state.prior_consumed_slots,
            remaining_founding_slots=max(
                0,
                FOUNDING_PURCHASE_LIMIT - state.prior_consumed_slots - purchases,
            ),
            prospects=active_prospect_count,
            contacted=contacted,
            replies=replies,
            sample_requests=sample_requests,
            customer_acceptances=customer_acceptances,
            checkouts_sent=checkouts_sent,
            purchases=purchases,
            scopes_confirmed=scopes_confirmed,
            orders_accepted=orders_accepted,
            orders_rejected=orders_rejected,
            cancellation_requests=cancellation_requests,
            refunds=refunds,
            active_orders=sum(
                item.order_id is not None
                and not item.refunded
                and item.order_rejection_ref is None
                and item.cancellation_ref is None
                for item in prospects
            ),
            deliveries=deliveries,
            feedback_responses=feedback_responses,
            opt_outs=opt_outs,
            risk_incidents=state.risk_incidents,
            booked_revenue_cents=booked_revenue_cents,
            refunded_revenue_cents=refunded_revenue_cents,
            payment_fees_cents=payment_fees_cents,
            net_cash_cents=booked_revenue_cents - refunded_revenue_cents - payment_fees_cents,
            owner_minutes=state.owner_minutes,
            owner_hours=round(state.owner_minutes / 60, 2),
            reply_rate=self._ratio(replies, contacted),
            sample_request_rate=self._ratio(sample_requests, replies),
            purchase_rate=self._ratio(purchases, sample_requests),
            refund_rate=self._ratio(refunds, purchases),
            decision_gate=decision_gate,
        )

    @staticmethod
    def _decision_gate(
        *,
        contacted: int,
        replies: int,
        purchases: int,
        refunds: int,
        risk_incidents: int,
        outreach_plan_imported: bool,
        qualified_outreach_required: bool,
    ) -> DecisionGate:
        if risk_incidents:
            return DecisionGate.PAUSE_IMMEDIATELY
        if contacted < DECISION_GATE_CONTACTS:
            return DecisionGate.COLLECT_MORE_DATA
        if qualified_outreach_required and not outreach_plan_imported:
            return DecisionGate.QUALIFICATION_PLAN_REQUIRED
        if replies < 5:
            return DecisionGate.STOP_THIS_MOTION
        if purchases < 2:
            return DecisionGate.REVISE_OFFER_OR_TARGET
        if refunds <= 1:
            return DecisionGate.CONTINUE_AND_REPRICE
        return DecisionGate.REVIEW_REQUIRED


def _order_from_payload(payload: Mapping[str, object]) -> PilotOrder:
    data = PilotLedger._fields(payload, set(_ORDER_MANIFEST_KEYS))
    prospect_id = PilotLedger._opaque_id(data["prospect_id"], OpaqueIdKind.PROSPECT, "prospect_id")
    checkout_ref = PilotLedger._opaque_id(
        data["checkout_ref"], OpaqueIdKind.CHECKOUT, "checkout_ref"
    )
    checkout_occurred_at = PilotLedger._normalize_timestamp(data["checkout_occurred_at"])
    order_id = PilotLedger._opaque_id(data["order_id"], OpaqueIdKind.ORDER, "order_id")
    payment_ref = PilotLedger._opaque_id(data["payment_ref"], OpaqueIdKind.PAYMENT, "payment_ref")
    scope_ref = PilotLedger._opaque_id(data["scope_ref"], OpaqueIdKind.SCOPE, "scope_ref")
    customer_acceptance_ref = PilotLedger._opaque_id(
        data["customer_acceptance_ref"],
        OpaqueIdKind.CUSTOMER_ACCEPTANCE,
        "customer_acceptance_ref",
    )
    customer_acceptance_evidence_sha256 = PilotLedger._sha256_digest(
        data["customer_acceptance_evidence_sha256"],
        "customer_acceptance_evidence_sha256",
    )
    payment_mode_value = PilotLedger._enum(data["payment_mode"], PaymentMode, "payment_mode")
    payment_mode = PaymentMode(payment_mode_value)
    if payment_mode is not PaymentMode.LIVE:
        raise PilotValidationError("order manifests cannot contain TEST purchases")
    provider_purchase_sha256 = PilotLedger._sha256_digest(
        data["provider_purchase_sha256"],
        "provider_purchase_sha256",
    )
    payment_evidence_sha256 = PilotLedger._sha256_digest(
        data["payment_evidence_sha256"], "payment_evidence_sha256"
    )
    payment_evidence_artifact_sha256 = PilotLedger._sha256_digest(
        data["payment_evidence_artifact_sha256"],
        "payment_evidence_artifact_sha256",
    )
    payment_evidence_observed_at = PilotLedger._normalize_timestamp(
        data["payment_evidence_observed_at"]
    )
    if payment_evidence_observed_at < checkout_occurred_at:
        raise PilotValidationError("payment evidence must be observed at or after checkout")

    order_acceptance_value = data["order_acceptance_ref"]
    order_acceptance_ref = (
        None
        if order_acceptance_value is None
        else PilotLedger._opaque_id(
            order_acceptance_value,
            OpaqueIdKind.ORDER_ACCEPTANCE,
            "order_acceptance_ref",
        )
    )
    order_acceptance_evidence_value = data["order_acceptance_evidence_sha256"]
    order_acceptance_evidence_sha256 = (
        None
        if order_acceptance_evidence_value is None
        else PilotLedger._sha256_digest(
            order_acceptance_evidence_value,
            "order_acceptance_evidence_sha256",
        )
    )
    if (order_acceptance_ref is None) != (order_acceptance_evidence_sha256 is None):
        raise PilotValidationError(
            "order acceptance reference and evidence digest must travel together"
        )

    order_rejection_value = data["order_rejection_ref"]
    order_rejection_ref = (
        None
        if order_rejection_value is None
        else PilotLedger._opaque_id(
            order_rejection_value,
            OpaqueIdKind.ORDER_REJECTION,
            "order_rejection_ref",
        )
    )
    cancellation_value = data["cancellation_ref"]
    cancellation_ref = (
        None
        if cancellation_value is None
        else PilotLedger._opaque_id(
            cancellation_value,
            OpaqueIdKind.CANCELLATION,
            "cancellation_ref",
        )
    )
    refund_ref_value = data["refund_ref"]
    refund_ref = (
        None
        if refund_ref_value is None
        else PilotLedger._opaque_id(refund_ref_value, OpaqueIdKind.REFUND, "refund_ref")
    )
    refund_evidence_value = data["refund_evidence_sha256"]
    refund_evidence_sha256 = (
        None
        if refund_evidence_value is None
        else PilotLedger._sha256_digest(
            refund_evidence_value,
            "refund_evidence_sha256",
        )
    )
    refund_evidence_artifact_value = data["refund_evidence_artifact_sha256"]
    refund_evidence_artifact_sha256 = (
        None
        if refund_evidence_artifact_value is None
        else PilotLedger._sha256_digest(
            refund_evidence_artifact_value,
            "refund_evidence_artifact_sha256",
        )
    )
    refund_evidence_observed_value = data["refund_evidence_observed_at"]
    refund_evidence_observed_at = (
        None
        if refund_evidence_observed_value is None
        else PilotLedger._normalize_timestamp(refund_evidence_observed_value)
    )
    refunded_amount_value = data["refunded_amount_cents"]
    if (
        len(
            {
                refund_ref is None,
                refund_evidence_sha256 is None,
                refund_evidence_artifact_sha256 is None,
                refund_evidence_observed_at is None,
                refunded_amount_value is None,
            }
        )
        != 1
    ):
        raise PilotValidationError(
            "refund reference and complete evidence metadata must travel together"
        )
    if (
        refund_evidence_observed_at is not None
        and refund_evidence_observed_at < payment_evidence_observed_at
    ):
        raise PilotValidationError("refund evidence must be observed at or after payment capture")
    state_value = PilotLedger._enum(data["state"], PilotOrderState, "state")
    state = PilotOrderState(state_value)

    raw_claim_ids = data["claim_ids"]
    if not isinstance(raw_claim_ids, list) or not 1 <= len(raw_claim_ids) <= 100:
        raise PilotValidationError("claim_ids must contain from 1 through 100 IDs")
    claim_ids = tuple(
        PilotLedger._machine_safe(item, _CLAIM_ID_RE, "claim_ids") for item in raw_claim_ids
    )
    if len(set(claim_ids)) != len(claim_ids):
        raise PilotValidationError("claim_ids must be unique")

    amount_cents = PilotLedger._integer(
        data["amount_cents"],
        "amount_cents",
        minimum=FOUNDING_PRICE_CENTS,
        maximum=FOUNDING_PRICE_CENTS,
    )
    tax_amount_cents = PilotLedger._integer(
        data["tax_amount_cents"],
        "tax_amount_cents",
        minimum=0,
        maximum=2**63 - 1 - amount_cents,
    )
    gross_amount_cents = PilotLedger._integer(
        data["gross_amount_cents"],
        "gross_amount_cents",
        minimum=amount_cents + tax_amount_cents,
        maximum=amount_cents + tax_amount_cents,
    )
    refunded_amount_cents = (
        None
        if refunded_amount_value is None
        else PilotLedger._integer(
            refunded_amount_value,
            "refunded_amount_cents",
            minimum=gross_amount_cents,
            maximum=gross_amount_cents,
        )
    )
    fee_cents = PilotLedger._integer(
        data["fee_cents"], "fee_cents", minimum=0, maximum=amount_cents
    )
    if data["currency"] != "USD":
        raise PilotValidationError("currency must be USD")

    deadline = PilotLedger._deadline(data["deadline"])
    terms_version = PilotLedger._machine_safe(
        data["terms_version"], _TERMS_VERSION_RE, "terms_version"
    )
    digest_value = data["deliverable_sha256"]
    deliverable_sha256 = (
        None
        if digest_value is None
        else PilotLedger._sha256_digest(digest_value, "deliverable_sha256")
    )
    artifact_completed_value = data["artifact_completed_at"]
    artifact_completed_at = (
        None
        if artifact_completed_value is None
        else PilotLedger._normalize_timestamp(artifact_completed_value)
    )
    if (deliverable_sha256 is None) != (artifact_completed_at is None):
        raise PilotValidationError("completed artifact digest and timestamp must travel together")
    delivery_ref_value = data["delivery_ref"]
    delivery_ref = (
        None
        if delivery_ref_value is None
        else PilotLedger._opaque_id(
            delivery_ref_value,
            OpaqueIdKind.DELIVERY,
            "delivery_ref",
        )
    )
    delivery_method_value = data["delivery_method"]
    delivery_method = (
        None
        if delivery_method_value is None
        else DeliveryMethod(
            PilotLedger._enum(
                delivery_method_value,
                DeliveryMethod,
                "delivery_method",
            )
        )
    )
    delivery_evidence_value = data["delivery_evidence_sha256"]
    delivery_evidence_sha256 = (
        None
        if delivery_evidence_value is None
        else PilotLedger._sha256_digest(
            delivery_evidence_value,
            "delivery_evidence_sha256",
        )
    )
    delivery_evidence_artifact_value = data["delivery_evidence_artifact_sha256"]
    delivery_evidence_artifact_sha256 = (
        None
        if delivery_evidence_artifact_value is None
        else PilotLedger._sha256_digest(
            delivery_evidence_artifact_value,
            "delivery_evidence_artifact_sha256",
        )
    )
    delivery_evidence_observed_value = data["delivery_evidence_observed_at"]
    delivery_evidence_observed_at = (
        None
        if delivery_evidence_observed_value is None
        else PilotLedger._normalize_timestamp(delivery_evidence_observed_value)
    )
    if (
        len(
            {
                delivery_ref is None,
                delivery_method is None,
                delivery_evidence_sha256 is None,
                delivery_evidence_artifact_sha256 is None,
                delivery_evidence_observed_at is None,
            }
        )
        != 1
    ):
        raise PilotValidationError(
            "delivery reference, method, and complete evidence metadata must travel together"
        )
    if (
        delivery_evidence_artifact_sha256 is not None
        and deliverable_sha256 is not None
        and hmac.compare_digest(
            delivery_evidence_artifact_sha256,
            deliverable_sha256,
        )
    ):
        raise PilotValidationError(
            "delivery evidence artifact must differ from the delivered artifact"
        )
    if (
        delivery_evidence_observed_at is not None
        and artifact_completed_at is not None
        and delivery_evidence_observed_at < artifact_completed_at
    ):
        raise PilotValidationError(
            "delivery evidence must be observed at or after artifact completion"
        )
    if deliverable_sha256 is not None and order_acceptance_ref is None:
        raise PilotValidationError("delivered work requires an accepted order")
    if delivery_ref is not None and deliverable_sha256 is None:
        raise PilotValidationError("delivery evidence requires a completed artifact")
    if order_rejection_ref is not None and (
        order_acceptance_ref is not None
        or cancellation_ref is not None
        or deliverable_sha256 is not None
    ):
        raise PilotValidationError("rejected order lifecycle fields are mutually exclusive")

    if state is PilotOrderState.PURCHASED:
        if (
            order_acceptance_ref is not None
            or order_rejection_ref is not None
            or cancellation_ref is not None
            or deliverable_sha256 is not None
            or delivery_ref is not None
            or refund_ref is not None
        ):
            raise PilotValidationError("PURCHASED manifest has invalid lifecycle fields")
    elif state is PilotOrderState.ORDER_ACCEPTED:
        if (
            order_acceptance_ref is None
            or order_rejection_ref is not None
            or cancellation_ref is not None
            or deliverable_sha256 is not None
            or delivery_ref is not None
            or refund_ref is not None
        ):
            raise PilotValidationError("ORDER_ACCEPTED manifest has invalid lifecycle fields")
    elif state is PilotOrderState.ORDER_REJECTED:
        if (
            order_acceptance_ref is not None
            or order_rejection_ref is None
            or cancellation_ref is not None
            or deliverable_sha256 is not None
            or delivery_ref is not None
            or refund_ref is not None
        ):
            raise PilotValidationError("ORDER_REJECTED manifest has invalid lifecycle fields")
    elif state is PilotOrderState.FULFILLMENT_STARTED:
        if (
            order_acceptance_ref is None
            or order_rejection_ref is not None
            or cancellation_ref is not None
            or deliverable_sha256 is not None
            or delivery_ref is not None
            or refund_ref is not None
        ):
            raise PilotValidationError("FULFILLMENT_STARTED manifest has invalid lifecycle fields")
    elif state is PilotOrderState.ARTIFACT_COMPLETED:
        if (
            order_acceptance_ref is None
            or order_rejection_ref is not None
            or cancellation_ref is not None
            or deliverable_sha256 is None
            or delivery_ref is not None
            or refund_ref is not None
        ):
            raise PilotValidationError("ARTIFACT_COMPLETED manifest has invalid lifecycle fields")
    elif state is PilotOrderState.DELIVERED:
        if (
            order_acceptance_ref is None
            or order_rejection_ref is not None
            or cancellation_ref is not None
            or deliverable_sha256 is None
            or delivery_ref is None
            or refund_ref is not None
        ):
            raise PilotValidationError("DELIVERED manifest has invalid lifecycle fields")
    elif state is PilotOrderState.CANCELLATION_REQUESTED:
        if cancellation_ref is None or order_rejection_ref is not None or refund_ref is not None:
            raise PilotValidationError(
                "CANCELLATION_REQUESTED manifest has invalid lifecycle fields"
            )
    elif state is PilotOrderState.REFUNDED and refund_ref is None:
        raise PilotValidationError("REFUNDED manifest has invalid lifecycle fields")

    return PilotOrder(
        prospect_id=prospect_id,
        checkout_ref=checkout_ref,
        checkout_occurred_at=checkout_occurred_at.isoformat(),
        order_id=order_id,
        payment_ref=payment_ref,
        scope_ref=scope_ref,
        customer_acceptance_ref=customer_acceptance_ref,
        customer_acceptance_evidence_sha256=customer_acceptance_evidence_sha256,
        payment_mode=payment_mode,
        provider_purchase_sha256=provider_purchase_sha256,
        payment_evidence_sha256=payment_evidence_sha256,
        payment_evidence_artifact_sha256=payment_evidence_artifact_sha256,
        payment_evidence_observed_at=payment_evidence_observed_at.isoformat(),
        order_acceptance_ref=order_acceptance_ref,
        order_acceptance_evidence_sha256=order_acceptance_evidence_sha256,
        order_rejection_ref=order_rejection_ref,
        cancellation_ref=cancellation_ref,
        refund_ref=refund_ref,
        refund_evidence_sha256=refund_evidence_sha256,
        refund_evidence_artifact_sha256=refund_evidence_artifact_sha256,
        refund_evidence_observed_at=(
            None if refund_evidence_observed_at is None else refund_evidence_observed_at.isoformat()
        ),
        state=state,
        claim_ids=claim_ids,
        amount_cents=amount_cents,
        tax_amount_cents=tax_amount_cents,
        gross_amount_cents=gross_amount_cents,
        refunded_amount_cents=refunded_amount_cents,
        fee_cents=fee_cents,
        currency="USD",
        deadline=deadline,
        terms_version=terms_version,
        deliverable_sha256=deliverable_sha256,
        artifact_completed_at=(
            None if artifact_completed_at is None else artifact_completed_at.isoformat()
        ),
        delivery_ref=delivery_ref,
        delivery_method=delivery_method,
        delivery_evidence_sha256=delivery_evidence_sha256,
        delivery_evidence_artifact_sha256=delivery_evidence_artifact_sha256,
        delivery_evidence_observed_at=(
            None
            if delivery_evidence_observed_at is None
            else delivery_evidence_observed_at.isoformat()
        ),
    )


def _order_payload(order: PilotOrder) -> dict[str, object]:
    raw: dict[str, object] = {
        "prospect_id": order.prospect_id,
        "checkout_ref": order.checkout_ref,
        "checkout_occurred_at": order.checkout_occurred_at,
        "order_id": order.order_id,
        "payment_ref": order.payment_ref,
        "scope_ref": order.scope_ref,
        "customer_acceptance_ref": order.customer_acceptance_ref,
        "customer_acceptance_evidence_sha256": (order.customer_acceptance_evidence_sha256),
        "payment_mode": order.payment_mode.value,
        "provider_purchase_sha256": order.provider_purchase_sha256,
        "payment_evidence_sha256": order.payment_evidence_sha256,
        "payment_evidence_artifact_sha256": (order.payment_evidence_artifact_sha256),
        "payment_evidence_observed_at": order.payment_evidence_observed_at,
        "order_acceptance_ref": order.order_acceptance_ref,
        "order_acceptance_evidence_sha256": (order.order_acceptance_evidence_sha256),
        "order_rejection_ref": order.order_rejection_ref,
        "cancellation_ref": order.cancellation_ref,
        "refund_ref": order.refund_ref,
        "refund_evidence_sha256": order.refund_evidence_sha256,
        "refund_evidence_artifact_sha256": (order.refund_evidence_artifact_sha256),
        "refund_evidence_observed_at": order.refund_evidence_observed_at,
        "state": order.state.value,
        "claim_ids": list(order.claim_ids),
        "amount_cents": order.amount_cents,
        "tax_amount_cents": order.tax_amount_cents,
        "gross_amount_cents": order.gross_amount_cents,
        "refunded_amount_cents": order.refunded_amount_cents,
        "fee_cents": order.fee_cents,
        "currency": order.currency,
        "deadline": order.deadline,
        "terms_version": order.terms_version,
        "deliverable_sha256": order.deliverable_sha256,
        "artifact_completed_at": order.artifact_completed_at,
        "delivery_ref": order.delivery_ref,
        "delivery_method": (None if order.delivery_method is None else order.delivery_method.value),
        "delivery_evidence_sha256": order.delivery_evidence_sha256,
        "delivery_evidence_artifact_sha256": (order.delivery_evidence_artifact_sha256),
        "delivery_evidence_observed_at": order.delivery_evidence_observed_at,
    }
    normalized = _order_from_payload(raw)
    return {
        "prospect_id": normalized.prospect_id,
        "checkout_ref": normalized.checkout_ref,
        "checkout_occurred_at": normalized.checkout_occurred_at,
        "order_id": normalized.order_id,
        "payment_ref": normalized.payment_ref,
        "scope_ref": normalized.scope_ref,
        "customer_acceptance_ref": normalized.customer_acceptance_ref,
        "customer_acceptance_evidence_sha256": (normalized.customer_acceptance_evidence_sha256),
        "payment_mode": normalized.payment_mode.value,
        "provider_purchase_sha256": normalized.provider_purchase_sha256,
        "payment_evidence_sha256": normalized.payment_evidence_sha256,
        "payment_evidence_artifact_sha256": (normalized.payment_evidence_artifact_sha256),
        "payment_evidence_observed_at": normalized.payment_evidence_observed_at,
        "order_acceptance_ref": normalized.order_acceptance_ref,
        "order_acceptance_evidence_sha256": (normalized.order_acceptance_evidence_sha256),
        "order_rejection_ref": normalized.order_rejection_ref,
        "cancellation_ref": normalized.cancellation_ref,
        "refund_ref": normalized.refund_ref,
        "refund_evidence_sha256": normalized.refund_evidence_sha256,
        "refund_evidence_artifact_sha256": (normalized.refund_evidence_artifact_sha256),
        "refund_evidence_observed_at": normalized.refund_evidence_observed_at,
        "state": normalized.state.value,
        "claim_ids": list(normalized.claim_ids),
        "amount_cents": normalized.amount_cents,
        "tax_amount_cents": normalized.tax_amount_cents,
        "gross_amount_cents": normalized.gross_amount_cents,
        "refunded_amount_cents": normalized.refunded_amount_cents,
        "fee_cents": normalized.fee_cents,
        "currency": normalized.currency,
        "deadline": normalized.deadline,
        "terms_version": normalized.terms_version,
        "deliverable_sha256": normalized.deliverable_sha256,
        "artifact_completed_at": normalized.artifact_completed_at,
        "delivery_ref": normalized.delivery_ref,
        "delivery_method": (
            None if normalized.delivery_method is None else normalized.delivery_method.value
        ),
        "delivery_evidence_sha256": normalized.delivery_evidence_sha256,
        "delivery_evidence_artifact_sha256": (normalized.delivery_evidence_artifact_sha256),
        "delivery_evidence_observed_at": normalized.delivery_evidence_observed_at,
    }


def write_order_manifest(
    path: str | Path,
    order: PilotOrder,
    *,
    ledger_head_sha256: str,
) -> str:
    """Write an atomic ledger-anchored projection and return its checksum."""
    destination = Path(path)
    try:
        PilotLedger._assert_safe_ancestors(destination)
        if destination.is_symlink():
            raise PilotManifestError("order manifest must not be a symbolic link")
        destination.parent.mkdir(parents=True, exist_ok=True)
        PilotLedger._assert_safe_ancestors(destination)
    except PilotLedgerError as exc:
        raise PilotManifestError("order manifest must not use symbolic-link ancestors") from exc
    ledger_head = PilotLedger._sha256_digest(ledger_head_sha256, "ledger_head_sha256")
    body: dict[str, object] = {
        "schema_version": ORDER_MANIFEST_SCHEMA_VERSION,
        "ledger_head_sha256": ledger_head,
        "order": _order_payload(order),
    }
    manifest_sha256 = sha256_json(body)
    envelope = {**body, "manifest_sha256": manifest_sha256}
    encoded = json.dumps(envelope, ensure_ascii=True, indent=2, sort_keys=True) + "\n"

    temporary_name = f".{destination.name}.{secrets.token_hex(8)}.tmp"
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        parent_descriptor = os.open(destination.parent, parent_flags)
        try:
            existing = os.stat(
                destination.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise PilotManifestError("order manifest destination must be a regular file")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            destination.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
    except (OSError, TypeError, ValueError) as exc:
        raise PilotManifestError("could not write order manifest") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            os.close(parent_descriptor)
    return manifest_sha256


def _decode_order_manifest(path: str | Path) -> tuple[PilotOrder, str]:
    source = Path(path)
    try:
        PilotLedger._assert_safe_ancestors(source)
    except PilotLedgerError as exc:
        raise PilotManifestError("order manifest must not use symbolic-link ancestors") from exc
    try:
        before = os.lstat(source)
    except OSError as exc:
        raise PilotManifestError("order manifest must be a regular file") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise PilotManifestError("order manifest must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(source, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise PilotManifestError("order manifest changed while opening")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            raw = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PilotManifestError("order manifest could not be decoded") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(raw, dict) or set(raw) != _MANIFEST_KEYS:
        raise PilotManifestError("order manifest fields are invalid")
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != ORDER_MANIFEST_SCHEMA_VERSION
    ):
        raise PilotManifestError("order manifest schema version is unsupported")
    try:
        ledger_head = PilotLedger._sha256_digest(raw["ledger_head_sha256"], "ledger_head_sha256")
    except PilotValidationError as exc:
        raise PilotManifestError("order manifest ledger anchor is invalid") from exc
    manifest_sha256 = raw["manifest_sha256"]
    if not isinstance(manifest_sha256, str) or _SHA256_RE.fullmatch(manifest_sha256) is None:
        raise PilotManifestError("order manifest digest is invalid")
    body = {
        "schema_version": raw["schema_version"],
        "ledger_head_sha256": ledger_head,
        "order": raw["order"],
    }
    if not hmac.compare_digest(manifest_sha256, sha256_json(body)):
        raise PilotManifestError("order manifest digest mismatch")
    order_payload = raw["order"]
    if not isinstance(order_payload, dict):
        raise PilotManifestError("order manifest projection must be an object")
    try:
        return _order_from_payload(order_payload), ledger_head
    except PilotValidationError as exc:
        raise PilotManifestError("order manifest projection is invalid") from exc


def load_order_manifest(path: str | Path) -> PilotOrder:
    """Verify a ledger-anchored manifest checksum and load its projection."""
    order, _ = _decode_order_manifest(path)
    return order


def load_verified_order_manifest(
    path: str | Path,
    ledger_path: str | Path,
) -> PilotOrder:
    """Verify a manifest against the trusted current pilot ledger state."""
    order, ledger_head = _decode_order_manifest(path)
    ledger_source = Path(ledger_path)
    if ledger_source.is_symlink() or not ledger_source.is_file():
        raise PilotManifestError("pilot ledger must be an existing regular file")
    try:
        ledger = PilotLedger(ledger_source)
        current_order = ledger.order_at_head(order.order_id, ledger_head)
    except (PilotLedgerError, PilotValidationError) as exc:
        raise PilotManifestError(
            "order manifest could not be verified against the current pilot ledger"
        ) from exc
    if current_order != order:
        raise PilotManifestError("order manifest does not match the current pilot ledger")
    return current_order
