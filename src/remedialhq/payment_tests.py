from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "remedialhq.payment-test-evidence.v1"
EXPECTED_PROVIDER = "STRIPE"
EXPECTED_MODE = "TEST"
EXPECTED_CURRENCY = "USD"
EXPECTED_UNIT_AMOUNT_CENTS = 9_900
EXPECTED_PAYMENT_TYPE = "ONE_TIME"
MAX_DOCUMENT_BYTES = 65_536


class PaymentTestEvidenceError(ValueError):
    """Raised when payment test evidence is incomplete, unsafe, or not test-only."""


class EvidenceClassification(StrEnum):
    SYNTHETIC = "SYNTHETIC"
    OWNER_CAPTURED = "OWNER_CAPTURED"


class PaymentTestFlow(StrEnum):
    SUCCESSFUL_CHECKOUT = "SUCCESSFUL_CHECKOUT"
    ABANDONMENT = "ABANDONMENT"
    RECEIPT = "RECEIPT"
    CANCELLATION_INTERPRETATION = "CANCELLATION_INTERPRETATION"
    FULL_REFUND = "FULL_REFUND"


FLOW_ORDER = (
    PaymentTestFlow.SUCCESSFUL_CHECKOUT,
    PaymentTestFlow.ABANDONMENT,
    PaymentTestFlow.RECEIPT,
    PaymentTestFlow.CANCELLATION_INTERPRETATION,
    PaymentTestFlow.FULL_REFUND,
)

CANCELLATION_INTERPRETATION = "A_CANCELLATION_REQUEST_DOES_NOT_CANCEL_A_COMPLETED_STRIPE_PAYMENT"

_COMMON_EVIDENCE_FIELDS = frozenset(
    {
        "flow",
        "classification",
        "observed_at",
        "evidence_ref",
        "provider_ref",
        "correlation_ref",
        "artifact_sha256",
        "outcome",
    }
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "provider",
        "mode",
        "livemode",
        "currency",
        "unit_amount_cents",
        "payment_type",
        "test_run_ref",
        "evidence",
    }
)
_FLOW_EXTRA_FIELDS: dict[PaymentTestFlow, frozenset[str]] = {
    PaymentTestFlow.SUCCESSFUL_CHECKOUT: frozenset(
        {"charged_amount_cents", "payment_method_redacted"}
    ),
    PaymentTestFlow.ABANDONMENT: frozenset({"payment_created"}),
    PaymentTestFlow.RECEIPT: frozenset({"receipt_amount_cents", "recipient_redacted"}),
    PaymentTestFlow.CANCELLATION_INTERPRETATION: frozenset(
        {"interpretation", "required_follow_up"}
    ),
    PaymentTestFlow.FULL_REFUND: frozenset({"refunded_amount_cents"}),
}
_EXPECTED_OUTCOME = {
    PaymentTestFlow.SUCCESSFUL_CHECKOUT: "PAYMENT_SUCCEEDED",
    PaymentTestFlow.ABANDONMENT: "CHECKOUT_ABANDONED_NO_PAYMENT",
    PaymentTestFlow.RECEIPT: "RECEIPT_ISSUED",
    PaymentTestFlow.CANCELLATION_INTERPRETATION: "CANCELLATION_REQUEST_RECORDED",
    PaymentTestFlow.FULL_REFUND: "REFUND_SUCCEEDED",
}

_EVIDENCE_REF_RE = re.compile(r"^evd_[0-9a-f]{32}$")
_PROVIDER_REF_RE = re.compile(r"^ref_[0-9a-f]{32}$")
_CORRELATION_REF_RE = re.compile(r"^cor_[0-9a-f]{32}$")
_TEST_RUN_REF_RE = re.compile(r"^run_[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_URL_RE = re.compile(r"(?:https?://|www\.)", re.IGNORECASE)
_ADDRESS_RE = re.compile(
    r"(?:\bP\.?\s*O\.?\s+Box\s+\d+\b|"
    r"\b\d{1,6}\s+[A-Z0-9.'-]+(?:\s+[A-Z0-9.'-]+){0,4}\s+"
    r"(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|"
    r"Highway|Hwy)\b)",
    re.IGNORECASE,
)
_PERSONAL_NAME_RE = re.compile(r"^[A-Z][a-z]{1,30}(?:[ '-][A-Z][a-z]{1,30}){1,3}$")
_CARD_LABEL_RE = re.compile(r"\b(?:card\s*number|cvc|cvv|expiration|expiry)\b", re.IGNORECASE)
_PAN_CANDIDATE_RE = re.compile(r"(?<![0-9A-Za-z])(?:\d[ -]?){12,18}\d(?![0-9A-Za-z])")
_RAW_PROVIDER_REF_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:cs_(?:test|live)_|pi_|ch_|re_|evt_|cus_|pm_|in_|sub_|"
    r"plink_)[A-Za-z0-9]+",
    re.IGNORECASE,
)
_SECRET_PATTERNS = (
    re.compile(r"\b(?:sk|rk|pk)_(?:test|live)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE),
    re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "address",
        "api_key",
        "authorization",
        "billing_details",
        "card",
        "card_number",
        "client_secret",
        "customer",
        "customer_details",
        "cvc",
        "cvv",
        "data",
        "email",
        "metadata",
        "name",
        "object",
        "password",
        "payload",
        "raw",
        "raw_payload",
        "secret",
        "shipping_details",
        "token",
        "url",
    }
)


@dataclass(frozen=True, slots=True)
class FlowEvidence:
    flow: PaymentTestFlow
    classification: EvidenceClassification
    observed_at: str
    evidence_ref: str
    provider_ref: str
    correlation_ref: str
    artifact_sha256: str
    outcome: str
    details: tuple[tuple[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "flow": self.flow.value,
            "classification": self.classification.value,
            "observed_at": self.observed_at,
            "evidence_ref": self.evidence_ref,
            "provider_ref": self.provider_ref,
            "correlation_ref": self.correlation_ref,
            "artifact_sha256": self.artifact_sha256,
            "outcome": self.outcome,
        }
        value.update(self.details)
        return value


@dataclass(frozen=True, slots=True)
class PaymentTestReport:
    test_run_ref: str
    flows: tuple[FlowEvidence, ...]
    first_observed_at: str
    last_observed_at: str

    @property
    def sha256(self) -> str:
        """Return the lowercase SHA-256 digest of the normalized aggregate report."""
        return hashlib.sha256(_canonical_json(self.to_dict()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        classification_counts = {
            classification.value: sum(item.classification is classification for item in self.flows)
            for classification in EvidenceClassification
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "schema_gate_status": "PASS",
            "provider": EXPECTED_PROVIDER,
            "mode": EXPECTED_MODE,
            "livemode": False,
            "currency": EXPECTED_CURRENCY,
            "unit_amount_cents": EXPECTED_UNIT_AMOUNT_CENTS,
            "payment_type": EXPECTED_PAYMENT_TYPE,
            "test_run_ref": self.test_run_ref,
            "flow_count": len(self.flows),
            "flows": [item.to_dict() for item in self.flows],
            "classification_counts": classification_counts,
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
            "raw_provider_payloads_accepted": False,
            "live_mode_evidence_accepted": False,
            "rmh_106_may_be_marked_complete": False,
            "completion_boundary": (
                "This local schema gate cannot mark RMH-106 complete or verify a live link."
            ),
        }

    def envelope(self) -> dict[str, object]:
        """Return the aggregate report beside its deterministic digest."""
        return {"report": self.to_dict(), "sha256": self.sha256}


def build_payment_test_report(document: Mapping[str, object]) -> PaymentTestReport:
    """Validate one redacted test-only evidence document and build its report."""
    _scan_redaction(document)
    _strict_keys(document, _TOP_LEVEL_FIELDS, "document")
    _require_exact_string(document["schema_version"], SCHEMA_VERSION, "schema_version")
    _require_exact_string(document["provider"], EXPECTED_PROVIDER, "provider")
    _require_exact_string(document["mode"], EXPECTED_MODE, "mode")
    if _strict_bool(document["livemode"], "livemode"):
        raise PaymentTestEvidenceError("livemode must be false")
    _require_exact_string(document["currency"], EXPECTED_CURRENCY, "currency")
    _require_exact_int(
        document["unit_amount_cents"],
        EXPECTED_UNIT_AMOUNT_CENTS,
        "unit_amount_cents",
    )
    _require_exact_string(document["payment_type"], EXPECTED_PAYMENT_TYPE, "payment_type")
    test_run_ref = _match_string(document["test_run_ref"], _TEST_RUN_REF_RE, "test_run_ref")

    raw_evidence = document["evidence"]
    if not isinstance(raw_evidence, list):
        raise PaymentTestEvidenceError("evidence must be a JSON array")
    if len(raw_evidence) != len(FLOW_ORDER):
        raise PaymentTestEvidenceError("evidence must contain exactly five required flows")

    validated: dict[PaymentTestFlow, tuple[FlowEvidence, datetime]] = {}
    evidence_refs: set[str] = set()
    provider_refs: set[str] = set()
    artifact_digests: set[str] = set()
    for index, raw_item in enumerate(raw_evidence):
        item, observed_at = _validate_flow(raw_item, index)
        if item.flow in validated:
            raise PaymentTestEvidenceError("each required flow must appear exactly once")
        if item.evidence_ref in evidence_refs:
            raise PaymentTestEvidenceError("evidence_ref values must be unique")
        if item.provider_ref in provider_refs:
            raise PaymentTestEvidenceError("provider_ref values must be unique")
        if item.artifact_sha256 in artifact_digests:
            raise PaymentTestEvidenceError("artifact_sha256 values must be unique")
        validated[item.flow] = (item, observed_at)
        evidence_refs.add(item.evidence_ref)
        provider_refs.add(item.provider_ref)
        artifact_digests.add(item.artifact_sha256)

    if set(validated) != set(FLOW_ORDER):
        raise PaymentTestEvidenceError("all five required flows must be present")

    checkout_at = validated[PaymentTestFlow.SUCCESSFUL_CHECKOUT][1]
    receipt_at = validated[PaymentTestFlow.RECEIPT][1]
    cancellation_at = validated[PaymentTestFlow.CANCELLATION_INTERPRETATION][1]
    refund_at = validated[PaymentTestFlow.FULL_REFUND][1]
    if not checkout_at <= receipt_at <= cancellation_at <= refund_at:
        raise PaymentTestEvidenceError(
            "checkout, receipt, cancellation interpretation, and refund timestamps "
            "must be chronological"
        )

    payment_chain = {
        validated[flow][0].correlation_ref
        for flow in (
            PaymentTestFlow.SUCCESSFUL_CHECKOUT,
            PaymentTestFlow.RECEIPT,
            PaymentTestFlow.CANCELLATION_INTERPRETATION,
            PaymentTestFlow.FULL_REFUND,
        )
    }
    if len(payment_chain) != 1:
        raise PaymentTestEvidenceError(
            "checkout, receipt, cancellation interpretation, and refund must share one "
            "correlation_ref"
        )
    abandonment_ref = validated[PaymentTestFlow.ABANDONMENT][0].correlation_ref
    if abandonment_ref in payment_chain:
        raise PaymentTestEvidenceError(
            "abandonment must use a separate checkout correlation_ref"
        )

    ordered_flows = tuple(validated[flow][0] for flow in FLOW_ORDER)
    observed_values = [observed_at for _, observed_at in validated.values()]
    return PaymentTestReport(
        test_run_ref=test_run_ref,
        flows=ordered_flows,
        first_observed_at=_normalize_timestamp(min(observed_values)),
        last_observed_at=_normalize_timestamp(max(observed_values)),
    )


def parse_payment_test_evidence(text: str) -> PaymentTestReport:
    """Parse strict JSON text and return a validated aggregate report."""
    if not isinstance(text, str):
        raise TypeError("payment test evidence must be JSON text")
    try:
        encoded_size = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise PaymentTestEvidenceError("payment test evidence must be valid UTF-8") from exc
    if encoded_size > MAX_DOCUMENT_BYTES:
        raise PaymentTestEvidenceError("payment test evidence exceeds the size limit")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except PaymentTestEvidenceError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise PaymentTestEvidenceError("payment test evidence is not valid JSON") from exc
    if not isinstance(document, Mapping):
        raise PaymentTestEvidenceError("payment test evidence must be a JSON object")
    return build_payment_test_report(document)


def load_payment_test_evidence(path: str | Path) -> PaymentTestReport:
    """Safely load one bounded UTF-8 regular file without traversing symlinks."""
    path_value = os.fspath(path)
    _reject_symlink_ancestors(path_value)
    try:
        before = os.lstat(path_value)
    except (OSError, TypeError, ValueError):
        before = None
    if before is None:
        raise PaymentTestEvidenceError("payment test evidence file is unavailable")
    if stat.S_ISLNK(before.st_mode):
        raise PaymentTestEvidenceError("payment test evidence file must not be a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise PaymentTestEvidenceError("payment test evidence file must be a regular file")
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise PaymentTestEvidenceError("payment test evidence exceeds the size limit")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path_value, flags)
    except (OSError, TypeError, ValueError):
        descriptor = None
    if descriptor is None:
        raise PaymentTestEvidenceError("payment test evidence file cannot be opened")

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PaymentTestEvidenceError("payment test evidence file must be a regular file")
        if _file_snapshot(before) != _file_snapshot(opened):
            raise PaymentTestEvidenceError("payment test evidence file changed while opening")
        if opened.st_size > MAX_DOCUMENT_BYTES:
            raise PaymentTestEvidenceError("payment test evidence exceeds the size limit")

        data = _read_bounded(descriptor)
        after = os.fstat(descriptor)
        if _file_snapshot(opened) != _file_snapshot(after) or len(data) != after.st_size:
            raise PaymentTestEvidenceError("payment test evidence file changed while reading")
        try:
            current = os.lstat(path_value)
        except (OSError, TypeError, ValueError):
            current = None
        if (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or _file_snapshot(current) != _file_snapshot(after)
        ):
            raise PaymentTestEvidenceError("payment test evidence file changed while reading")
    except OSError:
        raise PaymentTestEvidenceError("payment test evidence file cannot be read") from None
    finally:
        os.close(descriptor)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise PaymentTestEvidenceError("payment test evidence must be UTF-8")
    return parse_payment_test_evidence(text)


def _reject_symlink_ancestors(path: str) -> None:
    try:
        ancestors = Path(path).absolute().parents
    except (OSError, TypeError, ValueError):
        raise PaymentTestEvidenceError("payment test evidence file is unavailable") from None
    for ancestor in reversed(ancestors):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            metadata = None
        if metadata is None:
            raise PaymentTestEvidenceError("payment test evidence file is unavailable")
        if stat.S_ISLNK(metadata.st_mode):
            raise PaymentTestEvidenceError(
                "payment test evidence path must not use symlink ancestors"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise PaymentTestEvidenceError(
                "payment test evidence path ancestors must be directories"
            )


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    bytes_read = 0
    while bytes_read <= MAX_DOCUMENT_BYTES:
        chunk = os.read(descriptor, min(8_192, MAX_DOCUMENT_BYTES + 1 - bytes_read))
        if not chunk:
            break
        chunks.append(chunk)
        bytes_read += len(chunk)
    if bytes_read > MAX_DOCUMENT_BYTES:
        raise PaymentTestEvidenceError("payment test evidence exceeds the size limit")
    return b"".join(chunks)


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_flow(raw_item: object, index: int) -> tuple[FlowEvidence, datetime]:
    path = f"evidence[{index}]"
    if not isinstance(raw_item, Mapping):
        raise PaymentTestEvidenceError(f"{path} must be a JSON object")

    flow_value = raw_item.get("flow")
    if not isinstance(flow_value, str):
        raise PaymentTestEvidenceError(f"{path}.flow must be a string")
    try:
        flow = PaymentTestFlow(flow_value)
    except ValueError as exc:
        raise PaymentTestEvidenceError(f"{path}.flow is not allowed") from exc

    _strict_keys(raw_item, _COMMON_EVIDENCE_FIELDS | _FLOW_EXTRA_FIELDS[flow], path)
    classification_value = _require_string(raw_item["classification"], f"{path}.classification")
    try:
        classification = EvidenceClassification(classification_value)
    except ValueError as exc:
        raise PaymentTestEvidenceError(f"{path}.classification is not allowed") from exc

    observed_at, observed_datetime = _parse_timestamp(
        raw_item["observed_at"], f"{path}.observed_at"
    )
    evidence_ref = _match_string(raw_item["evidence_ref"], _EVIDENCE_REF_RE, f"{path}.evidence_ref")
    provider_ref = _match_string(raw_item["provider_ref"], _PROVIDER_REF_RE, f"{path}.provider_ref")
    correlation_ref = _match_string(
        raw_item["correlation_ref"],
        _CORRELATION_REF_RE,
        f"{path}.correlation_ref",
    )
    artifact_sha256 = _match_string(
        raw_item["artifact_sha256"], _SHA256_RE, f"{path}.artifact_sha256"
    )
    outcome = _require_string(raw_item["outcome"], f"{path}.outcome")
    if outcome != _EXPECTED_OUTCOME[flow]:
        raise PaymentTestEvidenceError(f"{path}.outcome does not match its flow")

    details = _validate_flow_details(flow, raw_item, path)
    return (
        FlowEvidence(
            flow=flow,
            classification=classification,
            observed_at=observed_at,
            evidence_ref=evidence_ref,
            provider_ref=provider_ref,
            correlation_ref=correlation_ref,
            artifact_sha256=artifact_sha256,
            outcome=outcome,
            details=details,
        ),
        observed_datetime,
    )


def _validate_flow_details(
    flow: PaymentTestFlow,
    raw_item: Mapping[str, object],
    path: str,
) -> tuple[tuple[str, object], ...]:
    if flow is PaymentTestFlow.SUCCESSFUL_CHECKOUT:
        _require_exact_int(
            raw_item["charged_amount_cents"],
            EXPECTED_UNIT_AMOUNT_CENTS,
            f"{path}.charged_amount_cents",
        )
        if not _strict_bool(raw_item["payment_method_redacted"], f"{path}.payment_method_redacted"):
            raise PaymentTestEvidenceError(f"{path}.payment_method_redacted must be true")
        return (
            ("charged_amount_cents", EXPECTED_UNIT_AMOUNT_CENTS),
            ("payment_method_redacted", True),
        )

    if flow is PaymentTestFlow.ABANDONMENT:
        if _strict_bool(raw_item["payment_created"], f"{path}.payment_created"):
            raise PaymentTestEvidenceError(f"{path}.payment_created must be false")
        return (("payment_created", False),)

    if flow is PaymentTestFlow.RECEIPT:
        _require_exact_int(
            raw_item["receipt_amount_cents"],
            EXPECTED_UNIT_AMOUNT_CENTS,
            f"{path}.receipt_amount_cents",
        )
        if not _strict_bool(raw_item["recipient_redacted"], f"{path}.recipient_redacted"):
            raise PaymentTestEvidenceError(f"{path}.recipient_redacted must be true")
        return (
            ("receipt_amount_cents", EXPECTED_UNIT_AMOUNT_CENTS),
            ("recipient_redacted", True),
        )

    if flow is PaymentTestFlow.CANCELLATION_INTERPRETATION:
        _require_exact_string(
            raw_item["interpretation"],
            CANCELLATION_INTERPRETATION,
            f"{path}.interpretation",
        )
        _require_exact_string(
            raw_item["required_follow_up"],
            "FULL_REFUND",
            f"{path}.required_follow_up",
        )
        return (
            ("interpretation", CANCELLATION_INTERPRETATION),
            ("required_follow_up", "FULL_REFUND"),
        )

    _require_exact_int(
        raw_item["refunded_amount_cents"],
        EXPECTED_UNIT_AMOUNT_CENTS,
        f"{path}.refunded_amount_cents",
    )
    return (("refunded_amount_cents", EXPECTED_UNIT_AMOUNT_CENTS),)


def _strict_keys(value: Mapping[str, object], expected: frozenset[str], path: str) -> None:
    if not all(isinstance(key, str) for key in value):
        raise PaymentTestEvidenceError(f"{path} field names must be strings")
    if set(value) != set(expected):
        raise PaymentTestEvidenceError(f"{path} has missing or unknown fields")


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise PaymentTestEvidenceError(f"{path} must be a string")
    return value


def _require_exact_string(value: object, expected: str, path: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise PaymentTestEvidenceError(f"{path} must use the required fixed value")


def _strict_bool(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise PaymentTestEvidenceError(f"{path} must be a JSON boolean")
    return value


def _require_exact_int(value: object, expected: int, path: str) -> None:
    if type(value) is not int or value != expected:
        raise PaymentTestEvidenceError(f"{path} must equal {expected}")


def _match_string(value: object, pattern: re.Pattern[str], path: str) -> str:
    string_value = _require_string(value, path)
    if pattern.fullmatch(string_value) is None:
        raise PaymentTestEvidenceError(f"{path} must be a lowercase opaque value")
    return string_value


def _parse_timestamp(value: object, path: str) -> tuple[str, datetime]:
    timestamp = _require_string(value, path)
    if _RFC3339_RE.fullmatch(timestamp) is None:
        raise PaymentTestEvidenceError(f"{path} must be a timezone-aware RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise PaymentTestEvidenceError(
            f"{path} must be a timezone-aware RFC 3339 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PaymentTestEvidenceError(f"{path} must include a timezone offset")
    return _normalize_timestamp(parsed), parsed


def _normalize_timestamp(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    if normalized.microsecond:
        rendered = normalized.isoformat(timespec="microseconds")
    else:
        rendered = normalized.isoformat(timespec="seconds")
    return rendered.replace("+00:00", "Z")


def _scan_redaction(
    value: object,
    path: str = "$",
    depth: int = 0,
    active: set[int] | None = None,
) -> None:
    if depth > 12:
        raise PaymentTestEvidenceError("payment test evidence is nested too deeply")
    active_ids = active if active is not None else set()

    if isinstance(value, Mapping):
        object_id = id(value)
        if object_id in active_ids:
            raise PaymentTestEvidenceError("payment test evidence cannot contain cycles")
        active_ids.add(object_id)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise PaymentTestEvidenceError("field names must be strings")
                if key.casefold() in _FORBIDDEN_FIELD_NAMES:
                    raise PaymentTestEvidenceError(
                        "payment test evidence contains a forbidden sensitive or raw field"
                    )
                _scan_redaction(item, path, depth + 1, active_ids)
        finally:
            active_ids.remove(object_id)
        return

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        object_id = id(value)
        if object_id in active_ids:
            raise PaymentTestEvidenceError("payment test evidence cannot contain cycles")
        active_ids.add(object_id)
        try:
            for index, item in enumerate(value):
                _scan_redaction(item, f"{path}[{index}]", depth + 1, active_ids)
        finally:
            active_ids.remove(object_id)
        return

    if isinstance(value, str):
        _screen_string(value, path)


def _screen_string(value: str, path: str) -> None:
    if _EMAIL_RE.search(value):
        raise PaymentTestEvidenceError(f"{path} contains an email address")
    if _URL_RE.search(value):
        raise PaymentTestEvidenceError(f"{path} contains a URL")
    if _ADDRESS_RE.search(value):
        raise PaymentTestEvidenceError(f"{path} contains a postal address")
    if _PERSONAL_NAME_RE.fullmatch(value):
        raise PaymentTestEvidenceError(f"{path} contains a personal name")
    if _CARD_LABEL_RE.search(value) or _contains_payment_card_number(value):
        raise PaymentTestEvidenceError(f"{path} contains payment card data")
    if _RAW_PROVIDER_REF_RE.search(value):
        raise PaymentTestEvidenceError(f"{path} contains a raw provider reference")
    if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise PaymentTestEvidenceError(f"{path} contains a credential or secret")


def _contains_payment_card_number(value: str) -> bool:
    for candidate in _PAN_CANDIDATE_RE.finditer(value):
        digits = re.sub(r"\D", "", candidate.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True
    return False


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PaymentTestEvidenceError("payment test evidence has a duplicate field")
        value[key] = item
    return value


def _reject_non_json_number(value: str) -> None:
    del value
    raise PaymentTestEvidenceError("payment test evidence contains a non-JSON number")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate redacted, test-only Stripe flow evidence."
    )
    parser.add_argument("evidence", help="path to the redacted JSON evidence file")
    parser.add_argument("--pretty", action="store_true", help="print the report with indentation")
    args = parser.parse_args(argv)
    try:
        report = load_payment_test_evidence(args.evidence)
    except (OSError, PaymentTestEvidenceError) as exc:
        print(f"payment test evidence rejected: {exc}", file=sys.stderr)
        return 2
    indent = 2 if args.pretty else None
    print(json.dumps(report.envelope(), indent=indent, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
