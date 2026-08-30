from __future__ import annotations

import argparse
import hashlib
import hmac
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
from typing import NoReturn

SCHEMA_VERSION = "remedialhq.live-payment-evidence.v1"
EXPECTED_PROVIDER = "STRIPE"
EXPECTED_MODE = "LIVE"
EXPECTED_STATUS = "SUCCEEDED"
EXPECTED_CURRENCY = "USD"
EXPECTED_AMOUNT_CENTS = 9_900
EXPECTED_PAYMENT_TYPE = "ONE_TIME"
MAX_DOCUMENT_BYTES = 16_384


class PaymentEvidenceError(ValueError):
    """Raised when live payment evidence is unsafe, incomplete, or invalid."""


class PaymentEvidenceEvent(StrEnum):
    PAYMENT_CAPTURED = "PAYMENT_CAPTURED"
    FULL_REFUND = "FULL_REFUND"


_COMMON_FIELDS = frozenset(
    {
        "schema_version",
        "event_type",
        "provider",
        "mode",
        "livemode",
        "status",
        "currency",
        "amount_cents",
        "payment_type",
        "order_id",
        "observed_at",
        "evidence_ref",
        "provider_ref",
        "artifact_sha256",
    }
)
_EVENT_FIELDS = {
    PaymentEvidenceEvent.PAYMENT_CAPTURED: _COMMON_FIELDS,
    PaymentEvidenceEvent.FULL_REFUND: _COMMON_FIELDS
    | frozenset({"original_payment_ref", "refunded_amount_cents"}),
}

_EVIDENCE_REF_RE = re.compile(r"^evd_[0-9a-f]{32}$")
_ORDER_ID_RE = re.compile(r"^ord_[0-9a-f]{32}$")
_PAYMENT_REF_RE = re.compile(r"^pay_[0-9a-f]{32}$")
_REFUND_REF_RE = re.compile(r"^rfd_[0-9a-f]{32}$")
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
_CARD_LABEL_RE = re.compile(
    r"\b(?:card\s*number|cardholder|cvc|cvv|expiration|expiry)\b", re.IGNORECASE
)
_PAN_CANDIDATE_RE = re.compile(r"(?<![0-9A-Za-z])(?:\d[ -]?){12,18}\d(?![0-9A-Za-z])")
_RAW_STRIPE_REF_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:cs_(?:test|live)_|pi_|ch_|re_|evt_|cus_|pm_|in_|sub_|"
    r"plink_)[A-Za-z0-9]+",
    re.IGNORECASE,
)
_SECRET_PATTERNS = (
    re.compile(r"\b(?:sk|rk|pk)_(?:test|live)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bcf(?:ut|k)_[A-Za-z0-9_-]{16,}\b"),
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
        "cardholder",
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
        "receipt_url",
        "secret",
        "shipping_details",
        "token",
        "url",
    }
)


@dataclass(frozen=True, slots=True)
class LivePaymentEvidence:
    """Normalized, immutable evidence for one live payment or full refund."""

    event_type: PaymentEvidenceEvent
    order_id: str
    observed_at: str
    evidence_ref: str
    provider_ref: str
    artifact_sha256: str
    original_payment_ref: str | None = None
    refunded_amount_cents: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, PaymentEvidenceEvent):
            raise PaymentEvidenceError("event_type is not allowed")
        _match_string(self.order_id, _ORDER_ID_RE, "order_id")
        if _parse_timestamp(self.observed_at, "observed_at") != self.observed_at:
            raise PaymentEvidenceError("observed_at must be normalized to UTC")
        _match_string(self.evidence_ref, _EVIDENCE_REF_RE, "evidence_ref")
        provider_pattern = (
            _PAYMENT_REF_RE
            if self.event_type is PaymentEvidenceEvent.PAYMENT_CAPTURED
            else _REFUND_REF_RE
        )
        _match_string(self.provider_ref, provider_pattern, "provider_ref")
        _match_string(self.artifact_sha256, _SHA256_RE, "artifact_sha256")

        if self.event_type is PaymentEvidenceEvent.PAYMENT_CAPTURED:
            if self.original_payment_ref is not None or self.refunded_amount_cents is not None:
                raise PaymentEvidenceError("captured payment evidence cannot contain refund fields")
            return

        if self.original_payment_ref is None or self.refunded_amount_cents is None:
            raise PaymentEvidenceError("refund evidence requires full correlation fields")
        _match_string(self.original_payment_ref, _PAYMENT_REF_RE, "original_payment_ref")
        _require_exact_int(
            self.refunded_amount_cents,
            EXPECTED_AMOUNT_CENTS,
            "refunded_amount_cents",
        )
        if len({self.evidence_ref, self.provider_ref, self.original_payment_ref}) != 3:
            raise PaymentEvidenceError("refund evidence references must be unique")

    def to_dict(self) -> dict[str, object]:
        record: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "event_type": self.event_type.value,
            "provider": EXPECTED_PROVIDER,
            "mode": EXPECTED_MODE,
            "livemode": True,
            "status": EXPECTED_STATUS,
            "currency": EXPECTED_CURRENCY,
            "amount_cents": EXPECTED_AMOUNT_CENTS,
            "payment_type": EXPECTED_PAYMENT_TYPE,
            "order_id": self.order_id,
            "observed_at": self.observed_at,
            "evidence_ref": self.evidence_ref,
            "provider_ref": self.provider_ref,
            "artifact_sha256": self.artifact_sha256,
        }
        if self.event_type is PaymentEvidenceEvent.FULL_REFUND:
            assert self.original_payment_ref is not None
            assert self.refunded_amount_cents is not None
            record["original_payment_ref"] = self.original_payment_ref
            record["refunded_amount_cents"] = self.refunded_amount_cents
        return record

    @property
    def sha256(self) -> str:
        """Return the deterministic lowercase digest of the normalized record."""
        encoded = _canonical_json(self.to_dict()).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def envelope(self) -> dict[str, object]:
        """Return only the normalized record and its ledger-ready digest."""
        return {"record": self.to_dict(), "sha256": self.sha256}


def build_live_payment_evidence(
    document: Mapping[str, object],
    *,
    expected_order_id: str,
) -> LivePaymentEvidence:
    """Validate a strict redacted evidence object and return an immutable record."""
    normalized_order_id = _match_string(expected_order_id, _ORDER_ID_RE, "expected_order_id")
    _scan_redaction(document)
    if not all(isinstance(key, str) for key in document):
        raise PaymentEvidenceError("payment evidence field names must be strings")

    raw_event_type = document.get("event_type")
    if not isinstance(raw_event_type, str):
        raise PaymentEvidenceError("event_type must be a string")
    if raw_event_type not in {item.value for item in PaymentEvidenceEvent}:
        raise PaymentEvidenceError("event_type is not allowed")
    event_type = PaymentEvidenceEvent(raw_event_type)

    _strict_keys(document, _EVENT_FIELDS[event_type])
    _require_exact_string(document["schema_version"], SCHEMA_VERSION, "schema_version")
    _require_exact_string(document["provider"], EXPECTED_PROVIDER, "provider")
    _require_exact_string(document["mode"], EXPECTED_MODE, "mode")
    if not _strict_bool(document["livemode"], "livemode"):
        raise PaymentEvidenceError("livemode must be true")
    _require_exact_string(document["status"], EXPECTED_STATUS, "status")
    _require_exact_string(document["currency"], EXPECTED_CURRENCY, "currency")
    _require_exact_int(document["amount_cents"], EXPECTED_AMOUNT_CENTS, "amount_cents")
    _require_exact_string(document["payment_type"], EXPECTED_PAYMENT_TYPE, "payment_type")

    order_id = _match_string(document["order_id"], _ORDER_ID_RE, "order_id")
    if not hmac.compare_digest(order_id, normalized_order_id):
        raise PaymentEvidenceError("order_id does not match the expected order")
    observed_at = _parse_timestamp(document["observed_at"], "observed_at")
    evidence_ref = _match_string(document["evidence_ref"], _EVIDENCE_REF_RE, "evidence_ref")
    provider_pattern = (
        _PAYMENT_REF_RE if event_type is PaymentEvidenceEvent.PAYMENT_CAPTURED else _REFUND_REF_RE
    )
    provider_ref = _match_string(document["provider_ref"], provider_pattern, "provider_ref")
    artifact_sha256 = _match_string(document["artifact_sha256"], _SHA256_RE, "artifact_sha256")

    original_payment_ref: str | None = None
    refunded_amount_cents: int | None = None
    if event_type is PaymentEvidenceEvent.FULL_REFUND:
        original_payment_ref = _match_string(
            document["original_payment_ref"],
            _PAYMENT_REF_RE,
            "original_payment_ref",
        )
        _require_exact_int(
            document["refunded_amount_cents"],
            EXPECTED_AMOUNT_CENTS,
            "refunded_amount_cents",
        )
        refunded_amount_cents = EXPECTED_AMOUNT_CENTS
        if len({evidence_ref, provider_ref, original_payment_ref}) != 3:
            raise PaymentEvidenceError("refund evidence references must be unique")

    return LivePaymentEvidence(
        event_type=event_type,
        order_id=order_id,
        observed_at=observed_at,
        evidence_ref=evidence_ref,
        provider_ref=provider_ref,
        artifact_sha256=artifact_sha256,
        original_payment_ref=original_payment_ref,
        refunded_amount_cents=refunded_amount_cents,
    )


def parse_live_payment_evidence(
    text: str,
    *,
    expected_order_id: str,
) -> LivePaymentEvidence:
    """Parse size-bounded strict JSON and return validated live evidence."""
    if not isinstance(text, str):
        raise TypeError("payment evidence must be JSON text")
    encoded_size: int | None
    try:
        encoded_size = len(text.encode("utf-8"))
    except UnicodeError:
        encoded_size = None
    if encoded_size is None:
        raise PaymentEvidenceError("payment evidence must be valid UTF-8")
    if encoded_size > MAX_DOCUMENT_BYTES:
        raise PaymentEvidenceError("payment evidence exceeds the size limit")
    document: object
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except PaymentEvidenceError:
        raise
    except (json.JSONDecodeError, UnicodeError):
        document = None
    if document is None:
        raise PaymentEvidenceError("payment evidence is not valid JSON")
    if not isinstance(document, Mapping):
        raise PaymentEvidenceError("payment evidence must be a JSON object")
    return build_live_payment_evidence(document, expected_order_id=expected_order_id)


def load_live_payment_evidence(
    path: str | Path,
    *,
    expected_order_id: str,
) -> LivePaymentEvidence:
    """Safely load one bounded UTF-8 regular file without traversing symlinks."""
    path_value = os.fspath(path)
    _reject_symlink_ancestors(path_value)
    try:
        before = os.lstat(path_value)
    except (OSError, TypeError, ValueError):
        before = None
    if before is None:
        raise PaymentEvidenceError("payment evidence file is unavailable")
    if stat.S_ISLNK(before.st_mode):
        raise PaymentEvidenceError("payment evidence file must not be a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise PaymentEvidenceError("payment evidence file must be a regular file")
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise PaymentEvidenceError("payment evidence exceeds the size limit")

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
        raise PaymentEvidenceError("payment evidence file cannot be opened")

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PaymentEvidenceError("payment evidence file must be a regular file")
        if _file_snapshot(before) != _file_snapshot(opened):
            raise PaymentEvidenceError("payment evidence file changed while opening")
        if opened.st_size > MAX_DOCUMENT_BYTES:
            raise PaymentEvidenceError("payment evidence exceeds the size limit")
        data = _read_bounded(descriptor)
        after = os.fstat(descriptor)
        if _file_snapshot(opened) != _file_snapshot(after) or len(data) != after.st_size:
            raise PaymentEvidenceError("payment evidence file changed while reading")
        try:
            current = os.lstat(path_value)
        except (OSError, TypeError, ValueError):
            current = None
        if (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or _file_snapshot(current) != _file_snapshot(after)
        ):
            raise PaymentEvidenceError("payment evidence file changed while reading")
    except OSError:
        raise PaymentEvidenceError("payment evidence file cannot be read") from None
    finally:
        os.close(descriptor)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise PaymentEvidenceError("payment evidence must be UTF-8")
    return parse_live_payment_evidence(text, expected_order_id=expected_order_id)


def _reject_symlink_ancestors(path: str) -> None:
    try:
        ancestors = Path(path).absolute().parents
    except (OSError, TypeError, ValueError):
        raise PaymentEvidenceError("payment evidence file is unavailable") from None
    for ancestor in reversed(ancestors):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            metadata = None
        if metadata is None:
            raise PaymentEvidenceError("payment evidence file is unavailable")
        if stat.S_ISLNK(metadata.st_mode):
            raise PaymentEvidenceError("payment evidence path must not use symlink ancestors")
        if not stat.S_ISDIR(metadata.st_mode):
            raise PaymentEvidenceError("payment evidence path ancestors must be directories")


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
        raise PaymentEvidenceError("payment evidence exceeds the size limit")
    return b"".join(chunks)


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _strict_keys(value: Mapping[str, object], expected: frozenset[str]) -> None:
    if set(value) != set(expected):
        raise PaymentEvidenceError("payment evidence has missing or unknown fields")


def _require_exact_string(value: object, expected: str, field: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise PaymentEvidenceError(f"{field} must use the required fixed value")


def _strict_bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise PaymentEvidenceError(f"{field} must be a JSON boolean")
    return value


def _require_exact_int(value: object, expected: int, field: str) -> None:
    if type(value) is not int or value != expected:
        raise PaymentEvidenceError(f"{field} must equal {expected}")


def _match_string(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PaymentEvidenceError(f"{field} must be a lowercase opaque value")
    return value


def _parse_timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or _RFC3339_RE.fullmatch(value) is None:
        raise PaymentEvidenceError(f"{field} must be a timezone-aware RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        parsed = None
    if parsed is None:
        raise PaymentEvidenceError(f"{field} must be a timezone-aware RFC 3339 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PaymentEvidenceError(f"{field} must include a timezone offset")
    normalized = parsed.astimezone(UTC)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _scan_redaction(
    value: object,
    depth: int = 0,
    active: set[int] | None = None,
) -> None:
    if depth > 8:
        raise PaymentEvidenceError("payment evidence is nested too deeply")
    active_ids = active if active is not None else set()

    if isinstance(value, Mapping):
        object_id = id(value)
        if object_id in active_ids:
            raise PaymentEvidenceError("payment evidence cannot contain cycles")
        active_ids.add(object_id)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise PaymentEvidenceError("payment evidence field names must be strings")
                if key.casefold() in _FORBIDDEN_FIELD_NAMES:
                    raise PaymentEvidenceError(
                        "payment evidence contains a forbidden sensitive or raw field"
                    )
                _scan_redaction(item, depth + 1, active_ids)
        finally:
            active_ids.remove(object_id)
        return

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        object_id = id(value)
        if object_id in active_ids:
            raise PaymentEvidenceError("payment evidence cannot contain cycles")
        active_ids.add(object_id)
        try:
            for item in value:
                _scan_redaction(item, depth + 1, active_ids)
        finally:
            active_ids.remove(object_id)
        return

    if isinstance(value, str) and _contains_sensitive_text(value):
        raise PaymentEvidenceError("payment evidence contains forbidden sensitive data")


def _contains_sensitive_text(value: str) -> bool:
    return bool(
        _EMAIL_RE.search(value)
        or _URL_RE.search(value)
        or _ADDRESS_RE.search(value)
        or _PERSONAL_NAME_RE.fullmatch(value)
        or _CARD_LABEL_RE.search(value)
        or _PAN_CANDIDATE_RE.search(value)
        or _RAW_STRIPE_REF_RE.search(value)
        or any(pattern.search(value) for pattern in _SECRET_PATTERNS)
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PaymentEvidenceError("payment evidence contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> NoReturn:
    del value
    raise PaymentEvidenceError("payment evidence contains a non-JSON number")


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
        description="Validate one redacted live Stripe transaction evidence record."
    )
    parser.add_argument("evidence", help="path to the redacted JSON evidence file")
    parser.add_argument(
        "--order-id",
        required=True,
        help="opaque order identifier for the live transaction",
    )
    args = parser.parse_args(argv)
    try:
        record = load_live_payment_evidence(
            args.evidence,
            expected_order_id=args.order_id,
        )
    except PaymentEvidenceError:
        print("live payment evidence rejected", file=sys.stderr)
        return 2
    print(_canonical_json(record.envelope()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
