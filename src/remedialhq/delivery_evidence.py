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

SCHEMA_VERSION = "remedialhq.delivery-evidence.v1"
EXPECTED_EVENT_TYPE = "DELIVERY_RECORDED"
MAX_DOCUMENT_BYTES = 16_384


class DeliveryEvidenceError(ValueError):
    """Raised when delivery evidence is unsafe, incomplete, or invalid."""


class DeliveryMethod(StrEnum):
    EMAIL_PROVIDER_ACCEPTED = "EMAIL_PROVIDER_ACCEPTED"
    PORTAL_UPLOAD_CONFIRMED = "PORTAL_UPLOAD_CONFIRMED"
    CUSTOMER_ACKNOWLEDGED = "CUSTOMER_ACKNOWLEDGED"


_FIELDS = frozenset(
    {
        "schema_version",
        "event_type",
        "delivery_method",
        "order_id",
        "artifact_sha256",
        "evidence_artifact_sha256",
        "observed_at",
        "evidence_ref",
        "delivery_ref",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ORDER_ID_RE = re.compile(r"^ord_[0-9a-f]{32}$")
_EVIDENCE_REF_RE = re.compile(r"^evd_[0-9a-f]{32}$")
_DELIVERY_REF_RE = re.compile(r"^dlv_[0-9a-f]{32}$")
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
_CARD_DATA_RE = re.compile(
    r"(?:\b(?:card\s*number|cardholder|cvc|cvv|expiration|expiry)\b|"
    r"(?<![0-9A-Za-z])(?:\d[ -]?){12,18}\d(?![0-9A-Za-z]))",
    re.IGNORECASE,
)
_RAW_PROVIDER_REF_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:cs_(?:test|live)_|pi_|ch_|re_|evt_|cus_|pm_|in_|sub_|"
    r"plink_|sg_|ses_|msg_|message_)[A-Za-z0-9._-]+",
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
        "client_secret",
        "customer",
        "customer_details",
        "data",
        "email",
        "headers",
        "message_id",
        "metadata",
        "name",
        "object",
        "password",
        "payload",
        "provider_id",
        "raw",
        "raw_payload",
        "recipient",
        "secret",
        "token",
        "url",
    }
)


@dataclass(frozen=True, slots=True)
class DeliveryEvidence:
    """Normalized proof that a specific completed artifact was externally delivered."""

    delivery_method: DeliveryMethod
    order_id: str
    artifact_sha256: str
    evidence_artifact_sha256: str
    observed_at: str
    evidence_ref: str
    delivery_ref: str

    def __post_init__(self) -> None:
        if not isinstance(self.delivery_method, DeliveryMethod):
            raise DeliveryEvidenceError("delivery_method is not allowed")
        _match_string(self.order_id, _ORDER_ID_RE, "order_id")
        _match_string(self.artifact_sha256, _SHA256_RE, "artifact_sha256")
        _match_string(
            self.evidence_artifact_sha256,
            _SHA256_RE,
            "evidence_artifact_sha256",
        )
        if hmac.compare_digest(self.artifact_sha256, self.evidence_artifact_sha256):
            raise DeliveryEvidenceError(
                "evidence_artifact_sha256 must differ from the delivered artifact"
            )
        if _parse_timestamp(self.observed_at, "observed_at") != self.observed_at:
            raise DeliveryEvidenceError("observed_at must be normalized to UTC")
        _match_string(self.evidence_ref, _EVIDENCE_REF_RE, "evidence_ref")
        _match_string(self.delivery_ref, _DELIVERY_REF_RE, "delivery_ref")
        if self.evidence_ref == self.delivery_ref:
            raise DeliveryEvidenceError("delivery evidence references must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "event_type": EXPECTED_EVENT_TYPE,
            "delivery_method": self.delivery_method.value,
            "order_id": self.order_id,
            "artifact_sha256": self.artifact_sha256,
            "evidence_artifact_sha256": self.evidence_artifact_sha256,
            "observed_at": self.observed_at,
            "evidence_ref": self.evidence_ref,
            "delivery_ref": self.delivery_ref,
        }

    @property
    def sha256(self) -> str:
        """Return the deterministic lowercase digest of the normalized record."""
        encoded = _canonical_json(self.to_dict()).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def envelope(self) -> dict[str, object]:
        """Return only the normalized record and its ledger-ready digest."""
        return {"record": self.to_dict(), "sha256": self.sha256}


def build_delivery_evidence(
    document: Mapping[str, object],
    *,
    expected_order_id: str,
    expected_artifact_sha256: str,
) -> DeliveryEvidence:
    """Validate redacted delivery proof correlated to one exact local artifact."""
    normalized_order_id = _match_string(expected_order_id, _ORDER_ID_RE, "expected_order_id")
    expected_digest = _match_string(
        expected_artifact_sha256,
        _SHA256_RE,
        "expected_artifact_sha256",
    )
    _scan_redaction(document)
    if not all(isinstance(key, str) for key in document):
        raise DeliveryEvidenceError("delivery evidence field names must be strings")
    if set(document) != set(_FIELDS):
        raise DeliveryEvidenceError("delivery evidence has missing or unknown fields")

    _require_exact_string(document["schema_version"], SCHEMA_VERSION, "schema_version")
    _require_exact_string(document["event_type"], EXPECTED_EVENT_TYPE, "event_type")

    raw_method = document["delivery_method"]
    if not isinstance(raw_method, str):
        raise DeliveryEvidenceError("delivery_method must be a string")
    if raw_method not in {item.value for item in DeliveryMethod}:
        raise DeliveryEvidenceError("delivery_method is not allowed")
    delivery_method = DeliveryMethod(raw_method)

    order_id = _match_string(document["order_id"], _ORDER_ID_RE, "order_id")
    if not hmac.compare_digest(order_id, normalized_order_id):
        raise DeliveryEvidenceError("order_id does not match the expected order")
    artifact_sha256 = _match_string(document["artifact_sha256"], _SHA256_RE, "artifact_sha256")
    if not hmac.compare_digest(artifact_sha256, expected_digest):
        raise DeliveryEvidenceError("artifact_sha256 does not match the completed artifact")
    evidence_artifact_sha256 = _match_string(
        document["evidence_artifact_sha256"],
        _SHA256_RE,
        "evidence_artifact_sha256",
    )
    if hmac.compare_digest(artifact_sha256, evidence_artifact_sha256):
        raise DeliveryEvidenceError(
            "evidence_artifact_sha256 must differ from the delivered artifact"
        )
    observed_at = _parse_timestamp(document["observed_at"], "observed_at")
    evidence_ref = _match_string(document["evidence_ref"], _EVIDENCE_REF_RE, "evidence_ref")
    delivery_ref = _match_string(document["delivery_ref"], _DELIVERY_REF_RE, "delivery_ref")

    return DeliveryEvidence(
        delivery_method=delivery_method,
        order_id=order_id,
        artifact_sha256=artifact_sha256,
        evidence_artifact_sha256=evidence_artifact_sha256,
        observed_at=observed_at,
        evidence_ref=evidence_ref,
        delivery_ref=delivery_ref,
    )


def parse_delivery_evidence(
    text: str,
    *,
    expected_order_id: str,
    expected_artifact_sha256: str,
) -> DeliveryEvidence:
    """Parse size-bounded strict JSON and validate external delivery proof."""
    if not isinstance(text, str):
        raise TypeError("delivery evidence must be JSON text")
    encoded_size: int | None
    try:
        encoded_size = len(text.encode("utf-8"))
    except UnicodeError:
        encoded_size = None
    if encoded_size is None:
        raise DeliveryEvidenceError("delivery evidence must be valid UTF-8")
    if encoded_size > MAX_DOCUMENT_BYTES:
        raise DeliveryEvidenceError("delivery evidence exceeds the size limit")

    document: object
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except DeliveryEvidenceError:
        raise
    except (json.JSONDecodeError, UnicodeError):
        document = None
    if document is None:
        raise DeliveryEvidenceError("delivery evidence is not valid JSON")
    if not isinstance(document, Mapping):
        raise DeliveryEvidenceError("delivery evidence must be a JSON object")
    return build_delivery_evidence(
        document,
        expected_order_id=expected_order_id,
        expected_artifact_sha256=expected_artifact_sha256,
    )


def load_delivery_evidence(
    path: str | Path,
    *,
    expected_order_id: str,
    expected_artifact_sha256: str,
) -> DeliveryEvidence:
    """Load one bounded regular file without traversing symbolic links."""
    path_value = os.fspath(path)
    _reject_symlink_ancestors(path_value)
    try:
        before = os.lstat(path_value)
    except (OSError, TypeError, ValueError):
        before = None
    if before is None:
        raise DeliveryEvidenceError("delivery evidence file is unavailable")
    if stat.S_ISLNK(before.st_mode):
        raise DeliveryEvidenceError("delivery evidence file must not be a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise DeliveryEvidenceError("delivery evidence file must be a regular file")
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise DeliveryEvidenceError("delivery evidence exceeds the size limit")

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
        raise DeliveryEvidenceError("delivery evidence file cannot be opened")

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise DeliveryEvidenceError("delivery evidence file must be a regular file")
        if _file_snapshot(before) != _file_snapshot(opened):
            raise DeliveryEvidenceError("delivery evidence file changed while opening")
        if opened.st_size > MAX_DOCUMENT_BYTES:
            raise DeliveryEvidenceError("delivery evidence exceeds the size limit")
        data = _read_bounded(descriptor)
        after = os.fstat(descriptor)
        if _file_snapshot(opened) != _file_snapshot(after) or len(data) != after.st_size:
            raise DeliveryEvidenceError("delivery evidence file changed while reading")
        try:
            current = os.lstat(path_value)
        except (OSError, TypeError, ValueError):
            current = None
        if (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or _file_snapshot(current) != _file_snapshot(after)
        ):
            raise DeliveryEvidenceError("delivery evidence file changed while reading")
    except OSError:
        raise DeliveryEvidenceError("delivery evidence file cannot be read") from None
    finally:
        os.close(descriptor)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise DeliveryEvidenceError("delivery evidence must be UTF-8")
    return parse_delivery_evidence(
        text,
        expected_order_id=expected_order_id,
        expected_artifact_sha256=expected_artifact_sha256,
    )


def _reject_symlink_ancestors(path: str) -> None:
    try:
        ancestors = Path(path).absolute().parents
    except (OSError, TypeError, ValueError):
        raise DeliveryEvidenceError("delivery evidence file is unavailable") from None
    for ancestor in reversed(ancestors):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            metadata = None
        if metadata is None:
            raise DeliveryEvidenceError("delivery evidence file is unavailable")
        if stat.S_ISLNK(metadata.st_mode):
            raise DeliveryEvidenceError("delivery evidence path must not use symlink ancestors")
        if not stat.S_ISDIR(metadata.st_mode):
            raise DeliveryEvidenceError("delivery evidence path ancestors must be directories")


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
        raise DeliveryEvidenceError("delivery evidence exceeds the size limit")
    return b"".join(chunks)


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_exact_string(value: object, expected: str, field: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise DeliveryEvidenceError(f"{field} must use the required fixed value")


def _match_string(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DeliveryEvidenceError(f"{field} must be a lowercase opaque value")
    return value


def _parse_timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or _RFC3339_RE.fullmatch(value) is None:
        raise DeliveryEvidenceError(f"{field} must be a timezone-aware RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DeliveryEvidenceError(f"{field} must be a timezone-aware RFC 3339 timestamp")
    normalized = parsed.astimezone(UTC)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _scan_redaction(
    value: object,
    depth: int = 0,
    active: set[int] | None = None,
) -> None:
    if depth > 8:
        raise DeliveryEvidenceError("delivery evidence is nested too deeply")
    active_ids = active if active is not None else set()

    if isinstance(value, Mapping):
        object_id = id(value)
        if object_id in active_ids:
            raise DeliveryEvidenceError("delivery evidence cannot contain cycles")
        active_ids.add(object_id)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise DeliveryEvidenceError("delivery evidence field names must be strings")
                if key.casefold() in _FORBIDDEN_FIELD_NAMES:
                    raise DeliveryEvidenceError(
                        "delivery evidence contains a forbidden sensitive or raw field"
                    )
                _scan_redaction(item, depth + 1, active_ids)
        finally:
            active_ids.remove(object_id)
        return

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        object_id = id(value)
        if object_id in active_ids:
            raise DeliveryEvidenceError("delivery evidence cannot contain cycles")
        active_ids.add(object_id)
        try:
            for item in value:
                _scan_redaction(item, depth + 1, active_ids)
        finally:
            active_ids.remove(object_id)
        return

    if isinstance(value, str) and _contains_sensitive_text(value):
        raise DeliveryEvidenceError("delivery evidence contains forbidden sensitive data")


def _contains_sensitive_text(value: str) -> bool:
    return bool(
        _EMAIL_RE.search(value)
        or _URL_RE.search(value)
        or _ADDRESS_RE.search(value)
        or _PERSONAL_NAME_RE.fullmatch(value)
        or _CARD_DATA_RE.search(value)
        or _RAW_PROVIDER_REF_RE.search(value)
        or any(pattern.search(value) for pattern in _SECRET_PATTERNS)
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DeliveryEvidenceError("delivery evidence contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> NoReturn:
    del value
    raise DeliveryEvidenceError("delivery evidence contains a non-JSON number")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate redacted external delivery evidence.")
    parser.add_argument("evidence", help="path to the redacted JSON evidence file")
    parser.add_argument(
        "--order-id",
        required=True,
        help="opaque order identifier for the delivered artifact",
    )
    parser.add_argument(
        "--artifact-sha256",
        required=True,
        help="lowercase SHA-256 of the completed local artifact",
    )
    args = parser.parse_args(argv)
    try:
        record = load_delivery_evidence(
            args.evidence,
            expected_order_id=args.order_id,
            expected_artifact_sha256=args.artifact_sha256,
        )
    except DeliveryEvidenceError:
        print("delivery evidence rejected", file=sys.stderr)
        return 2
    print(_canonical_json(record.envelope()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
