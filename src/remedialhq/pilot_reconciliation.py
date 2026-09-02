from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NoReturn

SCHEMA_VERSION: Final = "remedialhq.pilot-slot-reconciliation.v1"
RECONCILIATION_SCOPE: Final = "ALL_LIFETIME_FOUNDING_PURCHASES"
EXPECTED_PROVIDER: Final = "STRIPE"
EXPECTED_PROVIDER_MODE: Final = "LIVE"
PROVIDER_HISTORY_SCOPE: Final = "ALL_AVAILABLE_ACCOUNT_HISTORY"
MAX_DOCUMENT_BYTES: Final = 32_768
FOUNDING_PURCHASE_LIMIT: Final = 5

_TOP_LEVEL_FIELDS: Final = frozenset(
    {
        "schema_version",
        "reconciliation_ref",
        "reconciled_at",
        "scope",
        "checks",
        "payment_provider",
        "prior_ledger",
        "lifetime_consumed_slots",
    }
)
_CHECK_FIELDS: Final = frozenset(
    {
        "all_known_ledgers_reviewed",
        "payment_provider_history_reviewed",
        "single_authoritative_successor_designated",
    }
)
_PRIOR_LEDGER_FIELDS: Final = frozenset(
    {
        "ledger_schema_version",
        "ledger_head_sha256",
        "inherited_consumed_slots",
        "purchase_event_sha256s",
        "purchase_evidence_artifact_sha256s",
        "provider_purchase_sha256s",
    }
)
_PAYMENT_PROVIDER_FIELDS: Final = frozenset(
    {
        "provider",
        "mode",
        "observed_at",
        "history_scope",
        "history_evidence_sha256",
        "provider_purchase_sha256s",
    }
)
_RECONCILIATION_REF_RE: Final = re.compile(r"^rec_[0-9a-f]{32}$")
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_RE: Final = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)


class PilotReconciliationError(ValueError):
    """Raised when founding-slot reconciliation evidence cannot be trusted."""


@dataclass(frozen=True, slots=True)
class PriorPilotLedgerSnapshot:
    """Facts derived from one verified prior pilot ledger."""

    ledger_schema_version: int
    ledger_head_sha256: str
    inherited_consumed_slots: int
    purchase_event_sha256s: tuple[str, ...]
    purchase_evidence_artifact_sha256s: tuple[str, ...]
    provider_purchase_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.ledger_schema_version) is not int or not 1 <= self.ledger_schema_version <= 5:
            raise PilotReconciliationError("prior ledger schema version is invalid")
        _sha256(self.ledger_head_sha256, "ledger_head_sha256")
        _bounded_int(
            self.inherited_consumed_slots,
            "inherited_consumed_slots",
            maximum=FOUNDING_PURCHASE_LIMIT,
        )
        if not isinstance(self.purchase_event_sha256s, tuple):
            raise PilotReconciliationError("purchase event digests must be an immutable sequence")
        for digest in self.purchase_event_sha256s:
            _sha256(digest, "purchase_event_sha256s")
        if len(set(self.purchase_event_sha256s)) != len(self.purchase_event_sha256s):
            raise PilotReconciliationError("purchase event digests must be unique")
        if not isinstance(self.purchase_evidence_artifact_sha256s, tuple):
            raise PilotReconciliationError(
                "purchase evidence artifact digests must be an immutable sequence"
            )
        for digest in self.purchase_evidence_artifact_sha256s:
            _sha256(digest, "purchase_evidence_artifact_sha256s")
        if len(set(self.purchase_evidence_artifact_sha256s)) != len(
            self.purchase_evidence_artifact_sha256s
        ):
            raise PilotReconciliationError("purchase evidence artifact digests must be unique")
        if len(self.purchase_evidence_artifact_sha256s) > len(self.purchase_event_sha256s):
            raise PilotReconciliationError(
                "purchase evidence artifacts exceed direct purchase records"
            )
        if self.ledger_schema_version >= 3 and len(self.purchase_evidence_artifact_sha256s) != len(
            self.purchase_event_sha256s
        ):
            raise PilotReconciliationError(
                "schema 3 or later purchase records require evidence artifacts"
            )
        if not isinstance(self.provider_purchase_sha256s, tuple):
            raise PilotReconciliationError(
                "provider purchase digests must be an immutable sequence"
            )
        for digest in self.provider_purchase_sha256s:
            _sha256(digest, "provider_purchase_sha256s")
        if len(set(self.provider_purchase_sha256s)) != len(self.provider_purchase_sha256s):
            raise PilotReconciliationError("provider purchase digests must be unique")
        if (
            self.ledger_schema_version == 5
            and len(self.provider_purchase_sha256s) != self.lifetime_consumed_slots
        ):
            raise PilotReconciliationError(
                "schema 5 lifetime slots require provider purchase digests"
            )
        if self.ledger_schema_version < 5 and self.lifetime_consumed_slots != 0:
            raise PilotReconciliationError(
                "nonzero schema 1 through 4 ledgers lack verified provider purchase bindings"
            )
        if self.ledger_schema_version < 5 and self.provider_purchase_sha256s:
            raise PilotReconciliationError(
                "schema 1 through 4 ledgers cannot assert provider purchase bindings"
            )
        if self.lifetime_consumed_slots > FOUNDING_PURCHASE_LIMIT:
            raise PilotReconciliationError("prior ledger exceeds the five-slot limit")

    @property
    def lifetime_consumed_slots(self) -> int:
        return self.inherited_consumed_slots + len(self.purchase_event_sha256s)

    def to_dict(self) -> dict[str, object]:
        return {
            "ledger_schema_version": self.ledger_schema_version,
            "ledger_head_sha256": self.ledger_head_sha256,
            "inherited_consumed_slots": self.inherited_consumed_slots,
            "purchase_event_sha256s": list(self.purchase_event_sha256s),
            "purchase_evidence_artifact_sha256s": list(self.purchase_evidence_artifact_sha256s),
            "provider_purchase_sha256s": list(self.provider_purchase_sha256s),
        }


@dataclass(frozen=True, slots=True)
class PaymentProviderHistory:
    """Redacted Stripe LIVE history summary used as the lifetime-slot authority."""

    observed_at: str
    history_evidence_sha256: str
    provider_purchase_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        if _normalize_timestamp(self.observed_at) != self.observed_at:
            raise PilotReconciliationError("payment provider observed_at must be normalized to UTC")
        _sha256(self.history_evidence_sha256, "history_evidence_sha256")
        if not isinstance(self.provider_purchase_sha256s, tuple):
            raise PilotReconciliationError(
                "provider purchase digests must be an immutable sequence"
            )
        for digest in self.provider_purchase_sha256s:
            _sha256(digest, "provider_purchase_sha256s")
        if len(set(self.provider_purchase_sha256s)) != len(self.provider_purchase_sha256s):
            raise PilotReconciliationError("provider purchase digests must be unique")
        if len(self.provider_purchase_sha256s) > FOUNDING_PURCHASE_LIMIT:
            raise PilotReconciliationError("payment provider history exceeds the five-slot limit")

    @property
    def lifetime_consumed_slots(self) -> int:
        return len(self.provider_purchase_sha256s)

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": EXPECTED_PROVIDER,
            "mode": EXPECTED_PROVIDER_MODE,
            "observed_at": self.observed_at,
            "history_scope": PROVIDER_HISTORY_SCOPE,
            "history_evidence_sha256": self.history_evidence_sha256,
            "provider_purchase_sha256s": list(self.provider_purchase_sha256s),
        }


@dataclass(frozen=True, slots=True)
class PilotSlotReconciliation:
    """Validated, privacy-minimized evidence for the lifetime founding-slot count."""

    reconciliation_ref: str
    reconciled_at: str
    payment_provider: PaymentProviderHistory
    prior_ledger: PriorPilotLedgerSnapshot | None
    lifetime_consumed_slots: int
    evidence_sha256: str
    record_sha256: str

    def __post_init__(self) -> None:
        _match(self.reconciliation_ref, _RECONCILIATION_REF_RE, "reconciliation_ref")
        if _normalize_timestamp(self.reconciled_at) != self.reconciled_at:
            raise PilotReconciliationError("reconciled_at must be normalized to UTC")
        if self.prior_ledger is not None and not isinstance(
            self.prior_ledger, PriorPilotLedgerSnapshot
        ):
            raise PilotReconciliationError("prior_ledger is invalid")
        if not isinstance(self.payment_provider, PaymentProviderHistory):
            raise PilotReconciliationError("payment_provider is invalid")
        expected_slots = self.payment_provider.lifetime_consumed_slots
        _cross_check_provider_history(self.payment_provider, self.prior_ledger)
        _bounded_int(
            self.lifetime_consumed_slots,
            "lifetime_consumed_slots",
            maximum=FOUNDING_PURCHASE_LIMIT,
        )
        if self.lifetime_consumed_slots != expected_slots:
            raise PilotReconciliationError(
                "lifetime_consumed_slots contradicts the payment provider history"
            )
        _sha256(self.evidence_sha256, "evidence_sha256")
        _sha256(self.record_sha256, "record_sha256")
        expected_record_sha256 = hashlib.sha256(
            _canonical_json(self.to_dict()).encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(self.record_sha256, expected_record_sha256):
            raise PilotReconciliationError(
                "record_sha256 does not match the normalized reconciliation record"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "reconciliation_ref": self.reconciliation_ref,
            "reconciled_at": self.reconciled_at,
            "scope": RECONCILIATION_SCOPE,
            "checks": {
                "all_known_ledgers_reviewed": True,
                "payment_provider_history_reviewed": True,
                "single_authoritative_successor_designated": True,
            },
            "payment_provider": self.payment_provider.to_dict(),
            "prior_ledger": (None if self.prior_ledger is None else self.prior_ledger.to_dict()),
            "lifetime_consumed_slots": self.lifetime_consumed_slots,
        }


def build_pilot_slot_reconciliation(
    document: Mapping[str, object],
    *,
    expected_prior_ledger: PriorPilotLedgerSnapshot | None,
    evidence_bytes: bytes | None = None,
) -> PilotSlotReconciliation:
    """Validate one reconciliation object against independently derived ledger facts."""
    if not isinstance(document, Mapping) or any(not isinstance(key, str) for key in document):
        raise PilotReconciliationError("reconciliation evidence must be a JSON object")
    if set(document) != set(_TOP_LEVEL_FIELDS):
        raise PilotReconciliationError("reconciliation evidence has missing or unknown fields")
    _exact_string(document["schema_version"], SCHEMA_VERSION, "schema_version")
    reconciliation_ref = _match(
        document["reconciliation_ref"],
        _RECONCILIATION_REF_RE,
        "reconciliation_ref",
    )
    reconciled_at = _normalize_timestamp(document["reconciled_at"])
    if document["reconciled_at"] != reconciled_at:
        raise PilotReconciliationError("reconciled_at must be normalized to UTC")
    _exact_string(document["scope"], RECONCILIATION_SCOPE, "scope")

    checks = document["checks"]
    if not isinstance(checks, Mapping) or any(not isinstance(key, str) for key in checks):
        raise PilotReconciliationError("checks must be an object")
    if set(checks) != set(_CHECK_FIELDS):
        raise PilotReconciliationError("checks has missing or unknown fields")
    for field_name in sorted(_CHECK_FIELDS):
        if checks[field_name] is not True:
            raise PilotReconciliationError(f"{field_name} must be true")

    payment_provider = _build_payment_provider(document["payment_provider"])
    prior_document = document["prior_ledger"]
    prior_ledger = _build_prior_ledger(prior_document)
    if expected_prior_ledger is None:
        if prior_ledger is not None:
            raise PilotReconciliationError(
                "prior_ledger is not allowed without a verified --prior-ledger"
            )
    elif prior_ledger is None:
        raise PilotReconciliationError("prior_ledger is required when --prior-ledger is supplied")
    elif prior_ledger != expected_prior_ledger:
        raise PilotReconciliationError("prior_ledger contradicts the verified prior ledger")
    _cross_check_provider_history(payment_provider, prior_ledger)

    expected_slots = payment_provider.lifetime_consumed_slots
    declared_slots = _bounded_int(
        document["lifetime_consumed_slots"],
        "lifetime_consumed_slots",
        maximum=FOUNDING_PURCHASE_LIMIT,
    )
    if declared_slots != expected_slots:
        raise PilotReconciliationError(
            "lifetime_consumed_slots contradicts the payment provider history"
        )

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "reconciliation_ref": reconciliation_ref,
        "reconciled_at": reconciled_at,
        "scope": RECONCILIATION_SCOPE,
        "checks": {field_name: True for field_name in sorted(_CHECK_FIELDS)},
        "payment_provider": payment_provider.to_dict(),
        "prior_ledger": None if prior_ledger is None else prior_ledger.to_dict(),
        "lifetime_consumed_slots": declared_slots,
    }
    canonical_bytes = _canonical_json(normalized).encode("utf-8")
    source_bytes = canonical_bytes if evidence_bytes is None else evidence_bytes
    evidence_sha256 = hashlib.sha256(source_bytes).hexdigest()
    record_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    return PilotSlotReconciliation(
        reconciliation_ref=reconciliation_ref,
        reconciled_at=reconciled_at,
        payment_provider=payment_provider,
        prior_ledger=prior_ledger,
        lifetime_consumed_slots=declared_slots,
        evidence_sha256=evidence_sha256,
        record_sha256=record_sha256,
    )


def parse_pilot_slot_reconciliation(
    text: str,
    *,
    expected_prior_ledger: PriorPilotLedgerSnapshot | None,
) -> PilotSlotReconciliation:
    """Parse strict, bounded JSON and cross-check its prior-ledger facts."""
    if not isinstance(text, str):
        raise TypeError("reconciliation evidence must be JSON text")
    try:
        evidence_bytes = text.encode("utf-8")
    except UnicodeError:
        raise PilotReconciliationError("reconciliation evidence must be valid UTF-8") from None
    if len(evidence_bytes) > MAX_DOCUMENT_BYTES:
        raise PilotReconciliationError("reconciliation evidence exceeds the size limit")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except PilotReconciliationError:
        raise
    except (json.JSONDecodeError, UnicodeError):
        raise PilotReconciliationError("reconciliation evidence is not valid JSON") from None
    if not isinstance(document, Mapping):
        raise PilotReconciliationError("reconciliation evidence must be a JSON object")
    return build_pilot_slot_reconciliation(
        document,
        expected_prior_ledger=expected_prior_ledger,
        evidence_bytes=evidence_bytes,
    )


def load_pilot_slot_reconciliation(
    path: str | Path,
    *,
    expected_prior_ledger: PriorPilotLedgerSnapshot | None,
) -> PilotSlotReconciliation:
    """Load one stable regular reconciliation file without following symlinks."""
    path_value = os.fspath(path)
    _reject_symlink_ancestors(path_value)
    try:
        before = os.lstat(path_value)
    except (OSError, TypeError, ValueError):
        raise PilotReconciliationError("reconciliation evidence file is unavailable") from None
    if stat.S_ISLNK(before.st_mode):
        raise PilotReconciliationError("reconciliation evidence file must not be a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise PilotReconciliationError("reconciliation evidence file must be a regular file")
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise PilotReconciliationError("reconciliation evidence exceeds the size limit")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path_value, flags)
    except (OSError, TypeError, ValueError):
        raise PilotReconciliationError("reconciliation evidence file cannot be opened") from None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PilotReconciliationError("reconciliation evidence file must be a regular file")
        if _file_snapshot(before) != _file_snapshot(opened):
            raise PilotReconciliationError("reconciliation evidence file changed while opening")
        data = _read_bounded(descriptor)
        after = os.fstat(descriptor)
        if _file_snapshot(opened) != _file_snapshot(after) or len(data) != after.st_size:
            raise PilotReconciliationError("reconciliation evidence file changed while reading")
        try:
            current = os.lstat(path_value)
        except (OSError, TypeError, ValueError):
            current = None
        if (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or _file_snapshot(current) != _file_snapshot(after)
        ):
            raise PilotReconciliationError("reconciliation evidence file changed while reading")
    except OSError:
        raise PilotReconciliationError("reconciliation evidence file cannot be read") from None
    finally:
        os.close(descriptor)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise PilotReconciliationError("reconciliation evidence must be UTF-8") from None
    return parse_pilot_slot_reconciliation(
        text,
        expected_prior_ledger=expected_prior_ledger,
    )


def _build_prior_ledger(value: object) -> PriorPilotLedgerSnapshot | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise PilotReconciliationError("prior_ledger must be an object or null")
    if set(value) != set(_PRIOR_LEDGER_FIELDS):
        raise PilotReconciliationError("prior_ledger has missing or unknown fields")
    schema_version = _bounded_int(
        value["ledger_schema_version"],
        "ledger_schema_version",
        minimum=1,
        maximum=5,
    )
    head = _sha256(value["ledger_head_sha256"], "ledger_head_sha256")
    inherited = _bounded_int(
        value["inherited_consumed_slots"],
        "inherited_consumed_slots",
        maximum=FOUNDING_PURCHASE_LIMIT,
    )
    raw_purchase_hashes = value["purchase_event_sha256s"]
    if not isinstance(raw_purchase_hashes, Sequence) or isinstance(
        raw_purchase_hashes, (str, bytes, bytearray)
    ):
        raise PilotReconciliationError("purchase_event_sha256s must be an array")
    purchase_hashes = tuple(_sha256(item, "purchase_event_sha256s") for item in raw_purchase_hashes)
    raw_purchase_evidence_hashes = value["purchase_evidence_artifact_sha256s"]
    if not isinstance(raw_purchase_evidence_hashes, Sequence) or isinstance(
        raw_purchase_evidence_hashes, (str, bytes, bytearray)
    ):
        raise PilotReconciliationError("purchase_evidence_artifact_sha256s must be an array")
    purchase_evidence_hashes = tuple(
        _sha256(item, "purchase_evidence_artifact_sha256s") for item in raw_purchase_evidence_hashes
    )
    raw_provider_purchase_hashes = value["provider_purchase_sha256s"]
    if not isinstance(raw_provider_purchase_hashes, Sequence) or isinstance(
        raw_provider_purchase_hashes, (str, bytes, bytearray)
    ):
        raise PilotReconciliationError("provider_purchase_sha256s must be an array")
    provider_purchase_hashes = tuple(
        _sha256(item, "provider_purchase_sha256s") for item in raw_provider_purchase_hashes
    )
    return PriorPilotLedgerSnapshot(
        ledger_schema_version=schema_version,
        ledger_head_sha256=head,
        inherited_consumed_slots=inherited,
        purchase_event_sha256s=purchase_hashes,
        purchase_evidence_artifact_sha256s=purchase_evidence_hashes,
        provider_purchase_sha256s=provider_purchase_hashes,
    )


def _build_payment_provider(value: object) -> PaymentProviderHistory:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise PilotReconciliationError("payment_provider must be an object")
    if set(value) != set(_PAYMENT_PROVIDER_FIELDS):
        raise PilotReconciliationError("payment_provider has missing or unknown fields")
    _exact_string(value["provider"], EXPECTED_PROVIDER, "provider")
    _exact_string(value["mode"], EXPECTED_PROVIDER_MODE, "mode")
    observed_at = _normalize_timestamp(value["observed_at"])
    if value["observed_at"] != observed_at:
        raise PilotReconciliationError("payment provider observed_at must be normalized to UTC")
    _exact_string(value["history_scope"], PROVIDER_HISTORY_SCOPE, "history_scope")
    history_evidence_sha256 = _sha256(
        value["history_evidence_sha256"],
        "history_evidence_sha256",
    )
    raw_purchase_hashes = value["provider_purchase_sha256s"]
    if not isinstance(raw_purchase_hashes, Sequence) or isinstance(
        raw_purchase_hashes, (str, bytes, bytearray)
    ):
        raise PilotReconciliationError("provider_purchase_sha256s must be an array")
    purchase_hashes = tuple(
        _sha256(item, "provider_purchase_sha256s") for item in raw_purchase_hashes
    )
    return PaymentProviderHistory(
        observed_at=observed_at,
        history_evidence_sha256=history_evidence_sha256,
        provider_purchase_sha256s=purchase_hashes,
    )


def _cross_check_provider_history(
    payment_provider: PaymentProviderHistory,
    prior_ledger: PriorPilotLedgerSnapshot | None,
) -> None:
    if prior_ledger is None:
        return
    if payment_provider.lifetime_consumed_slots < prior_ledger.lifetime_consumed_slots:
        raise PilotReconciliationError(
            "payment provider purchase count is below the prior-ledger lifetime count"
        )
    provider_hashes = set(payment_provider.provider_purchase_sha256s)
    missing = set(prior_ledger.provider_purchase_sha256s) - provider_hashes
    if missing:
        raise PilotReconciliationError(
            "payment provider history omits verified prior-ledger provider purchases"
        )


def _normalize_timestamp(value: object) -> str:
    if not isinstance(value, str) or len(value) > 40 or _RFC3339_RE.fullmatch(value) is None:
        raise PilotReconciliationError("reconciled_at must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise PilotReconciliationError("reconciled_at must be an RFC 3339 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PilotReconciliationError("reconciled_at must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _exact_string(value: object, expected: str, field_name: str) -> str:
    if not isinstance(value, str) or not hmac.compare_digest(value, expected):
        raise PilotReconciliationError(f"{field_name} is not supported")
    return value


def _match(value: object, pattern: re.Pattern[str], field_name: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PilotReconciliationError(f"{field_name} is invalid")
    return value


def _sha256(value: object, field_name: str) -> str:
    return _match(value, _SHA256_RE, field_name)


def _bounded_int(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise PilotReconciliationError(
            f"{field_name} must be an integer from {minimum} through {maximum}"
        )
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PilotReconciliationError("reconciliation evidence contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> NoReturn:
    del value
    raise PilotReconciliationError("reconciliation evidence contains a non-JSON number")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _reject_symlink_ancestors(path: str) -> None:
    try:
        ancestors = Path(path).absolute().parents
    except (OSError, TypeError, ValueError):
        raise PilotReconciliationError("reconciliation evidence file is unavailable") from None
    for ancestor in reversed(ancestors):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise PilotReconciliationError(
                "reconciliation evidence path must not traverse symlinks"
            )


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(8192, MAX_DOCUMENT_BYTES + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_DOCUMENT_BYTES:
            raise PilotReconciliationError("reconciliation evidence exceeds the size limit")
