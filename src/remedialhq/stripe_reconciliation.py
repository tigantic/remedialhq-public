from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NoReturn, cast

from .pilot_reconciliation import (
    EXPECTED_PROVIDER,
    EXPECTED_PROVIDER_MODE,
    FOUNDING_PURCHASE_LIMIT,
    PROVIDER_HISTORY_SCOPE,
    RECONCILIATION_SCOPE,
    PilotReconciliationError,
    PilotSlotReconciliation,
    PriorPilotLedgerSnapshot,
    build_pilot_slot_reconciliation,
)
from .pilot_reconciliation import (
    SCHEMA_VERSION as RECONCILIATION_SCHEMA_VERSION,
)
from .pilots import PilotLedger, PilotLedgerError, PilotValidationError
from .stripe_live_history import (
    MAX_PAID_PURCHASES,
    OFFER_AMOUNT_CENTS,
    OFFER_CURRENCY,
    OFFER_NAME,
)
from .stripe_live_history import (
    SCHEMA_VERSION as STRIPE_HISTORY_SCHEMA_VERSION,
)

MAX_HISTORY_BYTES: Final = 1024 * 1024
_HISTORY_TOP_LEVEL_FIELDS: Final = frozenset(
    {
        "schema_version",
        "provider",
        "mode",
        "livemode",
        "observed_at",
        "offer",
        "endpoint_coverage",
        "account_controls",
        "aggregates",
        "purchases",
        "purchase_record_sha256",
        "provider_purchase_sha256s",
        "history_evidence_sha256",
    }
)
_OFFER_FIELDS: Final = frozenset({"name", "currency", "amount_cents", "payment_type", "slot_limit"})
_COVERAGE_FIELDS: Final = frozenset({"requests", "pages", "objects", "pagination_complete"})
_REQUIRED_COVERAGE: Final = frozenset(
    {
        "account",
        "products",
        "prices",
        "payment_links",
        "payment_link_line_items",
        "checkout_sessions",
        "payment_intents",
        "charges",
        "refunds",
        "disputes",
    }
)
_AGGREGATE_FIELDS: Final = frozenset(
    {
        "products_scanned",
        "prices_scanned",
        "payment_links_scanned",
        "payment_link_line_items_scanned",
        "matching_payment_links",
        "active_matching_payment_links",
        "checkout_sessions_scanned",
        "checkout_session_line_items_scanned",
        "matching_checkout_sessions",
        "abandoned_matching_checkout_sessions",
        "paid_founding_purchases",
        "gross_paid_amount_cents",
        "tax_collected_amount_cents",
        "successful_refunded_amount_cents",
    }
)
_PURCHASE_FIELDS: Final = frozenset(
    {
        "captured_at",
        "currency",
        "amount_cents",
        "gross_amount_cents",
        "tax_amount_cents",
        "status",
        "provider_purchase_sha256",
        "refund_attempt_count",
        "successful_refund_count",
        "refunded_amount_cents",
        "fully_refunded",
        "dispute_count",
        "has_open_dispute",
        "provider_reference_sha256",
    }
)
_PROVIDER_REFERENCE_FIELDS: Final = frozenset(
    {"checkout_session", "payment_intent", "charge", "refunds", "disputes"}
)
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_RECONCILIATION_REF_RE: Final = re.compile(r"^rec_[0-9a-f]{32}$")
_UTC_TIMESTAMP_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_EMAIL_RE: Final = re.compile(
    r"\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+\b",
    re.IGNORECASE,
)
_URL_RE: Final = re.compile(r"(?:https?://|www\.)", re.IGNORECASE)
_SECRET_RE: Final = re.compile(
    r"\b(?:(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_]{8,}|whsec_[A-Za-z0-9_]{8,})\b",
    re.IGNORECASE,
)
_RAW_PROVIDER_REFERENCE_RE: Final = re.compile(
    r"(?<![A-Za-z0-9])(?:acct|ba|card|ch|cs_live|cs_test|cus|dp|evt|in|li|"
    r"mandate|pi|plink|pm|po|price|prod|py|re|seti|si|src|sub|taxrate|txn|we|wsrc)_"
    r"[A-Za-z0-9_]+",
    re.IGNORECASE,
)


class StripeReconciliationError(RuntimeError):
    """Raised when Stripe history cannot safely become slot reconciliation evidence."""


@dataclass(frozen=True, slots=True)
class StripeHistoryReview:
    """Validated facts from one exact, retained Stripe history file."""

    document: Mapping[str, object]
    exact_file_sha256: str
    observed_at: str
    provider_purchase_sha256s: tuple[str, ...]

    @property
    def purchase_count(self) -> int:
        return len(self.provider_purchase_sha256s)


@dataclass(frozen=True, slots=True)
class StripeReconciliationResult:
    """One written reconciliation artifact and its aggregate-only facts."""

    reconciliation: PilotSlotReconciliation
    history_file_sha256: str
    output_path: Path


def load_stripe_history(path: str | Path) -> StripeHistoryReview:
    """Securely load and strictly validate one canonical Stripe history capture."""
    source_path, source_bytes = _read_owner_private_file(path, label="Stripe history")
    del source_path
    try:
        text = source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise StripeReconciliationError("Stripe history must be valid UTF-8") from None
    try:
        decoded: object = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except StripeReconciliationError:
        raise
    except (json.JSONDecodeError, UnicodeError):
        raise StripeReconciliationError("Stripe history is not valid JSON") from None
    document = _mapping(decoded, _HISTORY_TOP_LEVEL_FIELDS, "Stripe history")
    canonical_bytes = (_canonical_json(document) + "\n").encode("utf-8")
    if not hmac.compare_digest(source_bytes, canonical_bytes):
        raise StripeReconciliationError(
            "Stripe history must be canonical JSON with one final newline"
        )
    _validate_history_document(document)
    embedded_digest = _sha256(document["history_evidence_sha256"], "history digest")
    self_excluding_document = dict(document)
    del self_excluding_document["history_evidence_sha256"]
    expected_embedded_digest = hashlib.sha256(
        _canonical_json(self_excluding_document).encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(embedded_digest, expected_embedded_digest):
        raise StripeReconciliationError("Stripe history embedded digest does not match")
    provider_purchase_sha256s = tuple(
        _sha256(value, "provider purchase digest")
        for value in _sequence(
            document["provider_purchase_sha256s"],
            "provider_purchase_sha256s",
        )
    )
    return StripeHistoryReview(
        document=document,
        exact_file_sha256=hashlib.sha256(source_bytes).hexdigest(),
        observed_at=_utc_timestamp(document["observed_at"], "observed_at"),
        provider_purchase_sha256s=provider_purchase_sha256s,
    )


def create_stripe_reconciliation(
    history_path: str | Path,
    output_path: str | Path,
    *,
    prior_ledger: str | Path | None = None,
    reconciliation_ref: str | None = None,
    reconciled_at: str | None = None,
) -> StripeReconciliationResult:
    """Convert one retained live-history artifact into strict reconciliation evidence."""
    history = load_stripe_history(history_path)
    prior_snapshot = _load_prior_snapshot(prior_ledger)
    effective_ref = (
        f"rec_{secrets.token_hex(16)}"
        if reconciliation_ref is None
        else _reconciliation_ref(reconciliation_ref)
    )
    effective_time = (
        datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        if reconciled_at is None
        else reconciled_at
    )
    document: dict[str, object] = {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "reconciliation_ref": effective_ref,
        "reconciled_at": effective_time,
        "scope": RECONCILIATION_SCOPE,
        "checks": {
            "all_known_ledgers_reviewed": True,
            "payment_provider_history_reviewed": True,
            "single_authoritative_successor_designated": True,
        },
        "payment_provider": {
            "provider": EXPECTED_PROVIDER,
            "mode": EXPECTED_PROVIDER_MODE,
            "observed_at": history.observed_at,
            "history_scope": PROVIDER_HISTORY_SCOPE,
            "history_evidence_sha256": history.exact_file_sha256,
            "provider_purchase_sha256s": list(history.provider_purchase_sha256s),
        },
        "prior_ledger": None if prior_snapshot is None else prior_snapshot.to_dict(),
        "lifetime_consumed_slots": history.purchase_count,
    }
    reconciliation_bytes = (_canonical_json(document) + "\n").encode("utf-8")
    try:
        reconciliation = build_pilot_slot_reconciliation(
            document,
            expected_prior_ledger=prior_snapshot,
            evidence_bytes=reconciliation_bytes,
        )
    except PilotReconciliationError as exc:
        raise StripeReconciliationError(f"reconciliation was rejected: {exc}") from None
    normalized_path = _write_owner_private_create_only(output_path, reconciliation_bytes)
    return StripeReconciliationResult(
        reconciliation=reconciliation,
        history_file_sha256=history.exact_file_sha256,
        output_path=normalized_path,
    )


def _validate_history_document(document: Mapping[str, object]) -> None:
    _validate_no_sensitive_values(document)
    _exact_string(
        document["schema_version"],
        STRIPE_HISTORY_SCHEMA_VERSION,
        "Stripe history schema",
    )
    _exact_string(document["provider"], EXPECTED_PROVIDER, "provider")
    _exact_string(document["mode"], EXPECTED_PROVIDER_MODE, "mode")
    if document["livemode"] is not True:
        raise StripeReconciliationError("Stripe history must be live mode")
    _utc_timestamp(document["observed_at"], "observed_at")

    offer = _mapping(document["offer"], _OFFER_FIELDS, "offer")
    _exact_string(offer["name"], OFFER_NAME, "offer name")
    _exact_string(offer["currency"], OFFER_CURRENCY, "offer currency")
    _exact_int(offer["amount_cents"], OFFER_AMOUNT_CENTS, "offer amount")
    _exact_string(offer["payment_type"], "ONE_TIME", "offer payment type")
    _exact_int(offer["slot_limit"], FOUNDING_PURCHASE_LIMIT, "offer slot limit")
    if MAX_PAID_PURCHASES != FOUNDING_PURCHASE_LIMIT:
        raise StripeReconciliationError("founding purchase limits disagree")

    coverage = _string_mapping(document["endpoint_coverage"], "endpoint_coverage")
    if not _REQUIRED_COVERAGE <= set(coverage):
        raise StripeReconciliationError("Stripe endpoint coverage is incomplete")
    for endpoint, raw_entry in coverage.items():
        entry = _mapping(raw_entry, _COVERAGE_FIELDS, f"coverage for {endpoint}")
        requests = _nonnegative_int(entry["requests"], "coverage requests")
        pages = _nonnegative_int(entry["pages"], "coverage pages")
        _nonnegative_int(entry["objects"], "coverage objects")
        if requests == 0 or endpoint != "account" and pages == 0:
            raise StripeReconciliationError("Stripe endpoint coverage was not executed")
        if entry["pagination_complete"] is not True:
            raise StripeReconciliationError("Stripe endpoint pagination is incomplete")

    account_controls = _string_mapping(document["account_controls"], "account_controls")
    if not account_controls or any(type(value) is not bool for value in account_controls.values()):
        raise StripeReconciliationError("Stripe account controls must be boolean aggregates")

    aggregates = _mapping(document["aggregates"], _AGGREGATE_FIELDS, "aggregates")
    aggregate_values = {
        field: _nonnegative_int(aggregates[field], field) for field in _AGGREGATE_FIELDS
    }
    if (
        aggregate_values["checkout_sessions_scanned"] > 0
        and "checkout_session_line_items" not in coverage
    ):
        raise StripeReconciliationError("Checkout Session line-item coverage is incomplete")

    purchases = _sequence(document["purchases"], "purchases")
    record_digests = tuple(
        _sha256(value, "purchase record digest")
        for value in _sequence(document["purchase_record_sha256"], "purchase_record_sha256")
    )
    provider_digests = tuple(
        _sha256(value, "provider purchase digest")
        for value in _sequence(
            document["provider_purchase_sha256s"],
            "provider_purchase_sha256s",
        )
    )
    purchase_count = aggregate_values["paid_founding_purchases"]
    if not 0 <= purchase_count <= FOUNDING_PURCHASE_LIMIT:
        raise StripeReconciliationError("paid founding purchase count exceeds the slot limit")
    if not len(purchases) == len(record_digests) == len(provider_digests) == purchase_count:
        raise StripeReconciliationError("Stripe purchase arrays and aggregate count disagree")
    if len(set(record_digests)) != len(record_digests):
        raise StripeReconciliationError("purchase record digests must be unique")
    if len(set(provider_digests)) != len(provider_digests):
        raise StripeReconciliationError("provider purchase digests must be unique")

    gross_total = 0
    tax_total = 0
    refunded_total = 0
    for index, raw_purchase in enumerate(purchases):
        purchase = _mapping(raw_purchase, _PURCHASE_FIELDS, "purchase")
        _utc_timestamp(purchase["captured_at"], "purchase captured_at")
        _exact_string(purchase["currency"], OFFER_CURRENCY, "purchase currency")
        _exact_int(purchase["amount_cents"], OFFER_AMOUNT_CENTS, "purchase amount")
        _exact_string(purchase["status"], "PAID", "purchase status")
        provider_digest = _sha256(
            purchase["provider_purchase_sha256"],
            "purchase provider digest",
        )
        if not hmac.compare_digest(provider_digest, provider_digests[index]):
            raise StripeReconciliationError("purchase provider digest and top-level list disagree")
        expected_record_digest = hashlib.sha256(
            _canonical_json(purchase).encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(expected_record_digest, record_digests[index]):
            raise StripeReconciliationError("purchase record digest does not match")

        gross = _nonnegative_int(purchase["gross_amount_cents"], "gross amount")
        tax = _nonnegative_int(purchase["tax_amount_cents"], "tax amount")
        refunded = _nonnegative_int(purchase["refunded_amount_cents"], "refunded amount")
        if gross != OFFER_AMOUNT_CENTS + tax or refunded > gross:
            raise StripeReconciliationError("purchase amounts are inconsistent")
        refund_attempts = _nonnegative_int(
            purchase["refund_attempt_count"],
            "refund attempt count",
        )
        successful_refunds = _nonnegative_int(
            purchase["successful_refund_count"],
            "successful refund count",
        )
        dispute_count = _nonnegative_int(purchase["dispute_count"], "dispute count")
        if successful_refunds > refund_attempts:
            raise StripeReconciliationError("purchase refund counts are inconsistent")
        if type(purchase["fully_refunded"]) is not bool:
            raise StripeReconciliationError("fully_refunded must be a boolean")
        if purchase["fully_refunded"] is not (refunded == gross):
            raise StripeReconciliationError("purchase refund state is inconsistent")
        if type(purchase["has_open_dispute"]) is not bool:
            raise StripeReconciliationError("has_open_dispute must be a boolean")

        references = _mapping(
            purchase["provider_reference_sha256"],
            _PROVIDER_REFERENCE_FIELDS,
            "provider reference digests",
        )
        for reference_name in ("checkout_session", "payment_intent", "charge"):
            _sha256(references[reference_name], f"{reference_name} digest")
        refund_references = tuple(
            _sha256(value, "refund reference digest")
            for value in _sequence(references["refunds"], "refund reference digests")
        )
        dispute_references = tuple(
            _sha256(value, "dispute reference digest")
            for value in _sequence(references["disputes"], "dispute reference digests")
        )
        if len(set(refund_references)) != len(refund_references):
            raise StripeReconciliationError("refund reference digests must be unique")
        if len(set(dispute_references)) != len(dispute_references):
            raise StripeReconciliationError("dispute reference digests must be unique")
        if len(refund_references) != refund_attempts or len(dispute_references) != dispute_count:
            raise StripeReconciliationError("purchase provider-reference counts disagree")

        gross_total += gross
        tax_total += tax
        refunded_total += refunded

    if aggregate_values["gross_paid_amount_cents"] != gross_total:
        raise StripeReconciliationError("gross purchase aggregate is inconsistent")
    if aggregate_values["tax_collected_amount_cents"] != tax_total:
        raise StripeReconciliationError("tax purchase aggregate is inconsistent")
    if aggregate_values["successful_refunded_amount_cents"] != refunded_total:
        raise StripeReconciliationError("refund purchase aggregate is inconsistent")


def _load_prior_snapshot(path: str | Path | None) -> PriorPilotLedgerSnapshot | None:
    if path is None:
        return None
    try:
        return PilotLedger.prior_ledger_snapshot(path)
    except (PilotLedgerError, PilotValidationError, OSError, TypeError, ValueError) as exc:
        raise StripeReconciliationError(f"prior ledger was rejected: {exc}") from None


def _read_owner_private_file(path: str | Path, *, label: str) -> tuple[Path, bytes]:
    normalized = _normalized_path(path, label)
    _reject_symlink_ancestors(normalized, label)
    parent_descriptor, parent_before = _open_owner_private_directory(normalized.parent, label)
    descriptor = -1
    try:
        try:
            before = os.stat(normalized.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError:
            raise StripeReconciliationError(f"{label} file is unavailable") from None
        _require_owner_private_file_metadata(before, label)
        if before.st_size > MAX_HISTORY_BYTES:
            raise StripeReconciliationError(f"{label} exceeds the size limit")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(normalized.name, flags, dir_fd=parent_descriptor)
        except OSError:
            raise StripeReconciliationError(f"{label} file cannot be opened securely") from None
        opened = os.fstat(descriptor)
        _require_owner_private_file_metadata(opened, label)
        if _file_snapshot(before) != _file_snapshot(opened):
            raise StripeReconciliationError(f"{label} file changed while opening")
        data = _read_bounded(descriptor, label)
        after = os.fstat(descriptor)
        try:
            current = os.stat(normalized.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError:
            current = None
        if (
            current is None
            or _file_snapshot(opened) != _file_snapshot(after)
            or _file_snapshot(after) != _file_snapshot(current)
            or len(data) != after.st_size
        ):
            raise StripeReconciliationError(f"{label} file changed while reading")
        _require_directory_still_current(normalized.parent, parent_before, label)
        return normalized, data
    except StripeReconciliationError:
        raise
    except OSError:
        raise StripeReconciliationError(f"{label} file cannot be read securely") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _write_owner_private_create_only(path: str | Path, data: bytes) -> Path:
    normalized = _normalized_path(path, "reconciliation output")
    _reject_symlink_ancestors(normalized, "reconciliation output")
    parent_descriptor, parent_before = _open_owner_private_directory(
        normalized.parent,
        "reconciliation output",
    )
    temporary_name = f".{normalized.name}.{secrets.token_hex(16)}.tmp"
    temporary_descriptor = -1
    published_identity: tuple[int, int] | None = None
    try:
        try:
            os.stat(normalized.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            raise StripeReconciliationError("reconciliation output is unavailable") from None
        else:
            raise StripeReconciliationError("reconciliation output already exists")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        temporary_descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(temporary_descriptor, 0o600)
        _write_all(temporary_descriptor, data)
        os.fsync(temporary_descriptor)
        temporary_metadata = os.fstat(temporary_descriptor)
        _require_owner_private_file_metadata(temporary_metadata, "temporary reconciliation")
        _require_directory_still_current(
            normalized.parent,
            parent_before,
            "reconciliation output",
        )
        os.link(
            temporary_name,
            normalized.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published_identity = (temporary_metadata.st_dev, temporary_metadata.st_ino)
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        temporary_name = ""
        os.fsync(parent_descriptor)
        current = os.stat(normalized.name, dir_fd=parent_descriptor, follow_symlinks=False)
        _require_owner_private_file_metadata(current, "reconciliation output")
        if (current.st_dev, current.st_ino) != published_identity:
            raise StripeReconciliationError("reconciliation output identity is unstable")
        _require_directory_still_current(
            normalized.parent,
            parent_before,
            "reconciliation output",
        )
        return normalized
    except StripeReconciliationError:
        _unlink_published_file(parent_descriptor, normalized.name, published_identity)
        raise
    except FileExistsError:
        raise StripeReconciliationError("reconciliation output already exists") from None
    except OSError:
        _unlink_published_file(parent_descriptor, normalized.name, published_identity)
        raise StripeReconciliationError("reconciliation output could not be written") from None
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        os.close(parent_descriptor)


def _unlink_published_file(
    parent_descriptor: int,
    name: str,
    identity: tuple[int, int] | None,
) -> None:
    if identity is None:
        return
    try:
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
            os.unlink(name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
    except OSError:
        pass


def _open_owner_private_directory(
    path: Path,
    label: str,
) -> tuple[int, os.stat_result]:
    try:
        before = os.lstat(path)
    except OSError:
        raise StripeReconciliationError(f"{label} parent directory is unavailable") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise StripeReconciliationError(f"{label} parent must be a real directory")
    if stat.S_IMODE(before.st_mode) != 0o700:
        raise StripeReconciliationError(f"{label} parent directory must use mode 0700")
    _require_owner(before, f"{label} parent directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise StripeReconciliationError(f"{label} parent cannot be opened securely") from None
    try:
        opened = os.fstat(descriptor)
        if _file_snapshot(before) != _file_snapshot(opened):
            raise StripeReconciliationError(f"{label} parent changed while opening")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, before


def _require_directory_still_current(
    path: Path,
    expected: os.stat_result,
    label: str,
) -> None:
    try:
        current = os.lstat(path)
    except OSError:
        raise StripeReconciliationError(f"{label} parent changed during the operation") from None
    if _directory_identity(current) != _directory_identity(expected):
        raise StripeReconciliationError(f"{label} parent changed during the operation")


def _require_owner_private_file_metadata(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise StripeReconciliationError(f"{label} must be a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise StripeReconciliationError(f"{label} must use mode 0600")
    _require_owner(metadata, label)


def _require_owner(metadata: os.stat_result, label: str) -> None:
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise StripeReconciliationError(f"{label} must be owned by the current user")


def _reject_symlink_ancestors(path: Path, label: str) -> None:
    for ancestor in reversed(path.parents):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise StripeReconciliationError(f"{label} path must not traverse symbolic links")
        if not stat.S_ISDIR(metadata.st_mode):
            raise StripeReconciliationError(f"{label} path ancestors must be directories")


def _normalized_path(path: str | Path, label: str) -> Path:
    try:
        normalized = Path(path).absolute()
    except (OSError, TypeError, ValueError):
        raise StripeReconciliationError(f"{label} path is invalid") from None
    if normalized.name in {"", ".", ".."}:
        raise StripeReconciliationError(f"{label} path is invalid")
    return normalized


def _read_bounded(descriptor: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65_536, MAX_HISTORY_BYTES + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_HISTORY_BYTES:
            raise StripeReconciliationError(f"{label} exceeds the size limit")


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("write did not advance")
        offset += written


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    )


def _mapping(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise StripeReconciliationError(f"{label} must be an object")
    result = cast(Mapping[str, object], value)
    if set(result) != set(fields):
        raise StripeReconciliationError(f"{label} has missing or unknown fields")
    return result


def _string_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise StripeReconciliationError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise StripeReconciliationError(f"{label} must be an array")
    return cast(Sequence[object], value)


def _exact_string(value: object, expected: str, label: str) -> str:
    if not isinstance(value, str) or not hmac.compare_digest(value, expected):
        raise StripeReconciliationError(f"{label} is not supported")
    return value


def _exact_int(value: object, expected: int, label: str) -> int:
    if type(value) is not int or value != expected:
        raise StripeReconciliationError(f"{label} is not supported")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise StripeReconciliationError(f"{label} must be a nonnegative integer")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StripeReconciliationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _reconciliation_ref(value: object) -> str:
    if not isinstance(value, str) or _RECONCILIATION_REF_RE.fullmatch(value) is None:
        raise StripeReconciliationError("reconciliation reference is invalid")
    return value


def _utc_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise StripeReconciliationError(f"{label} must be normalized UTC time")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise StripeReconciliationError(f"{label} must be normalized UTC time") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StripeReconciliationError(f"{label} must be normalized UTC time")
    normalized = parsed.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if normalized != value:
        raise StripeReconciliationError(f"{label} must be normalized UTC time")
    return value


def _validate_no_sensitive_values(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise StripeReconciliationError("Stripe history has an invalid field name")
            _reject_sensitive_key(key)
            _validate_no_sensitive_values(child)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _validate_no_sensitive_values(child)
        return
    if isinstance(value, str):
        _reject_sensitive_string(value)


def _reject_sensitive_string(value: str) -> None:
    if (
        _EMAIL_RE.search(value)
        or _URL_RE.search(value)
        or _SECRET_RE.search(value)
        or _RAW_PROVIDER_REFERENCE_RE.search(value)
    ):
        raise StripeReconciliationError("Stripe history contains forbidden sensitive data")


def _reject_sensitive_key(value: str) -> None:
    if _EMAIL_RE.search(value) or _URL_RE.search(value) or _SECRET_RE.search(value):
        raise StripeReconciliationError("Stripe history contains forbidden sensitive data")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StripeReconciliationError("Stripe history contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> NoReturn:
    del value
    raise StripeReconciliationError("Stripe history contains a non-JSON number")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert one sanitized Stripe live-history capture into strict pilot-slot "
            "reconciliation evidence."
        )
    )
    parser.add_argument("--history", required=True, help="owner-private Stripe history JSON")
    parser.add_argument("--output", required=True, help="new owner-private reconciliation JSON")
    parser.add_argument("--prior-ledger", help="optional verified prior pilot ledger")
    parser.add_argument("--reconciliation-ref", help="optional rec_ opaque reference")
    parser.add_argument("--reconciled-at", help="optional normalized UTC timestamp")
    args = parser.parse_args(argv)
    try:
        result = create_stripe_reconciliation(
            args.history,
            args.output,
            prior_ledger=args.prior_ledger,
            reconciliation_ref=args.reconciliation_ref,
            reconciled_at=args.reconciled_at,
        )
    except StripeReconciliationError as exc:
        print(f"Stripe reconciliation rejected: {exc}", file=sys.stderr)
        return 2
    reconciliation = result.reconciliation
    print(
        json.dumps(
            {
                "history_file_sha256": result.history_file_sha256,
                "lifetime_consumed_slots": reconciliation.lifetime_consumed_slots,
                "observed_at": reconciliation.payment_provider.observed_at,
                "output": str(result.output_path),
                "reconciled_at": reconciliation.reconciled_at,
                "reconciliation_ref": reconciliation.reconciliation_ref,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
