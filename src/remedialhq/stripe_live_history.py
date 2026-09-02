from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, overload
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SCHEMA_VERSION = "remedialhq.stripe-live-founding-history.v1"
OFFER_NAME = "Creator Signal Desk Founding Pilot"
OFFER_CURRENCY = "USD"
OFFER_AMOUNT_CENTS = 9_900
MAX_PAID_PURCHASES = 5
MAX_LIST_PAGES = 10_000
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
STRIPE_API_ORIGIN = "https://api.stripe.com"

_RAW_STRIPE_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:acct_|ch_|cs_(?:live|test)_|cus_|dp_|in_|li_|pi_|plink_|"
    r"pm_|price_|prod_|re_|seti_|src_|sub_)[A-Za-z0-9_]+",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}\b")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_URL_RE = re.compile(r"(?:https?://|www\.)", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class StripeLiveHistoryError(RuntimeError):
    """Raised when a Stripe history capture cannot produce safe, consistent evidence."""


class StripeTransport(Protocol):
    """Minimal read-only transport used by the deterministic collector."""

    def get(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]: ...


class StripeAPITransport:
    """Read-only Stripe v1 transport that keeps the live secret out of output."""

    __slots__ = ("_secret", "_timeout_seconds")

    def __init__(self, secret: str, *, timeout_seconds: float = 30.0) -> None:
        if not _is_live_secret(secret):
            raise StripeLiveHistoryError("STRIPE_SECRET_KEY must be a live secret key")
        if timeout_seconds <= 0:
            raise StripeLiveHistoryError("Stripe request timeout must be positive")
        self._secret = secret
        self._timeout_seconds = timeout_seconds

    def __repr__(self) -> str:
        return "StripeAPITransport(secret=<redacted>)"

    def get(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        if not path.startswith("/v1/") or "://" in path:
            raise StripeLiveHistoryError("Stripe endpoint is not an allowed v1 path")
        query = urlencode(sorted(params.items()))
        target = f"{STRIPE_API_ORIGIN}{path}"
        if query:
            target = f"{target}?{query}"
        request = Request(
            target,
            method="GET",
            headers={
                "Authorization": f"Bearer {self._secret}",
                "Accept": "application/json",
                "User-Agent": "ReMediaLHQ-Stripe-History/1",
            },
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            status_code = exc.code
            exc.close()
            raise StripeLiveHistoryError(
                f"Stripe API request failed with HTTP status {status_code}"
            ) from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise StripeLiveHistoryError("Stripe API request failed") from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise StripeLiveHistoryError("Stripe API response exceeded the safety limit")
        try:
            decoded = json.loads(body.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, StripeLiveHistoryError):
            raise StripeLiveHistoryError("Stripe API returned invalid JSON") from None
        if not isinstance(decoded, Mapping):
            raise StripeLiveHistoryError("Stripe API returned an invalid object")
        return decoded


@dataclass(slots=True)
class _Coverage:
    requests: int = 0
    pages: int = 0
    objects: int = 0
    pagination_complete: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "requests": self.requests,
            "pages": self.pages,
            "objects": self.objects,
            "pagination_complete": self.pagination_complete,
        }


@dataclass(frozen=True, slots=True)
class StripeLiveHistoryEvidence:
    """A canonical, privacy-minimized Stripe history evidence document."""

    document: Mapping[str, object]

    def canonical_json(self) -> str:
        return _canonical_json(self.document) + "\n"

    @property
    def history_evidence_sha256(self) -> str:
        value = self.document.get("history_evidence_sha256")
        if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
            raise StripeLiveHistoryError("history evidence digest is invalid")
        return value


class StripeLiveHistoryCollector:
    """Collect all relevant Stripe lists and emit only sanitized aggregates and digests."""

    def __init__(
        self,
        transport: StripeTransport,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))
        self._coverage: dict[str, _Coverage] = {}

    def collect(self) -> StripeLiveHistoryEvidence:
        self._coverage = {}
        observed_at, history_cutoff = _observation_cutoff(self._clock())
        account = self._get_object("account", "/v1/account")
        account_controls = _account_control_booleans(account)

        products = self._list_all("products", "/v1/products")
        prices = self._list_all("prices", "/v1/prices")
        payment_links = self._list_all("payment_links", "/v1/payment_links")
        sessions = self._list_all(
            "checkout_sessions",
            "/v1/checkout/sessions",
            created_lte=history_cutoff,
        )
        payment_intents = self._list_all(
            "payment_intents",
            "/v1/payment_intents",
            created_lte=history_cutoff,
        )
        charges = self._list_all(
            "charges",
            "/v1/charges",
            created_lte=history_cutoff,
        )
        refunds = self._list_all(
            "refunds",
            "/v1/refunds",
            created_lte=history_cutoff,
        )
        disputes = self._list_all(
            "disputes",
            "/v1/disputes",
            created_lte=history_cutoff,
        )

        for objects, label in (
            (products, "products"),
            (prices, "prices"),
            (payment_links, "payment links"),
            (sessions, "Checkout Sessions"),
            (payment_intents, "PaymentIntents"),
            (charges, "charges"),
            (disputes, "disputes"),
        ):
            _require_live_objects(objects, label)
        _reject_explicit_test_objects(refunds, "refunds")

        _product_id, price_id = _resolve_exact_offer(products, prices)
        matching_link_ids: set[str] = set()
        active_matching_links = 0
        payment_link_line_item_count = 0
        for payment_link in payment_links:
            link_id = _object_id(payment_link, "payment link")
            line_items = self._list_all(
                "payment_link_line_items",
                f"/v1/payment_links/{link_id}/line_items",
            )
            payment_link_line_item_count += len(line_items)
            uses_offer = _line_items_use_offer(
                line_items,
                price_id=price_id,
                context="payment link",
            )
            if not uses_offer:
                continue
            currency = payment_link.get("currency")
            if currency is not None and currency != "usd":
                raise StripeLiveHistoryError("exact offer uses an unsupported currency")
            matching_link_ids.add(link_id)
            if _strict_bool(payment_link.get("active"), "payment link active state"):
                active_matching_links += 1
        if not matching_link_ids:
            raise StripeLiveHistoryError("exact founding offer has no Payment Link")

        matching_sessions: list[Mapping[str, object]] = []
        abandoned_sessions = 0
        checkout_line_item_count = 0
        for session in sessions:
            session_id = _object_id(session, "Checkout Session")
            line_items = self._list_all(
                "checkout_session_line_items",
                f"/v1/checkout/sessions/{session_id}/line_items",
            )
            checkout_line_item_count += len(line_items)
            uses_offer = _line_items_use_offer(
                line_items,
                price_id=price_id,
                context="Checkout Session",
            )
            if not uses_offer:
                continue
            _validate_offer_session(session, matching_link_ids)
            matching_sessions.append(session)
            if session.get("payment_status") == "unpaid":
                abandoned_sessions += 1

        pi_by_id = _index_by_id(payment_intents, "PaymentIntent")
        charges_by_payment_intent = _group_charges(charges, pi_by_id)
        refunds_by_charge = _group_refunds(refunds, charges)
        disputes_by_charge = _group_disputes(disputes, charges)

        paid_sessions = [
            session for session in matching_sessions if session.get("payment_status") == "paid"
        ]
        if len(paid_sessions) > MAX_PAID_PURCHASES:
            raise StripeLiveHistoryError("paid founding purchases exceed the five-slot limit")

        purchases: list[dict[str, object]] = []
        for session in paid_sessions:
            purchases.append(
                _build_purchase_record(
                    session,
                    pi_by_id=pi_by_id,
                    charges_by_payment_intent=charges_by_payment_intent,
                    refunds_by_charge=refunds_by_charge,
                    disputes_by_charge=disputes_by_charge,
                )
            )
        purchases.sort(
            key=lambda item: (
                str(item["captured_at"]),
                str(item["provider_reference_sha256"]["checkout_session"]),  # type: ignore[index]
            )
        )
        purchase_record_digests = [_sha256_json(record) for record in purchases]
        provider_purchase_digests = [
            _record_sha256(record, "provider_purchase_sha256") for record in purchases
        ]
        gross_paid_amount = sum(
            _record_nonnegative_amount(record, "gross_amount_cents") for record in purchases
        )
        tax_collected_amount = sum(
            _record_nonnegative_amount(record, "tax_amount_cents") for record in purchases
        )
        refunded_amount = sum(
            _record_nonnegative_amount(record, "refunded_amount_cents") for record in purchases
        )

        body: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "provider": "STRIPE",
            "mode": "LIVE",
            "livemode": True,
            "observed_at": observed_at,
            "offer": {
                "name": OFFER_NAME,
                "currency": OFFER_CURRENCY,
                "amount_cents": OFFER_AMOUNT_CENTS,
                "payment_type": "ONE_TIME",
                "slot_limit": MAX_PAID_PURCHASES,
            },
            "endpoint_coverage": {
                label: coverage.to_dict()
                for label, coverage in sorted(self._coverage.items())
            },
            "account_controls": account_controls,
            "aggregates": {
                "products_scanned": len(products),
                "prices_scanned": len(prices),
                "payment_links_scanned": len(payment_links),
                "payment_link_line_items_scanned": payment_link_line_item_count,
                "matching_payment_links": len(matching_link_ids),
                "active_matching_payment_links": active_matching_links,
                "checkout_sessions_scanned": len(sessions),
                "checkout_session_line_items_scanned": checkout_line_item_count,
                "matching_checkout_sessions": len(matching_sessions),
                "abandoned_matching_checkout_sessions": abandoned_sessions,
                "paid_founding_purchases": len(purchases),
                "gross_paid_amount_cents": gross_paid_amount,
                "tax_collected_amount_cents": tax_collected_amount,
                "successful_refunded_amount_cents": refunded_amount,
            },
            "purchases": purchases,
            "purchase_record_sha256": purchase_record_digests,
            "provider_purchase_sha256s": provider_purchase_digests,
        }
        _validate_sanitized_document(body)
        body["history_evidence_sha256"] = _sha256_json(body)
        _validate_sanitized_document(body)
        return StripeLiveHistoryEvidence(document=body)

    def _get_object(self, label: str, path: str) -> Mapping[str, object]:
        coverage = self._coverage.setdefault(label, _Coverage())
        coverage.requests += 1
        try:
            response = self._transport.get(path, {})
        except StripeLiveHistoryError:
            raise
        except Exception:  # noqa: BLE001 - transport details must never escape into output
            raise StripeLiveHistoryError("Stripe transport failed") from None
        if not isinstance(response, Mapping):
            raise StripeLiveHistoryError("Stripe API returned an invalid object")
        coverage.objects += 1
        return response

    def _list_all(
        self,
        label: str,
        path: str,
        *,
        created_lte: int | None = None,
    ) -> list[Mapping[str, object]]:
        coverage = self._coverage.setdefault(label, _Coverage())
        results: list[Mapping[str, object]] = []
        seen_ids: set[str] = set()
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            params = {"limit": "100"}
            if created_lte is not None:
                params["created[lte]"] = str(created_lte)
            if cursor is not None:
                params["starting_after"] = cursor
            coverage.requests += 1
            coverage.pages += 1
            try:
                response = self._transport.get(path, params)
            except StripeLiveHistoryError:
                raise
            except Exception:  # noqa: BLE001 - transport details must never escape into output
                raise StripeLiveHistoryError("Stripe transport failed") from None
            if not isinstance(response, Mapping) or response.get("object") != "list":
                raise StripeLiveHistoryError("Stripe list endpoint returned an invalid envelope")
            data = response.get("data")
            has_more = response.get("has_more")
            if not isinstance(data, list) or type(has_more) is not bool:
                raise StripeLiveHistoryError("Stripe list endpoint returned invalid pagination")
            if has_more and not data:
                coverage.pagination_complete = False
                raise StripeLiveHistoryError("Stripe pagination stopped without a cursor")
            for item in data:
                if not isinstance(item, Mapping):
                    raise StripeLiveHistoryError("Stripe list endpoint returned an invalid item")
                item_id = _object_id(item, "Stripe list item")
                if item_id in seen_ids:
                    coverage.pagination_complete = False
                    raise StripeLiveHistoryError("Stripe pagination returned a duplicate object")
                seen_ids.add(item_id)
                if created_lte is not None:
                    created = item.get("created")
                    if type(created) is not int or created > created_lte:
                        coverage.pagination_complete = False
                        raise StripeLiveHistoryError(
                            "Stripe history item falls outside the requested cutoff"
                        )
                results.append(item)
            coverage.objects += len(data)
            if not has_more:
                return results
            next_cursor = _object_id(data[-1], "Stripe pagination cursor")
            if next_cursor == cursor:
                coverage.pagination_complete = False
                raise StripeLiveHistoryError("Stripe pagination did not advance")
            cursor = next_cursor
        coverage.pagination_complete = False
        raise StripeLiveHistoryError("Stripe pagination exceeded the safety limit")


def load_live_secret_from_environment() -> str:
    """Load the Stripe key from the sole supported secret source."""
    value = os.environ.get("STRIPE_SECRET_KEY")
    if not isinstance(value, str) or not _is_live_secret(value):
        raise StripeLiveHistoryError("STRIPE_SECRET_KEY must be a live secret key")
    return value


def capture_live_history(
    output_path: str | Path,
    *,
    transport: StripeTransport | None = None,
    clock: Callable[[], datetime] | None = None,
) -> StripeLiveHistoryEvidence:
    """Collect live history and atomically write one owner-only evidence file."""
    active_transport = transport
    if active_transport is None:
        active_transport = StripeAPITransport(load_live_secret_from_environment())
    evidence = StripeLiveHistoryCollector(active_transport, clock=clock).collect()
    write_private_evidence(output_path, evidence)
    return evidence


def write_private_evidence(
    output_path: str | Path,
    evidence: StripeLiveHistoryEvidence,
) -> None:
    """Atomically write canonical JSON with a 0700 parent and 0600 file."""
    path = Path(output_path).absolute()
    _reject_symbolic_link_ancestors(path)
    parent = path.parent
    _prepare_private_parent(parent)
    _validate_existing_output(path)
    encoded = evidence.canonical_json().encode("utf-8")
    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if stat.S_IMODE(os.lstat(temporary_path).st_mode) != 0o600:
            raise StripeLiveHistoryError("temporary evidence file mode is insecure")
        os.replace(temporary_path, path)
        temporary_path = None
        if stat.S_IMODE(os.lstat(path).st_mode) != 0o600:
            raise StripeLiveHistoryError("evidence file mode is insecure")
        directory_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except StripeLiveHistoryError:
        raise
    except OSError:
        raise StripeLiveHistoryError("private evidence file could not be written") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _prepare_private_parent(parent: Path) -> None:
    if not parent.exists():
        if not parent.parent.is_dir():
            raise StripeLiveHistoryError("private evidence parent is unavailable")
        try:
            parent.mkdir(mode=0o700)
            parent.chmod(0o700)
        except OSError:
            raise StripeLiveHistoryError("private evidence parent could not be created") from None
    try:
        metadata = os.lstat(parent)
    except OSError:
        raise StripeLiveHistoryError("private evidence parent is unavailable") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise StripeLiveHistoryError("private evidence parent must be a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise StripeLiveHistoryError("private evidence parent mode is insecure")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise StripeLiveHistoryError("private evidence parent ownership is insecure")


def _reject_symbolic_link_ancestors(path: Path) -> None:
    for ancestor in reversed(path.parents):
        try:
            metadata = os.lstat(ancestor)
        except FileNotFoundError:
            continue
        except OSError:
            raise StripeLiveHistoryError("private evidence path is unavailable") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise StripeLiveHistoryError(
                "private evidence path must not use symbolic-link ancestors"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise StripeLiveHistoryError(
                "private evidence path ancestors must be directories"
            )


def _validate_existing_output(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        raise StripeLiveHistoryError("private evidence output is unavailable") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise StripeLiveHistoryError("private evidence output must be a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise StripeLiveHistoryError("existing evidence file mode is insecure")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise StripeLiveHistoryError("existing evidence file ownership is insecure")


def _resolve_exact_offer(
    products: Sequence[Mapping[str, object]],
    prices: Sequence[Mapping[str, object]],
) -> tuple[str, str]:
    matching_products = [product for product in products if product.get("name") == OFFER_NAME]
    if len(matching_products) != 1:
        raise StripeLiveHistoryError("exact founding offer product identity is ambiguous")
    product_id = _object_id(matching_products[0], "founding offer product")
    product_prices = [
        price for price in prices if _reference_id(price.get("product")) == product_id
    ]
    if not product_prices:
        raise StripeLiveHistoryError("exact founding offer has no Price")
    for price in product_prices:
        if (
            price.get("currency") != "usd"
            or price.get("unit_amount") != OFFER_AMOUNT_CENTS
            or price.get("type") != "one_time"
            or price.get("recurring") is not None
            or price.get("custom_unit_amount") is not None
        ):
            raise StripeLiveHistoryError(
                "exact founding offer uses an unsupported currency, amount, or payment type"
            )
    if len(product_prices) != 1:
        raise StripeLiveHistoryError("exact founding offer Price identity is ambiguous")
    return product_id, _object_id(product_prices[0], "founding offer Price")


def _line_items_use_offer(
    line_items: Sequence[Mapping[str, object]],
    *,
    price_id: str,
    context: str,
) -> bool:
    matching = [item for item in line_items if _reference_id(item.get("price")) == price_id]
    if not matching:
        return False
    if len(line_items) != 1 or len(matching) != 1:
        raise StripeLiveHistoryError(f"{context} has an ambiguous founding offer configuration")
    if matching[0].get("quantity") != 1:
        raise StripeLiveHistoryError(f"{context} has an unsupported founding offer quantity")
    return True


def _validate_offer_session(
    session: Mapping[str, object],
    matching_link_ids: set[str],
) -> None:
    if session.get("mode") != "payment":
        raise StripeLiveHistoryError("founding offer Checkout Session is not one-time payment mode")
    if session.get("currency") != "usd":
        raise StripeLiveHistoryError("founding offer Checkout Session uses an unsupported currency")
    _session_amounts(session)
    payment_link_id = _reference_id(session.get("payment_link"), allow_none=True)
    if payment_link_id is not None and payment_link_id not in matching_link_ids:
        raise StripeLiveHistoryError("Checkout Session and Payment Link offer identity disagree")
    payment_status = session.get("payment_status")
    if payment_status not in {"paid", "unpaid"}:
        raise StripeLiveHistoryError("founding offer Checkout Session has an unsupported status")
    status = session.get("status")
    if payment_status == "paid" and status != "complete":
        raise StripeLiveHistoryError("paid Checkout Session is not complete")
    if payment_status == "unpaid" and status not in {"open", "expired"}:
        raise StripeLiveHistoryError("unpaid Checkout Session has an unsupported status")


def _session_amounts(session: Mapping[str, object]) -> tuple[int, int]:
    subtotal = session.get("amount_subtotal")
    total = session.get("amount_total")
    if (
        type(subtotal) is not int
        or subtotal != OFFER_AMOUNT_CENTS
        or type(total) is not int
        or total < subtotal
    ):
        raise StripeLiveHistoryError("founding offer Checkout Session uses an unsupported amount")

    raw_details = session.get("total_details")
    if raw_details is None:
        if total != subtotal:
            raise StripeLiveHistoryError("Checkout Session tax total is not auditable")
        return total, 0
    if not isinstance(raw_details, Mapping):
        raise StripeLiveHistoryError("Checkout Session total details are invalid")
    tax_amount = _optional_nonnegative_amount(raw_details.get("amount_tax"), "tax")
    discount_amount = _optional_nonnegative_amount(
        raw_details.get("amount_discount"),
        "discount",
    )
    shipping_amount = _optional_nonnegative_amount(
        raw_details.get("amount_shipping"),
        "shipping",
    )
    if discount_amount != 0 or shipping_amount != 0:
        raise StripeLiveHistoryError(
            "founding offer Checkout Session has an unsupported discount or shipping amount"
        )
    if total != subtotal + tax_amount:
        raise StripeLiveHistoryError("Checkout Session subtotal, tax, and total disagree")
    return total, tax_amount


def _build_purchase_record(
    session: Mapping[str, object],
    *,
    pi_by_id: Mapping[str, Mapping[str, object]],
    charges_by_payment_intent: Mapping[str, Sequence[Mapping[str, object]]],
    refunds_by_charge: Mapping[str, Sequence[Mapping[str, object]]],
    disputes_by_charge: Mapping[str, Sequence[Mapping[str, object]]],
) -> dict[str, object]:
    session_id = _object_id(session, "paid Checkout Session")
    gross_amount, tax_amount = _session_amounts(session)
    payment_intent_id = _reference_id(session.get("payment_intent"))
    payment_intent = pi_by_id.get(payment_intent_id)
    if payment_intent is None:
        raise StripeLiveHistoryError("paid Checkout Session has no listed PaymentIntent")
    if (
        payment_intent.get("currency") != "usd"
        or payment_intent.get("amount") != gross_amount
        or payment_intent.get("amount_received") != gross_amount
        or payment_intent.get("status") != "succeeded"
    ):
        raise StripeLiveHistoryError("paid founding PaymentIntent is inconsistent")

    related_charges = list(charges_by_payment_intent.get(payment_intent_id, ()))
    successful_charges = [
        charge
        for charge in related_charges
        if charge.get("status") == "succeeded" and charge.get("paid") is True
    ]
    if len(successful_charges) != 1:
        raise StripeLiveHistoryError("paid founding PaymentIntent has ambiguous charge history")
    charge = successful_charges[0]
    charge_id = _object_id(charge, "paid founding charge")
    if (
        charge.get("currency") != "usd"
        or charge.get("amount") != gross_amount
        or charge.get("captured") is not True
    ):
        raise StripeLiveHistoryError("paid founding charge is inconsistent")
    latest_charge = _reference_id(payment_intent.get("latest_charge"))
    if latest_charge != charge_id:
        raise StripeLiveHistoryError("PaymentIntent and charge history disagree")

    refunds = list(refunds_by_charge.get(charge_id, ()))
    for refund in refunds:
        if refund.get("currency") != "usd":
            raise StripeLiveHistoryError("founding purchase refund currency is inconsistent")
    successful_refunds = [refund for refund in refunds if refund.get("status") == "succeeded"]
    refunded_amount = sum(_strict_positive_amount(item.get("amount"), "refund") for item in successful_refunds)
    if refunded_amount > gross_amount:
        raise StripeLiveHistoryError("founding purchase refund total exceeds the charge")
    if charge.get("amount_refunded") != refunded_amount:
        raise StripeLiveHistoryError("charge and refund history disagree")
    expected_refunded = refunded_amount == gross_amount
    if charge.get("refunded") is not expected_refunded:
        raise StripeLiveHistoryError("charge refunded state and refund history disagree")

    disputes = list(disputes_by_charge.get(charge_id, ()))
    allowed_dispute_statuses = {
        "warning_needs_response",
        "warning_under_review",
        "warning_closed",
        "needs_response",
        "under_review",
        "won",
        "lost",
        "prevented",
    }
    for dispute in disputes:
        amount = _strict_positive_amount(dispute.get("amount"), "dispute")
        if dispute.get("currency") != "usd" or amount > gross_amount:
            raise StripeLiveHistoryError("founding purchase dispute is inconsistent")
        if dispute.get("status") not in allowed_dispute_statuses:
            raise StripeLiveHistoryError("founding purchase dispute status is unsupported")
    open_dispute_statuses = {
        "warning_needs_response",
        "warning_under_review",
        "needs_response",
        "under_review",
    }

    refund_digests = sorted(
        _provider_reference_digest("refund", _object_id(refund, "refund"))
        for refund in refunds
    )
    dispute_digests = sorted(
        _provider_reference_digest("dispute", _object_id(dispute, "dispute"))
        for dispute in disputes
    )
    captured_at = _unix_timestamp(charge.get("created"), "charge creation time")
    immutable_provider_references = {
        "checkout_session": _provider_reference_digest("checkout_session", session_id),
        "payment_intent": _provider_reference_digest("payment_intent", payment_intent_id),
        "charge": _provider_reference_digest("charge", charge_id),
    }
    provider_purchase_sha256 = _sha256_json(
        {
            "schema_version": "remedialhq.stripe-provider-purchase.v1",
            "provider": "STRIPE",
            "mode": "LIVE",
            "livemode": True,
            "captured_at": captured_at,
            "currency": OFFER_CURRENCY,
            "base_amount_cents": OFFER_AMOUNT_CENTS,
            "gross_amount_cents": gross_amount,
            "tax_amount_cents": tax_amount,
            "provider_reference_sha256": immutable_provider_references,
        }
    )
    return {
        "captured_at": captured_at,
        "currency": OFFER_CURRENCY,
        "amount_cents": OFFER_AMOUNT_CENTS,
        "gross_amount_cents": gross_amount,
        "tax_amount_cents": tax_amount,
        "status": "PAID",
        "provider_purchase_sha256": provider_purchase_sha256,
        "refund_attempt_count": len(refunds),
        "successful_refund_count": len(successful_refunds),
        "refunded_amount_cents": refunded_amount,
        "fully_refunded": expected_refunded,
        "dispute_count": len(disputes),
        "has_open_dispute": any(
            dispute.get("status") in open_dispute_statuses for dispute in disputes
        ),
        "provider_reference_sha256": {
            **immutable_provider_references,
            "refunds": refund_digests,
            "disputes": dispute_digests,
        },
    }


def _account_control_booleans(account: Mapping[str, object]) -> dict[str, bool]:
    capabilities = account.get("capabilities")
    raw_requirements = account.get("requirements")
    settings = account.get("settings")
    business_profile = account.get("business_profile")
    if not isinstance(capabilities, Mapping):
        raise StripeLiveHistoryError("Stripe account controls are incomplete")
    assert isinstance(capabilities, Mapping)
    if raw_requirements is not None and not isinstance(raw_requirements, Mapping):
        raise StripeLiveHistoryError("Stripe account requirements controls are invalid")
    requirements = raw_requirements if isinstance(raw_requirements, Mapping) else None
    safe_settings = settings if isinstance(settings, Mapping) else {}
    raw_card_settings = safe_settings.get("card_payments")
    raw_payment_settings = safe_settings.get("payments")
    raw_payout_settings = safe_settings.get("payouts")
    card_settings = raw_card_settings if isinstance(raw_card_settings, Mapping) else {}
    payment_settings = raw_payment_settings if isinstance(raw_payment_settings, Mapping) else {}
    payout_settings = raw_payout_settings if isinstance(raw_payout_settings, Mapping) else {}
    if business_profile is not None and not isinstance(business_profile, Mapping):
        raise StripeLiveHistoryError("Stripe business profile controls are incomplete")
    profile = business_profile if isinstance(business_profile, Mapping) else {}
    return {
        "charges_enabled": _strict_bool(account.get("charges_enabled"), "charges enabled"),
        "payouts_enabled": _strict_bool(account.get("payouts_enabled"), "payouts enabled"),
        "details_submitted": _strict_bool(account.get("details_submitted"), "details submitted"),
        "card_payments_capability_active": capabilities.get("card_payments") == "active",
        "transfers_capability_active": capabilities.get("transfers") == "active",
        "requirements_exposed": requirements is not None,
        "currently_due_reported_empty": (
            requirements is not None and _list_is_empty(requirements.get("currently_due"))
        ),
        "eventually_due_reported_empty": (
            requirements is not None and _list_is_empty(requirements.get("eventually_due"))
        ),
        "past_due_reported_empty": (
            requirements is not None and _list_is_empty(requirements.get("past_due"))
        ),
        "disabled_reason_reported_absent": (
            requirements is not None
            and "disabled_reason" in requirements
            and requirements.get("disabled_reason") is None
        ),
        "payment_statement_descriptor_configured": (
            _is_nonblank_string(payment_settings.get("statement_descriptor"))
            or _is_nonblank_string(card_settings.get("statement_descriptor_prefix"))
        ),
        "payout_statement_descriptor_configured": _is_nonblank_string(
            payout_settings.get("statement_descriptor")
        ),
        "business_profile_configured": all(
            isinstance(profile.get(field), str) and bool(profile.get(field))
            for field in ("name", "support_email", "url")
        ),
    }


def _group_charges(
    charges: Sequence[Mapping[str, object]],
    payment_intents: Mapping[str, Mapping[str, object]],
) -> dict[str, list[Mapping[str, object]]]:
    grouped: dict[str, list[Mapping[str, object]]] = {}
    for charge in charges:
        payment_intent_id = _reference_id(charge.get("payment_intent"), allow_none=True)
        if payment_intent_id is None:
            continue
        if payment_intent_id not in payment_intents:
            raise StripeLiveHistoryError("charge references an unlisted PaymentIntent")
        grouped.setdefault(payment_intent_id, []).append(charge)
    return grouped


def _group_refunds(
    refunds: Sequence[Mapping[str, object]],
    charges: Sequence[Mapping[str, object]],
) -> dict[str, list[Mapping[str, object]]]:
    charges_by_id = {_object_id(charge, "charge"): charge for charge in charges}
    grouped: dict[str, list[Mapping[str, object]]] = {}
    allowed_statuses = {"pending", "requires_action", "succeeded", "failed", "canceled"}
    for refund in refunds:
        charge_id = _reference_id(refund.get("charge"))
        charge = charges_by_id.get(charge_id)
        if charge is None:
            raise StripeLiveHistoryError("refund references an unlisted charge")
        refund_payment_intent = _reference_id(
            refund.get("payment_intent"),
            allow_none=True,
        )
        charge_payment_intent = _reference_id(
            charge.get("payment_intent"),
            allow_none=True,
        )
        if (
            refund_payment_intent is not None
            and refund_payment_intent != charge_payment_intent
        ):
            raise StripeLiveHistoryError("refund and charge PaymentIntent history disagree")
        if refund.get("status") not in allowed_statuses:
            raise StripeLiveHistoryError("refund has an unsupported status")
        grouped.setdefault(charge_id, []).append(refund)
    return grouped


def _group_disputes(
    disputes: Sequence[Mapping[str, object]],
    charges: Sequence[Mapping[str, object]],
) -> dict[str, list[Mapping[str, object]]]:
    charges_by_id = {_object_id(charge, "charge"): charge for charge in charges}
    grouped: dict[str, list[Mapping[str, object]]] = {}
    for dispute in disputes:
        charge_id = _reference_id(dispute.get("charge"))
        charge = charges_by_id.get(charge_id)
        if charge is None:
            raise StripeLiveHistoryError("dispute references an unlisted charge")
        dispute_payment_intent = _reference_id(
            dispute.get("payment_intent"),
            allow_none=True,
        )
        charge_payment_intent = _reference_id(
            charge.get("payment_intent"),
            allow_none=True,
        )
        if (
            dispute_payment_intent is not None
            and dispute_payment_intent != charge_payment_intent
        ):
            raise StripeLiveHistoryError("dispute and charge PaymentIntent history disagree")
        grouped.setdefault(charge_id, []).append(dispute)
    return grouped


def _index_by_id(
    objects: Sequence[Mapping[str, object]],
    label: str,
) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for item in objects:
        item_id = _object_id(item, label)
        if item_id in result:
            raise StripeLiveHistoryError(f"{label} history contains duplicate objects")
        result[item_id] = item
    return result


def _get_livemode(value: Mapping[str, object]) -> bool | None:
    livemode = value.get("livemode")
    if livemode is None:
        return None
    if type(livemode) is not bool:
        raise StripeLiveHistoryError("Stripe object has an invalid livemode value")
    return livemode


def _require_live_objects(objects: Sequence[Mapping[str, object]], label: str) -> None:
    for item in objects:
        if _get_livemode(item) is not True:
            raise StripeLiveHistoryError(f"{label} include a non-live object")


def _reject_explicit_test_objects(objects: Sequence[Mapping[str, object]], label: str) -> None:
    for item in objects:
        if _get_livemode(item) is False:
            raise StripeLiveHistoryError(f"{label} include a non-live object")


def _object_id(value: Mapping[str, object], label: str) -> str:
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier or len(identifier) > 255:
        raise StripeLiveHistoryError(f"{label} has an invalid opaque reference")
    return identifier


@overload
def _reference_id(value: object, *, allow_none: Literal[False] = False) -> str: ...


@overload
def _reference_id(value: object, *, allow_none: Literal[True]) -> str | None: ...


def _reference_id(value: object, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if isinstance(value, str) and value and len(value) <= 255:
        return value
    if isinstance(value, Mapping):
        return _object_id(value, "expanded Stripe reference")
    raise StripeLiveHistoryError("Stripe object has an invalid opaque reference")


def _strict_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise StripeLiveHistoryError(f"{label} is not a boolean")
    return value


def _is_nonblank_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _list_is_empty(value: object) -> bool:
    return isinstance(value, list) and len(value) == 0


def _optional_nonnegative_amount(value: object, label: str) -> int:
    if value is None:
        return 0
    if type(value) is not int or value < 0:
        raise StripeLiveHistoryError(f"{label} amount is invalid")
    return value


def _strict_positive_amount(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise StripeLiveHistoryError(f"{label} amount is invalid")
    return value


def _record_nonnegative_amount(record: Mapping[str, object], field: str) -> int:
    value = record.get(field)
    if type(value) is not int or value < 0:
        raise StripeLiveHistoryError("sanitized purchase amount is invalid")
    return value


def _record_sha256(record: Mapping[str, object], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StripeLiveHistoryError("sanitized purchase digest is invalid")
    return value


def _provider_reference_digest(kind: str, value: str) -> str:
    return hashlib.sha256(f"stripe:{kind}:{value}".encode()).hexdigest()


def _unix_timestamp(value: object, label: str) -> str:
    if type(value) is not int or value <= 0:
        raise StripeLiveHistoryError(f"{label} is invalid")
    try:
        parsed = datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        raise StripeLiveHistoryError(f"{label} is invalid") from None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _observation_cutoff(value: datetime) -> tuple[str, int]:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise StripeLiveHistoryError("observation clock must return a timezone-aware datetime")
    normalized = value.astimezone(UTC).replace(microsecond=0)
    observed_at = normalized.isoformat(timespec="seconds").replace("+00:00", "Z")
    return observed_at, int(normalized.timestamp())


def _is_live_secret(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sk_live_")
        and len(value) >= len("sk_live_") + 8
        and value.strip() == value
        and all(character.isalnum() or character == "_" for character in value)
    )


def _validate_sanitized_document(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise StripeLiveHistoryError("evidence has an invalid field name")
            _validate_sanitized_document(item)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _validate_sanitized_document(item)
        return
    if isinstance(value, str) and (
        _RAW_STRIPE_REFERENCE_RE.search(value)
        or _SECRET_RE.search(value)
        or _EMAIL_RE.search(value)
        or _URL_RE.search(value)
    ):
        raise StripeLiveHistoryError("evidence contains forbidden sensitive data")


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


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
            raise StripeLiveHistoryError("Stripe API returned duplicate JSON fields")
        result[key] = value
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture sanitized live Stripe founding-pilot history evidence."
    )
    parser.add_argument(
        "--output",
        required=True,
        help="owner-private JSON evidence path; its parent must use mode 0700",
    )
    args = parser.parse_args(argv)
    try:
        evidence = capture_live_history(args.output)
    except StripeLiveHistoryError as exc:
        print(f"Stripe live history capture rejected: {exc}", file=sys.stderr)
        return 2
    purchase_count = len(evidence.document["purchases"])  # type: ignore[arg-type]
    print(f"Captured {purchase_count} sanitized live founding purchase record(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
