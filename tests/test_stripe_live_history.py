from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from remedialhq.stripe_live_history import (
    MAX_PAID_PURCHASES,
    StripeAPITransport,
    StripeLiveHistoryCollector,
    StripeLiveHistoryError,
    capture_live_history,
    load_live_secret_from_environment,
    main,
    write_private_evidence,
)

FIXED_NOW = datetime(2026, 8, 30, 14, 15, tzinfo=UTC)
LIVE_KEY = "sk" + "_live_" + "fixturevalue123456"


class FakeStripeTransport:
    def __init__(
        self,
        datasets: Mapping[str, list[dict[str, object]]],
        account: Mapping[str, object],
        *,
        page_size: int = 100,
    ) -> None:
        self.datasets = {path: [dict(item) for item in items] for path, items in datasets.items()}
        self.account = dict(account)
        self.page_size = page_size
        self.calls: list[tuple[str, dict[str, str]]] = []

    def get(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        self.calls.append((path, dict(params)))
        if path == "/v1/account":
            return dict(self.account)
        if path not in self.datasets:
            raise AssertionError("unexpected endpoint")
        objects = self.datasets[path]
        start = 0
        cursor = params.get("starting_after")
        if cursor is not None:
            identifiers = [str(item["id"]) for item in objects]
            start = identifiers.index(cursor) + 1
        page = objects[start : start + self.page_size]
        return {
            "object": "list",
            "data": [dict(item) for item in page],
            "has_more": start + len(page) < len(objects),
        }


def account_fixture() -> dict[str, object]:
    return {
        "id": "acct_live_owner",
        "object": "account",
        "charges_enabled": True,
        "payouts_enabled": True,
        "details_submitted": True,
        "capabilities": {"card_payments": "active", "transfers": "active"},
        "requirements": {
            "currently_due": [],
            "eventually_due": [],
            "past_due": [],
            "disabled_reason": None,
        },
        "settings": {
            "card_payments": {"statement_descriptor_prefix": "REMEDIALHQ"},
            "payouts": {"statement_descriptor": "REMEDIALHQ"},
        },
        "business_profile": {
            "name": "ReMediaLHQ",
            "support_email": "support@example.test",
            "url": "https://example.test",
        },
    }


def complete_datasets(
    *,
    purchase_count: int = 1,
    include_unpaid: bool = True,
) -> dict[str, list[dict[str, object]]]:
    product_id = "prod_creator_signal_desk"
    price_id = "price_founding_99_usd"
    link_id = "plink_founding_offer"
    datasets: dict[str, list[dict[str, object]]] = {
        "/v1/products": [
            {
                "id": product_id,
                "object": "product",
                "livemode": True,
                "name": "Creator Signal Desk Founding Pilot",
            }
        ],
        "/v1/prices": [
            {
                "id": price_id,
                "object": "price",
                "livemode": True,
                "product": product_id,
                "currency": "usd",
                "unit_amount": 9_900,
                "type": "one_time",
                "recurring": None,
                "custom_unit_amount": None,
            }
        ],
        "/v1/payment_links": [
            {
                "id": link_id,
                "object": "payment_link",
                "livemode": True,
                "active": True,
                "currency": "usd",
                "url": "https://buy.example.test/private",
            }
        ],
        f"/v1/payment_links/{link_id}/line_items": [
            {"id": "li_link_offer", "object": "item", "price": price_id, "quantity": 1}
        ],
        "/v1/checkout/sessions": [],
        "/v1/payment_intents": [],
        "/v1/charges": [],
        "/v1/refunds": [],
        "/v1/disputes": [],
    }
    sessions = datasets["/v1/checkout/sessions"]
    payment_intents = datasets["/v1/payment_intents"]
    charges = datasets["/v1/charges"]
    for number in range(purchase_count):
        session_id = f"cs_live_founding_{number}"
        payment_intent_id = f"pi_founding_{number}"
        charge_id = f"ch_founding_{number}"
        sessions.append(
            {
                "id": session_id,
                "object": "checkout.session",
                "livemode": True,
                "mode": "payment",
                "currency": "usd",
                "amount_subtotal": 9_900,
                "amount_total": 9_900,
                "total_details": {
                    "amount_tax": 0,
                    "amount_discount": 0,
                    "amount_shipping": 0,
                },
                "payment_status": "paid",
                "status": "complete",
                "payment_link": link_id,
                "payment_intent": payment_intent_id,
                "created": 1_788_000_000 + number,
                "customer_details": {
                    "email": f"buyer{number}@example.test",
                    "name": "Private Buyer",
                },
                "success_url": "https://example.test/secret",
            }
        )
        datasets[f"/v1/checkout/sessions/{session_id}/line_items"] = [
            {
                "id": f"li_session_{number}",
                "object": "item",
                "price": price_id,
                "quantity": 1,
            }
        ]
        payment_intents.append(
            {
                "id": payment_intent_id,
                "object": "payment_intent",
                "livemode": True,
                "currency": "usd",
                "amount": 9_900,
                "amount_received": 9_900,
                "status": "succeeded",
                "latest_charge": charge_id,
                "created": 1_788_000_050 + number,
            }
        )
        charges.append(
            {
                "id": charge_id,
                "object": "charge",
                "livemode": True,
                "payment_intent": payment_intent_id,
                "currency": "usd",
                "amount": 9_900,
                "amount_refunded": 0,
                "refunded": False,
                "status": "succeeded",
                "paid": True,
                "captured": True,
                "created": 1_788_000_100 + number,
                "receipt_url": "https://example.test/private-receipt",
                "billing_details": {"email": f"buyer{number}@example.test"},
            }
        )
    if include_unpaid:
        session_id = "cs_live_abandoned"
        sessions.append(
            {
                "id": session_id,
                "object": "checkout.session",
                "livemode": True,
                "mode": "payment",
                "currency": "usd",
                "amount_subtotal": 9_900,
                "amount_total": 9_900,
                "total_details": {
                    "amount_tax": 0,
                    "amount_discount": 0,
                    "amount_shipping": 0,
                },
                "payment_status": "unpaid",
                "status": "expired",
                "payment_link": link_id,
                "payment_intent": None,
                "created": 1_788_090_000,
            }
        )
        datasets[f"/v1/checkout/sessions/{session_id}/line_items"] = [
            {
                "id": "li_abandoned",
                "object": "item",
                "price": price_id,
                "quantity": 1,
            }
        ]
    return datasets


def collector_for(
    datasets: Mapping[str, list[dict[str, object]]],
    *,
    page_size: int = 100,
    account: Mapping[str, object] | None = None,
) -> tuple[StripeLiveHistoryCollector, FakeStripeTransport]:
    transport = FakeStripeTransport(
        datasets,
        account or account_fixture(),
        page_size=page_size,
    )
    return (
        StripeLiveHistoryCollector(transport, clock=lambda: FIXED_NOW),
        transport,
    )


class StripeLiveHistoryTests(unittest.TestCase):
    def test_capture_is_canonical_sanitized_private_and_digest_linked(self) -> None:
        datasets = complete_datasets()
        _collector, transport = collector_for(datasets)
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            output = Path(directory) / "stripe-private" / "history.json"
            evidence = capture_live_history(
                output,
                transport=transport,
                clock=lambda: FIXED_NOW,
            )
            raw = output.read_text(encoding="utf-8")
            document = json.loads(raw)

            self.assertTrue(raw.endswith("\n"))
            self.assertEqual(raw, json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
            self.assertEqual(stat.S_IMODE(output.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(document, evidence.document)
            self.assertEqual(document["observed_at"], "2026-08-30T14:15:00Z")
            self.assertEqual(document["aggregates"]["paid_founding_purchases"], 1)
            self.assertEqual(document["aggregates"]["abandoned_matching_checkout_sessions"], 1)
            for removed_name in (
                "usd_99_payment_intents",
                "usd_99_charges",
                "usd_99_refunds",
                "usd_99_disputes",
            ):
                self.assertNotIn(removed_name, document["aggregates"])

            history_digest = document.pop("history_evidence_sha256")
            expected_history_digest = hashlib.sha256(
                json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            self.assertEqual(history_digest, expected_history_digest)
            purchase = document["purchases"][0]
            purchase_digest = hashlib.sha256(
                json.dumps(purchase, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            self.assertEqual(document["purchase_record_sha256"], [purchase_digest])
            self.assertEqual(
                document["provider_purchase_sha256s"],
                [purchase["provider_purchase_sha256"]],
            )

            forbidden_values = (
                LIVE_KEY,
                "buyer0@example.test",
                "Private Buyer",
                "https://example.test",
                "cs_live_founding_0",
                "pi_founding_0",
                "ch_founding_0",
                "plink_founding_offer",
            )
            for value in forbidden_values:
                self.assertNotIn(value, raw)
            self.assertRegex(
                document["purchases"][0]["provider_reference_sha256"]["charge"],
                r"^[0-9a-f]{64}$",
            )

    def test_every_relevant_list_and_nested_list_is_fully_paginated(self) -> None:
        datasets = complete_datasets(purchase_count=2, include_unpaid=True)
        collector, transport = collector_for(datasets, page_size=1)
        evidence = collector.collect().document
        coverage = evidence["endpoint_coverage"]

        self.assertEqual(coverage["checkout_sessions"]["pages"], 3)
        self.assertEqual(coverage["payment_intents"]["pages"], 2)
        self.assertEqual(coverage["charges"]["pages"], 2)
        self.assertEqual(coverage["checkout_session_line_items"]["requests"], 3)
        self.assertTrue(
            all(item["pagination_complete"] for item in coverage.values())
        )
        called_paths = {path for path, _params in transport.calls}
        self.assertTrue(
            {
                "/v1/account",
                "/v1/products",
                "/v1/prices",
                "/v1/payment_links",
                "/v1/checkout/sessions",
                "/v1/payment_intents",
                "/v1/charges",
                "/v1/refunds",
                "/v1/disputes",
            }.issubset(called_paths)
        )

    def test_cutoff_is_taken_before_crawl_and_applied_to_every_history_page(self) -> None:
        events: list[str] = []
        datasets = complete_datasets(purchase_count=2, include_unpaid=True)

        class TimingTransport(FakeStripeTransport):
            def get(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
                events.append("get")
                return super().get(path, params)

        transport = TimingTransport(datasets, account_fixture(), page_size=1)

        def clock() -> datetime:
            events.append("clock")
            return FIXED_NOW.replace(microsecond=987_654)

        document = StripeLiveHistoryCollector(transport, clock=clock).collect().document
        expected_cutoff = str(int(FIXED_NOW.timestamp()))
        filtered_paths = {
            "/v1/checkout/sessions",
            "/v1/payment_intents",
            "/v1/charges",
            "/v1/refunds",
            "/v1/disputes",
        }

        self.assertEqual(events[0], "clock")
        self.assertEqual(events.count("clock"), 1)
        self.assertEqual(document["observed_at"], "2026-08-30T14:15:00Z")
        for path, params in transport.calls:
            if path in filtered_paths:
                self.assertEqual(params.get("created[lte]"), expected_cutoff)
            else:
                self.assertNotIn("created[lte]", params)
        self.assertTrue(filtered_paths.issubset({path for path, _params in transport.calls}))

    def test_history_object_after_cutoff_is_rejected_even_if_provider_returns_it(self) -> None:
        datasets = complete_datasets()
        datasets["/v1/payment_intents"][0]["created"] = int(FIXED_NOW.timestamp()) + 1
        collector, _transport = collector_for(datasets)
        with self.assertRaisesRegex(StripeLiveHistoryError, "outside the requested cutoff"):
            collector.collect()

    def test_account_output_contains_only_capability_and_control_booleans(self) -> None:
        collector, _transport = collector_for(complete_datasets(purchase_count=0))
        controls = collector.collect().document["account_controls"]

        self.assertTrue(controls)
        self.assertTrue(all(type(value) is bool for value in controls.values()))
        self.assertTrue(controls["requirements_exposed"])
        self.assertTrue(controls["currently_due_reported_empty"])
        self.assertTrue(controls["eventually_due_reported_empty"])
        self.assertTrue(controls["past_due_reported_empty"])
        self.assertTrue(controls["disabled_reason_reported_absent"])
        self.assertNotIn("id", controls)
        self.assertNotIn("business_profile", controls)

    def test_absent_standard_account_requirements_are_reported_without_inference(self) -> None:
        account = account_fixture()
        account.pop("requirements")
        collector, _transport = collector_for(
            complete_datasets(purchase_count=0),
            account=account,
        )
        controls = collector.collect().document["account_controls"]

        self.assertFalse(controls["requirements_exposed"])
        self.assertFalse(controls["currently_due_reported_empty"])
        self.assertFalse(controls["eventually_due_reported_empty"])
        self.assertFalse(controls["past_due_reported_empty"])
        self.assertFalse(controls["disabled_reason_reported_absent"])
        self.assertTrue(controls["charges_enabled"])
        self.assertTrue(controls["payouts_enabled"])
        self.assertTrue(controls["details_submitted"])

    def test_standard_payment_descriptor_and_payout_descriptor_are_reported_separately(self) -> None:
        account = account_fixture()
        account["settings"] = {
            "card_payments": {"statement_descriptor_prefix": "   "},
            "payments": {"statement_descriptor": "REMEDIALHQ"},
            "payouts": {"statement_descriptor": None},
        }
        collector, _transport = collector_for(
            complete_datasets(purchase_count=0),
            account=account,
        )
        controls = collector.collect().document["account_controls"]

        self.assertTrue(controls["payment_statement_descriptor_configured"])
        self.assertFalse(controls["payout_statement_descriptor_configured"])
        self.assertNotIn("card_statement_descriptor_configured", controls)

    def test_optional_account_profile_and_settings_may_be_null_or_omitted(self) -> None:
        account = account_fixture()
        account["settings"] = None
        account["business_profile"] = None
        account["capabilities"] = {"card_payments": "active"}
        account["requirements"] = {"currently_due": [], "disabled_reason": None}
        collector, _transport = collector_for(
            complete_datasets(purchase_count=0),
            account=account,
        )
        controls = collector.collect().document["account_controls"]

        self.assertTrue(controls["card_payments_capability_active"])
        self.assertFalse(controls["transfers_capability_active"])
        self.assertFalse(controls["payment_statement_descriptor_configured"])
        self.assertFalse(controls["business_profile_configured"])
        self.assertFalse(controls["eventually_due_reported_empty"])

    def test_exact_offer_product_or_price_ambiguity_fails_closed(self) -> None:
        product_ambiguous = complete_datasets(purchase_count=0)
        product_ambiguous["/v1/products"].append(
            {
                "id": "prod_duplicate",
                "object": "product",
                "livemode": True,
                "name": "Creator Signal Desk Founding Pilot",
            }
        )
        price_ambiguous = complete_datasets(purchase_count=0)
        price_ambiguous["/v1/prices"].append(
            {
                "id": "price_duplicate",
                "object": "price",
                "livemode": True,
                "product": "prod_creator_signal_desk",
                "currency": "usd",
                "unit_amount": 9_900,
                "type": "one_time",
                "recurring": None,
                "custom_unit_amount": None,
            }
        )
        for datasets in (product_ambiguous, price_ambiguous):
            with self.subTest(case=len(datasets["/v1/prices"])):
                collector, _transport = collector_for(datasets)
                with self.assertRaisesRegex(StripeLiveHistoryError, "ambiguous"):
                    collector.collect()

    def test_unsupported_offer_amount_currency_or_quantity_fails_closed(self) -> None:
        cases: list[dict[str, list[dict[str, object]]]] = []
        wrong_amount = complete_datasets(purchase_count=0)
        wrong_amount["/v1/prices"][0]["unit_amount"] = 9_899
        cases.append(wrong_amount)
        wrong_currency = complete_datasets(purchase_count=0)
        wrong_currency["/v1/prices"][0]["currency"] = "eur"
        cases.append(wrong_currency)
        wrong_quantity = complete_datasets(purchase_count=0)
        wrong_quantity["/v1/payment_links/plink_founding_offer/line_items"][0]["quantity"] = 2
        cases.append(wrong_quantity)
        for datasets in cases:
            collector, _transport = collector_for(datasets)
            with self.assertRaisesRegex(StripeLiveHistoryError, "unsupported"):
                collector.collect()

    def test_more_than_five_paid_purchases_fails_closed(self) -> None:
        collector, _transport = collector_for(
            complete_datasets(purchase_count=MAX_PAID_PURCHASES + 1, include_unpaid=False)
        )
        with self.assertRaisesRegex(StripeLiveHistoryError, "five-slot"):
            collector.collect()

    def test_automatic_tax_total_is_preserved_and_cross_checked(self) -> None:
        datasets = complete_datasets(include_unpaid=False)
        session = datasets["/v1/checkout/sessions"][0]
        session["amount_total"] = 10_593
        session["total_details"] = {
            "amount_tax": 693,
            "amount_discount": 0,
            "amount_shipping": 0,
        }
        datasets["/v1/payment_intents"][0]["amount"] = 10_593
        datasets["/v1/payment_intents"][0]["amount_received"] = 10_593
        datasets["/v1/charges"][0]["amount"] = 10_593

        collector, _transport = collector_for(datasets)
        document = collector.collect().document
        purchase = document["purchases"][0]

        self.assertEqual(purchase["amount_cents"], 9_900)
        self.assertEqual(purchase["gross_amount_cents"], 10_593)
        self.assertEqual(purchase["tax_amount_cents"], 693)
        self.assertEqual(document["aggregates"]["gross_paid_amount_cents"], 10_593)
        self.assertEqual(document["aggregates"]["tax_collected_amount_cents"], 693)

    def test_tax_total_without_consistent_total_details_fails_closed(self) -> None:
        datasets = complete_datasets(include_unpaid=False)
        datasets["/v1/checkout/sessions"][0]["amount_total"] = 10_593
        datasets["/v1/checkout/sessions"][0]["total_details"] = {
            "amount_tax": 600,
            "amount_discount": 0,
            "amount_shipping": 0,
        }
        collector, _transport = collector_for(datasets)
        with self.assertRaisesRegex(StripeLiveHistoryError, "disagree"):
            collector.collect()

    def test_non_live_objects_fail_closed(self) -> None:
        for endpoint in (
            "/v1/products",
            "/v1/prices",
            "/v1/payment_links",
            "/v1/checkout/sessions",
            "/v1/payment_intents",
            "/v1/charges",
        ):
            datasets = complete_datasets()
            datasets[endpoint][0]["livemode"] = False
            collector, _transport = collector_for(datasets)
            with (
                self.subTest(endpoint=endpoint),
                self.assertRaisesRegex(StripeLiveHistoryError, "non-live"),
            ):
                collector.collect()

        datasets = complete_datasets()
        datasets["/v1/refunds"].append(
            {
                "id": "re_test_mode",
                "object": "refund",
                "livemode": False,
                "charge": "ch_founding_0",
                "amount": 100,
                "status": "succeeded",
                "created": 1_788_000_200,
            }
        )
        collector, _transport = collector_for(datasets)
        with self.assertRaisesRegex(StripeLiveHistoryError, "non-live"):
            collector.collect()

    def test_pagination_anomalies_fail_closed(self) -> None:
        class EmptyAdvancingTransport(FakeStripeTransport):
            def get(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
                if path == "/v1/products":
                    return {"object": "list", "data": [], "has_more": True}
                return super().get(path, params)

        datasets = complete_datasets(purchase_count=0)
        transport = EmptyAdvancingTransport(datasets, account_fixture())
        collector = StripeLiveHistoryCollector(transport, clock=lambda: FIXED_NOW)
        with self.assertRaisesRegex(StripeLiveHistoryError, "without a cursor"):
            collector.collect()

    def test_paid_purchase_requires_consistent_payment_intent_and_charge(self) -> None:
        missing_charge = complete_datasets()
        missing_charge["/v1/charges"].clear()
        wrong_latest_charge = complete_datasets()
        wrong_latest_charge["/v1/payment_intents"][0]["latest_charge"] = "ch_different"
        for datasets in (missing_charge, wrong_latest_charge):
            collector, _transport = collector_for(datasets)
            with self.assertRaises(StripeLiveHistoryError):
                collector.collect()

    def test_refunds_and_disputes_are_correlated_without_raw_references(self) -> None:
        datasets = complete_datasets()
        datasets["/v1/refunds"].append(
            {
                "id": "re_partial_founding",
                "object": "refund",
                "charge": "ch_founding_0",
                "payment_intent": "pi_founding_0",
                "currency": "usd",
                "amount": 4_900,
                "status": "succeeded",
                "created": 1_788_000_200,
            }
        )
        datasets["/v1/charges"][0]["amount_refunded"] = 4_900
        datasets["/v1/disputes"].append(
            {
                "id": "dp_founding_review",
                "object": "dispute",
                "livemode": True,
                "charge": "ch_founding_0",
                "payment_intent": "pi_founding_0",
                "currency": "usd",
                "amount": 9_900,
                "status": "under_review",
                "created": 1_788_000_300,
            }
        )
        collector, _transport = collector_for(datasets)
        document = collector.collect().document
        purchase = document["purchases"][0]

        self.assertEqual(purchase["refunded_amount_cents"], 4_900)
        self.assertFalse(purchase["fully_refunded"])
        self.assertEqual(purchase["dispute_count"], 1)
        self.assertTrue(purchase["has_open_dispute"])
        serialized = json.dumps(document)
        self.assertNotIn("re_partial_founding", serialized)
        self.assertNotIn("dp_founding_review", serialized)

    def test_provider_purchase_digest_is_stable_across_refund_and_dispute_updates(self) -> None:
        baseline_collector, _transport = collector_for(complete_datasets())
        baseline = baseline_collector.collect().document

        updated_datasets = complete_datasets()
        updated_datasets["/v1/refunds"].append(
            {
                "id": "re_later_partial",
                "object": "refund",
                "charge": "ch_founding_0",
                "payment_intent": "pi_founding_0",
                "currency": "usd",
                "amount": 4_900,
                "status": "succeeded",
                "created": 1_788_000_200,
            }
        )
        updated_datasets["/v1/charges"][0]["amount_refunded"] = 4_900
        updated_datasets["/v1/disputes"].append(
            {
                "id": "dp_later_review",
                "object": "dispute",
                "livemode": True,
                "charge": "ch_founding_0",
                "payment_intent": "pi_founding_0",
                "currency": "usd",
                "amount": 9_900,
                "status": "under_review",
                "created": 1_788_000_300,
            }
        )
        updated_collector, _transport = collector_for(updated_datasets)
        updated = updated_collector.collect().document

        self.assertEqual(
            baseline["purchases"][0]["provider_purchase_sha256"],
            updated["purchases"][0]["provider_purchase_sha256"],
        )
        self.assertEqual(
            baseline["provider_purchase_sha256s"],
            updated["provider_purchase_sha256s"],
        )
        self.assertNotEqual(
            baseline["purchase_record_sha256"],
            updated["purchase_record_sha256"],
        )

    def test_refund_api_inconsistency_fails_closed(self) -> None:
        datasets = complete_datasets()
        datasets["/v1/refunds"].append(
            {
                "id": "re_partial_founding",
                "object": "refund",
                "charge": "ch_founding_0",
                "currency": "usd",
                "amount": 4_900,
                "status": "succeeded",
                "created": 1_788_000_200,
            }
        )
        collector, _transport = collector_for(datasets)
        with self.assertRaisesRegex(StripeLiveHistoryError, "disagree"):
            collector.collect()

    def test_live_secret_is_read_only_from_the_environment(self) -> None:
        with mock.patch.dict(os.environ, {"STRIPE_SECRET_KEY": LIVE_KEY}, clear=True):
            self.assertEqual(load_live_secret_from_environment(), LIVE_KEY)
            self.assertNotIn(LIVE_KEY, repr(StripeAPITransport(LIVE_KEY)))
        for value in ("", "sk_test_fixturevalue123456", "pk_live_fixturevalue123456"):
            with (
                mock.patch.dict(os.environ, {"STRIPE_SECRET_KEY": value}, clear=True),
                self.assertRaises(StripeLiveHistoryError),
            ):
                load_live_secret_from_environment()

    def test_insecure_parent_or_existing_output_mode_fails_closed(self) -> None:
        collector, _transport = collector_for(complete_datasets(purchase_count=0))
        evidence = collector.collect()
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            insecure_parent = Path(directory) / "insecure"
            insecure_parent.mkdir(mode=0o755)
            insecure_parent.chmod(0o755)
            with self.assertRaisesRegex(StripeLiveHistoryError, "parent mode"):
                write_private_evidence(insecure_parent / "history.json", evidence)

            secure_parent = Path(directory) / "secure"
            secure_parent.mkdir(mode=0o700)
            secure_parent.chmod(0o700)
            output = secure_parent / "history.json"
            output.write_text("old", encoding="utf-8")
            output.chmod(0o644)
            with self.assertRaisesRegex(StripeLiveHistoryError, "file mode"):
                write_private_evidence(output, evidence)
            self.assertEqual(output.read_text(encoding="utf-8"), "old")

    def test_symbolic_link_ancestor_is_rejected_before_any_write(self) -> None:
        collector, _transport = collector_for(complete_datasets(purchase_count=0))
        evidence = collector.collect()
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            real_parent = root / "real-private"
            real_parent.mkdir(mode=0o700)
            real_parent.chmod(0o700)
            linked_parent = root / "linked-private"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            output = linked_parent / "history.json"

            with self.assertRaisesRegex(StripeLiveHistoryError, "symbolic-link ancestors"):
                write_private_evidence(output, evidence)
            self.assertFalse((real_parent / "history.json").exists())
            self.assertEqual(list(real_parent.iterdir()), [])

    def test_atomic_replace_failure_preserves_existing_private_file(self) -> None:
        collector, _transport = collector_for(complete_datasets(purchase_count=0))
        evidence = collector.collect()
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = Path(directory) / "private"
            parent.mkdir(mode=0o700)
            parent.chmod(0o700)
            output = parent / "history.json"
            output.write_text("old", encoding="utf-8")
            output.chmod(0o600)
            with (
                mock.patch(
                    "remedialhq.stripe_live_history.os.replace",
                    side_effect=OSError("private path and raw id must remain hidden"),
                ),
                self.assertRaisesRegex(StripeLiveHistoryError, "could not be written"),
            ):
                write_private_evidence(output, evidence)
            self.assertEqual(output.read_text(encoding="utf-8"), "old")
            self.assertEqual(list(parent.iterdir()), [output])

    def test_transport_exceptions_are_sanitized(self) -> None:
        class ExplodingTransport:
            def get(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
                del path, params
                raise RuntimeError(
                    "sk_live_do_not_expose cs_live_do_not_expose https://private.example"
                )

        collector = StripeLiveHistoryCollector(ExplodingTransport(), clock=lambda: FIXED_NOW)
        with self.assertRaises(StripeLiveHistoryError) as raised:
            collector.collect()
        message = str(raised.exception)
        self.assertEqual(message, "Stripe transport failed")
        self.assertNotIn("sk_live", message)
        self.assertNotIn("https://", message)

    def test_cli_without_a_live_environment_key_is_safe_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            output = Path(directory) / "private" / "history.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = main(["--output", str(output)])
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("sk_live_", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
