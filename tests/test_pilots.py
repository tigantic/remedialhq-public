from __future__ import annotations

import json
import multiprocessing
import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Protocol
from unittest.mock import patch

from remedialhq.canonical import sha256_json
from remedialhq.contact_evidence import ContactEvidence
from remedialhq.delivery_evidence import (
    DeliveryEvidence,
    build_delivery_evidence,
)
from remedialhq.ledger import HashLedger
from remedialhq.outreach import OutreachPlan
from remedialhq.payment_evidence import (
    LivePaymentEvidence,
    build_live_payment_evidence,
)
from remedialhq.pilots import (
    ContactChannel,
    DecisionGate,
    FeedbackOutcome,
    OpaqueIdKind,
    OwnerTimeCategory,
    PaymentMode,
    PilotEventType,
    PilotLedger,
    PilotLedgerError,
    PilotManifestError,
    PilotOrderState,
    PilotReplayError,
    PilotStorageSecurityError,
    PilotValidationError,
    ProspectSegment,
    ReplyOutcome,
    RiskKind,
    RiskSeverity,
    load_order_manifest,
    new_opaque_id,
    write_order_manifest,
)
from tests.pilot_reconciliation_support import reconciliation_evidence

DELIVERABLE_SHA256 = "a" * 64
CUSTOMER_ACCEPTANCE_EVIDENCE_SHA256 = "c" * 64
ORDER_ACCEPTANCE_EVIDENCE_SHA256 = "d" * 64
RECONCILIATION_EVIDENCE_SHA256 = "f" * 64


def opaque(prefix: str, number: int) -> str:
    return f"{prefix}_{number:032x}"


def legacy_prior_ledger(path: Path, purchases: int) -> None:
    ledger = HashLedger(path, mode=0o600)
    ledger.append(
        PilotEventType.PILOT_LEDGER_INITIALIZED,
        {"schema_version": 1},
        occurred_at="1970-01-01T00:00:00+00:00",
    )
    for number in range(purchases):
        ledger.append(
            PilotEventType.PURCHASED,
            {"legacy_order_ref": number},
            occurred_at=f"2026-08-2{number + 1}T12:00:00+00:00",
        )


def payment_evidence(
    number: int,
    *,
    refund: bool = False,
    provider_number: int | None = None,
    observed_at: str | None = None,
    artifact_sha256: str | None = None,
    provider_purchase_sha256: str | None = None,
    tax_amount_cents: int = 0,
) -> LivePaymentEvidence:
    order_id = opaque("ord", number)
    provider_number = number if provider_number is None else provider_number
    document: dict[str, object] = {
        "schema_version": "remedialhq.live-payment-evidence.v2",
        "event_type": "FULL_REFUND" if refund else "PAYMENT_CAPTURED",
        "provider": "STRIPE",
        "mode": "LIVE",
        "livemode": True,
        "status": "SUCCEEDED",
        "currency": "USD",
        "amount_cents": 9_900,
        "tax_amount_cents": tax_amount_cents,
        "gross_amount_cents": 9_900 + tax_amount_cents,
        "payment_type": "ONE_TIME",
        "order_id": order_id,
        "observed_at": observed_at or datetime.now(UTC).isoformat(),
        "evidence_ref": opaque("evd", 100 + number if refund else number),
        "provider_ref": opaque("rfd" if refund else "pay", provider_number),
        "provider_purchase_sha256": provider_purchase_sha256 or f"{1000 + number:064x}",
        "artifact_sha256": artifact_sha256 or f"{200 + number if refund else number:064x}",
    }
    if refund:
        document["original_payment_ref"] = opaque("pay", provider_number)
        document["refunded_amount_cents"] = 9_900 + tax_amount_cents
    return build_live_payment_evidence(document, expected_order_id=order_id)


def delivery_evidence(
    number: int,
    artifact_sha256: str = DELIVERABLE_SHA256,
    *,
    observed_at: str | None = None,
    evidence_artifact_sha256: str | None = None,
) -> DeliveryEvidence:
    order_id = opaque("ord", number)
    return build_delivery_evidence(
        {
            "schema_version": "remedialhq.delivery-evidence.v1",
            "event_type": "DELIVERY_RECORDED",
            "delivery_method": "EMAIL_PROVIDER_ACCEPTED",
            "order_id": order_id,
            "artifact_sha256": artifact_sha256,
            "evidence_artifact_sha256": evidence_artifact_sha256 or f"{300 + number:064x}",
            "observed_at": observed_at or datetime.now(UTC).isoformat(),
            "evidence_ref": opaque("evd", 200 + number),
            "delivery_ref": opaque("dlv", number),
        },
        expected_order_id=order_id,
        expected_artifact_sha256=artifact_sha256,
    )


def qualified_outreach_plan(campaign_start: date) -> OutreachPlan:
    prospects: list[dict[str, object]] = []
    for index in range(50):
        evidence_base = 11_000 + index * 3
        prospects.append(
            {
                "prospect_id": opaque("prs", index + 1),
                "queue_position": index + 1,
                "segment": ProspectSegment.GAMING_CREATOR.value,
                "channel": ContactChannel.BUSINESS_EMAIL.value,
                "planned_contact_date": (
                    campaign_start + timedelta(days=2 + index // 10)
                ).isoformat(),
                "publishes_original_analysis": True,
                "specific_upcoming_piece": True,
                "public_business_channel_verified": True,
                "qualification_evidence_sha256": f"{evidence_base:064x}",
                "recent_work_reference_sha256": f"{evidence_base + 1:064x}",
                "sample_insight_sha256": f"{evidence_base + 2:064x}",
            }
        )
    return OutreachPlan.from_dict(
        {
            "schema_version": "remedialhq.outreach-plan.v1",
            "campaign_ref": opaque("cmp", 1),
            "campaign_start": campaign_start.isoformat(),
            "campaign_end": (campaign_start + timedelta(days=13)).isoformat(),
            "utc_offset_minutes": 0,
            "daily_contact_limit": 10,
            "controls": {
                "sender_identification_ready": True,
                "sending_domain_authenticated": True,
                "postal_address_requirement_reviewed": True,
                "opt_out_process_ready": True,
                "evidence_sha256": f"{10_000:064x}",
            },
            "prospects": prospects,
        }
    )


class _Waitable(Protocol):
    def wait(self, timeout: float | None = None) -> bool: ...


def _append_prospect_process(path: str, number: int, start: _Waitable) -> None:
    ledger = PilotLedger(path)
    if not start.wait(10):
        raise RuntimeError("concurrent append start timed out")
    ledger.record(
        PilotEventType.PROSPECT_ADDED,
        {
            "prospect_id": opaque("prs", number),
            "segment": ProspectSegment.GAMING_CREATOR,
        },
        occurred_at="2026-08-29T20:00:00+00:00",
    )


class PilotLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        secure_temp_root = "/tmp" if Path("/tmp").is_dir() else None
        self.temporary_directory = tempfile.TemporaryDirectory(dir=secure_temp_root)
        self.path = Path(self.temporary_directory.name) / "pilot.jsonl"
        self.ledger = PilotLedger.initialize(
            self.path,
            reconciliation_evidence=reconciliation_evidence(),
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def add_prospect(self, number: int) -> str:
        prospect_id = opaque("prs", number)
        self.ledger.record(
            PilotEventType.PROSPECT_ADDED,
            {
                "prospect_id": prospect_id,
                "segment": ProspectSegment.GAMING_CREATOR,
            },
        )
        return prospect_id

    def contact(self, prospect_id: str) -> None:
        self.ledger.record(
            PilotEventType.CONTACTED,
            {
                "prospect_id": prospect_id,
                "channel": ContactChannel.BUSINESS_EMAIL,
            },
        )

    def record_interested_reply(self, prospect_id: str) -> None:
        self.ledger.record(
            PilotEventType.REPLIED,
            {"prospect_id": prospect_id, "outcome": ReplyOutcome.INTERESTED},
        )

    def advance_to_sample(self, prospect_id: str) -> None:
        self.record_interested_reply(prospect_id)
        self.ledger.record(PilotEventType.SAMPLE_REQUESTED, {"prospect_id": prospect_id})

    def record_customer_acceptance(self, prospect_id: str, number: int) -> None:
        self.ledger.record(
            PilotEventType.CUSTOMER_ACCEPTANCE_RECORDED,
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", number),
                "customer_acceptance_ref": opaque("cac", number),
                "acceptance_evidence_sha256": CUSTOMER_ACCEPTANCE_EVIDENCE_SHA256,
            },
        )

    def advance_to_checkout(self, prospect_id: str, number: int) -> None:
        self.advance_to_sample(prospect_id)
        self.confirm_scope(prospect_id, number)
        self.record_customer_acceptance(prospect_id, number)
        self.ledger.record(
            PilotEventType.CHECKOUT_SENT,
            {"prospect_id": prospect_id, "checkout_ref": opaque("chk", number)},
        )

    def purchase(
        self,
        prospect_id: str,
        number: int,
        *,
        fee_cents: int = 317,
        tax_amount_cents: int = 0,
    ) -> None:
        self.ledger.record(
            PilotEventType.PURCHASED,
            {
                "prospect_id": prospect_id,
                "order_id": opaque("ord", number),
                "fee_cents": fee_cents,
            },
            payment_evidence=payment_evidence(
                number,
                tax_amount_cents=tax_amount_cents,
            ),
        )

    def accept_order(self, prospect_id: str, number: int) -> None:
        self.ledger.record(
            PilotEventType.ORDER_ACCEPTED,
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", number),
                "order_acceptance_ref": opaque("oac", number),
                "acceptance_evidence_sha256": ORDER_ACCEPTANCE_EVIDENCE_SHA256,
            },
        )

    def confirm_scope(
        self,
        prospect_id: str,
        number: int,
        *,
        claim_ids: list[str] | None = None,
    ) -> None:
        self.ledger.record(
            PilotEventType.SCOPE_CONFIRMED,
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", number),
                "deadline": "2026-09-15",
                "terms_version": "creator-desk-v1",
                "claim_ids": claim_ids or ["CLM-0001"],
            },
        )

    def amend_scope(
        self,
        prospect_id: str,
        old_number: int,
        new_number: int,
    ) -> None:
        self.ledger.record(
            PilotEventType.SCOPE_AMENDED,
            {
                "prospect_id": prospect_id,
                "supersedes_scope_ref": opaque("scp", old_number),
                "scope_ref": opaque("scp", new_number),
                "deadline": "2026-09-20",
                "terms_version": "creator-desk-v2",
                "claim_ids": ["CLM-0002"],
            },
        )

    def refund(
        self,
        prospect_id: str,
        number: int,
        *,
        tax_amount_cents: int = 0,
    ) -> None:
        self.ledger.record(
            PilotEventType.REFUNDED,
            {
                "prospect_id": prospect_id,
                "order_id": opaque("ord", number),
            },
            payment_evidence=payment_evidence(
                number,
                refund=True,
                tax_amount_cents=tax_amount_cents,
            ),
        )

    def complete_artifact(
        self,
        prospect_id: str,
        artifact_sha256: str = DELIVERABLE_SHA256,
    ) -> None:
        self.ledger.record(
            PilotEventType.ARTIFACT_COMPLETED,
            {
                "prospect_id": prospect_id,
                "deliverable_sha256": artifact_sha256,
            },
        )

    def deliver(
        self,
        prospect_id: str,
        number: int,
        artifact_sha256: str = DELIVERABLE_SHA256,
    ) -> None:
        self.ledger.record(
            PilotEventType.DELIVERED,
            {
                "prospect_id": prospect_id,
                "order_id": opaque("ord", number),
            },
            delivery_evidence=delivery_evidence(number, artifact_sha256),
        )

    def test_file_is_0600_and_generated_identifiers_are_opaque(self) -> None:
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)
        self.assertTrue(self.ledger.private_mode_enforced)
        self.assertEqual(
            self.ledger.storage_security(),
            {
                "private_mode_enforced": True,
                "storage_security_status": "ENFORCED",
                "ledger_mode": "0600",
                "lock_mode": "0600",
                "insecure_test_storage_override": False,
            },
        )
        initialized = json.loads(self.path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(initialized["payload"]["schema_version"], 5)
        generated = new_opaque_id(OpaqueIdKind.PROSPECT)
        self.assertRegex(generated, r"^prs_[0-9a-f]{32}$")
        self.assertEqual(len(generated), 36)
        self.assertRegex(
            new_opaque_id(OpaqueIdKind.RECONCILIATION),
            r"^rec_[0-9a-f]{32}$",
        )
        with self.assertRaises(PilotValidationError):
            new_opaque_id("customer")

    def test_initialization_is_explicit_and_cannot_overwrite(self) -> None:
        path = Path(self.temporary_directory.name) / "explicit.jsonl"
        unbound_legacy_path = Path(self.temporary_directory.name) / "prior-v1.jsonl"
        legacy_prior_ledger(unbound_legacy_path, 1)
        with self.assertRaisesRegex(PilotReplayError, "provider purchase bindings"):
            PilotLedger.prior_ledger_snapshot(unbound_legacy_path)
        prior_path = Path(self.temporary_directory.name) / "prior-v5.jsonl"
        PilotLedger.initialize(
            prior_path,
            reconciliation_evidence=reconciliation_evidence(
                provider_purchase_hashes=("8" * 64,),
            ),
        )
        prior_snapshot = PilotLedger.prior_ledger_snapshot(prior_path)
        with self.assertRaisesRegex(PilotReplayError, "initialize schema version 5"):
            PilotLedger(path)
        with self.assertRaisesRegex(PilotValidationError, "verified prior ledger"):
            PilotLedger.initialize(
                path,
                reconciliation_evidence=reconciliation_evidence(prior_snapshot),
            )
        initialized = PilotLedger.initialize(
            path,
            reconciliation_evidence=reconciliation_evidence(prior_snapshot),
            prior_ledger=prior_path,
        )
        self.assertEqual(initialized.metrics().prior_consumed_slots, 1)
        with self.assertRaisesRegex(PilotValidationError, "already exists"):
            PilotLedger.initialize(
                path,
                reconciliation_evidence=reconciliation_evidence(prior_snapshot),
                prior_ledger=prior_path,
            )

    def test_prior_slots_reduce_capacity_without_booking_revenue(self) -> None:
        path = Path(self.temporary_directory.name) / "reconciled.jsonl"
        self.ledger = PilotLedger.initialize(
            path,
            reconciliation_evidence=reconciliation_evidence(
                provider_purchase_hashes=tuple(f"{index:064x}" for index in range(500, 504)),
            ),
        )
        prospects: list[str] = []
        for number in (1, 2):
            prospect_id = self.add_prospect(number)
            prospects.append(prospect_id)
            self.contact(prospect_id)
            self.advance_to_checkout(prospect_id, number)
        self.purchase(prospects[0], 1)
        metrics = self.ledger.metrics()
        self.assertEqual(metrics.prior_consumed_slots, 4)
        self.assertEqual(metrics.remaining_founding_slots, 0)
        self.assertEqual(metrics.purchases, 1)
        self.assertEqual(metrics.booked_revenue_cents, 9_900)
        self.refund(prospects[0], 1)
        with self.assertRaisesRegex(PilotValidationError, "five founding"):
            self.purchase(prospects[1], 2)

    def test_provider_only_purchases_consume_capacity_without_a_prior_ledger(self) -> None:
        path = Path(self.temporary_directory.name) / "provider-history.jsonl"
        provider_hashes = ("8" * 64, "9" * 64)

        ledger = PilotLedger.initialize(
            path,
            reconciliation_evidence=reconciliation_evidence(
                provider_purchase_hashes=provider_hashes,
            ),
        )

        initialized = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(initialized["payload"]["prior_consumed_slots"], 2)
        self.assertEqual(
            initialized["payload"]["reconciled_provider_purchase_sha256s"],
            list(provider_hashes),
        )
        self.assertEqual(ledger.metrics().prior_consumed_slots, 2)
        self.assertEqual(ledger.metrics().remaining_founding_slots, 3)

    def test_zero_one_and_five_provider_digests_bind_through_initialization(self) -> None:
        for count in (0, 1, 5):
            with self.subTest(count=count):
                path = Path(self.temporary_directory.name) / f"provider-{count}.jsonl"
                provider_hashes = tuple(f"{5000 + index:064x}" for index in range(count))

                ledger = PilotLedger.initialize(
                    path,
                    reconciliation_evidence=reconciliation_evidence(
                        provider_purchase_hashes=provider_hashes,
                    ),
                )
                initialized = json.loads(path.read_text(encoding="utf-8").splitlines()[0])[
                    "payload"
                ]

                self.assertEqual(initialized["prior_consumed_slots"], count)
                self.assertEqual(
                    initialized["reconciled_provider_purchase_sha256s"],
                    list(provider_hashes),
                )
                self.assertEqual(
                    ledger.metrics().remaining_founding_slots,
                    5 - count,
                )

    def test_reconciled_provider_digest_cannot_be_reused_by_a_new_purchase(self) -> None:
        path = Path(self.temporary_directory.name) / "provider-reuse.jsonl"
        inherited_provider_digest = f"{1001:064x}"
        self.ledger = PilotLedger.initialize(
            path,
            reconciliation_evidence=reconciliation_evidence(
                provider_purchase_hashes=(inherited_provider_digest,),
            ),
        )
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)

        with self.assertRaisesRegex(
            PilotValidationError,
            "provider_purchase_sha256 must be unique",
        ):
            self.purchase(prospect_id, 1)

    def test_schema_five_ledger_can_roll_into_a_qualified_campaign(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)

        prior_slots, prior_head = PilotLedger.reconcile_prior_ledger(self.path)

        self.assertEqual(prior_slots, 1)
        self.assertEqual(prior_head, self.ledger.head)
        prior_snapshot = PilotLedger.prior_ledger_snapshot(self.path)
        self.assertEqual(
            prior_snapshot.purchase_evidence_artifact_sha256s,
            (f"{1:064x}",),
        )
        self.assertEqual(
            prior_snapshot.provider_purchase_sha256s,
            (f"{1001:064x}",),
        )
        next_path = Path(self.temporary_directory.name) / "qualified-campaign.jsonl"
        next_ledger = PilotLedger.initialize(
            next_path,
            reconciliation_evidence=reconciliation_evidence(prior_snapshot),
            prior_ledger=self.path,
        )
        next_ledger.import_outreach_plan(
            qualified_outreach_plan(date(2026, 9, 1)),
            occurred_at="2026-09-01T12:00:00Z",
        )
        metrics = next_ledger.metrics()
        self.assertEqual(metrics.prior_consumed_slots, 1)
        self.assertEqual(metrics.prospects, 50)
        self.assertEqual(metrics.contacted, 0)
        self.assertEqual(metrics.purchases, 0)
        self.assertEqual(metrics.remaining_founding_slots, 4)

    def test_zero_purchase_schema_five_rollover_keeps_the_audit_anchor(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)

        prior_slots, prior_head = PilotLedger.reconcile_prior_ledger(self.path)

        self.assertEqual(prior_slots, 0)
        prior_snapshot = PilotLedger.prior_ledger_snapshot(self.path)
        next_path = Path(self.temporary_directory.name) / "zero-purchase-rollover.jsonl"
        next_ledger = PilotLedger.initialize(
            next_path,
            reconciliation_evidence=reconciliation_evidence(prior_snapshot),
            prior_ledger=self.path,
        )
        initialized = json.loads(next_path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(
            initialized["payload"]["prior_ledger_head_sha256"],
            prior_head,
        )
        next_ledger.import_outreach_plan(
            qualified_outreach_plan(date(2026, 9, 1)),
            occurred_at="2026-09-01T12:00:00Z",
        )
        self.assertEqual(next_ledger.metrics().prior_consumed_slots, 0)
        self.assertEqual(next_ledger.metrics().prospects, 50)

    @unittest.skipUnless(
        "fork" in multiprocessing.get_all_start_methods(),
        "multiprocess race test requires POSIX fork",
    )
    def test_multiprocess_appends_preserve_semantics_and_hash_chain(self) -> None:
        context = multiprocessing.get_context("fork")
        start = context.Event()
        processes = [
            context.Process(
                target=_append_prospect_process,
                args=(str(self.path), number, start),
            )
            for number in range(100, 116)
        ]
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(15)
            self.assertEqual(process.exitcode, 0)

        replayed = PilotLedger(self.path)
        self.assertEqual(replayed.metrics().prospects, len(processes))
        verified, message = replayed.verify()
        self.assertTrue(verified)
        self.assertEqual(message, f"verified {len(processes) + 1} pilot events")

    def test_rejects_symbolic_link_ancestor_without_writing_outside(self) -> None:
        root = Path(self.temporary_directory.name)
        outside = root / "outside"
        linked = root / "linked"
        outside.mkdir()
        try:
            linked.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symbolic links are unavailable: {exc}")

        with self.assertRaisesRegex(PilotLedgerError, "symbolic-link ancestors"):
            PilotLedger(linked / "redirected.jsonl")
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics required")
    def test_insecure_ledger_mode_fails_closed_and_is_not_silently_repaired(self) -> None:
        self.path.chmod(0o644)

        with self.assertRaisesRegex(
            PilotStorageSecurityError,
            r"pilot ledger permissions.*observed 0644.*under /home",
        ):
            PilotLedger(self.path)

        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics required")
    def test_modes_are_rechecked_before_every_operation(self) -> None:
        self.path.chmod(0o644)
        with self.assertRaises(PilotStorageSecurityError):
            self.ledger.metrics()
        self.path.chmod(0o600)

        lock_path = self.path.with_name(f".{self.path.name}.lock")
        lock_path.chmod(0o644)
        with self.assertRaisesRegex(PilotStorageSecurityError, "pilot lock permissions"):
            self.ledger.verify()

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics required")
    def test_explicit_test_override_allows_only_bool_and_reports_insecurity(self) -> None:
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        self.path.chmod(0o644)
        lock_path.chmod(0o666)

        opened = PilotLedger(self.path, allow_insecure_test_storage=True)

        self.assertEqual(opened.metrics().prospects, 0)
        self.assertEqual(
            opened.storage_security(),
            {
                "private_mode_enforced": False,
                "storage_security_status": "INSECURE_TEST_OVERRIDE",
                "ledger_mode": "0644",
                "lock_mode": "0666",
                "insecure_test_storage_override": True,
            },
        )
        with self.assertRaisesRegex(TypeError, "must be a bool"):
            PilotLedger(self.path, allow_insecure_test_storage=1)  # type: ignore[arg-type]

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics required")
    def test_prior_ledger_permissions_fail_closed_without_test_override(self) -> None:
        prior_path = Path(self.temporary_directory.name) / "insecure-prior.jsonl"
        legacy_prior_ledger(prior_path, 0)
        prior_path.chmod(0o644)

        with self.assertRaises(PilotStorageSecurityError):
            PilotLedger.prior_ledger_snapshot(prior_path)
        snapshot = PilotLedger.prior_ledger_snapshot(
            prior_path,
            allow_insecure_test_storage=True,
        )

        self.assertEqual(snapshot.lifetime_consumed_slots, 0)
        self.assertEqual(stat.S_IMODE(prior_path.stat().st_mode), 0o644)

    def test_failed_initialization_removes_created_ledger_and_lock(self) -> None:
        path = Path(self.temporary_directory.name) / "failed-init.jsonl"
        lock_path = path.with_name(f".{path.name}.lock")

        with (
            patch.object(HashLedger, "append", side_effect=RuntimeError("forced failure")),
            self.assertRaisesRegex(RuntimeError, "forced failure"),
        ):
            PilotLedger.initialize(
                path,
                reconciliation_evidence=reconciliation_evidence(),
            )

        self.assertFalse(path.exists())
        self.assertFalse(lock_path.exists())

    def test_complete_order_flow_replays_and_aggregates(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.ledger.record(
            PilotEventType.OWNER_TIME_RECORDED,
            {
                "prospect_id": prospect_id,
                "time_entry_id": opaque("tim", 1),
                "category": OwnerTimeCategory.OUTREACH,
                "minutes": 8,
            },
        )
        self.advance_to_checkout(prospect_id, 1)
        self.ledger.record(
            PilotEventType.OWNER_TIME_RECORDED,
            {
                "prospect_id": prospect_id,
                "time_entry_id": opaque("tim", 2),
                "category": OwnerTimeCategory.SAMPLE,
                "minutes": 30,
            },
        )
        self.purchase(prospect_id, 1)
        self.accept_order(prospect_id, 1)
        self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        self.ledger.record(
            PilotEventType.OWNER_TIME_RECORDED,
            {
                "prospect_id": prospect_id,
                "time_entry_id": opaque("tim", 3),
                "category": OwnerTimeCategory.FULFILLMENT,
                "minutes": 180,
            },
        )
        self.complete_artifact(prospect_id)
        self.deliver(prospect_id, 1)
        self.ledger.record(
            PilotEventType.FEEDBACK_RECORDED,
            {
                "prospect_id": prospect_id,
                "feedback_id": opaque("fbk", 1),
                "outcomes": [
                    FeedbackOutcome.SAVED_TIME,
                    FeedbackOutcome.PREVENTED_ERROR,
                ],
            },
        )

        metrics = self.ledger.metrics()
        self.assertEqual(metrics.prospects, 1)
        self.assertEqual(metrics.contacted, 1)
        self.assertEqual(metrics.replies, 1)
        self.assertEqual(metrics.sample_requests, 1)
        self.assertEqual(metrics.checkouts_sent, 1)
        self.assertEqual(metrics.purchases, 1)
        self.assertEqual(metrics.scopes_confirmed, 1)
        self.assertEqual(metrics.customer_acceptances, 1)
        self.assertEqual(metrics.orders_accepted, 1)
        self.assertEqual(metrics.active_orders, 1)
        self.assertEqual(metrics.deliveries, 1)
        self.assertEqual(metrics.feedback_responses, 1)
        self.assertEqual(metrics.booked_revenue_cents, 9_900)
        self.assertEqual(metrics.payment_fees_cents, 317)
        self.assertEqual(metrics.net_cash_cents, 9_583)
        self.assertEqual(metrics.owner_minutes, 218)
        self.assertEqual(metrics.owner_hours, 3.63)
        self.assertEqual(metrics.reply_rate, 1.0)
        self.assertEqual(metrics.sample_request_rate, 1.0)
        self.assertEqual(metrics.purchase_rate, 1.0)
        self.assertEqual(metrics.decision_gate, DecisionGate.COLLECT_MORE_DATA)

        order = self.ledger.order(opaque("ord", 1))
        self.assertEqual(order.state, PilotOrderState.DELIVERED)
        self.assertEqual(order.scope_ref, opaque("scp", 1))
        self.assertEqual(order.claim_ids, ("CLM-0001",))
        self.assertEqual(order.deadline, "2026-09-15")
        self.assertEqual(order.terms_version, "creator-desk-v1")
        self.assertEqual(order.payment_mode, PaymentMode.LIVE)
        self.assertEqual(order.payment_evidence_artifact_sha256, f"{1:064x}")
        self.assertEqual(order.deliverable_sha256, DELIVERABLE_SHA256)
        self.assertEqual(self.ledger.orders(), (order,))
        with self.assertRaises(FrozenInstanceError):
            order.amount_cents = 1  # type: ignore[misc]

        replayed = PilotLedger(self.path).metrics()
        self.assertEqual(replayed, metrics)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_schema_blocks_free_form_and_personal_data_fields(self) -> None:
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.PROSPECT_ADDED,
                {
                    "prospect_id": "person@example.com",
                    "segment": ProspectSegment.GAMING_CREATOR,
                },
            )

        prospect_id = self.add_prospect(1)
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.CONTACTED,
                {
                    "prospect_id": prospect_id,
                    "channel": ContactChannel.BUSINESS_EMAIL,
                    "email": "person@example.com",
                },
            )
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.OWNER_TIME_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "time_entry_id": opaque("tim", 1),
                    "category": OwnerTimeCategory.ADMIN,
                    "minutes": True,
                },
            )
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.OPTED_OUT,
                {"prospect_id": prospect_id, "note": "do not contact"},
            )
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                "UNKNOWN_EVENT",
                {"prospect_id": prospect_id},
            )

    def test_invalid_funnel_transitions_are_rejected(self) -> None:
        missing_prospect = opaque("prs", 999)
        with self.assertRaises(PilotValidationError):
            self.contact(missing_prospect)

        prospect_id = self.add_prospect(1)
        with self.assertRaises(PilotValidationError):
            self.record_interested_reply(prospect_id)
        with self.assertRaises(PilotValidationError):
            self.ledger.record(PilotEventType.SAMPLE_REQUESTED, {"prospect_id": prospect_id})
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.CHECKOUT_SENT,
                {"prospect_id": prospect_id, "checkout_ref": opaque("chk", 1)},
            )
        with self.assertRaises(PilotValidationError):
            self.purchase(prospect_id, 1)
        with self.assertRaises(PilotValidationError):
            self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        with self.assertRaises(PilotValidationError):
            self.ledger.record(PilotEventType.DELIVERED, {"prospect_id": prospect_id})

        self.contact(prospect_id)
        self.ledger.record(
            PilotEventType.REPLIED,
            {"prospect_id": prospect_id, "outcome": ReplyOutcome.DECLINED},
        )
        with self.assertRaises(PilotValidationError):
            self.ledger.record(PilotEventType.SAMPLE_REQUESTED, {"prospect_id": prospect_id})

    def test_opt_out_suppresses_contact_and_checkout(self) -> None:
        prospect_id = self.add_prospect(1)
        self.ledger.record(PilotEventType.OPTED_OUT, {"prospect_id": prospect_id})
        with self.assertRaisesRegex(PilotValidationError, "suppressed"):
            self.contact(prospect_id)
        with self.assertRaises(PilotValidationError):
            self.ledger.record(PilotEventType.OPTED_OUT, {"prospect_id": prospect_id})

        second = self.add_prospect(2)
        self.contact(second)
        self.record_interested_reply(second)
        self.ledger.record(PilotEventType.SAMPLE_REQUESTED, {"prospect_id": second})
        self.ledger.record(PilotEventType.OPTED_OUT, {"prospect_id": second})
        with self.assertRaisesRegex(PilotValidationError, "suppressed"):
            self.ledger.record(
                PilotEventType.CHECKOUT_SENT,
                {"prospect_id": second, "checkout_ref": opaque("chk", 2)},
            )

        self.ledger.record(
            PilotEventType.OWNER_TIME_RECORDED,
            {
                "prospect_id": second,
                "time_entry_id": opaque("tim", 2),
                "category": OwnerTimeCategory.SAMPLE,
                "minutes": 15,
            },
        )
        self.assertEqual(self.ledger.metrics().opt_outs, 2)

    def test_unique_identifiers_and_five_purchase_cap_survive_refund(self) -> None:
        prospects: list[str] = []
        for number in range(1, 7):
            prospect_id = self.add_prospect(number)
            prospects.append(prospect_id)
            self.contact(prospect_id)
            self.advance_to_checkout(prospect_id, number)

        self.purchase(prospects[0], 1)
        with self.assertRaisesRegex(PilotValidationError, "payment_ref must be unique"):
            self.ledger.record(
                PilotEventType.PURCHASED,
                {
                    "prospect_id": prospects[1],
                    "order_id": opaque("ord", 2),
                    "fee_cents": 317,
                },
                payment_evidence=payment_evidence(2, provider_number=1),
            )
        for number in range(2, 6):
            self.purchase(prospects[number - 1], number)
        self.refund(prospects[0], 1)
        with self.assertRaisesRegex(PilotValidationError, "five founding"):
            self.purchase(prospects[5], 6)
        self.assertEqual(self.ledger.metrics().purchases, 5)
        self.assertEqual(self.ledger.metrics().active_orders, 4)

    def test_only_full_refunds_are_accepted(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)

        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.REFUNDED,
                {
                    "prospect_id": prospect_id,
                    "order_id": opaque("ord", 1),
                },
            )
        with self.assertRaisesRegex(PilotValidationError, "evidence is invalid"):
            self.ledger.record(
                PilotEventType.REFUNDED,
                {
                    "prospect_id": prospect_id,
                    "order_id": opaque("ord", 2),
                },
                payment_evidence=payment_evidence(1, refund=True),
            )

        self.refund(prospect_id, 1)
        with self.assertRaises(PilotValidationError):
            self.refund(prospect_id, 2)
        metrics = self.ledger.metrics()
        self.assertEqual(metrics.refunds, 1)
        self.assertEqual(metrics.refunded_revenue_cents, 9_900)
        self.assertEqual(metrics.net_cash_cents, -317)
        self.assertEqual(metrics.refund_rate, 1.0)
        order = self.ledger.order(opaque("ord", 1))
        self.assertEqual(order.state, PilotOrderState.REFUNDED)
        self.assertEqual(order.refund_ref, opaque("rfd", 1))
        self.assertEqual(order.refund_evidence_artifact_sha256, f"{201:064x}")

    def test_purchase_price_and_owner_time_rules_are_enforced(self) -> None:
        prospect_id = self.add_prospect(1)
        with self.assertRaisesRegex(PilotValidationError, "sample time"):
            self.ledger.record(
                PilotEventType.OWNER_TIME_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "time_entry_id": opaque("tim", 1),
                    "category": OwnerTimeCategory.SAMPLE,
                    "minutes": 30,
                },
            )
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.PURCHASED,
                {
                    "prospect_id": prospect_id,
                    "order_id": opaque("ord", 1),
                    "amount_cents": 9_899,
                    "fee_cents": 317,
                },
                payment_evidence=payment_evidence(1),
            )
        self.purchase(prospect_id, 1)
        self.accept_order(prospect_id, 1)
        fulfillment_time = {
            "prospect_id": prospect_id,
            "time_entry_id": opaque("tim", 2),
            "category": OwnerTimeCategory.FULFILLMENT,
            "minutes": 30,
        }
        with self.assertRaisesRegex(PilotValidationError, "requires fulfillment to start"):
            self.ledger.record(PilotEventType.OWNER_TIME_RECORDED, fulfillment_time)
        self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        self.ledger.record(PilotEventType.OWNER_TIME_RECORDED, fulfillment_time)

    def test_purchase_requires_validated_live_evidence(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        base_payload = {
            "prospect_id": prospect_id,
            "order_id": opaque("ord", 1),
            "fee_cents": 317,
        }
        with self.assertRaisesRegex(PilotValidationError, "validated live payment evidence"):
            self.ledger.record(
                PilotEventType.PURCHASED,
                base_payload,
            )
        with self.assertRaisesRegex(PilotValidationError, "PAYMENT_CAPTURED"):
            self.ledger.record(
                PilotEventType.PURCHASED,
                base_payload,
                payment_evidence=payment_evidence(1, refund=True),
            )
        self.ledger.record(
            PilotEventType.PURCHASED,
            base_payload,
            payment_evidence=payment_evidence(1),
        )
        self.assertEqual(self.ledger.metrics().booked_revenue_cents, 9_900)

    def test_tax_inclusive_purchase_and_full_gross_refund_project_truthfully(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)

        self.purchase(prospect_id, 1, tax_amount_cents=693)
        purchased = self.ledger.order(opaque("ord", 1))

        self.assertEqual(purchased.amount_cents, 9_900)
        self.assertEqual(purchased.tax_amount_cents, 693)
        self.assertEqual(purchased.gross_amount_cents, 10_593)
        self.assertIsNone(purchased.refunded_amount_cents)
        self.assertEqual(purchased.provider_purchase_sha256, f"{1001:064x}")
        self.assertEqual(self.ledger.metrics().booked_revenue_cents, 9_900)

        self.refund(prospect_id, 1, tax_amount_cents=693)
        refunded = self.ledger.order(opaque("ord", 1))

        self.assertEqual(refunded.state, PilotOrderState.REFUNDED)
        self.assertEqual(refunded.gross_amount_cents, 10_593)
        self.assertEqual(refunded.refunded_amount_cents, 10_593)
        self.assertEqual(refunded.provider_purchase_sha256, f"{1001:064x}")
        self.assertEqual(self.ledger.metrics().refunded_revenue_cents, 9_900)

        manifest_path = Path(self.temporary_directory.name) / "tax-refund-order.json"
        write_order_manifest(
            manifest_path,
            refunded,
            ledger_head_sha256=self.ledger.head,
        )
        self.assertEqual(load_order_manifest(manifest_path), refunded)

    def test_provider_purchase_digest_is_unique_but_artifact_domain_is_independent(
        self,
    ) -> None:
        first = self.add_prospect(1)
        self.contact(first)
        self.advance_to_checkout(first, 1)
        provider_digest = f"{1001:064x}"
        self.ledger.record(
            PilotEventType.PURCHASED,
            {
                "prospect_id": first,
                "order_id": opaque("ord", 1),
                "fee_cents": 317,
            },
            payment_evidence=payment_evidence(
                1,
                artifact_sha256=provider_digest,
                provider_purchase_sha256=provider_digest,
            ),
        )

        second = self.add_prospect(2)
        self.contact(second)
        self.advance_to_checkout(second, 2)
        with self.assertRaisesRegex(
            PilotValidationError,
            "provider_purchase_sha256 must be unique",
        ):
            self.ledger.record(
                PilotEventType.PURCHASED,
                {
                    "prospect_id": second,
                    "order_id": opaque("ord", 2),
                    "fee_cents": 317,
                },
                payment_evidence=payment_evidence(
                    2,
                    provider_purchase_sha256=provider_digest,
                ),
            )

    def test_rejected_order_allows_refund_suppression_and_bookkeeping(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)
        self.ledger.record(
            PilotEventType.ORDER_REJECTED,
            {
                "prospect_id": prospect_id,
                "order_rejection_ref": opaque("orj", 1),
            },
        )
        self.assertEqual(
            self.ledger.order(opaque("ord", 1)).state,
            PilotOrderState.ORDER_REJECTED,
        )
        self.assertEqual(self.ledger.metrics().active_orders, 0)
        for event, payload in (
            (
                PilotEventType.ORDER_ACCEPTED,
                {
                    "prospect_id": prospect_id,
                    "scope_ref": opaque("scp", 1),
                    "order_acceptance_ref": opaque("oac", 1),
                    "acceptance_evidence_sha256": ORDER_ACCEPTANCE_EVIDENCE_SHA256,
                },
            ),
            (
                PilotEventType.CANCELLATION_REQUESTED,
                {
                    "prospect_id": prospect_id,
                    "cancellation_ref": opaque("can", 1),
                },
            ),
            (
                PilotEventType.FULFILLMENT_STARTED,
                {"prospect_id": prospect_id},
            ),
        ):
            with (
                self.subTest(event=event),
                self.assertRaisesRegex(PilotValidationError, "allows only"),
            ):
                self.ledger.record(event, payload)
        self.ledger.record(PilotEventType.OPTED_OUT, {"prospect_id": prospect_id})
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.CONTACTED,
                {
                    "prospect_id": prospect_id,
                    "channel": ContactChannel.BUSINESS_EMAIL,
                },
            )
        self.refund(prospect_id, 1)
        self.assertEqual(
            self.ledger.order(opaque("ord", 1)).state,
            PilotOrderState.REFUNDED,
        )

    def test_cancellation_blocks_new_and_continuing_fulfillment(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)
        self.accept_order(prospect_id, 1)
        self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        self.complete_artifact(prospect_id)
        self.ledger.record(
            PilotEventType.CANCELLATION_REQUESTED,
            {
                "prospect_id": prospect_id,
                "cancellation_ref": opaque("can", 1),
            },
        )
        with self.assertRaisesRegex(PilotValidationError, "blocked after cancellation"):
            self.ledger.record(
                PilotEventType.DELIVERED,
                {
                    "prospect_id": prospect_id,
                    "order_id": opaque("ord", 1),
                },
                delivery_evidence=delivery_evidence(1),
            )
        with self.assertRaisesRegex(PilotValidationError, "blocked after cancellation"):
            self.ledger.record(
                PilotEventType.OWNER_TIME_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "time_entry_id": opaque("tim", 1),
                    "category": OwnerTimeCategory.FULFILLMENT,
                    "minutes": 5,
                },
            )
        order = self.ledger.order(opaque("ord", 1))
        self.assertEqual(order.state, PilotOrderState.CANCELLATION_REQUESTED)
        self.assertEqual(order.cancellation_ref, opaque("can", 1))
        self.assertEqual(self.ledger.metrics().cancellation_requests, 1)
        self.assertEqual(self.ledger.metrics().active_orders, 0)

        second = self.add_prospect(2)
        self.contact(second)
        self.advance_to_checkout(second, 2)
        self.purchase(second, 2)
        self.accept_order(second, 2)
        self.ledger.record(
            PilotEventType.CANCELLATION_REQUESTED,
            {"prospect_id": second, "cancellation_ref": opaque("can", 2)},
        )
        with self.assertRaisesRegex(PilotValidationError, "blocked after cancellation"):
            self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": second})

    def test_scope_is_required_and_rejects_free_form_fields(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        with self.assertRaisesRegex(PilotValidationError, "sample request"):
            self.confirm_scope(prospect_id, 1)
        self.advance_to_sample(prospect_id)
        invalid_scopes = (
            {
                "prospect_id": prospect_id,
                "scope_ref": "scope_for_person",
                "deadline": "2026-09-15",
                "terms_version": "creator-desk-v1",
                "claim_ids": ["CLM-0001"],
            },
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", 1),
                "deadline": "September 15",
                "terms_version": "creator-desk-v1",
                "claim_ids": ["CLM-0001"],
            },
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", 1),
                "deadline": "2026-09-15",
                "terms_version": "https://example.com/terms",
                "claim_ids": ["CLM-0001"],
            },
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", 1),
                "deadline": "2026-09-15",
                "terms_version": "creator-desk-v1",
                "claim_ids": [],
            },
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", 1),
                "deadline": "2026-09-15",
                "terms_version": "creator-desk-v1",
                "claim_ids": ["claim about a person"],
            },
        )
        for payload in invalid_scopes:
            with self.subTest(payload=payload), self.assertRaises(PilotValidationError):
                self.ledger.record(PilotEventType.SCOPE_CONFIRMED, payload)

        self.confirm_scope(prospect_id, 1)
        with self.assertRaises(PilotValidationError):
            self.confirm_scope(prospect_id, 2)
        with self.assertRaisesRegex(PilotValidationError, "written customer acceptance"):
            self.ledger.record(
                PilotEventType.CHECKOUT_SENT,
                {"prospect_id": prospect_id, "checkout_ref": opaque("chk", 1)},
            )
        with self.assertRaisesRegex(PilotValidationError, "lowercase SHA-256"):
            self.ledger.record(
                PilotEventType.CUSTOMER_ACCEPTANCE_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "scope_ref": opaque("scp", 1),
                    "customer_acceptance_ref": opaque("cac", 1),
                    "acceptance_evidence_sha256": "C" * 64,
                },
            )
        self.record_customer_acceptance(prospect_id, 1)
        self.ledger.record(
            PilotEventType.CHECKOUT_SENT,
            {"prospect_id": prospect_id, "checkout_ref": opaque("chk", 1)},
        )
        self.purchase(prospect_id, 1)
        with self.assertRaisesRegex(PilotValidationError, "post-payment"):
            self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        self.assertEqual(self.ledger.metrics().scopes_confirmed, 1)

    def test_scope_amendment_invalidates_stale_acceptance(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_sample(prospect_id)
        self.confirm_scope(prospect_id, 1)
        self.record_customer_acceptance(prospect_id, 1)

        with self.assertRaisesRegex(PilotValidationError, "active scope"):
            self.ledger.record(
                PilotEventType.SCOPE_AMENDED,
                {
                    "prospect_id": prospect_id,
                    "supersedes_scope_ref": opaque("scp", 9),
                    "scope_ref": opaque("scp", 2),
                    "deadline": "2026-09-20",
                    "terms_version": "creator-desk-v2",
                    "claim_ids": ["CLM-0002"],
                },
            )

        self.amend_scope(prospect_id, 1, 2)
        with self.assertRaisesRegex(PilotValidationError, "written customer acceptance"):
            self.ledger.record(
                PilotEventType.CHECKOUT_SENT,
                {"prospect_id": prospect_id, "checkout_ref": opaque("chk", 1)},
            )
        with self.assertRaisesRegex(PilotValidationError, "active scope"):
            self.ledger.record(
                PilotEventType.CUSTOMER_ACCEPTANCE_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "scope_ref": opaque("scp", 1),
                    "customer_acceptance_ref": opaque("cac", 2),
                    "acceptance_evidence_sha256": "e" * 64,
                },
            )
        self.record_customer_acceptance(prospect_id, 2)
        self.ledger.record(
            PilotEventType.CHECKOUT_SENT,
            {"prospect_id": prospect_id, "checkout_ref": opaque("chk", 1)},
        )

    def test_post_checkout_scope_amendment_blocks_purchase_until_reaccepted(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.amend_scope(prospect_id, 1, 2)

        with self.assertRaisesRegex(PilotValidationError, "active scope"):
            self.purchase(prospect_id, 1)
        self.record_customer_acceptance(prospect_id, 2)
        self.purchase(prospect_id, 1)

    def test_post_purchase_scope_amendment_requires_both_fresh_acceptances(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)
        self.accept_order(prospect_id, 1)
        self.amend_scope(prospect_id, 1, 2)

        with self.assertRaisesRegex(PilotValidationError, "post-payment"):
            self.ledger.record(
                PilotEventType.FULFILLMENT_STARTED,
                {"prospect_id": prospect_id},
            )
        self.record_customer_acceptance(prospect_id, 2)
        with self.assertRaisesRegex(PilotValidationError, "post-payment"):
            self.ledger.record(
                PilotEventType.FULFILLMENT_STARTED,
                {"prospect_id": prospect_id},
            )
        self.accept_order(prospect_id, 2)
        self.ledger.record(
            PilotEventType.FULFILLMENT_STARTED,
            {"prospect_id": prospect_id},
        )
        with self.assertRaisesRegex(PilotValidationError, "after fulfillment"):
            self.amend_scope(prospect_id, 2, 3)

    def test_artifact_completion_requires_lowercase_sha256_digest(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)
        self.accept_order(prospect_id, 1)
        self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        for digest in ("a" * 63, "A" * 64, "not-a-hash"):
            with self.subTest(digest=digest), self.assertRaises(PilotValidationError):
                self.ledger.record(
                    PilotEventType.ARTIFACT_COMPLETED,
                    {
                        "prospect_id": prospect_id,
                        "deliverable_sha256": digest,
                    },
                )
        self.complete_artifact(prospect_id)
        self.assertEqual(
            self.ledger.order(opaque("ord", 1)).state,
            PilotOrderState.ARTIFACT_COMPLETED,
        )

    def test_feedback_is_enumerated_and_requires_delivery(self) -> None:
        prospect_id = self.add_prospect(1)
        with self.assertRaisesRegex(PilotValidationError, "delivery"):
            self.ledger.record(
                PilotEventType.FEEDBACK_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "feedback_id": opaque("fbk", 1),
                    "outcomes": [FeedbackOutcome.SAVED_TIME],
                },
            )

        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)
        self.accept_order(prospect_id, 1)
        self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        self.complete_artifact(prospect_id)
        self.deliver(prospect_id, 1)
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.FEEDBACK_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "feedback_id": opaque("fbk", 1),
                    "outcomes": ["It was great"],
                },
            )
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.FEEDBACK_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "feedback_id": opaque("fbk", 1),
                    "outcomes": [
                        FeedbackOutcome.NONE_REPORTED,
                        FeedbackOutcome.SAVED_TIME,
                    ],
                },
            )

    def test_decision_gates_follow_the_fifty_prospect_playbook(self) -> None:
        campaign_start = datetime.now(UTC).date() - timedelta(days=6)
        self.ledger.import_outreach_plan(
            qualified_outreach_plan(campaign_start),
            occurred_at=f"{campaign_start.isoformat()}T00:00:00+00:00",
        )
        prospects = [opaque("prs", number) for number in range(1, 51)]
        for number, prospect_id in enumerate(prospects, 1):
            contact_date = campaign_start + timedelta(days=2 + (number - 1) // 10)
            occurred_at = f"{contact_date.isoformat()}T00:00:00+00:00"
            self.ledger.record(
                PilotEventType.SUPPRESSION_CHECKED,
                {
                    "prospect_id": prospect_id,
                    "status": "CLEAR",
                    "evidence_sha256": f"{20_000 + number:064x}",
                    "evidence_observed_at": occurred_at,
                },
                occurred_at=occurred_at,
            )
            contact_evidence = ContactEvidence(
                prospect_id=prospect_id,
                channel=ContactChannel.BUSINESS_EMAIL.value,
                sender_profile_evidence_sha256=f"{30_000:064x}",
                suppression_evidence_sha256=f"{20_000 + number:064x}",
                message_copy_sha256=f"{31_000 + number:064x}",
                provider_send_evidence_sha256=f"{32_000 + number:064x}",
                provider_message_sha256=f"{33_000 + number:064x}",
                observed_at=occurred_at.replace("+00:00", "Z"),
            )
            self.ledger.record(
                PilotEventType.CONTACTED,
                {
                    "prospect_id": prospect_id,
                    "channel": ContactChannel.BUSINESS_EMAIL,
                },
                occurred_at=occurred_at,
                contact_evidence=contact_evidence,
            )
        for prospect_id in prospects[:4]:
            self.record_interested_reply(prospect_id)
        self.assertEqual(self.ledger.metrics().decision_gate, DecisionGate.STOP_THIS_MOTION)

        self.record_interested_reply(prospects[4])
        self.assertEqual(
            self.ledger.metrics().decision_gate,
            DecisionGate.REVISE_OFFER_OR_TARGET,
        )

        for number, prospect_id in enumerate(prospects[:2], 1):
            self.ledger.record(PilotEventType.SAMPLE_REQUESTED, {"prospect_id": prospect_id})
            self.confirm_scope(prospect_id, number)
            self.record_customer_acceptance(prospect_id, number)
            self.ledger.record(
                PilotEventType.CHECKOUT_SENT,
                {"prospect_id": prospect_id, "checkout_ref": opaque("chk", number)},
            )
            self.purchase(prospect_id, number)
        self.assertEqual(
            self.ledger.metrics().decision_gate,
            DecisionGate.CONTINUE_AND_REPRICE,
        )

        for number, prospect_id in enumerate(prospects[:2], 1):
            self.refund(prospect_id, number)
        self.assertEqual(self.ledger.metrics().decision_gate, DecisionGate.REVIEW_REQUIRED)

        self.ledger.record(
            PilotEventType.RISK_INCIDENT_RECORDED,
            {
                "incident_id": opaque("inc", 1),
                "prospect_id": prospects[0],
                "kind": RiskKind.SOURCE_RIGHTS,
                "severity": RiskSeverity.MATERIAL,
            },
        )
        self.assertEqual(
            self.ledger.metrics().decision_gate,
            DecisionGate.PAUSE_IMMEDIATELY,
        )

    def test_unplanned_contacts_cannot_cross_the_qualification_gate(self) -> None:
        for number in range(1, 51):
            prospect_id = self.add_prospect(number)
            self.contact(prospect_id)

        self.assertEqual(
            self.ledger.metrics().decision_gate,
            DecisionGate.QUALIFICATION_PLAN_REQUIRED,
        )

    def test_global_risk_incident_is_allowed_without_personal_data(self) -> None:
        self.ledger.record(
            PilotEventType.RISK_INCIDENT_RECORDED,
            {
                "incident_id": opaque("inc", 1),
                "kind": RiskKind.PAYMENT_IDENTITY,
                "severity": RiskSeverity.CRITICAL,
            },
        )
        metrics = self.ledger.metrics()
        self.assertEqual(metrics.risk_incidents, 1)
        self.assertEqual(metrics.decision_gate, DecisionGate.PAUSE_IMMEDIATELY)
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.RISK_INCIDENT_RECORDED,
                {
                    "incident_id": opaque("inc", 1),
                    "kind": RiskKind.REFUND_HANDLING,
                    "severity": RiskSeverity.MATERIAL,
                },
            )

    def test_order_manifest_round_trip_is_ledger_anchored_and_private(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)
        self.accept_order(prospect_id, 1)
        self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        self.complete_artifact(prospect_id)
        self.deliver(prospect_id, 1)
        order = self.ledger.order(opaque("ord", 1))
        manifest_path = Path(self.temporary_directory.name) / "order-manifest.json"
        manifest_digest = write_order_manifest(
            manifest_path,
            order,
            ledger_head_sha256=self.ledger.head,
        )

        self.assertRegex(manifest_digest, r"^[0-9a-f]{64}$")
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
        self.assertEqual(load_order_manifest(manifest_path), order)
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(raw["schema_version"], 5)
        self.assertEqual(
            set(raw),
            {"schema_version", "ledger_head_sha256", "order", "manifest_sha256"},
        )
        self.assertEqual(raw["ledger_head_sha256"], self.ledger.head)
        self.assertEqual(
            set(raw["order"]),
            {
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
            },
        )

    def test_order_manifest_detects_hash_and_schema_tampering(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)
        order = self.ledger.order(opaque("ord", 1))
        manifest_path = Path(self.temporary_directory.name) / "order-manifest.json"
        write_order_manifest(
            manifest_path,
            order,
            ledger_head_sha256=self.ledger.head,
        )

        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw["order"]["amount_cents"] = 1
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(PilotManifestError, "digest mismatch"):
            load_order_manifest(manifest_path)

        write_order_manifest(
            manifest_path,
            order,
            ledger_head_sha256=self.ledger.head,
        )
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw["order"]["email"] = "person@example.com"
        body = {
            "schema_version": raw["schema_version"],
            "ledger_head_sha256": raw["ledger_head_sha256"],
            "order": raw["order"],
        }
        raw["manifest_sha256"] = sha256_json(body)
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(PilotManifestError, "projection is invalid"):
            load_order_manifest(manifest_path)

        write_order_manifest(
            manifest_path,
            order,
            ledger_head_sha256=self.ledger.head,
        )
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw["schema_version"] = 4
        body = {
            "schema_version": raw["schema_version"],
            "ledger_head_sha256": raw["ledger_head_sha256"],
            "order": raw["order"],
        }
        raw["manifest_sha256"] = sha256_json(body)
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(PilotManifestError, "schema version is unsupported"):
            load_order_manifest(manifest_path)

    def test_order_manifest_rejects_symbolic_link_ancestors(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        self.purchase(prospect_id, 1)
        order = self.ledger.order(opaque("ord", 1))
        root = Path(self.temporary_directory.name)
        outside = root / "outside"
        outside.mkdir()
        linked = root / "linked"
        try:
            linked.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symbolic links are unavailable: {exc}")

        with self.assertRaisesRegex(PilotManifestError, "symbolic-link ancestors"):
            write_order_manifest(
                linked / "order.json",
                order,
                ledger_head_sha256=self.ledger.head,
            )
        self.assertEqual(list(outside.iterdir()), [])

        real_manifest = outside / "order.json"
        write_order_manifest(
            real_manifest,
            order,
            ledger_head_sha256=self.ledger.head,
        )
        with self.assertRaisesRegex(PilotManifestError, "symbolic-link ancestors"):
            load_order_manifest(linked / "order.json")

    def test_order_projection_rejects_unknown_order(self) -> None:
        with self.assertRaisesRegex(PilotValidationError, "unknown"):
            self.ledger.order(opaque("ord", 999))

    def test_hash_tampering_fails_closed(self) -> None:
        prospect_id = self.add_prospect(1)
        records = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]
        records[1]["payload"]["segment"] = ProspectSegment.PODCAST
        self.path.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            encoding="utf-8",
        )

        with self.assertRaises(PilotReplayError):
            self.ledger.metrics()
        with self.assertRaises(PilotReplayError):
            self.ledger.record(PilotEventType.OPTED_OUT, {"prospect_id": prospect_id})
        with self.assertRaises(PilotReplayError):
            PilotLedger(self.path)

    def test_semantically_invalid_but_hash_valid_event_fails_closed(self) -> None:
        HashLedger(self.path, mode=0o600).append(
            PilotEventType.DELIVERED,
            {"prospect_id": opaque("prs", 1)},
            occurred_at="2026-08-29T12:00:00+00:00",
        )
        with self.assertRaisesRegex(PilotReplayError, "index 1"):
            PilotLedger(self.path)

    def test_existing_empty_ledger_fails_closed(self) -> None:
        empty_path = Path(self.temporary_directory.name) / "empty.jsonl"
        empty_path.touch(mode=0o600)
        with self.assertRaisesRegex(PilotReplayError, "empty"):
            PilotLedger(empty_path)

    def test_legacy_ledgers_are_read_only_migration_evidence(self) -> None:
        for schema_version in (1, 2):
            with self.subTest(schema_version=schema_version):
                legacy_path = (
                    Path(self.temporary_directory.name) / f"legacy-v{schema_version}.jsonl"
                )
                HashLedger(legacy_path, mode=0o600).append(
                    PilotEventType.PILOT_LEDGER_INITIALIZED,
                    {"schema_version": schema_version},
                    occurred_at="1970-01-01T00:00:00+00:00",
                )
                with self.assertRaisesRegex(
                    PilotReplayError,
                    f"schema version {schema_version} is read-only",
                ):
                    PilotLedger(legacy_path)

    def test_schema_three_is_readable_reconcilable_and_read_only(self) -> None:
        legacy_path = Path(self.temporary_directory.name) / "legacy-v3.jsonl"
        legacy = HashLedger(legacy_path, mode=0o600)
        legacy.append(
            PilotEventType.PILOT_LEDGER_INITIALIZED,
            {
                "schema_version": 3,
                "prior_consumed_slots": 0,
                "reconciliation_evidence_sha256": RECONCILIATION_EVIDENCE_SHA256,
            },
            occurred_at="1970-01-01T00:00:00+00:00",
        )
        for number in range(901, 951):
            prospect_id = opaque("prs", number)
            legacy.append(
                PilotEventType.PROSPECT_ADDED,
                {
                    "prospect_id": prospect_id,
                    "segment": ProspectSegment.PODCAST.value,
                },
                occurred_at="2026-08-29T12:00:00+00:00",
            )
            legacy.append(
                PilotEventType.CONTACTED,
                {
                    "prospect_id": prospect_id,
                    "channel": ContactChannel.BUSINESS_EMAIL.value,
                },
                occurred_at="2026-08-29T12:00:00+00:00",
            )

        opened = PilotLedger(legacy_path)

        metrics = opened.metrics()
        self.assertEqual(metrics.prospects, 50)
        self.assertEqual(metrics.contacted, 50)
        self.assertEqual(metrics.decision_gate, DecisionGate.STOP_THIS_MOTION)
        consumed_slots, prior_head = PilotLedger.reconcile_prior_ledger(legacy_path)
        self.assertEqual(consumed_slots, 0)
        self.assertEqual(prior_head, opened.head)
        with self.assertRaisesRegex(
            PilotValidationError,
            "schema version 3 is read-only",
        ):
            opened.record(
                PilotEventType.OPTED_OUT,
                {"prospect_id": opaque("prs", 901)},
                occurred_at="2026-08-29T13:00:00+00:00",
            )

    def test_schema_four_is_readable_reconcilable_and_read_only(self) -> None:
        legacy_path = Path(self.temporary_directory.name) / "legacy-v4.jsonl"
        legacy = HashLedger(legacy_path, mode=0o600)
        legacy.append(
            PilotEventType.PILOT_LEDGER_INITIALIZED,
            {
                "schema_version": 4,
                "prior_consumed_slots": 0,
                "reconciliation_evidence_sha256": RECONCILIATION_EVIDENCE_SHA256,
            },
            occurred_at="1970-01-01T00:00:00+00:00",
        )
        legacy.append(
            PilotEventType.PROSPECT_ADDED,
            {
                "prospect_id": opaque("prs", 990),
                "segment": ProspectSegment.PODCAST.value,
            },
            occurred_at="2026-08-29T12:00:00+00:00",
        )

        opened = PilotLedger(legacy_path)
        snapshot = PilotLedger.prior_ledger_snapshot(legacy_path)

        self.assertEqual(opened.metrics().prospects, 1)
        self.assertEqual(snapshot.ledger_schema_version, 4)
        self.assertEqual(snapshot.ledger_head_sha256, opened.head)
        self.assertEqual(snapshot.lifetime_consumed_slots, 0)
        with self.assertRaisesRegex(
            PilotValidationError,
            "schema version 4 is read-only",
        ):
            opened.record(
                PilotEventType.OPTED_OUT,
                {"prospect_id": opaque("prs", 990)},
                occurred_at="2026-08-29T13:00:00+00:00",
            )

    def test_schema_three_rejects_schema_four_events_and_relaxed_lineage(self) -> None:
        incompatible_path = Path(self.temporary_directory.name) / "legacy-v3-incompatible.jsonl"
        incompatible = HashLedger(incompatible_path, mode=0o600)
        incompatible.append(
            PilotEventType.PILOT_LEDGER_INITIALIZED,
            {
                "schema_version": 3,
                "prior_consumed_slots": 0,
                "reconciliation_evidence_sha256": RECONCILIATION_EVIDENCE_SHA256,
            },
            occurred_at="1970-01-01T00:00:00+00:00",
        )
        plan = qualified_outreach_plan(date(2026, 9, 1))
        incompatible.append(
            PilotEventType.OUTREACH_PLAN_IMPORTED,
            {**plan.to_dict(), "plan_sha256": plan.sha256},
            occurred_at="2026-09-01T12:00:00+00:00",
        )
        with self.assertRaisesRegex(PilotReplayError, "index 1"):
            PilotLedger(incompatible_path)

        expanded_payload_path = (
            Path(self.temporary_directory.name) / "legacy-v3-expanded-payload.jsonl"
        )
        expanded_payload = HashLedger(expanded_payload_path, mode=0o600)
        expanded_payload.append(
            PilotEventType.PILOT_LEDGER_INITIALIZED,
            {
                "schema_version": 3,
                "prior_consumed_slots": 0,
                "reconciliation_evidence_sha256": RECONCILIATION_EVIDENCE_SHA256,
            },
            occurred_at="1970-01-01T00:00:00+00:00",
        )
        expanded_payload.append(
            PilotEventType.PROSPECT_ADDED,
            {
                "prospect_id": opaque("prs", 903),
                "segment": ProspectSegment.PODCAST.value,
            },
            occurred_at="2026-08-29T12:00:00+00:00",
        )
        expanded_payload.append(
            PilotEventType.OPTED_OUT,
            {
                "prospect_id": opaque("prs", 903),
                "evidence_sha256": "2" * 64,
            },
            occurred_at="2026-08-29T12:01:00+00:00",
        )
        with self.assertRaisesRegex(PilotReplayError, "index 2"):
            PilotLedger(expanded_payload_path)

        relaxed_path = Path(self.temporary_directory.name) / "legacy-v3-relaxed.jsonl"
        HashLedger(relaxed_path, mode=0o600).append(
            PilotEventType.PILOT_LEDGER_INITIALIZED,
            {
                "schema_version": 3,
                "prior_consumed_slots": 0,
                "reconciliation_evidence_sha256": RECONCILIATION_EVIDENCE_SHA256,
                "prior_ledger_head_sha256": "1" * 64,
            },
            occurred_at="1970-01-01T00:00:00+00:00",
        )
        with self.assertRaisesRegex(PilotReplayError, "index 0"):
            PilotLedger(relaxed_path)

    def test_ledger_without_initialization_fails_closed(self) -> None:
        path = Path(self.temporary_directory.name) / "uninitialized.jsonl"
        HashLedger(path, mode=0o600).append(
            PilotEventType.PROSPECT_ADDED,
            {
                "prospect_id": opaque("prs", 902),
                "segment": ProspectSegment.PODCAST.value,
            },
            occurred_at="2026-08-29T12:00:00+00:00",
        )

        with self.assertRaisesRegex(PilotReplayError, "index 0"):
            PilotLedger(path)

    def test_external_evidence_observation_chronology_is_enforced(self) -> None:
        prospect_id = self.add_prospect(1)
        self.contact(prospect_id)
        self.advance_to_checkout(prospect_id, 1)
        purchase_payload = {
            "prospect_id": prospect_id,
            "order_id": opaque("ord", 1),
            "fee_cents": 317,
        }
        with self.assertRaisesRegex(PilotValidationError, "after checkout"):
            self.ledger.record(
                PilotEventType.PURCHASED,
                purchase_payload,
                payment_evidence=payment_evidence(
                    1,
                    observed_at="2000-01-01T00:00:00Z",
                ),
            )
        with self.assertRaisesRegex(PilotValidationError, "after the purchase event"):
            self.ledger.record(
                PilotEventType.PURCHASED,
                purchase_payload,
                payment_evidence=payment_evidence(
                    1,
                    observed_at="2099-01-01T00:00:00Z",
                ),
            )

        self.purchase(prospect_id, 1)
        with self.assertRaisesRegex(PilotValidationError, "after payment capture"):
            self.ledger.record(
                PilotEventType.REFUNDED,
                {"prospect_id": prospect_id, "order_id": opaque("ord", 1)},
                payment_evidence=payment_evidence(
                    1,
                    refund=True,
                    observed_at="2000-01-01T00:00:00Z",
                ),
            )

        self.accept_order(prospect_id, 1)
        self.ledger.record(
            PilotEventType.FULFILLMENT_STARTED,
            {"prospect_id": prospect_id},
        )
        self.complete_artifact(prospect_id)
        with self.assertRaisesRegex(PilotValidationError, "after artifact completion"):
            self.ledger.record(
                PilotEventType.DELIVERED,
                {"prospect_id": prospect_id, "order_id": opaque("ord", 1)},
                delivery_evidence=delivery_evidence(
                    1,
                    observed_at="2000-01-01T00:00:00Z",
                ),
            )
        with self.assertRaisesRegex(PilotValidationError, "after the delivery event"):
            self.ledger.record(
                PilotEventType.DELIVERED,
                {"prospect_id": prospect_id, "order_id": opaque("ord", 1)},
                delivery_evidence=delivery_evidence(
                    1,
                    observed_at="2099-01-01T00:00:00Z",
                ),
            )

    def test_source_evidence_artifact_cannot_be_reused(self) -> None:
        first = self.add_prospect(1)
        self.contact(first)
        self.advance_to_checkout(first, 1)
        self.purchase(first, 1)

        second = self.add_prospect(2)
        self.contact(second)
        self.advance_to_checkout(second, 2)
        with self.assertRaisesRegex(
            PilotValidationError,
            "payment_evidence_artifact_sha256 must be unique",
        ):
            self.ledger.record(
                PilotEventType.PURCHASED,
                {
                    "prospect_id": second,
                    "order_id": opaque("ord", 2),
                    "fee_cents": 317,
                },
                payment_evidence=payment_evidence(
                    2,
                    artifact_sha256=f"{1:064x}",
                ),
            )

    def test_timestamp_must_be_aware_and_monotonic(self) -> None:
        prospect_id = opaque("prs", 1)
        with self.assertRaises(PilotValidationError):
            self.ledger.record(
                PilotEventType.PROSPECT_ADDED,
                {
                    "prospect_id": prospect_id,
                    "segment": ProspectSegment.NEWSLETTER,
                },
                occurred_at="2026-08-29T12:00:00",
            )
        self.ledger.record(
            PilotEventType.PROSPECT_ADDED,
            {"prospect_id": prospect_id, "segment": ProspectSegment.NEWSLETTER},
            occurred_at="2026-08-29T12:00:00Z",
        )
        with self.assertRaisesRegex(PilotValidationError, "backward"):
            self.ledger.record(
                PilotEventType.CONTACTED,
                {
                    "prospect_id": prospect_id,
                    "channel": ContactChannel.CONTACT_FORM,
                },
                occurred_at="2026-08-29T11:59:59Z",
            )

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symbolic links are unavailable")
    def test_symbolic_link_ledger_is_rejected(self) -> None:
        target = Path(self.temporary_directory.name) / "target.jsonl"
        target.write_text("", encoding="utf-8")
        link = Path(self.temporary_directory.name) / "link.jsonl"
        try:
            link.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symbolic links are unavailable: {exc}")
        with self.assertRaises(PilotLedgerError):
            PilotLedger(link)


if __name__ == "__main__":
    unittest.main()
