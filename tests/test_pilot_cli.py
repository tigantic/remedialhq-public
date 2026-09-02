from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from remedialhq.cli import _parser, _pilot
from remedialhq.contact_evidence import ContactEvidence, private_file_sha256
from remedialhq.delivery_evidence import build_delivery_evidence
from remedialhq.payment_evidence import build_live_payment_evidence
from remedialhq.pilots import (
    ContactChannel,
    OpaqueIdKind,
    PilotEventType,
    PilotLedger,
    PilotOrderState,
    PilotValidationError,
    ProspectSegment,
    ReplyOutcome,
    load_order_manifest,
)
from tests.pilot_reconciliation_support import (
    reconciliation_document,
    reconciliation_evidence,
)


def opaque(prefix: str, number: int) -> str:
    return f"{prefix}_{number:032x}"


CUSTOMER_ACCEPTANCE_EVIDENCE_SHA256 = "c" * 64
ORDER_ACCEPTANCE_EVIDENCE_SHA256 = "d" * 64
RECONCILIATION_EVIDENCE_SHA256 = "f" * 64


def payment_document(number: int, *, refund: bool = False) -> dict[str, object]:
    order_id = opaque("ord", number)
    document: dict[str, object] = {
        "schema_version": "remedialhq.live-payment-evidence.v2",
        "event_type": "FULL_REFUND" if refund else "PAYMENT_CAPTURED",
        "provider": "STRIPE",
        "mode": "LIVE",
        "livemode": True,
        "status": "SUCCEEDED",
        "currency": "USD",
        "amount_cents": 9_900,
        "tax_amount_cents": 0,
        "gross_amount_cents": 9_900,
        "payment_type": "ONE_TIME",
        "order_id": order_id,
        "observed_at": datetime.now(UTC).isoformat(),
        "evidence_ref": opaque("evd", 100 + number if refund else number),
        "provider_ref": opaque("rfd" if refund else "pay", number),
        "provider_purchase_sha256": f"{1000 + number:064x}",
        "artifact_sha256": f"{100 + number if refund else number:064x}",
    }
    if refund:
        document["original_payment_ref"] = opaque("pay", number)
        document["refunded_amount_cents"] = 9_900
    return document


class PilotCliTests(unittest.TestCase):
    def setUp(self) -> None:
        secure_temp_root = "/tmp" if Path("/tmp").is_dir() else None
        self.temporary_directory = tempfile.TemporaryDirectory(dir=secure_temp_root)
        self.root = Path(self.temporary_directory.name)
        self.ledger_path = self.root / "pilot.jsonl"
        self.ledger = PilotLedger.initialize(
            self.ledger_path,
            reconciliation_evidence=reconciliation_evidence(),
        )
        self.sender_profile_path = self.root / "sender-profile.json"
        self.sender_profile_path.write_text('{"status":"verified"}\n', encoding="utf-8")
        self.sender_profile_path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_pilot(self, *arguments: str) -> tuple[int, str]:
        args = _parser().parse_args(["pilot", *arguments, "--ledger", str(self.ledger_path)])
        output = io.StringIO()
        with redirect_stdout(output):
            result = _pilot(args)
        return result, output.getvalue()

    def write_payment_evidence(self, number: int, *, refund: bool = False) -> Path:
        kind = "refund" if refund else "capture"
        path = self.root / f"{kind}-{number}.json"
        path.write_text(
            json.dumps(payment_document(number, refund=refund)),
            encoding="utf-8",
        )
        return path

    def write_delivery_evidence(
        self,
        number: int,
        artifact_sha256: str,
    ) -> Path:
        document = {
            "schema_version": "remedialhq.delivery-evidence.v1",
            "event_type": "DELIVERY_RECORDED",
            "delivery_method": "EMAIL_PROVIDER_ACCEPTED",
            "order_id": opaque("ord", number),
            "artifact_sha256": artifact_sha256,
            "evidence_artifact_sha256": f"{300 + number:064x}",
            "observed_at": datetime.now(UTC).isoformat(),
            "evidence_ref": opaque("evd", 200 + number),
            "delivery_ref": opaque("dlv", number),
        }
        build_delivery_evidence(
            document,
            expected_order_id=opaque("ord", number),
            expected_artifact_sha256=artifact_sha256,
        )
        path = self.root / f"delivery-{number}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def write_contact_evidence(self, number: int) -> Path:
        observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        evidence = ContactEvidence(
            prospect_id=opaque("prs", number),
            channel=ContactChannel.BUSINESS_EMAIL.value,
            sender_profile_evidence_sha256=private_file_sha256(
                self.sender_profile_path,
                maximum_bytes=16_384,
            ),
            suppression_evidence_sha256=f"{40_000 + number:064x}",
            message_copy_sha256=f"{41_000 + number:064x}",
            provider_send_evidence_sha256=f"{42_000 + number:064x}",
            provider_message_sha256=f"{43_000 + number:064x}",
            observed_at=observed_at,
        )
        path = self.root / f"contact-{number}.json"
        path.write_text(json.dumps(evidence.to_dict()), encoding="utf-8")
        path.chmod(0o600)
        return path

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

    def seed_sample(self, number: int = 1) -> str:
        prospect_id = self.add_prospect(number)
        self.ledger.record(
            PilotEventType.CONTACTED,
            {
                "prospect_id": prospect_id,
                "channel": ContactChannel.BUSINESS_EMAIL,
            },
        )
        self.ledger.record(
            PilotEventType.REPLIED,
            {"prospect_id": prospect_id, "outcome": ReplyOutcome.INTERESTED},
        )
        self.ledger.record(PilotEventType.SAMPLE_REQUESTED, {"prospect_id": prospect_id})
        return prospect_id

    def seed_purchase(self, number: int = 1) -> tuple[str, str]:
        prospect_id = self.seed_sample(number)
        self.ledger.record(
            PilotEventType.SCOPE_CONFIRMED,
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", number),
                "deadline": "2026-09-15",
                "terms_version": "creator-desk-v1",
                "claim_ids": ["CLM-0001", "CLM-0002"],
            },
        )
        self.ledger.record(
            PilotEventType.CUSTOMER_ACCEPTANCE_RECORDED,
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", number),
                "customer_acceptance_ref": opaque("cac", number),
                "acceptance_evidence_sha256": CUSTOMER_ACCEPTANCE_EVIDENCE_SHA256,
            },
        )
        self.ledger.record(
            PilotEventType.CHECKOUT_SENT,
            {"prospect_id": prospect_id, "checkout_ref": opaque("chk", number)},
        )
        order_id = opaque("ord", number)
        self.ledger.record(
            PilotEventType.PURCHASED,
            {
                "prospect_id": prospect_id,
                "order_id": order_id,
                "fee_cents": 317,
            },
            payment_evidence=build_live_payment_evidence(
                payment_document(number),
                expected_order_id=order_id,
            ),
        )
        return prospect_id, order_id

    def accept_order(self, prospect_id: str, number: int = 1) -> None:
        self.ledger.record(
            PilotEventType.ORDER_ACCEPTED,
            {
                "prospect_id": prospect_id,
                "scope_ref": opaque("scp", number),
                "order_acceptance_ref": opaque("oac", number),
                "acceptance_evidence_sha256": ORDER_ACCEPTANCE_EVIDENCE_SHA256,
            },
        )

    def test_scope_accepts_repeated_claim_ids_and_generates_only_scope_ref(self) -> None:
        prospect_id = self.seed_sample()
        generated_scope = opaque("scp", 1)
        with patch("remedialhq.cli.new_opaque_id", return_value=generated_scope) as generate:
            result, output = self.run_pilot(
                "scope",
                "--prospect-id",
                prospect_id,
                "--deadline",
                "2026-09-15",
                "--terms-version",
                "creator-desk-v1",
                "--claim-id",
                "CLM-0001",
                "--claim-id",
                "CLM-0002",
            )

        self.assertEqual(result, 0)
        generate.assert_called_once_with(OpaqueIdKind.SCOPE)
        record = json.loads(output)
        self.assertEqual(record["event_type"], PilotEventType.SCOPE_CONFIRMED)
        self.assertEqual(record["payload"]["claim_ids"], ["CLM-0001", "CLM-0002"])
        self.assertEqual(PilotLedger(self.ledger_path).metrics().scopes_confirmed, 1)

        second_prospect = self.seed_sample(2)
        explicit_scope = opaque("scp", 2)
        with patch("remedialhq.cli.new_opaque_id") as generate:
            result, _ = self.run_pilot(
                "scope",
                "--prospect-id",
                second_prospect,
                "--scope-ref",
                explicit_scope,
                "--deadline",
                "2026-09-16T12:00:00Z",
                "--terms-version",
                "creator-desk-v1",
                "--claim-id",
                "CLM-0003",
            )
        self.assertEqual(result, 0)
        generate.assert_not_called()
        self.assertEqual(PilotLedger(self.ledger_path).metrics().scopes_confirmed, 2)

    def test_amend_scope_requires_fresh_acceptance_before_purchase(self) -> None:
        prospect_id = self.seed_sample()
        self.run_pilot(
            "scope",
            "--prospect-id",
            prospect_id,
            "--scope-ref",
            opaque("scp", 1),
            "--deadline",
            "2026-09-15",
            "--terms-version",
            "creator-desk-v1",
            "--claim-id",
            "CLM-0001",
        )
        self.run_pilot(
            "customer-acceptance",
            "--prospect-id",
            prospect_id,
            "--scope-ref",
            opaque("scp", 1),
            "--acceptance-ref",
            opaque("cac", 1),
            "--evidence-sha256",
            CUSTOMER_ACCEPTANCE_EVIDENCE_SHA256,
        )
        self.run_pilot(
            "checkout",
            "--prospect-id",
            prospect_id,
            "--checkout-ref",
            opaque("chk", 1),
        )
        result, output = self.run_pilot(
            "amend-scope",
            "--prospect-id",
            prospect_id,
            "--supersedes-scope-ref",
            opaque("scp", 1),
            "--scope-ref",
            opaque("scp", 2),
            "--deadline",
            "2026-09-20",
            "--terms-version",
            "creator-desk-v2",
            "--claim-id",
            "CLM-0002",
        )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output)["event_type"], PilotEventType.SCOPE_AMENDED)

        evidence_path = self.write_payment_evidence(1)
        purchase_arguments = (
            "purchase",
            "--prospect-id",
            prospect_id,
            "--order-id",
            opaque("ord", 1),
            "--payment-evidence",
            str(evidence_path),
            "--fee-cents",
            "317",
        )
        with self.assertRaisesRegex(PilotValidationError, "active scope"):
            self.run_pilot(*purchase_arguments)
        self.run_pilot(
            "customer-acceptance",
            "--prospect-id",
            prospect_id,
            "--scope-ref",
            opaque("scp", 2),
            "--acceptance-ref",
            opaque("cac", 2),
            "--evidence-sha256",
            "e" * 64,
        )
        self.assertEqual(self.run_pilot(*purchase_arguments)[0], 0)

    def test_explicit_contact_does_not_generate_unused_identifiers(self) -> None:
        prospect_id = self.add_prospect(1)
        with patch("remedialhq.cli.new_opaque_id") as generate:
            result, _ = self.run_pilot(
                "contact",
                "--prospect-id",
                prospect_id,
                "--channel",
                ContactChannel.BUSINESS_EMAIL,
                "--sender-profile",
                str(self.sender_profile_path),
                "--contact-evidence",
                str(self.write_contact_evidence(1)),
            )
        self.assertEqual(result, 0)
        generate.assert_not_called()

    def test_init_hashes_reconciliation_evidence_and_refuses_overwrite(self) -> None:
        ledger_path = self.root / "initialized.jsonl"
        evidence_path = self.root / "slot-reconciliation.json"
        evidence_text = json.dumps(reconciliation_document())
        evidence_path.write_text(evidence_text, encoding="utf-8")
        args = _parser().parse_args(
            [
                "pilot",
                "init",
                "--ledger",
                str(ledger_path),
                "--reconciliation-evidence",
                str(evidence_path),
            ]
        )
        output = io.StringIO()
        with redirect_stdout(output):
            result = _pilot(args)
        self.assertEqual(result, 0)
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["prior_consumed_slots"], 0)
        self.assertEqual(summary["reconciled_provider_purchases"], 0)
        self.assertEqual(summary["remaining_founding_slots"], 5)
        self.assertEqual(
            summary["reconciliation_evidence_sha256"],
            hashlib.sha256(evidence_text.encode("utf-8")).hexdigest(),
        )
        self.assertRegex(summary["reconciliation_record_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            summary["reconciliation_ref"],
            "rec_00000000000000000000000000000001",
        )
        self.assertEqual(summary["private_mode_enforced"], True)
        self.assertEqual(summary["storage_security_status"], "ENFORCED")
        self.assertEqual(summary["ledger_mode"], "0600")
        self.assertEqual(summary["lock_mode"], "0600")
        self.assertEqual(summary["insecure_test_storage_override"], False)
        self.assertEqual(PilotLedger(ledger_path).metrics().prior_consumed_slots, 0)
        with self.assertRaisesRegex(PilotValidationError, "already exists"):
            _pilot(args)

    def test_reconciliation_facts_are_derived_from_the_verified_ledger(self) -> None:
        args = _parser().parse_args(
            [
                "pilot",
                "reconciliation-facts",
                "--prior-ledger",
                str(self.ledger_path),
            ]
        )
        output = io.StringIO()
        with redirect_stdout(output):
            result = _pilot(args)

        self.assertEqual(result, 0)
        facts = json.loads(output.getvalue())
        self.assertEqual(facts["lifetime_consumed_slots"], 0)
        self.assertEqual(facts["prior_ledger"]["ledger_schema_version"], 5)
        self.assertEqual(
            facts["prior_ledger"]["ledger_head_sha256"],
            self.ledger.head,
        )
        self.assertEqual(facts["prior_ledger"]["purchase_event_sha256s"], [])
        self.assertEqual(facts["prior_ledger"]["provider_purchase_sha256s"], [])

    def test_contract_sequence_requires_live_purchase_and_records_cancellation(self) -> None:
        prospect_id = self.seed_sample()
        with self.assertRaisesRegex(PilotValidationError, "confirmed pre-payment scope"):
            self.run_pilot(
                "customer-acceptance",
                "--prospect-id",
                prospect_id,
                "--scope-ref",
                opaque("scp", 1),
                "--evidence-sha256",
                CUSTOMER_ACCEPTANCE_EVIDENCE_SHA256,
            )
        self.run_pilot(
            "scope",
            "--prospect-id",
            prospect_id,
            "--scope-ref",
            opaque("scp", 1),
            "--deadline",
            "2026-09-15",
            "--terms-version",
            "creator-desk-v1",
            "--claim-id",
            "CLM-0001",
        )
        self.run_pilot(
            "customer-acceptance",
            "--prospect-id",
            prospect_id,
            "--scope-ref",
            opaque("scp", 1),
            "--acceptance-ref",
            opaque("cac", 1),
            "--evidence-sha256",
            CUSTOMER_ACCEPTANCE_EVIDENCE_SHA256,
        )
        self.run_pilot(
            "checkout",
            "--prospect-id",
            prospect_id,
            "--checkout-ref",
            opaque("chk", 1),
        )
        purchase_arguments = (
            "purchase",
            "--prospect-id",
            prospect_id,
            "--order-id",
            opaque("ord", 1),
            "--fee-cents",
            "317",
        )
        invalid_evidence = payment_document(1)
        invalid_evidence["mode"] = "TEST"
        invalid_path = self.root / "test-mode-payment.json"
        invalid_path.write_text(json.dumps(invalid_evidence), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_pilot(
                *purchase_arguments,
                "--payment-evidence",
                str(invalid_path),
            )
        evidence_path = self.write_payment_evidence(1)
        result, output = self.run_pilot(
            *purchase_arguments,
            "--payment-evidence",
            str(evidence_path),
        )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output)["payload"]["payment_mode"], "LIVE")
        self.run_pilot(
            "accept-order",
            "--prospect-id",
            prospect_id,
            "--scope-ref",
            opaque("scp", 1),
            "--acceptance-ref",
            opaque("oac", 1),
            "--evidence-sha256",
            ORDER_ACCEPTANCE_EVIDENCE_SHA256,
        )
        self.run_pilot(
            "cancel",
            "--prospect-id",
            prospect_id,
            "--cancellation-ref",
            opaque("can", 1),
        )
        order = PilotLedger(self.ledger_path).order(opaque("ord", 1))
        self.assertEqual(order.state, PilotOrderState.CANCELLATION_REQUESTED)

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            _parser().parse_args(
                [
                    "pilot",
                    "purchase",
                    "--prospect-id",
                    prospect_id,
                    "--fee-cents",
                    "317",
                ]
            )

    def test_artifact_completion_and_delivery_require_separate_evidence(self) -> None:
        prospect_id, order_id = self.seed_purchase()
        self.accept_order(prospect_id)
        self.ledger.record(PilotEventType.FULFILLMENT_STARTED, {"prospect_id": prospect_id})
        artifact = self.root / "customer-output.md"
        artifact_bytes = b"Evidence-linked creator brief\n"
        artifact.write_bytes(artifact_bytes)

        result, output = self.run_pilot(
            "complete-artifact",
            "--prospect-id",
            prospect_id,
            "--artifact",
            str(artifact),
        )

        self.assertEqual(result, 0)
        expected_digest = hashlib.sha256(artifact_bytes).hexdigest()
        record = json.loads(output)
        self.assertEqual(
            record["payload"],
            {
                "prospect_id": prospect_id,
                "deliverable_sha256": expected_digest,
            },
        )
        self.assertNotIn(str(artifact), self.ledger_path.read_text(encoding="utf-8"))
        order = PilotLedger(self.ledger_path).order(order_id)
        self.assertEqual(order.deliverable_sha256, expected_digest)
        self.assertEqual(order.state, PilotOrderState.ARTIFACT_COMPLETED)

        evidence_path = self.write_delivery_evidence(1, expected_digest)
        result, output = self.run_pilot(
            "deliver",
            "--prospect-id",
            prospect_id,
            "--order-id",
            order_id,
            "--delivery-evidence",
            str(evidence_path),
        )

        self.assertEqual(result, 0)
        record = json.loads(output)
        self.assertEqual(record["payload"]["delivery_ref"], opaque("dlv", 1))
        self.assertEqual(
            record["payload"]["delivery_method"],
            "EMAIL_PROVIDER_ACCEPTED",
        )
        self.assertNotIn(str(evidence_path), self.ledger_path.read_text(encoding="utf-8"))
        order = PilotLedger(self.ledger_path).order(order_id)
        self.assertEqual(order.state, PilotOrderState.DELIVERED)

    def test_completion_requires_artifact_and_delivery_requires_evidence(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            _parser().parse_args(
                [
                    "pilot",
                    "complete-artifact",
                    "--prospect-id",
                    opaque("prs", 1),
                    "--ledger",
                    str(self.ledger_path),
                ]
            )
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            _parser().parse_args(
                [
                    "pilot",
                    "deliver",
                    "--prospect-id",
                    opaque("prs", 1),
                    "--order-id",
                    opaque("ord", 1),
                    "--ledger",
                    str(self.ledger_path),
                ]
            )

    def test_order_and_orders_emit_json_projections(self) -> None:
        _, first_order_id = self.seed_purchase(1)
        _, second_order_id = self.seed_purchase(2)

        result, output = self.run_pilot("order", "--order-id", first_order_id)
        self.assertEqual(result, 0)
        order = json.loads(output)
        self.assertEqual(order["order_id"], first_order_id)
        self.assertEqual(order["state"], PilotOrderState.PURCHASED)
        self.assertEqual(order["amount_cents"], 9_900)
        self.assertEqual(order["tax_amount_cents"], 0)
        self.assertEqual(order["gross_amount_cents"], 9_900)
        self.assertIsNone(order["refunded_amount_cents"])
        self.assertEqual(order["provider_purchase_sha256"], f"{1001:064x}")

        result, output = self.run_pilot("orders")
        self.assertEqual(result, 0)
        orders = json.loads(output)
        self.assertEqual(
            [item["order_id"] for item in orders],
            [first_order_id, second_order_id],
        )

    def test_order_manifest_command_writes_verified_projection(self) -> None:
        _, order_id = self.seed_purchase()
        manifest_path = self.root / "order-manifest.json"

        result, output = self.run_pilot(
            "order-manifest",
            "--order-id",
            order_id,
            "--output",
            str(manifest_path),
        )

        self.assertEqual(result, 0)
        command_result = json.loads(output)
        self.assertEqual(command_result["order_id"], order_id)
        self.assertRegex(command_result["manifest_sha256"], r"^[0-9a-f]{64}$")
        loaded = load_order_manifest(manifest_path)
        self.assertEqual(loaded, PilotLedger(self.ledger_path).order(order_id))

    def test_order_manifest_cannot_overwrite_pilot_ledger(self) -> None:
        _, order_id = self.seed_purchase()
        with self.assertRaisesRegex(ValueError, "must not overwrite"):
            self.run_pilot(
                "order-manifest",
                "--order-id",
                order_id,
                "--output",
                str(self.ledger_path),
            )
        self.assertTrue(PilotLedger(self.ledger_path).verify()[0])

    def test_summary_remains_aggregate_only(self) -> None:
        prospect_id, order_id = self.seed_purchase()
        result, output = self.run_pilot("summary")

        self.assertEqual(result, 0)
        summary = json.loads(output)
        self.assertEqual(summary["prospects"], 1)
        self.assertEqual(summary["purchases"], 1)
        self.assertEqual(summary["private_mode_enforced"], True)
        self.assertEqual(summary["storage_security_status"], "ENFORCED")
        self.assertEqual(summary["ledger_mode"], "0600")
        self.assertEqual(summary["lock_mode"], "0600")
        self.assertEqual(summary["insecure_test_storage_override"], False)
        serialized = json.dumps(summary)
        self.assertNotIn(prospect_id, serialized)
        self.assertNotIn(order_id, serialized)
        self.assertNotIn("payment_ref", serialized)

    def test_verify_keeps_stdout_compatible_and_reports_storage_on_stderr(self) -> None:
        args = _parser().parse_args(["pilot", "verify", "--ledger", str(self.ledger_path)])
        output = io.StringIO()
        errors = io.StringIO()

        with redirect_stdout(output), redirect_stderr(errors):
            result = _pilot(args)

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "verified 1 pilot events\n")
        self.assertEqual(
            errors.getvalue(),
            "private storage: ENFORCED (ledger=0600, lock=0600)\n",
        )

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics required")
    def test_insecure_cli_override_warns_and_reports_flat_storage_fields(self) -> None:
        lock_path = self.ledger_path.with_name(f".{self.ledger_path.name}.lock")
        self.ledger_path.chmod(0o644)
        lock_path.chmod(0o666)
        args = _parser().parse_args(
            [
                "pilot",
                "summary",
                "--ledger",
                str(self.ledger_path),
                "--allow-insecure-test-storage",
            ]
        )
        output = io.StringIO()
        errors = io.StringIO()

        with redirect_stdout(output), redirect_stderr(errors):
            result = _pilot(args)

        self.assertEqual(result, 0)
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["private_mode_enforced"], False)
        self.assertEqual(
            summary["storage_security_status"],
            "INSECURE_TEST_OVERRIDE",
        )
        self.assertEqual(summary["ledger_mode"], "0644")
        self.assertEqual(summary["lock_mode"], "0666")
        self.assertEqual(summary["insecure_test_storage_override"], True)
        self.assertEqual(
            errors.getvalue(),
            "WARNING: insecure test storage override enabled. Do not use real "
            "prospects, customers, payments, or evidence.\n",
        )
        self.assertEqual(stat.S_IMODE(self.ledger_path.stat().st_mode), 0o644)

        verify_args = _parser().parse_args(
            [
                "pilot",
                "verify",
                "--ledger",
                str(self.ledger_path),
                "--allow-insecure-test-storage",
            ]
        )
        verify_output = io.StringIO()
        verify_errors = io.StringIO()
        with redirect_stdout(verify_output), redirect_stderr(verify_errors):
            verify_result = _pilot(verify_args)
        self.assertEqual(verify_result, 0)
        self.assertEqual(verify_output.getvalue(), "verified 1 pilot events\n")
        self.assertEqual(verify_errors.getvalue(), errors.getvalue())

    def test_new_id_supports_scope_kind(self) -> None:
        generated_scope = opaque("scp", 9)
        args = _parser().parse_args(["pilot", "new-id", "scope"])
        output = io.StringIO()
        with (
            patch("remedialhq.cli.new_opaque_id", return_value=generated_scope) as generate,
            redirect_stdout(output),
        ):
            result = _pilot(args)
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().strip(), generated_scope)
        generate.assert_called_once_with(OpaqueIdKind.SCOPE)


if __name__ == "__main__":
    unittest.main()
