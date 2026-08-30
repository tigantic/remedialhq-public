from __future__ import annotations

import io
import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

from remedialhq.cli import _creator_brief, _parser, _status
from remedialhq.payment_evidence import LivePaymentEvidence, build_live_payment_evidence
from remedialhq.pilots import (
    ContactChannel,
    PilotEventType,
    PilotLedger,
    ProspectSegment,
    ReplyOutcome,
    write_order_manifest,
)


def opaque(prefix: str, number: int) -> str:
    return f"{prefix}_{number:032x}"


def payment_evidence() -> LivePaymentEvidence:
    order_id = opaque("ord", 1)
    return build_live_payment_evidence(
        {
            "schema_version": "remedialhq.live-payment-evidence.v1",
            "event_type": "PAYMENT_CAPTURED",
            "provider": "STRIPE",
            "mode": "LIVE",
            "livemode": True,
            "status": "SUCCEEDED",
            "currency": "USD",
            "amount_cents": 9_900,
            "payment_type": "ONE_TIME",
            "order_id": order_id,
            "observed_at": datetime.now(UTC).isoformat(),
            "evidence_ref": opaque("evd", 1),
            "provider_ref": opaque("pay", 1),
            "artifact_sha256": "b" * 64,
        },
        expected_order_id=order_id,
    )


class CreatorBriefCliTests(unittest.TestCase):
    def test_status_has_an_explicit_private_plan_boundary(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = _status(
                    Namespace(
                        plan=str(Path(directory) / "missing-execution-plan.json"),
                        limit=12,
                        as_json=False,
                    )
                )
        self.assertEqual(result, 2)
        self.assertIn("private or absent", stderr.getvalue())

    def test_scoped_manifest_supplies_claims_and_custom_provenance_path(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary = Path(directory)
            ledger_path = temporary / "pilot.jsonl"
            ledger = PilotLedger.initialize(
                ledger_path,
                prior_consumed_slots=0,
                reconciliation_evidence_sha256="f" * 64,
            )
            prospect_id = opaque("prs", 1)
            ledger.record(
                PilotEventType.PROSPECT_ADDED,
                {"prospect_id": prospect_id, "segment": ProspectSegment.GAMING_CREATOR},
            )
            ledger.record(
                PilotEventType.CONTACTED,
                {"prospect_id": prospect_id, "channel": ContactChannel.BUSINESS_EMAIL},
            )
            ledger.record(
                PilotEventType.REPLIED,
                {"prospect_id": prospect_id, "outcome": ReplyOutcome.INTERESTED},
            )
            ledger.record(PilotEventType.SAMPLE_REQUESTED, {"prospect_id": prospect_id})
            ledger.record(
                PilotEventType.SCOPE_CONFIRMED,
                {
                    "prospect_id": prospect_id,
                    "scope_ref": opaque("scp", 1),
                    "deadline": "2026-09-15",
                    "terms_version": "creator-desk-v1",
                    "claim_ids": ["CLM-0001", "CLM-0021"],
                },
            )
            ledger.record(
                PilotEventType.CUSTOMER_ACCEPTANCE_RECORDED,
                {
                    "prospect_id": prospect_id,
                    "scope_ref": opaque("scp", 1),
                    "customer_acceptance_ref": opaque("cac", 1),
                    "acceptance_evidence_sha256": "c" * 64,
                },
            )
            ledger.record(
                PilotEventType.CHECKOUT_SENT,
                {"prospect_id": prospect_id, "checkout_ref": opaque("chk", 1)},
            )
            ledger.record(
                PilotEventType.PURCHASED,
                {
                    "prospect_id": prospect_id,
                    "order_id": opaque("ord", 1),
                    "fee_cents": 317,
                },
                payment_evidence=payment_evidence(),
            )
            ledger.record(
                PilotEventType.ORDER_ACCEPTED,
                {
                    "prospect_id": prospect_id,
                    "scope_ref": opaque("scp", 1),
                    "order_acceptance_ref": opaque("oac", 1),
                    "acceptance_evidence_sha256": "d" * 64,
                },
            )
            ledger.record(
                PilotEventType.FULFILLMENT_STARTED,
                {"prospect_id": prospect_id},
            )
            order_manifest = temporary / "order.json"
            output = temporary / "brief.md"
            provenance = temporary / "brief-provenance.json"
            write_order_manifest(
                order_manifest,
                ledger.order(opaque("ord", 1)),
                ledger_head_sha256=ledger.head,
            )
            args = _parser().parse_args(
                [
                    "creator-brief",
                    "--root",
                    str(root),
                    "--output",
                    str(output),
                    "--title",
                    "Scoped brief",
                    "--order-manifest",
                    str(order_manifest),
                    "--pilot-ledger",
                    str(ledger_path),
                    "--manifest-output",
                    str(provenance),
                ]
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = _creator_brief(args)

            self.assertEqual(result, 0)
            command_result = json.loads(stdout.getvalue())
            self.assertEqual(command_result["claim_ids"], ["CLM-0001", "CLM-0021"])
            self.assertEqual(Path(command_result["provenance_manifest"]), provenance)
            self.assertTrue(output.is_file())
            self.assertTrue(provenance.is_file())


if __name__ == "__main__":
    unittest.main()
