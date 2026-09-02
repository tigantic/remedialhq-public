from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from remedialhq.briefing import build_creator_brief
from remedialhq.canonical import sha256_bytes, sha256_json
from remedialhq.payment_evidence import LivePaymentEvidence, build_live_payment_evidence
from remedialhq.pilots import (
    ContactChannel,
    PilotEventType,
    PilotLedger,
    PilotManifestError,
    ProspectSegment,
    ReplyOutcome,
    write_order_manifest,
)
from tests.pilot_reconciliation_support import reconciliation_evidence


def opaque(prefix: str, number: int) -> str:
    return f"{prefix}_{number:032x}"


def payment_evidence(*, refund: bool = False) -> LivePaymentEvidence:
    order_id = opaque("ord", 1)
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
        "evidence_ref": opaque("evd", 2 if refund else 1),
        "provider_ref": opaque("rfd" if refund else "pay", 1),
        "provider_purchase_sha256": "f" * 64,
        "artifact_sha256": ("e" if refund else "b") * 64,
    }
    if refund:
        document["original_payment_ref"] = opaque("pay", 1)
        document["refunded_amount_cents"] = 9_900
    return build_live_payment_evidence(document, expected_order_id=order_id)


def seed_order(path: Path, *, accept_order: bool = True) -> PilotLedger:
    ledger = PilotLedger.initialize(
        path,
        reconciliation_evidence=reconciliation_evidence(),
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
    if accept_order:
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
    return ledger


class CreatorBriefTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]

    def test_builds_source_linked_brief(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            output = Path(directory) / "sample.md"
            result = build_creator_brief(
                self.root,
                output,
                title="GTA VI official-state signal",
                claim_ids=["CLM-0001", "CLM-0021"],
                angles=["What in-game footage proves and what it does not."],
            )
            body = output.read_text(encoding="utf-8")
            self.assertEqual(result["claim_ids"], ["CLM-0001", "CLM-0021"])
            self.assertIn("## Safe-to-say evidence", body)
            self.assertIn("https://www.rockstargames.com/VI", body)
            self.assertIn("CLM-0001", body)
            self.assertIn("## Do not overstate", body)
            self.assertNotIn("\u2014", body)
            provenance_path = Path(result["provenance_manifest"])
            self.assertTrue(provenance_path.is_file())
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(provenance_path.stat().st_mode), 0o600)
            self.assertEqual(provenance["artifact"]["sha256"], sha256_bytes(output.read_bytes()))
            body_without_digest = {
                key: value for key, value in provenance.items() if key != "manifest_sha256"
            }
            self.assertEqual(provenance["manifest_sha256"], sha256_json(body_without_digest))

    def test_rejects_unknown_claim(self) -> None:
        with (
            tempfile.TemporaryDirectory(dir="/tmp") as directory,
            self.assertRaisesRegex(ValueError, "unknown claim IDs"),
        ):
            build_creator_brief(
                self.root,
                Path(directory) / "sample.md",
                title="Unknown",
                claim_ids=["CLM-DOES-NOT-EXIST"],
            )

    def test_rejects_pending_claim(self) -> None:
        with (
            tempfile.TemporaryDirectory(dir="/tmp") as directory,
            self.assertRaisesRegex(ValueError, "non-publishable claim IDs"),
        ):
            build_creator_brief(
                self.root,
                Path(directory) / "sample.md",
                title="Pending",
                claim_ids=["CLM-0008"],
            )

    def test_order_manifest_binds_scope_and_writes_path_free_provenance(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary = Path(directory)
            ledger_path = temporary / "pilot.jsonl"
            ledger = seed_order(ledger_path)
            order_manifest = temporary / "order.json"
            write_order_manifest(
                order_manifest,
                ledger.order(opaque("ord", 1)),
                ledger_head_sha256=ledger.head,
            )
            output = temporary / "brief.md"
            result = build_creator_brief(
                self.root,
                output,
                title="Scoped creator brief",
                order_manifest=order_manifest,
                pilot_ledger=ledger_path,
            )
            self.assertEqual(result["claim_ids"], ["CLM-0001", "CLM-0021"])
            provenance = Path(result["provenance_manifest"]).read_text(encoding="utf-8")
            self.assertNotIn(str(temporary), provenance)
            self.assertNotIn("payment_ref", provenance)
            self.assertIn(opaque("ord", 1), provenance)
            self.assertIn(opaque("scp", 1), provenance)

    def test_order_manifest_rejects_unaccepted_or_mismatched_scope(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary = Path(directory)
            unscoped_ledger_path = temporary / "unscoped-ledger.jsonl"
            unscoped_ledger = seed_order(unscoped_ledger_path, accept_order=False)
            unscoped_manifest = temporary / "unscoped.json"
            write_order_manifest(
                unscoped_manifest,
                unscoped_ledger.order(opaque("ord", 1)),
                ledger_head_sha256=unscoped_ledger.head,
            )
            with self.assertRaisesRegex(ValueError, "fulfillment-started"):
                build_creator_brief(
                    self.root,
                    temporary / "unscoped.md",
                    title="Unscoped",
                    order_manifest=unscoped_manifest,
                    pilot_ledger=unscoped_ledger_path,
                )

            scoped_ledger_path = temporary / "scoped-ledger.jsonl"
            scoped_ledger = seed_order(scoped_ledger_path)
            scoped_manifest = temporary / "scoped.json"
            write_order_manifest(
                scoped_manifest,
                scoped_ledger.order(opaque("ord", 1)),
                ledger_head_sha256=scoped_ledger.head,
            )
            with self.assertRaisesRegex(ValueError, "exactly match"):
                build_creator_brief(
                    self.root,
                    temporary / "mismatch.md",
                    title="Mismatch",
                    claim_ids=["CLM-0001"],
                    order_manifest=scoped_manifest,
                    pilot_ledger=scoped_ledger_path,
                )

    def test_recomputed_manifest_checksum_cannot_change_ledger_scope(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary = Path(directory)
            ledger_path = temporary / "pilot.jsonl"
            ledger = seed_order(ledger_path)
            manifest_path = temporary / "order.json"
            write_order_manifest(
                manifest_path,
                ledger.order(opaque("ord", 1)),
                ledger_head_sha256=ledger.head,
            )
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            raw["order"]["claim_ids"] = ["CLM-0001"]
            body = {key: value for key, value in raw.items() if key != "manifest_sha256"}
            raw["manifest_sha256"] = sha256_json(body)
            manifest_path.write_text(json.dumps(raw), encoding="utf-8")

            with self.assertRaisesRegex(PilotManifestError, "current pilot ledger"):
                build_creator_brief(
                    self.root,
                    temporary / "forged.md",
                    title="Forged scope",
                    order_manifest=manifest_path,
                    pilot_ledger=ledger_path,
                )

    def test_manifest_is_rejected_after_order_refund(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary = Path(directory)
            ledger_path = temporary / "pilot.jsonl"
            ledger = seed_order(ledger_path)
            manifest_path = temporary / "order.json"
            write_order_manifest(
                manifest_path,
                ledger.order(opaque("ord", 1)),
                ledger_head_sha256=ledger.head,
            )
            ledger.record(
                PilotEventType.REFUNDED,
                {
                    "prospect_id": opaque("prs", 1),
                    "order_id": opaque("ord", 1),
                },
                payment_evidence=payment_evidence(refund=True),
            )

            with self.assertRaisesRegex(PilotManifestError, "current pilot ledger"):
                build_creator_brief(
                    self.root,
                    temporary / "refunded.md",
                    title="Refunded scope",
                    order_manifest=manifest_path,
                    pilot_ledger=ledger_path,
                )

    def test_manifest_is_rejected_after_ledger_head_advances(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary = Path(directory)
            ledger_path = temporary / "pilot.jsonl"
            ledger = seed_order(ledger_path)
            manifest_path = temporary / "order.json"
            write_order_manifest(
                manifest_path,
                ledger.order(opaque("ord", 1)),
                ledger_head_sha256=ledger.head,
            )
            ledger.record(
                PilotEventType.RISK_INCIDENT_RECORDED,
                {
                    "incident_id": opaque("inc", 1),
                    "kind": "OTHER_COMPLIANCE",
                    "severity": "MATERIAL",
                },
            )

            with self.assertRaisesRegex(PilotManifestError, "current pilot ledger"):
                build_creator_brief(
                    self.root,
                    temporary / "stale.md",
                    title="Stale scope",
                    order_manifest=manifest_path,
                    pilot_ledger=ledger_path,
                )

    def test_symlinked_private_outputs_are_rejected_without_target_changes(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary = Path(directory)
            target = temporary / "target.txt"
            target.write_text("unchanged\n", encoding="utf-8")
            output_link = temporary / "brief.md"
            output_link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                build_creator_brief(
                    self.root,
                    output_link,
                    title="Linked output",
                    claim_ids=["CLM-0001"],
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged\n")

            output = temporary / "safe.md"
            provenance_link = temporary / "provenance.json"
            provenance_link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                build_creator_brief(
                    self.root,
                    output,
                    title="Linked provenance",
                    claim_ids=["CLM-0001"],
                    manifest_output=provenance_link,
                )
            self.assertFalse(output.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged\n")

    def test_commit_failure_restores_both_private_outputs(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary = Path(directory)
            output = temporary / "brief.md"
            provenance = temporary / "provenance.json"
            output.write_text("original brief\n", encoding="utf-8")
            provenance.write_text("original provenance\n", encoding="utf-8")
            output.chmod(0o600)
            provenance.chmod(0o600)
            real_replace = os.replace

            def fail_provenance_commit(source: str | Path, destination: str | Path) -> None:
                source_path = Path(source)
                destination_path = Path(destination)
                if destination_path == provenance and source_path.name.endswith(".tmp"):
                    raise OSError("simulated provenance commit failure")
                real_replace(source, destination)

            with (
                patch("remedialhq.briefing.os.replace", side_effect=fail_provenance_commit),
                self.assertRaisesRegex(OSError, "simulated provenance commit failure"),
            ):
                build_creator_brief(
                    self.root,
                    output,
                    title="Atomic output",
                    claim_ids=["CLM-0001"],
                    manifest_output=provenance,
                )

            self.assertEqual(output.read_text(encoding="utf-8"), "original brief\n")
            self.assertEqual(provenance.read_text(encoding="utf-8"), "original provenance\n")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(provenance.stat().st_mode), 0o600)
            self.assertFalse(list(temporary.glob(".*.tmp")))
            self.assertFalse(list(temporary.glob(".*.bak")))


if __name__ == "__main__":
    unittest.main()
