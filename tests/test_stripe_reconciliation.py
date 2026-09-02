from __future__ import annotations

import hashlib
import io
import json
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import cast

from remedialhq.pilot_reconciliation import (
    PilotSlotReconciliation,
    build_pilot_slot_reconciliation,
    load_pilot_slot_reconciliation,
)
from remedialhq.pilots import PilotLedger
from remedialhq.stripe_live_history import write_private_evidence
from remedialhq.stripe_reconciliation import (
    MAX_HISTORY_BYTES,
    StripeReconciliationError,
    create_stripe_reconciliation,
    load_stripe_history,
    main,
)
from tests.test_stripe_live_history import collector_for, complete_datasets

OBSERVED_AT = "2026-08-30T14:15:00Z"
RECONCILED_AT = "2026-08-30T14:16:00Z"
RECONCILIATION_REF = "rec_0123456789abcdef0123456789abcdef"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _purchase(number: int, *, provider_digest: str | None = None) -> dict[str, object]:
    return {
        "captured_at": f"2026-08-30T14:15:{number:02d}Z",
        "currency": "USD",
        "amount_cents": 9_900,
        "gross_amount_cents": 9_900,
        "tax_amount_cents": 0,
        "status": "PAID",
        "provider_purchase_sha256": provider_digest or _digest(f"provider-{number}"),
        "refund_attempt_count": 0,
        "successful_refund_count": 0,
        "refunded_amount_cents": 0,
        "fully_refunded": False,
        "dispute_count": 0,
        "has_open_dispute": False,
        "provider_reference_sha256": {
            "checkout_session": _digest(f"session-{number}"),
            "payment_intent": _digest(f"intent-{number}"),
            "charge": _digest(f"charge-{number}"),
            "refunds": [],
            "disputes": [],
        },
    }


def _history_document(
    purchase_count: int = 0,
    *,
    provider_digests: list[str] | None = None,
) -> dict[str, object]:
    purchases = [
        _purchase(
            number,
            provider_digest=(None if provider_digests is None else provider_digests[number]),
        )
        for number in range(purchase_count)
    ]
    record_digests = [hashlib.sha256(_canonical(record)[:-1]).hexdigest() for record in purchases]
    purchase_provider_digests = [str(record["provider_purchase_sha256"]) for record in purchases]
    list_coverage = {
        "requests": 1,
        "pages": 1,
        "objects": 0,
        "pagination_complete": True,
    }
    endpoint_coverage = {
        label: dict(list_coverage)
        for label in (
            "products",
            "prices",
            "payment_links",
            "payment_link_line_items",
            "checkout_sessions",
            "checkout_session_line_items",
            "payment_intents",
            "charges",
            "refunds",
            "disputes",
        )
    }
    endpoint_coverage["account"] = {
        "requests": 1,
        "pages": 0,
        "objects": 1,
        "pagination_complete": True,
    }
    document: dict[str, object] = {
        "schema_version": "remedialhq.stripe-live-founding-history.v1",
        "provider": "STRIPE",
        "mode": "LIVE",
        "livemode": True,
        "observed_at": OBSERVED_AT,
        "offer": {
            "name": "Creator Signal Desk Founding Pilot",
            "currency": "USD",
            "amount_cents": 9_900,
            "payment_type": "ONE_TIME",
            "slot_limit": 5,
        },
        "endpoint_coverage": endpoint_coverage,
        "account_controls": {
            "charges_enabled": True,
            "payouts_enabled": True,
            "details_submitted": True,
        },
        "aggregates": {
            "products_scanned": 1,
            "prices_scanned": 1,
            "payment_links_scanned": 1,
            "payment_link_line_items_scanned": 1,
            "matching_payment_links": 1,
            "active_matching_payment_links": 1,
            "checkout_sessions_scanned": purchase_count + 1,
            "checkout_session_line_items_scanned": purchase_count + 1,
            "matching_checkout_sessions": purchase_count + 1,
            "abandoned_matching_checkout_sessions": 1,
            "paid_founding_purchases": purchase_count,
            "gross_paid_amount_cents": purchase_count * 9_900,
            "tax_collected_amount_cents": 0,
            "successful_refunded_amount_cents": 0,
        },
        "purchases": purchases,
        "purchase_record_sha256": record_digests,
        "provider_purchase_sha256s": purchase_provider_digests,
    }
    document["history_evidence_sha256"] = hashlib.sha256(_canonical(document)[:-1]).hexdigest()
    return document


def _rehash_history(document: dict[str, object]) -> None:
    document.pop("history_evidence_sha256", None)
    document["history_evidence_sha256"] = hashlib.sha256(_canonical(document)[:-1]).hexdigest()


def _secure_directory(root: Path, name: str = "private") -> Path:
    directory = root / name
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


def _write_history(path: Path, document: dict[str, object]) -> bytes:
    payload = _canonical(document)
    path.write_bytes(payload)
    path.chmod(0o600)
    return payload


def _initial_reconciliation(provider_digests: list[str]) -> PilotSlotReconciliation:
    document: dict[str, object] = {
        "schema_version": "remedialhq.pilot-slot-reconciliation.v1",
        "reconciliation_ref": "rec_11111111111111111111111111111111",
        "reconciled_at": RECONCILED_AT,
        "scope": "ALL_LIFETIME_FOUNDING_PURCHASES",
        "checks": {
            "all_known_ledgers_reviewed": True,
            "payment_provider_history_reviewed": True,
            "single_authoritative_successor_designated": True,
        },
        "payment_provider": {
            "provider": "STRIPE",
            "mode": "LIVE",
            "observed_at": OBSERVED_AT,
            "history_scope": "ALL_AVAILABLE_ACCOUNT_HISTORY",
            "history_evidence_sha256": _digest("prior-history-file"),
            "provider_purchase_sha256s": provider_digests,
        },
        "prior_ledger": None,
        "lifetime_consumed_slots": len(provider_digests),
    }
    return build_pilot_slot_reconciliation(
        document,
        expected_prior_ledger=None,
        evidence_bytes=_canonical(document),
    )


class StripeReconciliationTests(unittest.TestCase):
    def test_zero_one_and_five_purchases_generate_exact_strict_evidence(self) -> None:
        for purchase_count in (0, 1, 5):
            with (
                self.subTest(purchase_count=purchase_count),
                tempfile.TemporaryDirectory(dir="/tmp") as temporary,
            ):
                private = _secure_directory(Path(temporary))
                history = private / "stripe-history.json"
                history_bytes = _write_history(history, _history_document(purchase_count))
                output = private / "pilot-slot-reconciliation.json"

                result = create_stripe_reconciliation(
                    history,
                    output,
                    reconciliation_ref=RECONCILIATION_REF,
                    reconciled_at=RECONCILED_AT,
                )
                output_bytes = output.read_bytes()
                output_document = json.loads(output_bytes)

                self.assertEqual(result.output_path, output.absolute())
                self.assertEqual(
                    result.history_file_sha256,
                    hashlib.sha256(history_bytes).hexdigest(),
                )
                self.assertEqual(
                    output_document["payment_provider"]["history_evidence_sha256"],
                    hashlib.sha256(history_bytes).hexdigest(),
                )
                self.assertNotEqual(
                    output_document["payment_provider"]["history_evidence_sha256"],
                    json.loads(history_bytes)["history_evidence_sha256"],
                )
                self.assertEqual(output_document["lifetime_consumed_slots"], purchase_count)
                self.assertEqual(output_bytes, _canonical(output_document))
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                loaded = load_pilot_slot_reconciliation(
                    output,
                    expected_prior_ledger=None,
                )
                self.assertEqual(loaded.evidence_sha256, hashlib.sha256(output_bytes).hexdigest())
                self.assertEqual(loaded.record_sha256, result.reconciliation.record_sha256)

    def test_embedded_history_and_purchase_record_tampering_are_rejected(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []
        bad_history_digest = _history_document(1)
        bad_history_digest["history_evidence_sha256"] = "0" * 64
        cases.append(("embedded digest", bad_history_digest))

        bad_purchase_digest = _history_document(1)
        purchase = cast(list[dict[str, object]], bad_purchase_digest["purchases"])[0]
        purchase["has_open_dispute"] = True
        _rehash_history(bad_purchase_digest)
        cases.append(("purchase record", bad_purchase_digest))

        mismatched_provider = _history_document(1)
        mismatched_provider["provider_purchase_sha256s"] = [_digest("different-provider")]
        _rehash_history(mismatched_provider)
        cases.append(("provider digest", mismatched_provider))

        for label, document in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                private = _secure_directory(Path(temporary))
                history = private / "history.json"
                _write_history(history, document)
                with self.assertRaises(StripeReconciliationError):
                    create_stripe_reconciliation(history, private / "output.json")
                self.assertFalse((private / "output.json").exists())

    def test_source_must_be_canonical_and_rejects_duplicate_json_fields(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            private = _secure_directory(Path(temporary))
            history = private / "history.json"
            document = _history_document()
            history.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            history.chmod(0o600)
            with self.assertRaisesRegex(StripeReconciliationError, "canonical"):
                load_stripe_history(history)

            duplicate = _canonical(document).replace(
                b'"livemode":true',
                b'"livemode":true,"livemode":true',
                1,
            )
            history.write_bytes(duplicate)
            history.chmod(0o600)
            with self.assertRaisesRegex(StripeReconciliationError, "duplicate"):
                load_stripe_history(history)

    def test_history_file_and_parent_permissions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            private = _secure_directory(root)
            history = private / "history.json"
            _write_history(history, _history_document())
            history.chmod(0o644)
            with self.assertRaisesRegex(StripeReconciliationError, "0600"):
                load_stripe_history(history)

            history.chmod(0o600)
            private.chmod(0o755)
            with self.assertRaisesRegex(StripeReconciliationError, "0700"):
                load_stripe_history(history)

    def test_oversized_history_and_symbolic_link_ancestors_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            private = _secure_directory(root, "real-private")
            oversized = private / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(MAX_HISTORY_BYTES + 1)
            oversized.chmod(0o600)
            with self.assertRaisesRegex(StripeReconciliationError, "size limit"):
                load_stripe_history(oversized)

            history = private / "history.json"
            _write_history(history, _history_document())
            linked = root / "linked-private"
            linked.symlink_to(private, target_is_directory=True)
            with self.assertRaisesRegex(StripeReconciliationError, "symbolic links"):
                load_stripe_history(linked / "history.json")

    def test_output_is_create_only_and_preserves_an_existing_file(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            private = _secure_directory(Path(temporary))
            history = private / "history.json"
            _write_history(history, _history_document())
            output = private / "reconciliation.json"
            output.write_text("existing\n", encoding="utf-8")
            output.chmod(0o600)

            with self.assertRaisesRegex(StripeReconciliationError, "already exists"):
                create_stripe_reconciliation(history, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing\n")
            self.assertEqual(
                [path.name for path in private.iterdir()],
                ["history.json", "reconciliation.json"],
            )

    def test_duplicate_provider_digests_and_incomplete_pagination_are_rejected(self) -> None:
        duplicate_digest = _digest("same-provider")
        duplicate = _history_document(2, provider_digests=[duplicate_digest, duplicate_digest])
        incomplete = _history_document()
        endpoint_coverage = cast(
            dict[str, dict[str, object]],
            incomplete["endpoint_coverage"],
        )
        endpoint_coverage["charges"]["pagination_complete"] = False
        _rehash_history(incomplete)

        for label, document in (("unique", duplicate), ("pagination", incomplete)):
            with self.subTest(case=label), tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                private = _secure_directory(Path(temporary))
                history = private / "history.json"
                _write_history(history, document)
                with self.assertRaises(StripeReconciliationError):
                    create_stripe_reconciliation(history, private / "output.json")

    def test_raw_references_urls_emails_and_secrets_are_rejected(self) -> None:
        forbidden = (
            "cs_live_private_reference",
            "https://private.example",
            "buyer@example.test",
            "sk" + "_live_" + "fixturesecret123456",
        )
        for value in forbidden:
            with self.subTest(value=value), tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                private = _secure_directory(Path(temporary))
                history = private / "history.json"
                document = _history_document()
                cast(dict[str, object], document["offer"])["name"] = value
                _rehash_history(document)
                _write_history(history, document)
                with self.assertRaisesRegex(StripeReconciliationError, "sensitive"):
                    load_stripe_history(history)

    def test_prior_ledger_provider_subset_is_enforced_with_secure_storage(self) -> None:
        retained_provider = _digest("retained-provider")
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            private = _secure_directory(Path(temporary))
            prior_path = private / "prior-ledger.jsonl"
            PilotLedger.initialize(
                prior_path,
                reconciliation_evidence=_initial_reconciliation([retained_provider]),
            )
            history = private / "history.json"
            _write_history(
                history,
                _history_document(1, provider_digests=[retained_provider]),
            )
            result = create_stripe_reconciliation(
                history,
                private / "accepted.json",
                prior_ledger=prior_path,
                reconciliation_ref=RECONCILIATION_REF,
                reconciled_at=RECONCILED_AT,
            )
            self.assertEqual(result.reconciliation.lifetime_consumed_slots, 1)
            self.assertIsNotNone(result.reconciliation.prior_ledger)

            _write_history(
                history,
                _history_document(1, provider_digests=[_digest("other-provider")]),
            )
            with self.assertRaisesRegex(StripeReconciliationError, "omits"):
                create_stripe_reconciliation(
                    history,
                    private / "rejected.json",
                    prior_ledger=prior_path,
                )
            self.assertFalse((private / "rejected.json").exists())

    def test_zero_capture_to_reconciliation_to_secure_schema_five_ledger(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            private = _secure_directory(Path(temporary))
            history = private / "stripe-history.json"
            collector, _transport = collector_for(complete_datasets(purchase_count=0))
            write_private_evidence(history, collector.collect())
            output = private / "pilot-slot-reconciliation.json"
            create_stripe_reconciliation(
                history,
                output,
                reconciliation_ref=RECONCILIATION_REF,
                reconciled_at=RECONCILED_AT,
            )
            reconciliation = load_pilot_slot_reconciliation(
                output,
                expected_prior_ledger=None,
            )
            ledger_path = private / "pilot-events.jsonl"
            ledger = PilotLedger.initialize(
                ledger_path,
                reconciliation_evidence=reconciliation,
            )

            self.assertEqual(ledger.metrics().remaining_founding_slots, 5)
            self.assertEqual(ledger.metrics().prior_consumed_slots, 0)
            self.assertTrue(ledger.storage_security()["private_mode_enforced"])
            self.assertEqual(stat.S_IMODE(history.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(ledger_path.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE((private / ".pilot-events.jsonl.lock").stat().st_mode),
                0o600,
            )

    def test_cli_stdout_is_aggregate_only(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            private = _secure_directory(Path(temporary))
            history = private / "history.json"
            document = _history_document(1)
            _write_history(history, document)
            output = private / "reconciliation.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = main(
                    [
                        "--history",
                        str(history),
                        "--output",
                        str(output),
                        "--reconciliation-ref",
                        RECONCILIATION_REF,
                        "--reconciled-at",
                        RECONCILED_AT,
                    ]
                )
            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["lifetime_consumed_slots"], 1)
            self.assertEqual(report["reconciliation_ref"], RECONCILIATION_REF)
            self.assertEqual(report["observed_at"], OBSERVED_AT)
            self.assertEqual(report["reconciled_at"], RECONCILED_AT)
            self.assertEqual(report["output"], str(output.absolute()))
            serialized = stdout.getvalue()
            provider_digests = cast(list[str], document["provider_purchase_sha256s"])
            self.assertNotIn(provider_digests[0], serialized)
            self.assertNotIn("provider_purchase", serialized)


if __name__ == "__main__":
    unittest.main()
