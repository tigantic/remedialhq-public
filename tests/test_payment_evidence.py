from __future__ import annotations

import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

from remedialhq.payment_evidence import (
    MAX_DOCUMENT_BYTES,
    LivePaymentEvidence,
    PaymentEvidenceError,
    PaymentEvidenceEvent,
    build_live_payment_evidence,
    load_live_payment_evidence,
    main,
    parse_live_payment_evidence,
)

ORDER_ID = "ord_" + "a" * 32


def opaque(prefix: str, number: int) -> str:
    return f"{prefix}_{number:032x}"


def captured_document() -> dict[str, object]:
    return {
        "schema_version": "remedialhq.live-payment-evidence.v1",
        "event_type": "PAYMENT_CAPTURED",
        "provider": "STRIPE",
        "mode": "LIVE",
        "livemode": True,
        "status": "SUCCEEDED",
        "currency": "USD",
        "amount_cents": 9_900,
        "payment_type": "ONE_TIME",
        "order_id": ORDER_ID,
        "observed_at": "2026-08-29T10:30:00-04:00",
        "evidence_ref": opaque("evd", 1),
        "provider_ref": opaque("pay", 2),
        "artifact_sha256": f"{3:064x}",
    }


def refund_document() -> dict[str, object]:
    document = captured_document()
    document.update(
        {
            "event_type": "FULL_REFUND",
            "observed_at": "2026-08-29T15:00:01+00:00",
            "evidence_ref": opaque("evd", 4),
            "provider_ref": opaque("rfd", 5),
            "artifact_sha256": f"{6:064x}",
            "original_payment_ref": opaque("pay", 2),
            "refunded_amount_cents": 9_900,
        }
    )
    return document


class PaymentEvidenceTests(unittest.TestCase):
    def test_capture_returns_normalized_immutable_record_and_digest(self) -> None:
        record = build_live_payment_evidence(
            captured_document(),
            expected_order_id=ORDER_ID,
        )

        self.assertEqual(record.event_type, PaymentEvidenceEvent.PAYMENT_CAPTURED)
        self.assertEqual(record.order_id, ORDER_ID)
        self.assertEqual(record.observed_at, "2026-08-29T14:30:00Z")
        self.assertIsNone(record.original_payment_ref)
        self.assertIsNone(record.refunded_amount_cents)
        self.assertEqual(record.to_dict()["amount_cents"], 9_900)
        self.assertRegex(record.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(record.envelope(), {"record": record.to_dict(), "sha256": record.sha256})
        with self.assertRaises(FrozenInstanceError):
            record.observed_at = "2026-08-29T00:00:00Z"  # type: ignore[misc]

    def test_refund_requires_opaque_correlation_and_exact_full_amount(self) -> None:
        record = build_live_payment_evidence(
            refund_document(),
            expected_order_id=ORDER_ID,
        )
        output = record.to_dict()

        self.assertEqual(record.event_type, PaymentEvidenceEvent.FULL_REFUND)
        self.assertEqual(output["original_payment_ref"], opaque("pay", 2))
        self.assertEqual(output["refunded_amount_cents"], 9_900)
        self.assertEqual(output["amount_cents"], 9_900)

    def test_digest_is_deterministic_across_key_order_and_timezone_spelling(self) -> None:
        first = captured_document()
        second = dict(reversed(list(first.items())))
        second["observed_at"] = "2026-08-29T14:30:00Z"

        first_record = build_live_payment_evidence(first, expected_order_id=ORDER_ID)
        second_record = build_live_payment_evidence(second, expected_order_id=ORDER_ID)

        self.assertEqual(first_record.to_dict(), second_record.to_dict())
        self.assertEqual(first_record.sha256, second_record.sha256)

    def test_returned_dict_is_fresh_and_cannot_mutate_record(self) -> None:
        record = build_live_payment_evidence(
            captured_document(),
            expected_order_id=ORDER_ID,
        )
        mutable = record.to_dict()
        mutable["mode"] = "TEST"

        self.assertEqual(record.to_dict()["mode"], "LIVE")
        self.assertEqual(record.sha256, record.envelope()["sha256"])

    def test_capture_and_refund_must_match_the_expected_order(self) -> None:
        other_order_id = opaque("ord", 10)
        for fixture in (captured_document, refund_document):
            with (
                self.subTest(event=fixture()["event_type"]),
                self.assertRaisesRegex(PaymentEvidenceError, "expected order"),
            ):
                build_live_payment_evidence(
                    fixture(),
                    expected_order_id=other_order_id,
                )

        other_document = captured_document()
        other_document["order_id"] = other_order_id
        other_record = build_live_payment_evidence(
            other_document,
            expected_order_id=other_order_id,
        )
        original_record = build_live_payment_evidence(
            captured_document(),
            expected_order_id=ORDER_ID,
        )
        self.assertNotEqual(other_record.sha256, original_record.sha256)

    def test_order_id_must_be_lowercase_and_opaque(self) -> None:
        for value in ("ord_short", ORDER_ID.upper(), opaque("pay", 9)):
            with self.subTest(value=value[:4]):
                document = captured_document()
                document["order_id"] = value
                with self.assertRaises(PaymentEvidenceError):
                    build_live_payment_evidence(
                        document,
                        expected_order_id=ORDER_ID,
                    )

    def test_exact_live_stripe_success_and_product_controls(self) -> None:
        invalid_values = (
            ("schema_version", "remedialhq.live-payment-evidence.v2"),
            ("provider", "stripe"),
            ("mode", "TEST"),
            ("livemode", False),
            ("livemode", 1),
            ("status", "PENDING"),
            ("currency", "usd"),
            ("amount_cents", 9_899),
            ("amount_cents", 99.0),
            ("payment_type", "RECURRING"),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                document = captured_document()
                document[field] = value
                with self.assertRaises(PaymentEvidenceError):
                    build_live_payment_evidence(document, expected_order_id=ORDER_ID)

    def test_only_two_event_types_are_allowed(self) -> None:
        for value in ("PAYMENT_CREATED", "PARTIAL_REFUND", "payment_captured", 1):
            with self.subTest(value=value):
                document = captured_document()
                document["event_type"] = value
                with self.assertRaises(PaymentEvidenceError):
                    build_live_payment_evidence(document, expected_order_id=ORDER_ID)

    def test_unknown_and_missing_fields_are_rejected_for_each_event(self) -> None:
        cases: list[dict[str, object]] = []
        for fixture in (captured_document, refund_document):
            unknown = fixture()
            unknown["note"] = "redacted"
            missing = fixture()
            missing.pop("artifact_sha256")
            cases.extend((unknown, missing))

        for document in cases:
            with (
                self.subTest(event=document.get("event_type")),
                self.assertRaisesRegex(PaymentEvidenceError, "missing or unknown"),
            ):
                build_live_payment_evidence(document, expected_order_id=ORDER_ID)

    def test_event_specific_fields_cannot_cross_boundaries(self) -> None:
        capture_with_refund = captured_document()
        capture_with_refund["original_payment_ref"] = opaque("pay", 7)
        capture_with_refund["refunded_amount_cents"] = 9_900

        refund_without_correlation = refund_document()
        refund_without_correlation.pop("original_payment_ref")

        for document in (capture_with_refund, refund_without_correlation):
            with self.assertRaises(PaymentEvidenceError):
                build_live_payment_evidence(document, expected_order_id=ORDER_ID)

    def test_partial_over_or_non_integer_refunds_are_rejected(self) -> None:
        for value in (0, 5_000, 9_901, 9_900.0, True):
            with self.subTest(value=value):
                document = refund_document()
                document["refunded_amount_cents"] = value
                with self.assertRaises(PaymentEvidenceError):
                    build_live_payment_evidence(document, expected_order_id=ORDER_ID)

    def test_references_are_lowercase_opaque_and_event_typed(self) -> None:
        invalid_values = (
            (captured_document, "evidence_ref", "evd_short"),
            (captured_document, "provider_ref", opaque("rfd", 2)),
            (captured_document, "provider_ref", "pi_1234567890abcdef"),
            (captured_document, "artifact_sha256", "A" * 64),
            (refund_document, "provider_ref", opaque("pay", 5)),
            (refund_document, "original_payment_ref", opaque("rfd", 2)),
            (refund_document, "original_payment_ref", "pi_1234567890abcdef"),
        )
        for fixture, field, value in invalid_values:
            with self.subTest(field=field, value=value[:4]):
                document = fixture()
                document[field] = value
                with self.assertRaises(PaymentEvidenceError):
                    build_live_payment_evidence(document, expected_order_id=ORDER_ID)

    def test_timestamp_must_be_valid_timezone_aware_rfc3339(self) -> None:
        invalid_values = (
            "2026-08-29T14:30:00",
            "2026-08-29 14:30:00Z",
            "2026-02-30T14:30:00Z",
            "2026-08-29T14:30Z",
            "yesterday",
        )
        for value in invalid_values:
            with self.subTest(value=value):
                document = captured_document()
                document["observed_at"] = value
                with self.assertRaises(PaymentEvidenceError):
                    build_live_payment_evidence(document, expected_order_id=ORDER_ID)

    def test_sensitive_values_are_rejected_without_echo(self) -> None:
        sensitive_values = (
            "sk_" + "live_" + "a" * 24,
            "cf" + "ut_" + "b" * 24,
            "wh" + "sec_" + "c" * 24,
            "4242 4242 4242 4242",
            "buyer" + "@" + "example.com",
            "https" + "://example.com/receipt",
            "Jo" + "hn Do" + "e",
            "123" + " Main Street",
            "C" + "VC 123",
            "pi_" + "1234567890abcdef",
        )
        for sensitive_value in sensitive_values:
            with self.subTest(category=sensitive_value[:3]):
                document = captured_document()
                document["note"] = sensitive_value
                with self.assertRaises(PaymentEvidenceError) as context:
                    build_live_payment_evidence(document, expected_order_id=ORDER_ID)
                self.assertNotIn(sensitive_value, str(context.exception))

    def test_raw_provider_payload_and_sensitive_field_names_are_rejected(self) -> None:
        for field in ("payload", "raw", "data", "card", "email", "receipt_url"):
            with self.subTest(field=field):
                document = captured_document()
                document[field] = {"object": "redacted"}
                with self.assertRaisesRegex(PaymentEvidenceError, "forbidden"):
                    build_live_payment_evidence(document, expected_order_id=ORDER_ID)

    def test_strict_json_rejects_duplicate_keys_and_non_json_numbers(self) -> None:
        duplicate = '{"event_type":"PAYMENT_CAPTURED","event_type":"FULL_REFUND"}'
        for text in (duplicate, '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(text=text), self.assertRaises(PaymentEvidenceError):
                parse_live_payment_evidence(text, expected_order_id=ORDER_ID)

    def test_invalid_json_and_non_object_json_are_rejected_without_content_echo(self) -> None:
        invalid_text = '{"secret":"sk_' + "live_" + "z" * 24
        with self.assertRaises(PaymentEvidenceError) as context:
            parse_live_payment_evidence(invalid_text, expected_order_id=ORDER_ID)
        self.assertNotIn(invalid_text, str(context.exception))

        for text in ("[]", '"PAYMENT_CAPTURED"', "null"):
            with self.subTest(text=text), self.assertRaises(PaymentEvidenceError):
                parse_live_payment_evidence(text, expected_order_id=ORDER_ID)

    def test_direct_mapping_cycle_and_excessive_nesting_are_rejected(self) -> None:
        cyclic: dict[str, object] = {}
        cyclic["payload"] = cyclic
        nested: object = "leaf"
        for _ in range(10):
            nested = [nested]

        for value in (cyclic, {"payload": nested}):
            with self.assertRaises(PaymentEvidenceError):
                build_live_payment_evidence(value, expected_order_id=ORDER_ID)

    def test_file_loader_accepts_regular_file(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(captured_document()), encoding="utf-8")

            record = load_live_payment_evidence(path, expected_order_id=ORDER_ID)

        self.assertEqual(record.event_type, PaymentEvidenceEvent.PAYMENT_CAPTURED)

    def test_file_loader_detects_replacement_between_inspection_and_open(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            replacement = Path(directory) / "replacement.json"
            path.write_text(json.dumps(captured_document()), encoding="utf-8")
            replacement.write_text(json.dumps(captured_document()), encoding="utf-8")
            original_open = os.open
            replaced = False

            def replace_then_open(
                target: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
            ) -> int:
                nonlocal replaced
                if not replaced:
                    path.unlink()
                    replacement.replace(path)
                    replaced = True
                return original_open(target, flags, mode)

            with (
                mock.patch(
                    "remedialhq.payment_evidence.os.open",
                    side_effect=replace_then_open,
                ),
                self.assertRaisesRegex(PaymentEvidenceError, "changed while opening"),
            ):
                load_live_payment_evidence(path, expected_order_id=ORDER_ID)

    def test_file_loader_detects_growth_during_read(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(captured_document()), encoding="utf-8")
            original_read = os.read
            grew = False

            def read_then_grow(descriptor: int, size: int) -> bytes:
                nonlocal grew
                chunk = original_read(descriptor, size)
                if chunk and not grew:
                    with path.open("ab") as stream:
                        stream.write(b" ")
                    grew = True
                return chunk

            with (
                mock.patch(
                    "remedialhq.payment_evidence.os.read",
                    side_effect=read_then_grow,
                ),
                self.assertRaisesRegex(PaymentEvidenceError, "changed while reading"),
            ):
                load_live_payment_evidence(path, expected_order_id=ORDER_ID)

    def test_file_loader_rejects_leaf_symlinks_and_non_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text(json.dumps(captured_document()), encoding="utf-8")
            symlink = root / "linked.json"
            symlink.symlink_to(target)
            real_parent = root / "real-parent"
            real_parent.mkdir()
            nested_target = real_parent / "nested.json"
            nested_target.write_text(json.dumps(captured_document()), encoding="utf-8")
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaisesRegex(PaymentEvidenceError, "symlink"):
                load_live_payment_evidence(symlink, expected_order_id=ORDER_ID)
            with self.assertRaisesRegex(PaymentEvidenceError, "symlink ancestors"):
                load_live_payment_evidence(
                    linked_parent / "nested.json",
                    expected_order_id=ORDER_ID,
                )
            with self.assertRaisesRegex(PaymentEvidenceError, "regular file"):
                load_live_payment_evidence(root, expected_order_id=ORDER_ID)

            if hasattr(os, "mkfifo"):
                fifo = root / "evidence.fifo"
                os.mkfifo(fifo)
                with self.assertRaisesRegex(PaymentEvidenceError, "regular file"):
                    load_live_payment_evidence(fifo, expected_order_id=ORDER_ID)

    def test_file_loader_rejects_oversized_and_non_utf8_input(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            oversized = root / "oversized.json"
            oversized.write_text(" " * (MAX_DOCUMENT_BYTES + 1), encoding="utf-8")
            invalid_utf8 = root / "invalid.json"
            invalid_utf8.write_bytes(b"\xff\xfe\xfd")

            with self.assertRaisesRegex(PaymentEvidenceError, "size limit"):
                load_live_payment_evidence(oversized, expected_order_id=ORDER_ID)
            with self.assertRaisesRegex(PaymentEvidenceError, "UTF-8"):
                load_live_payment_evidence(invalid_utf8, expected_order_id=ORDER_ID)

    def test_module_cli_prints_only_normalized_record_and_digest(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(refund_document()), encoding="utf-8")
            standard_output = io.StringIO()
            standard_error = io.StringIO()

            with redirect_stdout(standard_output), redirect_stderr(standard_error):
                exit_code = main([str(path), "--order-id", ORDER_ID])

        self.assertEqual(exit_code, 0)
        self.assertEqual(standard_error.getvalue(), "")
        output = json.loads(standard_output.getvalue())
        self.assertEqual(set(output), {"record", "sha256"})
        self.assertEqual(output["record"]["event_type"], "FULL_REFUND")
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", output["sha256"]))

    def test_module_cli_rejection_is_generic_and_does_not_echo_content(self) -> None:
        secret = "sk_" + "live_" + "z" * 24
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            document = captured_document()
            document["note"] = secret
            path.write_text(json.dumps(document), encoding="utf-8")
            standard_output = io.StringIO()
            standard_error = io.StringIO()

            with redirect_stdout(standard_output), redirect_stderr(standard_error):
                exit_code = main([str(path), "--order-id", ORDER_ID])

        self.assertEqual(exit_code, 2)
        self.assertEqual(standard_output.getvalue(), "")
        self.assertEqual(standard_error.getvalue(), "live payment evidence rejected\n")
        self.assertNotIn(secret, standard_error.getvalue())

    def test_public_constructor_shape_cannot_create_invalid_refund_output(self) -> None:
        with self.assertRaises(PaymentEvidenceError):
            LivePaymentEvidence(
                event_type=PaymentEvidenceEvent.FULL_REFUND,
                order_id=ORDER_ID,
                observed_at="2026-08-29T15:00:00Z",
                evidence_ref=opaque("evd", 1),
                provider_ref=opaque("rfd", 2),
                artifact_sha256=f"{3:064x}",
            )


if __name__ == "__main__":
    unittest.main()
