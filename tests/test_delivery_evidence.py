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

from remedialhq.delivery_evidence import (
    MAX_DOCUMENT_BYTES,
    DeliveryEvidence,
    DeliveryEvidenceError,
    DeliveryMethod,
    build_delivery_evidence,
    load_delivery_evidence,
    main,
    parse_delivery_evidence,
)

ARTIFACT_SHA256 = "a" * 64
EVIDENCE_ARTIFACT_SHA256 = "c" * 64
ORDER_ID = "ord_" + "b" * 32


def opaque(prefix: str, number: int) -> str:
    return f"{prefix}_{number:032x}"


def valid_document(method: str = "EMAIL_PROVIDER_ACCEPTED") -> dict[str, object]:
    return {
        "schema_version": "remedialhq.delivery-evidence.v1",
        "event_type": "DELIVERY_RECORDED",
        "delivery_method": method,
        "order_id": ORDER_ID,
        "artifact_sha256": ARTIFACT_SHA256,
        "evidence_artifact_sha256": EVIDENCE_ARTIFACT_SHA256,
        "observed_at": "2026-08-29T11:15:00-04:00",
        "evidence_ref": opaque("evd", 1),
        "delivery_ref": opaque("dlv", 2),
    }


class DeliveryEvidenceTests(unittest.TestCase):
    def test_each_externally_meaningful_method_produces_normalized_record(self) -> None:
        for method in DeliveryMethod:
            with self.subTest(method=method.value):
                record = build_delivery_evidence(
                    valid_document(method.value),
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )
                output = record.to_dict()

                self.assertEqual(output["event_type"], "DELIVERY_RECORDED")
                self.assertEqual(output["delivery_method"], method.value)
                self.assertEqual(output["order_id"], ORDER_ID)
                self.assertEqual(output["artifact_sha256"], ARTIFACT_SHA256)
                self.assertEqual(
                    output["evidence_artifact_sha256"],
                    EVIDENCE_ARTIFACT_SHA256,
                )
                self.assertEqual(output["observed_at"], "2026-08-29T15:15:00Z")
                self.assertRegex(record.sha256, r"^[0-9a-f]{64}$")

    def test_record_is_immutable_and_returns_fresh_output(self) -> None:
        record = build_delivery_evidence(
            valid_document(),
            expected_order_id=ORDER_ID,
            expected_artifact_sha256=ARTIFACT_SHA256,
        )
        mutable = record.to_dict()
        mutable["delivery_method"] = "LOCAL_FILE_CREATED"

        self.assertEqual(record.to_dict()["delivery_method"], "EMAIL_PROVIDER_ACCEPTED")
        self.assertEqual(record.envelope(), {"record": record.to_dict(), "sha256": record.sha256})
        with self.assertRaises(FrozenInstanceError):
            record.observed_at = "2026-08-29T00:00:00Z"  # type: ignore[misc]

    def test_digest_is_deterministic_across_key_order_and_timezone_spelling(self) -> None:
        first = valid_document()
        second = dict(reversed(list(first.items())))
        second["observed_at"] = "2026-08-29T15:15:00Z"

        first_record = build_delivery_evidence(
            first,
            expected_order_id=ORDER_ID,
            expected_artifact_sha256=ARTIFACT_SHA256,
        )
        second_record = build_delivery_evidence(
            second,
            expected_order_id=ORDER_ID,
            expected_artifact_sha256=ARTIFACT_SHA256,
        )

        self.assertEqual(first_record.to_dict(), second_record.to_dict())
        self.assertEqual(first_record.sha256, second_record.sha256)

    def test_exact_completed_artifact_digest_is_mandatory(self) -> None:
        different_digest = "b" * 64
        cases = (
            (valid_document(), different_digest),
            ({**valid_document(), "artifact_sha256": different_digest}, ARTIFACT_SHA256),
            (valid_document(), ARTIFACT_SHA256.upper()),
            ({**valid_document(), "artifact_sha256": ARTIFACT_SHA256.upper()}, ARTIFACT_SHA256),
        )
        for document, expected in cases:
            with self.subTest(expected=expected[:4]), self.assertRaises(DeliveryEvidenceError):
                build_delivery_evidence(
                    document,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=expected,
                )

    def test_delivery_must_match_the_expected_order(self) -> None:
        other_order_id = opaque("ord", 55)
        with self.assertRaisesRegex(DeliveryEvidenceError, "expected order"):
            build_delivery_evidence(
                valid_document(),
                expected_order_id=other_order_id,
                expected_artifact_sha256=ARTIFACT_SHA256,
            )

        other_document = valid_document()
        other_document["order_id"] = other_order_id
        other_record = build_delivery_evidence(
            other_document,
            expected_order_id=other_order_id,
            expected_artifact_sha256=ARTIFACT_SHA256,
        )
        original_record = build_delivery_evidence(
            valid_document(),
            expected_order_id=ORDER_ID,
            expected_artifact_sha256=ARTIFACT_SHA256,
        )
        self.assertNotEqual(other_record.sha256, original_record.sha256)

    def test_order_id_must_be_lowercase_and_opaque(self) -> None:
        for value in ("ord_short", ORDER_ID.upper(), opaque("dlv", 55)):
            with self.subTest(value=value[:4]):
                document = valid_document()
                document["order_id"] = value
                with self.assertRaises(DeliveryEvidenceError):
                    build_delivery_evidence(
                        document,
                        expected_order_id=ORDER_ID,
                        expected_artifact_sha256=ARTIFACT_SHA256,
                    )

    def test_evidence_artifact_digest_is_distinct_and_lowercase(self) -> None:
        cases = (
            ARTIFACT_SHA256,
            EVIDENCE_ARTIFACT_SHA256.upper(),
            "short",
        )
        for value in cases:
            with self.subTest(value=value[:4]):
                document = valid_document()
                document["evidence_artifact_sha256"] = value
                with self.assertRaises(DeliveryEvidenceError):
                    build_delivery_evidence(
                        document,
                        expected_order_id=ORDER_ID,
                        expected_artifact_sha256=ARTIFACT_SHA256,
                    )

        alternate_document = valid_document()
        alternate_document["evidence_artifact_sha256"] = "d" * 64
        alternate_record = build_delivery_evidence(
            alternate_document,
            expected_order_id=ORDER_ID,
            expected_artifact_sha256=ARTIFACT_SHA256,
        )
        original_record = build_delivery_evidence(
            valid_document(),
            expected_order_id=ORDER_ID,
            expected_artifact_sha256=ARTIFACT_SHA256,
        )
        self.assertNotEqual(alternate_record.sha256, original_record.sha256)

    def test_local_completion_or_internal_transfer_is_not_a_delivery_method(self) -> None:
        invalid_methods = (
            "LOCAL_FILE_CREATED",
            "ARTIFACT_COMPLETED",
            "INTERNAL_UPLOAD",
            "EMAIL_SENT",
            "DELIVERED",
        )
        for method in invalid_methods:
            with self.subTest(method=method), self.assertRaises(DeliveryEvidenceError):
                build_delivery_evidence(
                    valid_document(method),
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )

    def test_schema_event_and_method_are_exact(self) -> None:
        cases = (
            ("schema_version", "remedialhq.delivery-evidence.v2"),
            ("event_type", "DELIVERED"),
            ("event_type", "delivery_recorded"),
            ("delivery_method", "email_provider_accepted"),
            ("delivery_method", 1),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                document = valid_document()
                document[field] = value
                with self.assertRaises(DeliveryEvidenceError):
                    build_delivery_evidence(
                        document,
                        expected_order_id=ORDER_ID,
                        expected_artifact_sha256=ARTIFACT_SHA256,
                    )

    def test_unknown_and_missing_fields_are_rejected(self) -> None:
        unknown = valid_document()
        unknown["recipient_redacted"] = True
        missing = valid_document()
        missing.pop("delivery_ref")

        for document in (unknown, missing):
            with self.assertRaisesRegex(DeliveryEvidenceError, "missing or unknown"):
                build_delivery_evidence(
                    document,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )

    def test_references_must_be_opaque_and_lowercase(self) -> None:
        cases = (
            ("evidence_ref", "evd_short"),
            ("evidence_ref", opaque("evd", 1).upper()),
            ("delivery_ref", "sg_1234567890abcdef"),
            ("delivery_ref", "message_1234567890abcdef"),
            ("delivery_ref", opaque("dlv", 2).upper()),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value[:4]):
                document = valid_document()
                document[field] = value
                with self.assertRaises(DeliveryEvidenceError):
                    build_delivery_evidence(
                        document,
                        expected_order_id=ORDER_ID,
                        expected_artifact_sha256=ARTIFACT_SHA256,
                    )

    def test_timestamp_must_be_valid_timezone_aware_rfc3339(self) -> None:
        for value in (
            "2026-08-29T15:15:00",
            "2026-08-29 15:15:00Z",
            "2026-02-30T15:15:00Z",
            "2026-08-29T15:15Z",
            "yesterday",
        ):
            with self.subTest(value=value):
                document = valid_document()
                document["observed_at"] = value
                with self.assertRaises(DeliveryEvidenceError):
                    build_delivery_evidence(
                        document,
                        expected_order_id=ORDER_ID,
                        expected_artifact_sha256=ARTIFACT_SHA256,
                    )

    def test_sensitive_values_are_rejected_without_echo(self) -> None:
        sensitive_values = (
            "sk_" + "live_" + "a" * 24,
            "cf" + "ut_" + "b" * 24,
            "wh" + "sec_" + "c" * 24,
            "4242 4242 4242 4242",
            "buyer" + "@" + "example.com",
            "https" + "://example.com/download",
            "Jo" + "hn Do" + "e",
            "123" + " Main Street",
            "message_" + "1234567890abcdef",
        )
        for sensitive_value in sensitive_values:
            with self.subTest(category=sensitive_value[:3]):
                document = valid_document()
                document["note"] = sensitive_value
                with self.assertRaises(DeliveryEvidenceError) as context:
                    build_delivery_evidence(
                        document,
                        expected_order_id=ORDER_ID,
                        expected_artifact_sha256=ARTIFACT_SHA256,
                    )
                self.assertNotIn(sensitive_value, str(context.exception))

    def test_raw_payload_and_sensitive_field_names_are_rejected(self) -> None:
        for field in ("payload", "raw", "data", "email", "recipient", "message_id"):
            with self.subTest(field=field):
                document = valid_document()
                document[field] = {"provider_id": "redacted"}
                with self.assertRaisesRegex(DeliveryEvidenceError, "forbidden"):
                    build_delivery_evidence(
                        document,
                        expected_order_id=ORDER_ID,
                        expected_artifact_sha256=ARTIFACT_SHA256,
                    )

    def test_strict_json_rejects_duplicate_fields_and_non_json_numbers(self) -> None:
        duplicate = '{"event_type":"DELIVERY_RECORDED","event_type":"DELIVERED"}'
        for text in (duplicate, '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(text=text), self.assertRaises(DeliveryEvidenceError):
                parse_delivery_evidence(
                    text,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )

    def test_invalid_and_non_object_json_are_rejected_without_echo(self) -> None:
        invalid_text = '{"secret":"sk_' + "live_" + "z" * 24
        with self.assertRaises(DeliveryEvidenceError) as context:
            parse_delivery_evidence(
                invalid_text,
                expected_order_id=ORDER_ID,
                expected_artifact_sha256=ARTIFACT_SHA256,
            )
        self.assertNotIn(invalid_text, str(context.exception))

        for text in ("[]", '"DELIVERY_RECORDED"', "null"):
            with self.subTest(text=text), self.assertRaises(DeliveryEvidenceError):
                parse_delivery_evidence(
                    text,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )

    def test_direct_constructor_enforces_normalized_validated_shape(self) -> None:
        with self.assertRaises(DeliveryEvidenceError):
            DeliveryEvidence(
                delivery_method=DeliveryMethod.CUSTOMER_ACKNOWLEDGED,
                order_id=ORDER_ID,
                artifact_sha256=ARTIFACT_SHA256,
                evidence_artifact_sha256=EVIDENCE_ARTIFACT_SHA256,
                observed_at="2026-08-29T11:15:00-04:00",
                evidence_ref=opaque("evd", 1),
                delivery_ref=opaque("dlv", 2),
            )

    def test_file_loader_accepts_regular_file(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "delivery.json"
            path.write_text(json.dumps(valid_document()), encoding="utf-8")

            record = load_delivery_evidence(
                path,
                expected_order_id=ORDER_ID,
                expected_artifact_sha256=ARTIFACT_SHA256,
            )

        self.assertEqual(record.delivery_method, DeliveryMethod.EMAIL_PROVIDER_ACCEPTED)

    def test_file_loader_detects_replacement_between_inspection_and_open(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            replacement = Path(directory) / "replacement.json"
            path.write_text(json.dumps(valid_document()), encoding="utf-8")
            replacement.write_text(json.dumps(valid_document()), encoding="utf-8")
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
                    "remedialhq.delivery_evidence.os.open",
                    side_effect=replace_then_open,
                ),
                self.assertRaisesRegex(DeliveryEvidenceError, "changed while opening"),
            ):
                load_delivery_evidence(
                    path,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )

    def test_file_loader_detects_growth_during_read(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(valid_document()), encoding="utf-8")
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
                    "remedialhq.delivery_evidence.os.read",
                    side_effect=read_then_grow,
                ),
                self.assertRaisesRegex(DeliveryEvidenceError, "changed while reading"),
            ):
                load_delivery_evidence(
                    path,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )

    def test_file_loader_rejects_symlinks_and_non_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text(json.dumps(valid_document()), encoding="utf-8")
            linked_file = root / "linked.json"
            linked_file.symlink_to(target)
            real_parent = root / "real-parent"
            real_parent.mkdir()
            nested_target = real_parent / "nested.json"
            nested_target.write_text(json.dumps(valid_document()), encoding="utf-8")
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaisesRegex(DeliveryEvidenceError, "symlink"):
                load_delivery_evidence(
                    linked_file,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )
            with self.assertRaisesRegex(DeliveryEvidenceError, "symlink ancestors"):
                load_delivery_evidence(
                    linked_parent / "nested.json",
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )
            with self.assertRaisesRegex(DeliveryEvidenceError, "regular file"):
                load_delivery_evidence(
                    root,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )

            if hasattr(os, "mkfifo"):
                fifo = root / "delivery.fifo"
                os.mkfifo(fifo)
                with self.assertRaisesRegex(DeliveryEvidenceError, "regular file"):
                    load_delivery_evidence(
                        fifo,
                        expected_order_id=ORDER_ID,
                        expected_artifact_sha256=ARTIFACT_SHA256,
                    )

    def test_file_loader_rejects_oversized_and_non_utf8_input(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            oversized = root / "oversized.json"
            oversized.write_text(" " * (MAX_DOCUMENT_BYTES + 1), encoding="utf-8")
            invalid_utf8 = root / "invalid.json"
            invalid_utf8.write_bytes(b"\xff\xfe\xfd")

            with self.assertRaisesRegex(DeliveryEvidenceError, "size limit"):
                load_delivery_evidence(
                    oversized,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )
            with self.assertRaisesRegex(DeliveryEvidenceError, "UTF-8"):
                load_delivery_evidence(
                    invalid_utf8,
                    expected_order_id=ORDER_ID,
                    expected_artifact_sha256=ARTIFACT_SHA256,
                )

    def test_cli_prints_only_normalized_record_and_digest(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "delivery.json"
            path.write_text(json.dumps(valid_document()), encoding="utf-8")
            standard_output = io.StringIO()
            standard_error = io.StringIO()

            with redirect_stdout(standard_output), redirect_stderr(standard_error):
                exit_code = main(
                    [
                        str(path),
                        "--order-id",
                        ORDER_ID,
                        "--artifact-sha256",
                        ARTIFACT_SHA256,
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(standard_error.getvalue(), "")
        output = json.loads(standard_output.getvalue())
        self.assertEqual(set(output), {"record", "sha256"})
        self.assertEqual(output["record"]["event_type"], "DELIVERY_RECORDED")
        self.assertEqual(output["record"]["order_id"], ORDER_ID)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", output["sha256"]))

    def test_cli_rejection_is_generic(self) -> None:
        secret = "sk_" + "live_" + "z" * 24
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "delivery.json"
            document = valid_document()
            document["note"] = secret
            path.write_text(json.dumps(document), encoding="utf-8")
            standard_output = io.StringIO()
            standard_error = io.StringIO()

            with redirect_stdout(standard_output), redirect_stderr(standard_error):
                exit_code = main(
                    [
                        str(path),
                        "--order-id",
                        ORDER_ID,
                        "--artifact-sha256",
                        ARTIFACT_SHA256,
                    ]
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(standard_output.getvalue(), "")
        self.assertEqual(standard_error.getvalue(), "delivery evidence rejected\n")
        self.assertNotIn(secret, standard_error.getvalue())


if __name__ == "__main__":
    unittest.main()
