from __future__ import annotations

import copy
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import cast
from unittest import mock

from remedialhq.payment_tests import (
    CANCELLATION_INTERPRETATION,
    MAX_DOCUMENT_BYTES,
    PaymentTestEvidenceError,
    PaymentTestFlow,
    build_payment_test_report,
    load_payment_test_evidence,
    main,
    parse_payment_test_evidence,
)


def _opaque(prefix: str, number: int) -> str:
    return f"{prefix}_{number:032x}"


def _artifact(number: int) -> str:
    return f"{number:064x}"


def valid_document(classification: str = "SYNTHETIC") -> dict[str, object]:
    return {
        "schema_version": "remedialhq.payment-test-evidence.v1",
        "provider": "STRIPE",
        "mode": "TEST",
        "livemode": False,
        "currency": "USD",
        "unit_amount_cents": 9_900,
        "payment_type": "ONE_TIME",
        "test_run_ref": _opaque("run", 1),
        "evidence": [
            {
                "flow": "SUCCESSFUL_CHECKOUT",
                "classification": classification,
                "observed_at": "2026-08-29T10:00:00-04:00",
                "evidence_ref": _opaque("evd", 1),
                "provider_ref": _opaque("ref", 11),
                "correlation_ref": _opaque("cor", 21),
                "artifact_sha256": _artifact(101),
                "outcome": "PAYMENT_SUCCEEDED",
                "charged_amount_cents": 9_900,
                "payment_method_redacted": True,
            },
            {
                "flow": "ABANDONMENT",
                "classification": classification,
                "observed_at": "2026-08-29T09:00:00-04:00",
                "evidence_ref": _opaque("evd", 2),
                "provider_ref": _opaque("ref", 12),
                "correlation_ref": _opaque("cor", 22),
                "artifact_sha256": _artifact(102),
                "outcome": "CHECKOUT_ABANDONED_NO_PAYMENT",
                "payment_created": False,
            },
            {
                "flow": "RECEIPT",
                "classification": classification,
                "observed_at": "2026-08-29T14:01:00Z",
                "evidence_ref": _opaque("evd", 3),
                "provider_ref": _opaque("ref", 13),
                "correlation_ref": _opaque("cor", 21),
                "artifact_sha256": _artifact(103),
                "outcome": "RECEIPT_ISSUED",
                "receipt_amount_cents": 9_900,
                "recipient_redacted": True,
            },
            {
                "flow": "CANCELLATION_INTERPRETATION",
                "classification": classification,
                "observed_at": "2026-08-29T14:02:00+00:00",
                "evidence_ref": _opaque("evd", 4),
                "provider_ref": _opaque("ref", 14),
                "correlation_ref": _opaque("cor", 21),
                "artifact_sha256": _artifact(104),
                "outcome": "CANCELLATION_REQUEST_RECORDED",
                "interpretation": CANCELLATION_INTERPRETATION,
                "required_follow_up": "FULL_REFUND",
            },
            {
                "flow": "FULL_REFUND",
                "classification": classification,
                "observed_at": "2026-08-29T14:03:00Z",
                "evidence_ref": _opaque("evd", 5),
                "provider_ref": _opaque("ref", 15),
                "correlation_ref": _opaque("cor", 21),
                "artifact_sha256": _artifact(105),
                "outcome": "REFUND_SUCCEEDED",
                "refunded_amount_cents": 9_900,
            },
        ],
    }


def evidence_for(document: dict[str, object], flow: PaymentTestFlow) -> dict[str, object]:
    evidence = document["evidence"]
    if not isinstance(evidence, list):
        raise TypeError("test fixture evidence must be a list")
    for item in evidence:
        if isinstance(item, dict) and item.get("flow") == flow.value:
            return item
    raise AssertionError(f"missing test fixture flow {flow.value}")


class PaymentTestEvidenceTests(unittest.TestCase):
    def test_valid_document_produces_normalized_report_and_lowercase_digest(self) -> None:
        report = build_payment_test_report(valid_document())
        output = report.to_dict()

        self.assertEqual(output["schema_gate_status"], "PASS")
        self.assertEqual(output["provider"], "STRIPE")
        self.assertEqual(output["mode"], "TEST")
        self.assertIs(output["livemode"], False)
        self.assertEqual(output["currency"], "USD")
        self.assertEqual(output["unit_amount_cents"], 9_900)
        self.assertEqual(output["payment_type"], "ONE_TIME")
        self.assertEqual(output["test_run_ref"], _opaque("run", 1))
        self.assertEqual(output["flow_count"], 5)
        flows = cast(list[dict[str, object]], output["flows"])
        self.assertEqual(
            [item["flow"] for item in flows],
            [flow.value for flow in PaymentTestFlow],
        )
        self.assertEqual(output["first_observed_at"], "2026-08-29T13:00:00Z")
        self.assertEqual(output["last_observed_at"], "2026-08-29T14:03:00Z")
        self.assertEqual(
            output["classification_counts"],
            {"SYNTHETIC": 5, "OWNER_CAPTURED": 0},
        )
        self.assertRegex(report.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(report.envelope()["sha256"], report.sha256)

    def test_digest_is_deterministic_across_input_order_and_timezone_spelling(self) -> None:
        first = valid_document()
        second = copy.deepcopy(first)
        evidence = cast(list[dict[str, object]], second["evidence"])
        evidence.reverse()
        checkout = evidence_for(second, PaymentTestFlow.SUCCESSFUL_CHECKOUT)
        checkout["observed_at"] = "2026-08-29T14:00:00Z"

        self.assertEqual(
            build_payment_test_report(first).sha256,
            build_payment_test_report(second).sha256,
        )

    def test_owner_captured_evidence_still_has_no_completion_authority(self) -> None:
        report = build_payment_test_report(valid_document("OWNER_CAPTURED")).to_dict()

        self.assertEqual(
            report["classification_counts"],
            {"SYNTHETIC": 0, "OWNER_CAPTURED": 5},
        )
        self.assertIs(report["rmh_106_may_be_marked_complete"], False)
        completion_boundary = cast(str, report["completion_boundary"])
        self.assertIn("cannot mark RMH-106 complete", completion_boundary)
        self.assertIs(report["live_mode_evidence_accepted"], False)
        self.assertIs(report["raw_provider_payloads_accepted"], False)

    def test_mixed_evidence_is_classified_per_flow(self) -> None:
        document = valid_document()
        evidence_for(document, PaymentTestFlow.RECEIPT)["classification"] = "OWNER_CAPTURED"

        counts = build_payment_test_report(document).to_dict()["classification_counts"]
        self.assertEqual(counts, {"SYNTHETIC": 4, "OWNER_CAPTURED": 1})

    def test_live_mode_is_rejected_by_both_independent_controls(self) -> None:
        for field, value in (("mode", "LIVE"), ("livemode", True)):
            with self.subTest(field=field):
                document = valid_document()
                document[field] = value
                with self.assertRaises(PaymentTestEvidenceError):
                    build_payment_test_report(document)

    def test_strict_boolean_fields_reject_integer_lookalikes(self) -> None:
        cases = (
            (None, "livemode", 0),
            (PaymentTestFlow.ABANDONMENT, "payment_created", 0),
            (PaymentTestFlow.SUCCESSFUL_CHECKOUT, "payment_method_redacted", 1),
            (PaymentTestFlow.RECEIPT, "recipient_redacted", 1),
        )
        for flow, field, value in cases:
            with self.subTest(field=field):
                document = valid_document()
                target = document if flow is None else evidence_for(document, flow)
                target[field] = value
                with self.assertRaises(PaymentTestEvidenceError):
                    build_payment_test_report(document)

    def test_price_currency_and_payment_type_are_exact(self) -> None:
        cases = (
            ("unit_amount_cents", 9_901),
            ("unit_amount_cents", 99.0),
            ("currency", "usd"),
            ("payment_type", "RECURRING"),
            ("provider", "stripe"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                document = valid_document()
                document[field] = value
                with self.assertRaises(PaymentTestEvidenceError):
                    build_payment_test_report(document)

    def test_checkout_receipt_and_refund_amounts_must_all_equal_9900(self) -> None:
        cases = (
            (PaymentTestFlow.SUCCESSFUL_CHECKOUT, "charged_amount_cents", 9_899),
            (PaymentTestFlow.RECEIPT, "receipt_amount_cents", 9_901),
            (PaymentTestFlow.FULL_REFUND, "refunded_amount_cents", 5_000),
        )
        for flow, field, value in cases:
            with self.subTest(flow=flow.value):
                document = valid_document()
                evidence_for(document, flow)[field] = value
                with self.assertRaises(PaymentTestEvidenceError):
                    build_payment_test_report(document)

    def test_payment_chain_and_abandonment_correlation_are_enforced(self) -> None:
        mismatched_payment = valid_document()
        evidence_for(mismatched_payment, PaymentTestFlow.RECEIPT)["correlation_ref"] = (
            _opaque("cor", 99)
        )

        reused_abandonment = valid_document()
        evidence_for(reused_abandonment, PaymentTestFlow.ABANDONMENT)["correlation_ref"] = (
            _opaque("cor", 21)
        )

        for label, document in (
            ("payment chain", mismatched_payment),
            ("abandonment", reused_abandonment),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                PaymentTestEvidenceError, "correlation_ref"
            ):
                build_payment_test_report(document)

    def test_missing_duplicate_and_unknown_flows_are_rejected(self) -> None:
        missing = valid_document()
        missing_evidence = cast(list[dict[str, object]], missing["evidence"])
        missing_evidence.pop()

        duplicate = valid_document()
        duplicate_evidence = cast(list[dict[str, object]], duplicate["evidence"])
        duplicate_evidence[-1] = copy.deepcopy(duplicate_evidence[0])
        duplicate_evidence[-1]["evidence_ref"] = _opaque("evd", 99)
        duplicate_evidence[-1]["artifact_sha256"] = _artifact(999)

        unknown = valid_document()
        evidence_for(unknown, PaymentTestFlow.ABANDONMENT)["flow"] = "OTHER"

        for label, document in (
            ("missing", missing),
            ("duplicate", duplicate),
            ("unknown", unknown),
        ):
            with self.subTest(label=label), self.assertRaises(PaymentTestEvidenceError):
                build_payment_test_report(document)

    def test_unknown_and_missing_fields_are_rejected_at_every_level(self) -> None:
        extra_top = valid_document()
        extra_top["status"] = "PASS"

        extra_flow = valid_document()
        evidence_for(extra_flow, PaymentTestFlow.RECEIPT)["note"] = "redacted"

        missing_flow = valid_document()
        evidence_for(missing_flow, PaymentTestFlow.RECEIPT).pop("recipient_redacted")

        for label, document in (
            ("extra top", extra_top),
            ("extra flow", extra_flow),
            ("missing flow", missing_flow),
        ):
            with self.subTest(label=label), self.assertRaises(PaymentTestEvidenceError):
                build_payment_test_report(document)

    def test_flow_outcomes_and_cancellation_interpretation_are_fixed(self) -> None:
        cases = (
            (PaymentTestFlow.SUCCESSFUL_CHECKOUT, "outcome", "PAID"),
            (PaymentTestFlow.ABANDONMENT, "outcome", "UNKNOWN"),
            (PaymentTestFlow.RECEIPT, "outcome", "SENT"),
            (
                PaymentTestFlow.CANCELLATION_INTERPRETATION,
                "interpretation",
                "PAYMENT_CANCELLED",
            ),
            (
                PaymentTestFlow.CANCELLATION_INTERPRETATION,
                "required_follow_up",
                "NONE",
            ),
            (PaymentTestFlow.FULL_REFUND, "outcome", "PARTIAL_REFUND"),
        )
        for flow, field, value in cases:
            with self.subTest(flow=flow.value, field=field):
                document = valid_document()
                evidence_for(document, flow)[field] = value
                with self.assertRaises(PaymentTestEvidenceError):
                    build_payment_test_report(document)

    def test_abandonment_must_attest_that_no_payment_was_created(self) -> None:
        document = valid_document()
        evidence_for(document, PaymentTestFlow.ABANDONMENT)["payment_created"] = True

        with self.assertRaises(PaymentTestEvidenceError):
            build_payment_test_report(document)

    def test_timestamps_must_be_timezone_aware_and_chronological(self) -> None:
        naive = valid_document()
        evidence_for(naive, PaymentTestFlow.RECEIPT)["observed_at"] = "2026-08-29T14:01:00"

        reversed_flow = valid_document()
        evidence_for(reversed_flow, PaymentTestFlow.FULL_REFUND)["observed_at"] = (
            "2026-08-29T13:59:00Z"
        )

        for label, document in (("naive", naive), ("reversed", reversed_flow)):
            with self.subTest(label=label), self.assertRaises(PaymentTestEvidenceError):
                build_payment_test_report(document)

    def test_evidence_and_artifact_references_must_be_unique(self) -> None:
        duplicate_ref = valid_document()
        receipt = evidence_for(duplicate_ref, PaymentTestFlow.RECEIPT)
        checkout = evidence_for(duplicate_ref, PaymentTestFlow.SUCCESSFUL_CHECKOUT)
        receipt["evidence_ref"] = checkout["evidence_ref"]

        duplicate_digest = valid_document()
        receipt = evidence_for(duplicate_digest, PaymentTestFlow.RECEIPT)
        checkout = evidence_for(duplicate_digest, PaymentTestFlow.SUCCESSFUL_CHECKOUT)
        receipt["artifact_sha256"] = checkout["artifact_sha256"]

        for label, document in (
            ("reference", duplicate_ref),
            ("artifact", duplicate_digest),
        ):
            with self.subTest(label=label), self.assertRaises(PaymentTestEvidenceError):
                build_payment_test_report(document)

    def test_provider_and_evidence_references_must_be_opaque(self) -> None:
        raw_provider_id = "cs_" + "test_" + "a" * 24
        cases = (
            ("provider_ref", raw_provider_id),
            ("provider_ref", "REF_0123456789abcdef0123456789abcdef"),
            ("evidence_ref", "evd_short"),
            ("artifact_sha256", "A" * 64),
        )
        for field, value in cases:
            with self.subTest(field=field):
                document = valid_document()
                evidence_for(document, PaymentTestFlow.SUCCESSFUL_CHECKOUT)[field] = value
                with self.assertRaises(PaymentTestEvidenceError):
                    build_payment_test_report(document)

    def test_secrets_card_data_and_personal_data_are_rejected_without_echo(self) -> None:
        sensitive_values = (
            "sk_" + "test_" + "a" * 24,
            "wh" + "sec_" + "b" * 24,
            "4242" * 4,
            "buyer" + "@" + "example.com",
            "https" + "://example.com/checkout",
            "Jo" + "hn Do" + "e",
            "123" + " Main Street",
            "C" + "VC 123",
        )
        for sensitive_value in sensitive_values:
            with self.subTest(category=sensitive_value[:3]):
                document = valid_document()
                document["note"] = sensitive_value
                with self.assertRaises(PaymentTestEvidenceError) as context:
                    build_payment_test_report(document)
                self.assertNotIn(sensitive_value, str(context.exception))

    def test_raw_provider_payload_objects_are_rejected(self) -> None:
        document = valid_document()
        evidence_for(document, PaymentTestFlow.SUCCESSFUL_CHECKOUT)["payload"] = {
            "object": "checkout.session",
            "livemode": False,
        }

        with self.assertRaisesRegex(PaymentTestEvidenceError, "forbidden"):
            build_payment_test_report(document)

    def test_strict_json_rejects_duplicate_keys_and_non_json_numbers(self) -> None:
        duplicate = (
            '{"schema_version":"remedialhq.payment-test-evidence.v1",'
            '"schema_version":"remedialhq.payment-test-evidence.v1"}'
        )
        for text in (duplicate, '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(text=text), self.assertRaises(PaymentTestEvidenceError):
                parse_payment_test_evidence(text)

        with self.assertRaisesRegex(PaymentTestEvidenceError, "valid UTF-8"):
            parse_payment_test_evidence('"\ud800"')

    def test_file_loader_enforces_size_limit(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "oversized.json"
            path.write_text(" " * (MAX_DOCUMENT_BYTES + 1), encoding="utf-8")
            with self.assertRaisesRegex(PaymentTestEvidenceError, "size limit"):
                load_payment_test_evidence(path)

    def test_file_loader_rejects_leaf_and_ancestor_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            real_directory = root / "real"
            real_directory.mkdir()
            evidence = real_directory / "evidence.json"
            evidence.write_text(json.dumps(valid_document()), encoding="utf-8")

            leaf_link = root / "leaf.json"
            leaf_link.symlink_to(evidence)
            with self.assertRaisesRegex(PaymentTestEvidenceError, "symlink"):
                load_payment_test_evidence(leaf_link)

            directory_link = root / "linked-directory"
            directory_link.symlink_to(real_directory, target_is_directory=True)
            with self.assertRaisesRegex(PaymentTestEvidenceError, "symlink ancestors"):
                load_payment_test_evidence(directory_link / "evidence.json")

    def test_file_loader_rejects_directories_and_fifo_without_opening(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            fifo = root / "evidence.fifo"
            os.mkfifo(fifo)

            for label, path in (("directory", root), ("fifo", fifo)):
                with (
                    self.subTest(label=label),
                    mock.patch("remedialhq.payment_tests.os.open") as mocked_open,
                    self.assertRaisesRegex(PaymentTestEvidenceError, "regular file"),
                ):
                    load_payment_test_evidence(path)
                mocked_open.assert_not_called()

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
                mock.patch("remedialhq.payment_tests.os.open", side_effect=replace_then_open),
                self.assertRaisesRegex(PaymentTestEvidenceError, "changed while opening"),
            ):
                load_payment_test_evidence(path)

    def test_file_loader_detects_growth_during_bounded_read(self) -> None:
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
                mock.patch("remedialhq.payment_tests.os.read", side_effect=read_then_grow),
                self.assertRaisesRegex(PaymentTestEvidenceError, "changed while reading"),
            ):
                load_payment_test_evidence(path)

    def test_file_loader_errors_never_disclose_rejected_content(self) -> None:
        sensitive = "sk_" + "test_" + "z" * 32
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            document = valid_document()
            document["secret"] = sensitive
            path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaises(PaymentTestEvidenceError) as context:
                load_payment_test_evidence(path)

        self.assertNotIn(sensitive, str(context.exception))

    def test_module_cli_prints_report_and_digest_without_mutating_state(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(valid_document()), encoding="utf-8")
            standard_output = io.StringIO()
            standard_error = io.StringIO()

            with redirect_stdout(standard_output), redirect_stderr(standard_error):
                exit_code = main([str(path)])

        self.assertEqual(exit_code, 0)
        self.assertEqual(standard_error.getvalue(), "")
        envelope = json.loads(standard_output.getvalue())
        self.assertRegex(envelope["sha256"], r"^[0-9a-f]{64}$")
        self.assertIs(envelope["report"]["rmh_106_may_be_marked_complete"], False)

    def test_module_has_no_pilot_ledger_or_execution_state_dependency(self) -> None:
        source_path = Path(__file__).resolve().parents[1] / "src/remedialhq/payment_tests.py"
        source = source_path.read_text(encoding="utf-8")
        prohibited_dependencies = (
            "remedialhq.pilots",
            "remedialhq.execution",
            "PilotLedger",
            "ExecutionPlan",
        )
        for dependency in prohibited_dependencies:
            with self.subTest(dependency=dependency):
                self.assertNotIn(dependency, source)

    def test_runbook_template_validates_and_preserves_completion_boundary(self) -> None:
        runbook_path = Path(__file__).resolve().parents[1] / "ops/PAYMENT_TEST_RUNBOOK.md"
        runbook = runbook_path.read_text(encoding="utf-8")
        template = runbook.split("```json\n", 1)[1].split("\n```", 1)[0]

        report = parse_payment_test_evidence(template).to_dict()

        self.assertEqual(
            report["classification_counts"],
            {"SYNTHETIC": 5, "OWNER_CAPTURED": 0},
        )
        self.assertIn("cannot mark RMH-106 complete", runbook)
        self.assertIn("Never record a Stripe test payment as revenue", runbook)
        self.assertNotIn("\u2014", runbook)

    def test_report_returns_fresh_data_and_digest_tracks_validated_content(self) -> None:
        synthetic = build_payment_test_report(valid_document())
        owner = build_payment_test_report(valid_document("OWNER_CAPTURED"))
        mutable_copy = synthetic.to_dict()
        mutable_copy["mode"] = "LIVE"

        self.assertEqual(synthetic.to_dict()["mode"], "TEST")
        self.assertNotEqual(synthetic.sha256, owner.sha256)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", synthetic.sha256))


if __name__ == "__main__":
    unittest.main()
