from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from remedialhq.pilot_reconciliation import (
    MAX_DOCUMENT_BYTES,
    PilotReconciliationError,
    PriorPilotLedgerSnapshot,
    build_pilot_slot_reconciliation,
    load_pilot_slot_reconciliation,
    parse_pilot_slot_reconciliation,
)
from tests.pilot_reconciliation_support import reconciliation_document


class PilotSlotReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        secure_temp_root = "/tmp" if Path("/tmp").is_dir() else None
        self.temporary_directory = tempfile.TemporaryDirectory(dir=secure_temp_root)
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @staticmethod
    def prior_snapshot() -> PriorPilotLedgerSnapshot:
        return PriorPilotLedgerSnapshot(
            ledger_schema_version=5,
            ledger_head_sha256="a" * 64,
            inherited_consumed_slots=2,
            purchase_event_sha256s=("b" * 64, "c" * 64),
            purchase_evidence_artifact_sha256s=("d" * 64, "e" * 64),
            provider_purchase_sha256s=(
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
            ),
        )

    def test_valid_no_prior_record_derives_zero_and_binds_exact_bytes(self) -> None:
        document = reconciliation_document()
        text = json.dumps(document, indent=2) + "\n"

        evidence = parse_pilot_slot_reconciliation(
            text,
            expected_prior_ledger=None,
        )

        self.assertEqual(evidence.lifetime_consumed_slots, 0)
        self.assertIsNone(evidence.prior_ledger)
        self.assertEqual(
            evidence.evidence_sha256,
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
        self.assertNotEqual(evidence.evidence_sha256, evidence.record_sha256)

    def test_structured_prior_records_derive_and_cross_check_four_slots(self) -> None:
        prior = self.prior_snapshot()
        document = reconciliation_document(prior)

        evidence = build_pilot_slot_reconciliation(
            document,
            expected_prior_ledger=prior,
        )

        self.assertEqual(evidence.lifetime_consumed_slots, 4)
        self.assertEqual(evidence.prior_ledger, prior)
        self.assertEqual(
            evidence.to_dict()["prior_ledger"],
            prior.to_dict(),
        )

    def test_provider_history_is_the_slot_authority_without_a_prior_ledger(self) -> None:
        purchase_hashes = ("1" * 64, "2" * 64)
        document = reconciliation_document(
            provider_purchase_hashes=purchase_hashes,
        )

        evidence = build_pilot_slot_reconciliation(
            document,
            expected_prior_ledger=None,
        )

        self.assertEqual(evidence.lifetime_consumed_slots, 2)
        self.assertEqual(
            evidence.payment_provider.provider_purchase_sha256s,
            purchase_hashes,
        )

    def test_provider_purchase_count_cannot_regress_below_prior_lifetime(self) -> None:
        prior = self.prior_snapshot()
        document = reconciliation_document(
            prior,
            provider_purchase_hashes=("1" * 64, "2" * 64),
        )

        with self.assertRaisesRegex(
            PilotReconciliationError,
            "below the prior-ledger lifetime count",
        ):
            build_pilot_slot_reconciliation(
                document,
                expected_prior_ledger=prior,
            )

    def test_provider_history_must_include_every_prior_provider_purchase(self) -> None:
        prior = PriorPilotLedgerSnapshot(
            ledger_schema_version=5,
            ledger_head_sha256="a" * 64,
            inherited_consumed_slots=0,
            purchase_event_sha256s=("b" * 64, "c" * 64),
            purchase_evidence_artifact_sha256s=("d" * 64, "e" * 64),
            provider_purchase_sha256s=("3" * 64, "4" * 64),
        )
        document = reconciliation_document(
            prior,
            provider_purchase_hashes=("1" * 64, "2" * 64),
        )

        with self.assertRaisesRegex(
            PilotReconciliationError,
            "omits verified prior-ledger provider purchases",
        ):
            build_pilot_slot_reconciliation(
                document,
                expected_prior_ledger=prior,
            )

    def test_refunds_do_not_reduce_provider_derived_slot_count(self) -> None:
        retained_provider_purchases = ("1" * 64, "2" * 64, "3" * 64)
        document = reconciliation_document(
            provider_purchase_hashes=retained_provider_purchases,
        )

        evidence = build_pilot_slot_reconciliation(
            document,
            expected_prior_ledger=None,
        )

        self.assertEqual(evidence.lifetime_consumed_slots, 3)

    def test_claimed_slot_count_cannot_contradict_structured_records(self) -> None:
        prior = self.prior_snapshot()
        document = reconciliation_document(prior)
        document["lifetime_consumed_slots"] = 3

        with self.assertRaisesRegex(
            PilotReconciliationError,
            "contradicts the payment provider history",
        ):
            build_pilot_slot_reconciliation(
                document,
                expected_prior_ledger=prior,
            )

    def test_every_prior_ledger_fact_must_match_verified_input(self) -> None:
        prior = self.prior_snapshot()
        mutations: tuple[tuple[str, object], ...] = (
            ("ledger_schema_version", 3),
            ("ledger_head_sha256", "d" * 64),
            ("inherited_consumed_slots", 1),
            ("purchase_event_sha256s", ["b" * 64, "e" * 64]),
            ("purchase_evidence_artifact_sha256s", ["d" * 64, "f" * 64]),
            (
                "provider_purchase_sha256s",
                ["1" * 64, "2" * 64, "3" * 64, "5" * 64],
            ),
        )
        for field_name, replacement in mutations:
            with self.subTest(field_name=field_name):
                document = reconciliation_document(prior)
                prior_document = document["prior_ledger"]
                assert isinstance(prior_document, dict)
                prior_document[field_name] = replacement
                if field_name in {
                    "inherited_consumed_slots",
                    "purchase_event_sha256s",
                }:
                    derived = int(prior_document["inherited_consumed_slots"]) + len(
                        prior_document["purchase_event_sha256s"]  # type: ignore[arg-type]
                    )
                    document["lifetime_consumed_slots"] = derived
                with self.assertRaises(PilotReconciliationError):
                    build_pilot_slot_reconciliation(
                        document,
                        expected_prior_ledger=prior,
                    )

    def test_prior_presence_must_match_command_input(self) -> None:
        prior = self.prior_snapshot()
        with self.assertRaisesRegex(
            PilotReconciliationError,
            "not allowed without a verified --prior-ledger",
        ):
            build_pilot_slot_reconciliation(
                reconciliation_document(prior),
                expected_prior_ledger=None,
            )
        with self.assertRaisesRegex(
            PilotReconciliationError,
            "required when --prior-ledger is supplied",
        ):
            build_pilot_slot_reconciliation(
                reconciliation_document(),
                expected_prior_ledger=prior,
            )

    def test_unknown_missing_duplicate_and_non_json_fields_fail_closed(self) -> None:
        base = reconciliation_document()
        unknown = {**base, "note": "trust me"}
        missing = dict(base)
        del missing["checks"]
        for label, document in (("unknown", unknown), ("missing", missing)):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    PilotReconciliationError,
                    "missing or unknown fields",
                ),
            ):
                build_pilot_slot_reconciliation(
                    document,
                    expected_prior_ledger=None,
                )

        duplicate = json.dumps(base)[:-1] + ',"lifetime_consumed_slots":0}'
        with self.assertRaisesRegex(PilotReconciliationError, "duplicate JSON fields"):
            parse_pilot_slot_reconciliation(
                duplicate,
                expected_prior_ledger=None,
            )
        with self.assertRaisesRegex(PilotReconciliationError, "non-JSON number"):
            parse_pilot_slot_reconciliation(
                json.dumps(base).replace(
                    '"lifetime_consumed_slots": 0',
                    '"lifetime_consumed_slots": NaN',
                ),
                expected_prior_ledger=None,
            )

    def test_attestations_schema_timestamp_and_integer_types_are_strict(self) -> None:
        cases: list[dict[str, object]] = []
        false_check = copy.deepcopy(reconciliation_document())
        checks = false_check["checks"]
        assert isinstance(checks, dict)
        checks["payment_provider_history_reviewed"] = False
        cases.append(false_check)
        wrong_schema = reconciliation_document()
        wrong_schema["schema_version"] = "v1"
        cases.append(wrong_schema)
        non_utc = reconciliation_document()
        non_utc["reconciled_at"] = "2026-08-30T08:00:00-04:00"
        cases.append(non_utc)
        bool_slots = reconciliation_document()
        bool_slots["lifetime_consumed_slots"] = False
        cases.append(bool_slots)

        for index, document in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(PilotReconciliationError):
                build_pilot_slot_reconciliation(
                    document,
                    expected_prior_ledger=None,
                )

    def test_payment_provider_contract_is_closed_and_live_only(self) -> None:
        cases: list[dict[str, object]] = []
        wrong_provider = copy.deepcopy(reconciliation_document())
        provider = wrong_provider["payment_provider"]
        assert isinstance(provider, dict)
        provider["provider"] = "OTHER"
        cases.append(wrong_provider)
        test_mode = copy.deepcopy(reconciliation_document())
        provider = test_mode["payment_provider"]
        assert isinstance(provider, dict)
        provider["mode"] = "TEST"
        cases.append(test_mode)
        partial_history = copy.deepcopy(reconciliation_document())
        provider = partial_history["payment_provider"]
        assert isinstance(provider, dict)
        provider["history_scope"] = "LAST_30_DAYS"
        cases.append(partial_history)
        non_utc = copy.deepcopy(reconciliation_document())
        provider = non_utc["payment_provider"]
        assert isinstance(provider, dict)
        provider["observed_at"] = "2026-08-30T07:59:00-04:00"
        cases.append(non_utc)
        unknown_field = copy.deepcopy(reconciliation_document())
        provider = unknown_field["payment_provider"]
        assert isinstance(provider, dict)
        provider["stripe_account_id"] = "acct_raw"
        cases.append(unknown_field)

        for index, document in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(PilotReconciliationError):
                build_pilot_slot_reconciliation(
                    document,
                    expected_prior_ledger=None,
                )

    def test_provider_history_rejects_duplicate_or_excess_digests(self) -> None:
        duplicate = reconciliation_document(
            provider_purchase_hashes=("1" * 64, "1" * 64),
        )
        with self.assertRaisesRegex(PilotReconciliationError, "must be unique"):
            build_pilot_slot_reconciliation(
                duplicate,
                expected_prior_ledger=None,
            )

        excess = reconciliation_document(
            provider_purchase_hashes=tuple(f"{index:064x}" for index in range(1, 7)),
        )
        with self.assertRaisesRegex(PilotReconciliationError, "five-slot limit"):
            build_pilot_slot_reconciliation(
                excess,
                expected_prior_ledger=None,
            )

    def test_history_artifact_and_provider_identity_are_independent_domains(self) -> None:
        same_textual_digest = reconciliation_document(
            provider_purchase_hashes=(f"{8000:064x}",),
        )

        evidence = build_pilot_slot_reconciliation(
            same_textual_digest,
            expected_prior_ledger=None,
        )

        self.assertEqual(evidence.lifetime_consumed_slots, 1)

    def test_duplicate_or_excess_purchase_records_are_rejected(self) -> None:
        with self.assertRaisesRegex(PilotReconciliationError, "must be unique"):
            PriorPilotLedgerSnapshot(
                ledger_schema_version=5,
                ledger_head_sha256="a" * 64,
                inherited_consumed_slots=0,
                purchase_event_sha256s=("b" * 64, "b" * 64),
                purchase_evidence_artifact_sha256s=("c" * 64, "d" * 64),
                provider_purchase_sha256s=("e" * 64, "f" * 64),
            )
        with self.assertRaisesRegex(PilotReconciliationError, "five-slot limit"):
            PriorPilotLedgerSnapshot(
                ledger_schema_version=5,
                ledger_head_sha256="a" * 64,
                inherited_consumed_slots=4,
                purchase_event_sha256s=("b" * 64, "c" * 64),
                purchase_evidence_artifact_sha256s=("d" * 64, "e" * 64),
                provider_purchase_sha256s=tuple(f"{index:064x}" for index in range(1, 7)),
            )

    def test_nonzero_legacy_snapshot_fails_without_provider_binding(self) -> None:
        with self.assertRaisesRegex(
            PilotReconciliationError,
            "nonzero schema 1 through 4",
        ):
            PriorPilotLedgerSnapshot(
                ledger_schema_version=4,
                ledger_head_sha256="a" * 64,
                inherited_consumed_slots=0,
                purchase_event_sha256s=("b" * 64,),
                purchase_evidence_artifact_sha256s=("c" * 64,),
                provider_purchase_sha256s=(),
            )

    def test_loader_rejects_unsafe_or_unbounded_files(self) -> None:
        valid_path = self.root / "evidence.json"
        valid_path.write_text(json.dumps(reconciliation_document()), encoding="utf-8")
        loaded = load_pilot_slot_reconciliation(
            valid_path,
            expected_prior_ledger=None,
        )
        self.assertEqual(loaded.lifetime_consumed_slots, 0)

        with self.assertRaisesRegex(PilotReconciliationError, "regular file"):
            load_pilot_slot_reconciliation(
                self.root,
                expected_prior_ledger=None,
            )

        oversized = self.root / "oversized.json"
        oversized.write_bytes(b" " * (MAX_DOCUMENT_BYTES + 1))
        with self.assertRaisesRegex(PilotReconciliationError, "size limit"):
            load_pilot_slot_reconciliation(
                oversized,
                expected_prior_ledger=None,
            )

        invalid_utf8 = self.root / "invalid.json"
        invalid_utf8.write_bytes(b"\xff")
        with self.assertRaisesRegex(PilotReconciliationError, "UTF-8"):
            load_pilot_slot_reconciliation(
                invalid_utf8,
                expected_prior_ledger=None,
            )

        symlink = self.root / "linked.json"
        try:
            os.symlink(valid_path, symlink)
        except OSError as exc:
            self.skipTest(f"symbolic links are unavailable: {exc}")
        with self.assertRaisesRegex(PilotReconciliationError, "must not be a symlink"):
            load_pilot_slot_reconciliation(
                symlink,
                expected_prior_ledger=None,
            )

    def test_repository_json_schema_exposes_the_same_closed_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        schema = json.loads(
            (root / "config/pilot-slot-reconciliation.schema.json").read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            "remedialhq.pilot-slot-reconciliation.v1",
        )
        self.assertEqual(
            set(schema["required"]),
            set(reconciliation_document()),
        )


if __name__ == "__main__":
    unittest.main()
