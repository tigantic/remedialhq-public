from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest import mock

from remedialhq import outreach
from remedialhq.outreach import OutreachPlan, OutreachPlanError, load_outreach_plan
from remedialhq.pilots import (
    ContactChannel,
    OutreachCadenceStatus,
    PilotEventType,
    PilotLedger,
    PilotValidationError,
    ProspectSegment,
    ReplyOutcome,
    SuppressionStatus,
)

RECONCILIATION_EVIDENCE_SHA256 = "f" * 64


def opaque(prefix: str, number: int) -> str:
    return f"{prefix}_{number:032x}"


def digest(number: int) -> str:
    return f"{number:064x}"


def plan_document(count: int = 50) -> dict[str, object]:
    campaign_start = date(2026, 9, 1)
    prospects: list[dict[str, object]] = []
    for index in range(count):
        evidence_base = 100 + index * 3
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
                "qualification_evidence_sha256": digest(evidence_base),
                "recent_work_reference_sha256": digest(evidence_base + 1),
                "sample_insight_sha256": digest(evidence_base + 2),
            }
        )
    return {
        "schema_version": "remedialhq.outreach-plan.v1",
        "campaign_ref": opaque("cmp", 1),
        "campaign_start": campaign_start.isoformat(),
        "campaign_end": (campaign_start + timedelta(days=13)).isoformat(),
        "utc_offset_minutes": -240,
        "daily_contact_limit": 10,
        "controls": {
            "sender_identification_ready": True,
            "sending_domain_authenticated": True,
            "postal_address_requirement_reviewed": True,
            "opt_out_process_ready": True,
            "evidence_sha256": digest(1),
        },
        "prospects": prospects,
    }


class OutreachPlanTests(unittest.TestCase):
    def test_published_schema_matches_the_runtime_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        schema_text = (root / "config/outreach-plan.schema.json").read_text(
            encoding="utf-8"
        )
        schema = json.loads(schema_text)

        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            "remedialhq.outreach-plan.v1",
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["prospects"]["maxItems"], 50)
        self.assertEqual(schema["properties"]["campaign_ref"]["minLength"], 36)
        self.assertEqual(schema["properties"]["campaign_ref"]["maxLength"], 36)
        self.assertEqual(schema["properties"]["campaign_start"]["minLength"], 10)
        self.assertEqual(schema["properties"]["campaign_start"]["maxLength"], 10)
        self.assertEqual(schema["$defs"]["sha256"]["minLength"], 64)
        self.assertEqual(schema["$defs"]["sha256"]["maxLength"], 64)
        self.assertNotIn("\u2014", schema_text)

    def test_complete_plan_binds_fifty_qualified_personalized_prospects(self) -> None:
        plan = OutreachPlan.from_dict(plan_document())

        self.assertTrue(plan.is_complete)
        self.assertEqual(len(plan.prospects), 50)
        report = plan.validation_report()
        self.assertEqual(
            report["daily_contact_counts"],
            {
                "2026-09-03": 10,
                "2026-09-04": 10,
                "2026-09-05": 10,
                "2026-09-06": 10,
                "2026-09-07": 10,
            },
        )
        self.assertIs(report["outreach_sent"], False)
        self.assertIs(report["rmh_107_may_be_marked_complete"], False)
        self.assertIs(report["evidence_artifacts_verified"], False)
        self.assertNotIn(opaque("prs", 1), json.dumps(report))

    def test_partial_plan_validates_but_is_not_import_ready(self) -> None:
        plan = OutreachPlan.from_dict(plan_document(9))

        self.assertFalse(plan.is_complete)
        self.assertEqual(plan.validation_report()["prospects"], 9)

    def test_qualification_personalization_and_daily_limits_fail_closed(self) -> None:
        unqualified = plan_document()
        prospects = unqualified["prospects"]
        assert isinstance(prospects, list)
        assert isinstance(prospects[0], dict)
        prospects[0]["specific_upcoming_piece"] = False
        with self.assertRaisesRegex(OutreachPlanError, "must be true"):
            OutreachPlan.from_dict(unqualified)

        reused_evidence = plan_document()
        reused = reused_evidence["prospects"]
        assert isinstance(reused, list)
        assert isinstance(reused[0], dict)
        assert isinstance(reused[1], dict)
        reused[1]["sample_insight_sha256"] = reused[0]["sample_insight_sha256"]
        with self.assertRaisesRegex(OutreachPlanError, "digest must be unique"):
            OutreachPlan.from_dict(reused_evidence)

        over_daily_limit = plan_document()
        over_limit = over_daily_limit["prospects"]
        assert isinstance(over_limit, list)
        assert isinstance(over_limit[10], dict)
        over_limit[10]["planned_contact_date"] = "2026-09-03"
        with self.assertRaisesRegex(OutreachPlanError, "10-contact limit"):
            OutreachPlan.from_dict(over_daily_limit)

    def test_unknown_identity_or_message_fields_are_rejected(self) -> None:
        document = plan_document(1)
        prospects = document["prospects"]
        assert isinstance(prospects, list)
        assert isinstance(prospects[0], dict)
        prospects[0]["email"] = "not-accepted@example.test"

        with self.assertRaisesRegex(OutreachPlanError, "unexpected fields"):
            OutreachPlan.from_dict(document)

    def test_runtime_rejects_noncanonical_schema_scalar_representations(self) -> None:
        floating_offset = plan_document()
        floating_offset["utc_offset_minutes"] = -240.0
        with self.assertRaisesRegex(OutreachPlanError, "must be an integer"):
            OutreachPlan.from_dict(floating_offset)

        floating_limit = plan_document()
        floating_limit["daily_contact_limit"] = 10.0
        with self.assertRaisesRegex(OutreachPlanError, "must be an integer"):
            OutreachPlan.from_dict(floating_limit)

        trailing_newline = plan_document()
        prospects = trailing_newline["prospects"]
        assert isinstance(prospects, list)
        assert isinstance(prospects[0], dict)
        prospects[0]["prospect_id"] = f"{opaque('prs', 1)}\n"
        with self.assertRaisesRegex(OutreachPlanError, "invalid format"):
            OutreachPlan.from_dict(trailing_newline)

        impossible_date = plan_document()
        impossible_date["campaign_start"] = "2026-02-30"
        with self.assertRaisesRegex(OutreachPlanError, "canonical ISO date"):
            OutreachPlan.from_dict(impossible_date)

    def test_file_loader_rejects_duplicate_keys_and_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":"remedialhq.outreach-plan.v1",'
                '"schema_version":"remedialhq.outreach-plan.v1"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(OutreachPlanError, "duplicate JSON keys"):
                load_outreach_plan(duplicate)

            target = root / "target.json"
            target.write_text(json.dumps(plan_document()), encoding="utf-8")
            linked = root / "linked.json"
            try:
                linked.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")
            with self.assertRaisesRegex(OutreachPlanError, "regular file"):
                load_outreach_plan(linked)

            target_directory = root / "target-directory"
            target_directory.mkdir()
            nested_target = target_directory / "plan.json"
            nested_target.write_text(json.dumps(plan_document()), encoding="utf-8")
            linked_directory = root / "linked-directory"
            linked_directory.symlink_to(target_directory, target_is_directory=True)
            with self.assertRaisesRegex(OutreachPlanError, "symbolic-link ancestors"):
                load_outreach_plan(linked_directory / "plan.json")

    def test_file_loader_detects_replacement_between_inspection_and_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            replacement = Path(directory) / "replacement.json"
            path.write_text(json.dumps(plan_document()), encoding="utf-8")
            replacement.write_text(json.dumps(plan_document()), encoding="utf-8")
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
                    "remedialhq.outreach.os.open",
                    side_effect=replace_then_open,
                ),
                self.assertRaisesRegex(OutreachPlanError, "changed while opening"),
            ):
                load_outreach_plan(path)

    def test_file_loader_detects_growth_and_path_replacement_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "plan.json"
            path.write_text(json.dumps(plan_document()), encoding="utf-8")
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
                    "remedialhq.outreach.os.read",
                    side_effect=read_then_grow,
                ),
                self.assertRaisesRegex(OutreachPlanError, "changed while reading"),
            ):
                load_outreach_plan(path)

            path.write_text(json.dumps(plan_document()), encoding="utf-8")
            original_read_bounded = outreach._read_bounded
            original_lstat = os.lstat
            read_finished = False

            def read_then_change_identity(descriptor: int) -> bytes:
                nonlocal read_finished
                raw = original_read_bounded(descriptor)
                read_finished = True
                return raw

            def changed_identity_after_read(
                target: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            ) -> os.stat_result | SimpleNamespace:
                metadata = original_lstat(target)
                if read_finished and Path(target) == path:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino + 1,
                        st_size=metadata.st_size,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                    )
                return metadata

            with (
                mock.patch(
                    "remedialhq.outreach._read_bounded",
                    side_effect=read_then_change_identity,
                ),
                mock.patch(
                    "remedialhq.outreach.os.lstat",
                    side_effect=changed_identity_after_read,
                ),
                self.assertRaisesRegex(OutreachPlanError, "changed while reading"),
            ):
                load_outreach_plan(path)

    def test_file_loader_rejects_a_short_read_against_stable_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan_document()), encoding="utf-8")
            original_read_bounded = outreach._read_bounded

            def short_read(descriptor: int) -> bytes:
                return original_read_bounded(descriptor)[:-1]

            with (
                mock.patch(
                    "remedialhq.outreach._read_bounded",
                    side_effect=short_read,
                ),
                self.assertRaisesRegex(OutreachPlanError, "changed while reading"),
            ):
                load_outreach_plan(path)


class OutreachLedgerTests(unittest.TestCase):
    temporary_directory: tempfile.TemporaryDirectory[str]
    path: Path
    ledger: PilotLedger
    plan: OutreachPlan

    def setUp(self) -> None:
        secure_temp_root = "/tmp" if Path("/tmp").is_dir() else None
        self.temporary_directory = tempfile.TemporaryDirectory(dir=secure_temp_root)
        self.path = Path(self.temporary_directory.name) / "pilot.jsonl"
        self.ledger = PilotLedger.initialize(
            self.path,
            prior_consumed_slots=0,
            reconciliation_evidence_sha256=RECONCILIATION_EVIDENCE_SHA256,
        )
        self.plan = OutreachPlan.from_dict(plan_document())

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def import_plan(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.ledger.import_outreach_plan(
                self.plan,
                occurred_at="2026-09-01T12:00:00Z",
            ),
        )

    def suppression_check(
        self,
        number: int,
        *,
        observed_at: str,
        status: SuppressionStatus = SuppressionStatus.CLEAR,
        evidence_number: int | None = None,
    ) -> None:
        self.ledger.record(
            PilotEventType.SUPPRESSION_CHECKED,
            {
                "prospect_id": opaque("prs", number),
                "status": status,
                "evidence_sha256": digest(
                    evidence_number if evidence_number is not None else 10_000 + number
                ),
            },
            occurred_at=observed_at,
        )

    def contact(self, number: int, *, observed_at: str) -> None:
        self.ledger.record(
            PilotEventType.CONTACTED,
            {
                "prospect_id": opaque("prs", number),
                "channel": ContactChannel.BUSINESS_EMAIL,
            },
            occurred_at=observed_at,
        )

    def test_import_is_one_event_and_queue_requires_suppression_recheck(self) -> None:
        result = self.import_plan()

        self.assertEqual(result["prospects_imported"], 50)
        self.assertIs(result["outreach_sent"], False)
        self.assertIs(result["rmh_107_may_be_marked_complete"], False)
        metrics = self.ledger.metrics()
        self.assertEqual(metrics.prospects, 50)
        self.assertEqual(metrics.contacted, 0)
        self.assertEqual(self.ledger.verify(), (True, "verified 2 pilot events"))

        queue = self.ledger.outreach_queue(as_of="2026-09-03T12:00:00Z")
        self.assertEqual(len(queue), 50)
        self.assertEqual(
            queue[0].cadence_status,
            OutreachCadenceStatus.RECHECK_SUPPRESSION,
        )
        self.assertEqual(queue[0].next_action, "RECORD_SUPPRESSION_CHECK")
        self.assertFalse(queue[0].contact_allowed)
        self.assertEqual(queue[10].cadence_status, OutreachCadenceStatus.SCHEDULED)

    def test_contact_requires_schedule_channel_and_fresh_suppression_check(self) -> None:
        self.import_plan()
        prospect_id = opaque("prs", 1)

        with self.assertRaisesRegex(PilotValidationError, "planned contact date"):
            self.contact(1, observed_at="2026-09-02T12:00:00Z")
        with self.assertRaisesRegex(PilotValidationError, "suppression check"):
            self.contact(1, observed_at="2026-09-03T12:00:00Z")

        self.suppression_check(1, observed_at="2026-09-03T12:00:00Z")
        with self.assertRaisesRegex(PilotValidationError, "channel must match"):
            self.ledger.record(
                PilotEventType.CONTACTED,
                {
                    "prospect_id": prospect_id,
                    "channel": ContactChannel.SOCIAL_DM,
                },
                occurred_at="2026-09-03T12:30:00Z",
            )
        self.contact(1, observed_at="2026-09-03T12:30:00Z")

        queue = self.ledger.outreach_queue(as_of="2026-09-03T13:00:00Z")
        self.assertEqual(queue[0].cadence_status, OutreachCadenceStatus.CONTACTED)
        self.assertEqual(queue[0].outcome, "AWAITING_REPLY")
        self.assertFalse(queue[0].contact_allowed)

    def test_clear_check_expires_and_can_be_refreshed(self) -> None:
        self.import_plan()
        self.suppression_check(1, observed_at="2026-09-03T12:00:00Z")

        with self.assertRaisesRegex(PilotValidationError, "prior 24 hours"):
            self.contact(1, observed_at="2026-09-04T12:01:00Z")

        self.suppression_check(
            1,
            observed_at="2026-09-04T12:02:00Z",
            evidence_number=20_001,
        )
        self.contact(1, observed_at="2026-09-04T12:03:00Z")
        self.assertEqual(self.ledger.metrics().contacted, 1)

    def test_daily_contact_limit_applies_to_delayed_contacts(self) -> None:
        self.import_plan()
        contact_time = "2026-09-04T12:00:00Z"
        for number in range(1, 11):
            self.suppression_check(number, observed_at=contact_time)
            self.contact(number, observed_at=contact_time)

        self.suppression_check(11, observed_at=contact_time)
        with self.assertRaisesRegex(PilotValidationError, "daily contact limit"):
            self.contact(11, observed_at=contact_time)

    def test_contact_stops_after_the_day_seven_outreach_window(self) -> None:
        self.import_plan()
        self.suppression_check(50, observed_at="2026-09-08T11:59:00Z")

        with self.assertRaisesRegex(PilotValidationError, "day-7 outreach window"):
            self.contact(50, observed_at="2026-09-08T12:00:00Z")

        entry = self.ledger.outreach_queue(as_of="2026-09-08T12:01:00Z")[-1]
        self.assertEqual(entry.cadence_status, OutreachCadenceStatus.OUTCOME_RECORDED)
        self.assertEqual(entry.outcome, "NOT_CONTACTED")
        self.assertEqual(entry.next_action, "STOP_CONTACT")
        self.assertFalse(entry.contact_allowed)

    def test_day_seven_daily_cap_closes_remaining_queue_entries(self) -> None:
        self.import_plan()
        contact_time = "2026-09-07T12:00:00Z"
        for number in range(1, 11):
            self.suppression_check(number, observed_at=contact_time)
            self.contact(number, observed_at=contact_time)

        entry = self.ledger.outreach_queue(as_of="2026-09-07T12:01:00Z")[40]
        self.assertEqual(entry.cadence_status, OutreachCadenceStatus.OUTCOME_RECORDED)
        self.assertEqual(entry.outcome, "NOT_CONTACTED")
        self.assertEqual(entry.next_action, "STOP_CONTACT")
        self.assertFalse(entry.contact_allowed)

    def test_opt_out_is_evidenced_irreversible_and_visible_in_queue(self) -> None:
        self.import_plan()
        prospect_id = opaque("prs", 1)

        with self.assertRaisesRegex(PilotValidationError, "evidence digest"):
            self.ledger.record(
                PilotEventType.OPTED_OUT,
                {"prospect_id": prospect_id},
                occurred_at="2026-09-03T11:59:00Z",
            )
        self.ledger.record(
            PilotEventType.OPTED_OUT,
            {
                "prospect_id": prospect_id,
                "evidence_sha256": digest(30_001),
            },
            occurred_at="2026-09-03T12:00:00Z",
        )
        with self.assertRaisesRegex(PilotValidationError, "cannot be cleared"):
            self.suppression_check(
                1,
                observed_at="2026-09-03T12:01:00Z",
                evidence_number=30_002,
            )

        entry = self.ledger.outreach_queue(as_of="2026-09-03T13:00:00Z")[0]
        self.assertEqual(entry.suppression_status, SuppressionStatus.OPTED_OUT)
        self.assertEqual(entry.cadence_status, OutreachCadenceStatus.SUPPRESSED)
        self.assertEqual(entry.next_action, "STOP_CONTACT")
        self.assertFalse(entry.contact_allowed)

    def test_pre_contact_opt_out_can_be_replaced_without_expanding_the_cohort(self) -> None:
        self.import_plan()
        self.suppression_check(
            1,
            observed_at="2026-09-03T11:00:00Z",
            status=SuppressionStatus.OPTED_OUT,
        )
        amended_document = plan_document()
        prospects = amended_document["prospects"]
        assert isinstance(prospects, list)
        replacement = dict(cast(dict[str, object], prospects[0]))
        replacement.update(
            {
                "prospect_id": opaque("prs", 99),
                "qualification_evidence_sha256": digest(50_000),
                "recent_work_reference_sha256": digest(50_001),
                "sample_insight_sha256": digest(50_002),
            }
        )
        prospects[0] = replacement
        amended_plan = OutreachPlan.from_dict(amended_document)

        result = self.ledger.amend_outreach_plan(
            amended_plan,
            occurred_at="2026-09-03T11:01:00Z",
        )

        self.assertEqual(result["prospects_active"], 50)
        self.assertIs(result["outreach_sent"], False)
        queue = self.ledger.outreach_queue(as_of="2026-09-03T11:02:00Z")
        self.assertEqual(len(queue), 50)
        self.assertEqual(queue[0].prospect_id, opaque("prs", 99))
        self.assertEqual(self.ledger.metrics().prospects, 50)
        self.assertEqual(self.ledger.metrics().opt_outs, 1)

        self.ledger.record(
            PilotEventType.SUPPRESSION_CHECKED,
            {
                "prospect_id": opaque("prs", 99),
                "status": SuppressionStatus.CLEAR,
                "evidence_sha256": digest(50_003),
            },
            occurred_at="2026-09-03T11:03:00Z",
        )
        self.ledger.record(
            PilotEventType.CONTACTED,
            {
                "prospect_id": opaque("prs", 99),
                "channel": ContactChannel.BUSINESS_EMAIL,
            },
            occurred_at="2026-09-03T11:04:00Z",
        )
        self.assertEqual(self.ledger.metrics().contacted, 1)

    def test_amendment_requires_exactly_one_uncontacted_opted_out_prospect(self) -> None:
        self.import_plan()
        amended_document = plan_document()
        prospects = amended_document["prospects"]
        assert isinstance(prospects, list)
        replacement = dict(cast(dict[str, object], prospects[0]))
        replacement.update(
            {
                "prospect_id": opaque("prs", 99),
                "qualification_evidence_sha256": digest(50_000),
                "recent_work_reference_sha256": digest(50_001),
                "sample_insight_sha256": digest(50_002),
            }
        )
        prospects[0] = replacement
        amended_plan = OutreachPlan.from_dict(amended_document)

        with self.assertRaisesRegex(PilotValidationError, "opted-out prospect"):
            self.ledger.amend_outreach_plan(
                amended_plan,
                occurred_at="2026-09-03T11:01:00Z",
            )

        self.suppression_check(
            1,
            observed_at="2026-09-03T11:02:00Z",
            status=SuppressionStatus.OPTED_OUT,
        )
        with self.assertRaisesRegex(PilotValidationError, "planned date"):
            self.ledger.amend_outreach_plan(
                amended_plan,
                occurred_at="2026-09-04T11:01:00Z",
            )

    def test_reply_and_sample_outcomes_update_queue_without_free_text(self) -> None:
        self.import_plan()
        self.suppression_check(1, observed_at="2026-09-03T12:00:00Z")
        self.contact(1, observed_at="2026-09-03T12:01:00Z")
        prospect_id = opaque("prs", 1)
        self.ledger.record(
            PilotEventType.REPLIED,
            {"prospect_id": prospect_id, "outcome": ReplyOutcome.INTERESTED},
            occurred_at="2026-09-03T13:00:00Z",
        )
        interested = self.ledger.outreach_queue(as_of="2026-09-03T13:01:00Z")[0]
        self.assertEqual(interested.outcome, ReplyOutcome.INTERESTED.value)
        self.assertEqual(interested.next_action, "REVIEW_SAMPLE_REQUEST")

        self.ledger.record(
            PilotEventType.SAMPLE_REQUESTED,
            {"prospect_id": prospect_id},
            occurred_at="2026-09-03T13:02:00Z",
        )
        sampled = self.ledger.outreach_queue(as_of="2026-09-03T13:03:00Z")[0]
        self.assertEqual(sampled.outcome, "SAMPLE_REQUESTED")
        self.assertEqual(sampled.next_action, "CONTINUE_FIT_AND_SCOPE_WORKFLOW")

    def test_plan_import_refuses_partial_or_progressed_ledgers(self) -> None:
        partial = OutreachPlan.from_dict(plan_document(5))
        with self.assertRaisesRegex(PilotValidationError, "exactly 50"):
            self.ledger.import_outreach_plan(partial)

        self.ledger.record(
            PilotEventType.PROSPECT_ADDED,
            {
                "prospect_id": opaque("prs", 99),
                "segment": ProspectSegment.PODCAST,
            },
            occurred_at="2026-08-31T12:00:00Z",
        )
        with self.assertRaisesRegex(PilotValidationError, "immediately after"):
            self.import_plan()
        self.assertEqual(self.ledger.metrics().prospects, 1)

    def test_manual_prospects_are_blocked_after_campaign_import(self) -> None:
        self.import_plan()
        with self.assertRaisesRegex(PilotValidationError, "cannot be added"):
            self.ledger.record(
                PilotEventType.PROSPECT_ADDED,
                {
                    "prospect_id": opaque("prs", 99),
                    "segment": ProspectSegment.PODCAST,
                },
                occurred_at="2026-09-01T13:00:00Z",
            )


if __name__ == "__main__":
    unittest.main()
