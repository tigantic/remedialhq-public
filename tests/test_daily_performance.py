from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from remedialhq.cli import _parser, _reconcile_performance
from remedialhq.daily_performance import (
    MAX_DOCUMENT_BYTES,
    MAX_METRIC_VALUE,
    BlockReason,
    DailyPerformanceError,
    MetricName,
    PublicationResult,
    ReconciliationStatus,
    build_daily_performance,
    load_daily_performance,
    load_global_publication_authority,
    load_prelaunch_calendar,
    parse_daily_performance,
    reconcile_calendar,
    reconcile_performance_files,
)

ROOT = Path(__file__).resolve().parents[1]
CALENDAR_PATH = ROOT / "content/calendar/prelaunch-calendar.json"
AUTHORITY_PATH = ROOT / "config/publication_authority.json"
CURRENT_RECONCILIATION_PATH = (
    ROOT / "artifacts/performance/calendar-reconciliation-2026-09-01.json"
)
SCHEMA_PATH = ROOT / "config/daily-performance.schema.json"


def performance_record(
    number: int,
    *,
    day_number: int = 2,
    calendar_date: str = "2026-08-30",
    opportunity_id: str = "OPP-0002",
    result: str = "PUBLISHED",
    block_reason: str | None = None,
    source_record_number: int | None = None,
) -> dict[str, object]:
    metrics: list[dict[str, object]] = []
    if result == "PUBLISHED":
        metrics = [
            {"metric": "VIEWS", "value": 120},
            {"metric": "QUALIFIED_VIEWS", "value": 42},
            {"metric": "PRODUCTION_MINUTES", "value": 75},
            {"metric": "PRODUCTION_COST_CENTS", "value": 2_500},
        ]
    return {
        "record_id": f"prf_{number:032x}",
        "day_number": day_number,
        "calendar_date": calendar_date,
        "opportunity_id": opportunity_id,
        "observed_at": f"{calendar_date}T18:00:00Z",
        "publication_result": result,
        "block_reason": block_reason,
        "source": {
            "kind": (
                "PLATFORM_ANALYTICS_EXPORT"
                if result == "PUBLISHED"
                else "LOCAL_PUBLICATION_LOG"
            ),
            "artifact_sha256": f"{1000 + number:064x}",
            "record_sha256": f"{source_record_number or 2000 + number:064x}",
        },
        "metrics": metrics,
    }


def performance_document(
    calendar_sha256: str,
    *,
    records: list[dict[str, object]] | None = None,
    performance_date: str = "2026-08-30",
) -> dict[str, object]:
    return {
        "schema_version": "remedialhq.daily-performance.v1",
        "performance_date": performance_date,
        "calendar_sha256": calendar_sha256,
        "records": records or [performance_record(1)],
    }


class DailyPerformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calendar_bytes = CALENDAR_PATH.read_bytes()
        self.calendar = load_prelaunch_calendar(CALENDAR_PATH)
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_authority(self, enabled: object) -> Path:
        path = self.root / "authority.json"
        path.write_text(
            json.dumps({"global_publication_enabled": enabled}),
            encoding="utf-8",
        )
        return path

    def write_feedback(self, document: dict[str, object], name: str = "daily.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_valid_ingestion_is_bounded_source_bound_and_deterministic(self) -> None:
        document = performance_document(self.calendar.sha256)
        text = json.dumps(document, indent=2) + "\n"

        batch = parse_daily_performance(
            text,
            calendar=self.calendar,
            global_publication_enabled=True,
        )

        self.assertEqual(batch.performance_date, "2026-08-30")
        self.assertEqual(batch.calendar_sha256, self.calendar.sha256)
        self.assertEqual(batch.evidence_sha256, hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(len(batch.records), 1)
        record = batch.records[0]
        self.assertEqual(record.publication_result, PublicationResult.PUBLISHED)
        self.assertEqual(record.metrics[1].name, MetricName.QUALIFIED_VIEWS)
        self.assertRegex(record.source.artifact_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(record.source.record_sha256, r"^[0-9a-f]{64}$")
        self.assertNotIn("name", record.source.to_dict())
        self.assertEqual(batch.to_dict(), document)

    def test_schema_and_runtime_enforce_all_collection_and_value_bounds(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["records"]["maxItems"], 82)
        metric_schema = schema["$defs"]["metric"]["properties"]["value"]
        self.assertEqual(metric_schema["maximum"], MAX_METRIC_VALUE)

        unbounded_metric = performance_document(self.calendar.sha256)
        records = unbounded_metric["records"]
        assert isinstance(records, list)
        metrics = records[0]["metrics"]
        assert isinstance(metrics, list)
        metrics[0]["value"] = MAX_METRIC_VALUE + 1
        with self.assertRaisesRegex(DailyPerformanceError, "metric value"):
            build_daily_performance(
                unbounded_metric,
                calendar=self.calendar,
                global_publication_enabled=True,
            )

        too_many_records = performance_document(
            self.calendar.sha256,
            records=[performance_record(index + 1) for index in range(83)],
        )
        with self.assertRaisesRegex(DailyPerformanceError, "1 through 82"):
            build_daily_performance(
                too_many_records,
                calendar=self.calendar,
                global_publication_enabled=True,
            )
        with self.assertRaisesRegex(DailyPerformanceError, "size limit"):
            parse_daily_performance(
                " " * (MAX_DOCUMENT_BYTES + 1),
                calendar=self.calendar,
                global_publication_enabled=True,
            )

    def test_identifying_free_text_raw_fields_and_secrets_are_rejected(self) -> None:
        cases: list[dict[str, object]] = []
        email_field = performance_document(self.calendar.sha256)
        email_field["email"] = "person@example.com"
        cases.append(email_field)

        personal_name = performance_document(self.calendar.sha256)
        records = personal_name["records"]
        assert isinstance(records, list)
        records[0]["record_id"] = "Sample Person"
        cases.append(personal_name)

        platform_identifier = performance_document(self.calendar.sha256)
        records = platform_identifier["records"]
        assert isinstance(records, list)
        source = records[0]["source"]
        assert isinstance(source, dict)
        source["video_id"] = "UCaaaaaaaaaaaaaaaaaaaaaa"
        cases.append(platform_identifier)

        secret = performance_document(self.calendar.sha256)
        records = secret["records"]
        assert isinstance(records, list)
        records[0]["record_id"] = "Bearer secret-token-value"
        cases.append(secret)

        for document in cases:
            with (
                self.subTest(document=document),
                self.assertRaisesRegex(DailyPerformanceError, "identifying|secret"),
            ):
                build_daily_performance(
                    document,
                    calendar=self.calendar,
                    global_publication_enabled=True,
                )

    def test_unknown_missing_duplicate_and_non_json_fields_fail_closed(self) -> None:
        unknown = performance_document(self.calendar.sha256)
        unknown["comment"] = "redacted"
        missing = performance_document(self.calendar.sha256)
        missing.pop("calendar_sha256")
        for document in (unknown, missing):
            with self.assertRaisesRegex(DailyPerformanceError, "missing or unknown"):
                build_daily_performance(
                    document,
                    calendar=self.calendar,
                    global_publication_enabled=True,
                )

        text = json.dumps(performance_document(self.calendar.sha256))
        duplicate = text[:-1] + ',"performance_date":"2026-08-30"}'
        with self.assertRaisesRegex(DailyPerformanceError, "duplicate JSON fields"):
            parse_daily_performance(
                duplicate,
                calendar=self.calendar,
                global_publication_enabled=True,
            )
        with self.assertRaisesRegex(DailyPerformanceError, "non-JSON number"):
            parse_daily_performance(
                text.replace('"value": 120', '"value": NaN'),
                calendar=self.calendar,
                global_publication_enabled=True,
            )

    def test_authority_false_rejects_published_and_accepts_only_matching_block(self) -> None:
        published = performance_document(self.calendar.sha256)
        with self.assertRaisesRegex(DailyPerformanceError, "global publication authority"):
            build_daily_performance(
                published,
                calendar=self.calendar,
                global_publication_enabled=False,
            )

        blocked = performance_document(
            self.calendar.sha256,
            records=[
                performance_record(
                    2,
                    result="BLOCKED",
                    block_reason="PUBLICATION_AUTHORITY_DISABLED",
                )
            ],
        )
        batch = build_daily_performance(
            blocked,
            calendar=self.calendar,
            global_publication_enabled=False,
        )
        self.assertEqual(
            batch.records[0].block_reason,
            BlockReason.PUBLICATION_AUTHORITY_DISABLED,
        )
        self.assertEqual(batch.records[0].metrics, ())

        contradictory = copy.deepcopy(blocked)
        records = contradictory["records"]
        assert isinstance(records, list)
        records[0]["block_reason"] = "ASSET_NOT_READY"
        with self.assertRaisesRegex(DailyPerformanceError, "contradicts"):
            build_daily_performance(
                contradictory,
                calendar=self.calendar,
                global_publication_enabled=False,
            )

    def test_authority_false_report_blocks_launch_now_without_execution(self) -> None:
        report = reconcile_calendar(
            self.calendar,
            (),
            as_of_date="2026-08-30",
            global_publication_enabled=False,
        )
        output = report.to_dict()

        self.assertFalse(report.clear)
        self.assertEqual(report.missed_rows, 0)
        self.assertEqual(report.blocked_rows, 2)
        launch_issue = next(
            issue for issue in report.issues if issue.opportunity_id == "OPP-0002"
        )
        self.assertEqual(launch_issue.status, ReconciliationStatus.BLOCKED)
        self.assertEqual(launch_issue.reason, "PUBLICATION_AUTHORITY_DISABLED")
        safeguards = output["safeguards"]
        assert isinstance(safeguards, dict)
        self.assertFalse(safeguards["publication_performed"])
        self.assertFalse(safeguards["calendar_content_changed"])
        self.assertFalse(safeguards["calendar_dates_changed"])
        self.assertEqual(CALENDAR_PATH.read_bytes(), self.calendar_bytes)

    def test_missing_due_launch_row_is_flagged_without_moving_its_date(self) -> None:
        report = reconcile_calendar(
            self.calendar,
            (),
            as_of_date="2026-08-30",
            global_publication_enabled=True,
        )

        self.assertEqual(report.missed_rows, 1)
        missed = next(
            issue for issue in report.issues if issue.status is ReconciliationStatus.MISSED
        )
        self.assertEqual(missed.opportunity_id, "OPP-0002")
        self.assertEqual(missed.scheduled_date, "2026-08-30")
        self.assertEqual(missed.reason, "NO_DAILY_PERFORMANCE_RECORD")
        planned = next(
            issue for issue in report.issues if issue.opportunity_id == "OPP-0001"
        )
        self.assertEqual(planned.reason, "CALENDAR_STATE_NOT_EXECUTABLE")

    def test_not_published_record_is_reported_as_missed(self) -> None:
        document = performance_document(
            self.calendar.sha256,
            records=[performance_record(3, result="NOT_PUBLISHED")],
        )
        batch = build_daily_performance(
            document,
            calendar=self.calendar,
            global_publication_enabled=True,
        )
        report = reconcile_calendar(
            self.calendar,
            (batch,),
            as_of_date="2026-08-30",
            global_publication_enabled=True,
        )
        missed = next(
            issue for issue in report.issues if issue.opportunity_id == "OPP-0002"
        )
        self.assertEqual(missed.status, ReconciliationStatus.MISSED)
        self.assertEqual(missed.reason, "REPORTED_NOT_PUBLISHED")

    def test_duplicate_records_and_reused_source_rows_are_rejected(self) -> None:
        duplicate_calendar_row = performance_document(
            self.calendar.sha256,
            records=[performance_record(4), performance_record(5)],
        )
        with self.assertRaisesRegex(DailyPerformanceError, "duplicate records"):
            build_daily_performance(
                duplicate_calendar_row,
                calendar=self.calendar,
                global_publication_enabled=True,
            )

        reused_source_row = performance_document(
            self.calendar.sha256,
            records=[
                performance_record(6, source_record_number=99),
                performance_record(7, source_record_number=99),
            ],
        )
        with self.assertRaises(DailyPerformanceError):
            build_daily_performance(
                reused_source_row,
                calendar=self.calendar,
                global_publication_enabled=True,
            )

        first = build_daily_performance(
            performance_document(self.calendar.sha256, records=[performance_record(8)]),
            calendar=self.calendar,
            global_publication_enabled=True,
        )
        second = build_daily_performance(
            performance_document(self.calendar.sha256, records=[performance_record(9)]),
            calendar=self.calendar,
            global_publication_enabled=True,
        )
        with self.assertRaisesRegex(DailyPerformanceError, "across daily batches"):
            reconcile_calendar(
                self.calendar,
                (first, second),
                as_of_date="2026-08-30",
                global_publication_enabled=True,
            )

    def test_source_calendar_digest_and_row_mismatches_are_rejected(self) -> None:
        wrong_digest = performance_document("f" * 64)
        with self.assertRaisesRegex(DailyPerformanceError, "calendar source"):
            build_daily_performance(
                wrong_digest,
                calendar=self.calendar,
                global_publication_enabled=True,
            )

        wrong_row = performance_document(
            self.calendar.sha256,
            records=[performance_record(10, opportunity_id="OPP-0003")],
        )
        with self.assertRaisesRegex(DailyPerformanceError, "calendar row"):
            build_daily_performance(
                wrong_row,
                calendar=self.calendar,
                global_publication_enabled=True,
            )

        wrong_date = performance_document(
            self.calendar.sha256,
            records=[performance_record(11, calendar_date="2026-08-31")],
        )
        with self.assertRaisesRegex(DailyPerformanceError, "performance_date"):
            build_daily_performance(
                wrong_date,
                calendar=self.calendar,
                global_publication_enabled=True,
            )

    def test_calendar_state_cannot_be_overridden_by_feedback(self) -> None:
        planned_publication = performance_document(
            self.calendar.sha256,
            performance_date="2026-08-29",
            records=[
                performance_record(
                    12,
                    day_number=1,
                    calendar_date="2026-08-29",
                    opportunity_id="OPP-0001",
                )
            ],
        )
        with self.assertRaisesRegex(DailyPerformanceError, "immutable calendar state"):
            build_daily_performance(
                planned_publication,
                calendar=self.calendar,
                global_publication_enabled=True,
            )

        planned_block = performance_document(
            self.calendar.sha256,
            performance_date="2026-08-29",
            records=[
                performance_record(
                    13,
                    day_number=1,
                    calendar_date="2026-08-29",
                    opportunity_id="OPP-0001",
                    result="BLOCKED",
                    block_reason="CALENDAR_STATE_NOT_EXECUTABLE",
                )
            ],
        )
        batch = build_daily_performance(
            planned_block,
            calendar=self.calendar,
            global_publication_enabled=True,
        )
        self.assertEqual(
            batch.records[0].block_reason,
            BlockReason.CALENDAR_STATE_NOT_EXECUTABLE,
        )

    def test_filesystem_import_and_authority_are_strict_and_offline(self) -> None:
        authority = self.write_authority(True)
        feedback = self.write_feedback(performance_document(self.calendar.sha256))

        self.assertTrue(load_global_publication_authority(authority))
        loaded = load_daily_performance(
            feedback,
            calendar=self.calendar,
            global_publication_enabled=True,
        )
        self.assertEqual(loaded.records[0].opportunity_id, "OPP-0002")

        invalid_authority = self.write_authority("false")
        with self.assertRaisesRegex(DailyPerformanceError, "JSON boolean"):
            load_global_publication_authority(invalid_authority)

    def test_cli_emits_report_and_returns_nonzero_for_blocked_or_missed_rows(self) -> None:
        authority = self.write_authority(False)
        args = _parser().parse_args(
            [
                "reconcile-performance",
                "--calendar",
                str(CALENDAR_PATH),
                "--authority",
                str(authority),
                "--as-of",
                "2026-08-30",
            ]
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = _reconcile_performance(args)

        self.assertEqual(result, 2)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["outcome"], "ACTION_REQUIRED")
        self.assertFalse(report["global_publication_enabled"])
        self.assertFalse(report["safeguards"]["publication_performed"])
        self.assertEqual(report["summary"]["blocked_rows"], 2)

        clear_args = _parser().parse_args(
            [
                "reconcile-performance",
                "--calendar",
                str(CALENDAR_PATH),
                "--authority",
                str(authority),
                "--as-of",
                "2026-08-28",
            ]
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(_reconcile_performance(clear_args), 0)

    def test_cli_rejects_invalid_feedback_without_echoing_sensitive_input(self) -> None:
        authority = self.write_authority(True)
        document = performance_document(self.calendar.sha256)
        document["email"] = "person@example.com"
        feedback = self.write_feedback(document)
        args = _parser().parse_args(
            [
                "reconcile-performance",
                "--calendar",
                str(CALENDAR_PATH),
                "--authority",
                str(authority),
                "--feedback",
                str(feedback),
                "--as-of",
                "2026-08-30",
            ]
        )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = _reconcile_performance(args)

        self.assertEqual(result, 2)
        self.assertEqual(stderr.getvalue(), "daily performance reconciliation rejected\n")
        self.assertNotIn("person@example.com", stderr.getvalue())

    def test_end_to_end_file_reconciliation_never_changes_calendar_bytes(self) -> None:
        authority = self.write_authority(True)
        feedback = self.write_feedback(performance_document(self.calendar.sha256))

        report = reconcile_performance_files(
            calendar_path=CALENDAR_PATH,
            authority_path=authority,
            feedback_paths=(feedback,),
            as_of_date="2026-08-30",
        )

        self.assertEqual(report.reconciled_rows, 1)
        self.assertEqual(report.missed_rows, 0)
        self.assertEqual(report.blocked_rows, 1)
        self.assertEqual(CALENDAR_PATH.read_bytes(), self.calendar_bytes)

    def test_current_reconciliation_artifact_is_reproducible_from_public_inputs(self) -> None:
        report = reconcile_performance_files(
            calendar_path=CALENDAR_PATH,
            authority_path=AUTHORITY_PATH,
            feedback_paths=(),
            as_of_date="2026-09-01",
        )
        recorded = json.loads(CURRENT_RECONCILIATION_PATH.read_text(encoding="utf-8"))

        self.assertEqual(recorded, report.to_dict())
        self.assertEqual(CALENDAR_PATH.read_bytes(), self.calendar_bytes)


if __name__ == "__main__":
    unittest.main()
