from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date, timedelta
from pathlib import Path

from remedialhq.cli import _parser, _pilot
from remedialhq.pilots import PilotLedger, PilotValidationError

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
                "segment": "GAMING_CREATOR",
                "channel": "BUSINESS_EMAIL",
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


class OutreachCliTests(unittest.TestCase):
    temporary_directory: tempfile.TemporaryDirectory[str]
    root: Path
    ledger_path: Path
    plan_path: Path

    def setUp(self) -> None:
        secure_temp_root = "/tmp" if Path("/tmp").is_dir() else None
        self.temporary_directory = tempfile.TemporaryDirectory(dir=secure_temp_root)
        self.root = Path(self.temporary_directory.name)
        self.ledger_path = self.root / "pilot.jsonl"
        self.plan_path = self.root / "outreach-plan.json"
        self.plan_path.write_text(json.dumps(plan_document()), encoding="utf-8")
        PilotLedger.initialize(
            self.ledger_path,
            prior_consumed_slots=0,
            reconciliation_evidence_sha256=RECONCILIATION_EVIDENCE_SHA256,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_command(self, *arguments: str) -> tuple[int, str]:
        args = _parser().parse_args(["pilot", *arguments])
        output = io.StringIO()
        with redirect_stdout(output):
            result = _pilot(args)
        return result, output.getvalue()

    def test_validate_is_aggregate_read_only_and_cannot_complete_rmh_107(self) -> None:
        result, output = self.run_command(
            "outreach-validate",
            "--input",
            str(self.plan_path),
        )

        self.assertEqual(result, 0)
        report = json.loads(output)
        self.assertTrue(report["plan_complete"])
        self.assertEqual(report["prospects"], 50)
        self.assertIs(report["outreach_sent"], False)
        self.assertIs(report["rmh_107_may_be_marked_complete"], False)
        self.assertNotIn(opaque("prs", 1), output)
        self.assertEqual(PilotLedger(self.ledger_path).verify(), (True, "verified 1 pilot events"))

    def test_import_queue_suppression_and_contact_commands_form_safe_sequence(self) -> None:
        result, output = self.run_command(
            "outreach-import",
            "--input",
            str(self.plan_path),
            "--occurred-at",
            "2026-09-01T12:00:00Z",
            "--ledger",
            str(self.ledger_path),
        )
        self.assertEqual(result, 0)
        imported = json.loads(output)
        self.assertEqual(imported["prospects_imported"], 50)
        self.assertIs(imported["outreach_sent"], False)

        _, output = self.run_command(
            "outreach-queue",
            "--as-of",
            "2026-09-03T12:00:00Z",
            "--ledger",
            str(self.ledger_path),
        )
        queue = json.loads(output)
        self.assertEqual(queue["prospects"], 50)
        self.assertEqual(queue["entries"][0]["cadence_status"], "RECHECK_SUPPRESSION")
        self.assertIs(queue["entries"][0]["contact_allowed"], False)

        self.run_command(
            "suppression-check",
            "--prospect-id",
            opaque("prs", 1),
            "--status",
            "CLEAR",
            "--evidence-sha256",
            digest(40_001),
            "--occurred-at",
            "2026-09-03T12:01:00Z",
            "--ledger",
            str(self.ledger_path),
        )
        self.run_command(
            "contact",
            "--prospect-id",
            opaque("prs", 1),
            "--channel",
            "BUSINESS_EMAIL",
            "--occurred-at",
            "2026-09-03T12:02:00Z",
            "--ledger",
            str(self.ledger_path),
        )

        _, output = self.run_command(
            "outreach-queue",
            "--as-of",
            "2026-09-03T12:03:00Z",
            "--ledger",
            str(self.ledger_path),
        )
        entry = json.loads(output)["entries"][0]
        self.assertEqual(entry["outcome"], "AWAITING_REPLY")
        self.assertEqual(entry["next_action"], "WAIT_FOR_REPLY_OR_OPT_OUT")
        self.assertIs(entry["contact_allowed"], False)

    def test_import_requires_complete_plan(self) -> None:
        self.plan_path.write_text(json.dumps(plan_document(5)), encoding="utf-8")

        with self.assertRaisesRegex(PilotValidationError, "exactly 50"):
            self.run_command(
                "outreach-import",
                "--input",
                str(self.plan_path),
                "--occurred-at",
                "2026-09-01T12:00:00Z",
                "--ledger",
                str(self.ledger_path),
            )
        self.assertEqual(PilotLedger(self.ledger_path).metrics().prospects, 0)

    def test_amend_replaces_one_pre_contact_suppressed_candidate(self) -> None:
        self.run_command(
            "outreach-import",
            "--input",
            str(self.plan_path),
            "--occurred-at",
            "2026-09-01T12:00:00Z",
            "--ledger",
            str(self.ledger_path),
        )
        self.run_command(
            "suppression-check",
            "--prospect-id",
            opaque("prs", 1),
            "--status",
            "OPTED_OUT",
            "--evidence-sha256",
            digest(60_000),
            "--occurred-at",
            "2026-09-03T11:00:00Z",
            "--ledger",
            str(self.ledger_path),
        )
        document = plan_document()
        prospects = document["prospects"]
        assert isinstance(prospects, list)
        assert isinstance(prospects[0], dict)
        prospects[0].update(
            {
                "prospect_id": opaque("prs", 99),
                "qualification_evidence_sha256": digest(60_001),
                "recent_work_reference_sha256": digest(60_002),
                "sample_insight_sha256": digest(60_003),
            }
        )
        self.plan_path.write_text(json.dumps(document), encoding="utf-8")

        result, output = self.run_command(
            "outreach-amend",
            "--input",
            str(self.plan_path),
            "--occurred-at",
            "2026-09-03T11:01:00Z",
            "--ledger",
            str(self.ledger_path),
        )

        self.assertEqual(result, 0)
        report = json.loads(output)
        self.assertEqual(report["prospects_active"], 50)
        self.assertIs(report["outreach_sent"], False)
        self.assertIs(report["rmh_107_may_be_marked_complete"], False)


if __name__ == "__main__":
    unittest.main()
