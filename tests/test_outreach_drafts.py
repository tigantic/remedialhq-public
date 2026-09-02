from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from remedialhq.outreach_drafts import (
    OutreachDraftError,
    _atomic_private_write,
    build_draft_packet,
    render_markdown,
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def _cohort() -> dict[str, object]:
    return {
        "campaign_ref": "cmp_" + "1" * 32,
        "prospects": [
            {
                "prospect_id": "prs_" + "2" * 32,
                "prospect_name": "Test Creator",
                "queue_position": 1,
                "planned_contact_date": "2026-09-03",
                "channel": "BUSINESS_EMAIL",
                "segment": "GAMING_CREATOR",
                "source_batch": "batch.json",
                "public_business_route": {"url": "https://example.test/contact"},
            }
        ],
    }


def _batch() -> dict[str, object]:
    return {
        "prospects": [
            {
                "prospect_name": "Test Creator",
                "qualifying_gta_vi_item": {
                    "title": "What the footage actually showed",
                    "url": "https://example.test/work",
                },
                "specific_upcoming_piece_hypothesis": "A sourced follow-up.",
                "personalized_sample_insight": {
                    "text": "A visible prompt supports an observation, not a final system claim.",
                    "source_urls": ["https://www.rockstargames.com/VI"],
                },
            }
        ]
    }


def _angles(
    angle: str = "A practical GTA VI follow-up built around the next official update.",
) -> dict[str, object]:
    return {
        "schema_version": "remedialhq.sales-angles.v1",
        "campaign_ref": "cmp_" + "1" * 32,
        "generated_at": "2026-09-01T22:00:00Z",
        "prospect_count": 1,
        "privacy_boundary": "Owner-private.",
        "angles": [
            {
                "prospect_id": "prs_" + "2" * 32,
                "queue_position": 1,
                "customer_facing_angle": angle,
            }
        ],
    }


def _owner_profile() -> dict[str, object]:
    return {
        "schema_version": 1,
        "classification": "OWNER_PRIVATE",
        "reported_at": "2026-09-02T00:00:00Z",
        "legal_name": "Private Owner",
        "birthdate": "1990-01-02",
        "root_google_email": "owner@example.test",
        "phone_e164": "+13365550199",
        "phone_display": "(336) 555-0199",
        "address": {
            "line1": "123 Example Street",
            "city": "Exampleville",
            "state": "NC",
            "postal_code": "27101",
            "country": "US",
        },
        "domain": "example.test",
        "youtube_handle": "@Example",
        "brand": "Example Brand",
    }


class OutreachDraftTests(unittest.TestCase):
    def test_builds_grounded_private_draft_without_sending(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, _batch())
            _write_json(angle_path, _angles())
            _write_json(owner_path, _owner_profile())

            packet = build_draft_packet(
                cohort_path,
                [batch_path],
                angle_path,
                owner_path,
                expected_count=1,
                generated_at="2026-09-01T22:00:00+00:00",
            )

        self.assertEqual(packet["prospect_count"], 1)
        self.assertIs(packet["outreach_sent"], False)
        drafts = packet["drafts"]
        assert isinstance(drafts, list)
        draft = drafts[0]
        assert isinstance(draft, dict)
        self.assertIn("What the footage actually showed", draft["body"])
        self.assertIn("A practical GTA VI follow-up", draft["body"])
        self.assertIn("A sourced follow-up", draft["fit_hypothesis"])
        self.assertNotIn("A visible prompt supports", draft["body"])
        self.assertIn("A visible prompt supports", draft["research_note"])
        self.assertIn("I run ReMediaL HQ", draft["body"])
        self.assertIn("three angles worth using", draft["body"])
        self.assertIn("reply no", draft["body"])
        self.assertTrue(
            str(draft["body"]).endswith(
                "support@remedialhq.com\n123 Example Street\nExampleville, NC 27101\nUS"
            )
        )
        self.assertNotIn("Private Owner", draft["body"])
        self.assertTrue(packet["postal_footer_included_for_email"])
        self.assertEqual(len(str(packet["postal_footer_sha256"])), 64)
        self.assertNotIn("unresolved-claim watchlist", draft["body"])
        self.assertNotIn("wording matched to the evidence", draft["body"])
        self.assertNotIn("\u2014", json.dumps(packet, ensure_ascii=False))

    def test_normalizes_em_dash_from_source_copy(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            batch = _batch()
            prospects = batch["prospects"]
            assert isinstance(prospects, list)
            first = prospects[0]
            assert isinstance(first, dict)
            first["personalized_sample_insight"] = "Shown \u2014 not final."
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, batch)
            _write_json(
                angle_path,
                _angles("A practical GTA VI follow-up \u2014 built for the next official update."),
            )
            _write_json(owner_path, _owner_profile())

            packet = build_draft_packet(
                cohort_path,
                [batch_path],
                angle_path,
                owner_path,
                expected_count=1,
            )

        self.assertNotIn("\u2014", json.dumps(packet, ensure_ascii=False))

    def test_addresses_editorial_publications_as_teams(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            batch = _batch()
            prospects = batch["prospects"]
            assert isinstance(prospects, list)
            prospect = prospects[0]
            assert isinstance(prospect, dict)
            prospect["prospect_type"] = "GAMING_EDITORIAL_TEAM"
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, batch)
            _write_json(angle_path, _angles())
            _write_json(owner_path, _owner_profile())

            packet = build_draft_packet(
                cohort_path,
                [batch_path],
                angle_path,
                owner_path,
                expected_count=1,
            )

        drafts = packet["drafts"]
        assert isinstance(drafts, list)
        draft = drafts[0]
        assert isinstance(draft, dict)
        self.assertTrue(str(draft["body"]).startswith("Hi Test Creator team,"))

    def test_keeps_internal_planning_language_out_of_pitch(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            batch = _batch()
            prospects = batch["prospects"]
            assert isinstance(prospects, list)
            prospect = prospects[0]
            assert isinstance(prospect, dict)
            prospect["specific_upcoming_piece_hypothesis"] = (
                "A launch guide with a separate evidence pass for performance claims."
            )
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, batch)
            _write_json(angle_path, _angles())
            _write_json(owner_path, _owner_profile())

            packet = build_draft_packet(
                cohort_path,
                [batch_path],
                angle_path,
                owner_path,
                expected_count=1,
            )

        drafts = packet["drafts"]
        assert isinstance(drafts, list)
        draft = drafts[0]
        assert isinstance(draft, dict)
        self.assertNotIn("evidence pass", draft["body"])
        self.assertIn("A practical GTA VI follow-up", draft["body"])
        self.assertIn("evidence pass", draft["fit_hypothesis"])

    def test_rejects_internal_language_in_customer_facing_angle(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, _batch())
            _write_json(
                angle_path,
                _angles("An unresolved claim audit for the next GTA VI video update."),
            )
            _write_json(owner_path, _owner_profile())

            with self.assertRaisesRegex(OutreachDraftError, "internal pitch language"):
                build_draft_packet(
                    cohort_path,
                    [batch_path],
                    angle_path,
                    owner_path,
                    expected_count=1,
                )

    def test_rejects_internal_language_variants_in_customer_facing_angle(self) -> None:
        variants = (
            "A practical update built from multiple sources for your next GTA VI video.",
            "A practical update with citations ready for your next GTA VI video.",
            "A practical fact-checking pass for your next major GTA VI video update.",
        )
        for angle in variants:
            with self.subTest(angle=angle), tempfile.TemporaryDirectory(dir="/tmp") as directory:
                root = Path(directory)
                cohort_path = root / "cohort.json"
                batch_path = root / "batch.json"
                angle_path = root / "angles.json"
                owner_path = root / "owner.json"
                _write_json(cohort_path, _cohort())
                _write_json(batch_path, _batch())
                _write_json(angle_path, _angles(angle))
                _write_json(owner_path, _owner_profile())

                with self.assertRaisesRegex(OutreachDraftError, "internal pitch language"):
                    build_draft_packet(
                        cohort_path,
                        [batch_path],
                        angle_path,
                        owner_path,
                        expected_count=1,
                    )

    def test_rejects_identity_data_in_customer_facing_angle(self) -> None:
        variants = (
            "A practical GTA VI follow-up for Private Owner and the next official update.",
            "A practical GTA VI follow-up at www.example.test for the next official update.",
            "A practical GTA VI follow-up via mailto:desk@example.test for the next update.",
            "A practical GTA VI follow-up by calling 336-555-0199 before the next update.",
            "A practical GTA VI follow-up from 123 Example Street for the next update.",
            "A practical GTA VI follow-up for Exampleville creators covering the next update.",
            "A practical GTA VI follow-up planned around a birthday on 01/02/1990.",
        )
        for angle in variants:
            with self.subTest(angle=angle), tempfile.TemporaryDirectory(dir="/tmp") as directory:
                root = Path(directory)
                cohort_path = root / "cohort.json"
                batch_path = root / "batch.json"
                angle_path = root / "angles.json"
                owner_path = root / "owner.json"
                _write_json(cohort_path, _cohort())
                _write_json(batch_path, _batch())
                _write_json(angle_path, _angles(angle))
                _write_json(owner_path, _owner_profile())

                with self.assertRaisesRegex(OutreachDraftError, "prohibited identity data"):
                    build_draft_packet(
                        cohort_path,
                        [batch_path],
                        angle_path,
                        owner_path,
                        expected_count=1,
                    )

    def test_rejects_owner_identity_from_source_title_in_rendered_copy(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            batch = _batch()
            prospects = batch["prospects"]
            assert isinstance(prospects, list)
            prospect = prospects[0]
            assert isinstance(prospect, dict)
            work = prospect["qualifying_gta_vi_item"]
            assert isinstance(work, dict)
            work["title"] = "Private Owner reviews the latest GTA VI footage"
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, batch)
            _write_json(angle_path, _angles())
            _write_json(owner_path, _owner_profile())

            with self.assertRaisesRegex(OutreachDraftError, "owner identity data"):
                build_draft_packet(
                    cohort_path,
                    [batch_path],
                    angle_path,
                    owner_path,
                    expected_count=1,
                )

    def test_rejects_angle_without_terminal_punctuation(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, _batch())
            _write_json(
                angle_path,
                _angles("A practical GTA VI follow-up built around the next official update"),
            )
            _write_json(owner_path, _owner_profile())

            with self.assertRaisesRegex(OutreachDraftError, "end with punctuation"):
                build_draft_packet(
                    cohort_path,
                    [batch_path],
                    angle_path,
                    owner_path,
                    expected_count=1,
                )

    def test_refuses_missing_source_record(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            batch = _batch()
            prospects = batch["prospects"]
            assert isinstance(prospects, list)
            prospect = prospects[0]
            assert isinstance(prospect, dict)
            prospect["prospect_name"] = "Wrong Creator"
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, batch)
            _write_json(angle_path, _angles())
            _write_json(owner_path, _owner_profile())

            with self.assertRaisesRegex(OutreachDraftError, "missing source record"):
                build_draft_packet(
                    cohort_path,
                    [batch_path],
                    angle_path,
                    owner_path,
                    expected_count=1,
                )

    def test_private_writer_enforces_modes(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            root.chmod(0o700)
            output = root / "packet.json"

            _atomic_private_write(output, "{}\n")

            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_markdown_is_an_operator_packet(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            cohort_path = root / "cohort.json"
            batch_path = root / "batch.json"
            angle_path = root / "angles.json"
            owner_path = root / "owner.json"
            _write_json(cohort_path, _cohort())
            _write_json(batch_path, _batch())
            _write_json(angle_path, _angles())
            _write_json(owner_path, _owner_profile())
            packet = build_draft_packet(
                cohort_path,
                [batch_path],
                angle_path,
                owner_path,
                expected_count=1,
            )

        markdown = render_markdown(packet)
        self.assertIn("Drafts only. No message was sent", markdown)
        self.assertIn("https://example.test/contact", markdown)


if __name__ == "__main__":
    unittest.main()
