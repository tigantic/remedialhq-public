from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from remedialhq.contact_evidence import (
    ContactEvidenceError,
    build_contact_evidence,
    load_contact_evidence,
    parse_contact_evidence,
    private_file_sha256,
)

PROSPECT_ID = "prs_" + "1" * 32
SENDER_PROFILE_SHA256 = "1" * 64


def valid_document() -> dict[str, object]:
    return {
        "schema_version": "remedialhq.contact-evidence.v1",
        "event_type": "OUTREACH_MESSAGE_SENT",
        "prospect_id": PROSPECT_ID,
        "channel": "BUSINESS_EMAIL",
        "sender_profile_evidence_sha256": SENDER_PROFILE_SHA256,
        "suppression_evidence_sha256": "2" * 64,
        "message_copy_sha256": "3" * 64,
        "provider_send_evidence_sha256": "4" * 64,
        "provider_message_sha256": "5" * 64,
        "observed_at": "2026-09-03T08:10:00-04:00",
    }


class ContactEvidenceTests(unittest.TestCase):
    def build(self, document: dict[str, object] | None = None):
        return build_contact_evidence(
            valid_document() if document is None else document,
            expected_prospect_id=PROSPECT_ID,
            expected_channel="BUSINESS_EMAIL",
            expected_sender_profile_evidence_sha256=SENDER_PROFILE_SHA256,
        )

    def test_normalizes_and_binds_post_send_evidence(self) -> None:
        evidence = self.build()

        self.assertEqual(evidence.observed_at, "2026-09-03T12:10:00Z")
        self.assertEqual(evidence.prospect_id, PROSPECT_ID)
        self.assertRegex(evidence.sha256, r"^[0-9a-f]{64}$")
        with self.assertRaises(FrozenInstanceError):
            evidence.channel = "SOCIAL_DM"  # type: ignore[misc]

    def test_exact_prospect_channel_and_sender_profile_are_required(self) -> None:
        cases = (
            {"expected_prospect_id": "prs_" + "9" * 32},
            {"expected_channel": "SOCIAL_DM"},
            {"expected_sender_profile_evidence_sha256": "9" * 64},
        )
        for overrides in cases:
            arguments = {
                "expected_prospect_id": PROSPECT_ID,
                "expected_channel": "BUSINESS_EMAIL",
                "expected_sender_profile_evidence_sha256": SENDER_PROFILE_SHA256,
                **overrides,
            }
            with self.subTest(overrides=overrides), self.assertRaises(ContactEvidenceError):
                build_contact_evidence(valid_document(), **arguments)

    def test_only_provider_confirmed_send_event_is_accepted(self) -> None:
        for value in ("MESSAGE_DRAFTED", "SEND_REQUESTED", "EMAIL_SENT"):
            document = valid_document()
            document["event_type"] = value
            with self.subTest(value=value), self.assertRaises(ContactEvidenceError):
                self.build(document)

    def test_all_evidence_digests_are_distinct_lowercase_sha256(self) -> None:
        duplicate = valid_document()
        duplicate["provider_message_sha256"] = duplicate["message_copy_sha256"]
        uppercase = valid_document()
        uppercase["provider_message_sha256"] = "A" * 64

        for document in (duplicate, uppercase):
            with self.assertRaises(ContactEvidenceError):
                self.build(document)

    def test_unknown_fields_and_raw_identity_values_are_rejected(self) -> None:
        unknown = valid_document()
        unknown["recipient"] = "redacted"
        identity = valid_document()
        identity["recipient"] = "person" + "@" + "example.com"

        for document in (unknown, identity):
            with self.assertRaises(ContactEvidenceError) as context:
                self.build(document)
            self.assertNotIn(str(document.get("recipient")), str(context.exception))

    def test_strict_json_rejects_duplicate_fields_and_bad_timestamp(self) -> None:
        duplicate = '{"event_type":"OUTREACH_MESSAGE_SENT","event_type":"SEND_REQUESTED"}'
        with self.assertRaises(ContactEvidenceError):
            parse_contact_evidence(
                duplicate,
                expected_prospect_id=PROSPECT_ID,
                expected_channel="BUSINESS_EMAIL",
                expected_sender_profile_evidence_sha256=SENDER_PROFILE_SHA256,
            )

        document = valid_document()
        document["observed_at"] = "2026-09-03T12:10:00"
        with self.assertRaises(ContactEvidenceError):
            self.build(document)

    def test_private_load_requires_mode_0600_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            path = root / "contact.json"
            path.write_text(json.dumps(valid_document()), encoding="utf-8")
            path.chmod(0o600)
            loaded = load_contact_evidence(
                path,
                expected_prospect_id=PROSPECT_ID,
                expected_channel="BUSINESS_EMAIL",
                expected_sender_profile_evidence_sha256=SENDER_PROFILE_SHA256,
            )
            self.assertEqual(loaded.prospect_id, PROSPECT_ID)
            self.assertRegex(private_file_sha256(path, maximum_bytes=16_384), r"^[0-9a-f]{64}$")

            path.chmod(0o644)
            with self.assertRaisesRegex(ContactEvidenceError, "0600"):
                private_file_sha256(path, maximum_bytes=16_384)

            path.chmod(0o600)
            linked = root / "linked.json"
            linked.symlink_to(path)
            with self.assertRaisesRegex(ContactEvidenceError, "regular file"):
                load_contact_evidence(
                    linked,
                    expected_prospect_id=PROSPECT_ID,
                    expected_channel="BUSINESS_EMAIL",
                    expected_sender_profile_evidence_sha256=SENDER_PROFILE_SHA256,
                )


if __name__ == "__main__":
    unittest.main()
