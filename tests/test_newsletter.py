from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from remedialhq.newsletter import (
    NewsletterConfiguration,
    NewsletterContractError,
    validate_signup,
    verify_webhook,
)

ROOT = Path(__file__).resolve().parents[1]


class NewsletterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inert = NewsletterConfiguration.from_path(ROOT / "config" / "newsletter_contract.json")
        self.active = replace(
            self.inert,
            enabled=True,
            provider="synthetic-test-provider",
            public_signup_endpoint="https://example.invalid/newsletter/signup",
            public_webhook_endpoint="https://example.invalid/newsletter/webhook",
            store_addresses=True,
            status="SYNTHETIC_TEST_ONLY",
        )
        self.now = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
        self.timestamp = str(int(self.now.timestamp()))
        self.secret = b"synthetic-webhook-secret-32-bytes-minimum"

    def signed(self, payload: object) -> tuple[bytes, str]:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        digest = hmac.new(
            self.secret,
            self.timestamp.encode("ascii") + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        return body, f"v1={digest}"

    def valid_event(self) -> dict[str, object]:
        return {
            "event_id": "evt_123456789012",
            "event_type": "subscriber.confirmed",
            "occurred_at": "2026-09-01T12:00:00Z",
            "subscriber_ref": "sub_123456789012",
            "consent_ref": "cns_123456789012",
        }

    def test_repository_configuration_is_inert(self) -> None:
        self.assertFalse(self.inert.enabled)
        self.assertIsNone(self.inert.provider)
        self.assertIsNone(self.inert.public_signup_endpoint)
        self.assertIsNone(self.inert.public_webhook_endpoint)
        self.assertFalse(self.inert.store_addresses)
        with self.assertRaisesRegex(NewsletterContractError, "disabled"):
            validate_signup(self.inert, {}, body_size=2)

    def test_signup_requires_exact_bounded_consented_input(self) -> None:
        intent = validate_signup(
            self.active,
            {
                "email": "SYNTHETIC@EXAMPLE.INVALID",
                "consent": True,
                "terms_version": "2026-08-29",
                "privacy_version": "2026-08-29",
            },
            body_size=128,
        )
        self.assertEqual(intent.email, "synthetic@example.invalid")
        for payload, size in (
            ({"email": "synthetic@example.invalid"}, 40),
            (
                {
                    "email": "synthetic@example.invalid",
                    "consent": False,
                    "terms_version": "v1",
                    "privacy_version": "v1",
                },
                100,
            ),
            (
                {
                    "email": "synthetic@example.invalid",
                    "consent": True,
                    "terms_version": "v1",
                    "privacy_version": "v1",
                },
                9000,
            ),
        ):
            with self.assertRaises(NewsletterContractError):
                validate_signup(self.active, payload, body_size=size)

    def test_signed_webhook_returns_only_opaque_event_data(self) -> None:
        body, signature = self.signed(self.valid_event())
        event = verify_webhook(
            self.active,
            body,
            timestamp=self.timestamp,
            signature=signature,
            secret=self.secret,
            now=self.now,
        )
        self.assertEqual(event.event_type, "subscriber.confirmed")
        self.assertEqual(event.subscriber_ref, "sub_123456789012")

    def test_webhook_rejects_bad_signature_replay_and_identifying_fields(self) -> None:
        body, signature = self.signed(self.valid_event())
        with self.assertRaisesRegex(NewsletterContractError, "does not match"):
            verify_webhook(
                self.active,
                body,
                timestamp=self.timestamp,
                signature="v1=" + "0" * 64,
                secret=self.secret,
                now=self.now,
            )
        stale = datetime(2026, 9, 1, 13, 0, tzinfo=UTC)
        with self.assertRaisesRegex(NewsletterContractError, "replay window"):
            verify_webhook(
                self.active,
                body,
                timestamp=self.timestamp,
                signature=signature,
                secret=self.secret,
                now=stale,
            )
        identifying = self.valid_event() | {"email": "synthetic@example.invalid"}
        identifying_body, identifying_signature = self.signed(identifying)
        with self.assertRaisesRegex(NewsletterContractError, "identifying"):
            verify_webhook(
                self.active,
                identifying_body,
                timestamp=self.timestamp,
                signature=identifying_signature,
                secret=self.secret,
                now=self.now,
            )

    def test_configuration_rejects_partial_activation(self) -> None:
        incomplete = replace(self.inert, enabled=True, provider="synthetic")
        with self.assertRaises(NewsletterContractError):
            incomplete.validate()
        raw = json.loads((ROOT / "config" / "newsletter_contract.json").read_text())
        raw["provider"] = "must-not-exist-while-disabled"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "newsletter.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(NewsletterContractError, "must not name live routes"):
                NewsletterConfiguration.from_path(path)


if __name__ == "__main__":
    unittest.main()
