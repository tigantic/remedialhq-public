from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from remedialhq.cli import _google_setup, _parser
from remedialhq.google_setup import (
    ANALYTICS_ACCOUNT_NAME,
    ANALYTICS_DEFAULT_URI,
    ANALYTICS_PROPERTY_NAME,
    ANALYTICS_STREAM_NAME,
    DOMAIN,
    PROJECT_ID_PLACEHOLDER,
    SEARCH_CONSOLE_PROPERTY,
    SITEMAP_URL,
    TAG_MANAGER_ACCOUNT_NAME,
    TAG_MANAGER_CONTAINER_NAME,
    GoogleSetupError,
    build_plan,
    owner_account_sha256,
    run_google_setup,
    write_private_evidence,
)

OWNER_EMAIL = "owner@remedialhq.example"
OWNER_DIGEST = owner_account_sha256(OWNER_EMAIL)
TEST_PROJECT_ID = "example-project-123456"
FIXED_TIME = datetime(2026, 9, 2, 12, 30, tzinfo=UTC)


class FakeGoogleSetupTransport:
    def __init__(self) -> None:
        self.email = OWNER_EMAIL
        self.verified_email = True
        self.sites: list[dict[str, object]] = []
        self.verifications: list[dict[str, object]] = []
        self.sitemaps: list[dict[str, object]] = []
        self.analytics_account_items: list[dict[str, object]] = [
            {"account": "accounts/100", "displayName": ANALYTICS_ACCOUNT_NAME}
        ]
        self.properties: list[dict[str, object]] = []
        self.streams: list[dict[str, object]] = []
        self.gtm_account_items: list[dict[str, object]] = [
            {
                "path": "accounts/200",
                "accountId": "200",
                "name": TAG_MANAGER_ACCOUNT_NAME,
            }
        ]
        self.containers: list[dict[str, object]] = []
        self.calls: list[str] = []

    def owner_identity(self) -> Mapping[str, object]:
        self.calls.append("read:owner")
        return {"email": self.email, "verified_email": self.verified_email}

    def search_console_sites(self) -> Sequence[Mapping[str, object]]:
        self.calls.append("read:search-sites")
        return tuple(self.sites)

    def site_verifications(self) -> Sequence[Mapping[str, object]]:
        self.calls.append("read:site-verification")
        return tuple(self.verifications)

    def search_console_sitemaps(
        self, site_url: str
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append(f"read:sitemaps:{site_url}")
        return tuple(self.sitemaps)

    def analytics_accounts(self) -> Sequence[Mapping[str, object]]:
        self.calls.append("read:analytics-accounts")
        return tuple(self.analytics_account_items)

    def analytics_properties(
        self, account_name: str
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append(f"read:analytics-properties:{account_name}")
        return tuple(self.properties)

    def analytics_streams(
        self, property_name: str
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append(f"read:analytics-streams:{property_name}")
        return tuple(self.streams)

    def tag_manager_accounts(self) -> Sequence[Mapping[str, object]]:
        self.calls.append("read:gtm-accounts")
        return tuple(self.gtm_account_items)

    def tag_manager_containers(
        self, account_path: str
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append(f"read:gtm-containers:{account_path}")
        return tuple(self.containers)

    def verify_search_domain(self) -> None:
        self.calls.append("write:verify-domain")
        self.verifications = [
            {"site": {"type": "INET_DOMAIN", "identifier": DOMAIN}}
        ]

    def add_search_console_property(self) -> None:
        self.calls.append("write:add-search-property")
        self.sites = [
            {"siteUrl": SEARCH_CONSOLE_PROPERTY, "permissionLevel": "siteOwner"}
        ]

    def submit_search_console_sitemap(self) -> None:
        self.calls.append("write:submit-sitemap")
        self.sitemaps = [{"path": SITEMAP_URL}]

    def create_analytics_property(self, account_name: str) -> None:
        self.calls.append(f"write:create-analytics-property:{account_name}")
        self.properties = [
            {"name": "properties/300", "displayName": ANALYTICS_PROPERTY_NAME}
        ]

    def create_analytics_stream(self, property_name: str) -> None:
        self.calls.append(f"write:create-analytics-stream:{property_name}")
        self.streams = [
            {
                "name": "properties/300/dataStreams/400",
                "displayName": ANALYTICS_STREAM_NAME,
                "type": "WEB_DATA_STREAM",
                "webStreamData": {
                    "defaultUri": ANALYTICS_DEFAULT_URI,
                    "measurementId": "G-TEST123",
                },
            }
        ]

    def create_tag_manager_container(self, account_path: str) -> None:
        self.calls.append(f"write:create-gtm-container:{account_path}")
        self.containers = [
            {
                "path": "accounts/200/containers/500",
                "name": TAG_MANAGER_CONTAINER_NAME,
                "usageContext": ["web"],
                "publicId": "GTM-TEST123",
            }
        ]


class GoogleSetupTests(unittest.TestCase):
    def test_plan_is_offline_exact_and_contains_no_account_creation(self) -> None:
        plan = build_plan()
        self.assertEqual(plan["mode"], "PLAN_ONLY")
        self.assertFalse(plan["network_used"])
        self.assertFalse(plan["mutation_authorized"])
        targets = cast(dict[str, object], plan["targets"])
        self.assertIsInstance(targets, dict)
        self.assertEqual(targets["project_id"], PROJECT_ID_PLACEHOLDER)
        explicit_targets = cast(dict[str, object], build_plan(TEST_PROJECT_ID)["targets"])
        self.assertEqual(explicit_targets["project_id"], TEST_PROJECT_ID)
        self.assertEqual(targets["domain"], DOMAIN)
        serialized = json.dumps(plan)
        self.assertNotIn("create Analytics account", serialized)
        self.assertNotIn("create Tag Manager account", serialized)
        self.assertIn("no terms acceptance", serialized)

    def test_default_cli_mode_does_not_load_a_credential(self) -> None:
        args = _parser().parse_args(["google-setup"])
        loaded = False

        def forbidden_loader(_path: str) -> object:
            nonlocal loaded
            loaded = True
            raise AssertionError("credential loader called in plan-only mode")

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = _google_setup(args, credential_loader=forbidden_loader)
        self.assertEqual(result, 0)
        self.assertFalse(loaded)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "PLANNED")

    def test_live_readback_never_calls_a_mutation(self) -> None:
        transport = FakeGoogleSetupTransport()
        result = run_google_setup(
            transport,
            project_id=TEST_PROJECT_ID,
            owner_account_digest=OWNER_DIGEST,
            apply_live=False,
            clock=lambda: FIXED_TIME,
        )
        self.assertEqual(result["status"], "READY")
        self.assertFalse(result["mutation_authorized"])
        self.assertEqual(result["mutations"], [])
        self.assertFalse(any(call.startswith("write:") for call in transport.calls))

    def test_invalid_project_id_is_rejected_before_transport_read(self) -> None:
        transport = FakeGoogleSetupTransport()
        for project_id in ("", "INVALID_PROJECT", "-bad-project"):
            with self.subTest(project_id=project_id), self.assertRaisesRegex(
                GoogleSetupError, "valid Google Cloud project ID"
            ):
                run_google_setup(
                    transport,
                    project_id=project_id,
                    owner_account_digest=OWNER_DIGEST,
                    apply_live=False,
                )
        self.assertEqual(transport.calls, [])

    def test_apply_creates_exact_missing_resources_then_rerun_is_idempotent(self) -> None:
        transport = FakeGoogleSetupTransport()
        first = run_google_setup(
            transport,
            project_id=TEST_PROJECT_ID,
            owner_account_digest=OWNER_DIGEST,
            apply_live=True,
            clock=lambda: FIXED_TIME,
        )
        self.assertEqual(first["status"], "COMPLETE")
        self.assertEqual(
            first["mutations"],
            [
                "RMH-053:verified-domain",
                "RMH-053:created-domain-property",
                "RMH-053:submitted-sitemap",
                "RMH-055:created-property",
                "RMH-055:created-web-stream",
                "RMH-056:created-web-container",
            ],
        )
        writes_after_first = [call for call in transport.calls if call.startswith("write:")]
        second = run_google_setup(
            transport,
            project_id=TEST_PROJECT_ID,
            owner_account_digest=OWNER_DIGEST,
            apply_live=True,
            clock=lambda: FIXED_TIME,
        )
        self.assertEqual(second["status"], "COMPLETE")
        self.assertEqual(second["mutations"], [])
        self.assertEqual(
            [call for call in transport.calls if call.startswith("write:")],
            writes_after_first,
        )

    def test_missing_existing_account_blocks_every_mutation(self) -> None:
        transport = FakeGoogleSetupTransport()
        transport.analytics_account_items = []
        result = run_google_setup(
            transport,
            project_id=TEST_PROJECT_ID,
            owner_account_digest=OWNER_DIGEST,
            apply_live=True,
            clock=lambda: FIXED_TIME,
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["mutations"], [])
        self.assertFalse(any(call.startswith("write:") for call in transport.calls))
        blockers = cast(list[dict[str, str]], result["blockers"])
        self.assertEqual(blockers[0]["code"], "EXACT_ANALYTICS_ACCOUNT_REQUIRED")

    def test_identity_mismatch_fails_closed_without_retaining_email(self) -> None:
        transport = FakeGoogleSetupTransport()
        result = run_google_setup(
            transport,
            project_id=TEST_PROJECT_ID,
            owner_account_digest="a" * 64,
            apply_live=True,
            clock=lambda: FIXED_TIME,
        )
        serialized = json.dumps(result)
        self.assertEqual(result["status"], "FAILED_CLOSED")
        self.assertNotIn(OWNER_EMAIL, serialized)
        self.assertEqual(result["mutations"], [])

    def test_private_evidence_is_sanitized_outside_repository_at_0600(self) -> None:
        transport = FakeGoogleSetupTransport()
        evidence = run_google_setup(
            transport,
            project_id=TEST_PROJECT_ID,
            owner_account_digest=OWNER_DIGEST,
            apply_live=False,
            clock=lambda: FIXED_TIME,
        )
        with (
            tempfile.TemporaryDirectory(dir="/tmp") as repository,
            tempfile.TemporaryDirectory(dir="/tmp") as private_parent,
        ):
            os.chmod(private_parent, 0o700)
            destination = Path(private_parent) / "google-setup.json"
            digest = write_private_evidence(
                destination,
                evidence,
                repository_root=repository,
            )
            self.assertEqual(len(digest), 64)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            encoded = destination.read_text(encoding="utf-8")
            self.assertNotIn(OWNER_EMAIL, encoded)
            self.assertNotIn("refresh_token", encoded)
            self.assertNotIn("access_token", encoded)

    def test_evidence_inside_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as repository:
            os.chmod(repository, 0o700)
            with self.assertRaisesRegex(GoogleSetupError, "outside the repository"):
                write_private_evidence(
                    Path(repository) / "evidence.json",
                    build_plan(),
                    repository_root=repository,
                )

    def test_live_cli_requires_all_explicit_private_inputs(self) -> None:
        args = _parser().parse_args(["google-setup", "--apply-live"])
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = _google_setup(args)
        self.assertEqual(result, 2)
        self.assertIn("requires project ID", stderr.getvalue())

    def test_live_cli_rejects_invalid_project_before_loading_credentials(self) -> None:
        calls: list[str] = []

        def credential_loader(path: str) -> object:
            calls.append(f"credential:{path}")
            return object()

        def transport_builder(_credentials: object) -> object:
            calls.append("transport")
            return object()

        args = _parser().parse_args(
            [
                "google-setup",
                "--apply-live",
                "--project-id",
                "INVALID_PROJECT",
                "--credential",
                "/tmp/not-used.json",
                "--owner-account-sha256",
                "a" * 64,
                "--evidence-output",
                "/tmp/not-written.json",
            ]
        )
        with redirect_stderr(io.StringIO()):
            result = _google_setup(
                args,
                credential_loader=credential_loader,
                transport_builder=transport_builder,
            )
        self.assertEqual(result, 2)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
