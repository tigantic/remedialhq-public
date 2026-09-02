from __future__ import annotations

import http.client
import json
import shutil
import tempfile
import threading
import unittest
from collections.abc import Mapping
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from typing import Literal

from remedialhq.edge import (
    IAP_AUDIENCE_ENV,
    IAP_EMAIL_HEADER,
    IAP_EMAIL_NAMESPACE,
    IAP_ISSUER,
    IAP_JWT_HEADER,
    IAP_REGION,
    MAX_CLAIMS,
    EdgeApplication,
    EdgeConfig,
    EdgeConfigurationError,
    EdgeHTTPServer,
    PublicDataError,
    TokenVerifier,
    load_config,
    load_public_snapshot,
    owner_email_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
TEST_EMAIL = "owner@example.test"
TEST_HEADER = IAP_EMAIL_NAMESPACE + TEST_EMAIL
TEST_DIGEST = owner_email_sha256(TEST_EMAIL)
TEST_SERVICE = "remedialhq-prod-app"
TEST_PROJECT_NUMBER = "123456789012"
TEST_AUDIENCE = f"/projects/{TEST_PROJECT_NUMBER}/locations/{IAP_REGION}/services/{TEST_SERVICE}"
TEST_TOKEN = "signed-header.signed-claims.signed-signature"


def _headers(*pairs: tuple[str, str]) -> Message:
    value = Message()
    for name, item in pairs:
        value.add_header(name, item)
    return value


def _verified_claims(**overrides: object) -> Mapping[str, object]:
    claims: dict[str, object] = {
        "iss": IAP_ISSUER,
        "aud": TEST_AUDIENCE,
        "sub": "accounts.google.com:1234567890",
        "email": TEST_EMAIL,
        "iat": 1_787_987_000,
        "exp": 1_787_990_600,
    }
    claims.update(overrides)
    return claims


def _valid_verifier(token: str, audience: str) -> Mapping[str, object]:
    if token != TEST_TOKEN or audience != TEST_AUDIENCE:
        raise ValueError("unexpected test token")
    return _verified_claims()


def _static_verifier(claims: Mapping[str, object]) -> TokenVerifier:
    def verifier(token: str, audience: str) -> Mapping[str, object]:
        return claims

    return verifier


def _private_application(
    role: Literal["app", "api"],
    *,
    verifier: TokenVerifier = _valid_verifier,
) -> EdgeApplication:
    return EdgeApplication(
        EdgeConfig(
            role=role,
            root=ROOT,
            expected_owner_email_sha256=TEST_DIGEST,
            iap_audience=TEST_AUDIENCE,
        ),
        token_verifier=verifier,
    )


def _private_headers(*, compatibility_email: str | None = None) -> Message:
    pairs = [(IAP_JWT_HEADER, TEST_TOKEN)]
    if compatibility_email is not None:
        pairs.append((IAP_EMAIL_HEADER, compatibility_email))
    return _headers(*pairs)


def _copy_public_data(destination: Path) -> None:
    (destination / "site" / "data").mkdir(parents=True)
    for relative in (
        "site/data/claims.json",
        "site/data/sources.json",
        "site/data/manifest.json",
        "VERSION",
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


class EdgeConfigurationTests(unittest.TestCase):
    def test_role_is_explicit_and_private_roles_require_a_digest(self) -> None:
        for environment in (
            {},
            {"EDGE_ROLE": ""},
            {"EDGE_ROLE": "site"},
            {"EDGE_ROLE": "APP"},
            {"EDGE_ROLE": "app"},
            {
                "EDGE_ROLE": "app",
                "EDGE_EXPECTED_OWNER_EMAIL_SHA256": TEST_DIGEST,
            },
            {
                "EDGE_ROLE": "app",
                "EDGE_EXPECTED_OWNER_EMAIL_SHA256": TEST_DIGEST,
                "K_SERVICE": "Invalid_Service",
            },
            {
                "EDGE_ROLE": "app",
                "EDGE_EXPECTED_OWNER_EMAIL_SHA256": TEST_DIGEST,
                "K_SERVICE": TEST_SERVICE,
            },
            {
                "EDGE_ROLE": "app",
                "EDGE_EXPECTED_OWNER_EMAIL_SHA256": TEST_DIGEST,
                "K_SERVICE": TEST_SERVICE,
                IAP_AUDIENCE_ENV: TEST_AUDIENCE + "-other",
            },
            {
                "EDGE_ROLE": "app",
                "EDGE_EXPECTED_OWNER_EMAIL_SHA256": TEST_DIGEST,
                "K_SERVICE": TEST_SERVICE,
                IAP_AUDIENCE_ENV: TEST_AUDIENCE.replace(
                    TEST_PROJECT_NUMBER, "not-numeric"
                ),
            },
            {"EDGE_ROLE": "api", "EDGE_EXPECTED_OWNER_EMAIL_SHA256": "A" * 64},
            {"EDGE_ROLE": "api", "EDGE_EXPECTED_OWNER_EMAIL_SHA256": "0" * 63},
        ):
            with self.subTest(environment=environment), self.assertRaises(EdgeConfigurationError):
                load_config(environment)

        verify = load_config({"EDGE_ROLE": "verify", "APP_ROOT": str(ROOT)})
        self.assertEqual(verify.role, "verify")
        self.assertIsNone(verify.expected_owner_email_sha256)
        app = load_config(
            {
                "EDGE_ROLE": "app",
                "APP_ROOT": str(ROOT),
                "EDGE_EXPECTED_OWNER_EMAIL_SHA256": TEST_DIGEST,
                "K_SERVICE": TEST_SERVICE,
                IAP_AUDIENCE_ENV: TEST_AUDIENCE,
            }
        )
        self.assertEqual(app.expected_owner_email_sha256, TEST_DIGEST)
        self.assertEqual(app.iap_audience, TEST_AUDIENCE)

    def test_owner_digest_is_canonical_and_rejects_malformed_addresses(self) -> None:
        self.assertEqual(owner_email_sha256("Owner@Example.Test"), TEST_DIGEST)
        for value in (
            "",
            " owner@example.test",
            "owner@example.test ",
            "owner",
            "owner@-example.test",
            ".owner@example.test",
            "owner..name@example.test",
            "owner@example..test",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                owner_email_sha256(value)


class EdgeAccessTests(unittest.TestCase):
    def test_app_and_api_require_one_verified_iap_jwt(self) -> None:
        valid = _private_headers()
        for role in ("app", "api"):
            application = _private_application(role)
            self.assertEqual(application.respond("GET", "/", valid).status, HTTPStatus.OK)
            for headers in (
                _headers(),
                _headers((IAP_EMAIL_HEADER, TEST_HEADER)),
                _headers((IAP_JWT_HEADER, "unsigned.payload.")),
                _headers((IAP_JWT_HEADER, "not-a-jwt")),
                _headers(
                    (IAP_JWT_HEADER, TEST_TOKEN),
                    (IAP_JWT_HEADER, TEST_TOKEN),
                ),
                _headers((IAP_EMAIL_HEADER, TEST_EMAIL)),
                _headers((IAP_EMAIL_HEADER, IAP_EMAIL_NAMESPACE + "other@example.test")),
                _headers((IAP_EMAIL_HEADER, TEST_HEADER + " ")),
            ):
                with self.subTest(role=role, headers=headers.items()):
                    response = application.respond("GET", "/", headers)
                    self.assertEqual(response.status, HTTPStatus.UNAUTHORIZED)
                    self.assertNotIn(TEST_EMAIL.encode(), response.body)
                    self.assertNotIn(TEST_DIGEST.encode(), response.body)

    def test_forged_token_or_invalid_verified_claims_fail_closed(self) -> None:
        def rejected_token(token: str, audience: str) -> Mapping[str, object]:
            raise ValueError("signature mismatch")

        forged = _private_application("app", verifier=rejected_token).respond(
            "GET",
            "/",
            _private_headers(compatibility_email=TEST_HEADER),
        )
        self.assertEqual(forged.status, HTTPStatus.UNAUTHORIZED)

        invalid_claims = (
            {"iss": "https://attacker.invalid"},
            {"aud": TEST_AUDIENCE + "-other"},
            {"sub": ""},
            {"sub": " subject-with-padding "},
            {"email": "other@example.test"},
            {"email": "not-an-email"},
        )
        for overrides in invalid_claims:
            with self.subTest(overrides=overrides):
                verifier = _static_verifier(_verified_claims(**overrides))
                response = _private_application("api", verifier=verifier).respond(
                    "GET",
                    "/",
                    _private_headers(),
                )
                self.assertEqual(response.status, HTTPStatus.UNAUTHORIZED)

    def test_compatibility_email_is_optional_but_must_match_when_present(self) -> None:
        application = _private_application("app")
        self.assertEqual(
            application.respond("GET", "/", _private_headers()).status,
            HTTPStatus.OK,
        )
        self.assertEqual(
            application.respond(
                "GET",
                "/",
                _private_headers(compatibility_email=TEST_HEADER),
            ).status,
            HTTPStatus.OK,
        )
        for compatibility_email in (
            TEST_EMAIL,
            IAP_EMAIL_NAMESPACE + "other@example.test",
            TEST_HEADER + " ",
        ):
            with self.subTest(compatibility_email=compatibility_email):
                self.assertEqual(
                    application.respond(
                        "GET",
                        "/",
                        _private_headers(compatibility_email=compatibility_email),
                    ).status,
                    HTTPStatus.UNAUTHORIZED,
                )

    def test_private_authentication_precedes_route_and_method_disclosure(self) -> None:
        application = _private_application("api")
        valid = _private_headers()
        self.assertEqual(
            application.respond("POST", "/", _headers()).status,
            HTTPStatus.UNAUTHORIZED,
        )
        self.assertEqual(
            application.respond("GET", "/missing", _headers()).status,
            HTTPStatus.UNAUTHORIZED,
        )
        method = application.respond("POST", "/", valid)
        self.assertEqual(method.status, HTTPStatus.METHOD_NOT_ALLOWED)
        self.assertIn(("Allow", "GET, HEAD"), method.headers)
        self.assertEqual(
            application.respond("GET", "/missing", valid).status,
            HTTPStatus.NOT_FOUND,
        )

    def test_private_responses_never_echo_the_authenticated_identity(self) -> None:
        valid = _private_headers(compatibility_email=TEST_HEADER)
        for role in ("app", "api"):
            response = _private_application(role).respond("GET", "/", valid)
            self.assertNotIn(TEST_EMAIL.encode(), response.body)
            self.assertNotIn(IAP_EMAIL_NAMESPACE.encode(), response.body)
            self.assertNotIn(TEST_DIGEST.encode(), response.body)
            self.assertNotIn(b"X-Goog", response.body)


class PublicVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.application = EdgeApplication(EdgeConfig("verify", ROOT, None))

    def test_public_routes_are_bounded_useful_and_do_not_require_identity(self) -> None:
        page = self.application.respond("GET", "/", _headers())
        status = self.application.respond("GET", "/status.json", _headers())
        claims = self.application.respond("GET", "/claims.json", _headers())
        health = self.application.respond("GET", "/healthz", _headers())

        self.assertEqual(page.status, HTTPStatus.OK)
        self.assertIn(b"ReMediaLHQ verification", page.body)
        self.assertIn(b"Claim manifest SHA-256", page.body)
        status_document = json.loads(status.body)
        claims_document = json.loads(claims.body)
        self.assertEqual(status_document["status"], "ok")
        self.assertEqual(status_document["claims"], 20)
        self.assertEqual(status_document["publishable_claims"], 20)
        self.assertEqual(status_document["sources"], 13)
        self.assertEqual(claims_document["claim_count"], 20)
        self.assertEqual(
            status_document["claim_manifest_sha256"],
            claims_document["claim_manifest_sha256"],
        )
        self.assertEqual(health.body, status.body)
        self.assertLess(len(claims.body), 131_072)

        combined = page.body + status.body + claims.body
        for prohibited in (b"@", b"gmail", b"owner_email", b"individual", b"sole proprietor"):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, combined.lower())

    def test_public_role_never_calls_the_private_token_verifier(self) -> None:
        def should_not_run(token: str, audience: str) -> Mapping[str, object]:
            raise AssertionError("public verifier called the IAP token verifier")

        application = EdgeApplication(
            EdgeConfig("verify", ROOT, None),
            token_verifier=should_not_run,
        )
        self.assertEqual(
            application.respond("GET", "/status.json", _headers()).status,
            HTTPStatus.OK,
        )

    def test_claim_manifest_exposes_only_reviewed_public_fields(self) -> None:
        response = self.application.respond("GET", "/claims.json", _headers())
        document = json.loads(response.body)
        self.assertEqual(
            set(document),
            {
                "schema_version",
                "service",
                "version",
                "claim_count",
                "claim_manifest_sha256",
                "claims_file_sha256",
                "claims",
            },
        )
        allowed_claim_fields = {
            "claim_id",
            "state",
            "public_wording",
            "source_ids",
            "observed_at",
            "sha256",
        }
        self.assertTrue(document["claims"])
        for claim in document["claims"]:
            self.assertEqual(set(claim), allowed_claim_fields)
            self.assertNotIn("entities", claim)
            self.assertNotIn("proposition", claim)

    def test_verifier_rejects_writes_unknown_paths_and_queries(self) -> None:
        method = self.application.respond("DELETE", "/claims.json", _headers())
        self.assertEqual(method.status, HTTPStatus.METHOD_NOT_ALLOWED)
        self.assertIn(("Allow", "GET, HEAD"), method.headers)
        self.assertEqual(
            self.application.respond("GET", "/missing", _headers()).status,
            HTTPStatus.NOT_FOUND,
        )
        for target in (
            "/status.json?full=true",
            "/%73tatus.json",
            "/../status.json",
            "//status.json",
            "/status.json#fragment",
            "/" + ("a" * 2_100),
        ):
            with self.subTest(target=target):
                self.assertNotEqual(
                    self.application.respond("GET", target, _headers()).status,
                    HTTPStatus.OK,
                )

    def test_request_header_and_body_bounds_reject_ambiguous_input(self) -> None:
        too_many = _headers(*tuple((f"X-Test-{index}", "1") for index in range(65)))
        self.assertEqual(
            self.application.respond("GET", "/", too_many).status,
            HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
        )
        for headers in (
            _headers(("Content-Length", "1")),
            _headers(("Content-Length", "1"), ("Content-Length", "1")),
            _headers(("Content-Length", "not-a-number")),
            _headers(("Content-Length", "20000")),
            _headers(("Transfer-Encoding", "chunked")),
        ):
            with self.subTest(headers=headers.items()):
                self.assertNotEqual(
                    self.application.respond("GET", "/", headers).status,
                    HTTPStatus.OK,
                )

    def test_security_headers_are_present_and_private_roles_are_not_indexable(self) -> None:
        verify = self.application.respond("GET", "/", _headers())
        verify_headers = dict(verify.headers)
        for name in (
            "Cache-Control",
            "Content-Security-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Permissions-Policy",
            "Referrer-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
        ):
            self.assertIn(name, verify_headers)
        self.assertNotIn("Access-Control-Allow-Origin", verify_headers)
        self.assertNotIn("X-Robots-Tag", verify_headers)

        private = _private_application("api").respond(
            "GET",
            "/",
            _private_headers(compatibility_email=TEST_HEADER),
        )
        self.assertEqual(dict(private.headers)["X-Robots-Tag"], "noindex, nofollow, noarchive")


class PublicVerifierDataTests(unittest.TestCase):
    def test_repository_public_snapshot_loads_deterministically(self) -> None:
        first = load_public_snapshot(ROOT)
        second = load_public_snapshot(ROOT)
        self.assertEqual(first, second)

    def test_rejects_manifest_drift_unknown_sources_and_email_addresses(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            _copy_public_data(root)
            manifest_path = root / "site/data/manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["claims"] += 1
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(PublicDataError, "manifest"):
                load_public_snapshot(root)

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            _copy_public_data(root)
            claims_path = root / "site/data/claims.json"
            claims = json.loads(claims_path.read_text(encoding="utf-8"))
            claims[0]["source_ids"] = ["SRC-UNKNOWN-0001"]
            claims_path.write_text(json.dumps(claims), encoding="utf-8")
            with self.assertRaisesRegex(PublicDataError, "unknown source"):
                load_public_snapshot(root)

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            _copy_public_data(root)
            claims_path = root / "site/data/claims.json"
            claims = json.loads(claims_path.read_text(encoding="utf-8"))
            claims[0]["public_wording"] = "Contact owner@example.test for the private record."
            claims_path.write_text(json.dumps(claims), encoding="utf-8")
            with self.assertRaisesRegex(PublicDataError, "email address"):
                load_public_snapshot(root)

    def test_rejects_duplicate_json_fields_and_excess_claims(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            _copy_public_data(root)
            (root / "site/data/manifest.json").write_text(
                '{"claims":22,"claims":22,"outputs":[],"publishable_claims":20,"sources":13}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PublicDataError, "duplicate JSON field"):
                load_public_snapshot(root)

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            _copy_public_data(root)
            claims_path = root / "site/data/claims.json"
            claim = json.loads(claims_path.read_text(encoding="utf-8"))[0]
            claims_path.write_text(
                json.dumps([claim] * (MAX_CLAIMS + 1)),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PublicDataError, "bounded"):
                load_public_snapshot(root)

    def test_rejects_symlinked_public_data(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            _copy_public_data(root)
            claims_path = root / "site/data/claims.json"
            original = root / "claims-original.json"
            claims_path.replace(original)
            try:
                claims_path.symlink_to(original)
            except OSError as exc:  # pragma: no cover - platform capability
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaisesRegex(PublicDataError, "symlinks"):
                load_public_snapshot(root)


class EdgeHTTPTests(unittest.TestCase):
    def test_http_head_has_get_length_without_a_body(self) -> None:
        application = EdgeApplication(EdgeConfig("verify", ROOT, None))
        server = EdgeHTTPServer(("127.0.0.1", 0), application)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = int(server.server_address[1])
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("GET", "/status.json")
            get_response = connection.getresponse()
            get_body = get_response.read()
            self.assertEqual(get_response.status, 200)
            self.assertEqual(int(get_response.getheader("Content-Length", "0")), len(get_body))
            self.assertEqual(get_response.getheader("X-Content-Type-Options"), "nosniff")
            connection.close()

            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("HEAD", "/status.json")
            head_response = connection.getresponse()
            head_body = head_response.read()
            self.assertEqual(head_response.status, 200)
            self.assertEqual(head_body, b"")
            self.assertEqual(
                int(head_response.getheader("Content-Length", "0")),
                len(get_body),
            )
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
