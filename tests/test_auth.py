from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

from remedialhq.auth import (
    DEFAULT_YOUTUBE_SCOPES,
    AuthorizationError,
    _normalize_scopes,
    _write_private_json,
    authorize_youtube,
    record_youtube_policy_acceptance,
    revoke_youtube_credentials,
    validate_youtube_policy_acceptance,
)
from remedialhq.cli import _accept_youtube_policies, _parser, _revoke_youtube

ROOT = Path(__file__).resolve().parents[1]


def _fixture_value(*parts: str) -> str:
    return "-".join(parts)


class AuthorizationHelpersTests(unittest.TestCase):
    def test_default_scopes_include_upload_and_read(self) -> None:
        scopes = _normalize_scopes(None)
        self.assertEqual(scopes, DEFAULT_YOUTUBE_SCOPES)
        self.assertTrue(any(scope.endswith("youtube.upload") for scope in scopes))

    def test_private_json_is_written_with_restricted_permissions(self) -> None:
        secure_temp = "/tmp" if os.name == "posix" and Path("/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(dir=secure_temp) as directory:
            path = Path(directory) / "token.json"
            _write_private_json(path, {"refresh_token": "placeholder"})
            self.assertEqual(json.loads(path.read_text())["refresh_token"], "placeholder")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_policy_acceptance_is_explicit_create_only_and_source_bound(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "acceptance.json"
            result = record_youtube_policy_acceptance(
                ROOT,
                path,
                accept_privacy=True,
                accept_terms=True,
                accepted_at=datetime(2026, 9, 2, 10, 0, tzinfo=UTC),
            )
            self.assertEqual(result["status"], "ACCEPTED")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["oauth_scopes"], list(DEFAULT_YOUTUBE_SCOPES))
            self.assertEqual(
                set(document["policies"]),
                {"privacy", "terms"},
            )
            for policy in document["policies"].values():
                self.assertTrue(policy["accepted"])
                self.assertRegex(policy["sha256"], r"^[0-9a-f]{64}$")
            validated = validate_youtube_policy_acceptance(
                path,
                repository_root=ROOT,
                now=datetime(2026, 9, 2, 10, 1, tzinfo=UTC),
            )
            self.assertEqual(validated["evidence_sha256"], result["evidence_sha256"])
            with self.assertRaisesRegex(AuthorizationError, "already exists"):
                record_youtube_policy_acceptance(
                    ROOT,
                    path,
                    accept_privacy=True,
                    accept_terms=True,
                )

    def test_policy_acceptance_rejects_partial_consent_and_repository_storage(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            output = Path(directory) / "acceptance.json"
            for privacy, terms in ((False, True), (True, False), (False, False)):
                with self.subTest(privacy=privacy, terms=terms), self.assertRaisesRegex(
                    AuthorizationError, "both Privacy Policy and Terms"
                ):
                    record_youtube_policy_acceptance(
                        ROOT,
                        output,
                        accept_privacy=privacy,
                        accept_terms=terms,
                    )
        with self.assertRaisesRegex(AuthorizationError, "outside the repository"):
            record_youtube_policy_acceptance(
                ROOT,
                ROOT / "local-private" / "acceptance.json",
                accept_privacy=True,
                accept_terms=True,
            )

    def test_policy_acceptance_rejects_tampering_scope_drift_and_future_time(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "acceptance.json"
            record_youtube_policy_acceptance(
                ROOT,
                path,
                accept_privacy=True,
                accept_terms=True,
                accepted_at=datetime(2026, 9, 2, 10, 0, tzinfo=UTC),
            )
            with self.assertRaisesRegex(AuthorizationError, "requested OAuth scopes"):
                validate_youtube_policy_acceptance(
                    path,
                    repository_root=ROOT,
                    scopes=("https://www.googleapis.com/auth/youtube.readonly",),
                    now=datetime(2026, 9, 2, 10, 1, tzinfo=UTC),
                )
            with self.assertRaisesRegex(AuthorizationError, "in the future"):
                validate_youtube_policy_acceptance(
                    path,
                    repository_root=ROOT,
                    now=datetime(2026, 9, 2, 9, 59, tzinfo=UTC),
                )
            document = json.loads(path.read_text(encoding="utf-8"))
            document["policies"]["terms"]["sha256"] = "0" * 64
            path.write_text(json.dumps(document), encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(AuthorizationError, "current policy sources"):
                validate_youtube_policy_acceptance(
                    path,
                    repository_root=ROOT,
                    now=datetime(2026, 9, 2, 10, 1, tzinfo=UTC),
                )

    def test_authorization_rejects_before_loading_google_without_acceptance(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "unavailable"):
            authorize_youtube(
                "missing-client.json",
                "/tmp/missing-token.json",
                policy_acceptance="/tmp/missing-acceptance.json",
                repository_root=ROOT,
            )

    def test_revocation_deletes_exact_local_token_and_writes_redacted_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            token_path = Path(directory) / "youtube-token.json"
            evidence_path = Path(directory) / "revocation.json"
            client_secret_value = _fixture_value("client", "secret")
            token_path.write_text(
                json.dumps(
                    {
                        "token": "access-secret",
                        "refresh_token": "refresh-secret",
                        "client_secret": client_secret_value,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(token_path, 0o600)
            revoked: list[str] = []
            result = revoke_youtube_credentials(
                token_path,
                evidence_path,
                repository_root=ROOT,
                confirm_revoke_and_delete=True,
                revoker=revoked.append,
                occurred_at=datetime(2026, 9, 2, 11, 0, tzinfo=UTC),
            )
            self.assertEqual(revoked, ["refresh-secret"])
            self.assertFalse(token_path.exists())
            self.assertEqual(result["status"], "REVOKED_LOCAL_CREDENTIAL_DELETED")
            self.assertEqual(evidence_path.stat().st_mode & 0o777, 0o600)
            evidence = evidence_path.read_text(encoding="utf-8")
            self.assertNotIn("access-secret", evidence)
            self.assertNotIn("refresh-secret", evidence)
            self.assertNotIn(client_secret_value, evidence)
            self.assertTrue(json.loads(evidence)["local_credential_deleted"])

    def test_revocation_fails_closed_before_deletion_or_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            token_path = Path(directory) / "youtube-token.json"
            evidence_path = Path(directory) / "revocation.json"
            token_path.write_text(
                json.dumps({"refresh_token": "refresh-secret"}),
                encoding="utf-8",
            )
            os.chmod(token_path, 0o600)
            calls: list[str] = []

            def reject(token: str) -> None:
                calls.append(token)
                raise RuntimeError("provider rejected revocation")

            with self.assertRaisesRegex(AuthorizationError, "revocation failed"):
                revoke_youtube_credentials(
                    token_path,
                    evidence_path,
                    repository_root=ROOT,
                    confirm_revoke_and_delete=True,
                    revoker=reject,
                )
            self.assertEqual(calls, ["refresh-secret"])
            self.assertTrue(token_path.is_file())
            self.assertFalse(evidence_path.exists())

            with self.assertRaisesRegex(AuthorizationError, "explicit"):
                revoke_youtube_credentials(
                    token_path,
                    evidence_path,
                    repository_root=ROOT,
                    confirm_revoke_and_delete=False,
                    revoker=calls.append,
                )
            self.assertEqual(calls, ["refresh-secret"])

    def test_policy_acceptance_and_revocation_cli_paths_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            private = Path(directory)
            acceptance = private / "acceptance.json"
            accept_args = _parser().parse_args(
                [
                    "auth",
                    "youtube-policy-acceptance",
                    "--repository-root",
                    str(ROOT),
                    "--output",
                    str(acceptance),
                    "--accept-privacy-policy",
                    "--accept-terms",
                ]
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(_accept_youtube_policies(accept_args), 0)
            self.assertTrue(acceptance.is_file())

            token_path = private / "youtube-token.json"
            evidence_path = private / "revocation.json"
            token_path.write_text(
                json.dumps({"refresh_token": "refresh-secret"}),
                encoding="utf-8",
            )
            os.chmod(token_path, 0o600)
            revoke_args = _parser().parse_args(
                [
                    "auth",
                    "youtube-revoke",
                    "--repository-root",
                    str(ROOT),
                    "--token-file",
                    str(token_path),
                    "--evidence-output",
                    str(evidence_path),
                    "--confirm-revoke-and-delete",
                ]
            )
            revoked: list[str] = []
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(_revoke_youtube(revoke_args, revoker=revoked.append), 0)
            self.assertEqual(revoked, ["refresh-secret"])
            self.assertFalse(token_path.exists())
            self.assertTrue(evidence_path.is_file())


if __name__ == "__main__":
    unittest.main()
