from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import urlsplit

from scripts.check_live_site import (
    CLOUDFLARE_CHALLENGE_MARKER,
    CLOUDFLARE_CHALLENGE_PREFIX,
    DEFAULT_BASE_URL,
    EXPECTED_SECURITY_HEADERS,
    LiveSiteReportError,
    _verified_body,
    attest_live_site,
    check_live_site,
    validate_live_site_report,
)
from scripts.stage_sites_deployment import ROOT


def _run_git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
    ).stdout


def _make_source_repository(parent: Path) -> Path:
    source = parent / "source"
    shutil.copytree(ROOT / "site", source / "site")
    (source / "infra/sites").mkdir(parents=True)
    for name in ("worker.ts", "vite-env.d.ts"):
        shutil.copy2(ROOT / f"infra/sites/{name}", source / f"infra/sites/{name}")
    _run_git(source, "init", "-q")
    _run_git(source, "config", "user.email", "test@example.invalid")
    _run_git(source, "config", "user.name", "Test")
    _run_git(source, "add", "site", "infra/sites")
    _run_git(source, "commit", "-q", "-m", "site fixture")
    return source


def _response(
    url: str,
    method: str,
    status: int,
    body: bytes,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    headers = dict(EXPECTED_SECURITY_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    return {
        "url": url,
        "method": method,
        "status": status,
        "headers": headers,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body": body,
    }


def _fake_requester(source: Path) -> Callable[..., dict[str, Any]]:
    def fake_request(url: str, *, method: str = "GET") -> dict[str, Any]:
        split = urlsplit(url)
        query = f"?{split.query}" if split.query else ""
        if method == "POST":
            return _response(
                url,
                method,
                405,
                b"Method Not Allowed",
                {"allow": "GET, HEAD", "cache-control": "no-store"},
            )
        if method == "HEAD":
            return _response(
                url,
                method,
                200,
                b"",
                {
                    "cache-control": "public, max-age=0, must-revalidate",
                    "content-type": "text/html; charset=utf-8",
                },
            )
        if split.path == "/creator-desk.html":
            return _response(
                url,
                method,
                308,
                b"",
                {
                    "cache-control": "public, max-age=3600",
                    "location": f"https://remedialhq.com/creator-desk{query}",
                },
            )
        if split.path == "/":
            return _response(
                url,
                method,
                200,
                (source / "site/index.html").read_bytes(),
                {
                    "cache-control": "public, max-age=0, must-revalidate",
                    "content-type": "text/html; charset=utf-8",
                },
            )
        if split.path == "/creator-desk":
            return _response(
                url,
                method,
                200,
                (source / "site/creator-desk.html").read_bytes(),
                {
                    "cache-control": "public, max-age=0, must-revalidate",
                    "content-type": "text/html; charset=utf-8",
                },
            )
        document = source / f"site/{split.path.lstrip('/')}.html"
        if document.is_file():
            return _response(
                url,
                method,
                200,
                document.read_bytes(),
                {
                    "cache-control": "public, max-age=0, must-revalidate",
                    "content-type": "text/html; charset=utf-8",
                },
            )
        asset = source / "site" / split.path.lstrip("/")
        if asset.is_file():
            return _response(url, method, 200, asset.read_bytes())
        return _response(
            url,
            method,
            404,
            (source / "site/404.html").read_bytes(),
            {"cache-control": "no-store", "content-type": "text/html; charset=utf-8"},
        )

    return fake_request


def _passing_report(source: Path, now: datetime) -> dict[str, Any]:
    with patch("scripts.check_live_site._request", side_effect=_fake_requester(source)):
        return check_live_site(DEFAULT_BASE_URL, root=source, now=now)


def _offline(_base_url: str, _root: Path, _now: datetime) -> dict[str, Any]:
    raise URLError("offline")


class LiveSiteTests(unittest.TestCase):
    def test_report_binds_exact_headers_content_digest_and_source(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            source = _make_source_repository(Path(directory))
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            report = _passing_report(source, now)

            verified = validate_live_site_report(report, root=source, now=now)

            self.assertEqual(verified["status"], "VERIFIED")
            self.assertEqual(
                verified["canonical_site_sha256"],
                report["source"]["canonical_site_sha256"],
            )
            expected_documents = len(list((source / "site").glob("*.html")))
            expected_assets = sum(
                path.is_file()
                and path.suffix.casefold() != ".html"
                and path.name not in {"_headers", "_redirects"}
                for path in (source / "site").rglob("*")
            )
            self.assertEqual(verified["documents_verified"], expected_documents)
            self.assertEqual(verified["assets_verified"], expected_assets)
            self.assertEqual(
                verified["deployable_files_verified"],
                expected_documents + expected_assets,
            )

    def test_managed_cloudflare_html_injection_is_normalized_only_to_exact_source(self) -> None:
        expected = b"<html><body>trusted</body></html>"
        injection = (
            CLOUDFLARE_CHALLENGE_PREFIX
            + b"window.__CF$cv$params={};"
            + CLOUDFLARE_CHALLENGE_MARKER
            + b"</script>"
        )
        observed = expected.replace(b"</body>", injection + b"</body>")

        normalized, transform = _verified_body(
            observed, expected, allow_managed_html=True
        )

        self.assertEqual(normalized, expected)
        self.assertEqual(transform, "cloudflare-managed-js-challenge")

    def test_report_uses_exact_latest_canonical_site_source_commit(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            source = _make_source_repository(Path(directory))
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            site_source_commit = _run_git(source, "rev-parse", "HEAD").decode().strip()
            (source / "README.md").write_text("report-only commit\n", encoding="utf-8")
            _run_git(source, "add", "README.md")
            _run_git(source, "commit", "-q", "-m", "record report")
            report = _passing_report(source, now)

            verified = validate_live_site_report(report, root=source, now=now)

            self.assertNotEqual(verified["source_commit"], verified["current_commit"])
            self.assertEqual(verified["source_commit"], site_source_commit)
            self.assertEqual(verified["status"], "VERIFIED")

    def test_every_exact_security_header_policy_value_is_required(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            source = _make_source_repository(Path(directory))
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            requester = _fake_requester(source)

            for header_name, expected_value in EXPECTED_SECURITY_HEADERS.items():
                with self.subTest(header_name=header_name):
                    def wrong_header(
                        url: str,
                        *,
                        method: str = "GET",
                        changed_header: str = header_name,
                        changed_value: str = expected_value,
                    ) -> dict[str, Any]:
                        result = requester(url, method=method)
                        result["headers"][changed_header] = f"{changed_value} changed"
                        return result

                    with (
                        patch(
                            "scripts.check_live_site._request",
                            side_effect=wrong_header,
                        ),
                        self.assertRaisesRegex(
                            ValueError, "incorrect effective security"
                        ),
                    ):
                        check_live_site(DEFAULT_BASE_URL, root=source, now=now)

    def test_static_assets_can_use_provider_managed_headers(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            source = _make_source_repository(Path(directory))
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            requester = _fake_requester(source)

            def provider_asset_headers(
                url: str,
                *,
                method: str = "GET",
            ) -> dict[str, Any]:
                result = requester(url, method=method)
                if urlsplit(url).path == "/app.js":
                    for header_name in EXPECTED_SECURITY_HEADERS:
                        result["headers"].pop(header_name, None)
                return result

            with patch(
                "scripts.check_live_site._request",
                side_effect=provider_asset_headers,
            ):
                report = check_live_site(DEFAULT_BASE_URL, root=source, now=now)

            self.assertGreater(
                report["content_coverage"]["assets_verified"],
                0,
            )

    def test_missing_cached_report_is_unverified_when_network_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            result = attest_live_site(
                temporary_root / "missing.json",
                root=source,
                now=datetime(2026, 8, 29, 20, 0, tzinfo=UTC),
                live_check=_offline,
            )
            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertEqual(result["reason_code"], "missing_report")

    def test_stale_cached_report_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            report_path = temporary_root / "report.json"
            report_path.write_text(
                json.dumps(_passing_report(source, now - timedelta(hours=25))),
                encoding="utf-8",
            )

            result = attest_live_site(
                report_path,
                root=source,
                now=now,
                live_check=_offline,
            )

            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertEqual(result["reason_code"], "stale_report")

    def test_site_hash_mismatched_cached_report_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            report = _passing_report(source, now)
            report["source"]["canonical_site_sha256"] = "0" * 64
            report_path = temporary_root / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            result = attest_live_site(
                report_path,
                root=source,
                now=now,
                live_check=_offline,
            )

            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertEqual(result["reason_code"], "source_mismatch")

    def test_commit_mismatched_cached_report_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            report = _passing_report(source, now)
            (source / "README.md").write_text("evidence commit\n", encoding="utf-8")
            _run_git(source, "add", "README.md")
            _run_git(source, "commit", "-q", "-m", "record evidence")
            report["source"]["source_commit"] = (
                _run_git(source, "rev-parse", "HEAD").decode().strip()
            )
            report_path = temporary_root / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            result = attest_live_site(
                report_path,
                root=source,
                now=now,
                live_check=_offline,
            )

            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertEqual(result["reason_code"], "source_mismatch")

    def test_failing_cached_report_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            report = _passing_report(source, now)
            report["status"] = "FAIL"
            report_path = temporary_root / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            result = attest_live_site(
                report_path,
                root=source,
                now=now,
                live_check=_offline,
            )

            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertEqual(result["reason_code"], "failing_report")

    def test_reachable_failed_check_does_not_fall_back_to_cached_pass(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            now = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
            report_path = temporary_root / "report.json"
            report_path.write_text(
                json.dumps(_passing_report(source, now)), encoding="utf-8"
            )

            def failing_check(
                _base_url: str, _root: Path, _now: datetime
            ) -> dict[str, Any]:
                raise ValueError("effective header mismatch")

            result = attest_live_site(
                report_path,
                root=source,
                now=now,
                live_check=failing_check,
            )

            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertEqual(result["reason_code"], "live_check_failed")
            self.assertEqual(result["network_status"], "REACHABLE_BUT_FAILED")

    def test_report_output_symlink_is_rejected_before_write(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            real_report = temporary_root / "real-report.json"
            real_report.write_text("sentinel\n", encoding="utf-8")
            linked_report = temporary_root / "linked-report.json"
            linked_report.symlink_to(real_report)

            result = attest_live_site(
                linked_report,
                root=source,
                now=datetime(2026, 8, 29, 20, 0, tzinfo=UTC),
                live_check=_offline,
            )

            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertEqual(result["reason_code"], "unsafe_report_path")
            self.assertEqual(real_report.read_text(encoding="utf-8"), "sentinel\n")

    def test_dirty_source_is_unverified_before_network_check(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            temporary_root = Path(directory)
            source = _make_source_repository(temporary_root)
            with (source / "site/app.js").open("a", encoding="utf-8") as handle:
                handle.write("\n// dirty\n")

            result = attest_live_site(
                temporary_root / "report.json",
                root=source,
                now=datetime(2026, 8, 29, 20, 0, tzinfo=UTC),
                live_check=_offline,
            )

            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertEqual(result["reason_code"], "source_state_invalid")
            self.assertEqual(result["network_status"], "NOT_ATTEMPTED")

    def test_invalid_report_raises_typed_failure(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            source = _make_source_repository(Path(directory))
            with self.assertRaises(LiveSiteReportError) as caught:
                validate_live_site_report(
                    {},
                    root=source,
                    now=datetime(2026, 8, 29, 20, 0, tzinfo=UTC),
                )
            self.assertEqual(caught.exception.code, "invalid_report")


if __name__ == "__main__":
    unittest.main()
