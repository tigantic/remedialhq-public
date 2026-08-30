#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, MutableMapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.stage_sites_deployment import (
    HOSTING_CONTROL_FILES,
    SOURCE_PATHSPECS,
    CanonicalSiteSnapshot,
    canonical_site_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_URL = "https://remedialhq.com"
DEFAULT_MAX_REPORT_AGE = timedelta(hours=24)
MAX_FUTURE_SKEW = timedelta(minutes=5)
EXPECTED_SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'self' mailto:; "
        "upgrade-insecure-requests"
    ),
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "referrer-policy": "strict-origin-when-cross-origin",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}
RECORDED_HEADERS = (
    "allow",
    "cache-control",
    "content-security-policy",
    "content-type",
    "cross-origin-opener-policy",
    "location",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
)

LiveCheck = Callable[[str, Path, datetime], dict[str, Any]]
CLOUDFLARE_CHALLENGE_PREFIX = (
    b"<script>(function(){function c(){var b=a.contentDocument||"
    b"(a.contentWindow&&a.contentWindow.document);"
)
CLOUDFLARE_CHALLENGE_MARKER = b"/cdn-cgi/challenge-platform/scripts/jsd/main.js"


class LiveSiteReportError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _request(url: str, *, method: str = "GET") -> dict[str, Any]:
    request = Request(
        url,
        data=b"" if method == "POST" else None,
        method=method,
        headers={"User-Agent": "ReMediaLHQ-Release-Verification/0.4"},
    )
    opener = build_opener(_NoRedirect())
    try:
        response = opener.open(request, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        body = response.read()
        headers: dict[str, str] = {}
        for name in RECORDED_HEADERS:
            values = response.headers.get_all(name)
            if values:
                headers[name] = ", ".join(values)
        return {
            "url": url,
            "method": method,
            "status": response.status,
            "headers": headers,
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body": body,
        }


def _mapping(value: object, label: str) -> MutableMapping[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value


def _require_security_headers(result: Mapping[str, Any]) -> None:
    headers = _mapping(result.get("headers"), "response headers")
    mismatched = [
        name
        for name, expected in EXPECTED_SECURITY_HEADERS.items()
        if headers.get(name) != expected
    ]
    if mismatched:
        method = result.get("method", "request")
        url = result.get("url", "unknown URL")
        raise ValueError(
            f"{method} {url} has incorrect effective security headers: {mismatched}"
        )


def _verified_body(body: bytes, expected: bytes, *, allow_managed_html: bool) -> tuple[bytes, str]:
    if body == expected:
        return body, "none"
    if allow_managed_html:
        start = body.find(CLOUDFLARE_CHALLENGE_PREFIX)
        if start >= 0 and body.find(CLOUDFLARE_CHALLENGE_PREFIX, start + 1) < 0:
            end = body.find(b"</script>", start)
            if end >= 0:
                end += len(b"</script>")
                injected = body[start:end]
                candidate = body[:start] + body[end:]
                if (
                    candidate == expected
                    and CLOUDFLARE_CHALLENGE_MARKER in injected
                    and len(injected) <= 4096
                ):
                    return candidate, "cloudflare-managed-js-challenge"
    raise ValueError("response body does not match canonical content")


def _require_body(
    result: MutableMapping[str, Any],
    expected: bytes,
    label: str,
    *,
    allow_managed_html: bool = False,
) -> None:
    expected_sha256 = hashlib.sha256(expected).hexdigest()
    body = result.get("body")
    if isinstance(body, bytes):
        try:
            verified, transform = _verified_body(
                body, expected, allow_managed_html=allow_managed_html
            )
        except ValueError as exc:
            raise ValueError(f"{label} body does not match canonical content") from exc
        result["verified_body_bytes"] = len(verified)
        result["verified_body_sha256"] = hashlib.sha256(verified).hexdigest()
        result["content_transform"] = transform
    if result.get("verified_body_bytes") != len(expected):
        raise ValueError(f"{label} verified body length does not match canonical content")
    if result.get("verified_body_sha256") != expected_sha256:
        raise ValueError(f"{label} verified body hash does not match canonical content")
    transform_value = result.get("content_transform")
    allowed_transforms = (
        {"none", "cloudflare-managed-js-challenge"}
        if allow_managed_html
        else {"none"}
    )
    if transform_value not in allowed_transforms:
        raise ValueError(f"{label} content transform is not allowed")


def _validate_cases(
    cases_value: object,
    *,
    apex_origin: str,
) -> None:
    cases = _mapping(cases_value, "live checks")
    required_cases = {
        "root",
        "clean_route",
        "legacy_html",
        "www_legacy_html",
        "missing_route",
        "head",
        "post",
    }
    missing_cases = sorted(required_cases - set(cases))
    if missing_cases:
        raise ValueError(f"live report is missing checks: {missing_cases}")
    checked = {name: _mapping(cases[name], f"{name} check") for name in required_cases}
    for case in checked.values():
        _require_security_headers(case)

    root = checked["root"]
    clean = checked["clean_route"]
    missing = checked["missing_route"]
    if root.get("status") != 200:
        raise ValueError("live root page did not return 200")
    if clean.get("status") != 200:
        raise ValueError("live clean route did not return 200")
    if missing.get("status") != 404:
        raise ValueError("missing route did not return 404")
    root_url = urlsplit(str(root.get("url", "")))
    if f"{root_url.scheme}://{root_url.netloc}" != apex_origin or root_url.path != "/":
        raise ValueError("root check URL does not match the canonical origin")
    if not root_url.query.startswith("verification="):
        raise ValueError("root check URL has no verification marker")
    suffix = f"?{root_url.query}" if root_url.query else ""
    expected_location = f"{apex_origin}/creator-desk{suffix}"
    expected_requests = {
        "root": ("GET", f"{apex_origin}/{suffix}"),
        "clean_route": ("GET", expected_location),
        "legacy_html": ("GET", f"{apex_origin}/creator-desk.html{suffix}"),
        "www_legacy_html": (
            "GET",
            f"https://www.{urlsplit(apex_origin).hostname}/creator-desk.html{suffix}",
        ),
        "head": ("HEAD", expected_location),
        "post": ("POST", expected_location),
    }
    for name, (method, url) in expected_requests.items():
        if checked[name].get("method") != method or checked[name].get("url") != url:
            raise ValueError(f"{name} request identity does not match the verification run")
    missing_url = urlsplit(str(missing.get("url", "")))
    if (
        missing.get("method") != "GET"
        or f"{missing_url.scheme}://{missing_url.netloc}" != apex_origin
        or not missing_url.path.startswith("/missing-")
        or missing_url.query
    ):
        raise ValueError("missing-route request identity does not match the verification run")
    for name in ("legacy_html", "www_legacy_html"):
        case = checked[name]
        headers = _mapping(case.get("headers"), f"{name} headers")
        if case.get("status") != 308 or headers.get("location") != expected_location:
            raise ValueError(f"{name} did not return the canonical permanent redirect")
        _require_body(case, b"", name)

    head = checked["head"]
    if head.get("status") != 200 or head.get("body_bytes") != 0:
        raise ValueError("HEAD route did not return an empty 200 response")
    _require_body(head, b"", "HEAD")
    post = checked["post"]
    post_headers = _mapping(post.get("headers"), "POST headers")
    if post.get("status") != 405 or post_headers.get("allow") != "GET, HEAD":
        raise ValueError("POST route did not return the read-only method policy")
    _require_body(post, b"Method Not Allowed", "POST")

    expected_cache = {
        "root": "public, max-age=0, must-revalidate",
        "clean_route": "public, max-age=0, must-revalidate",
        "legacy_html": "public, max-age=3600",
        "www_legacy_html": "public, max-age=3600",
        "missing_route": "no-store",
        "head": "public, max-age=0, must-revalidate",
        "post": "no-store",
    }
    for name, expected in expected_cache.items():
        headers = _mapping(checked[name].get("headers"), f"{name} headers")
        if headers.get("cache-control") != expected:
            raise ValueError(f"{name} returned an incorrect cache policy")


def _deployable_content(
    snapshot: CanonicalSiteSnapshot,
) -> tuple[dict[Path, bytes], dict[Path, bytes]]:
    site_root = Path("site")
    site_files = {
        path: content
        for path, content in snapshot.files.items()
        if path.is_relative_to(site_root)
    }
    documents = {
        path: content
        for path, content in site_files.items()
        if path.suffix.casefold() == ".html"
    }
    assets = {
        path: content
        for path, content in site_files.items()
        if path.suffix.casefold() != ".html"
        and path.relative_to(site_root) not in HOSTING_CONTROL_FILES
    }
    return documents, assets


def _validate_content_coverage(
    checks_value: object,
    *,
    apex_origin: str,
    verification_query: str,
    snapshot: CanonicalSiteSnapshot,
) -> dict[str, Any]:
    checks = _mapping(checks_value, "content checks")
    documents, assets = _deployable_content(snapshot)
    expected_paths = set(documents) | set(assets)
    if set(checks) != {path.as_posix() for path in expected_paths}:
        raise ValueError("content checks do not cover the exact deployable source set")

    transform_counts: dict[str, int] = {}
    for path in sorted(expected_paths, key=lambda item: item.as_posix()):
        name = path.as_posix()
        case = _mapping(checks[name], f"{name} content check")
        relative = path.relative_to(Path("site"))
        is_html = path in documents
        if relative == Path("index.html"):
            expected_url = f"{apex_origin}/?{verification_query}"
            expected_status = 200
        elif relative == Path("404.html"):
            expected_url = str(case.get("url", ""))
            expected_status = 404
            missing_url = urlsplit(expected_url)
            if (
                f"{missing_url.scheme}://{missing_url.netloc}" != apex_origin
                or not missing_url.path.startswith("/missing-")
                or missing_url.query
            ):
                raise ValueError("404 content check does not use the missing-route request")
        elif is_html:
            expected_url = f"{apex_origin}/{relative.stem}?{verification_query}"
            expected_status = 200
        else:
            expected_url = f"{apex_origin}/{relative.as_posix()}?{verification_query}"
            expected_status = 200
        if (
            case.get("method") != "GET"
            or case.get("url") != expected_url
            or case.get("status") != expected_status
        ):
            raise ValueError(f"{name} content check has an incorrect request or status")
        if is_html:
            _require_security_headers(case)
        _require_body(
            case,
            snapshot.files[path],
            name,
            allow_managed_html=is_html,
        )
        transform = str(case["content_transform"])
        transform_counts[transform] = transform_counts.get(transform, 0) + 1
    return {
        "status": "PASS",
        "documents_verified": len(documents),
        "assets_verified": len(assets),
        "deployable_files_verified": len(expected_paths),
        "worker_policy_checks": 7,
        "excluded_hosting_controls": sorted(
            f"site/{path.as_posix()}" for path in HOSTING_CONTROL_FILES
        ),
        "content_transforms": dict(sorted(transform_counts.items())),
    }


def _normalized_origin(base_url: str) -> tuple[str, str]:
    normalized_base = base_url.rstrip("/")
    split = urlsplit(normalized_base)
    if (
        split.scheme != "https"
        or not split.hostname
        or split.path
        or split.query
        or split.fragment
        or split.username
        or split.password
    ):
        raise ValueError("base URL must be an HTTPS origin without a path")
    return f"{split.scheme}://{split.netloc}", split.hostname


def check_live_site(
    base_url: str,
    *,
    root: str | Path = ROOT,
    now: datetime | None = None,
) -> dict[str, Any]:
    apex_origin, hostname = _normalized_origin(base_url)
    source_root = Path(root).resolve()
    snapshot = canonical_site_snapshot(source_root)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("verification time must include a timezone")
    generated_at = current.astimezone(UTC).replace(microsecond=0)
    marker = generated_at.isoformat().replace("+00:00", "Z").replace(":", "")
    query = f"verification={marker}"
    www_origin = f"https://www.{hostname}"

    cases = {
        "root": _request(f"{apex_origin}/?{query}"),
        "clean_route": _request(f"{apex_origin}/creator-desk?{query}"),
        "legacy_html": _request(f"{apex_origin}/creator-desk.html?{query}"),
        "www_legacy_html": _request(f"{www_origin}/creator-desk.html?{query}"),
        "missing_route": _request(f"{apex_origin}/missing-{marker}"),
        "head": _request(f"{apex_origin}/creator-desk?{query}", method="HEAD"),
        "post": _request(f"{apex_origin}/creator-desk?{query}", method="POST"),
    }
    _validate_cases(cases, apex_origin=apex_origin)

    documents, assets = _deployable_content(snapshot)
    content_cases: dict[str, dict[str, Any]] = {}
    for path in sorted(documents, key=lambda item: item.as_posix()):
        relative = path.relative_to(Path("site"))
        if relative == Path("index.html"):
            case = cases["root"]
        elif relative == Path("404.html"):
            case = cases["missing_route"]
        elif relative == Path("creator-desk.html"):
            case = cases["clean_route"]
        else:
            case = _request(f"{apex_origin}/{relative.stem}?{query}")
        content_cases[path.as_posix()] = case
    for path in sorted(assets, key=lambda item: item.as_posix()):
        relative = path.relative_to(Path("site"))
        content_cases[path.as_posix()] = _request(
            f"{apex_origin}/{relative.as_posix()}?{query}"
        )
    content_coverage = _validate_content_coverage(
        content_cases,
        apex_origin=apex_origin,
        verification_query=query,
        snapshot=snapshot,
    )

    public_cases = {
        name: {key: value for key, value in case.items() if key != "body"}
        for name, case in cases.items()
    }
    public_content_cases = {
        name: {key: value for key, value in case.items() if key != "body"}
        for name, case in content_cases.items()
    }
    return {
        "schema_version": 2,
        "status": "PASS",
        "generated_at": generated_at.isoformat(),
        "base_url": apex_origin,
        "source": {
            "source_commit": _canonical_site_source_commit(source_root),
            "canonical_site_sha256": snapshot.sha256,
            "canonical_site_files": len(snapshot.files),
        },
        "checks": public_cases,
        "content_checks": public_content_cases,
        "content_coverage": content_coverage,
    }


def _canonical_site_source_commit(root: Path) -> str:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "rev-list",
            "-1",
            "HEAD",
            "--",
            *(path.as_posix() for path in SOURCE_PATHSPECS),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    source_commit = completed.stdout.strip()
    if (
        completed.returncode != 0
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source_commit) is None
    ):
        detail = completed.stderr.strip()
        raise ValueError(
            "canonical site source commit could not be resolved"
            + (f": {detail}" if detail else "")
        )
    return source_commit


def validate_live_site_report(
    report_value: object,
    *,
    root: str | Path = ROOT,
    now: datetime | None = None,
    max_age: timedelta = DEFAULT_MAX_REPORT_AGE,
    expected_base_url: str = DEFAULT_BASE_URL,
) -> dict[str, Any]:
    try:
        report = _mapping(report_value, "live-site report")
        if report.get("schema_version") != 2:
            raise LiveSiteReportError("invalid_report", "live-site report schema is not current")
        if report.get("status") != "PASS":
            raise LiveSiteReportError("failing_report", "live-site report is not passing")
        expected_origin, _ = _normalized_origin(expected_base_url)
        if report.get("base_url") != expected_origin:
            raise LiveSiteReportError("invalid_report", "live-site report origin does not match")

        generated_value = report.get("generated_at")
        if not isinstance(generated_value, str):
            raise LiveSiteReportError("invalid_report", "live-site report has no timestamp")
        generated_at = datetime.fromisoformat(generated_value)
        if generated_at.tzinfo is None:
            raise LiveSiteReportError("invalid_report", "live-site timestamp has no timezone")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        generated_at = generated_at.astimezone(UTC)
        if generated_at - current > MAX_FUTURE_SKEW:
            raise LiveSiteReportError("stale_report", "live-site report is dated in the future")
        if current - generated_at > max_age:
            raise LiveSiteReportError("stale_report", "live-site report is stale")

        source_root = Path(root).resolve()
        snapshot = canonical_site_snapshot(source_root)
        expected_source_commit = _canonical_site_source_commit(source_root)
        source = _mapping(report.get("source"), "live-site source binding")
        source_commit = source.get("source_commit")
        if source_commit != expected_source_commit:
            raise LiveSiteReportError(
                "source_mismatch",
                "live-site source commit is not the exact canonical site source commit",
            )
        if source.get("canonical_site_sha256") != snapshot.sha256:
            raise LiveSiteReportError(
                "source_mismatch", "live-site canonical source digest does not match"
            )
        if source.get("canonical_site_files") != len(snapshot.files):
            raise LiveSiteReportError(
                "source_mismatch", "live-site canonical source file count does not match"
            )
        report_checks = _mapping(report.get("checks"), "live checks")
        _validate_cases(report_checks, apex_origin=expected_origin)
        root_check = _mapping(report_checks.get("root"), "root check")
        verification_query = urlsplit(str(root_check.get("url", ""))).query
        coverage = _validate_content_coverage(
            report.get("content_checks"),
            apex_origin=expected_origin,
            verification_query=verification_query,
            snapshot=snapshot,
        )
        if report.get("content_coverage") != coverage:
            raise LiveSiteReportError(
                "invalid_report", "live-site content coverage summary does not match"
            )
    except LiveSiteReportError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveSiteReportError("invalid_report", str(exc)) from exc
    return {
        "status": "VERIFIED",
        "generated_at": generated_at.isoformat(),
        "source_commit": source_commit,
        "current_commit": snapshot.commit,
        "canonical_site_sha256": snapshot.sha256,
        "canonical_site_files": len(snapshot.files),
        "deployable_files_verified": coverage["deployable_files_verified"],
        "documents_verified": coverage["documents_verified"],
        "assets_verified": coverage["assets_verified"],
        "max_age_hours": max_age.total_seconds() / 3600,
    }


def _default_live_check(base_url: str, root: Path, now: datetime) -> dict[str, Any]:
    return check_live_site(base_url, root=root, now=now)


def _unverified(
    code: str,
    detail: str,
    report_path: str,
    *,
    network_status: str,
) -> dict[str, Any]:
    return {
        "status": "UNVERIFIED",
        "reason_code": code,
        "detail": detail,
        "network_status": network_status,
        "report_path": report_path,
    }


def _unresolved_absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _display_path(path: Path, root: Path) -> str:
    if path.is_relative_to(root):
        return path.relative_to(root).as_posix()
    return str(path)


def attest_live_site(
    report_path: str | Path,
    *,
    base_url: str = DEFAULT_BASE_URL,
    root: str | Path = ROOT,
    now: datetime | None = None,
    max_age: timedelta = DEFAULT_MAX_REPORT_AGE,
    live_check: LiveCheck | None = None,
) -> dict[str, Any]:
    output = _unresolved_absolute(report_path)
    source_root = Path(root).resolve()
    report_label = _display_path(output, source_root)
    if output.is_symlink():
        return _unverified(
            "unsafe_report_path",
            "live-site report path must not be a symbolic link",
            report_label,
            network_status="NOT_ATTEMPTED",
        )
    current = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    try:
        canonical_site_snapshot(source_root)
    except (OSError, ValueError) as exc:
        return _unverified(
            "source_state_invalid",
            str(exc),
            report_label,
            network_status="NOT_ATTEMPTED",
        )
    checker = live_check or _default_live_check
    try:
        live_report = checker(base_url, source_root, current)
    except (URLError, TimeoutError, ConnectionError) as exc:
        network_detail = str(exc)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return _unverified(
            "live_check_failed",
            str(exc),
            report_label,
            network_status="REACHABLE_BUT_FAILED",
        )
    else:
        try:
            verified = validate_live_site_report(
                live_report,
                root=source_root,
                now=current,
                max_age=max_age,
                expected_base_url=base_url,
            )
        except LiveSiteReportError as exc:
            return _unverified(
                exc.code,
                str(exc),
                report_label,
                network_status="REACHABLE_BUT_FAILED",
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(live_report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {
            **verified,
            "verification_mode": "live",
            "network_status": "REACHABLE",
            "report_path": report_label,
        }

    if not output.is_file() or output.is_symlink():
        return _unverified(
            "missing_report",
            f"network unavailable and no safe live-site report exists: {network_detail}",
            report_label,
            network_status="UNAVAILABLE",
        )
    try:
        cached: object = json.loads(output.read_text(encoding="utf-8"))
        verified = validate_live_site_report(
            cached,
            root=source_root,
            now=current,
            max_age=max_age,
            expected_base_url=base_url,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _unverified(
            "invalid_report",
            str(exc),
            report_label,
            network_status="UNAVAILABLE",
        )
    except LiveSiteReportError as exc:
        return _unverified(
            exc.code,
            str(exc),
            report_label,
            network_status="UNAVAILABLE",
        )
    return {
        **verified,
        "verification_mode": "cached_report",
        "network_status": "UNAVAILABLE",
        "network_detail": network_detail,
        "report_path": report_label,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="verify the live ReMediaLHQ site policy")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = check_live_site(args.base_url)
    output = _unresolved_absolute(args.output)
    if output.is_symlink():
        raise ValueError("live-site report path must not be a symbolic link")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
