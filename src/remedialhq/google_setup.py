from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

PROJECT_ID_PLACEHOLDER = "<owner-private-project-id>"
DOMAIN = "remedialhq.com"
SEARCH_CONSOLE_PROPERTY = f"sc-domain:{DOMAIN}"
SITEMAP_URL = f"https://{DOMAIN}/sitemap.xml"
ANALYTICS_ACCOUNT_NAME = "ReMediaLHQ"
ANALYTICS_PROPERTY_NAME = "ReMediaLHQ Production"
ANALYTICS_STREAM_NAME = "ReMediaLHQ Website"
ANALYTICS_DEFAULT_URI = f"https://{DOMAIN}"
ANALYTICS_TIME_ZONE = "America/New_York"
ANALYTICS_CURRENCY = "USD"
TAG_MANAGER_ACCOUNT_NAME = "ReMediaLHQ"
TAG_MANAGER_CONTAINER_NAME = "ReMediaLHQ Website"
TAG_MANAGER_USAGE_CONTEXT = "web"

OWNER_EMAIL_SCOPE = "https://www.googleapis.com/auth/userinfo.email"
SITE_VERIFICATION_SCOPE = "https://www.googleapis.com/auth/siteverification"
SEARCH_CONSOLE_SCOPE = "https://www.googleapis.com/auth/webmasters"
ANALYTICS_EDIT_SCOPE = "https://www.googleapis.com/auth/analytics.edit"
TAG_MANAGER_EDIT_SCOPE = (
    "https://www.googleapis.com/auth/tagmanager.edit.containers"
)
REQUIRED_SCOPES = (
    OWNER_EMAIL_SCOPE,
    SITE_VERIFICATION_SCOPE,
    SEARCH_CONSOLE_SCOPE,
    ANALYTICS_EDIT_SCOPE,
    TAG_MANAGER_EDIT_SCOPE,
)

SCHEMA_VERSION = 1
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


class GoogleSetupError(RuntimeError):
    """Raised when the guarded Google setup cannot continue safely."""


class GoogleSetupTransport(Protocol):
    def owner_identity(self) -> Mapping[str, object]: ...

    def search_console_sites(self) -> Sequence[Mapping[str, object]]: ...

    def site_verifications(self) -> Sequence[Mapping[str, object]]: ...

    def search_console_sitemaps(
        self, site_url: str
    ) -> Sequence[Mapping[str, object]]: ...

    def analytics_accounts(self) -> Sequence[Mapping[str, object]]: ...

    def analytics_properties(
        self, account_name: str
    ) -> Sequence[Mapping[str, object]]: ...

    def analytics_streams(
        self, property_name: str
    ) -> Sequence[Mapping[str, object]]: ...

    def tag_manager_accounts(self) -> Sequence[Mapping[str, object]]: ...

    def tag_manager_containers(
        self, account_path: str
    ) -> Sequence[Mapping[str, object]]: ...

    def verify_search_domain(self) -> None: ...

    def add_search_console_property(self) -> None: ...

    def submit_search_console_sitemap(self) -> None: ...

    def create_analytics_property(self, account_name: str) -> None: ...

    def create_analytics_stream(self, property_name: str) -> None: ...

    def create_tag_manager_container(self, account_path: str) -> None: ...


def owner_account_sha256(email: str) -> str:
    normalized = email.strip().casefold()
    if not normalized or "@" not in normalized:
        raise GoogleSetupError("owner email is invalid")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def build_plan(project_id: str | None = None) -> dict[str, object]:
    """Return the deterministic offline plan without loading credentials or using a network."""
    target_project_id = (
        PROJECT_ID_PLACEHOLDER
        if project_id is None
        else validate_project_id(project_id)
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "PLAN_ONLY",
        "network_used": False,
        "mutation_authorized": False,
        "status": "PLANNED",
        "targets": _targets(target_project_id),
        "required_scopes": list(REQUIRED_SCOPES),
        "operations": [
            {
                "task_id": "RMH-053",
                "steps": [
                    "inspect site verification and Search Console property",
                    "verify the existing DNS token when needed",
                    "create the exact domain property when absent",
                    "submit the exact sitemap when absent",
                ],
            },
            {
                "task_id": "RMH-055",
                "steps": [
                    "select one existing exact-name Analytics account",
                    "create the exact GA4 property when absent",
                    "create the exact web stream when absent",
                ],
            },
            {
                "task_id": "RMH-056",
                "steps": [
                    "select one existing exact-name Tag Manager account",
                    "create the exact web container when absent",
                ],
            },
        ],
        "prohibitions": [
            "no Google Analytics account creation",
            "no Google Tag Manager account creation",
            "no terms acceptance",
            "no credential persistence or raw API response retention",
        ],
    }


def run_google_setup(
    transport: GoogleSetupTransport,
    *,
    project_id: str,
    owner_account_digest: str,
    apply_live: bool,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Inspect exact targets and optionally apply only the bounded idempotent mutations."""
    if not _SHA256_PATTERN.fullmatch(owner_account_digest):
        raise GoogleSetupError("--owner-account-sha256 must be a lowercase SHA-256 digest")
    target_project_id = validate_project_id(project_id)
    now = clock or (lambda: datetime.now(UTC))
    mutations: list[str] = []
    try:
        identity = transport.owner_identity()
        email = _required_text(identity, "email", "owner identity")
        if identity.get("verified_email") is not True:
            raise GoogleSetupError("owner Google email is not verified")
        if owner_account_sha256(email) != owner_account_digest:
            raise GoogleSetupError("owner Google account does not match the approved digest")

        before = _inspect(transport)
        blockers = _preflight_blockers(before)
        if apply_live and not blockers:
            mutations.extend(_apply(transport, before))
            after = _inspect(transport)
            blockers = _completion_blockers(after)
        else:
            after = before
        status = "COMPLETE" if not _completion_blockers(after) else (
            "BLOCKED" if blockers else "READY"
        )
        if not apply_live and not blockers and status != "COMPLETE":
            status = "READY"
        return {
            "schema_version": SCHEMA_VERSION,
            "checked_at": _timestamp(now()),
            "mode": "APPLY_LIVE" if apply_live else "LIVE_READBACK",
            "network_used": True,
            "mutation_authorized": apply_live,
            "status": status,
            "owner_identity": {
                "verified": True,
                "account_sha256": owner_account_digest,
            },
            "targets": _targets(target_project_id),
            "inspection": after,
            "blockers": blockers,
            "mutations": mutations,
            "sanitization": {
                "raw_api_responses_retained": False,
                "oauth_material_retained": False,
                "owner_email_retained": False,
            },
        }
    # Provider libraries raise several optional exception classes. Collapse every
    # provider failure into a sanitized fail-closed record without retaining its body.
    except Exception as exc:  # noqa: BLE001
        return {
            "schema_version": SCHEMA_VERSION,
            "checked_at": _timestamp(now()),
            "mode": "APPLY_LIVE" if apply_live else "LIVE_READBACK",
            "network_used": True,
            "mutation_authorized": apply_live,
            "status": "FAILED_CLOSED",
            "targets": _targets(target_project_id),
            "inspection": {},
            "blockers": [
                {
                    "code": "GOOGLE_SETUP_REJECTED",
                    "type": type(exc).__name__,
                }
            ],
            "mutations": mutations,
            "sanitization": {
                "raw_api_responses_retained": False,
                "oauth_material_retained": False,
                "owner_email_retained": False,
            },
        }


def load_owner_credentials(path: str | Path) -> object:
    """Load and refresh one explicit owner token without persisting refreshed material."""
    credential_path = _secure_regular_file(path, "owner OAuth credential")
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
    except ImportError as exc:  # pragma: no cover - optional integration
        raise GoogleSetupError("install remedialhq-engine[google-control]") from exc
    credentials = cast(Any, Credentials.from_authorized_user_file)(
        str(credential_path), scopes=list(REQUIRED_SCOPES)
    )
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
    if not credentials.valid:
        raise GoogleSetupError("owner OAuth credential is not valid")
    granted = credentials.granted_scopes
    if granted is not None and not set(REQUIRED_SCOPES).issubset(set(granted)):
        raise GoogleSetupError("owner OAuth credential is missing required scopes")
    return credentials


class GoogleAPITransport:
    """Thin Google API adapter whose public methods expose only setup-relevant fields."""

    def __init__(
        self,
        credentials: object,
        *,
        builder: Callable[..., Any] | None = None,
    ) -> None:
        if builder is None:
            try:
                from googleapiclient.discovery import build
            except ImportError as exc:  # pragma: no cover - optional integration
                raise GoogleSetupError("install remedialhq-engine[google-control]") from exc
            builder = cast(Callable[..., Any], build)
        options = {"credentials": credentials, "cache_discovery": False}
        self._oauth = builder("oauth2", "v2", **options)
        self._verification = builder("siteVerification", "v1", **options)
        self._search = builder("searchconsole", "v1", **options)
        self._analytics = builder("analyticsadmin", "v1beta", **options)
        self._tag_manager = builder("tagmanager", "v2", **options)

    def owner_identity(self) -> Mapping[str, object]:
        return _mapping(self._oauth.userinfo().get().execute(), "owner identity")

    def search_console_sites(self) -> Sequence[Mapping[str, object]]:
        response = _mapping(self._search.sites().list().execute(), "Search Console sites")
        return _mapping_items(response, "siteEntry")

    def site_verifications(self) -> Sequence[Mapping[str, object]]:
        response = _mapping(
            self._verification.webResource().list().execute(), "site verifications"
        )
        return _mapping_items(response, "items")

    def search_console_sitemaps(
        self, site_url: str
    ) -> Sequence[Mapping[str, object]]:
        response = _mapping(
            self._search.sitemaps().list(siteUrl=site_url).execute(),
            "Search Console sitemaps",
        )
        return _mapping_items(response, "sitemap")

    def analytics_accounts(self) -> Sequence[Mapping[str, object]]:
        return self._paged(
            self._analytics.accountSummaries().list,
            "accountSummaries",
            pageSize=200,
        )

    def analytics_properties(
        self, account_name: str
    ) -> Sequence[Mapping[str, object]]:
        return self._paged(
            self._analytics.properties().list,
            "properties",
            filter=f"parent:{account_name}",
            pageSize=200,
            showDeleted=False,
        )

    def analytics_streams(
        self, property_name: str
    ) -> Sequence[Mapping[str, object]]:
        return self._paged(
            self._analytics.properties().dataStreams().list,
            "dataStreams",
            parent=property_name,
            pageSize=200,
        )

    def tag_manager_accounts(self) -> Sequence[Mapping[str, object]]:
        return self._paged(self._tag_manager.accounts().list, "account")

    def tag_manager_containers(
        self, account_path: str
    ) -> Sequence[Mapping[str, object]]:
        return self._paged(
            self._tag_manager.accounts().containers().list,
            "container",
            parent=account_path,
        )

    def verify_search_domain(self) -> None:
        self._verification.webResource().insert(
            verificationMethod="DNS_TXT",
            body={"site": {"identifier": DOMAIN, "type": "INET_DOMAIN"}},
        ).execute()

    def add_search_console_property(self) -> None:
        self._search.sites().add(siteUrl=SEARCH_CONSOLE_PROPERTY).execute()

    def submit_search_console_sitemap(self) -> None:
        self._search.sitemaps().submit(
            siteUrl=SEARCH_CONSOLE_PROPERTY,
            feedpath=SITEMAP_URL,
        ).execute()

    def create_analytics_property(self, account_name: str) -> None:
        self._analytics.properties().create(
            body={
                "parent": account_name,
                "displayName": ANALYTICS_PROPERTY_NAME,
                "timeZone": ANALYTICS_TIME_ZONE,
                "currencyCode": ANALYTICS_CURRENCY,
            }
        ).execute()

    def create_analytics_stream(self, property_name: str) -> None:
        self._analytics.properties().dataStreams().create(
            parent=property_name,
            body={
                "displayName": ANALYTICS_STREAM_NAME,
                "type": "WEB_DATA_STREAM",
                "webStreamData": {"defaultUri": ANALYTICS_DEFAULT_URI},
            },
        ).execute()

    def create_tag_manager_container(self, account_path: str) -> None:
        self._tag_manager.accounts().containers().create(
            parent=account_path,
            body={
                "name": TAG_MANAGER_CONTAINER_NAME,
                "usageContext": [TAG_MANAGER_USAGE_CONTEXT],
            },
        ).execute()

    def _paged(
        self,
        method: Callable[..., Any],
        item_key: str,
        **kwargs: object,
    ) -> Sequence[Mapping[str, object]]:
        results: list[Mapping[str, object]] = []
        token: str | None = None
        seen: set[str] = set()
        while True:
            request_kwargs = dict(kwargs)
            if token:
                request_kwargs["pageToken"] = token
            response = _mapping(method(**request_kwargs).execute(), item_key)
            results.extend(_mapping_items(response, item_key))
            raw_token = response.get("nextPageToken")
            token = raw_token.strip() if isinstance(raw_token, str) else None
            if not token:
                return tuple(results)
            if token in seen:
                raise GoogleSetupError("Google API pagination did not advance")
            seen.add(token)


def write_private_evidence(
    output_path: str | Path,
    evidence: Mapping[str, object],
    *,
    repository_root: str | Path,
) -> str:
    """Atomically retain sanitized evidence outside the repository at 0600."""
    path = Path(os.path.abspath(Path(output_path).expanduser()))
    root = Path(repository_root).expanduser().resolve()
    if _is_relative_to(path, root):
        raise GoogleSetupError("Google setup evidence must be outside the repository")
    _reject_symlink_ancestors(path)
    parent = path.parent
    if not parent.exists():
        parent.mkdir(mode=0o700)
    metadata = os.lstat(parent)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise GoogleSetupError("private evidence parent must be a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise GoogleSetupError("private evidence parent must use mode 0700")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise GoogleSetupError("private evidence parent ownership is insecure")
    if path.exists():
        existing = os.lstat(path)
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
            raise GoogleSetupError("private evidence output must be a regular file")
        if stat.S_IMODE(existing.st_mode) != 0o600:
            raise GoogleSetupError("existing evidence output must use mode 0600")
    payload = (json.dumps(evidence, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if stat.S_IMODE(os.lstat(path).st_mode) != 0o600:
            raise GoogleSetupError("private evidence output mode is insecure")
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(payload).hexdigest()


def _apply(
    transport: GoogleSetupTransport,
    before: Mapping[str, object],
) -> list[str]:
    mutations: list[str] = []
    search = _mapping(before.get("search_console"), "Search Console inspection")
    if search.get("verified_owner") is not True:
        transport.verify_search_domain()
        mutations.append("RMH-053:verified-domain")
    sites = _site_snapshot(transport)
    if sites.get("property_owner") is not True:
        transport.add_search_console_property()
        mutations.append("RMH-053:created-domain-property")
    sites = _site_snapshot(transport)
    if sites.get("property_owner") is not True:
        raise GoogleSetupError("Search Console owner readback failed")
    if not _sitemap_present(transport):
        transport.submit_search_console_sitemap()
        mutations.append("RMH-053:submitted-sitemap")

    analytics = _mapping(before.get("analytics"), "Analytics inspection")
    account_name = _required_text(analytics, "account_resource", "Analytics inspection")
    property_name = analytics.get("property_resource")
    if not isinstance(property_name, str):
        transport.create_analytics_property(account_name)
        mutations.append("RMH-055:created-property")
        refreshed = _analytics_snapshot(transport)
        property_name = refreshed.get("property_resource")
    if not isinstance(property_name, str):
        raise GoogleSetupError("GA4 property readback failed")
    refreshed = _analytics_snapshot(transport)
    if refreshed.get("stream_present") is not True:
        transport.create_analytics_stream(property_name)
        mutations.append("RMH-055:created-web-stream")

    tag_manager = _mapping(before.get("tag_manager"), "Tag Manager inspection")
    account_path = _required_text(tag_manager, "account_path", "Tag Manager inspection")
    if tag_manager.get("container_present") is not True:
        transport.create_tag_manager_container(account_path)
        mutations.append("RMH-056:created-web-container")
    return mutations


def _inspect(transport: GoogleSetupTransport) -> dict[str, object]:
    search = _site_snapshot(transport)
    search["sitemap_present"] = (
        _sitemap_present(transport) if search["property_present"] else False
    )
    return {
        "search_console": search,
        "analytics": _analytics_snapshot(transport),
        "tag_manager": _tag_manager_snapshot(transport),
    }


def _site_snapshot(transport: GoogleSetupTransport) -> dict[str, object]:
    verified = False
    for item in transport.site_verifications():
        site = item.get("site")
        if not isinstance(site, Mapping):
            continue
        if site.get("type") == "INET_DOMAIN" and site.get("identifier") == DOMAIN:
            verified = True
    matches = [
        item
        for item in transport.search_console_sites()
        if item.get("siteUrl") == SEARCH_CONSOLE_PROPERTY
    ]
    if len(matches) > 1:
        raise GoogleSetupError("Search Console property identity is ambiguous")
    permission = matches[0].get("permissionLevel") if matches else None
    return {
        "verified_owner": verified,
        "property_present": bool(matches),
        "property_owner": permission == "siteOwner",
        "permission_level": permission if isinstance(permission, str) else None,
    }


def _sitemap_present(transport: GoogleSetupTransport) -> bool:
    return any(
        item.get("path") == SITEMAP_URL
        for item in transport.search_console_sitemaps(SEARCH_CONSOLE_PROPERTY)
    )


def _analytics_snapshot(transport: GoogleSetupTransport) -> dict[str, object]:
    accounts = [
        item
        for item in transport.analytics_accounts()
        if item.get("displayName") == ANALYTICS_ACCOUNT_NAME
    ]
    snapshot: dict[str, object] = {
        "matching_account_count": len(accounts),
        "account_resource": None,
        "property_present": False,
        "property_resource": None,
        "stream_present": False,
        "stream_resource": None,
        "measurement_id": None,
    }
    if len(accounts) != 1:
        return snapshot
    account_name = _required_text(accounts[0], "account", "Analytics account")
    snapshot["account_resource"] = account_name
    properties = [
        item
        for item in transport.analytics_properties(account_name)
        if item.get("displayName") == ANALYTICS_PROPERTY_NAME
    ]
    if len(properties) > 1:
        raise GoogleSetupError("GA4 property identity is ambiguous")
    if not properties:
        return snapshot
    property_name = _required_text(properties[0], "name", "GA4 property")
    snapshot["property_present"] = True
    snapshot["property_resource"] = property_name
    streams = list(transport.analytics_streams(property_name))
    candidates = [
        item
        for item in streams
        if item.get("displayName") == ANALYTICS_STREAM_NAME
        or _stream_uri(item) == ANALYTICS_DEFAULT_URI
    ]
    if len(candidates) > 1:
        raise GoogleSetupError("GA4 web stream identity is ambiguous")
    if candidates:
        candidate = candidates[0]
        if (
            candidate.get("displayName") != ANALYTICS_STREAM_NAME
            or candidate.get("type") != "WEB_DATA_STREAM"
            or _stream_uri(candidate) != ANALYTICS_DEFAULT_URI
        ):
            raise GoogleSetupError("GA4 web stream conflicts with the exact target")
        snapshot["stream_present"] = True
        snapshot["stream_resource"] = candidate.get("name")
        web_data = candidate.get("webStreamData")
        if isinstance(web_data, Mapping):
            measurement = web_data.get("measurementId")
            snapshot["measurement_id"] = measurement if isinstance(measurement, str) else None
    return snapshot


def _tag_manager_snapshot(transport: GoogleSetupTransport) -> dict[str, object]:
    accounts = [
        item
        for item in transport.tag_manager_accounts()
        if item.get("name") == TAG_MANAGER_ACCOUNT_NAME
    ]
    snapshot: dict[str, object] = {
        "matching_account_count": len(accounts),
        "account_path": None,
        "container_present": False,
        "container_path": None,
        "public_id": None,
    }
    if len(accounts) != 1:
        return snapshot
    account_path = _required_text(accounts[0], "path", "Tag Manager account")
    snapshot["account_path"] = account_path
    containers = [
        item
        for item in transport.tag_manager_containers(account_path)
        if item.get("name") == TAG_MANAGER_CONTAINER_NAME
    ]
    if len(containers) > 1:
        raise GoogleSetupError("Tag Manager container identity is ambiguous")
    if containers:
        contexts = containers[0].get("usageContext")
        if (
            not isinstance(contexts, Sequence)
            or isinstance(contexts, (str, bytes))
            or TAG_MANAGER_USAGE_CONTEXT not in contexts
        ):
            raise GoogleSetupError("Tag Manager container is not a web container")
        snapshot["container_present"] = True
        snapshot["container_path"] = containers[0].get("path")
        snapshot["public_id"] = containers[0].get("publicId")
    return snapshot


def _preflight_blockers(inspection: Mapping[str, object]) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    analytics = _mapping(inspection.get("analytics"), "Analytics inspection")
    if analytics.get("matching_account_count") != 1:
        blockers.append(
            {
                "code": "EXACT_ANALYTICS_ACCOUNT_REQUIRED",
                "resolution": "create or select the existing ReMediaLHQ account and accept terms manually",
            }
        )
    tag_manager = _mapping(inspection.get("tag_manager"), "Tag Manager inspection")
    if tag_manager.get("matching_account_count") != 1:
        blockers.append(
            {
                "code": "EXACT_TAG_MANAGER_ACCOUNT_REQUIRED",
                "resolution": "create or select the existing ReMediaLHQ account and accept terms manually",
            }
        )
    return blockers


def _completion_blockers(inspection: Mapping[str, object]) -> list[dict[str, str]]:
    blockers = _preflight_blockers(inspection)
    search = _mapping(inspection.get("search_console"), "Search Console inspection")
    analytics = _mapping(inspection.get("analytics"), "Analytics inspection")
    tag_manager = _mapping(inspection.get("tag_manager"), "Tag Manager inspection")
    checks = (
        (search.get("verified_owner") is True, "SEARCH_DOMAIN_NOT_VERIFIED"),
        (search.get("property_owner") is True, "SEARCH_PROPERTY_NOT_OWNED"),
        (search.get("sitemap_present") is True, "SEARCH_SITEMAP_NOT_SUBMITTED"),
        (analytics.get("property_present") is True, "GA4_PROPERTY_NOT_PRESENT"),
        (analytics.get("stream_present") is True, "GA4_STREAM_NOT_PRESENT"),
        (tag_manager.get("container_present") is True, "GTM_CONTAINER_NOT_PRESENT"),
    )
    blockers.extend(
        {"code": code, "resolution": "run again with --apply-live after reviewing preflight"}
        for clear, code in checks
        if not clear
    )
    return blockers


def validate_project_id(value: str) -> str:
    project_id = value.strip()
    if _PROJECT_ID_PATTERN.fullmatch(project_id) is None:
        raise GoogleSetupError("--project-id must be a valid Google Cloud project ID")
    return project_id


def _targets(project_id: str) -> dict[str, object]:
    return {
        "project_id": project_id,
        "domain": DOMAIN,
        "search_console": {
            "property": SEARCH_CONSOLE_PROPERTY,
            "sitemap": SITEMAP_URL,
        },
        "analytics": {
            "account_name": ANALYTICS_ACCOUNT_NAME,
            "property_name": ANALYTICS_PROPERTY_NAME,
            "stream_name": ANALYTICS_STREAM_NAME,
            "default_uri": ANALYTICS_DEFAULT_URI,
            "time_zone": ANALYTICS_TIME_ZONE,
            "currency": ANALYTICS_CURRENCY,
        },
        "tag_manager": {
            "account_name": TAG_MANAGER_ACCOUNT_NAME,
            "container_name": TAG_MANAGER_CONTAINER_NAME,
            "usage_context": TAG_MANAGER_USAGE_CONTEXT,
        },
    }


def _stream_uri(item: Mapping[str, object]) -> str | None:
    web_data = item.get("webStreamData")
    if not isinstance(web_data, Mapping):
        return None
    uri = web_data.get("defaultUri")
    return uri.rstrip("/") if isinstance(uri, str) else None


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise GoogleSetupError(f"{label} is malformed")
    return value


def _mapping_items(
    response: Mapping[str, object], key: str
) -> Sequence[Mapping[str, object]]:
    value = response.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise GoogleSetupError(f"Google API {key} collection is malformed")
    return tuple(cast(Mapping[str, object], item) for item in value)


def _required_text(value: Mapping[str, object], key: str, label: str) -> str:
    text = value.get(key)
    if not isinstance(text, str) or not text.strip():
        raise GoogleSetupError(f"{label} is missing {key}")
    return text.strip()


def _secure_regular_file(path: str | Path, label: str) -> Path:
    resolved = Path(os.path.abspath(Path(path).expanduser()))
    _reject_symlink_ancestors(resolved)
    try:
        metadata = os.lstat(resolved)
    except OSError as exc:
        raise GoogleSetupError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise GoogleSetupError(f"{label} must be a regular file")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise GoogleSetupError(f"{label} must use mode 0600")
    return resolved


def _reject_symlink_ancestors(path: Path) -> None:
    for ancestor in (path, *path.parents):
        try:
            metadata = os.lstat(ancestor)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise GoogleSetupError("private path must not use symbolic links")


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise GoogleSetupError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
