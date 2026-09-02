from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

YOUTUBE_UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload"
YOUTUBE_READ_SCOPE = "https://www.googleapis.com/auth/youtube.readonly"
YOUTUBE_ANALYTICS_SCOPE = "https://www.googleapis.com/auth/yt-analytics.readonly"
DEFAULT_YOUTUBE_SCOPES = (
    YOUTUBE_UPLOAD_SCOPE,
    YOUTUBE_READ_SCOPE,
    YOUTUBE_ANALYTICS_SCOPE,
)
YOUTUBE_POLICY_ACCEPTANCE_SCHEMA = "remedialhq.youtube-policy-acceptance.v1"
YOUTUBE_POLICY_ROUTES = {
    "privacy": ("site/privacy.html", "https://remedialhq.com/privacy"),
    "terms": ("site/terms.html", "https://remedialhq.com/terms"),
}
MAX_POLICY_ACCEPTANCE_BYTES = 65_536
YOUTUBE_REVOCATION_EVIDENCE_SCHEMA = "remedialhq.youtube-revocation-evidence.v1"
GOOGLE_REVOCATION_ENDPOINT = "https://oauth2.googleapis.com/revoke"

TokenRevoker = Callable[[str], None]


class AuthorizationError(RuntimeError):
    """Raised when an owner authorization cannot be completed or resolved."""


def _normalize_scopes(scopes: Iterable[str] | None) -> tuple[str, ...]:
    values = tuple(dict.fromkeys(scopes or DEFAULT_YOUTUBE_SCOPES))
    if not values:
        raise ValueError("at least one OAuth scope is required")
    return values


def load_youtube_credentials(
    token_file: str | Path,
    *,
    scopes: Iterable[str] | None = None,
    refresh: bool = True,
    persist_refresh: bool = True,
) -> Any:
    """Load and optionally refresh an authorized-user token.

    Google dependencies remain optional so the deterministic engine can run without
    platform SDKs. The token file must be created by the owner authorization command or
    retrieved from an owner-controlled secret store.
    """
    token_path = Path(token_file).expanduser().resolve()
    if not token_path.is_file():
        raise FileNotFoundError(token_path)
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError('install remedialhq-engine[youtube]') from exc

    credentials = cast(Any, Credentials.from_authorized_user_file)(
        str(token_path), scopes=list(_normalize_scopes(scopes))
    )
    if refresh and credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        if persist_refresh:
            _write_private_json(token_path, json.loads(credentials.to_json()))
    if not credentials.valid:
        raise AuthorizationError("YouTube owner credentials are not valid")
    return credentials


def resolve_youtube_channel(credentials: Any) -> dict[str, str]:
    """Resolve the channel selected by the authenticated owner grant."""
    try:
        from googleapiclient.discovery import build
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError('install remedialhq-engine[youtube]') from exc

    youtube = build("youtube", "v3", credentials=credentials, cache_discovery=False)
    response = youtube.channels().list(part="id,snippet", mine=True).execute()
    items = response.get("items", []) if isinstance(response, dict) else []
    if len(items) != 1:
        raise AuthorizationError(
            f"expected exactly one authorized YouTube channel, received {len(items)}"
        )
    item = items[0]
    snippet = item.get("snippet", {})
    channel_id = str(item.get("id", "")).strip()
    if not channel_id:
        raise AuthorizationError("authorized channel response did not include a channel ID")
    return {
        "channel_id": channel_id,
        "channel_title": str(snippet.get("title", "")),
        "channel_url": f"https://www.youtube.com/channel/{channel_id}",
    }


def authorize_youtube(
    client_secrets: str | Path,
    token_output: str | Path,
    *,
    policy_acceptance: str | Path,
    repository_root: str | Path,
    scopes: Iterable[str] | None = None,
    open_browser: bool = True,
) -> dict[str, Any]:
    """Run the owner-controlled installed-app OAuth flow and persist the token locally."""
    normalized = _normalize_scopes(scopes)
    acceptance = validate_youtube_policy_acceptance(
        policy_acceptance,
        repository_root=repository_root,
        scopes=normalized,
    )
    client_path = Path(client_secrets).expanduser().resolve()
    token_path = Path(token_output).expanduser().resolve()
    if not client_path.is_file():
        raise FileNotFoundError(client_path)
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError('install remedialhq-engine[youtube]') from exc

    flow = InstalledAppFlow.from_client_secrets_file(str(client_path), scopes=list(normalized))
    credentials = flow.run_local_server(
        host="127.0.0.1",
        port=0,
        open_browser=open_browser,
        authorization_prompt_message=(
            "Open this URL to authorize the owner-controlled ReMediaLHQ YouTube channel:\n{url}"
        ),
        success_message="ReMediaLHQ YouTube authorization completed. You may close this window.",
    )
    channel = resolve_youtube_channel(credentials)
    token_payload = json.loads(credentials.to_json())
    _write_private_json(token_path, token_payload)
    return {
        "token_file": str(token_path),
        "scopes": list(normalized),
        "policy_acceptance_sha256": acceptance["evidence_sha256"],
        **channel,
    }


def record_youtube_policy_acceptance(
    repository_root: str | Path,
    output_path: str | Path,
    *,
    accept_privacy: bool,
    accept_terms: bool,
    scopes: Iterable[str] | None = None,
    accepted_at: datetime | None = None,
) -> dict[str, Any]:
    """Record explicit acceptance of the exact current policies before OAuth starts."""
    if not accept_privacy or not accept_terms:
        raise AuthorizationError("both Privacy Policy and Terms acceptance are required")
    root = _validated_repository_root(repository_root)
    normalized_scopes = _normalize_scopes(scopes)
    moment = accepted_at or datetime.now(UTC)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise AuthorizationError("accepted_at must include a timezone")
    moment = moment.astimezone(UTC).replace(microsecond=0)
    policies = _current_policy_records(root)
    payload: dict[str, Any] = {
        "schema_version": YOUTUBE_POLICY_ACCEPTANCE_SCHEMA,
        "accepted_at": moment.isoformat().replace("+00:00", "Z"),
        "policies": policies,
        "oauth_scopes": list(normalized_scopes),
        "consent": {
            "privacy_policy_accepted": True,
            "terms_accepted": True,
        },
    }
    destination = _write_private_json_create_only(
        output_path,
        payload,
        repository_root=root,
        label="policy acceptance evidence",
    )
    evidence_sha256 = _sha256_bytes(destination.read_bytes())
    return {
        "status": "ACCEPTED",
        "accepted_at": payload["accepted_at"],
        "evidence_path": str(destination),
        "evidence_sha256": evidence_sha256,
        "oauth_scopes": list(normalized_scopes),
    }


def revoke_youtube_credentials(
    token_file: str | Path,
    evidence_output: str | Path,
    *,
    repository_root: str | Path,
    confirm_revoke_and_delete: bool,
    revoker: TokenRevoker | None = None,
    occurred_at: datetime | None = None,
) -> dict[str, Any]:
    """Revoke one Google grant and delete the exact supplied local credential."""
    if not confirm_revoke_and_delete:
        raise AuthorizationError("revocation requires explicit revoke-and-delete confirmation")
    root = _validated_repository_root(repository_root)
    token_path, token_bytes = _read_owner_private_file(
        token_file,
        repository_root=root,
        label="YouTube token",
    )
    token_document = _strict_json_object(token_bytes, "YouTube token")
    revocation_token = token_document.get("refresh_token") or token_document.get("token")
    if (
        not isinstance(revocation_token, str)
        or not revocation_token
        or len(revocation_token.encode("utf-8")) > 16_384
    ):
        raise AuthorizationError("YouTube token contains no bounded revocation credential")
    _validate_create_only_destination(
        evidence_output,
        repository_root=root,
        label="revocation evidence",
    )
    active_revoker = revoker or _revoke_google_token
    try:
        active_revoker(revocation_token)
    except AuthorizationError:
        raise
    except Exception as exc:
        raise AuthorizationError("Google token revocation failed") from exc

    try:
        if token_path.read_bytes() != token_bytes:
            raise AuthorizationError("YouTube token changed during revocation")
        token_path.unlink()
    except AuthorizationError:
        raise
    except OSError as exc:
        raise AuthorizationError("revoked YouTube token could not be deleted") from exc

    moment = occurred_at or datetime.now(UTC)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise AuthorizationError("occurred_at must include a timezone")
    occurred = moment.astimezone(UTC).replace(microsecond=0)
    evidence = {
        "schema_version": YOUTUBE_REVOCATION_EVIDENCE_SCHEMA,
        "status": "REVOKED_LOCAL_CREDENTIAL_DELETED",
        "occurred_at": occurred.isoformat().replace("+00:00", "Z"),
        "provider": "google_oauth",
        "credential_sha256": _sha256_bytes(token_bytes),
        "local_credential_deleted": True,
        "raw_provider_response_retained": False,
    }
    evidence_path = _write_private_json_create_only(
        evidence_output,
        evidence,
        repository_root=root,
        label="revocation evidence",
    )
    return {
        "status": evidence["status"],
        "occurred_at": evidence["occurred_at"],
        "evidence_path": str(evidence_path),
        "evidence_sha256": _sha256_bytes(evidence_path.read_bytes()),
    }


def _revoke_google_token(token: str) -> None:
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlencode
    from urllib.request import Request, urlopen

    request = Request(
        GOOGLE_REVOCATION_ENDPOINT,
        data=urlencode({"token": token}).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            status = int(response.status)
            response.read(4_096)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise AuthorizationError("Google token revocation failed") from exc
    if status != 200:
        raise AuthorizationError("Google token revocation failed")


def validate_youtube_policy_acceptance(
    evidence_path: str | Path,
    *,
    repository_root: str | Path,
    scopes: Iterable[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate owner-private acceptance against the exact current policy sources."""
    root = _validated_repository_root(repository_root)
    candidate = Path(evidence_path).expanduser()
    if candidate.is_symlink():
        raise AuthorizationError("policy acceptance evidence must be a regular file")
    destination = candidate.resolve()
    if destination.is_relative_to(root):
        raise AuthorizationError("policy acceptance evidence must remain outside the repository")
    try:
        metadata = destination.lstat()
    except OSError as exc:
        raise AuthorizationError("policy acceptance evidence is unavailable") from exc
    if destination.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise AuthorizationError("policy acceptance evidence must be a regular file")
    if os.name == "posix" and metadata.st_mode & 0o777 != 0o600:
        raise AuthorizationError("policy acceptance evidence must use mode 0600")
    if metadata.st_size > MAX_POLICY_ACCEPTANCE_BYTES:
        raise AuthorizationError("policy acceptance evidence is too large")
    try:
        raw = destination.read_bytes()
    except OSError as exc:
        raise AuthorizationError("policy acceptance evidence is unreadable") from exc
    if len(raw) > MAX_POLICY_ACCEPTANCE_BYTES:
        raise AuthorizationError("policy acceptance evidence is too large")
    payload = _strict_json_object(raw, "policy acceptance evidence")
    expected_fields = {
        "schema_version",
        "accepted_at",
        "policies",
        "oauth_scopes",
        "consent",
    }
    if set(payload) != expected_fields:
        raise AuthorizationError("policy acceptance evidence fields are invalid")
    if payload["schema_version"] != YOUTUBE_POLICY_ACCEPTANCE_SCHEMA:
        raise AuthorizationError("policy acceptance evidence schema is invalid")
    expected_scopes = list(_normalize_scopes(scopes))
    if payload["oauth_scopes"] != expected_scopes:
        raise AuthorizationError("policy acceptance does not match the requested OAuth scopes")
    if payload["policies"] != _current_policy_records(root):
        raise AuthorizationError("policy acceptance does not match the current policy sources")
    if payload["consent"] != {
        "privacy_policy_accepted": True,
        "terms_accepted": True,
    }:
        raise AuthorizationError("policy acceptance is incomplete")
    accepted_at = _parse_utc_timestamp(payload["accepted_at"])
    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise AuthorizationError("current time must include a timezone")
    if accepted_at > current.astimezone(UTC):
        raise AuthorizationError("policy acceptance timestamp is in the future")
    return {
        "accepted_at": payload["accepted_at"],
        "evidence_path": str(destination),
        "evidence_sha256": _sha256_bytes(raw),
        "oauth_scopes": expected_scopes,
    }


def _validated_repository_root(value: str | Path) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_symlink():
        raise AuthorizationError("repository root must be a real directory")
    root = candidate.resolve()
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise AuthorizationError("repository root is unavailable") from exc
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise AuthorizationError("repository root must be a real directory")
    return root


def _current_policy_records(root: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for policy, (relative, url) in YOUTUBE_POLICY_ROUTES.items():
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise AuthorizationError(f"{policy} policy source is unavailable") from exc
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise AuthorizationError(f"{policy} policy source must be a regular file")
        data = path.read_bytes()
        records[policy] = {
            "accepted": True,
            "source": relative,
            "url": url,
            "sha256": _sha256_bytes(data),
        }
    return records


def _strict_json_object(data: bytes, label: str) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise AuthorizationError(f"{label} contains a duplicate field")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=object_pairs)
    except AuthorizationError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise AuthorizationError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise AuthorizationError(f"{label} must be an object")
    return value


def _parse_utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AuthorizationError("policy acceptance timestamp must be UTC")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuthorizationError("policy acceptance timestamp is invalid") from exc
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise AuthorizationError("policy acceptance timestamp must use whole UTC seconds")
    return parsed


def _sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _write_private_json_create_only(
    path: str | Path,
    payload: dict[str, Any],
    *,
    repository_root: Path,
    label: str,
) -> Path:
    destination = _validate_create_only_destination(
        path,
        repository_root=repository_root,
        label=label,
    )
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError as exc:
        raise AuthorizationError(f"{label} already exists") from exc
    except OSError as exc:
        raise AuthorizationError(f"{label} cannot be created") from exc
    completed = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix" and destination.stat().st_mode & 0o777 != 0o600:
            raise AuthorizationError(f"{label} cannot enforce mode 0600")
        completed = True
    finally:
        if not completed:
            destination.unlink(missing_ok=True)
    return destination


def _validate_create_only_destination(
    path: str | Path,
    *,
    repository_root: Path,
    label: str,
) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise AuthorizationError(f"{label} must be a regular file")
    destination = candidate.resolve()
    if destination.is_relative_to(repository_root):
        raise AuthorizationError(f"{label} must remain outside the repository")
    if destination.exists():
        raise AuthorizationError(f"{label} already exists")
    parent = destination.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise AuthorizationError(f"{label} directory is unavailable") from exc
    if parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        raise AuthorizationError(f"{label} directory must be real")
    if os.name == "posix" and parent_metadata.st_mode & 0o777 != 0o700:
        raise AuthorizationError(f"{label} directory must use mode 0700")
    return destination


def _read_owner_private_file(
    path: str | Path,
    *,
    repository_root: Path,
    label: str,
) -> tuple[Path, bytes]:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise AuthorizationError(f"{label} must be a regular file")
    source = candidate.resolve()
    if source.is_relative_to(repository_root):
        raise AuthorizationError(f"{label} must remain outside the repository")
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise AuthorizationError(f"{label} is unavailable") from exc
    if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise AuthorizationError(f"{label} must be a regular file")
    if os.name == "posix" and metadata.st_mode & 0o777 != 0o600:
        raise AuthorizationError(f"{label} must use mode 0600")
    if metadata.st_size > MAX_POLICY_ACCEPTANCE_BYTES:
        raise AuthorizationError(f"{label} is too large")
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise AuthorizationError(f"{label} is unreadable") from exc
    if len(data) > MAX_POLICY_ACCEPTANCE_BYTES:
        raise AuthorizationError(f"{label} is too large")
    return source, data


def install_secret_version(
    project_id: str,
    secret_id: str,
    source_file: str | Path,
) -> dict[str, str]:
    """Add a local credential file as a new Secret Manager version."""
    path = Path(source_file).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        from google.cloud.secretmanager import SecretManagerServiceClient
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError('install remedialhq-engine[gcp]') from exc
    client = SecretManagerServiceClient()
    parent = f"projects/{project_id}/secrets/{secret_id}"
    response = client.add_secret_version(
        request={"parent": parent, "payload": {"data": path.read_bytes()}}
    )
    return {"secret": parent, "version": str(response.name)}


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    replaced = False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        replaced = True
        os.chmod(path, 0o600)
        if os.name == "posix" and path.stat().st_mode & 0o777 != 0o600:
            path.unlink(missing_ok=True)
            raise PermissionError(
                "token path cannot enforce owner-only permissions; use a Linux filesystem "
                "or install the token directly into Secret Manager"
            )
    finally:
        if not replaced:
            temporary.unlink(missing_ok=True)
