from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
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
    scopes: Iterable[str] | None = None,
    open_browser: bool = True,
) -> dict[str, Any]:
    """Run the owner-controlled installed-app OAuth flow and persist the token locally."""
    client_path = Path(client_secrets).expanduser().resolve()
    token_path = Path(token_output).expanduser().resolve()
    if not client_path.is_file():
        raise FileNotFoundError(client_path)
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError('install remedialhq-engine[youtube]') from exc

    normalized = _normalize_scopes(scopes)
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
        **channel,
    }


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
