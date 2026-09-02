from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.message import Message
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

EdgeRole = Literal["app", "api", "verify"]

IAP_EMAIL_HEADER = "X-Goog-Authenticated-User-Email"
IAP_EMAIL_NAMESPACE = "accounts.google.com:"
IAP_JWT_HEADER = "X-Goog-IAP-JWT-Assertion"
IAP_CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"
IAP_ISSUER = "https://cloud.google.com/iap"
IAP_REGION = "us-east1"
OWNER_DIGEST_ENV = "EDGE_EXPECTED_OWNER_EMAIL_SHA256"
IAP_AUDIENCE_ENV = "EDGE_IAP_AUDIENCE"

MAX_REQUEST_TARGET_BYTES = 2_048
MAX_REQUEST_HEADERS = 64
MAX_REQUEST_HEADER_BYTES = 16_384
MAX_REQUEST_BODY_BYTES = 16_384
MAX_RESPONSE_BYTES = 131_072
MAX_CLAIMS = 200
MAX_SOURCES = 200
MAX_IAP_JWT_BYTES = 12_288

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_CLOUD_RUN_SERVICE_RE = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_COMPACT_JWT_RE = re.compile(
    r"[A-Za-z0-9_-]{1,4096}\."
    r"[A-Za-z0-9_-]{1,8192}\."
    r"[A-Za-z0-9_-]{1,4096}"
)
_CLAIM_ID_RE = re.compile(r"CLM-[0-9]{4,8}")
_SOURCE_ID_RE = re.compile(r"[A-Z][A-Z0-9-]{2,63}")
_EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")
_EMAIL_IN_TEXT_RE = re.compile(
    r"(?i)(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63}"
    r"(?![A-Z0-9.-])"
)
_ALLOWED_STATES = frozenset(
    {"CONFIRMED", "OBSERVED", "REPORTED", "INFERRED", "PENDING", "REJECTED"}
)
_PUBLISHABLE_STATES = frozenset({"CONFIRMED", "OBSERVED", "REPORTED", "INFERRED"})
_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'none'; img-src 'none'; object-src 'none'; script-src 'none'; "
    "style-src 'none'"
)
_PERMISSIONS_POLICY = (
    "accelerometer=(), autoplay=(), camera=(), geolocation=(), gyroscope=(), "
    "magnetometer=(), microphone=(), payment=(), usb=()"
)
_PUBLIC_DATA_FILES = {
    "claims": ("site/data/claims.json", 256_000),
    "sources": ("site/data/sources.json", 256_000),
    "manifest": ("site/data/manifest.json", 16_384),
    "version": ("VERSION", 64),
}


class EdgeConfigurationError(RuntimeError):
    """Raised when an edge role cannot start securely."""


class PublicDataError(RuntimeError):
    """Raised when public verifier data does not satisfy the bounded contract."""


@dataclass(frozen=True)
class EdgeConfig:
    role: EdgeRole
    root: Path
    expected_owner_email_sha256: str | None
    iap_audience: str | None = None


@dataclass(frozen=True)
class EdgeResponse:
    status: HTTPStatus
    body: bytes
    content_type: str
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class PublicSnapshot:
    status_body: bytes
    claims_body: bytes
    page_body: bytes


TokenVerifier = Callable[[str, str], Mapping[str, object]]


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _validate_json_unicode(value: object, label: str) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise PublicDataError(f"{label} contains invalid Unicode") from exc
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def _strict_json(data: bytes, label: str) -> object:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PublicDataError(f"{label} contains a duplicate JSON field")
            value[key] = item
        return value

    def invalid_constant(value: str) -> None:
        raise PublicDataError(f"{label} contains an invalid JSON number: {value}")

    try:
        value = json.loads(
            data,
            object_pairs_hook=object_pairs,
            parse_constant=invalid_constant,
        )
    except PublicDataError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PublicDataError(f"{label} is not strict UTF-8 JSON") from exc
    _validate_json_unicode(value, label)
    return value


def _bounded_text(value: object, label: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise PublicDataError(f"{label} must be nonempty text")
    encoded = value.encode("utf-8")
    if len(encoded) > maximum_bytes:
        raise PublicDataError(f"{label} is too large")
    if any(ord(character) < 32 and character not in {"\t"} for character in value):
        raise PublicDataError(f"{label} contains a control character")
    return value


def _bounded_int(value: object, label: str, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise PublicDataError(f"{label} is outside its allowed range")
    return value


def _read_public_file(root: Path, relative: str, maximum_bytes: int) -> bytes:
    relative_path = PurePosixPath(relative)
    if relative_path.is_absolute() or any(part in {"", ".", ".."} for part in relative_path.parts):
        raise PublicDataError("public data path is invalid")
    if root.is_symlink() or not root.is_dir():
        raise PublicDataError("APP_ROOT must be a real directory")

    candidate = root
    for part in relative_path.parts:
        candidate = candidate / part
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise PublicDataError(f"missing public data file: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise PublicDataError(f"public data path must not contain symlinks: {relative}")
    if not stat.S_ISREG(metadata.st_mode):
        raise PublicDataError(f"public data path must be a regular file: {relative}")
    if metadata.st_size > maximum_bytes:
        raise PublicDataError(f"public data file is too large: {relative}")
    try:
        data = candidate.read_bytes()
    except OSError as exc:
        raise PublicDataError(f"public data file could not be read: {relative}") from exc
    if len(data) > maximum_bytes:
        raise PublicDataError(f"public data file is too large: {relative}")
    return data


def _safe_source_ids(value: object, known_sources: frozenset[str], label: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise PublicDataError(f"{label} must contain 1 through 16 source IDs")
    source_ids: list[str] = []
    for item in value:
        if not isinstance(item, str) or _SOURCE_ID_RE.fullmatch(item) is None:
            raise PublicDataError(f"{label} contains an invalid source ID")
        if item not in known_sources:
            raise PublicDataError(f"{label} references an unknown source ID")
        if item in source_ids:
            raise PublicDataError(f"{label} contains a duplicate source ID")
        source_ids.append(item)
    return source_ids


def _validate_sources(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SOURCES:
        raise PublicDataError("sources must contain a bounded nonempty list")
    source_ids: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise PublicDataError(f"sources[{index}] must be an object")
        source_id = item.get("source_id")
        if not isinstance(source_id, str) or _SOURCE_ID_RE.fullmatch(source_id) is None:
            raise PublicDataError(f"sources[{index}].source_id is invalid")
        if source_id in source_ids:
            raise PublicDataError("sources contains a duplicate source ID")
        source_ids.add(source_id)
    return frozenset(source_ids)


def _safe_claims(value: object, known_sources: frozenset[str]) -> list[dict[str, object]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CLAIMS:
        raise PublicDataError("claims must contain a bounded nonempty list")
    claim_ids: set[str] = set()
    claims: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise PublicDataError(f"claims[{index}] must be an object")
        claim_id = item.get("claim_id")
        if not isinstance(claim_id, str) or _CLAIM_ID_RE.fullmatch(claim_id) is None:
            raise PublicDataError(f"claims[{index}].claim_id is invalid")
        if claim_id in claim_ids:
            raise PublicDataError("claims contains a duplicate claim ID")
        claim_ids.add(claim_id)

        state = item.get("state")
        if not isinstance(state, str) or state not in _ALLOWED_STATES:
            raise PublicDataError(f"claims[{index}].state is invalid")
        public_wording = _bounded_text(
            item.get("public_wording"),
            f"claims[{index}].public_wording",
            1_000,
        )
        if _EMAIL_IN_TEXT_RE.search(public_wording):
            raise PublicDataError("public claim wording must not contain an email address")
        source_ids = _safe_source_ids(
            item.get("source_ids"),
            known_sources,
            f"claims[{index}].source_ids",
        )
        observed_value = item.get("observed_at")
        observed_at: str | None
        if observed_value is None:
            observed_at = None
        else:
            observed_at = _bounded_text(
                observed_value,
                f"claims[{index}].observed_at",
                64,
            )

        public_record: dict[str, object] = {
            "claim_id": claim_id,
            "state": state,
            "public_wording": public_wording,
            "source_ids": source_ids,
            "observed_at": observed_at,
        }
        public_record["sha256"] = hashlib.sha256(_canonical_json(public_record)).hexdigest()
        claims.append(public_record)
    return claims


def load_public_snapshot(root: Path) -> PublicSnapshot:
    data = {
        name: _read_public_file(root, relative, limit)
        for name, (relative, limit) in _PUBLIC_DATA_FILES.items()
    }
    manifest_value = _strict_json(data["manifest"], "public manifest")
    claims_value = _strict_json(data["claims"], "public claims")
    sources_value = _strict_json(data["sources"], "public sources")
    if not isinstance(manifest_value, dict):
        raise PublicDataError("public manifest must be an object")

    source_ids = _validate_sources(sources_value)
    claims = _safe_claims(claims_value, source_ids)
    publishable_count = sum(1 for claim in claims if claim.get("state") in _PUBLISHABLE_STATES)
    expected_manifest = {
        "claims": len(claims),
        "outputs": ["/data/claims.json", "/data/sources.json"],
        "publishable_claims": publishable_count,
        "sources": len(source_ids),
    }
    if manifest_value != expected_manifest:
        raise PublicDataError("public manifest does not match the validated data")

    try:
        version = data["version"].decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise PublicDataError("VERSION must be ASCII") from exc
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?", version) is None:
        raise PublicDataError("VERSION is invalid")

    claims_digest = hashlib.sha256(data["claims"]).hexdigest()
    sources_digest = hashlib.sha256(data["sources"]).hexdigest()
    source_manifest_digest = hashlib.sha256(data["manifest"]).hexdigest()
    claim_manifest_digest = hashlib.sha256(_canonical_json(claims)).hexdigest()

    status_document = {
        "schema_version": 1,
        "service": "remedialhq-public-verifier",
        "status": "ok",
        "version": version,
        "claims": len(claims),
        "publishable_claims": publishable_count,
        "sources": len(source_ids),
        "claims_file_sha256": claims_digest,
        "sources_file_sha256": sources_digest,
        "source_manifest_sha256": source_manifest_digest,
        "claim_manifest_sha256": claim_manifest_digest,
    }
    claims_document = {
        "schema_version": 1,
        "service": "remedialhq-public-verifier",
        "version": version,
        "claim_count": len(claims),
        "claim_manifest_sha256": claim_manifest_digest,
        "claims_file_sha256": claims_digest,
        "claims": claims,
    }
    status_body = _canonical_json(status_document)
    claims_body = _canonical_json(claims_document)
    page_body = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>ReMediaLHQ verification</title></head><body><main>"
        "<h1>ReMediaLHQ verification</h1>"
        "<p>This service exposes the public claim index packaged with this release.</p>"
        f"<dl><dt>Release</dt><dd>{html.escape(version)}</dd>"
        f"<dt>Claims</dt><dd>{len(claims)}</dd>"
        f"<dt>Publishable claims</dt><dd>{publishable_count}</dd>"
        f"<dt>Sources</dt><dd>{len(source_ids)}</dd></dl>"
        f"<p>Claim manifest SHA-256: <code>{claim_manifest_digest}</code></p>"
        '<nav><a href="/status.json">Service status</a> | '
        '<a href="/claims.json">Claim manifest</a> | '
        '<a href="https://remedialhq.com/">ReMediaLHQ</a></nav>'
        "</main></body></html>\n"
    ).encode()
    for body in (status_body, claims_body, page_body):
        if len(body) > MAX_RESPONSE_BYTES:
            raise PublicDataError("public verifier response exceeds its size bound")
    return PublicSnapshot(status_body, claims_body, page_body)


def load_config(environment: Mapping[str, str] | None = None) -> EdgeConfig:
    values = os.environ if environment is None else environment
    role_value = values.get("EDGE_ROLE", "")
    if role_value not in {"app", "api", "verify"}:
        raise EdgeConfigurationError("EDGE_ROLE must be app, api, or verify")
    role = cast(EdgeRole, role_value)
    root = Path(values.get("APP_ROOT", "."))
    expected_digest: str | None = None
    iap_audience: str | None = None
    if role in {"app", "api"}:
        expected_digest = values.get(OWNER_DIGEST_ENV)
        if expected_digest is None or _DIGEST_RE.fullmatch(expected_digest) is None:
            raise EdgeConfigurationError(f"{OWNER_DIGEST_ENV} must be a lowercase SHA-256 digest")
        service_name = values.get("K_SERVICE", "")
        if _CLOUD_RUN_SERVICE_RE.fullmatch(service_name) is None:
            raise EdgeConfigurationError("K_SERVICE must be the exact Cloud Run service name")
        iap_audience = values.get(IAP_AUDIENCE_ENV)
        expected_audience = re.compile(
            rf"/projects/[1-9][0-9]{{5,19}}/locations/{re.escape(IAP_REGION)}"
            rf"/services/{re.escape(service_name)}"
        )
        if iap_audience is None or expected_audience.fullmatch(iap_audience) is None:
            raise EdgeConfigurationError(
                f"{IAP_AUDIENCE_ENV} must exactly match the Cloud Run service"
            )
    return EdgeConfig(role, root, expected_digest, iap_audience)


def owner_email_sha256(email: str) -> str:
    normalized = email.lower()
    if email != email.strip() or not _valid_email(normalized):
        raise ValueError("owner email is invalid")
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def _valid_email(email: str) -> bool:
    if not 3 <= len(email) <= 254 or not email.isascii() or _EMAIL_RE.fullmatch(email) is None:
        return False
    local, domain = email.rsplit("@", 1)
    if not 1 <= len(local) <= 64 or local.startswith(".") or local.endswith("."):
        return False
    if ".." in local or not domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    return all(
        1 <= len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and re.fullmatch(r"[a-z0-9-]+", label) is not None
        for label in labels
    )


def _verify_iap_token(token: str, audience: str) -> Mapping[str, object]:
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token

    verified = id_token.verify_token(
        token,
        Request(),
        audience=audience,
        certs_url=IAP_CERTS_URL,
    )
    if not isinstance(verified, Mapping):
        raise TypeError("IAP token did not contain claims")
    return cast(Mapping[str, object], verified)


def _normalized_jwt_email(value: object) -> str | None:
    if not isinstance(value, str) or value != value.strip() or not value.isascii():
        return None
    email = value.lower()
    return email if _valid_email(email) else None


def _compatibility_email(headers: Message) -> str | None:
    values = headers.get_all(IAP_EMAIL_HEADER, [])
    if not values:
        return ""
    if len(values) != 1:
        return None
    value = values[0]
    if not isinstance(value, str) or value != value.strip() or not value.isascii():
        return None
    if len(value) > len(IAP_EMAIL_NAMESPACE) + 254 or not value.startswith(IAP_EMAIL_NAMESPACE):
        return None
    email = value[len(IAP_EMAIL_NAMESPACE) :].lower()
    return email if _valid_email(email) else None


def _authenticated_owner(
    headers: Message,
    expected_digest: str | None,
    audience: str | None,
    token_verifier: TokenVerifier,
) -> bool:
    if expected_digest is None or audience is None:
        return False
    tokens = headers.get_all(IAP_JWT_HEADER, [])
    if len(tokens) != 1:
        return False
    token = tokens[0]
    if (
        not isinstance(token, str)
        or token != token.strip()
        or not token.isascii()
        or len(token.encode("ascii")) > MAX_IAP_JWT_BYTES
        or _COMPACT_JWT_RE.fullmatch(token) is None
    ):
        return False

    try:
        claims = token_verifier(token, audience)
    except Exception:  # noqa: BLE001 - every verifier or key-fetch failure denies access
        return False

    if claims.get("iss") != IAP_ISSUER or claims.get("aud") != audience:
        return False
    subject = claims.get("sub")
    if (
        not isinstance(subject, str)
        or subject != subject.strip()
        or not subject.isascii()
        or not 1 <= len(subject) <= 256
    ):
        return False
    email = _normalized_jwt_email(claims.get("email"))
    if email is None:
        return False

    actual_digest = hashlib.sha256(email.encode("ascii")).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        return False

    compatibility_email = _compatibility_email(headers)
    if compatibility_email is None:
        return False
    return not compatibility_email or hmac.compare_digest(
        compatibility_email.encode("ascii"), email.encode("ascii")
    )


def _security_headers(role: EdgeRole) -> tuple[tuple[str, str], ...]:
    headers = (
        ("Cache-Control", "no-store"),
        (
            "Content-Security-Policy",
            _CONTENT_SECURITY_POLICY,
        ),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        (
            "Permissions-Policy",
            _PERMISSIONS_POLICY,
        ),
        ("Referrer-Policy", "no-referrer"),
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
    )
    if role in {"app", "api"}:
        return (*headers, ("X-Robots-Tag", "noindex, nofollow, noarchive"))
    return headers


def _json_error(role: EdgeRole, status: HTTPStatus, code: str) -> EdgeResponse:
    return EdgeResponse(
        status,
        _canonical_json({"status": "error", "code": code}),
        "application/json; charset=utf-8",
        _security_headers(role),
    )


def _request_headers_within_bounds(headers: Message) -> bool:
    items = list(headers.items())
    if len(items) > MAX_REQUEST_HEADERS:
        return False
    total = 0
    for name, value in items:
        try:
            total += len(name.encode("ascii")) + len(value.encode("utf-8")) + 4
        except (UnicodeEncodeError, AttributeError):
            return False
        if total > MAX_REQUEST_HEADER_BYTES:
            return False
    return True


def _request_body_status(headers: Message, method: str) -> tuple[HTTPStatus, str] | None:
    if headers.get_all("Transfer-Encoding", []):
        return HTTPStatus.BAD_REQUEST, "transfer_encoding_not_allowed"
    lengths = headers.get_all("Content-Length", [])
    if len(lengths) > 1:
        return HTTPStatus.BAD_REQUEST, "invalid_content_length"
    length = 0
    if lengths:
        raw = lengths[0]
        if re.fullmatch(r"[0-9]{1,10}", raw) is None:
            return HTTPStatus.BAD_REQUEST, "invalid_content_length"
        length = int(raw)
    if length > MAX_REQUEST_BODY_BYTES:
        return HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request_body_too_large"
    if method in {"GET", "HEAD"} and length != 0:
        return HTTPStatus.BAD_REQUEST, "request_body_not_allowed"
    return None


def _request_target_status(target: str) -> tuple[HTTPStatus, str] | None:
    try:
        target_bytes = target.encode("ascii")
    except UnicodeEncodeError:
        return HTTPStatus.BAD_REQUEST, "invalid_request_target"
    if len(target_bytes) > MAX_REQUEST_TARGET_BYTES:
        return HTTPStatus.REQUEST_URI_TOO_LONG, "request_target_too_long"
    if (
        not target.startswith("/")
        or target.startswith("//")
        or "?" in target
        or "#" in target
        or "%" in target
        or "\\" in target
        or any(segment in {".", ".."} for segment in target.split("/"))
    ):
        return HTTPStatus.BAD_REQUEST, "invalid_request_target"
    return None


class EdgeApplication:
    def __init__(
        self,
        config: EdgeConfig,
        token_verifier: TokenVerifier = _verify_iap_token,
    ) -> None:
        self.config = config
        self.token_verifier = token_verifier
        self.public_snapshot = (
            load_public_snapshot(config.root) if config.role == "verify" else None
        )

    def respond(self, method: str, target: str, headers: Message) -> EdgeResponse:
        if not _request_headers_within_bounds(headers):
            return _json_error(
                self.config.role,
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "request_headers_too_large",
            )
        target_error = _request_target_status(target)
        if target_error is not None:
            return _json_error(self.config.role, *target_error)
        body_error = _request_body_status(headers, method)
        if body_error is not None:
            return _json_error(self.config.role, *body_error)

        if self.config.role in {"app", "api"} and not _authenticated_owner(
            headers,
            self.config.expected_owner_email_sha256,
            self.config.iap_audience,
            self.token_verifier,
        ):
            return _json_error(self.config.role, HTTPStatus.UNAUTHORIZED, "unauthorized")
        if method not in {"GET", "HEAD"}:
            response = _json_error(
                self.config.role,
                HTTPStatus.METHOD_NOT_ALLOWED,
                "method_not_allowed",
            )
            return EdgeResponse(
                response.status,
                response.body,
                response.content_type,
                (*response.headers, ("Allow", "GET, HEAD")),
            )
        return self._route(target)

    def _route(self, target: str) -> EdgeResponse:
        role = self.config.role
        security_headers = _security_headers(role)
        if role == "verify":
            snapshot = self.public_snapshot
            if snapshot is None:  # pragma: no cover - constructor invariant
                return _json_error(role, HTTPStatus.SERVICE_UNAVAILABLE, "service_unavailable")
            if target == "/":
                return EdgeResponse(
                    HTTPStatus.OK,
                    snapshot.page_body,
                    "text/html; charset=utf-8",
                    security_headers,
                )
            if target in {"/healthz", "/status.json"}:
                return EdgeResponse(
                    HTTPStatus.OK,
                    snapshot.status_body,
                    "application/json; charset=utf-8",
                    security_headers,
                )
            if target == "/claims.json":
                return EdgeResponse(
                    HTTPStatus.OK,
                    snapshot.claims_body,
                    "application/json; charset=utf-8",
                    security_headers,
                )
            return _json_error(role, HTTPStatus.NOT_FOUND, "not_found")

        private_status = _canonical_json(
            {
                "schema_version": 1,
                "service": f"remedialhq-owner-{role}",
                "status": "ok",
                "access": "owner",
            }
        )
        if role == "app" and target == "/":
            body = (
                b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
                b'<meta name="viewport" content="width=device-width,initial-scale=1">'
                b"<title>ReMediaLHQ owner app</title></head><body><main>"
                b"<h1>ReMediaLHQ owner app</h1><p>Signed in. The owner workspace is ready.</p>"
                b"</main></body></html>\n"
            )
            return EdgeResponse(
                HTTPStatus.OK,
                body,
                "text/html; charset=utf-8",
                security_headers,
            )
        if target in {"/", "/healthz", "/status.json"} and (role == "api" or target == "/healthz"):
            return EdgeResponse(
                HTTPStatus.OK,
                private_status,
                "application/json; charset=utf-8",
                security_headers,
            )
        return _json_error(role, HTTPStatus.NOT_FOUND, "not_found")


class EdgeHTTPServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address: tuple[str, int], application: EdgeApplication) -> None:
        self.application = application
        super().__init__(address, EdgeHandler)


class EdgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ReMediaLHQ"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def do_GET(self) -> None:
        self._serve()

    def do_HEAD(self) -> None:
        self._serve()

    def do_OPTIONS(self) -> None:
        self._serve()

    def do_POST(self) -> None:
        self._serve()

    def do_PUT(self) -> None:
        self._serve()

    def do_PATCH(self) -> None:
        self._serve()

    def do_DELETE(self) -> None:
        self._serve()

    def do_TRACE(self) -> None:
        self._serve()

    def do_CONNECT(self) -> None:
        self._serve()

    def _serve(self) -> None:
        server = self.server
        if not isinstance(server, EdgeHTTPServer):  # pragma: no cover - handler invariant
            self.close_connection = True
            return
        response = server.application.respond(self.command, self.path, self.headers)
        self.send_response(response.status.value)
        self.send_header("Content-Type", response.content_type)
        for name, value in response.headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        # Do not log IAP identity headers, client IPs, query strings, or user agents.
        return


def _port(environment: Mapping[str, str]) -> int:
    raw = environment.get("PORT", "8080")
    if re.fullmatch(r"[0-9]{1,5}", raw) is None:
        raise EdgeConfigurationError("PORT is invalid")
    port = int(raw)
    if not 1 <= port <= 65_535:
        raise EdgeConfigurationError("PORT is invalid")
    return port


def main() -> None:
    try:
        config = load_config()
        application = EdgeApplication(config)
        port = _port(os.environ)
    except (EdgeConfigurationError, PublicDataError, OSError):
        print(
            json.dumps({"service": "remedialhq-edge", "status": "startup_failed"}),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    EdgeHTTPServer(("0.0.0.0", port), application).serve_forever()


if __name__ == "__main__":
    main()
