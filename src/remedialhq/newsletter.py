from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class NewsletterContractError(ValueError):
    """Raised when a disabled or malformed newsletter operation is requested."""


_EMAIL_PATTERN = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,189}$")
_OPAQUE_REFERENCE = re.compile(r"^(?:evt|sub|cns)_[A-Za-z0-9_-]{12,120}$")
_SIGNATURE = re.compile(r"^v1=([0-9a-f]{64})$")
_FORBIDDEN_KEY = re.compile(r"(?:address|email|name|phone|token|cookie|ip)", re.IGNORECASE)
_EVENT_TYPES = frozenset({"subscriber.confirmed", "subscriber.unsubscribed"})


@dataclass(frozen=True)
class NewsletterConfiguration:
    schema_version: str
    enabled: bool
    provider: str | None
    public_signup_endpoint: str | None
    public_webhook_endpoint: str | None
    store_addresses: bool
    webhook_signing_algorithm: str
    webhook_tolerance_seconds: int
    max_signup_body_bytes: int
    max_webhook_body_bytes: int
    status: str

    @classmethod
    def from_path(cls, path: Path) -> NewsletterConfiguration:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NewsletterContractError("newsletter configuration is unreadable") from exc
        if not isinstance(value, dict):
            raise NewsletterContractError("newsletter configuration must be an object")
        required = {field for field in cls.__dataclass_fields__}
        if set(value) != required:
            raise NewsletterContractError("newsletter configuration fields do not match contract")
        try:
            config = cls(**value)
        except TypeError as exc:
            raise NewsletterContractError("newsletter configuration has invalid fields") from exc
        config.validate()
        return config

    def validate(self) -> None:
        if self.schema_version != "remedialhq.newsletter-contract.v1":
            raise NewsletterContractError("unsupported newsletter contract version")
        if not isinstance(self.enabled, bool) or not isinstance(self.store_addresses, bool):
            raise NewsletterContractError("newsletter switches must be boolean")
        if self.webhook_signing_algorithm != "hmac-sha256":
            raise NewsletterContractError("unsupported webhook signing algorithm")
        if not 60 <= self.webhook_tolerance_seconds <= 900:
            raise NewsletterContractError("webhook tolerance is out of bounds")
        if not 512 <= self.max_signup_body_bytes <= 8192:
            raise NewsletterContractError("signup body limit is out of bounds")
        if not 1024 <= self.max_webhook_body_bytes <= 65536:
            raise NewsletterContractError("webhook body limit is out of bounds")
        if self.enabled:
            if not self.provider or not self.provider.strip():
                raise NewsletterContractError("enabled newsletter contract requires a provider")
            if not self.public_signup_endpoint or not self.public_webhook_endpoint:
                raise NewsletterContractError("enabled newsletter contract requires both endpoints")
            if not self.store_addresses:
                raise NewsletterContractError("enabled signup requires an approved address boundary")
        else:
            if any(
                value is not None
                for value in (
                    self.provider,
                    self.public_signup_endpoint,
                    self.public_webhook_endpoint,
                )
            ):
                raise NewsletterContractError("disabled newsletter contract must not name live routes")
            if self.store_addresses:
                raise NewsletterContractError("disabled newsletter contract must not store addresses")

    def require_active(self) -> None:
        self.validate()
        if not self.enabled:
            raise NewsletterContractError("newsletter integration is disabled")


@dataclass(frozen=True)
class SignupIntent:
    email: str
    consent: bool
    terms_version: str
    privacy_version: str


@dataclass(frozen=True)
class NewsletterEvent:
    event_id: str
    event_type: str
    occurred_at: str
    subscriber_ref: str
    consent_ref: str


def validate_signup(
    config: NewsletterConfiguration,
    payload: Mapping[str, object],
    *,
    body_size: int,
) -> SignupIntent:
    config.require_active()
    if body_size < 2 or body_size > config.max_signup_body_bytes:
        raise NewsletterContractError("signup body size is out of bounds")
    required = {"email", "consent", "terms_version", "privacy_version"}
    if set(payload) != required:
        raise NewsletterContractError("signup fields do not match contract")
    email = payload["email"]
    consent = payload["consent"]
    terms_version = payload["terms_version"]
    privacy_version = payload["privacy_version"]
    if not isinstance(email, str) or len(email) > 254 or not _EMAIL_PATTERN.fullmatch(email):
        raise NewsletterContractError("signup email is invalid")
    if consent is not True:
        raise NewsletterContractError("explicit signup consent is required")
    if not isinstance(terms_version, str) or not 1 <= len(terms_version) <= 40:
        raise NewsletterContractError("terms_version is invalid")
    if not isinstance(privacy_version, str) or not 1 <= len(privacy_version) <= 40:
        raise NewsletterContractError("privacy_version is invalid")
    return SignupIntent(email.casefold(), True, terms_version, privacy_version)


def _parse_utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise NewsletterContractError("event time must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise NewsletterContractError("event time is invalid") from exc
    return parsed.astimezone(UTC)


def _reject_identifying_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or _FORBIDDEN_KEY.search(key):
                raise NewsletterContractError("webhook contains a forbidden identifying field")
            _reject_identifying_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_identifying_keys(child)


def verify_webhook(
    config: NewsletterConfiguration,
    body: bytes,
    *,
    timestamp: str,
    signature: str,
    secret: bytes,
    now: datetime | None = None,
) -> NewsletterEvent:
    config.require_active()
    if not 2 <= len(body) <= config.max_webhook_body_bytes:
        raise NewsletterContractError("webhook body size is out of bounds")
    if len(secret) < 32:
        raise NewsletterContractError("webhook secret is too short")
    try:
        timestamp_value = int(timestamp)
    except ValueError as exc:
        raise NewsletterContractError("webhook timestamp is invalid") from exc
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise NewsletterContractError("current time must be timezone-aware")
    if abs(current.timestamp() - timestamp_value) > config.webhook_tolerance_seconds:
        raise NewsletterContractError("webhook timestamp is outside the replay window")
    match = _SIGNATURE.fullmatch(signature)
    if match is None:
        raise NewsletterContractError("webhook signature format is invalid")
    expected = hmac.new(secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, match.group(1)):
        raise NewsletterContractError("webhook signature does not match")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NewsletterContractError("webhook body is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise NewsletterContractError("webhook body must be an object")
    _reject_identifying_keys(payload)
    required = {"event_id", "event_type", "occurred_at", "subscriber_ref", "consent_ref"}
    if set(payload) != required:
        raise NewsletterContractError("webhook fields do not match contract")
    if payload["event_type"] not in _EVENT_TYPES:
        raise NewsletterContractError("webhook event type is unsupported")
    for key in ("event_id", "subscriber_ref", "consent_ref"):
        value = payload[key]
        if not isinstance(value, str) or _OPAQUE_REFERENCE.fullmatch(value) is None:
            raise NewsletterContractError(f"webhook {key} is not an opaque reference")
    occurred_at = payload["occurred_at"]
    if not isinstance(occurred_at, str):
        raise NewsletterContractError("webhook event time is invalid")
    _parse_utc(occurred_at)
    return NewsletterEvent(
        event_id=payload["event_id"],
        event_type=payload["event_type"],
        occurred_at=occurred_at,
        subscriber_ref=payload["subscriber_ref"],
        consent_ref=payload["consent_ref"],
    )
