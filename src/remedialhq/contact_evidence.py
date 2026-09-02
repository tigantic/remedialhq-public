from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "remedialhq.contact-evidence.v1"
EXPECTED_EVENT_TYPE = "OUTREACH_MESSAGE_SENT"
MAX_DOCUMENT_BYTES = 16_384
MAX_PRIVATE_FILE_BYTES = 256 * 1024


class ContactEvidenceError(ValueError):
    """Raised when post-send outreach evidence is incomplete or unsafe."""


_FIELDS = frozenset(
    {
        "schema_version",
        "event_type",
        "prospect_id",
        "channel",
        "sender_profile_evidence_sha256",
        "suppression_evidence_sha256",
        "message_copy_sha256",
        "provider_send_evidence_sha256",
        "provider_message_sha256",
        "observed_at",
    }
)
_CHANNELS = frozenset(
    {
        "BUSINESS_EMAIL",
        "CONTACT_FORM",
        "SOCIAL_DM",
        "OTHER_PUBLIC_BUSINESS_CHANNEL",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROSPECT_ID_RE = re.compile(r"^prs_[0-9a-f]{32}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
_FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"(?:https?://|www\.)", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9_])(?:msg_|message_)[A-Za-z0-9._-]+", re.IGNORECASE),
    re.compile(r"\b(?:sk|rk|pk)_(?:test|live)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE),
)


@dataclass(frozen=True, slots=True)
class ContactEvidence:
    """Privacy-minimized proof created only after one provider-confirmed send."""

    prospect_id: str
    channel: str
    sender_profile_evidence_sha256: str
    suppression_evidence_sha256: str
    message_copy_sha256: str
    provider_send_evidence_sha256: str
    provider_message_sha256: str
    observed_at: str

    def __post_init__(self) -> None:
        _match(self.prospect_id, _PROSPECT_ID_RE, "prospect_id")
        if self.channel not in _CHANNELS:
            raise ContactEvidenceError("channel is not supported")
        digests = (
            self.sender_profile_evidence_sha256,
            self.suppression_evidence_sha256,
            self.message_copy_sha256,
            self.provider_send_evidence_sha256,
            self.provider_message_sha256,
        )
        for field_name, value in zip(
            (
                "sender_profile_evidence_sha256",
                "suppression_evidence_sha256",
                "message_copy_sha256",
                "provider_send_evidence_sha256",
                "provider_message_sha256",
            ),
            digests,
            strict=True,
        ):
            _match(value, _SHA256_RE, field_name)
        if len(set(digests)) != len(digests):
            raise ContactEvidenceError("contact evidence digests must be distinct")
        if _parse_timestamp(self.observed_at) != self.observed_at:
            raise ContactEvidenceError("observed_at must be normalized to UTC")

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": SCHEMA_VERSION,
            "event_type": EXPECTED_EVENT_TYPE,
            "prospect_id": self.prospect_id,
            "channel": self.channel,
            "sender_profile_evidence_sha256": self.sender_profile_evidence_sha256,
            "suppression_evidence_sha256": self.suppression_evidence_sha256,
            "message_copy_sha256": self.message_copy_sha256,
            "provider_send_evidence_sha256": self.provider_send_evidence_sha256,
            "provider_message_sha256": self.provider_message_sha256,
            "observed_at": self.observed_at,
        }

    @property
    def sha256(self) -> str:
        encoded = json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def build_contact_evidence(
    document: Mapping[str, object],
    *,
    expected_prospect_id: str,
    expected_channel: str,
    expected_sender_profile_evidence_sha256: str,
) -> ContactEvidence:
    """Validate redacted evidence tied to the exact prospect, channel, and sender profile."""
    _scan_values(document)
    if any(not isinstance(key, str) for key in document):
        raise ContactEvidenceError("contact evidence field names must be strings")
    if set(document) != set(_FIELDS):
        raise ContactEvidenceError("contact evidence has missing or unknown fields")
    _exact(document["schema_version"], SCHEMA_VERSION, "schema_version")
    _exact(document["event_type"], EXPECTED_EVENT_TYPE, "event_type")

    prospect_id = _match(document["prospect_id"], _PROSPECT_ID_RE, "prospect_id")
    expected_id = _match(expected_prospect_id, _PROSPECT_ID_RE, "expected_prospect_id")
    if not hmac.compare_digest(prospect_id, expected_id):
        raise ContactEvidenceError("prospect_id does not match the expected prospect")

    channel = document["channel"]
    if not isinstance(channel, str) or channel not in _CHANNELS:
        raise ContactEvidenceError("channel is not supported")
    if channel != expected_channel:
        raise ContactEvidenceError("channel does not match the planned channel")

    expected_sender_digest = _match(
        expected_sender_profile_evidence_sha256,
        _SHA256_RE,
        "expected_sender_profile_evidence_sha256",
    )
    sender_digest = _match(
        document["sender_profile_evidence_sha256"],
        _SHA256_RE,
        "sender_profile_evidence_sha256",
    )
    if not hmac.compare_digest(sender_digest, expected_sender_digest):
        raise ContactEvidenceError(
            "sender_profile_evidence_sha256 does not match the selected sender profile"
        )

    return ContactEvidence(
        prospect_id=prospect_id,
        channel=channel,
        sender_profile_evidence_sha256=sender_digest,
        suppression_evidence_sha256=_match(
            document["suppression_evidence_sha256"],
            _SHA256_RE,
            "suppression_evidence_sha256",
        ),
        message_copy_sha256=_match(
            document["message_copy_sha256"],
            _SHA256_RE,
            "message_copy_sha256",
        ),
        provider_send_evidence_sha256=_match(
            document["provider_send_evidence_sha256"],
            _SHA256_RE,
            "provider_send_evidence_sha256",
        ),
        provider_message_sha256=_match(
            document["provider_message_sha256"],
            _SHA256_RE,
            "provider_message_sha256",
        ),
        observed_at=_parse_timestamp(document["observed_at"]),
    )


def parse_contact_evidence(
    text: str,
    *,
    expected_prospect_id: str,
    expected_channel: str,
    expected_sender_profile_evidence_sha256: str,
) -> ContactEvidence:
    if not isinstance(text, str):
        raise TypeError("contact evidence must be JSON text")
    try:
        encoded = text.encode("utf-8")
    except UnicodeError:
        raise ContactEvidenceError("contact evidence must be valid UTF-8") from None
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise ContactEvidenceError("contact evidence exceeds the size limit")
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (ContactEvidenceError, json.JSONDecodeError, UnicodeError):
        raise ContactEvidenceError("contact evidence is not valid strict JSON") from None
    if not isinstance(document, Mapping):
        raise ContactEvidenceError("contact evidence must be a JSON object")
    return build_contact_evidence(
        document,
        expected_prospect_id=expected_prospect_id,
        expected_channel=expected_channel,
        expected_sender_profile_evidence_sha256=expected_sender_profile_evidence_sha256,
    )


def private_file_sha256(path: str | Path, *, maximum_bytes: int) -> str:
    """Hash one stable owner-private 0600 regular file without following links."""
    raw = _read_private_file(path, maximum_bytes=maximum_bytes)
    return hashlib.sha256(raw).hexdigest()


def read_private_file(path: str | Path, *, maximum_bytes: int) -> bytes:
    """Read one stable owner-private 0600 regular file without following links."""
    return _read_private_file(path, maximum_bytes=maximum_bytes)


def load_contact_evidence(
    path: str | Path,
    *,
    expected_prospect_id: str,
    expected_channel: str,
    expected_sender_profile_evidence_sha256: str,
) -> ContactEvidence:
    raw = _read_private_file(path, maximum_bytes=MAX_DOCUMENT_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ContactEvidenceError("contact evidence must be UTF-8") from None
    return parse_contact_evidence(
        text,
        expected_prospect_id=expected_prospect_id,
        expected_channel=expected_channel,
        expected_sender_profile_evidence_sha256=expected_sender_profile_evidence_sha256,
    )


def _read_private_file(path: str | Path, *, maximum_bytes: int) -> bytes:
    path_value = os.fspath(path)
    try:
        absolute = Path(path_value).absolute()
    except (OSError, TypeError, ValueError):
        raise ContactEvidenceError("private evidence file is unavailable") from None
    for ancestor in reversed(absolute.parents):
        try:
            metadata = os.lstat(ancestor)
        except OSError:
            raise ContactEvidenceError("private evidence file is unavailable") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise ContactEvidenceError("private evidence path must not use symlink ancestors")
    try:
        before = os.lstat(path_value)
    except OSError:
        raise ContactEvidenceError("private evidence file is unavailable") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ContactEvidenceError("private evidence file must be a regular file")
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise ContactEvidenceError("private evidence file must have mode 0600")
    if before.st_size > maximum_bytes:
        raise ContactEvidenceError("private evidence file exceeds the size limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path_value, flags)
    except OSError:
        raise ContactEvidenceError("private evidence file cannot be opened") from None
    try:
        opened = os.fstat(descriptor)
        snapshot = _snapshot(opened)
        if snapshot != _snapshot(before) or stat.S_IMODE(opened.st_mode) != 0o600:
            raise ContactEvidenceError("private evidence file changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ContactEvidenceError("private evidence file exceeds the size limit")
        after = os.fstat(descriptor)
        if _snapshot(after) != snapshot or total != after.st_size:
            raise ContactEvidenceError("private evidence file changed while reading")
        current = os.lstat(path_value)
        if _snapshot(current) != snapshot:
            raise ContactEvidenceError("private evidence file changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _match(value: object, pattern: re.Pattern[str], field_name: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContactEvidenceError(f"{field_name} has an invalid format")
    return value


def _exact(value: object, expected: str, field_name: str) -> None:
    if value != expected:
        raise ContactEvidenceError(f"{field_name} is not supported")


def _parse_timestamp(value: object) -> str:
    if not isinstance(value, str) or _RFC3339_RE.fullmatch(value) is None:
        raise ContactEvidenceError("observed_at must be a timezone-aware RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ContactEvidenceError("observed_at must be a valid timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContactEvidenceError("observed_at must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContactEvidenceError("contact evidence contains duplicate fields")
        result[key] = value
    return result


def _scan_values(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ContactEvidenceError("contact evidence field names must be strings")
            _scan_values(nested)
        return
    if isinstance(value, list):
        for nested in value:
            _scan_values(nested)
        return
    if isinstance(value, str):
        for pattern in _FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(value):
                raise ContactEvidenceError("contact evidence contains prohibited raw data")
