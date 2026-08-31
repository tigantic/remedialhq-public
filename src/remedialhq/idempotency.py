from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast


class LeaseAction(StrEnum):
    PROCESS = "PROCESS"
    DISPATCH = "DISPATCH"
    RETURN = "RETURN"
    BUSY = "BUSY"


class LeaseLost(RuntimeError):
    """Raised when another worker has taken ownership of an expired lease."""


class EventConflict(RuntimeError):
    """Raised when an event ID is replayed with different request material."""


@dataclass(frozen=True, slots=True)
class EventLease:
    action: LeaseAction
    phase: str
    event_id: str
    token: str | None = None
    revision: int | None = None
    response: dict[str, Any] | None = None
    next_payload: dict[str, Any] | None = None
    request_digest: str | None = None


class EventStateStore(Protocol):
    def claim(
        self,
        phase: str,
        event_id: str,
        *,
        request_digest: str,
        lease_seconds: int = 900,
    ) -> EventLease: ...

    def save_result(
        self,
        lease: EventLease,
        response: dict[str, Any],
        next_payload: dict[str, Any] | None,
    ) -> None: ...

    def abandon_retryable(self, lease: EventLease) -> None: ...

    def complete_dispatch(self, lease: EventLease, message_id: str) -> dict[str, Any]: ...


def event_key(event_id: str) -> str:
    """Return a path-safe, stable identity without exposing attacker-controlled input."""
    return hashlib.sha256(event_id.encode("utf-8")).hexdigest()


def child_event_id(parent_event_id: str, next_phase: str) -> str:
    material = f"remedialhq:v1:{parent_event_id}:{next_phase}".encode()
    return f"ev_{hashlib.sha256(material).hexdigest()[:40]}"


def _token() -> str:
    return secrets.token_urlsafe(24)


def _request_digest(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("request_digest must be a lowercase SHA-256 digest")
    return value


def _retry_transition(lease: EventLease) -> tuple[str, str, float | None]:
    if not lease.token or not lease.request_digest:
        raise LeaseLost("retryable abandonment requires an owned event lease")
    if lease.action == LeaseAction.PROCESS:
        return "PROCESSING", "PROCESSING", 0.0
    if lease.action == LeaseAction.DISPATCH:
        return "DISPATCHING", "RESULT_READY", None
    raise LeaseLost("only processing or dispatch leases can be abandoned for retry")


class SQLiteEventStateStore:
    """Transactional local store for development, tests, and single-host execution."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _initialize(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    phase TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    token TEXT,
                    lease_until REAL,
                    response_json TEXT,
                    next_payload_json TEXT,
                    message_id TEXT,
                    request_digest TEXT,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (phase, event_id)
                )
                """
            )
            columns = {
                str(row[1]) for row in conn.execute("PRAGMA table_info(events)").fetchall()
            }
            if "request_digest" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN request_digest TEXT")

    def claim(
        self,
        phase: str,
        event_id: str,
        *,
        request_digest: str,
        lease_seconds: int = 900,
    ) -> EventLease:
        request_digest = _request_digest(request_digest)
        now = time.time()
        token = _token()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM events WHERE phase = ? AND event_id = ?",
                (phase, event_id),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO events
                    (phase, event_id, status, token, lease_until, request_digest, updated_at)
                    VALUES (?, ?, 'PROCESSING', ?, ?, ?, ?)
                    """,
                    (phase, event_id, token, now + lease_seconds, request_digest, now),
                )
                conn.execute("COMMIT")
                return EventLease(
                    LeaseAction.PROCESS,
                    phase,
                    event_id,
                    token=token,
                    request_digest=request_digest,
                )

            if row["request_digest"] != request_digest:
                conn.execute("ROLLBACK")
                raise EventConflict("event ID was replayed with different request material")

            status = str(row["status"])
            response = json.loads(row["response_json"]) if row["response_json"] else None
            next_payload = (
                json.loads(row["next_payload_json"]) if row["next_payload_json"] else None
            )
            if status == "COMPLETE":
                conn.execute("COMMIT")
                return EventLease(
                    LeaseAction.RETURN,
                    phase,
                    event_id,
                    response=response,
                    next_payload=next_payload,
                    request_digest=request_digest,
                )

            lease_until = float(row["lease_until"] or 0.0)
            if status in {"PROCESSING", "DISPATCHING"} and lease_until > now:
                conn.execute("COMMIT")
                return EventLease(
                    LeaseAction.BUSY,
                    phase,
                    event_id,
                    request_digest=request_digest,
                )

            if status == "RESULT_READY" or status == "DISPATCHING":
                next_status = "DISPATCHING"
                action = LeaseAction.DISPATCH
            else:
                next_status = "PROCESSING"
                action = LeaseAction.PROCESS
            conn.execute(
                """
                UPDATE events
                SET status = ?, token = ?, lease_until = ?, updated_at = ?
                WHERE phase = ? AND event_id = ?
                """,
                (next_status, token, now + lease_seconds, now, phase, event_id),
            )
            conn.execute("COMMIT")
            return EventLease(
                action,
                phase,
                event_id,
                token=token,
                response=response,
                next_payload=next_payload,
                request_digest=request_digest,
            )

    def save_result(
        self,
        lease: EventLease,
        response: dict[str, Any],
        next_payload: dict[str, Any] | None,
    ) -> None:
        if lease.action != LeaseAction.PROCESS or not lease.token or not lease.request_digest:
            raise LeaseLost("result can only be saved by a processing lease")
        status = "RESULT_READY" if next_payload is not None else "COMPLETE"
        now = time.time()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE events
                SET status = ?, token = NULL, lease_until = NULL,
                    response_json = ?, next_payload_json = ?, updated_at = ?
                WHERE phase = ? AND event_id = ? AND status = 'PROCESSING' AND token = ?
                    AND request_digest = ?
                """,
                (
                    status,
                    json.dumps(response, sort_keys=True),
                    json.dumps(next_payload, sort_keys=True) if next_payload is not None else None,
                    now,
                    lease.phase,
                    lease.event_id,
                    lease.token,
                    lease.request_digest,
                ),
            )
            if cursor.rowcount != 1:
                conn.execute("ROLLBACK")
                raise LeaseLost("processing lease was lost before result commit")
            conn.execute("COMMIT")

    def abandon_retryable(self, lease: EventLease) -> None:
        expected_status, next_status, lease_until = _retry_transition(lease)
        now = time.time()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE events
                SET status = ?, token = NULL, lease_until = ?, updated_at = ?
                WHERE phase = ? AND event_id = ? AND status = ? AND token = ?
                    AND request_digest = ?
                """,
                (
                    next_status,
                    lease_until,
                    now,
                    lease.phase,
                    lease.event_id,
                    expected_status,
                    lease.token,
                    lease.request_digest,
                ),
            )
            if cursor.rowcount != 1:
                conn.execute("ROLLBACK")
                raise LeaseLost("event lease was lost before retryable abandonment")
            conn.execute("COMMIT")

    def complete_dispatch(self, lease: EventLease, message_id: str) -> dict[str, Any]:
        if lease.action != LeaseAction.DISPATCH or not lease.token or not lease.request_digest:
            raise LeaseLost("dispatch can only be completed by a dispatch lease")
        now = time.time()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT response_json FROM events
                WHERE phase = ? AND event_id = ? AND request_digest = ?
                """,
                (lease.phase, lease.event_id, lease.request_digest),
            ).fetchone()
            if row is None or not row["response_json"]:
                conn.execute("ROLLBACK")
                raise LeaseLost("dispatch record has no committed phase result")
            response = cast(dict[str, Any], json.loads(row["response_json"]))
            response["next_message_id"] = message_id
            cursor = conn.execute(
                """
                UPDATE events
                SET status = 'COMPLETE', token = NULL, lease_until = NULL,
                    response_json = ?, message_id = ?, updated_at = ?
                WHERE phase = ? AND event_id = ? AND status = 'DISPATCHING' AND token = ?
                    AND request_digest = ?
                """,
                (
                    json.dumps(response, sort_keys=True),
                    message_id,
                    now,
                    lease.phase,
                    lease.event_id,
                    lease.token,
                    lease.request_digest,
                ),
            )
            if cursor.rowcount != 1:
                conn.execute("ROLLBACK")
                raise LeaseLost("dispatch lease was lost before completion")
            conn.execute("COMMIT")
            return response


class GCSEventStateStore:
    """Generation-matched state machine for horizontally scaled Cloud Run workers."""

    def __init__(self, bucket_name: str, *, prefix: str = "_state/events") -> None:
        try:
            from google.cloud.storage import Client
        except ImportError as exc:  # pragma: no cover - cloud-only dependency
            raise RuntimeError("google-cloud-storage is required for GCS event state") from exc
        self.bucket = Client().bucket(bucket_name)
        self.prefix = prefix.strip("/")

    def _blob(self, phase: str, event_id: str) -> Any:
        return self.bucket.blob(f"{self.prefix}/{phase}/{event_key(event_id)}.json")

    @staticmethod
    def _encode(record: dict[str, Any]) -> str:
        return json.dumps(record, sort_keys=True, separators=(",", ":"))

    def _read(self, blob: Any) -> tuple[dict[str, Any], int]:
        blob.reload()
        generation = int(blob.generation)
        value = cast(
            dict[str, Any],
            json.loads(blob.download_as_text(if_generation_match=generation)),
        )
        return value, generation

    def _write(self, blob: Any, record: dict[str, Any], generation: int) -> int:
        blob.upload_from_string(
            self._encode(record),
            content_type="application/json",
            if_generation_match=generation,
        )
        blob.reload()
        return int(blob.generation)

    def claim(
        self,
        phase: str,
        event_id: str,
        *,
        request_digest: str,
        lease_seconds: int = 900,
    ) -> EventLease:
        try:
            from google.api_core.exceptions import NotFound, PreconditionFailed
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("google-api-core is required for GCS event state") from exc

        request_digest = _request_digest(request_digest)
        blob = self._blob(phase, event_id)
        for _ in range(8):
            now = time.time()
            token = _token()
            record = {
                "schema_version": 2,
                "phase": phase,
                "event_id": event_id,
                "status": "PROCESSING",
                "token": token,
                "lease_until": now + lease_seconds,
                "response": None,
                "next_payload": None,
                "message_id": None,
                "request_digest": request_digest,
                "updated_at": now,
            }
            try:
                blob.upload_from_string(
                    self._encode(record),
                    content_type="application/json",
                    if_generation_match=0,
                )
                blob.reload()
                return EventLease(
                    LeaseAction.PROCESS,
                    phase,
                    event_id,
                    token=token,
                    revision=int(blob.generation),
                    request_digest=request_digest,
                )
            except PreconditionFailed:
                pass

            try:
                existing, generation = self._read(blob)
            except NotFound:
                continue
            status = str(existing["status"])
            if (
                existing.get("schema_version") != 2
                or existing.get("phase") != phase
                or existing.get("event_id") != event_id
                or existing.get("request_digest") != request_digest
            ):
                raise EventConflict("event state identity or request digest does not match")
            response = existing.get("response")
            next_payload = existing.get("next_payload")
            if status == "COMPLETE":
                return EventLease(
                    LeaseAction.RETURN,
                    phase,
                    event_id,
                    revision=generation,
                    response=response,
                    next_payload=next_payload,
                    request_digest=request_digest,
                )
            lease_until = float(existing.get("lease_until") or 0.0)
            if status in {"PROCESSING", "DISPATCHING"} and lease_until > now:
                return EventLease(
                    LeaseAction.BUSY,
                    phase,
                    event_id,
                    revision=generation,
                    request_digest=request_digest,
                )
            if status in {"RESULT_READY", "DISPATCHING"}:
                action = LeaseAction.DISPATCH
                existing["status"] = "DISPATCHING"
            else:
                action = LeaseAction.PROCESS
                existing["status"] = "PROCESSING"
            existing["token"] = token
            existing["lease_until"] = now + lease_seconds
            existing["updated_at"] = now
            try:
                new_generation = self._write(blob, existing, generation)
            except PreconditionFailed:
                continue
            return EventLease(
                action,
                phase,
                event_id,
                token=token,
                revision=new_generation,
                response=response,
                next_payload=next_payload,
                request_digest=request_digest,
            )
        raise RuntimeError("could not acquire event lease after repeated CAS contention")

    def save_result(
        self,
        lease: EventLease,
        response: dict[str, Any],
        next_payload: dict[str, Any] | None,
    ) -> None:
        try:
            from google.api_core.exceptions import PreconditionFailed
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("google-api-core is required for GCS event state") from exc
        if (
            lease.action != LeaseAction.PROCESS
            or not lease.token
            or lease.revision is None
            or not lease.request_digest
        ):
            raise LeaseLost("result can only be saved by a processing lease")
        blob = self._blob(lease.phase, lease.event_id)
        record, generation = self._read(blob)
        if (
            generation != lease.revision
            or record.get("token") != lease.token
            or record.get("request_digest") != lease.request_digest
        ):
            raise LeaseLost("processing lease generation or token changed")
        record.update(
            {
                "status": "RESULT_READY" if next_payload is not None else "COMPLETE",
                "token": None,
                "lease_until": None,
                "response": response,
                "next_payload": next_payload,
                "updated_at": time.time(),
            }
        )
        try:
            self._write(blob, record, generation)
        except PreconditionFailed as exc:
            raise LeaseLost("processing lease was lost before result commit") from exc

    def abandon_retryable(self, lease: EventLease) -> None:
        try:
            from google.api_core.exceptions import PreconditionFailed
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("google-api-core is required for GCS event state") from exc
        expected_status, next_status, lease_until = _retry_transition(lease)
        if lease.revision is None:
            raise LeaseLost("retryable abandonment requires a generation-bound lease")
        blob = self._blob(lease.phase, lease.event_id)
        try:
            record, generation = self._read(blob)
        except PreconditionFailed as exc:
            raise LeaseLost("event lease changed before retryable abandonment") from exc
        if (
            generation != lease.revision
            or record.get("schema_version") != 2
            or record.get("phase") != lease.phase
            or record.get("event_id") != lease.event_id
            or record.get("status") != expected_status
            or record.get("token") != lease.token
            or record.get("request_digest") != lease.request_digest
        ):
            raise LeaseLost("event lease generation, token, or state changed")
        record.update(
            {
                "status": next_status,
                "token": None,
                "lease_until": lease_until,
                "updated_at": time.time(),
            }
        )
        try:
            self._write(blob, record, generation)
        except PreconditionFailed as exc:
            raise LeaseLost("event lease was lost before retryable abandonment") from exc

    def complete_dispatch(self, lease: EventLease, message_id: str) -> dict[str, Any]:
        try:
            from google.api_core.exceptions import PreconditionFailed
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("google-api-core is required for GCS event state") from exc
        if (
            lease.action != LeaseAction.DISPATCH
            or not lease.token
            or lease.revision is None
            or not lease.request_digest
        ):
            raise LeaseLost("dispatch can only be completed by a dispatch lease")
        blob = self._blob(lease.phase, lease.event_id)
        record, generation = self._read(blob)
        if (
            generation != lease.revision
            or record.get("token") != lease.token
            or record.get("request_digest") != lease.request_digest
        ):
            raise LeaseLost("dispatch lease generation or token changed")
        response = dict(record.get("response") or {})
        response["next_message_id"] = message_id
        record.update(
            {
                "status": "COMPLETE",
                "token": None,
                "lease_until": None,
                "response": response,
                "message_id": message_id,
                "updated_at": time.time(),
            }
        )
        try:
            self._write(blob, record, generation)
        except PreconditionFailed as exc:
            raise LeaseLost("dispatch lease was lost before completion") from exc
        return response
