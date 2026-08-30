from __future__ import annotations

import base64
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .canonical import sha256_json
from .idempotency import (
    GCSEventStateStore,
    LeaseAction,
    SQLiteEventStateStore,
    child_event_id,
    event_key,
)
from .phases import NEXT_PHASE, PHASE_ORDER, run_phase
from .pipeline import build_content_packages


def _decode_envelope(value: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    message = value.get("message") or {}
    fallback_id = str(message.get("messageId") or message.get("message_id") or "missing-event-id")
    raw = message.get("data")
    if not raw:
        return fallback_id, {}
    decoded = base64.b64decode(str(raw), validate=True).decode("utf-8")
    payload = json.loads(decoded)
    if not isinstance(payload, dict):
        raise TypeError("Pub/Sub message data must decode to a JSON object")
    event_id = str(payload.get("event_id") or fallback_id)
    if len(event_id) > 512:
        raise ValueError("event_id exceeds maximum length")
    return event_id, payload


def _publication_event_id(root: Path) -> str:
    packages = sorted(
        (package.to_dict() for package in build_content_packages(root)),
        key=lambda package: str(package["package_id"]),
    )
    authority = json.loads(
        (root / "config/publication_authority.json").read_text(encoding="utf-8")
    )
    runtime_authority = {
        name: os.environ.get(name, "")
        for name in (
            "PUBLISHING_ENABLED",
            "PUBLISH_TARGETS",
            "YOUTUBE_CREDENTIALS_READY",
            "YOUTUBE_EXPECTED_CHANNEL_ID",
            "YOUTUBE_LIVE_ADAPTER_ENABLED",
            "YOUTUBE_MEDIA_PATH",
            "YOUTUBE_PRIVACY_STATUS",
            "YOUTUBE_THUMBNAIL_PATH",
            "YOUTUBE_VISIBLE_PUBLICATION_AUTHORIZED",
        )
    }
    material = {
        "schema_version": 2,
        "packages": packages,
        "repository_authority": authority,
        "runtime_authority": runtime_authority,
    }
    return f"pub_{sha256_json(material)[:40]}"


def _next_payload(
    phase: str,
    event_id: str,
    payload: dict[str, Any],
    result: dict[str, Any],
    root: Path,
) -> dict[str, Any] | None:
    next_phase = NEXT_PHASE[phase]
    if next_phase is None or not os.environ.get("NEXT_TOPIC"):
        return None
    next_event_id = (
        _publication_event_id(root)
        if next_phase == "publish"
        else child_event_id(event_id, next_phase)
    )
    return {
        "event_id": next_event_id,
        "root_event_id": str(payload.get("root_event_id") or event_id),
        "parent_event_id": event_id,
        "from_phase": phase,
        "next_phase": next_phase,
        "phase_result": result,
    }


def _dispatch(payload: dict[str, Any]) -> str:
    topic = os.environ.get("NEXT_TOPIC")
    if not topic:
        raise RuntimeError("NEXT_TOPIC is required for dispatch")
    try:
        from google.cloud.pubsub_v1 import PublisherClient
    except ImportError as exc:  # pragma: no cover - cloud-only integration
        raise RuntimeError("google-cloud-pubsub is required for chained execution") from exc
    client = PublisherClient()
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    event_id = str(payload["event_id"])
    future = client.publish(topic, data, event_id=event_id, schema_version="1")
    return str(future.result(timeout=30))


def _state_store() -> GCSEventStateStore | SQLiteEventStateStore:
    bucket = os.environ.get("STATE_BUCKET")
    if bucket:
        return GCSEventStateStore(bucket)
    path = os.environ.get("STATE_DB", "/tmp/remedialhq/state/events.sqlite3")
    return SQLiteEventStateStore(path)


class Handler(BaseHTTPRequestHandler):
    server_version = "ReMediaLHQ/0.3"

    def do_GET(self) -> None:
        if self.path not in {"/", "/healthz"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self._json(
            HTTPStatus.OK,
            {
                "status": "ok",
                "phase": os.environ.get("PHASE"),
                "state_backend": "gcs" if os.environ.get("STATE_BUCKET") else "sqlite",
            },
        )

    def do_POST(self) -> None:
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                raise ValueError("invalid request size")
            envelope = json.loads(self.rfile.read(length))
            if not isinstance(envelope, dict):
                raise TypeError("request body must be a JSON object")
            event_id, payload = _decode_envelope(envelope)
            phase = os.environ["PHASE"]
            if phase not in PHASE_ORDER:
                raise ValueError("invalid PHASE")

            store = _state_store()
            lease = store.claim(
                phase,
                event_id,
                lease_seconds=3600 if phase == "publish" else 900,
            )
            if lease.action == LeaseAction.RETURN:
                cached_response = dict(lease.response or {})
                cached_response["duplicate_delivery"] = True
                self._json(HTTPStatus.OK, cached_response)
                return
            if lease.action == LeaseAction.BUSY:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"status": "retry", "event_id": event_id, "reason": "event lease is active"},
                )
                return
            if lease.action == LeaseAction.DISPATCH:
                if lease.next_payload is None:
                    raise RuntimeError("dispatch lease has no committed next payload")
                message_id = _dispatch(lease.next_payload)
                dispatch_response = store.complete_dispatch(lease, message_id)
                self._json(HTTPStatus.OK, dispatch_response)
                return

            workspace = (
                Path(os.environ.get("WORKSPACE", "/tmp/remedialhq"))
                / event_key(event_id)
                / phase
            )
            phase_result = run_phase(phase, os.environ.get("APP_ROOT", "."), workspace)
            phase_response: dict[str, Any] = {
                "event_id": event_id,
                "result": phase_result.to_dict(),
                "next_message_id": None,
                "duplicate_delivery": False,
            }
            next_payload = None
            if phase == "publish" and phase_result.status != "PASS":
                # A fail-closed HOLD is not a terminal publication result. Keeping the
                # lease uncommitted and returning a retryable status makes Pub/Sub
                # redeliver after the bounded lease expires.
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {
                        **phase_response,
                        "status": "retry",
                        "reason": "publication is held by fail-closed controls",
                    },
                )
                return
            if phase_result.status == "PASS":
                next_payload = _next_payload(
                    phase,
                    event_id,
                    payload,
                    phase_result.to_dict(),
                    Path(os.environ.get("APP_ROOT", ".")).resolve(),
                )
            store.save_result(lease, phase_response, next_payload)

            if next_payload is None:
                self._json(HTTPStatus.OK, phase_response)
                return
            dispatch_lease = store.claim(phase, event_id)
            if dispatch_lease.action != LeaseAction.DISPATCH or dispatch_lease.next_payload is None:
                raise RuntimeError("committed result could not acquire dispatch lease")
            message_id = _dispatch(dispatch_lease.next_payload)
            final_response = store.complete_dispatch(dispatch_lease, message_id)
            self._json(HTTPStatus.OK, final_response)
        except Exception as exc:  # noqa: BLE001 - HTTP boundary must fail closed for retries
            print(json.dumps({"status": "error", "error": type(exc).__name__}))
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "error", "error": type(exc).__name__},
            )

    def log_message(self, format: str, *args: Any) -> None:
        print(json.dumps({"remote": self.client_address[0], "message": format % args}))

    def _json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
        payload = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
