from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .canonical import sha256_json
from .idempotency import (
    EventConflict,
    EventLease,
    GCSEventStateStore,
    LeaseAction,
    SQLiteEventStateStore,
    child_event_id,
    event_key,
)
from .phase_artifacts import (
    ArtifactConflict,
    ArtifactIntegrityError,
    GCSPhaseArtifactStore,
    LocalPhaseArtifactStore,
    PhaseArtifactRef,
    PhaseArtifactStore,
)
from .phases import NEXT_PHASE, PHASE_ORDER, PhaseResult, run_phase
from .pipeline import build_content_packages


class PermanentInputError(ValueError):
    """Raised when retrying the same authenticated input cannot make it valid."""


def _validate_json_unicode(value: object, name: str) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise PermanentInputError(
                    f"{name} contains a string that is not valid Unicode"
                ) from exc
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def _strict_json_object(data: bytes, name: str) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PermanentInputError(f"{name} contains a duplicate JSON field")
            value[key] = item
        return value

    def invalid_constant(value: str) -> None:
        raise PermanentInputError(f"{name} contains an invalid JSON number: {value}")

    try:
        value = json.loads(
            data,
            object_pairs_hook=object_pairs,
            parse_constant=invalid_constant,
        )
    except PermanentInputError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PermanentInputError(f"{name} is not strict UTF-8 JSON") from exc
    _validate_json_unicode(value, name)
    if not isinstance(value, dict):
        raise PermanentInputError(f"{name} must decode to a JSON object")
    return value


def _strict_payload(data: bytes) -> dict[str, Any]:
    return _strict_json_object(data, "Pub/Sub data")


def _bounded_event_identity(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PermanentInputError(f"{name} must be a nonempty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PermanentInputError(f"{name} must contain valid Unicode") from exc
    if len(encoded) > 512:
        raise PermanentInputError(f"{name} exceeds 512 UTF-8 bytes")
    return value


def _decode_envelope(value: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    message_value = value.get("message")
    if not isinstance(message_value, dict):
        raise PermanentInputError("request body must contain one Pub/Sub message object")
    message = message_value
    fallback_value = message.get("messageId") or message.get("message_id")
    fallback_id = (
        _bounded_event_identity(fallback_value, "messageId")
        if fallback_value is not None
        else ""
    )
    raw = message.get("data")
    if raw is None or raw == "":
        if not fallback_id:
            raise PermanentInputError("messageId must contain 1 through 512 UTF-8 bytes")
        return fallback_id, {}
    if not isinstance(raw, str):
        raise PermanentInputError("Pub/Sub message data must be base64 text")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PermanentInputError("Pub/Sub message data is not valid base64") from exc
    payload = _strict_payload(decoded)
    if "event_id" in payload:
        payload_event_id = payload["event_id"]
        if not isinstance(payload_event_id, str):
            raise PermanentInputError("event_id must be a string")
        event_id = _bounded_event_identity(payload_event_id, "event_id")
    else:
        event_id = fallback_id
    if not event_id:
        raise PermanentInputError("event_id must contain 1 through 512 UTF-8 bytes")
    return event_id, payload


def _validate_collect_trigger(payload: dict[str, Any]) -> None:
    expected = {
        "schema_version": 1,
        "trigger": "scheduler",
        "mode": "bounded",
        "phase": "collect",
    }
    if type(payload.get("schema_version")) is not int or payload != expected:
        raise PermanentInputError("collect requires the exact scheduler trigger schema")


def _request_identity_digest(
    phase: str,
    event_id: str,
    payload: dict[str, Any],
) -> str:
    # Publish event IDs are already derived from the complete package and
    # publication-authority material. Treating lineage-only differences as a
    # new publish request would defeat external-side-effect idempotency.
    identity: dict[str, Any]
    if phase == "publish":
        identity = {
            "schema_version": 1,
            "phase": phase,
            "event_id": event_id,
            "identity": "publication_material",
        }
    else:
        identity = {
            "schema_version": 1,
            "phase": phase,
            "event_id": event_id,
            "payload": payload,
        }
    return sha256_json(
        identity
    )


def _lease_seconds(phase: str) -> int:
    # Keep each lease longer than the matching Cloud Run request timeout while
    # bounding crash recovery. Publish keeps a longer reconciliation window
    # because a remote side effect can succeed before local state is committed.
    if phase == "collect":
        return 2100
    if phase == "publish":
        return 3600
    return 1200


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
    phase_artifact: PhaseArtifactRef | None = None,
) -> dict[str, Any] | None:
    next_phase = NEXT_PHASE[phase]
    if next_phase is None:
        return None
    if not os.environ.get("NEXT_TOPIC"):
        raise RuntimeError("NEXT_TOPIC is required for a nonterminal PASS phase")
    next_event_id = (
        _publication_event_id(root)
        if next_phase == "publish"
        else child_event_id(event_id, next_phase)
    )
    root_event_id = event_id if phase == "collect" else str(
        payload.get("root_event_id") or event_id
    )
    common: dict[str, Any] = {
        "event_id": next_event_id,
        "root_event_id": root_event_id,
        "parent_event_id": event_id,
        "from_phase": phase,
        "next_phase": next_phase,
    }
    if phase == "collect":
        common.update(
            {
                "schema_version": 2,
                "phase_artifact": (
                    phase_artifact.to_dict() if phase_artifact is not None else None
                ),
            }
        )
        return common
    common.update({"schema_version": 1, "phase_result": result})
    return common


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
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or schema_version not in {1, 2}:
        raise ValueError("outbound payload schema_version is invalid")
    future = client.publish(
        topic,
        data,
        event_id=event_id,
        schema_version=str(schema_version),
    )
    return str(future.result(timeout=30))


def _state_store() -> GCSEventStateStore | SQLiteEventStateStore:
    bucket = os.environ.get("STATE_BUCKET")
    if bucket:
        return GCSEventStateStore(bucket)
    path = os.environ.get("STATE_DB", "/tmp/remedialhq/state/events.sqlite3")
    return SQLiteEventStateStore(path)


def _artifact_store() -> PhaseArtifactStore:
    bucket = os.environ.get("PHASE_ARTIFACT_BUCKET", "").strip()
    if bucket:
        return GCSPhaseArtifactStore(bucket)
    if os.environ.get("K_SERVICE") and os.environ.get("ENABLE_NETWORK_COLLECTION", "").casefold() == "true":
        raise RuntimeError("PHASE_ARTIFACT_BUCKET is required for live Cloud Run collection")
    directory = os.environ.get(
        "PHASE_ARTIFACT_DIRECTORY",
        "/tmp/remedialhq/phase-artifacts",
    )
    return LocalPhaseArtifactStore(directory)


def _collect_input(
    event_id: str,
    payload: dict[str, Any],
    store: PhaseArtifactStore,
    workspace: Path,
) -> tuple[Path | None, str | None]:
    required = {
        "schema_version",
        "event_id",
        "root_event_id",
        "parent_event_id",
        "from_phase",
        "next_phase",
        "phase_artifact",
    }
    if (
        set(payload) != required
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 2
    ):
        raise PermanentInputError("reconcile requires the strict collect handoff schema")
    string_fields = {
        key: payload.get(key)
        for key in (
            "event_id",
            "root_event_id",
            "parent_event_id",
            "from_phase",
            "next_phase",
        )
    }
    if any(not isinstance(value, str) or not value for value in string_fields.values()):
        raise PermanentInputError("collect handoff lineage fields must be nonempty strings")
    parent_event_id = str(string_fields["parent_event_id"])
    root_event_id = str(string_fields["root_event_id"])
    if (
        string_fields["event_id"] != event_id
        or payload.get("from_phase") != "collect"
        or payload.get("next_phase") != "reconcile"
        or not parent_event_id
        or root_event_id != parent_event_id
        or child_event_id(parent_event_id, "reconcile") != event_id
    ):
        raise PermanentInputError("collect handoff lineage is invalid")
    reference_value = payload.get("phase_artifact")
    network_enabled = os.environ.get("ENABLE_NETWORK_COLLECTION", "").casefold() == "true"
    if not network_enabled:
        if reference_value is not None:
            raise PermanentInputError(
                "offline registry validation cannot consume a live snapshot artifact"
            )
        return None, None
    reference = PhaseArtifactRef.from_dict(reference_value)
    if reference.event_id != parent_event_id or reference.root_event_id != root_event_id:
        raise PermanentInputError(
            "collect artifact reference belongs to a different event chain"
        )
    destination = workspace / "upstream"
    manifest = store.materialize(reference, destination)
    registry_digest = manifest.phase_result["details"]["source_registry_sha256"]
    return destination, str(registry_digest)


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
        request_workspace: tempfile.TemporaryDirectory[str] | None = None
        store: GCSEventStateStore | SQLiteEventStateStore | None = None
        active_lease: EventLease | None = None
        publication_may_have_occurred = False
        event_id = ""
        phase = ""
        try:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise PermanentInputError("Content-Length is invalid") from exc
            if length <= 0 or length > 1_000_000:
                raise PermanentInputError("invalid request size")
            envelope = _strict_json_object(self.rfile.read(length), "request body")
            event_id, payload = _decode_envelope(envelope)
            phase = os.environ["PHASE"]
            if phase not in PHASE_ORDER:
                raise RuntimeError("invalid PHASE")
            if phase == "collect":
                _validate_collect_trigger(payload)
            if phase == "publish":
                expected_event_id = _publication_event_id(
                    Path(os.environ.get("APP_ROOT", ".")).resolve()
                )
                if event_id != expected_event_id:
                    raise PermanentInputError(
                        "publish event identity does not match publication material"
                    )
                if not os.environ.get("NEXT_TOPIC"):
                    raise RuntimeError("NEXT_TOPIC is required before publication")
            request_digest = _request_identity_digest(phase, event_id, payload)

            store = _state_store()
            lease = store.claim(
                phase,
                event_id,
                request_digest=request_digest,
                lease_seconds=_lease_seconds(phase),
            )
            if lease.action in {LeaseAction.PROCESS, LeaseAction.DISPATCH}:
                active_lease = lease
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
                active_lease = None
                self._json(HTTPStatus.OK, dispatch_response)
                return

            workspace_base = Path(os.environ.get("WORKSPACE", "/tmp/remedialhq"))
            workspace_base.mkdir(parents=True, exist_ok=True)
            if workspace_base.is_symlink() or not workspace_base.is_dir():
                raise RuntimeError("WORKSPACE must be a real directory")
            request_workspace = tempfile.TemporaryDirectory(
                prefix=f"{event_key(event_id)}-{phase}-",
                dir=workspace_base,
            )
            workspace = Path(request_workspace.name)
            phase_artifact: PhaseArtifactRef | None = None
            upstream_snapshot_dir: Path | None = None
            upstream_registry_sha256: str | None = None
            network_enabled = (
                os.environ.get("ENABLE_NETWORK_COLLECTION", "").casefold() == "true"
            )
            artifact_store: PhaseArtifactStore | None = None
            if (phase == "collect" and network_enabled) or phase == "reconcile":
                artifact_store = _artifact_store()

            if phase == "collect" and network_enabled:
                if artifact_store is None:  # pragma: no cover - guarded above
                    raise RuntimeError("phase artifact store is unavailable")
                phase_artifact = artifact_store.find(event_id, event_id)
                if phase_artifact is not None:
                    committed = artifact_store.read_manifest(phase_artifact)
                    phase_result = PhaseResult.from_dict(committed.phase_result)
                else:
                    collect_attempt = workspace / "collect"
                    phase_result = run_phase(
                        phase,
                        os.environ.get("APP_ROOT", "."),
                        collect_attempt,
                    )
                    if phase_result.status == "PASS":
                        phase_artifact = artifact_store.commit(
                            event_id,
                            event_id,
                            collect_attempt / "snapshots",
                            phase_result.to_dict(),
                        )
            else:
                if phase == "reconcile":
                    if artifact_store is None:  # pragma: no cover - guarded above
                        raise RuntimeError("phase artifact store is unavailable")
                    upstream_snapshot_dir, upstream_registry_sha256 = _collect_input(
                        event_id,
                        payload,
                        artifact_store,
                        workspace,
                    )
                if phase == "publish" and os.environ.get(
                    "PUBLISHING_ENABLED",
                    "",
                ).casefold() in {"1", "true", "yes", "on"}:
                    publication_may_have_occurred = True
                phase_result = run_phase(
                    phase,
                    os.environ.get("APP_ROOT", "."),
                    workspace,
                    upstream_snapshot_dir=upstream_snapshot_dir,
                    upstream_registry_sha256=upstream_registry_sha256,
                )
            phase_response: dict[str, Any] = {
                "event_id": event_id,
                "result": phase_result.to_dict(),
                "phase_artifact": (
                    phase_artifact.to_dict() if phase_artifact is not None else None
                ),
                "next_message_id": None,
                "duplicate_delivery": False,
            }
            next_payload = None
            if phase == "publish" and phase_result.status != "PASS":
                # A fail-closed HOLD is not a terminal publication result. Release
                # the token before returning a retryable status so normal failures
                # do not leave the event BUSY for the full crash-recovery lease.
                if not publication_may_have_occurred:
                    store.abandon_retryable(lease)
                    active_lease = None
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
                    phase_artifact,
                )
            store.save_result(lease, phase_response, next_payload)
            active_lease = None

            if next_payload is None:
                self._json(HTTPStatus.OK, phase_response)
                return
            dispatch_lease = store.claim(
                phase,
                event_id,
                request_digest=request_digest,
            )
            active_lease = dispatch_lease
            if dispatch_lease.action != LeaseAction.DISPATCH or dispatch_lease.next_payload is None:
                raise RuntimeError("committed result could not acquire dispatch lease")
            message_id = _dispatch(dispatch_lease.next_payload)
            final_response = store.complete_dispatch(dispatch_lease, message_id)
            active_lease = None
            self._json(HTTPStatus.OK, final_response)
        except EventConflict:
            self._json(
                HTTPStatus.OK,
                {
                    "status": "REJECT",
                    "reason": "event identity conflicts with committed request material",
                },
            )
        except (PermanentInputError, ArtifactConflict, ArtifactIntegrityError):
            if (
                store is not None
                and active_lease is not None
                and active_lease.action == LeaseAction.PROCESS
            ):
                rejection_lease = active_lease
                rejection = {
                    "event_id": event_id,
                    "result": PhaseResult(
                        phase,
                        "REJECT",
                        datetime.now(UTC).isoformat(),
                        {"reason": "permanent input validation failed"},
                    ).to_dict(),
                    "phase_artifact": None,
                    "next_message_id": None,
                    "duplicate_delivery": False,
                }
                try:
                    store.save_result(rejection_lease, rejection, None)
                    active_lease = None
                except Exception as exc:  # noqa: BLE001 - state failure must retry
                    with suppress(Exception):
                        store.abandon_retryable(rejection_lease)
                    print(json.dumps({"status": "error", "error": type(exc).__name__}))
                    self._json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"status": "error", "error": type(exc).__name__},
                    )
                    return
            self._json(
                HTTPStatus.OK,
                {
                    "status": "REJECT",
                    "reason": "permanent input validation failed",
                },
            )
        except Exception as exc:  # noqa: BLE001 - HTTP boundary must fail closed for retries
            if (
                store is not None
                and active_lease is not None
                and not publication_may_have_occurred
            ):
                with suppress(Exception):
                    store.abandon_retryable(active_lease)
            print(json.dumps({"status": "error", "error": type(exc).__name__}))
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "error", "error": type(exc).__name__},
            )
        finally:
            if request_workspace is not None:
                request_workspace.cleanup()

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
