from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest.mock import patch

from remedialhq.idempotency import (
    EventConflict,
    EventLease,
    LeaseAction,
    child_event_id,
    event_key,
)
from remedialhq.phase_artifacts import (
    ArtifactIntegrityError,
    ArtifactUnavailableError,
    LocalPhaseArtifactStore,
    PhaseArtifactRef,
)
from remedialhq.phases import PhaseResult
from remedialhq.service import (
    Handler,
    PermanentInputError,
    _collect_input,
    _decode_envelope,
    _dispatch,
    _lease_seconds,
    _next_payload,
    _request_identity_digest,
    _validate_collect_trigger,
)


class _Store:
    def __init__(self) -> None:
        self.saved = False
        self.abandoned = False

    @staticmethod
    def claim(
        phase: str,
        event_id: str,
        *,
        request_digest: str,
        lease_seconds: int = 900,
    ) -> EventLease:
        if (phase, event_id, lease_seconds) != ("publish", "evt-1", 3600):
            raise AssertionError("unexpected lease request")
        return EventLease(
            LeaseAction.PROCESS,
            phase,
            event_id,
            token="lease-token",
            request_digest=request_digest,
        )

    def save_result(self, *_args: object) -> None:
        self.saved = True

    def abandon_retryable(self, _lease: EventLease) -> None:
        self.abandoned = True


class ServiceHandlerTests(unittest.TestCase):
    def test_publish_hold_returns_retryable_status_without_committing_result(self) -> None:
        envelope = json.dumps({"message": {"messageId": "evt-1"}}).encode("utf-8")
        handler = object.__new__(Handler)
        handler.path = "/"
        handler.headers = {"Content-Length": str(len(envelope))}  # type: ignore[assignment]
        handler.rfile = io.BytesIO(envelope)  # type: ignore[assignment]
        store = _Store()

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "PHASE": "publish",
                "APP_ROOT": directory,
                "WORKSPACE": str(Path(directory) / "workspace"),
                "NEXT_TOPIC": "projects/test/topics/measure",
                "PUBLISHING_ENABLED": "false",
            },
            clear=False,
        ), patch("remedialhq.service._state_store", return_value=store), patch(
            "remedialhq.service._publication_event_id",
            return_value="evt-1",
        ), patch(
            "remedialhq.service.run_phase",
            return_value=PhaseResult(
                "publish",
                "HOLD",
                "2026-08-29T00:00:00+00:00",
                {"reason": "publication switch is false"},
            ),
        ), patch.object(Handler, "_json", autospec=True) as emit:
            Handler.do_POST(handler)

        self.assertFalse(store.saved)
        self.assertTrue(store.abandoned)
        emit.assert_called_once()
        _, status, body = emit.call_args.args
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertEqual(body["status"], "retry")
        self.assertEqual(body["result"]["status"], "HOLD")

    def test_missing_pubsub_identity_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _decode_envelope({"message": {}})

    def test_pubsub_payload_rejects_duplicate_fields_and_nonfinite_numbers(self) -> None:
        for raw in (
            b'{"event_id":"one","event_id":"two"}',
            b'{"event_id":"one","value":NaN}',
            b'{"event_id":123}',
            b'{"event_id":"one","value":' + (b"9" * 5_000) + b"}",
            b'{"event_id":"\\ud800"}',
            b'{"event_id":"one","phase_result":{"details":{"note":"\\ud800"}}}',
            b'{"event_id":"one","phase_result":{"details":{"\\ud800":"value"}}}',
        ):
            with self.subTest(raw=raw), self.assertRaises(PermanentInputError):
                _decode_envelope(
                    {
                        "message": {
                            "data": base64.b64encode(raw).decode("ascii"),
                            "messageId": "fallback",
                        }
                    }
                )

    def test_collect_trigger_is_exact_and_versioned(self) -> None:
        trigger = {
            "schema_version": 1,
            "trigger": "scheduler",
            "mode": "bounded",
            "phase": "collect",
        }
        _validate_collect_trigger(trigger)
        for field in trigger:
            altered = dict(trigger)
            altered.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                _validate_collect_trigger(altered)
        invalid_version = dict(trigger)
        invalid_version["schema_version"] = True
        with self.assertRaises(ValueError):
            _validate_collect_trigger(invalid_version)

    def test_collect_lease_exceeds_the_cloud_run_request_timeout(self) -> None:
        self.assertGreater(_lease_seconds("collect"), 1800)
        self.assertEqual(_lease_seconds("publish"), 3600)
        self.assertEqual(_lease_seconds("reconcile"), 1200)

    def test_publish_request_identity_collapses_lineage_only_replays(self) -> None:
        first = _request_identity_digest(
            "publish",
            "pub_material",
            {"root_event_id": "root-one", "phase_result": {"occurred_at": "one"}},
        )
        second = _request_identity_digest(
            "publish",
            "pub_material",
            {"root_event_id": "root-two", "phase_result": {"occurred_at": "two"}},
        )
        self.assertEqual(first, second)
        self.assertNotEqual(
            _request_identity_digest("reconcile", "event", {"root_event_id": "one"}),
            _request_identity_digest("reconcile", "event", {"root_event_id": "two"}),
        )

    def test_nonterminal_pass_requires_next_topic(self) -> None:
        result = PhaseResult(
            "collect",
            "PASS",
            "2026-08-30T00:00:00+00:00",
            {"mode": "REGISTRY_VALIDATION"},
        )
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
            _next_payload(
                "collect",
                "event-1",
                {},
                result.to_dict(),
                Path(__file__).resolve().parents[1],
            )

    def test_collect_handoff_root_cannot_be_forged_by_trigger_payload(self) -> None:
        result = PhaseResult(
            "collect",
            "PASS",
            "2026-08-30T00:00:00+00:00",
            {"mode": "REGISTRY_VALIDATION"},
        )
        with patch.dict(os.environ, {"NEXT_TOPIC": "topic"}, clear=False):
            payload = _next_payload(
                "collect",
                "actual-root",
                {"root_event_id": "forged-root"},
                result.to_dict(),
                Path(__file__).resolve().parents[1],
            )
        assert payload is not None
        self.assertEqual(payload["root_event_id"], "actual-root")

    def test_dispatch_advertises_the_actual_payload_schema(self) -> None:
        published: dict[str, object] = {}

        class Future:
            @staticmethod
            def result(*, timeout: int) -> str:
                self.assertEqual(timeout, 30)
                return "message-2"

        class Publisher:
            @staticmethod
            def publish(topic: str, data: bytes, **attributes: str) -> Future:
                published.update(
                    {"topic": topic, "body": json.loads(data), "attributes": attributes}
                )
                return Future()

        module = types.ModuleType("google.cloud.pubsub_v1")
        module.PublisherClient = Publisher  # type: ignore[attr-defined]
        with patch.dict(
            sys.modules,
            {"google.cloud.pubsub_v1": module},
        ), patch.dict(os.environ, {"NEXT_TOPIC": "topic"}, clear=False):
            message_id = _dispatch({"schema_version": 2, "event_id": "event"})
        self.assertEqual(message_id, "message-2")
        self.assertEqual(published["attributes"], {"event_id": "event", "schema_version": "2"})

    def test_reconcile_materializes_exact_collect_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            body = b"immutable\n"
            digest = hashlib.sha256(body).hexdigest()
            snapshot = source / "source-one" / digest
            snapshot.mkdir(parents=True)
            (snapshot / "body.txt").write_bytes(body)
            retrieved_at = "2026-08-30T00:00:00+00:00"
            (snapshot / "metadata.json").write_text(
                json.dumps(
                    {
                        "source_id": "source-one",
                        "canonical_url": "https://example.com/source",
                        "status": 200,
                        "content_type": "text/plain",
                        "etag": None,
                        "last_modified": None,
                        "retrieved_at": retrieved_at,
                        "rights_posture": "reference_only",
                        "sha256": digest,
                        "bytes": len(body),
                    }
                ),
                encoding="utf-8",
            )
            store = LocalPhaseArtifactStore(root / "store")
            result = PhaseResult(
                "collect",
                "PASS",
                "2026-08-30T00:00:00+00:00",
                {
                    "mode": "NETWORK_SNAPSHOT",
                    "source_registry_sha256": "b" * 64,
                    "snapshots": [
                        {
                            "source_id": "source-one",
                            "retrieved_at": retrieved_at,
                            "sha256": digest,
                            "bytes": len(body),
                            "content_type": "text/plain",
                        }
                    ],
                },
            )
            reference = store.commit(
                "collect-event",
                "collect-event",
                source,
                result.to_dict(),
            )
            reconcile_event = child_event_id("collect-event", "reconcile")
            payload = {
                "schema_version": 2,
                "event_id": reconcile_event,
                "root_event_id": "collect-event",
                "parent_event_id": "collect-event",
                "from_phase": "collect",
                "next_phase": "reconcile",
                "phase_artifact": reference.to_dict(),
            }
            with patch.dict(
                os.environ,
                {"ENABLE_NETWORK_COLLECTION": "true"},
                clear=False,
            ):
                destination, registry_digest = _collect_input(
                    reconcile_event,
                    payload,
                    store,
                    root / "workspace",
                )
            self.assertIsNotNone(destination)
            assert destination is not None
            self.assertEqual(registry_digest, "b" * 64)
            self.assertEqual(
                (destination / "source-one" / digest / "body.txt").read_bytes(),
                body,
            )

            payload["phase_artifact"] = {
                **reference.to_dict(),
                "manifest_sha256": "0" * 64,
            }
            with patch.dict(
                os.environ,
                {"ENABLE_NETWORK_COLLECTION": "true"},
                clear=False,
            ), self.assertRaises(ArtifactIntegrityError):
                _collect_input(
                    reconcile_event,
                    payload,
                    store,
                    root / "workspace-2",
                )

            payload["phase_artifact"] = reference.to_dict()
            payload["schema_version"] = 2.0
            with patch.dict(
                os.environ,
                {"ENABLE_NETWORK_COLLECTION": "true"},
                clear=False,
            ), self.assertRaises(ValueError):
                _collect_input(
                    reconcile_event,
                    payload,
                    store,
                    root / "workspace-3",
                )

    def test_event_conflict_is_terminally_acked_without_processing(self) -> None:
        envelope = json.dumps({"message": {"messageId": "evt-1"}}).encode("utf-8")
        handler = object.__new__(Handler)
        handler.path = "/"
        handler.headers = {"Content-Length": str(len(envelope))}  # type: ignore[assignment]
        handler.rfile = io.BytesIO(envelope)  # type: ignore[assignment]

        class Store:
            @staticmethod
            def claim(*_args: object, **_kwargs: object) -> EventLease:
                raise EventConflict("conflict")

        with patch.dict(
            os.environ,
            {"PHASE": "publish", "NEXT_TOPIC": "projects/test/topics/measure"},
            clear=False,
        ), patch(
            "remedialhq.service._publication_event_id",
            return_value="evt-1",
        ), patch(
            "remedialhq.service._state_store",
            return_value=Store(),
        ), patch.object(Handler, "_json", autospec=True) as emit:
            Handler.do_POST(handler)

        emit.assert_called_once()
        _, status, body = emit.call_args.args
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(body["status"], "REJECT")

    def test_post_publication_state_failure_keeps_reconciliation_lease(self) -> None:
        envelope = json.dumps({"message": {"messageId": "publish-event"}}).encode(
            "utf-8"
        )
        handler = object.__new__(Handler)
        handler.path = "/"
        handler.headers = {"Content-Length": str(len(envelope))}  # type: ignore[assignment]
        handler.rfile = io.BytesIO(envelope)  # type: ignore[assignment]
        abandoned: list[EventLease] = []

        class Store:
            @staticmethod
            def claim(
                phase: str,
                event_id: str,
                *,
                request_digest: str,
                lease_seconds: int = 900,
            ) -> EventLease:
                self.assertEqual(lease_seconds, 3600)
                return EventLease(
                    LeaseAction.PROCESS,
                    phase,
                    event_id,
                    token="token",
                    request_digest=request_digest,
                )

            @staticmethod
            def save_result(*_args: object) -> None:
                raise RuntimeError("state commit unavailable")

            @staticmethod
            def abandon_retryable(lease: EventLease) -> None:
                abandoned.append(lease)

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "PHASE": "publish",
                "APP_ROOT": directory,
                "WORKSPACE": str(Path(directory) / "workspace"),
                "NEXT_TOPIC": "projects/test/topics/measure",
                "PUBLISHING_ENABLED": "yes",
            },
            clear=False,
        ), patch(
            "remedialhq.service._publication_event_id",
            return_value="publish-event",
        ), patch("remedialhq.service._state_store", return_value=Store()), patch(
            "remedialhq.service.run_phase",
            return_value=PhaseResult(
                "publish",
                "PASS",
                "2026-08-30T00:00:00+00:00",
                {"published": [{"remote_id": "video"}], "held": []},
            ),
        ), patch.object(Handler, "_json", autospec=True) as emit:
            Handler.do_POST(handler)

        self.assertEqual(abandoned, [])
        _, status, body = emit.call_args.args
        self.assertEqual(status, HTTPStatus.INTERNAL_SERVER_ERROR)
        self.assertEqual(body["error"], "RuntimeError")

    def test_publish_event_id_must_match_current_publication_material(self) -> None:
        envelope = json.dumps({"message": {"messageId": "forged-publish-id"}}).encode(
            "utf-8"
        )
        handler = object.__new__(Handler)
        handler.path = "/"
        handler.headers = {"Content-Length": str(len(envelope))}  # type: ignore[assignment]
        handler.rfile = io.BytesIO(envelope)  # type: ignore[assignment]

        with patch.dict(os.environ, {"PHASE": "publish"}, clear=False), patch(
            "remedialhq.service._publication_event_id",
            return_value="expected-publish-id",
        ), patch("remedialhq.service._state_store") as state_store, patch.object(
            Handler,
            "_json",
            autospec=True,
        ) as emit:
            Handler.do_POST(handler)

        state_store.assert_not_called()
        _, status, body = emit.call_args.args
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(body["status"], "REJECT")

    def test_permanent_artifact_failure_is_committed_and_terminally_acked(self) -> None:
        reconcile_event = child_event_id("collect-event", "reconcile")
        payload = {
            "schema_version": 2,
            "event_id": reconcile_event,
            "root_event_id": "collect-event",
            "parent_event_id": "collect-event",
            "from_phase": "collect",
            "next_phase": "reconcile",
            "phase_artifact": {},
        }
        envelope = json.dumps(
            {
                "message": {
                    "data": base64.b64encode(json.dumps(payload).encode()).decode(),
                    "messageId": "transport-id",
                }
            }
        ).encode()
        handler = object.__new__(Handler)
        handler.path = "/"
        handler.headers = {"Content-Length": str(len(envelope))}  # type: ignore[assignment]
        handler.rfile = io.BytesIO(envelope)  # type: ignore[assignment]
        saved: list[tuple[dict[str, object], object]] = []
        abandoned: list[EventLease] = []

        class Store:
            @staticmethod
            def claim(
                phase: str,
                event_id: str,
                *,
                request_digest: str,
                lease_seconds: int = 900,
            ) -> EventLease:
                return EventLease(
                    LeaseAction.PROCESS,
                    phase,
                    event_id,
                    token="token",
                    request_digest=request_digest,
                )

            @staticmethod
            def save_result(
                _lease: EventLease,
                response: dict[str, object],
                next_payload: object,
            ) -> None:
                saved.append((response, next_payload))

            @staticmethod
            def abandon_retryable(lease: EventLease) -> None:
                abandoned.append(lease)

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "PHASE": "reconcile",
                "APP_ROOT": directory,
                "WORKSPACE": str(Path(directory) / "workspace"),
                "ENABLE_NETWORK_COLLECTION": "true",
            },
            clear=False,
        ), patch("remedialhq.service._state_store", return_value=Store()), patch(
            "remedialhq.service._artifact_store",
            return_value=object(),
        ), patch(
            "remedialhq.service._collect_input",
            side_effect=ArtifactIntegrityError("tampered"),
        ), patch.object(Handler, "_json", autospec=True) as emit:
            Handler.do_POST(handler)

        self.assertEqual(len(saved), 1)
        self.assertIsNone(saved[0][1])
        self.assertEqual(saved[0][0]["result"]["status"], "REJECT")  # type: ignore[index]
        self.assertEqual(abandoned, [])
        _, status, body = emit.call_args.args
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(body["status"], "REJECT")

    def test_transient_artifact_failure_is_released_for_retry(self) -> None:
        reconcile_event = child_event_id("collect-event", "reconcile")
        payload = {
            "schema_version": 2,
            "event_id": reconcile_event,
            "root_event_id": "collect-event",
            "parent_event_id": "collect-event",
            "from_phase": "collect",
            "next_phase": "reconcile",
            "phase_artifact": {},
        }
        envelope = json.dumps(
            {
                "message": {
                    "data": base64.b64encode(json.dumps(payload).encode()).decode(),
                    "messageId": "transport-id",
                }
            }
        ).encode()
        handler = object.__new__(Handler)
        handler.path = "/"
        handler.headers = {"Content-Length": str(len(envelope))}  # type: ignore[assignment]
        handler.rfile = io.BytesIO(envelope)  # type: ignore[assignment]
        saved: list[object] = []
        abandoned: list[EventLease] = []

        class Store:
            @staticmethod
            def claim(
                phase: str,
                event_id: str,
                *,
                request_digest: str,
                lease_seconds: int = 900,
            ) -> EventLease:
                return EventLease(
                    LeaseAction.PROCESS,
                    phase,
                    event_id,
                    token="token",
                    request_digest=request_digest,
                )

            @staticmethod
            def save_result(*args: object) -> None:
                saved.append(args)

            @staticmethod
            def abandon_retryable(lease: EventLease) -> None:
                abandoned.append(lease)

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "PHASE": "reconcile",
                "APP_ROOT": directory,
                "WORKSPACE": str(Path(directory) / "workspace"),
                "ENABLE_NETWORK_COLLECTION": "true",
            },
            clear=False,
        ), patch("remedialhq.service._state_store", return_value=Store()), patch(
            "remedialhq.service._artifact_store",
            return_value=object(),
        ), patch(
            "remedialhq.service._collect_input",
            side_effect=ArtifactUnavailableError("storage unavailable"),
        ), patch.object(Handler, "_json", autospec=True) as emit:
            Handler.do_POST(handler)

        self.assertEqual(saved, [])
        self.assertEqual(len(abandoned), 1)
        _, status, body = emit.call_args.args
        self.assertEqual(status, HTTPStatus.INTERNAL_SERVER_ERROR)
        self.assertEqual(body["error"], "ArtifactUnavailableError")

    def test_processing_failure_releases_lease_and_removes_request_workspace(self) -> None:
        envelope = json.dumps({"message": {"messageId": "evt-failure"}}).encode("utf-8")
        handler = object.__new__(Handler)
        handler.path = "/"
        handler.headers = {"Content-Length": str(len(envelope))}  # type: ignore[assignment]
        handler.rfile = io.BytesIO(envelope)  # type: ignore[assignment]
        abandoned: list[EventLease] = []
        used_workspaces: list[Path] = []

        class Store:
            @staticmethod
            def claim(
                phase: str,
                event_id: str,
                *,
                request_digest: str,
                lease_seconds: int = 900,
            ) -> EventLease:
                self.assertEqual((phase, event_id, lease_seconds), ("measure", "evt-failure", 1200))
                return EventLease(
                    LeaseAction.PROCESS,
                    phase,
                    event_id,
                    token="token",
                    request_digest=request_digest,
                )

            @staticmethod
            def abandon_retryable(lease: EventLease) -> None:
                abandoned.append(lease)

        def fail_phase(
            _phase: str,
            _root: str,
            output: Path,
            **_kwargs: object,
        ) -> PhaseResult:
            used_workspaces.append(Path(output))
            (Path(output) / "partial").mkdir(parents=True)
            raise RuntimeError("retryable")

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "PHASE": "measure",
                "APP_ROOT": directory,
                "WORKSPACE": str(Path(directory) / "workspace"),
            },
            clear=False,
        ), patch("remedialhq.service._state_store", return_value=Store()), patch(
            "remedialhq.service.run_phase",
            side_effect=fail_phase,
        ), patch.object(Handler, "_json", autospec=True) as emit:
            Handler.do_POST(handler)

        self.assertEqual(len(abandoned), 1)
        self.assertEqual(len(used_workspaces), 1)
        self.assertFalse(used_workspaces[0].exists())
        _, status, body = emit.call_args.args
        self.assertEqual(status, HTTPStatus.INTERNAL_SERVER_ERROR)
        self.assertEqual(body["error"], "RuntimeError")

    def test_collect_commits_artifact_before_state_and_dispatch(self) -> None:
        events: list[str] = []
        reference = PhaseArtifactRef(
            bucket="local-test-store",
            manifest_object=(
                f"phase-artifacts/v1/collect/{event_key('collect-event')}/manifest.json"
            ),
            manifest_generation=1,
            manifest_sha256="a" * 64,
            manifest_bytes=100,
            event_id="collect-event",
            root_event_id="collect-event",
        )

        class ArtifactStore:
            @staticmethod
            def find(event_id: str, root_event_id: str) -> None:
                self.assertEqual((event_id, root_event_id), ("collect-event", "collect-event"))
                events.append("artifact.find")

            @staticmethod
            def commit(
                event_id: str,
                root_event_id: str,
                _source: Path,
                _result: dict[str, object],
            ) -> PhaseArtifactRef:
                self.assertEqual((event_id, root_event_id), ("collect-event", "collect-event"))
                events.append("artifact.commit")
                return reference

        class StateStore:
            def __init__(self) -> None:
                self.claims = 0
                self.next_payload: dict[str, object] | None = None

            def claim(
                self,
                phase: str,
                event_id: str,
                *,
                request_digest: str,
                lease_seconds: int = 900,
            ) -> EventLease:
                self.claims += 1
                if self.claims == 1:
                    events.append("state.claim.process")
                    return EventLease(
                        LeaseAction.PROCESS,
                        phase,
                        event_id,
                        token="token",
                        request_digest=request_digest,
                    )
                events.append("state.claim.dispatch")
                return EventLease(
                    LeaseAction.DISPATCH,
                    phase,
                    event_id,
                    token="token-2",
                    next_payload=self.next_payload,
                    request_digest=request_digest,
                )

            def save_result(
                self,
                _lease: EventLease,
                _response: dict[str, object],
                next_payload: dict[str, object] | None,
            ) -> None:
                events.append("state.save")
                self.next_payload = next_payload

            @staticmethod
            def complete_dispatch(_lease: EventLease, message_id: str) -> dict[str, object]:
                events.append("state.complete")
                return {"next_message_id": message_id}

        state = StateStore()
        trigger = {
            "schema_version": 1,
            "trigger": "scheduler",
            "mode": "bounded",
            "phase": "collect",
        }
        envelope = json.dumps(
            {
                "message": {
                    "messageId": "collect-event",
                    "data": base64.b64encode(json.dumps(trigger).encode()).decode(),
                }
            }
        ).encode()
        handler = object.__new__(Handler)
        handler.path = "/"
        handler.headers = {"Content-Length": str(len(envelope))}  # type: ignore[assignment]
        handler.rfile = io.BytesIO(envelope)  # type: ignore[assignment]

        def execute_phase(*_args: object, **_kwargs: object) -> PhaseResult:
            events.append("phase.execute")
            return PhaseResult(
                "collect",
                "PASS",
                "2026-08-30T00:00:00+00:00",
                {"mode": "NETWORK_SNAPSHOT", "snapshots": []},
            )

        def dispatch(_payload: dict[str, object]) -> str:
            events.append("dispatch")
            return "message-1"

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "PHASE": "collect",
                "APP_ROOT": directory,
                "WORKSPACE": str(Path(directory) / "workspace"),
                "ENABLE_NETWORK_COLLECTION": "true",
                "NEXT_TOPIC": "projects/test/topics/reconcile",
            },
            clear=False,
        ), patch("remedialhq.service._state_store", return_value=state), patch(
            "remedialhq.service._artifact_store",
            return_value=ArtifactStore(),
        ), patch("remedialhq.service.run_phase", side_effect=execute_phase), patch(
            "remedialhq.service._dispatch",
            side_effect=dispatch,
        ), patch.object(Handler, "_json", autospec=True) as emit:
            Handler.do_POST(handler)

        self.assertEqual(
            events,
            [
                "state.claim.process",
                "artifact.find",
                "phase.execute",
                "artifact.commit",
                "state.save",
                "state.claim.dispatch",
                "dispatch",
                "state.complete",
            ],
        )
        emit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
