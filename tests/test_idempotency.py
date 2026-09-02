import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from remedialhq.idempotency import (
    EventConflict,
    GCSEventStateStore,
    LeaseAction,
    LeaseLost,
    SQLiteEventStateStore,
    child_event_id,
    event_key,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def _fake_gcs() -> tuple[
    dict[str, ModuleType],
    dict[str, tuple[str, int]],
    list[int | None],
]:
    records: dict[str, tuple[str, int]] = {}
    uploads: list[int | None] = []

    class NotFound(Exception):
        pass

    class PreconditionFailed(Exception):
        pass

    class Blob:
        def __init__(self, name: str) -> None:
            self.name = name
            self.generation: int | None = None

        def upload_from_string(
            self,
            data: str,
            *,
            content_type: str,
            if_generation_match: int | None = None,
        ) -> None:
            del content_type
            uploads.append(if_generation_match)
            current = records.get(self.name)
            current_generation = current[1] if current is not None else 0
            if if_generation_match == 0:
                if current is not None:
                    raise PreconditionFailed("object already exists")
            elif if_generation_match != current_generation:
                raise PreconditionFailed("generation changed")
            generation = current_generation + 1
            records[self.name] = (data, generation)
            self.generation = generation

        def reload(self) -> None:
            try:
                self.generation = records[self.name][1]
            except KeyError as exc:
                raise NotFound("object is missing") from exc

        def download_as_text(self, *, if_generation_match: int | None = None) -> str:
            try:
                data, generation = records[self.name]
            except KeyError as exc:
                raise NotFound("object is missing") from exc
            if if_generation_match != generation:
                raise PreconditionFailed("generation changed")
            return data

    class Bucket:
        @staticmethod
        def blob(name: str) -> Blob:
            return Blob(name)

    class Client:
        @staticmethod
        def bucket(_name: str) -> Bucket:
            return Bucket()

    google = ModuleType("google")
    cloud = ModuleType("google.cloud")
    storage = ModuleType("google.cloud.storage")
    api_core = ModuleType("google.api_core")
    exceptions = ModuleType("google.api_core.exceptions")
    storage.Client = Client  # type: ignore[attr-defined]
    exceptions.NotFound = NotFound  # type: ignore[attr-defined]
    exceptions.PreconditionFailed = PreconditionFailed  # type: ignore[attr-defined]
    modules = {
        "google": google,
        "google.cloud": cloud,
        "google.cloud.storage": storage,
        "google.api_core": api_core,
        "google.api_core.exceptions": exceptions,
    }
    return modules, records, uploads


class IdempotencyTests(unittest.TestCase):
    def test_full_process_dispatch_return_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEventStateStore(Path(directory) / "state.sqlite3")
            first = store.claim(
                "collect",
                "root-1",
                request_digest=DIGEST_A,
                lease_seconds=30,
            )
            self.assertEqual(first.action, LeaseAction.PROCESS)
            self.assertEqual(
                store.claim("collect", "root-1", request_digest=DIGEST_A).action,
                LeaseAction.BUSY,
            )

            response = {"event_id": "root-1", "result": {"status": "PASS"}}
            next_payload = {"event_id": child_event_id("root-1", "reconcile")}
            store.save_result(first, response, next_payload)

            dispatch = store.claim("collect", "root-1", request_digest=DIGEST_A)
            self.assertEqual(dispatch.action, LeaseAction.DISPATCH)
            self.assertEqual(dispatch.next_payload, next_payload)
            terminal = store.complete_dispatch(dispatch, "pubsub-message-7")
            self.assertEqual(terminal["next_message_id"], "pubsub-message-7")

            duplicate = store.claim("collect", "root-1", request_digest=DIGEST_A)
            self.assertEqual(duplicate.action, LeaseAction.RETURN)
            self.assertEqual(duplicate.response["next_message_id"], "pubsub-message-7")

    def test_expired_processing_lease_is_reclaimed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEventStateStore(Path(directory) / "state.sqlite3")
            first = store.claim(
                "compile",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=0,
            )
            self.assertEqual(first.action, LeaseAction.PROCESS)
            time.sleep(0.01)
            second = store.claim(
                "compile",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=30,
            )
            self.assertEqual(second.action, LeaseAction.PROCESS)
            self.assertNotEqual(first.token, second.token)

    def test_sqlite_retryable_abandonment_is_immediate_and_token_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEventStateStore(Path(directory) / "state.sqlite3")
            processing = store.claim(
                "collect",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=3600,
            )
            store.abandon_retryable(processing)
            reclaimed = store.claim(
                "collect",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=3600,
            )
            self.assertEqual(reclaimed.action, LeaseAction.PROCESS)
            self.assertNotEqual(processing.token, reclaimed.token)
            with self.assertRaises(LeaseLost):
                store.abandon_retryable(processing)

            response = {"event_id": "event", "result": {"status": "PASS"}}
            next_payload = {"event_id": child_event_id("event", "reconcile")}
            store.save_result(reclaimed, response, next_payload)
            dispatch = store.claim("collect", "event", request_digest=DIGEST_A)
            self.assertEqual(dispatch.action, LeaseAction.DISPATCH)
            store.abandon_retryable(dispatch)
            redispatch = store.claim("collect", "event", request_digest=DIGEST_A)
            self.assertEqual(redispatch.action, LeaseAction.DISPATCH)
            self.assertEqual(redispatch.response, response)
            self.assertEqual(redispatch.next_payload, next_payload)
            with self.assertRaises(LeaseLost):
                store.abandon_retryable(dispatch)

    def test_derived_identities_are_stable_and_path_safe(self) -> None:
        a = child_event_id("../../unsafe", "gate")
        b = child_event_id("../../unsafe", "gate")
        c = child_event_id("../../unsafe", "publish")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("ev_"))
        self.assertEqual(len(event_key("../../unsafe")), 64)
        self.assertNotIn("/", event_key("../../unsafe"))

    def test_same_event_id_with_different_request_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEventStateStore(Path(directory) / "state.sqlite3")
            store.claim("reconcile", "event", request_digest=DIGEST_A)
            with self.assertRaises(EventConflict):
                store.claim("reconcile", "event", request_digest=DIGEST_B)

    def test_gcs_state_is_schema_v2_and_retries_require_the_same_digest(self) -> None:
        modules, records, uploads = _fake_gcs()
        with patch.dict(sys.modules, modules):
            store = GCSEventStateStore("state-bucket")
            first = store.claim(
                "reconcile",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=30,
            )
            self.assertEqual(first.action, LeaseAction.PROCESS)

            object_name = f"_state/events/reconcile/{event_key('event')}.json"
            record = json.loads(records[object_name][0])
            self.assertEqual(record["schema_version"], 2)
            self.assertEqual(record["request_digest"], DIGEST_A)
            self.assertEqual(
                store.claim("reconcile", "event", request_digest=DIGEST_A).action,
                LeaseAction.BUSY,
            )
            with self.assertRaises(EventConflict):
                store.claim("reconcile", "event", request_digest=DIGEST_B)

            store.save_result(first, {"status": "held"}, None)
            retry = store.claim("reconcile", "event", request_digest=DIGEST_A)
            self.assertEqual(retry.action, LeaseAction.RETURN)
            self.assertEqual(retry.response, {"status": "held"})

        self.assertTrue(uploads)
        self.assertEqual(uploads[0], 0)
        self.assertTrue(any(generation not in {None, 0} for generation in uploads))

    def test_gcs_generation_cas_prevents_a_reclaimed_lease_from_committing(self) -> None:
        modules, _records, uploads = _fake_gcs()
        with patch.dict(sys.modules, modules):
            store = GCSEventStateStore("state-bucket")
            first = store.claim(
                "collect",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=0,
            )
            second = store.claim(
                "collect",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=30,
            )
            self.assertEqual(second.action, LeaseAction.PROCESS)
            self.assertNotEqual(first.revision, second.revision)
            with self.assertRaises(LeaseLost):
                store.save_result(first, {"status": "stale"}, None)
            store.save_result(second, {"status": "current"}, None)
            retry = store.claim("collect", "event", request_digest=DIGEST_A)
            self.assertEqual(retry.action, LeaseAction.RETURN)
            self.assertEqual(retry.response, {"status": "current"})

        conditional_updates = [generation for generation in uploads if generation not in {None, 0}]
        self.assertGreaterEqual(len(conditional_updates), 2)

    def test_gcs_retryable_abandonment_is_immediate_and_generation_safe(self) -> None:
        modules, _records, uploads = _fake_gcs()
        with patch.dict(sys.modules, modules):
            store = GCSEventStateStore("state-bucket")
            processing = store.claim(
                "collect",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=3600,
            )
            store.abandon_retryable(processing)
            reclaimed = store.claim(
                "collect",
                "event",
                request_digest=DIGEST_A,
                lease_seconds=3600,
            )
            self.assertEqual(reclaimed.action, LeaseAction.PROCESS)
            self.assertNotEqual(processing.revision, reclaimed.revision)
            with self.assertRaises(LeaseLost):
                store.abandon_retryable(processing)

            response = {"event_id": "event", "result": {"status": "PASS"}}
            next_payload = {"event_id": child_event_id("event", "reconcile")}
            store.save_result(reclaimed, response, next_payload)
            dispatch = store.claim("collect", "event", request_digest=DIGEST_A)
            self.assertEqual(dispatch.action, LeaseAction.DISPATCH)
            store.abandon_retryable(dispatch)
            redispatch = store.claim("collect", "event", request_digest=DIGEST_A)
            self.assertEqual(redispatch.action, LeaseAction.DISPATCH)
            self.assertEqual(redispatch.response, response)
            self.assertEqual(redispatch.next_payload, next_payload)
            with self.assertRaises(LeaseLost):
                store.abandon_retryable(dispatch)

        conditional_updates = [generation for generation in uploads if generation not in {None, 0}]
        self.assertGreaterEqual(len(conditional_updates), 4)

    def test_gcs_legacy_schema_v1_record_fails_closed(self) -> None:
        modules, records, _uploads = _fake_gcs()
        object_name = f"_state/events/collect/{event_key('legacy-event')}.json"
        records[object_name] = (
            json.dumps(
                {
                    "schema_version": 1,
                    "phase": "collect",
                    "event_id": "legacy-event",
                    "status": "COMPLETE",
                    "response": {"status": "legacy"},
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            1,
        )
        with patch.dict(sys.modules, modules):
            store = GCSEventStateStore("state-bucket")
            with self.assertRaises(EventConflict):
                store.claim("collect", "legacy-event", request_digest=DIGEST_A)


if __name__ == "__main__":
    unittest.main()
