import tempfile
import time
import unittest
from pathlib import Path

from remedialhq.idempotency import (
    LeaseAction,
    SQLiteEventStateStore,
    child_event_id,
    event_key,
)


class IdempotencyTests(unittest.TestCase):
    def test_full_process_dispatch_return_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEventStateStore(Path(directory) / "state.sqlite3")
            first = store.claim("collect", "root-1", lease_seconds=30)
            self.assertEqual(first.action, LeaseAction.PROCESS)
            self.assertEqual(store.claim("collect", "root-1").action, LeaseAction.BUSY)

            response = {"event_id": "root-1", "result": {"status": "PASS"}}
            next_payload = {"event_id": child_event_id("root-1", "reconcile")}
            store.save_result(first, response, next_payload)

            dispatch = store.claim("collect", "root-1")
            self.assertEqual(dispatch.action, LeaseAction.DISPATCH)
            self.assertEqual(dispatch.next_payload, next_payload)
            terminal = store.complete_dispatch(dispatch, "pubsub-message-7")
            self.assertEqual(terminal["next_message_id"], "pubsub-message-7")

            duplicate = store.claim("collect", "root-1")
            self.assertEqual(duplicate.action, LeaseAction.RETURN)
            self.assertEqual(duplicate.response["next_message_id"], "pubsub-message-7")

    def test_expired_processing_lease_is_reclaimed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEventStateStore(Path(directory) / "state.sqlite3")
            first = store.claim("compile", "event", lease_seconds=0)
            self.assertEqual(first.action, LeaseAction.PROCESS)
            time.sleep(0.01)
            second = store.claim("compile", "event", lease_seconds=30)
            self.assertEqual(second.action, LeaseAction.PROCESS)
            self.assertNotEqual(first.token, second.token)

    def test_derived_identities_are_stable_and_path_safe(self) -> None:
        a = child_event_id("../../unsafe", "gate")
        b = child_event_id("../../unsafe", "gate")
        c = child_event_id("../../unsafe", "publish")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("ev_"))
        self.assertEqual(len(event_key("../../unsafe")), 64)
        self.assertNotIn("/", event_key("../../unsafe"))


if __name__ == "__main__":
    unittest.main()
