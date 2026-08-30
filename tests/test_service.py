from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest.mock import patch

from remedialhq.idempotency import EventLease, LeaseAction
from remedialhq.phases import PhaseResult
from remedialhq.service import Handler


class _Store:
    def __init__(self) -> None:
        self.saved = False

    @staticmethod
    def claim(phase: str, event_id: str, *, lease_seconds: int = 900) -> EventLease:
        if (phase, event_id, lease_seconds) != ("publish", "evt-1", 3600):
            raise AssertionError("unexpected lease request")
        return EventLease(LeaseAction.PROCESS, phase, event_id, token="lease-token")

    def save_result(self, *_args: object) -> None:
        self.saved = True


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
            },
            clear=False,
        ), patch("remedialhq.service._state_store", return_value=store), patch(
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
        emit.assert_called_once()
        _, status, body = emit.call_args.args
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertEqual(body["status"], "retry")
        self.assertEqual(body["result"]["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
