from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remedialhq.phases import PHASE_ORDER, run_phase


class PhaseTests(unittest.TestCase):
    def test_offline_phase_chain(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"ENABLE_NETWORK_COLLECTION": "false", "PUBLISHING_ENABLED": "false"}):
            statuses = {phase: run_phase(phase, root, directory).status for phase in PHASE_ORDER}
        self.assertEqual(statuses["collect"], "PASS")
        self.assertEqual(statuses["reconcile"], "PASS")
        self.assertEqual(statuses["compile"], "PASS")
        self.assertEqual(statuses["gate"], "PASS")
        self.assertEqual(statuses["publish"], "HOLD")
        self.assertEqual(statuses["measure"], "PASS")

    def test_enabled_publish_without_adapter_authority_holds(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "PUBLISHING_ENABLED": "true",
                "PUBLISH_TARGETS": "youtube",
                "YOUTUBE_LIVE_ADAPTER_ENABLED": "false",
            },
            clear=False,
        ):
            result = run_phase("publish", root, directory)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(len(result.details["held"]), 1)
        self.assertIn("YOUTUBE_LIVE_ADAPTER_ENABLED", result.details["held"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
