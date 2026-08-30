from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from remedialhq.ledger import HashLedger


class LedgerTests(unittest.TestCase):
    def test_append_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = HashLedger(Path(directory) / "ledger.jsonl")
            ledger.append("RUN_OPENED", {"run_id": "R1"}, occurred_at="2026-08-29T00:00:00Z")
            ledger.append("RUN_CLOSED", {"status": "PASS"}, occurred_at="2026-08-29T00:01:00Z")
            ok, message = ledger.verify()
            self.assertTrue(ok)
            self.assertEqual(message, "verified 2 records")
            self.assertNotEqual(ledger.head, ledger.GENESIS)

    def test_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            ledger = HashLedger(path)
            ledger.append("CLAIM_ADDED", {"claim": "truth"})
            row = json.loads(path.read_text(encoding="utf-8"))
            row["payload"]["claim"] = "altered"
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            ok, message = ledger.verify()
            self.assertFalse(ok)
            self.assertIn("hash mismatch", message)

    @unittest.skipIf(os.name != "posix", "POSIX permission check")
    def test_custom_file_mode_is_enforced(self) -> None:
        secure_temp_root = "/tmp" if Path("/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(dir=secure_temp_root) as directory:
            path = Path(directory) / "private-ledger.jsonl"
            ledger = HashLedger(path, mode=0o600)
            ledger.append("PRIVATE_EVENT", {"reference": "opaque"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
