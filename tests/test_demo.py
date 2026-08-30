from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from remedialhq.pipeline import run_demo


class DemoTests(unittest.TestCase):
    def test_end_to_end_dry_run(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "demo"
            result = run_demo(root, output)
            self.assertTrue(result["ledger_verified"])
            self.assertEqual(len(result["packages"]), 4)
            self.assertTrue(all(row["gate"]["decision"] == "PASS" for row in result["packages"]))
            self.assertTrue((output / "run-report.json").is_file())
            self.assertTrue((output / "render/launch-claim-cards.svg").is_file())

    def test_existing_directory_without_sentinel_is_never_cleared(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            protected = output / "user-file.txt"
            protected.write_text("keep me", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sentinel"):
                run_demo(root, output)
            self.assertEqual(protected.read_text(encoding="utf-8"), "keep me")


if __name__ == "__main__":
    unittest.main()
