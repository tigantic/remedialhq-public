from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from remedialhq.auth import DEFAULT_YOUTUBE_SCOPES, _normalize_scopes, _write_private_json


class AuthorizationHelpersTests(unittest.TestCase):
    def test_default_scopes_include_upload_and_read(self) -> None:
        scopes = _normalize_scopes(None)
        self.assertEqual(scopes, DEFAULT_YOUTUBE_SCOPES)
        self.assertTrue(any(scope.endswith("youtube.upload") for scope in scopes))

    def test_private_json_is_written_with_restricted_permissions(self) -> None:
        secure_temp = "/tmp" if os.name == "posix" and Path("/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(dir=secure_temp) as directory:
            path = Path(directory) / "token.json"
            _write_private_json(path, {"refresh_token": "placeholder"})
            self.assertEqual(json.loads(path.read_text())["refresh_token"], "placeholder")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
