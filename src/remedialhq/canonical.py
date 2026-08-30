from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    '''Return deterministic JSON used for hashes and identities.'''
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_id(prefix: str, value: Any, length: int = 16) -> str:
    return f"{prefix}-{sha256_json(value)[:length].upper()}"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
