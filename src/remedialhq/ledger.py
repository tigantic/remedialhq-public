from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import sha256_json


class LedgerError(RuntimeError):
    pass


class HashLedger:
    '''Append-only hash-chained JSONL ledger.

    POSIX append + fsync protects individual writes; an in-process lock serializes
    callers. Production should use a single-writer queue or transactional uniqueness.
    '''

    GENESIS = "0" * 64

    def __init__(self, path: str | Path, *, mode: int = 0o640) -> None:
        if mode < 0 or mode > 0o777:
            raise ValueError("mode must be a POSIX permission value between 000 and 777")
        self.path = Path(path)
        self.mode = mode
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise LedgerError(f"invalid JSON at line {line_number}") from exc
        return records

    def append(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        if not event_type or not event_type.replace("_", "").isalnum():
            raise ValueError("event_type must be non-empty and machine-safe")
        with self._lock:
            records = self._records()
            previous_hash = records[-1]["hash"] if records else self.GENESIS
            record: dict[str, Any] = {
                "index": len(records),
                "occurred_at": occurred_at or datetime.now(UTC).isoformat(),
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous_hash,
            }
            record["hash"] = sha256_json(record)
            encoded = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, self.mode)
            try:
                os.fchmod(fd, self.mode)
                os.write(fd, encoded.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            return record

    def verify(self) -> tuple[bool, str]:
        records = self._records()
        if not records:
            return False, "ledger is missing or empty"
        previous = self.GENESIS
        for expected_index, record in enumerate(records):
            if record.get("index") != expected_index:
                return False, f"index mismatch at {expected_index}"
            if record.get("previous_hash") != previous:
                return False, f"chain mismatch at {expected_index}"
            claimed_hash = record.get("hash")
            body = {key: value for key, value in record.items() if key != "hash"}
            if claimed_hash != sha256_json(body):
                return False, f"hash mismatch at {expected_index}"
            previous = str(claimed_hash)
        return True, f"verified {len(records)} records"

    def iter_events(self, event_type: str | None = None) -> Iterable[dict[str, Any]]:
        for record in self._records():
            if event_type is None or record.get("event_type") == event_type:
                yield record

    @property
    def head(self) -> str:
        records = self._records()
        return records[-1]["hash"] if records else self.GENESIS
