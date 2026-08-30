from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Self

from remedialhq.collector import CollectionError, TextSnapshotCollector
from remedialhq.source_registry import SourceRegistry, SourceSpec


class _Headers:
    @staticmethod
    def get_content_type() -> str:
        return "text/plain"

    @staticmethod
    def get(_name: str) -> None:
        return None


class _Response:
    status = 200
    headers = _Headers()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    @staticmethod
    def read(_limit: int) -> bytes:
        return b"trusted source body\n"


class _Opener:
    @staticmethod
    def open(_request: object, timeout: int) -> _Response:
        if timeout != 30:
            raise AssertionError("unexpected collection timeout")
        return _Response()


class SourceRegistryTests(unittest.TestCase):
    def test_default_deny_registry(self) -> None:
        root = Path(__file__).resolve().parents[1]
        registry = SourceRegistry.load(root / "config/sources.json")
        self.assertGreaterEqual(len(registry.allowed()), 4)
        spec = registry.authorize_url("https://www.rockstargames.com/VI/")
        self.assertEqual(spec.source_id, "rockstar-gta6-official")
        provider = registry.authorize_url(
            "connected://vidiq/keyword-research/2026-08-28"
        )
        self.assertEqual(provider.tier, "AUDIENCE_RESEARCH_PROVIDER")
        self.assertNotIn(provider, registry.network_sources())
        with self.assertRaises(PermissionError):
            registry.authorize_url("https://example.com/leak")

    def test_non_deny_config_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.json"
            path.write_text('{"default_policy":"allow","sources":[]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                SourceRegistry.load(path)

    def test_string_false_cannot_enable_a_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.json"
            path.write_text(
                '{"default_policy":"deny","sources":[{'
                '"id":"unsafe","name":"Unsafe","url":"https://example.com",'
                '"tier":"FIRST_PARTY","collection":"http",'
                '"asset_rights":"TEXT_FACTS_ONLY","poll_minutes":60,"allowed":"false"}]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(TypeError, "must be a JSON boolean"):
                SourceRegistry.load(path)

    def test_source_ids_are_ascii_machine_safe(self) -> None:
        unsafe_ids = (
            "../escape",
            "/absolute",
            "nested/source",
            "nested\\source",
            "unicode\u2215separator",
            "line\nbreak",
            "UPPERCASE",
            "-leading",
            "trailing-",
            "a" * 65,
        )
        for source_id in unsafe_ids:
            with self.subTest(source_id=source_id), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "sources.json"
                path.write_text(
                    json.dumps(
                        {
                            "default_policy": "deny",
                            "sources": [
                                {
                                    "id": source_id,
                                    "name": "Unsafe",
                                    "url": "https://example.com",
                                    "tier": "FIRST_PARTY",
                                    "collection": "http",
                                    "asset_rights": "TEXT_FACTS_ONLY",
                                    "poll_minutes": 60,
                                    "allowed": True,
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "source ID must contain"):
                    SourceRegistry.load(path)

    def test_collector_revalidates_direct_source_specs_before_network_access(self) -> None:
        source = SourceSpec(
            source_id="../escape",
            name="Unsafe",
            url="https://example.com",
            tier="FIRST_PARTY",
            collection="http",
            asset_rights="TEXT_FACTS_ONLY",
            poll_minutes=60,
            allowed=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            collector = TextSnapshotCollector(Path(directory) / "snapshots")
            with self.assertRaisesRegex(ValueError, "source ID must contain"):
                collector.collect(source)
            self.assertFalse((Path(directory) / "escape").exists())

    def test_collector_writes_safe_source_only_below_output_root(self) -> None:
        source = SourceSpec(
            source_id="safe-source",
            name="Safe",
            url="https://example.com",
            tier="FIRST_PARTY",
            collection="http",
            asset_rights="TEXT_FACTS_ONLY",
            poll_minutes=60,
            allowed=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "snapshots"
            collector = TextSnapshotCollector(output)
            collector._opener = _Opener()  # type: ignore[assignment]

            snapshot = collector.collect(source)

            body_path = Path(snapshot.body_path).resolve()
            metadata_path = Path(snapshot.metadata_path).resolve()
            body_path.relative_to(output.resolve())
            metadata_path.relative_to(output.resolve())
            self.assertEqual(body_path.read_bytes(), b"trusted source body\n")

    def test_collector_rejects_source_directory_symlinks(self) -> None:
        source = SourceSpec(
            source_id="safe-source",
            name="Safe",
            url="https://example.com",
            tier="FIRST_PARTY",
            collection="http",
            asset_rights="TEXT_FACTS_ONLY",
            poll_minutes=60,
            allowed=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "snapshots"
            outside = root / "outside"
            output.mkdir()
            outside.mkdir()
            try:
                (output / source.source_id).symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")
            collector = TextSnapshotCollector(output)
            collector._opener = _Opener()  # type: ignore[assignment]

            with self.assertRaisesRegex(CollectionError, "must not be a symbolic link"):
                collector.collect(source)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
