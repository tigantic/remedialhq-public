from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remedialhq.collector import Snapshot
from remedialhq.phase_artifacts import ArtifactUnavailableError
from remedialhq.phases import PHASE_ORDER, run_phase
from remedialhq.source_registry import SourceRegistry, SourceSpec


def _materialized_snapshots(root: Path, destination: Path) -> int:
    registry = SourceRegistry.load(root / "config/sources.json")
    specs = registry.network_sources()
    for spec in specs:
        body = f"snapshot for {spec.source_id}\n".encode()
        digest = hashlib.sha256(body).hexdigest()
        directory = destination / spec.source_id / digest
        directory.mkdir(parents=True)
        (directory / "body.html").write_bytes(body)
        (directory / "metadata.json").write_text(
            json.dumps(
                {
                    "source_id": spec.source_id,
                    "canonical_url": spec.url,
                    "status": 200,
                    "content_type": "text/html",
                    "etag": None,
                    "last_modified": None,
                    "retrieved_at": "2026-08-30T00:00:00+00:00",
                    "rights_posture": spec.asset_rights,
                    "sha256": digest,
                    "bytes": len(body),
                }
            ),
            encoding="utf-8",
        )
    return len(specs)


def _registry_digest(root: Path) -> str:
    return hashlib.sha256((root / "config/sources.json").read_bytes()).hexdigest()


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

    def test_network_reconcile_requires_immutable_collect_artifact(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"ENABLE_NETWORK_COLLECTION": "true"},
            clear=False,
        ):
            result = run_phase("reconcile", root, directory)
        self.assertEqual(result.status, "REJECT")
        self.assertIn("immutable collect artifact", result.details["reason"])

    def test_verified_live_snapshots_hold_before_seed_compilation(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            count = _materialized_snapshots(root, temp / "snapshots")
            with patch.dict(
                os.environ,
                {"ENABLE_NETWORK_COLLECTION": "true"},
                clear=False,
            ):
                result = run_phase(
                    "reconcile",
                    root,
                    temp / "output",
                    upstream_snapshot_dir=temp / "snapshots",
                    upstream_registry_sha256=_registry_digest(root),
                )
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.details["reason"], "live_claim_extraction_not_implemented")
        self.assertEqual(result.details["snapshots_verified"], count)

    def test_live_snapshot_metadata_duplicate_field_is_rejected(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            _materialized_snapshots(root, temp / "snapshots")
            metadata = next((temp / "snapshots").glob("*/*/metadata.json"))
            value = json.loads(metadata.read_text(encoding="utf-8"))
            encoded = json.dumps(value)
            metadata.write_text(
                encoded[:-1] + ',"source_id":"duplicate"}',
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"ENABLE_NETWORK_COLLECTION": "true"},
                clear=False,
            ):
                result = run_phase(
                    "reconcile",
                    root,
                    temp / "output",
                    upstream_snapshot_dir=temp / "snapshots",
                    upstream_registry_sha256=_registry_digest(root),
                )
        self.assertEqual(result.status, "REJECT")
        self.assertEqual(result.details["reason"], "immutable collect artifact failed validation")

    def test_network_collect_result_contains_no_instance_local_paths(self) -> None:
        root = Path(__file__).resolve().parents[1]

        def collect(spec: SourceSpec) -> Snapshot:
            source_id = spec.source_id
            return Snapshot(
                source_id=source_id,
                retrieved_at="2026-08-30T00:00:00+00:00",
                sha256="a" * 64,
                bytes=7,
                content_type="text/html",
                body_path=f"/tmp/private/{source_id}/body.html",
                metadata_path=f"/tmp/private/{source_id}/metadata.json",
            )

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"ENABLE_NETWORK_COLLECTION": "true"},
            clear=False,
        ), patch("remedialhq.phases.TextSnapshotCollector.collect", side_effect=collect):
            result = run_phase("collect", root, directory)
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.details["mode"], "NETWORK_SNAPSHOT")
        self.assertEqual(result.details["source_registry_sha256"], _registry_digest(root))
        encoded = json.dumps(result.to_dict())
        self.assertNotIn("body_path", encoded)
        self.assertNotIn("metadata_path", encoded)
        self.assertNotIn("/tmp/private", encoded)

    def test_live_reconcile_binds_the_collect_source_registry_revision(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            _materialized_snapshots(root, temp / "snapshots")
            with patch.dict(
                os.environ,
                {"ENABLE_NETWORK_COLLECTION": "true"},
                clear=False,
            ):
                result = run_phase(
                    "reconcile",
                    root,
                    temp / "output",
                    upstream_snapshot_dir=temp / "snapshots",
                    upstream_registry_sha256="0" * 64,
                )
        self.assertEqual(result.status, "REJECT")
        self.assertEqual(result.details["reason"], "immutable collect artifact failed validation")

    def test_live_reconcile_does_not_load_seed_claims(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            _materialized_snapshots(root, temp / "snapshots")
            with patch.dict(
                os.environ,
                {"ENABLE_NETWORK_COLLECTION": "true"},
                clear=False,
            ), patch(
                "remedialhq.phases.load_claims",
                side_effect=AssertionError("seed claims must not be loaded"),
            ):
                result = run_phase(
                    "reconcile",
                    root,
                    temp / "output",
                    upstream_snapshot_dir=temp / "snapshots",
                    upstream_registry_sha256=_registry_digest(root),
                )
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.details["reason"], "live_claim_extraction_not_implemented")

    def test_live_reconcile_does_not_terminalize_transient_artifact_io(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            _materialized_snapshots(root, temp / "snapshots")
            with patch.dict(
                os.environ,
                {"ENABLE_NETWORK_COLLECTION": "true"},
                clear=False,
            ), patch(
                "remedialhq.phases.read_bounded_regular_file",
                side_effect=ArtifactUnavailableError("transient I/O failure"),
            ), self.assertRaises(ArtifactUnavailableError):
                run_phase(
                    "reconcile",
                    root,
                    temp / "output",
                    upstream_snapshot_dir=temp / "snapshots",
                    upstream_registry_sha256=_registry_digest(root),
                )


if __name__ == "__main__":
    unittest.main()
