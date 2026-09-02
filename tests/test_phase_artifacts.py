from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from remedialhq.canonical import sha256_bytes
from remedialhq.phase_artifacts import (
    ArtifactConflict,
    ArtifactIntegrityError,
    ArtifactUnavailableError,
    GCSPhaseArtifactStore,
    LocalPhaseArtifactStore,
    PhaseArtifactFile,
    PhaseArtifactManifest,
    read_bounded_regular_file,
)

SNAPSHOT_BODY = b"trusted source body\n"
SNAPSHOT_DIGEST = sha256_bytes(SNAPSHOT_BODY)
RETRIEVED_AT = "2026-08-30T00:00:00+00:00"


def _phase_result() -> dict[str, object]:
    return {
        "phase": "collect",
        "status": "PASS",
        "occurred_at": RETRIEVED_AT,
        "details": {
            "mode": "NETWORK_SNAPSHOT",
            "source_registry_sha256": "f" * 64,
            "snapshots": [
                {
                    "source_id": "official-source",
                    "retrieved_at": RETRIEVED_AT,
                    "sha256": SNAPSHOT_DIGEST,
                    "bytes": len(SNAPSHOT_BODY),
                    "content_type": "text/plain",
                }
            ],
        },
    }


def _snapshot_source(root: Path) -> Path:
    source = root / "source"
    directory = source / "official-source" / SNAPSHOT_DIGEST
    directory.mkdir(parents=True)
    (directory / "body.txt").write_bytes(SNAPSHOT_BODY)
    (directory / "metadata.json").write_text(
        json.dumps(
            {
                "source_id": "official-source",
                "canonical_url": "https://example.test/official",
                "status": 200,
                "content_type": "text/plain",
                "etag": None,
                "last_modified": None,
                "retrieved_at": RETRIEVED_AT,
                "rights_posture": "TEXT_FACTS_ONLY",
                "sha256": SNAPSHOT_DIGEST,
                "bytes": len(SNAPSHOT_BODY),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return source


class PhaseArtifactTests(unittest.TestCase):
    def test_commit_find_and_materialize_are_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = LocalPhaseArtifactStore(root / "store")
            source = _snapshot_source(root)
            reference = store.commit("event-1", "event-1", source, _phase_result())

            recovered = store.find("event-1", "event-1")
            self.assertEqual(recovered, reference)
            manifest = store.materialize(reference, root / "materialized")
            self.assertEqual(len(manifest.files), 2)
            self.assertEqual(
                (root / "materialized/official-source" / SNAPSHOT_DIGEST / "body.txt").read_bytes(),
                SNAPSHOT_BODY,
            )

    def test_identical_retry_reuses_manifest_but_changed_retry_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = LocalPhaseArtifactStore(root / "store")
            source = _snapshot_source(root)
            first = store.commit("event-1", "event-1", source, _phase_result())
            second = store.commit("event-1", "event-1", source, _phase_result())
            self.assertEqual(first, second)

            metadata_path = source / "official-source" / SNAPSHOT_DIGEST / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["canonical_url"] = "https://example.test/changed"
            metadata_path.write_text(json.dumps(metadata, sort_keys=True), encoding="utf-8")
            with self.assertRaises(ArtifactConflict):
                store.commit("event-1", "event-1", source, _phase_result())

    def test_manifest_tampering_and_cross_store_reference_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = LocalPhaseArtifactStore(root / "store")
            reference = store.commit(
                "event-1",
                "event-1",
                _snapshot_source(root),
                _phase_result(),
            )
            with self.assertRaises(ArtifactIntegrityError):
                store.read_manifest(replace(reference, bucket="foreign-bucket"))

            manifest_path = store.root.joinpath(*reference.manifest_object.split("/"))
            manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
            with self.assertRaises(ArtifactIntegrityError):
                store.read_manifest(reference)

    def test_file_tampering_is_detected_before_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = LocalPhaseArtifactStore(root / "store")
            reference = store.commit(
                "event-1",
                "event-1",
                _snapshot_source(root),
                _phase_result(),
            )
            manifest = store.read_manifest(reference)
            object_path = store.root.joinpath(*manifest.files[0].object.split("/"))
            object_path.write_bytes(b"tampered")
            destination = root / "materialized"
            with self.assertRaises(ArtifactIntegrityError):
                store.materialize(reference, destination)
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.glob(".materialized.tmp-*")), [])

            missing_reference = store.commit(
                "event-2",
                "event-2",
                root / "source",
                _phase_result(),
            )
            missing_manifest = store.read_manifest(missing_reference)
            missing_object = store.root.joinpath(
                *missing_manifest.files[0].object.split("/")
            )
            missing_object.unlink()
            missing_destination = root / "missing-materialization"
            with self.assertRaises(ArtifactIntegrityError):
                store.materialize(missing_reference, missing_destination)
            self.assertFalse(missing_destination.exists())
            self.assertEqual(list(root.glob(".missing-materialization.tmp-*")), [])

    def test_manifest_rejects_duplicate_fields_noncanonical_json_and_traversal(self) -> None:
        duplicate = (
            b'{"schema_version":"remedialhq.phase-artifact.v1",'
            b'"schema_version":"remedialhq.phase-artifact.v1"}'
        )
        with self.assertRaises(ArtifactIntegrityError):
            PhaseArtifactManifest.from_bytes(duplicate)
        with self.assertRaises(ArtifactIntegrityError):
            PhaseArtifactManifest.from_bytes(b'{"value":NaN}')
        with self.assertRaises(ArtifactIntegrityError):
            PhaseArtifactFile(
                path="../escape",
                object="phase-artifacts/v1/collect/file",
                generation=1,
                sha256="a" * 64,
                bytes=1,
                content_type="text/plain",
            )

    def test_manifest_requires_root_snapshot_result_and_exact_file_coherence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = LocalPhaseArtifactStore(root / "store")
            reference = store.commit(
                "event-1",
                "event-1",
                _snapshot_source(root),
                _phase_result(),
            )
            manifest = store.read_manifest(reference)

            with self.assertRaises(ArtifactIntegrityError):
                replace(manifest, parent_manifest_sha256="a" * 64)

            missing_registry = json.loads(json.dumps(manifest.phase_result))
            del missing_registry["details"]["source_registry_sha256"]
            with self.assertRaises(ArtifactIntegrityError):
                replace(manifest, phase_result=missing_registry)

            extra_detail = json.loads(json.dumps(manifest.phase_result))
            extra_detail["details"]["unexpected"] = True
            with self.assertRaises(ArtifactIntegrityError):
                replace(manifest, phase_result=extra_detail)

            unsorted = json.loads(json.dumps(manifest.phase_result))
            second = dict(unsorted["details"]["snapshots"][0])
            second["source_id"] = "another-source"
            unsorted["details"]["snapshots"].append(second)
            with self.assertRaises(ArtifactIntegrityError):
                replace(manifest, phase_result=unsorted)

            duplicate = json.loads(json.dumps(manifest.phase_result))
            duplicate["details"]["snapshots"].append(
                dict(duplicate["details"]["snapshots"][0])
            )
            with self.assertRaises(ArtifactIntegrityError):
                replace(manifest, phase_result=duplicate)

            body_index = next(
                index
                for index, entry in enumerate(manifest.files)
                if Path(entry.path).name != "metadata.json"
            )
            mismatched_files = list(manifest.files)
            mismatched_files[body_index] = replace(
                mismatched_files[body_index],
                content_type="text/html",
            )
            with self.assertRaises(ArtifactIntegrityError):
                replace(manifest, files=tuple(mismatched_files))

    def test_commit_rejects_metadata_and_body_summary_mismatches(self) -> None:
        for field, value in (("bytes", len(SNAPSHOT_BODY) + 1), ("bytes", True)):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = _snapshot_source(root)
                metadata_path = source / "official-source" / SNAPSHOT_DIGEST / "metadata.json"
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                metadata[field] = value
                metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
                store = LocalPhaseArtifactStore(root / "store")
                with self.assertRaises(ArtifactIntegrityError):
                    store.commit("event-1", "event-1", source, _phase_result())

    def test_bounded_reader_rejects_oversize_and_symlink_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular.bin"
            regular.write_bytes(b"abcd")
            self.assertEqual(
                read_bounded_regular_file(regular, maximum=4, name="test file"),
                b"abcd",
            )
            with self.assertRaises(ArtifactIntegrityError):
                read_bounded_regular_file(regular, maximum=3, name="test file")

            leaf_link = root / "leaf-link"
            leaf_link.symlink_to(regular)
            with self.assertRaises(ArtifactIntegrityError):
                read_bounded_regular_file(leaf_link, maximum=4, name="test file")

            real_parent = root / "real-parent"
            real_parent.mkdir()
            nested = real_parent / "nested.bin"
            nested.write_bytes(b"safe")
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(ArtifactIntegrityError):
                read_bounded_regular_file(
                    linked_parent / "nested.bin",
                    maximum=4,
                    name="test file",
                )

    def test_source_traversal_enforces_limits_before_unbounded_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _snapshot_source(root)
            import remedialhq.phase_artifacts as artifacts

            original_reader = artifacts.read_bounded_regular_file
            with (
                patch.object(artifacts, "MAX_FILES", 1),
                patch.object(artifacts, "read_bounded_regular_file", wraps=original_reader) as reader,
                self.assertRaises(ArtifactIntegrityError),
            ):
                LocalPhaseArtifactStore(root / "store").commit(
                    "event-1",
                    "event-1",
                    source,
                    _phase_result(),
                )
            self.assertEqual(reader.call_count, 1)

            with (
                patch.object(artifacts, "MAX_TRAVERSAL_ENTRIES", 1),
                patch.object(artifacts, "read_bounded_regular_file", wraps=original_reader) as reader,
                self.assertRaises(ArtifactIntegrityError),
            ):
                LocalPhaseArtifactStore(root / "other-store").commit(
                    "event-2",
                    "event-2",
                    source,
                    _phase_result(),
                )
            self.assertEqual(reader.call_count, 0)

    def test_local_publication_links_only_fsynced_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _snapshot_source(root)
            real_link = os.link
            observations: list[tuple[bool, bool]] = []

            def inspect_link(
                source_path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                destination_path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                follow_symlinks: bool = True,
            ) -> None:
                temporary = Path(source_path)
                destination = Path(destination_path)
                observations.append((temporary.is_file(), destination.exists()))
                self.assertIn(".tmp-", temporary.name)
                self.assertGreaterEqual(temporary.stat().st_nlink, 1)
                real_link(
                    source_path,
                    destination_path,
                    follow_symlinks=follow_symlinks,
                )

            with patch("remedialhq.phase_artifacts.os.link", side_effect=inspect_link):
                store = LocalPhaseArtifactStore(root / "store")
                store.commit("event-1", "event-1", source, _phase_result())
            self.assertTrue(observations)
            self.assertTrue(all(temporary and not destination for temporary, destination in observations))
            self.assertEqual(list((root / "store").rglob("*.tmp-*")), [])

            failed_store = LocalPhaseArtifactStore(root / "failed-store")
            with (
                patch(
                    "remedialhq.phase_artifacts.os.link",
                    side_effect=OSError("simulated publication failure"),
                ),
                self.assertRaises(ArtifactUnavailableError),
            ):
                failed_store.commit("event-2", "event-2", source, _phase_result())
            self.assertEqual(list((root / "failed-store").rglob("*.tmp-*")), [])
            self.assertEqual(
                [path for path in (root / "failed-store").rglob("*") if path.is_file()],
                [],
            )

    def test_materialize_stages_complete_tree_before_atomic_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = LocalPhaseArtifactStore(root / "store")
            reference = store.commit(
                "event-1",
                "event-1",
                _snapshot_source(root),
                _phase_result(),
            )
            destination = root / "materialized"
            import remedialhq.phase_artifacts as artifacts

            real_publish = artifacts._publish_staging_directory

            def inspect_publish(staging: Path, final: Path) -> None:
                self.assertFalse(final.exists())
                self.assertEqual(len([path for path in staging.rglob("*") if path.is_file()]), 2)
                real_publish(staging, final)

            with patch.object(artifacts, "_publish_staging_directory", side_effect=inspect_publish):
                store.materialize(reference, destination)
            self.assertTrue(destination.is_dir())
            self.assertEqual(list(root.glob(".materialized.tmp-*")), [])

            failed_destination = root / "failed-materialization"
            with (
                patch.object(
                    artifacts,
                    "_publish_staging_directory",
                    side_effect=ArtifactIntegrityError("simulated handoff failure"),
                ),
                self.assertRaises(ArtifactIntegrityError),
            ):
                store.materialize(reference, failed_destination)
            self.assertFalse(failed_destination.exists())
            self.assertEqual(list(root.glob(".failed-materialization.tmp-*")), [])

    def test_symlink_source_and_existing_destination_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_store = root / "real-store"
            real_store.mkdir()
            linked_store = root / "linked-store"
            linked_store.symlink_to(real_store, target_is_directory=True)
            with self.assertRaises(ArtifactIntegrityError):
                LocalPhaseArtifactStore(linked_store)

            store = LocalPhaseArtifactStore(root / "store")
            source = _snapshot_source(root)
            (source / "link").symlink_to(source / "official-source", target_is_directory=True)
            with self.assertRaises(ArtifactIntegrityError):
                store.commit("event-1", "event-1", source, _phase_result())

            (source / "link").unlink()
            reference = store.commit("event-1", "event-1", source, _phase_result())
            destination = root / "materialized"
            destination.mkdir()
            with self.assertRaises(ArtifactIntegrityError):
                store.materialize(reference, destination)

            dangling = root / "dangling-destination"
            dangling_target = root / "missing-target"
            dangling.symlink_to(dangling_target, target_is_directory=True)
            with self.assertRaises(ArtifactIntegrityError):
                store.materialize(reference, dangling)
            self.assertTrue(dangling.is_symlink())
            self.assertFalse(dangling_target.exists())

    def test_gcs_store_creates_once_and_pins_every_read_generation(self) -> None:
        records: dict[str, tuple[bytes, int]] = {}
        uploads: list[int | None] = []
        downloads: list[int | None] = []
        reloads: list[str] = []
        state = {"disappear_after_reload": False}

        class NotFound(Exception):
            pass

        class PreconditionFailed(Exception):
            pass

        class Blob:
            def __init__(self, name: str, generation: int | None = None) -> None:
                self.name = name
                self.requested_generation = generation
                self.generation: int | None = generation

            def upload_from_string(
                self,
                data: bytes,
                *,
                content_type: str,
                if_generation_match: int | None = None,
            ) -> None:
                del content_type
                uploads.append(if_generation_match)
                if if_generation_match == 0 and self.name in records:
                    raise PreconditionFailed("exists")
                generation = records.get(self.name, (b"", 0))[1] + 1
                records[self.name] = (data, generation)
                self.generation = generation

            def reload(self) -> None:
                reloads.append(self.name)
                if self.name not in records:
                    raise NotFound("missing")
                self.generation = records[self.name][1]

            def download_as_bytes(self, *, if_generation_match: int | None = None) -> bytes:
                downloads.append(if_generation_match)
                if self.name not in records:
                    raise NotFound("missing")
                if (
                    state["disappear_after_reload"]
                    and self.name.endswith("/manifest.json")
                    and self.requested_generation is None
                ):
                    raise NotFound("disappeared")
                data, generation = records[self.name]
                if if_generation_match != generation or (
                    self.requested_generation is not None
                    and self.requested_generation != generation
                ):
                    raise PreconditionFailed("generation mismatch")
                return data

        class Bucket:
            @staticmethod
            def blob(name: str, generation: int | None = None) -> Blob:
                return Blob(name, generation)

        class Client:
            @staticmethod
            def bucket(_name: str) -> Bucket:
                return Bucket()

        google = ModuleType("google")
        cloud = ModuleType("google.cloud")
        storage = ModuleType("google.cloud.storage")
        api_core = ModuleType("google.api_core")
        exceptions = ModuleType("google.api_core.exceptions")
        storage.Client = Client  # type: ignore[attr-defined]
        exceptions.NotFound = NotFound  # type: ignore[attr-defined]
        exceptions.PreconditionFailed = PreconditionFailed  # type: ignore[attr-defined]
        modules = {
            "google": google,
            "google.cloud": cloud,
            "google.cloud.storage": storage,
            "google.api_core": api_core,
            "google.api_core.exceptions": exceptions,
        }

        with tempfile.TemporaryDirectory() as directory, patch.dict(sys.modules, modules):
            root = Path(directory)
            store = GCSPhaseArtifactStore("artifact-bucket")
            source = _snapshot_source(root)
            first = store.commit("event-1", "event-1", source, _phase_result())
            self.assertEqual(reloads, [])
            second = store.commit("event-1", "event-1", source, _phase_result())
            self.assertEqual(first, second)
            self.assertEqual(len(reloads), 3)
            manifest = store.materialize(first, root / "materialized")
            self.assertEqual(len(manifest.files), 2)
            self.assertIsNone(store.find("absent-event", "absent-event"))
            state["disappear_after_reload"] = True
            with self.assertRaises(ArtifactIntegrityError):
                store.find("event-1", "event-1")

        self.assertTrue(uploads)
        self.assertEqual(set(uploads), {0})
        self.assertTrue(downloads)
        self.assertNotIn(None, downloads)


if __name__ == "__main__":
    unittest.main()
