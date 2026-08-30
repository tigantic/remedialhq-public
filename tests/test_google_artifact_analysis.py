from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import check_google_artifact_analysis as gate

DIGEST = "sha256:" + "a" * 64
IMAGE_URI = f"us-east1-docker.pkg.dev/example-project/repository/engine@{DIGEST}"
RESOURCE_URI = f"https://{IMAGE_URI}"
SBOM_LOCATION = (
    "gs://artifact-analysis/example-image/sbom/artifactanalysis-2-3.spdx.json"
)
def _sbom_reference() -> dict[str, object]:
    payload = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://containeranalysis.googleapis.com/reference/v0.1",
        "subject": [
            {
                "name": RESOURCE_URI,
                "digest": {"sha256": DIGEST.removeprefix("sha256:")},
            }
        ],
        "predicate": {
            "digest": {"sha256": _sbom_sha256()},
            "location": SBOM_LOCATION,
            "mimeType": "application/spdx+json",
            "referrerId": "https://containeranalysis.googleapis.com/ArtifactAnalysis@v0.1",
        },
    }
    signatures = [
        {
            "keyid": (
                "projects/goog-analysis/locations/global/keyRings/sbomAttestor/"
                "cryptoKeys/generatedByArtifactAnalysis/cryptoKeyVersions/1"
            ),
            "sig": base64.b64encode(b"s" * 72).decode(),
        }
    ]
    payload_type = "application/vnd.in-toto+json"
    return {
        "kind": "SBOM_REFERENCE",
        "noteName": "projects/goog-analysis/locations/us-east1/notes/sbom-spdx-2-3",
        "resourceUri": RESOURCE_URI,
        "envelope": {
            "payload": base64.b64encode(json.dumps(payload).encode()).decode(),
            "payloadType": payload_type,
            "signatures": signatures,
        },
        "sbomReference": {
            "payload": payload,
            "payloadType": payload_type,
            "signatures": signatures,
        },
    }


def _spdx_document() -> dict[str, object]:
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "dataLicense": "CC0-1.0",
        "name": IMAGE_URI.rsplit("/", 1)[-1],
        "documentNamespace": f"{RESOURCE_URI}_test-document",
        "packages": [{"SPDXID": "SPDXRef-Package", "name": "example"}],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            }
        ],
    }


def _sbom_sha256() -> str:
    payload = json.dumps(_spdx_document(), separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _discovery(
    *,
    status: str = "FINISHED_SUCCESS",
    with_sbom: bool = False,
) -> dict[str, object]:
    discovery: dict[str, object] = {
        "analysisStatus": status,
        "analysisCompleted": {
            "analysisType": ["OS", "PYPI", "NPM"],
        },
    }
    image_summary: dict[str, object] = {
        "digest": DIGEST,
        "fully_qualified_digest": IMAGE_URI,
    }
    document: dict[str, object] = {
        "image_summary": image_summary,
        "discovery_summary": {
            "discovery": [
                {
                    "kind": "DISCOVERY",
                    "resourceUri": RESOURCE_URI,
                    "discovery": discovery,
                }
            ]
        },
    }
    if with_sbom:
        discovery["sbomStatus"] = {"sbomState": "COMPLETE"}
        image_summary["sbom_locations"] = [SBOM_LOCATION]
        document["sbom_summary"] = {"sbom_references": [_sbom_reference()]}
    return document


def _finding(severity: str, *, resource_uri: str = RESOURCE_URI) -> dict[str, object]:
    return {
        "occurrence": {
            "noteName": f"notes/CVE-{severity}",
            "resourceUri": resource_uri,
            "vulnerability": {
                "effectiveSeverity": severity,
                "shortDescription": f"{severity} test finding",
            },
        }
    }


def _response(
    document: object,
    *,
    returncode: int = 0,
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=json.dumps(document, separators=(",", ":")),
        stderr=stderr,
    )


def _success_responses(
    vulnerabilities: object,
    *,
    final_discovery: dict[str, object] | None = None,
) -> list[subprocess.CompletedProcess[str]]:
    return [
        _response(_discovery(status="PENDING")),
        _response(_discovery()),
        _response([]),
        _response(final_discovery or _discovery(with_sbom=True)),
        _response(_spdx_document()),
        _response(vulnerabilities),
    ]


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class FakeRunner:
    def __init__(self, responses: list[subprocess.CompletedProcess[str]]) -> None:
        self.responses = list(responses)
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if not self.responses:
            raise AssertionError(f"unexpected command: {command}")
        return self.responses.pop(0)


class GoogleArtifactAnalysisTests(unittest.TestCase):
    def _setup(
        self,
        responses: list[subprocess.CompletedProcess[str]],
    ) -> tuple[Path, FakeRunner, FakeClock]:
        directory = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(directory.cleanup)
        return Path(directory.name), FakeRunner(responses), FakeClock()

    def _run_success(
        self,
        vulnerabilities: object,
        *,
        final_discovery: dict[str, object] | None = None,
    ) -> tuple[dict[str, object], Path, FakeRunner, FakeClock]:
        root, runner, clock = self._setup(
            _success_responses(vulnerabilities, final_discovery=final_discovery)
        )
        summary = gate.run_gate(
            IMAGE_URI,
            output_dir=root,
            timeout_seconds=120,
            poll_interval_seconds=5,
            runner=runner,
            clock=clock.monotonic,
            sleeper=clock.sleep,
        )
        return summary, root, runner, clock

    def test_pending_scan_exports_once_then_accepts_signed_sbom_and_clean_null(self) -> None:
        summary, root, runner, clock = self._run_success([None])

        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(summary["digest"], DIGEST)
        self.assertEqual(summary["total_findings"], 0)
        self.assertTrue(summary["raw_singleton_null_normalized"])
        self.assertEqual(summary["sbom_reference_count"], 1)
        self.assertEqual(summary["sbom_document"]["package_count"], 1)
        self.assertTrue(summary["sbom_document"]["signed_reference_hash_matches_download"])
        self.assertFalse(summary["signature_cryptographically_verified_independently"])
        self.assertEqual(clock.sleeps, [5])
        self.assertEqual((root / "artifact-analysis-vulnerabilities.json").read_text(), "[null]\n")
        self.assertEqual(
            hashlib.sha256((root / "artifact-analysis-sbom.spdx.json").read_bytes()).hexdigest(),
            _sbom_sha256(),
        )
        saved = json.loads((root / "artifact-analysis-summary.json").read_text())
        self.assertEqual(saved, summary)

        export_commands = [
            command
            for command in runner.commands
            if command[:4] == ["gcloud", "artifacts", "sbom", "export"]
        ]
        self.assertEqual(len(export_commands), 1)
        self.assertIn(f"--uri={IMAGE_URI}", export_commands[0])
        self.assertNotIn("--location", export_commands[0])
        self.assertFalse(any(part.startswith("--location=") for part in export_commands[0]))
        self.assertNotIn("--show-sbom-references", runner.commands[0])
        self.assertIn("--show-sbom-references", runner.commands[3])
        self.assertEqual(
            runner.commands[4],
            ["gcloud", "storage", "cat", SBOM_LOCATION, "--quiet"],
        )
        self.assertLess(runner.commands.index(export_commands[0]), 3)

    def test_downloaded_sbom_failure_hash_mismatch_and_invalid_spdx_fail_closed(self) -> None:
        valid_text = json.dumps(_spdx_document(), separators=(",", ":"))
        invalid_spdx = _spdx_document()
        invalid_spdx["spdxVersion"] = "SPDX-2.2"
        invalid_text = json.dumps(invalid_spdx, separators=(",", ":"))
        cases = (
            (
                subprocess.CompletedProcess([], 1, "", "PERMISSION_DENIED"),
                hashlib.sha256(valid_text.encode()).hexdigest(),
                "could not be read",
            ),
            (
                subprocess.CompletedProcess([], 0, valid_text, ""),
                "f" * 64,
                "hash does not match",
            ),
            (
                subprocess.CompletedProcess([], 0, invalid_text, ""),
                hashlib.sha256(invalid_text.encode()).hexdigest(),
                "not SPDX 2.3",
            ),
        )
        for response, expected_hash, message in cases:
            with self.subTest(message=message):
                root, runner, clock = self._setup([response])
                with self.assertRaisesRegex(gate.ArtifactAnalysisError, message):
                    gate._download_and_verify_sbom(
                        [{"location": SBOM_LOCATION, "sha256": expected_hash}],
                        image_uri=IMAGE_URI,
                        output_path=root / "sbom.json",
                        deadline=30,
                        runner=runner,
                        clock=clock.monotonic,
                    )

    def test_post_export_selects_the_complete_discovery_occurrence(self) -> None:
        final = _discovery(with_sbom=True)
        discovery_summary = final["discovery_summary"]
        assert isinstance(discovery_summary, dict)
        occurrences = discovery_summary["discovery"]
        assert isinstance(occurrences, list)
        first = copy.deepcopy(occurrences[0])
        assert isinstance(first, dict)
        first_discovery = first["discovery"]
        assert isinstance(first_discovery, dict)
        first_discovery.pop("sbomStatus", None)
        occurrences.insert(0, first)

        summary, _, _, _ = self._run_success([None], final_discovery=final)

        self.assertEqual(summary["status"], "PASS")

    def test_empty_medium_and_low_results_are_accepted_without_broad_normalization(self) -> None:
        for vulnerabilities, expected_total in (
            ([], 0),
            ([_finding("MEDIUM"), _finding("LOW")], 2),
        ):
            with self.subTest(vulnerabilities=vulnerabilities):
                summary, _, _, _ = self._run_success(vulnerabilities)
                self.assertEqual(summary["status"], "PASS")
                self.assertEqual(summary["total_findings"], expected_total)
                self.assertFalse(summary["raw_singleton_null_normalized"])

    def test_only_exact_singleton_null_is_normalized(self) -> None:
        for malformed in (None, [None, None], [None, _finding("LOW")], "null"):
            with self.subTest(malformed=malformed):
                root, runner, clock = self._setup(_success_responses(malformed))
                with self.assertRaises(gate.ArtifactAnalysisError):
                    gate.run_gate(
                        IMAGE_URI,
                        output_dir=root,
                        timeout_seconds=120,
                        poll_interval_seconds=5,
                        runner=runner,
                        clock=clock.monotonic,
                        sleeper=clock.sleep,
                    )
                summary = json.loads(
                    (root / "artifact-analysis-summary.json").read_text(encoding="utf-8")
                )
                self.assertEqual(summary["status"], "FAIL")

    def test_discovery_requires_exact_digest_uri_and_analysis_types(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []
        wrong_digest = _discovery()
        image_summary = wrong_digest["image_summary"]
        assert isinstance(image_summary, dict)
        image_summary["digest"] = "sha256:" + "f" * 64
        cases.append(("digest", wrong_digest, "wrong digest"))

        wrong_uri = _discovery()
        discovery_summary = wrong_uri["discovery_summary"]
        assert isinstance(discovery_summary, dict)
        occurrences = discovery_summary["discovery"]
        assert isinstance(occurrences, list)
        assert isinstance(occurrences[0], dict)
        occurrences[0]["resourceUri"] = RESOURCE_URI + "-suffix"
        cases.append(("URI", wrong_uri, "wrong image"))

        missing_python = _discovery()
        discovery_summary = missing_python["discovery_summary"]
        assert isinstance(discovery_summary, dict)
        occurrences = discovery_summary["discovery"]
        assert isinstance(occurrences, list)
        assert isinstance(occurrences[0], dict)
        discovery = occurrences[0]["discovery"]
        assert isinstance(discovery, dict)
        discovery["analysisCompleted"] = {"analysisType": ["OS"]}
        cases.append(("types", missing_python, "OS and Python"))

        for label, document, message in cases:
            with self.subTest(label=label):
                root, runner, clock = self._setup([_response(document)])
                with self.assertRaisesRegex(gate.ArtifactAnalysisError, message):
                    gate.run_gate(
                        IMAGE_URI,
                        output_dir=root,
                        timeout_seconds=30,
                        poll_interval_seconds=5,
                        runner=runner,
                        clock=clock.monotonic,
                        sleeper=clock.sleep,
                    )
                self.assertFalse(
                    any("export" in command for command in runner.commands),
                    "invalid discovery must fail before export",
                )

    def test_signed_reference_rejects_wrong_resource_subject_location_mime_or_signature(self) -> None:
        mutations = {
            "reference resource": lambda ref: ref.__setitem__(
                "resourceUri", RESOURCE_URI + "-wrong"
            ),
            "subject name": lambda ref: ref["sbomReference"]["payload"]["subject"][0].__setitem__(
                "name", RESOURCE_URI + "-wrong"
            ),
            "subject digest": lambda ref: ref["sbomReference"]["payload"]["subject"][0][
                "digest"
            ].__setitem__("sha256", "f" * 64),
            "location": lambda ref: ref["sbomReference"]["payload"]["predicate"].__setitem__(
                "location", "gs://wrong/sbom.json"
            ),
            "MIME": lambda ref: ref["sbomReference"]["payload"]["predicate"].__setitem__(
                "mimeType", "application/json"
            ),
            "signature": lambda ref: ref["sbomReference"].__setitem__("signatures", []),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                final = copy.deepcopy(_discovery(with_sbom=True))
                sbom_summary = final["sbom_summary"]
                assert isinstance(sbom_summary, dict)
                references = sbom_summary["sbom_references"]
                assert isinstance(references, list)
                reference = references[0]
                assert isinstance(reference, dict)
                mutate(reference)
                root, runner, clock = self._setup(
                    [
                        _response(_discovery()),
                        _response([]),
                        _response(final),
                    ]
                )
                with self.assertRaises(gate.ArtifactAnalysisError):
                    gate.run_gate(
                        IMAGE_URI,
                        output_dir=root,
                        timeout_seconds=30,
                        poll_interval_seconds=5,
                        runner=runner,
                        clock=clock.monotonic,
                        sleeper=clock.sleep,
                    )

    def test_envelope_must_decode_to_the_expanded_signed_payload(self) -> None:
        final = _discovery(with_sbom=True)
        sbom_summary = final["sbom_summary"]
        assert isinstance(sbom_summary, dict)
        references = sbom_summary["sbom_references"]
        assert isinstance(references, list)
        reference = references[0]
        assert isinstance(reference, dict)
        envelope = reference["envelope"]
        assert isinstance(envelope, dict)
        envelope["payload"] = base64.b64encode(b"{}").decode()
        root, runner, clock = self._setup(
            [_response(_discovery()), _response([]), _response(final)]
        )

        with self.assertRaisesRegex(gate.ArtifactAnalysisError, "payload does not match"):
            gate.run_gate(
                IMAGE_URI,
                output_dir=root,
                timeout_seconds=30,
                poll_interval_seconds=5,
                runner=runner,
                clock=clock.monotonic,
                sleeper=clock.sleep,
            )

    def test_terminal_scan_failure_and_shared_deadline_fail_closed(self) -> None:
        root, runner, clock = self._setup([_response(_discovery(status="FINISHED_FAILED"))])
        with self.assertRaisesRegex(gate.ArtifactAnalysisError, "FINISHED_FAILED"):
            gate.run_gate(
                IMAGE_URI,
                output_dir=root,
                timeout_seconds=30,
                poll_interval_seconds=5,
                runner=runner,
                clock=clock.monotonic,
                sleeper=clock.sleep,
            )

        root, runner, clock = self._setup(
            [_response(_discovery(status="PENDING")), _response(_discovery(status="PENDING"))]
        )
        with self.assertRaisesRegex(gate.ArtifactAnalysisError, "shared polling deadline"):
            gate.run_gate(
                IMAGE_URI,
                output_dir=root,
                timeout_seconds=10,
                poll_interval_seconds=5,
                runner=runner,
                clock=clock.monotonic,
                sleeper=clock.sleep,
            )
        self.assertFalse(any("export" in command for command in runner.commands))

    def test_unauthorized_discovery_and_failed_export_fail_closed(self) -> None:
        root, runner, clock = self._setup(
            [_response({}, returncode=1, stderr="PERMISSION_DENIED")]
        )
        with self.assertRaisesRegex(gate.ArtifactAnalysisError, "unauthorized"):
            gate.run_gate(
                IMAGE_URI,
                output_dir=root,
                timeout_seconds=30,
                poll_interval_seconds=5,
                runner=runner,
                clock=clock.monotonic,
                sleeper=clock.sleep,
            )

        root, runner, clock = self._setup(
            [
                _response(_discovery()),
                _response({}, returncode=1, stderr="export denied"),
            ]
        )
        with self.assertRaisesRegex(gate.ArtifactAnalysisError, "export failed"):
            gate.run_gate(
                IMAGE_URI,
                output_dir=root,
                timeout_seconds=30,
                poll_interval_seconds=5,
                runner=runner,
                clock=clock.monotonic,
                sleeper=clock.sleep,
            )
        self.assertEqual(
            json.loads((root / "artifact-analysis-summary.json").read_text())["status"],
            "FAIL",
        )

    def test_critical_and_high_findings_block_with_preserved_summary(self) -> None:
        for severity in ("CRITICAL", "HIGH"):
            with self.subTest(severity=severity):
                root, runner, clock = self._setup(_success_responses([_finding(severity)]))
                with self.assertRaisesRegex(gate.ArtifactAnalysisError, "rejected 1"):
                    gate.run_gate(
                        IMAGE_URI,
                        output_dir=root,
                        timeout_seconds=120,
                        poll_interval_seconds=5,
                        runner=runner,
                        clock=clock.monotonic,
                        sleeper=clock.sleep,
                    )
                summary = json.loads(
                    (root / "artifact-analysis-summary.json").read_text(encoding="utf-8")
                )
                self.assertEqual(summary["status"], "FAIL")
                self.assertEqual(summary["severity_counts"][severity], 1)
                self.assertEqual(len(summary["blocked_findings"]), 1)

    def test_vulnerability_identity_and_severity_are_exact(self) -> None:
        cases = (
            ([_finding("LOW", resource_uri=RESOURCE_URI + "-suffix")], "wrong image"),
            ([_finding("IMPORTANT")], "valid effective severity"),
        )
        for findings, message in cases:
            with self.subTest(message=message):
                root, runner, clock = self._setup(_success_responses(findings))
                with self.assertRaisesRegex(gate.ArtifactAnalysisError, message):
                    gate.run_gate(
                        IMAGE_URI,
                        output_dir=root,
                        timeout_seconds=120,
                        poll_interval_seconds=5,
                        runner=runner,
                        clock=clock.monotonic,
                        sleeper=clock.sleep,
                    )

    def test_missing_or_null_effective_severity_is_rejected(self) -> None:
        missing = _finding("LOW")
        occurrence = missing["occurrence"]
        assert isinstance(occurrence, dict)
        vulnerability = occurrence["vulnerability"]
        assert isinstance(vulnerability, dict)
        vulnerability.pop("effectiveSeverity")
        null = _finding("LOW")
        occurrence = null["occurrence"]
        assert isinstance(occurrence, dict)
        vulnerability = occurrence["vulnerability"]
        assert isinstance(vulnerability, dict)
        vulnerability["effectiveSeverity"] = None

        for finding in (missing, null):
            with self.subTest(finding=finding):
                root, runner, clock = self._setup(_success_responses([finding]))
                with self.assertRaisesRegex(gate.ArtifactAnalysisError, "valid effective severity"):
                    gate.run_gate(
                        IMAGE_URI,
                        output_dir=root,
                        timeout_seconds=120,
                        poll_interval_seconds=5,
                        runner=runner,
                        clock=clock.monotonic,
                        sleeper=clock.sleep,
                    )

    def test_nonfinite_timeout_and_poll_interval_are_rejected(self) -> None:
        for timeout, interval in ((float("nan"), 5), (30, float("inf"))):
            with self.subTest(timeout=timeout, interval=interval):
                root, runner, clock = self._setup([])
                with self.assertRaisesRegex(ValueError, "finite positive"):
                    gate.run_gate(
                        IMAGE_URI,
                        output_dir=root,
                        timeout_seconds=timeout,
                        poll_interval_seconds=interval,
                        runner=runner,
                        clock=clock.monotonic,
                        sleeper=clock.sleep,
                    )
                self.assertEqual(runner.commands, [])

    def test_invalid_mutable_image_reference_fails_before_gcloud(self) -> None:
        root, runner, clock = self._setup([])
        with self.assertRaisesRegex(gate.ArtifactAnalysisError, "immutable"):
            gate.run_gate(
                "us-east1-docker.pkg.dev/example-project/repository/engine:latest",
                output_dir=root,
                timeout_seconds=30,
                poll_interval_seconds=5,
                runner=runner,
                clock=clock.monotonic,
                sleeper=clock.sleep,
            )
        self.assertEqual(runner.commands, [])
        self.assertEqual(
            json.loads((root / "artifact-analysis-summary.json").read_text())["status"],
            "FAIL",
        )


if __name__ == "__main__":
    unittest.main()
