from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scripts import check_container_scan


def _trivy_finding(
    severity: str,
    *,
    vulnerability_id: str = "CVE-2026-1000",
    fixed_version: str = "",
) -> dict[str, str]:
    return {
        "VulnerabilityID": vulnerability_id,
        "PkgName": "example-package",
        "InstalledVersion": "1.0.0",
        "FixedVersion": fixed_version,
        "Severity": severity,
        "Status": "fixed" if fixed_version else "affected",
    }


def _trivy_report(*findings: dict[str, str]) -> dict[str, object]:
    return {
        "SchemaVersion": 2,
        "ArtifactName": "example.invalid/image:release",
        "ArtifactType": "container_image",
        "Metadata": {
            "ImageID": "sha256:" + "a" * 64,
            "Reference": "example.invalid/image:release",
            "RepoTags": ["example.invalid/image:release"],
            "RepoDigests": ["example.invalid/image@sha256:" + "a" * 64],
        },
        "Results": [
            {
                "Target": "wolfi",
                "Class": "os-pkgs",
                "Vulnerabilities": list(findings),
            }
        ],
    }


def _grype_finding(
    severity: str,
    *,
    vulnerability_id: str = "CVE-2026-2000",
    fixed_versions: list[str] | None = None,
) -> dict[str, object]:
    versions = fixed_versions or []
    return {
        "vulnerability": {
            "id": vulnerability_id,
            "severity": severity,
            "fix": {
                "versions": versions,
                "state": "fixed" if versions else "not-fixed",
            },
        },
        "artifact": {
            "name": "example-package",
            "version": "1.0.0",
            "type": "apk",
        },
    }


def _grype_report(*findings: dict[str, object]) -> dict[str, object]:
    return {
        "matches": list(findings),
        "descriptor": {"name": "grype", "version": "0.110.0"},
        "schema": {"version": "16.1.0"},
        "source": {
            "type": "image",
            "target": {
                "userInput": "example.invalid/image:release",
                "imageID": "sha256:" + "b" * 64,
                "manifestDigest": "sha256:" + "c" * 64,
                "tags": ["example.invalid/image:release"],
                "repoDigests": ["example.invalid/image@sha256:" + "c" * 64],
            },
        },
    }


class ContainerScanTests(unittest.TestCase):
    def _write_report(self, root: Path, document: object) -> Path:
        path = root / "scan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_trivy_counts_every_supported_severity(self) -> None:
        report = _trivy_report(
            _trivy_finding("MEDIUM", vulnerability_id="CVE-MEDIUM"),
            _trivy_finding("LOW", vulnerability_id="CVE-LOW"),
            _trivy_finding("UNKNOWN", vulnerability_id="CVE-UNKNOWN"),
        )
        summary = check_container_scan.summarize_report(report)

        self.assertEqual(summary["scanner"], "trivy")
        self.assertEqual(summary["format"], "trivy-json")
        self.assertEqual(summary["scanner_schema"], 2)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(
            summary["severity_counts"],
            {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 1,
                "negligible": 0,
                "unknown": 1,
            },
        )
        self.assertEqual(summary["blocked_count"], 0)
        self.assertEqual(summary["status"], "PASS")

    def test_grype_counts_negligible_and_empty_results_pass(self) -> None:
        report = _grype_report(
            _grype_finding("Negligible", vulnerability_id="CVE-NEGLIGIBLE"),
            _grype_finding("Low", vulnerability_id="CVE-LOW"),
        )
        summary = check_container_scan.summarize_report(report, "grype")

        self.assertEqual(summary["scanner_schema"], "16.1.0")
        self.assertEqual(summary["severity_counts"]["negligible"], 1)
        self.assertEqual(summary["severity_counts"]["low"], 1)
        self.assertEqual(
            check_container_scan.summarize_report(_grype_report())["status"],
            "PASS",
        )

    def test_parse_report_returns_json_serializable_pass_summary(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = self._write_report(Path(directory), _trivy_report(_trivy_finding("LOW")))
            summary = check_container_scan.parse_report(path, "auto")

        self.assertEqual(json.loads(json.dumps(summary)), summary)
        self.assertEqual(summary["findings"][0]["fixed_versions"], [])
        self.assertEqual(summary["artifact"]["type"], "container_image")

    def test_expected_image_identity_accepts_tag_or_digest_and_rejects_mismatch(self) -> None:
        summary = check_container_scan.summarize_report(_trivy_report())
        self.assertIs(
            check_container_scan.enforce_identity(summary, "example.invalid/image:release"),
            summary,
        )
        self.assertIs(
            check_container_scan.enforce_identity(summary, "sha256:" + "a" * 64),
            summary,
        )
        with self.assertRaisesRegex(ValueError, "not bound to expected image"):
            check_container_scan.enforce_identity(summary, "sha256:" + "f" * 64)

    def test_fixed_high_finding_still_blocks(self) -> None:
        report = _trivy_report(_trivy_finding("HIGH", fixed_version="1.0.1"))
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = self._write_report(Path(directory), report)
            with self.assertRaises(check_container_scan.ContainerScanGateError) as caught:
                check_container_scan.parse_report(path)

        self.assertEqual(caught.exception.summary["blocked_count"], 1)
        self.assertEqual(caught.exception.summary["unfixed_blocked_count"], 0)
        self.assertEqual(caught.exception.summary["status"], "FAIL")

    def test_unfixed_critical_finding_blocks(self) -> None:
        report = _grype_report(_grype_finding("Critical"))
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = self._write_report(Path(directory), report)
            with self.assertRaisesRegex(ValueError, "without a reported fix") as caught:
                check_container_scan.parse_report(path)

        error = caught.exception
        self.assertIsInstance(error, check_container_scan.ContainerScanGateError)
        assert isinstance(error, check_container_scan.ContainerScanGateError)
        self.assertEqual(error.summary["unfixed_blocked_count"], 1)

    def test_multiple_blockers_count_fixed_and_unfixed_without_exemption(self) -> None:
        summary = check_container_scan.summarize_report(
            _grype_report(
                _grype_finding("High", vulnerability_id="CVE-HIGH-FIXED", fixed_versions=["2"]),
                _grype_finding("High", vulnerability_id="CVE-HIGH-UNFIXED"),
                _grype_finding("Critical", vulnerability_id="CVE-CRITICAL"),
            )
        )

        self.assertEqual(summary["blocked_count"], 3)
        self.assertEqual(summary["unfixed_blocked_count"], 2)
        with self.assertRaises(check_container_scan.ContainerScanGateError):
            check_container_scan.enforce_policy(summary)

    def test_missing_unreadable_and_invalid_json_reports_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "could not be read"):
                check_container_scan.parse_report(root / "missing.json")
            invalid = root / "invalid.json"
            invalid.write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not valid JSON"):
                check_container_scan.parse_report(invalid)

    def test_non_object_and_unsupported_reports_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be a JSON object"):
            check_container_scan.summarize_report([])
        with self.assertRaisesRegex(ValueError, "unsupported container scan report"):
            check_container_scan.summarize_report({"vulnerabilities": []})

    def test_ambiguous_and_explicitly_mismatched_formats_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            check_container_scan.summarize_report({"Results": [], "matches": []})
        with self.assertRaisesRegex(ValueError, "not requested grype"):
            check_container_scan.summarize_report(_trivy_report(), "grype")
        with self.assertRaisesRegex(ValueError, "unsupported container scanner"):
            check_container_scan.summarize_report(_trivy_report(), "clair")

    def test_malformed_trivy_structure_is_rejected(self) -> None:
        cases = [
            {"Results": {}},
            {"Results": ["not-an-object"]},
            {"Results": [{"Vulnerabilities": {}}]},
            {"Results": [{"Vulnerabilities": [None]}]},
            {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE", "Severity": 4}]}]},
            {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "", "Severity": "LOW"}]}]},
            {"Results": [], "ArtifactName": "image", "ArtifactType": "container_image"},
            {"Results": [], "SchemaVersion": True},
            {"Results": [], "SchemaVersion": 3},
        ]
        for report in cases:
            with self.subTest(report=report), self.assertRaises(ValueError):
                check_container_scan.summarize_report(report)

    def test_malformed_grype_structure_is_rejected(self) -> None:
        cases = [
            {"matches": {}},
            {"matches": [None]},
            {"matches": [{}]},
            {"matches": [{"vulnerability": {"id": "CVE", "severity": "High"}, "artifact": []}]},
            {"matches": [{"vulnerability": {"id": "CVE", "severity": "High", "fix": []}}]},
            {
                "matches": [
                    {"vulnerability": {"id": "CVE", "severity": "High", "fix": {"versions": {}}}}
                ]
            },
            {"matches": [], "descriptor": {"name": "not-grype"}},
            {"matches": [], "schema": {}},
            {"matches": [], "descriptor": {"name": "grype", "version": "1"}},
        ]
        for report in cases:
            with self.subTest(report=report), self.assertRaises(ValueError):
                check_container_scan.summarize_report(report)

    def test_unknown_severity_is_rejected_instead_of_ignored(self) -> None:
        report = _grype_report(_grype_finding("Important"))
        with self.assertRaisesRegex(ValueError, "severity is unsupported"):
            check_container_scan.summarize_report(report)

    def test_trivy_requires_at_least_one_named_scan_target(self) -> None:
        empty = _trivy_report()
        empty["Results"] = []
        with self.assertRaisesRegex(ValueError, "must contain scan targets"):
            check_container_scan.summarize_report(empty)

        unnamed = _trivy_report()
        assert isinstance(unnamed["Results"], list)
        assert isinstance(unnamed["Results"][0], dict)
        del unnamed["Results"][0]["Target"]
        with self.assertRaisesRegex(ValueError, "Target must be a non-empty string"):
            check_container_scan.summarize_report(unnamed)

    def test_cli_writes_passing_release_summary(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            report = self._write_report(root, _trivy_report(_trivy_finding("LOW")))
            summary_path = root / "evidence/scan-summary.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                result = check_container_scan.main(
                    [str(report), "--scanner", "trivy", "--summary", str(summary_path), "--json"]
                )

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(result, 0)
        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(json.loads(stdout.getvalue()), summary)

    def test_cli_preserves_failing_summary_and_returns_one(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            report = self._write_report(root, _grype_report(_grype_finding("High")))
            summary_path = root / "scan-summary.json"
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                result = check_container_scan.main([str(report), "--output", str(summary_path)])

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(result, 1)
        self.assertEqual(summary["status"], "FAIL")
        self.assertIn("container vulnerability gate failed", stderr.getvalue())

    def test_cli_returns_two_for_malformed_report_without_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            report = self._write_report(root, {"unknown": []})
            summary_path = root / "scan-summary.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = check_container_scan.main([str(report), "--output", str(summary_path)])

        self.assertEqual(result, 2)
        self.assertFalse(summary_path.exists())


if __name__ == "__main__":
    unittest.main()
