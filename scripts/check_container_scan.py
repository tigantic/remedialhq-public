#!/usr/bin/env python3
"""Fail-closed policy gate for Trivy and Grype container scan reports."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SUMMARY_SCHEMA_VERSION = 1
SUPPORTED_SCANNERS = ("auto", "trivy", "grype")
SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")
BLOCKING_SEVERITIES = frozenset({"critical", "high"})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ContainerScanGateError(ValueError):
    """A valid scan report contained a policy-blocking vulnerability."""

    def __init__(self, summary: dict[str, Any]) -> None:
        self.summary = summary
        counts = summary["severity_counts"]
        blocked = summary["blocked_count"]
        unfixed = summary["unfixed_blocked_count"]
        super().__init__(
            "container vulnerability gate failed: "
            f"{blocked} blocking findings "
            f"({counts['critical']} critical, {counts['high']} high; "
            f"{unfixed} without a reported fix)"
        )


class ContainerScanReportError(ValueError):
    """The supplied report is missing, malformed, or unsupported."""


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ContainerScanReportError(f"{label} must be a JSON object")
    return value


def _array(value: object, label: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise ContainerScanReportError(f"{label} must be a JSON array")
    return value


def _optional_string(value: object, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ContainerScanReportError(f"{label} must be a string when present")
    return value.strip()


def _required_string(value: object, label: str) -> str:
    text = _optional_string(value, label)
    if not text:
        raise ContainerScanReportError(f"{label} must be a non-empty string")
    return text


def _string_array(value: object, label: str) -> list[str]:
    values = _array(value, label)
    return [_required_string(item, f"{label}[{index}]") for index, item in enumerate(values)]


def _required_digest(value: object, label: str) -> str:
    digest = _required_string(value, label)
    if _SHA256_RE.fullmatch(digest) is None:
        raise ContainerScanReportError(f"{label} must be a sha256 digest")
    return digest


def _reference_digest(value: str) -> str | None:
    candidate = value.rsplit("@", 1)[-1]
    return candidate if _SHA256_RE.fullmatch(candidate) else None


def _severity(value: object, label: str) -> str:
    normalized = _required_string(value, label).lower()
    if normalized not in SEVERITIES:
        raise ValueError(f"{label} is unsupported: {value!r}")
    return normalized


def _detect_scanner(report: Mapping[str, Any], requested: str) -> str:
    normalized = requested.strip().lower()
    if normalized not in SUPPORTED_SCANNERS:
        raise ValueError(f"unsupported container scanner: {requested!r}")
    looks_like_trivy = "Results" in report
    looks_like_grype = "matches" in report
    if looks_like_trivy and looks_like_grype:
        raise ValueError("container scan report format is ambiguous")
    detected = "trivy" if looks_like_trivy else "grype" if looks_like_grype else ""
    if not detected:
        raise ValueError("unsupported container scan report format")
    if normalized != "auto" and normalized != detected:
        raise ValueError(
            f"container scan report is {detected} JSON, not requested {normalized} JSON"
        )
    return detected


def _trivy_schema(report: Mapping[str, Any]) -> int | None:
    schema = report.get("SchemaVersion")
    if schema is None:
        raise ContainerScanReportError("Trivy SchemaVersion is required")
    if type(schema) is not int:
        raise ValueError("Trivy SchemaVersion must be an integer")
    if schema != 2:
        raise ValueError(f"unsupported Trivy schema version: {schema}")
    return schema


def _grype_schema(report: Mapping[str, Any]) -> str | None:
    descriptor_value = report.get("descriptor")
    if descriptor_value is None:
        raise ContainerScanReportError("Grype descriptor is required")
    descriptor = _object(descriptor_value, "Grype descriptor")
    name = _required_string(descriptor.get("name"), "Grype descriptor name")
    if name.lower() != "grype":
        raise ContainerScanReportError("Grype descriptor does not identify Grype")
    _required_string(descriptor.get("version"), "Grype descriptor version")
    schema_value = report.get("schema")
    if schema_value is None:
        return None
    schema = _object(schema_value, "Grype schema")
    return _required_string(schema.get("version"), "Grype schema version")


def _trivy_artifact(report: Mapping[str, Any]) -> dict[str, Any]:
    name = _required_string(report.get("ArtifactName"), "Trivy ArtifactName")
    artifact_type = _required_string(report.get("ArtifactType"), "Trivy ArtifactType")
    if artifact_type != "container_image":
        raise ContainerScanReportError("Trivy report does not describe a container image")
    metadata = _object(report.get("Metadata"), "Trivy Metadata")
    image_id = _required_digest(metadata.get("ImageID"), "Trivy Metadata.ImageID")
    references = {name, image_id}
    reference = _optional_string(metadata.get("Reference"), "Trivy Metadata.Reference")
    if reference:
        references.add(reference)
    for label in ("RepoTags", "RepoDigests"):
        value = metadata.get(label, [])
        references.update(_string_array(value, f"Trivy Metadata.{label}"))
    digests = {image_id}
    digests.update(digest for item in references if (digest := _reference_digest(item)) is not None)
    return {
        "type": artifact_type,
        "name": name,
        "image_id": image_id,
        "manifest_digest": image_id,
        "references": sorted(references),
        "digests": sorted(digests),
    }


def _grype_artifact(report: Mapping[str, Any]) -> dict[str, Any]:
    source = _object(report.get("source"), "Grype source")
    source_type = _required_string(source.get("type"), "Grype source.type")
    if source_type != "image":
        raise ContainerScanReportError("Grype report does not describe a container image")
    target = _object(source.get("target"), "Grype source.target")
    name = _required_string(target.get("userInput"), "Grype source.target.userInput")
    image_id = _required_digest(target.get("imageID"), "Grype source.target.imageID")
    manifest_digest = _required_digest(
        target.get("manifestDigest"), "Grype source.target.manifestDigest"
    )
    references = {name, image_id, manifest_digest}
    for label in ("tags", "repoDigests"):
        references.update(_string_array(target.get(label, []), f"Grype source.target.{label}"))
    digests = {image_id, manifest_digest}
    digests.update(digest for item in references if (digest := _reference_digest(item)) is not None)
    return {
        "type": "container_image",
        "name": name,
        "image_id": image_id,
        "manifest_digest": manifest_digest,
        "references": sorted(references),
        "digests": sorted(digests),
    }


def _trivy_findings(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    results = _array(report.get("Results"), "Trivy Results")
    if not results:
        raise ContainerScanReportError("Trivy Results must contain scan targets")
    findings: list[dict[str, Any]] = []
    for result_index, result_value in enumerate(results):
        result = _object(result_value, f"Trivy Results[{result_index}]")
        target = _required_string(result.get("Target"), f"Trivy Results[{result_index}].Target")
        vulnerabilities_value = result.get("Vulnerabilities")
        if vulnerabilities_value is None:
            continue
        vulnerabilities = _array(
            vulnerabilities_value,
            f"Trivy Results[{result_index}].Vulnerabilities",
        )
        for finding_index, finding_value in enumerate(vulnerabilities):
            prefix = f"Trivy Results[{result_index}].Vulnerabilities[{finding_index}]"
            finding = _object(finding_value, prefix)
            fixed_version = _optional_string(finding.get("FixedVersion"), f"{prefix}.FixedVersion")
            normalized: dict[str, Any] = {
                "id": _required_string(finding.get("VulnerabilityID"), f"{prefix}.VulnerabilityID"),
                "severity": _severity(finding.get("Severity"), f"{prefix}.Severity"),
                "package": _optional_string(finding.get("PkgName"), f"{prefix}.PkgName"),
                "installed_version": _optional_string(
                    finding.get("InstalledVersion"), f"{prefix}.InstalledVersion"
                ),
                "fixed_versions": [fixed_version] if fixed_version else [],
                "fix_state": _optional_string(finding.get("Status"), f"{prefix}.Status"),
                "target": target,
            }
            findings.append(normalized)
    return findings


def _grype_findings(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    matches = _array(report.get("matches"), "Grype matches")
    findings: list[dict[str, Any]] = []
    for match_index, match_value in enumerate(matches):
        prefix = f"Grype matches[{match_index}]"
        match = _object(match_value, prefix)
        vulnerability = _object(match.get("vulnerability"), f"{prefix}.vulnerability")
        artifact_value = match.get("artifact")
        artifact = {} if artifact_value is None else _object(artifact_value, f"{prefix}.artifact")
        fix_value = vulnerability.get("fix")
        fix = {} if fix_value is None else _object(fix_value, f"{prefix}.vulnerability.fix")
        versions_value = fix.get("versions", [])
        versions = _array(versions_value, f"{prefix}.vulnerability.fix.versions")
        fixed_versions = [
            _required_string(version, f"{prefix}.vulnerability.fix.versions[{index}]")
            for index, version in enumerate(versions)
        ]
        findings.append(
            {
                "id": _required_string(vulnerability.get("id"), f"{prefix}.vulnerability.id"),
                "severity": _severity(
                    vulnerability.get("severity"),
                    f"{prefix}.vulnerability.severity",
                ),
                "package": _optional_string(artifact.get("name"), f"{prefix}.artifact.name"),
                "installed_version": _optional_string(
                    artifact.get("version"), f"{prefix}.artifact.version"
                ),
                "fixed_versions": fixed_versions,
                "fix_state": _optional_string(
                    fix.get("state"), f"{prefix}.vulnerability.fix.state"
                ),
                "target": _optional_string(artifact.get("type"), f"{prefix}.artifact.type"),
            }
        )
    return findings


def summarize_report(document: object, scanner: str = "auto") -> dict[str, Any]:
    """Normalize a decoded Trivy or Grype report without enforcing the gate."""

    report = _object(document, "container scan report")
    detected = _detect_scanner(report, scanner)
    if detected == "trivy":
        scanner_schema: int | str | None = _trivy_schema(report)
        artifact = _trivy_artifact(report)
        findings = _trivy_findings(report)
    else:
        scanner_schema = _grype_schema(report)
        artifact = _grype_artifact(report)
        findings = _grype_findings(report)

    severity_counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity_counts[finding["severity"]] += 1
    blocked_count = sum(severity_counts[item] for item in BLOCKING_SEVERITIES)
    unfixed_blocked_count = sum(
        1
        for finding in findings
        if finding["severity"] in BLOCKING_SEVERITIES and not finding["fixed_versions"]
    )
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "scanner": detected,
        "format": f"{detected}-json",
        "scanner_schema": scanner_schema,
        "artifact": artifact,
        "total": len(findings),
        "severity_counts": severity_counts,
        "blocked_count": blocked_count,
        "unfixed_blocked_count": unfixed_blocked_count,
        "status": "FAIL" if blocked_count else "PASS",
        "findings": findings,
    }


def enforce_policy(summary: dict[str, Any]) -> dict[str, Any]:
    """Return a passing summary or raise with the failing summary attached."""

    if summary.get("blocked_count"):
        raise ContainerScanGateError(summary)
    return summary


def enforce_identity(summary: dict[str, Any], expected_image: str) -> dict[str, Any]:
    """Require the scanner report to be bound to the intended tag or digest."""

    expected = expected_image.strip()
    if not expected:
        raise ContainerScanReportError("expected image identity must not be empty")
    artifact = _object(summary.get("artifact"), "container scan artifact summary")
    references = _string_array(artifact.get("references"), "container scan artifact references")
    digests = _string_array(artifact.get("digests"), "container scan artifact digests")
    expected_digest = _reference_digest(expected)
    if expected in references or (expected_digest is not None and expected_digest in digests):
        return summary
    raise ContainerScanReportError(
        f"container scan report is not bound to expected image: {expected}"
    )


def parse_report(
    path: str | Path,
    scanner: str = "auto",
    *,
    expected_image: str | None = None,
) -> dict[str, Any]:
    """Load, validate, normalize, and enforce policy for a scan report path."""

    report_path = Path(path)
    try:
        raw = report_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"container scan report could not be read: {report_path}") from exc
    try:
        document: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"container scan report is not valid JSON: {report_path}") from exc
    summary = summarize_report(document, scanner)
    if expected_image is not None:
        enforce_identity(summary, expected_image)
    return enforce_policy(summary)


def _emit_summary(summary: Mapping[str, Any], output: Path | None, as_json: bool) -> None:
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    if as_json:
        print(rendered, end="")
    else:
        counts = summary["severity_counts"]
        print(
            f"{summary['status']}: {summary['scanner']} reported {summary['total']} "
            f"findings ({counts['critical']} critical, {counts['high']} high)"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="fail closed on High or Critical Trivy/Grype container findings"
    )
    parser.add_argument("report", type=Path, help="Trivy or Grype JSON report")
    parser.add_argument(
        "--scanner",
        "--format",
        choices=SUPPORTED_SCANNERS,
        default="auto",
        help="report format (default: auto-detect)",
    )
    parser.add_argument(
        "--output",
        "--summary",
        "--summary-json",
        dest="output",
        type=Path,
        help="write normalized JSON release evidence to this path",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the normalized JSON summary instead of a one-line result",
    )
    parser.add_argument(
        "--expected-image",
        help="require the report to identify this exact tag or sha256 digest",
    )
    arguments = parser.parse_args(argv)
    try:
        summary = parse_report(
            arguments.report,
            arguments.scanner,
            expected_image=arguments.expected_image,
        )
    except ContainerScanGateError as exc:
        _emit_summary(exc.summary, arguments.output, arguments.json)
        print(str(exc), file=sys.stderr)
        return 1
    except (TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _emit_summary(summary, arguments.output, arguments.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
