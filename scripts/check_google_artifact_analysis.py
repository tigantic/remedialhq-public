#!/usr/bin/env python3
"""Fail-closed Google Artifact Analysis gate for an immutable container image."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SUMMARY_SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 1_200.0
DEFAULT_POLL_INTERVAL_SECONDS = 15.0
VALID_SEVERITIES = ("CRITICAL", "HIGH", "LOW", "MEDIUM", "MINIMAL", "UNKNOWN")
BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
REQUIRED_ANALYSIS_TYPES = frozenset({"OS", "PYPI"})
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_URI_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9.-]*-docker\.pkg\.dev/[A-Za-z0-9._/-]+)"
    r"@(?P<digest>sha256:[0-9a-f]{64})$"
)
_GOOGLE_SBOM_KEY_RE = re.compile(
    r"^projects/goog-analysis/locations/global/keyRings/sbomAttestor/"
    r"cryptoKeys/generatedByArtifactAnalysis/cryptoKeyVersions/[1-9][0-9]*$"
)

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
Clock = Callable[[], float]
Sleeper = Callable[[float], None]


class ArtifactAnalysisError(RuntimeError):
    """Artifact Analysis evidence is unavailable, malformed, or policy-blocking."""


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ArtifactAnalysisError(f"{label} must be a JSON object")
    return value


def _array(value: object, label: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise ArtifactAnalysisError(f"{label} must be a JSON array")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ArtifactAnalysisError(f"{label} must be a non-empty string")
    return value


def _image_identity(image_uri: str) -> tuple[str, str]:
    match = _IMAGE_URI_RE.fullmatch(image_uri)
    if match is None or "//" in image_uri or len(match.group("name").split("/")) < 4:
        raise ArtifactAnalysisError(
            "image URI must be an immutable Artifact Registry sha256 reference"
        )
    return match.group("digest"), f"https://{image_uri}"


def _expected_sbom_note(image_uri: str) -> str:
    registry = image_uri.split("/", 1)[0]
    location = registry.removesuffix("-docker.pkg.dev")
    if not location or location == registry:
        raise ArtifactAnalysisError("image URI does not identify an Artifact Registry location")
    return f"projects/goog-analysis/locations/{location}/notes/sbom-spdx-2-3"


def _write_raw(path: Path, value: str) -> None:
    path.write_text(value if value.endswith("\n") else value + "\n", encoding="utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parse_json(value: str, label: str) -> object:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ArtifactAnalysisError(f"{label} returned invalid JSON: {exc}") from exc


def _run_command(
    command: Sequence[str],
    *,
    deadline: float,
    runner: CommandRunner,
    clock: Clock,
) -> subprocess.CompletedProcess[str]:
    remaining = deadline - clock()
    if remaining <= 0:
        raise ArtifactAnalysisError("Artifact Analysis exceeded the shared polling deadline")
    try:
        return runner(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1.0, remaining),
        )
    except subprocess.TimeoutExpired as exc:
        raise ArtifactAnalysisError("Artifact Analysis command exceeded the shared deadline") from exc
    except OSError as exc:
        raise ArtifactAnalysisError(f"Artifact Analysis command could not run: {exc}") from exc


def _authorization_failure(result: subprocess.CompletedProcess[str]) -> bool:
    error = result.stderr.upper()
    return "PERMISSION_DENIED" in error or "UNAUTHENTICATED" in error


def _retry_sleep(
    *,
    deadline: float,
    interval: float,
    clock: Clock,
    sleeper: Sleeper,
    timeout_message: str,
) -> None:
    remaining = deadline - clock()
    if remaining <= 0:
        raise ArtifactAnalysisError(timeout_message)
    sleeper(min(interval, remaining))


def _validate_discovery(
    document: Mapping[str, Any],
    *,
    image_uri: str,
    expected_digest: str,
    expected_resource_uri: str,
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]]] | None:
    image_summary_value = document.get("image_summary")
    if image_summary_value is None:
        return None
    image_summary = _object(image_summary_value, "Artifact Analysis image summary")
    if image_summary.get("digest") != expected_digest:
        raise ArtifactAnalysisError("Artifact Analysis discovery is bound to the wrong digest")
    if image_summary.get("fully_qualified_digest") != image_uri:
        raise ArtifactAnalysisError("Artifact Analysis discovery is bound to the wrong image URI")

    discovery_summary_value = document.get("discovery_summary")
    if discovery_summary_value is None:
        return None
    discovery_summary = _object(
        discovery_summary_value,
        "Artifact Analysis discovery summary",
    )
    discoveries_value = discovery_summary.get("discovery")
    if discoveries_value is None:
        return None
    discoveries = _array(discoveries_value, "Artifact Analysis discoveries")
    if not discoveries:
        return None

    successful: list[Mapping[str, Any]] = []
    terminal_failures: list[str] = []
    for index, occurrence_value in enumerate(discoveries):
        occurrence = _object(
            occurrence_value,
            f"Artifact Analysis discovery occurrence {index}",
        )
        if occurrence.get("resourceUri") != expected_resource_uri:
            raise ArtifactAnalysisError(
                f"Artifact Analysis discovery occurrence {index} has the wrong image"
            )
        discovery = _object(
            occurrence.get("discovery"),
            f"Artifact Analysis discovery occurrence {index} result",
        )
        status = discovery.get("analysisStatus")
        if status == "FINISHED_SUCCESS":
            successful.append(discovery)
        elif isinstance(status, str) and status.startswith("FINISHED"):
            terminal_failures.append(status)
    if terminal_failures:
        raise ArtifactAnalysisError(
            f"Artifact Analysis finished unsuccessfully: {sorted(terminal_failures)}"
        )
    if not successful:
        return None

    qualified: list[Mapping[str, Any]] = []
    for discovery in successful:
        completed = _object(
            discovery.get("analysisCompleted"),
            "Artifact Analysis completed analysis",
        )
        analysis_types = _array(
            completed.get("analysisType"),
            "Artifact Analysis completed analysis types",
        )
        if all(isinstance(item, str) for item in analysis_types) and (
            REQUIRED_ANALYSIS_TYPES <= set(analysis_types)
        ):
            qualified.append(discovery)
    if qualified:
        return image_summary, qualified
    raise ArtifactAnalysisError("Artifact Analysis did not complete OS and Python analysis")


def _validate_signature(
    reference: Mapping[str, Any],
    *,
    expected_resource_uri: str,
    expected_digest: str,
    expected_note_name: str,
    sbom_locations: frozenset[str],
) -> dict[str, str]:
    if reference.get("kind") != "SBOM_REFERENCE":
        raise ArtifactAnalysisError("Artifact Analysis SBOM occurrence kind is invalid")
    if reference.get("noteName") != expected_note_name:
        raise ArtifactAnalysisError("Artifact Analysis SBOM note is not Google-managed")
    sbom_reference = _object(reference.get("sbomReference"), "Artifact Analysis SBOM reference")
    if sbom_reference.get("payloadType") != "application/vnd.in-toto+json":
        raise ArtifactAnalysisError("Artifact Analysis SBOM payload type is invalid")
    payload = _object(sbom_reference.get("payload"), "Artifact Analysis SBOM payload")
    if payload.get("_type") != "https://in-toto.io/Statement/v0.1":
        raise ArtifactAnalysisError("Artifact Analysis SBOM statement type is invalid")
    if payload.get("predicateType") != "https://containeranalysis.googleapis.com/reference/v0.1":
        raise ArtifactAnalysisError("Artifact Analysis SBOM predicate type is invalid")

    subjects = _array(payload.get("subject"), "Artifact Analysis SBOM subjects")
    if len(subjects) != 1:
        raise ArtifactAnalysisError("Artifact Analysis SBOM must identify exactly one subject")
    subject = _object(subjects[0], "Artifact Analysis SBOM subject")
    subject_digest = _object(
        subject.get("digest"),
        "Artifact Analysis SBOM subject digest",
    )
    if subject.get("name") != expected_resource_uri:
        raise ArtifactAnalysisError("Artifact Analysis SBOM subject has the wrong image URI")
    if subject_digest.get("sha256") != expected_digest.removeprefix("sha256:"):
        raise ArtifactAnalysisError("Artifact Analysis SBOM subject has the wrong digest")

    predicate = _object(payload.get("predicate"), "Artifact Analysis SBOM predicate")
    if (
        predicate.get("referrerId")
        != "https://containeranalysis.googleapis.com/ArtifactAnalysis@v0.1"
    ):
        raise ArtifactAnalysisError("Artifact Analysis SBOM referrer is invalid")
    location = _string(predicate.get("location"), "Artifact Analysis SBOM location")
    if location not in sbom_locations or not location.startswith("gs://"):
        raise ArtifactAnalysisError("Artifact Analysis SBOM location is not image-bound")
    if predicate.get("mimeType") != "application/spdx+json":
        raise ArtifactAnalysisError("Artifact Analysis SBOM MIME type is invalid")
    predicate_digest = _object(
        predicate.get("digest"),
        "Artifact Analysis SBOM document digest",
    )
    sbom_sha256 = _string(
        predicate_digest.get("sha256"),
        "Artifact Analysis SBOM document sha256",
    )
    if re.fullmatch(r"[0-9a-f]{64}", sbom_sha256) is None:
        raise ArtifactAnalysisError("Artifact Analysis SBOM document sha256 is invalid")

    signatures = _array(
        sbom_reference.get("signatures"),
        "Artifact Analysis SBOM signatures",
    )
    if not signatures:
        raise ArtifactAnalysisError("Artifact Analysis SBOM has no signature")
    for index, signature_value in enumerate(signatures):
        signature = _object(
            signature_value,
            f"Artifact Analysis SBOM signature {index}",
        )
        key_id = _string(signature.get("keyid"), "Artifact Analysis SBOM signature key ID")
        if _GOOGLE_SBOM_KEY_RE.fullmatch(key_id) is None:
            raise ArtifactAnalysisError("Artifact Analysis SBOM signature is not Google-bound")
        encoded_signature = _string(signature.get("sig"), "Artifact Analysis SBOM signature")
        try:
            signature_bytes = base64.b64decode(encoded_signature, validate=True)
        except binascii.Error as exc:
            raise ArtifactAnalysisError("Artifact Analysis SBOM signature encoding is invalid") from exc
        if len(signature_bytes) < 64:
            raise ArtifactAnalysisError("Artifact Analysis SBOM signature is too short")

    envelope = _object(reference.get("envelope"), "Artifact Analysis SBOM envelope")
    if envelope.get("payloadType") != sbom_reference.get("payloadType"):
        raise ArtifactAnalysisError("Artifact Analysis SBOM envelope payload type does not match")
    if envelope.get("signatures") != sbom_reference.get("signatures"):
        raise ArtifactAnalysisError("Artifact Analysis SBOM envelope signatures do not match")
    encoded_payload = _string(
        envelope.get("payload"),
        "Artifact Analysis SBOM envelope payload",
    )
    try:
        decoded_payload = json.loads(base64.b64decode(encoded_payload, validate=True))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactAnalysisError("Artifact Analysis SBOM envelope payload is invalid") from exc
    if decoded_payload != payload:
        raise ArtifactAnalysisError("Artifact Analysis SBOM envelope payload does not match")
    return {"location": location, "sha256": sbom_sha256}


def _validate_sbom(
    document: Mapping[str, Any],
    *,
    image_summary: Mapping[str, Any],
    discovery: Mapping[str, Any],
    image_uri: str,
    expected_digest: str,
    expected_resource_uri: str,
) -> list[dict[str, str]] | None:
    sbom_status_value = discovery.get("sbomStatus")
    if sbom_status_value is None:
        return None
    sbom_status = _object(sbom_status_value, "Artifact Analysis SBOM status")
    sbom_state = sbom_status.get("sbomState")
    if sbom_state != "COMPLETE":
        if isinstance(sbom_state, str) and sbom_state not in {"PENDING", "UNSPECIFIED"}:
            raise ArtifactAnalysisError(f"Artifact Analysis SBOM finished as {sbom_state}")
        return None

    locations_value = image_summary.get("sbom_locations")
    if locations_value is None:
        return None
    locations = _array(locations_value, "Artifact Analysis SBOM locations")
    if not locations:
        return None
    if not all(isinstance(item, str) and item for item in locations):
        raise ArtifactAnalysisError("Artifact Analysis SBOM locations are malformed")
    sbom_locations = frozenset(locations)
    if len(sbom_locations) != len(locations):
        raise ArtifactAnalysisError("Artifact Analysis SBOM locations contain duplicates")

    summary_value = document.get("sbom_summary")
    if summary_value is None:
        return None
    summary = _object(summary_value, "Artifact Analysis SBOM summary")
    references_value = summary.get("sbom_references")
    if references_value is None:
        return None
    references = _array(references_value, "Artifact Analysis SBOM references")
    if not references:
        return None

    verified: list[dict[str, str]] = []
    for index, reference_value in enumerate(references):
        reference = _object(
            reference_value,
            f"Artifact Analysis SBOM reference {index}",
        )
        if reference.get("resourceUri") != expected_resource_uri:
            raise ArtifactAnalysisError(
                f"Artifact Analysis SBOM reference {index} has the wrong image"
            )
        verified.append(
            _validate_signature(
                reference,
                expected_resource_uri=expected_resource_uri,
                expected_digest=expected_digest,
                expected_note_name=_expected_sbom_note(image_uri),
                sbom_locations=sbom_locations,
            )
        )
    return verified


def _describe_command(image_uri: str, *, include_sbom_references: bool) -> list[str]:
    command = [
        "gcloud",
        "artifacts",
        "docker",
        "images",
        "describe",
        image_uri,
        "--show-package-vulnerability",
    ]
    if include_sbom_references:
        command.append("--show-sbom-references")
    command.append("--format=json")
    return command


def _poll_discovery(
    image_uri: str,
    *,
    expected_digest: str,
    expected_resource_uri: str,
    require_sbom: bool,
    discovery_path: Path,
    deadline: float,
    poll_interval_seconds: float,
    runner: CommandRunner,
    clock: Clock,
    sleeper: Sleeper,
) -> tuple[Mapping[str, Any], Mapping[str, Any], list[dict[str, str]]]:
    attempt = 0
    timeout_message = (
        "Artifact Analysis did not publish a complete signed SBOM before the shared deadline"
        if require_sbom
        else "Artifact Analysis did not finish OS and Python analysis before the shared deadline"
    )
    while True:
        attempt += 1
        result = _run_command(
            _describe_command(image_uri, include_sbom_references=require_sbom),
            deadline=deadline,
            runner=runner,
            clock=clock,
        )
        if result.returncode != 0:
            if _authorization_failure(result):
                raise ArtifactAnalysisError(
                    f"Artifact Analysis discovery is unauthorized: {result.stderr.strip()}"
                )
            print(
                f"Artifact Analysis discovery attempt {attempt} failed; retrying",
                file=sys.stderr,
            )
        else:
            document_value = _parse_json(result.stdout, "Artifact Analysis discovery")
            document = _object(document_value, "Artifact Analysis discovery response")
            _write_raw(discovery_path, result.stdout)
            ready = _validate_discovery(
                document,
                image_uri=image_uri,
                expected_digest=expected_digest,
                expected_resource_uri=expected_resource_uri,
            )
            if ready is not None:
                image_summary, discoveries = ready
                if not require_sbom:
                    return image_summary, discoveries[0], []
                ordered_discoveries = sorted(
                    discoveries,
                    key=lambda item: (
                        isinstance(item.get("sbomStatus"), dict)
                        and item["sbomStatus"].get("sbomState") == "COMPLETE"
                    ),
                    reverse=True,
                )
                for discovery in ordered_discoveries:
                    references = _validate_sbom(
                        document,
                        image_summary=image_summary,
                        discovery=discovery,
                        image_uri=image_uri,
                        expected_digest=expected_digest,
                        expected_resource_uri=expected_resource_uri,
                    )
                    if references is not None:
                        return image_summary, discovery, references
        _retry_sleep(
            deadline=deadline,
            interval=poll_interval_seconds,
            clock=clock,
            sleeper=sleeper,
            timeout_message=timeout_message,
        )


def _validate_spdx_document(value: object, *, image_uri: str) -> dict[str, Any]:
    document = _object(value, "Artifact Analysis SPDX document")
    if document.get("spdxVersion") != "SPDX-2.3":
        raise ArtifactAnalysisError("Artifact Analysis SBOM is not SPDX 2.3")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ArtifactAnalysisError("Artifact Analysis SPDX document ID is invalid")
    if document.get("dataLicense") != "CC0-1.0":
        raise ArtifactAnalysisError("Artifact Analysis SPDX data license is invalid")
    if document.get("name") != image_uri.rsplit("/", 1)[-1]:
        raise ArtifactAnalysisError("Artifact Analysis SPDX name is not image-bound")
    namespace = _string(
        document.get("documentNamespace"),
        "Artifact Analysis SPDX document namespace",
    )
    if not namespace.startswith(f"https://{image_uri}_"):
        raise ArtifactAnalysisError("Artifact Analysis SPDX namespace is not image-bound")
    packages = _array(document.get("packages"), "Artifact Analysis SPDX packages")
    relationships = _array(
        document.get("relationships"),
        "Artifact Analysis SPDX relationships",
    )
    if not packages or not all(isinstance(item, dict) for item in packages):
        raise ArtifactAnalysisError("Artifact Analysis SPDX package inventory is empty or malformed")
    if not relationships or not all(isinstance(item, dict) for item in relationships):
        raise ArtifactAnalysisError("Artifact Analysis SPDX relationships are empty or malformed")
    return {
        "data_license": "CC0-1.0",
        "document_namespace": namespace,
        "package_count": len(packages),
        "relationship_count": len(relationships),
        "spdx_version": "SPDX-2.3",
    }


def _download_and_verify_sbom(
    references: Sequence[Mapping[str, str]],
    *,
    image_uri: str,
    output_path: Path,
    deadline: float,
    runner: CommandRunner,
    clock: Clock,
) -> dict[str, Any]:
    unique_references = {
        (reference.get("location", ""), reference.get("sha256", ""))
        for reference in references
    }
    if len(unique_references) != 1:
        raise ArtifactAnalysisError("Artifact Analysis SBOM references are ambiguous")
    location, expected_sha256 = next(iter(unique_references))
    if not location.startswith("gs://") or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ArtifactAnalysisError("Artifact Analysis SBOM download reference is invalid")
    result = _run_command(
        ["gcloud", "storage", "cat", location, "--quiet"],
        deadline=deadline,
        runner=runner,
        clock=clock,
    )
    if result.returncode != 0:
        raise ArtifactAnalysisError(
            f"Artifact Analysis SBOM object could not be read: {result.stderr.strip()}"
        )
    sbom_bytes = result.stdout.encode("utf-8")
    output_path.write_bytes(sbom_bytes)
    actual_sha256 = hashlib.sha256(sbom_bytes).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ArtifactAnalysisError("Artifact Analysis SBOM object hash does not match its reference")
    spdx_summary = _validate_spdx_document(
        _parse_json(result.stdout, "Artifact Analysis SBOM object"),
        image_uri=image_uri,
    )
    return {
        "downloaded_sha256": actual_sha256,
        "location": location,
        "signed_reference_hash_matches_download": True,
        **spdx_summary,
    }


def _summarize_vulnerabilities(
    value: object,
    *,
    expected_resource_uri: str,
) -> dict[str, Any]:
    raw = _array(value, "Artifact Analysis vulnerabilities response")
    singleton_null_normalized = list(raw) == [None]
    findings: Sequence[Any] = [] if singleton_null_normalized else raw
    counts = dict.fromkeys(VALID_SEVERITIES, 0)
    blocked: list[dict[str, Any]] = []
    for index, item_value in enumerate(findings):
        item = _object(item_value, f"Artifact Analysis vulnerability {index}")
        occurrence = _object(
            item.get("occurrence"),
            f"Artifact Analysis vulnerability {index} occurrence",
        )
        if occurrence.get("resourceUri") != expected_resource_uri:
            raise ArtifactAnalysisError(
                f"Artifact Analysis vulnerability {index} has the wrong image"
            )
        vulnerability = _object(
            occurrence.get("vulnerability"),
            f"Artifact Analysis vulnerability {index} details",
        )
        severity = vulnerability.get("effectiveSeverity")
        if not isinstance(severity, str) or severity not in counts:
            raise ArtifactAnalysisError(
                f"Artifact Analysis vulnerability {index} has no valid effective severity"
            )
        counts[severity] += 1
        if severity in BLOCKING_SEVERITIES:
            blocked.append(
                {
                    "effective_severity": severity,
                    "note": occurrence.get("noteName"),
                    "short_description": vulnerability.get("shortDescription"),
                }
            )
    return {
        "blocked_findings": blocked,
        "raw_singleton_null_normalized": singleton_null_normalized,
        "severity_counts": counts,
        "total_findings": len(findings),
    }


def run_gate(
    image_uri: str,
    *,
    output_dir: Path,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    runner: CommandRunner = subprocess.run,
    clock: Clock = time.monotonic,
    sleeper: Sleeper = time.sleep,
) -> dict[str, Any]:
    if (
        not math.isfinite(timeout_seconds)
        or not math.isfinite(poll_interval_seconds)
        or timeout_seconds <= 0
        or poll_interval_seconds <= 0
    ):
        raise ValueError("timeout and poll interval must be finite positive numbers")
    output_dir.mkdir(parents=True, exist_ok=True)
    discovery_path = output_dir / "artifact-analysis-discovery.json"
    export_path = output_dir / "artifact-analysis-sbom-export.json"
    sbom_path = output_dir / "artifact-analysis-sbom.spdx.json"
    vulnerabilities_path = output_dir / "artifact-analysis-vulnerabilities.json"
    summary_path = output_dir / "artifact-analysis-summary.json"
    started_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    started = clock()
    deadline = started + timeout_seconds
    summary: dict[str, Any] = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "status": "FAIL",
        "generated_at": started_at,
        "image": image_uri,
    }
    try:
        expected_digest, expected_resource_uri = _image_identity(image_uri)
        summary["digest"] = expected_digest
        _poll_discovery(
            image_uri,
            expected_digest=expected_digest,
            expected_resource_uri=expected_resource_uri,
            require_sbom=False,
            discovery_path=discovery_path,
            deadline=deadline,
            poll_interval_seconds=poll_interval_seconds,
            runner=runner,
            clock=clock,
            sleeper=sleeper,
        )

        export_result = _run_command(
            [
                "gcloud",
                "artifacts",
                "sbom",
                "export",
                f"--uri={image_uri}",
                "--format=json",
            ],
            deadline=deadline,
            runner=runner,
            clock=clock,
        )
        _write_raw(export_path, export_result.stdout)
        if export_result.returncode != 0:
            raise ArtifactAnalysisError(
                f"Artifact Analysis SBOM export failed: {export_result.stderr.strip()}"
            )
        _parse_json(export_result.stdout, "Artifact Analysis SBOM export")

        _, _, sbom_references = _poll_discovery(
            image_uri,
            expected_digest=expected_digest,
            expected_resource_uri=expected_resource_uri,
            require_sbom=True,
            discovery_path=discovery_path,
            deadline=deadline,
            poll_interval_seconds=poll_interval_seconds,
            runner=runner,
            clock=clock,
            sleeper=sleeper,
        )
        sbom_summary = _download_and_verify_sbom(
            sbom_references,
            image_uri=image_uri,
            output_path=sbom_path,
            deadline=deadline,
            runner=runner,
            clock=clock,
        )

        vulnerability_result = _run_command(
            [
                "gcloud",
                "artifacts",
                "vulnerabilities",
                "list",
                image_uri,
                "--format=json",
            ],
            deadline=deadline,
            runner=runner,
            clock=clock,
        )
        _write_raw(vulnerabilities_path, vulnerability_result.stdout)
        if vulnerability_result.returncode != 0:
            raise ArtifactAnalysisError(
                "Artifact Analysis vulnerabilities could not be listed: "
                + vulnerability_result.stderr.strip()
            )
        vulnerabilities = _parse_json(
            vulnerability_result.stdout,
            "Artifact Analysis vulnerabilities",
        )
        vulnerability_summary = _summarize_vulnerabilities(
            vulnerabilities,
            expected_resource_uri=expected_resource_uri,
        )
        summary.update(
            {
                "analysis_status": "FINISHED_SUCCESS",
                "sbom_export_requested": True,
                "sbom_export_location_flag_used": False,
                "sbom_reference_count": len(sbom_references),
                "sbom_references": sbom_references,
                "sbom_state": "COMPLETE",
                "sbom_document": sbom_summary,
                "signature_trust_boundary": (
                    "authenticated read-only Google Artifact Analysis API response"
                ),
                "signature_cryptographically_verified_independently": False,
                **vulnerability_summary,
            }
        )
        blocked = vulnerability_summary["blocked_findings"]
        if blocked:
            raise ArtifactAnalysisError(
                f"Artifact Analysis rejected {len(blocked)} Critical or High finding(s)"
            )
        summary["status"] = "PASS"
        summary["elapsed_seconds"] = round(clock() - started, 3)
        _write_json(summary_path, summary)
        return summary
    except ArtifactAnalysisError as exc:
        summary["status"] = "FAIL"
        summary["error"] = str(exc)
        summary["elapsed_seconds"] = round(clock() - started, 3)
        _write_json(summary_path, summary)
        raise


def _positive_number(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image_uri", help="Immutable Artifact Registry image URI")
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument(
        "--timeout-seconds",
        type=_positive_number,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=_positive_number,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run_gate(
            args.image_uri,
            output_dir=args.output_dir,
            timeout_seconds=args.timeout_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
        )
    except (ArtifactAnalysisError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
