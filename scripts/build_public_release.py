#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

SAFE_DIRECTORIES = {
    ".github",
    "artifacts",
    "brand",
    "config",
    "content",
    "data",
    "docs",
    "infra",
    "ops",
    "scripts",
    "site",
    "src",
    "tests",
}
PUBLIC_ROOT_FILES = {
    ".dockerignore",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "BUILD_REPORT.md",
    "CHANGELOG.md",
    "Dockerfile",
    "LICENSE.txt",
    "README.md",
    "RELEASE_NOTES.md",
    "requirements-build.in",
    "requirements-build.lock",
    "requirements-dev.in",
    "requirements-dev.lock",
    "requirements-production.lock",
    "requirements-runtime.lock",
    "SBOM.cdx.json",
    "SECURITY.md",
    "VERSION",
    "pyproject.toml",
}
FORBIDDEN_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    ".venv",
    "__pycache__",
    "archive",
    "local-private",
    "release",
    "secrets",
}
FORBIDDEN_NAME_FRAGMENTS = (
    "client_secret",
    "owner_profile",
    "private_key",
    "recovery_code",
)
FORBIDDEN_SUFFIXES = {".bundle", ".key", ".pem", ".token", ".zip"}

# Only these reviewed, public-facing artifacts may cross the release boundary.
# Generated evidence, dry-run envelopes, and held red-team output are not public assets.
PUBLIC_ARTIFACT_PATHS = {
    *(f"artifacts/launch/frames/scene-{number:02d}.png" for number in range(1, 10)),
    *(f"artifacts/launch/short-contact-sheet-{number}.png" for number in range(9)),
    "artifacts/launch/remedialhq-launch-short-visual-prototype.mp4",
    "artifacts/launch/short-001-storyboard.json",
    "artifacts/launch/short-contact-sheet.png",
    "artifacts/revenue/first_dollar_validation.csv",
    "artifacts/revenue/first_dollar_validation.json",
    "artifacts/revenue/sample-creator-signal-desk.md",
    "artifacts/revenue/scenarios.csv",
    "artifacts/revenue/scenarios.json",
}

# Administrative authority and owner-identity records remain available only in the
# private Git bundle or the ignored owner workspace. They never cross into the
# shareable public-source archive, even when they are tracked and otherwise reviewed.
PRIVATE_ADMIN_PATHS = frozenset({
    "docs/07_BOOTSTRAP_AND_RUNBOOK.md",
    "docs/10_BRAND_AUTHORITY.md",
    "docs/11_REMEDIALHQ_BRAND_STATUS.md",
    "docs/12_OWNER_DECISION_RECORD.md",
    "docs/13_CONTEXT_WINDOW_DELIVERABLES.md",
    "docs/15_OWNER_CREDENTIAL_MATRIX.md",
    "ops/CREATOR_DESK_ORDER_CONFIRMATION_TEMPLATE.md",
    "ops/EXECUTION_PLAN.csv",
    "ops/EXECUTION_PLAN.md",
    "ops/NEXT_ACTIONS.md",
    "ops/account_inventory.json",
    "ops/execution_plan.json",
    "scripts/check_release_evidence.py",
    "scripts/render_execution_plan.py",
    "scripts/validate_release.py",
    "tests/test_execution.py",
    "tests/test_paid_service_terms.py",
    "tests/test_release_integrity.py",
})

# Every repository blob eligible for the public ZIP is named here. New files do not
# cross the public release boundary until a reviewer adds their exact path.
PUBLIC_FILE_PATHS = frozenset(PUBLIC_ROOT_FILES | PUBLIC_ARTIFACT_PATHS | {
    ".github/workflows/ci.yml",
    ".github/workflows/deploy.yml",
    "brand/brand.json",
    "brand/channel-banner.png",
    "brand/channel-banner.svg",
    "brand/favicon.png",
    "brand/favicon.svg",
    "brand/logo-lockup.png",
    "brand/logo-lockup.svg",
    "brand/logo-mark.png",
    "brand/logo-mark.svg",
    "brand/render-manifest.json",
    "brand/short-cover-001.png",
    "brand/short-cover-001.svg",
    "brand/social-avatar.png",
    "brand/social-avatar.svg",
    "brand/thumbnail-episode-001.png",
    "brand/thumbnail-episode-001.svg",
    "brand/video-watermark.png",
    "brand/video-watermark.svg",
    "config/platforms.json",
    "config/outreach-plan.schema.json",
    "config/policy.json",
    "config/public_identity.json",
    "config/publication_authority.json",
    "config/revenue.json",
    "config/sources.json",
    "content/calendar/LAUNCH_DAY_COMMAND_CENTER.md",
    "content/calendar/prelaunch-calendar.csv",
    "content/calendar/prelaunch-calendar.json",
    "content/launch/article-001.md",
    "content/launch/episode-001.md",
    "content/launch/episode-001.structured.json",
    "content/launch/newsletter-001.md",
    "content/launch/publish-package-001.json",
    "content/launch/short-001.md",
    "content/launch/social-thread-001.md",
    "content/quarantine/README.md",
    "content/queue/seed_queue.jsonl",
    "content/queue/seed_queue_summary.json",
    "data/claims/seed_claims.jsonl",
    "data/research/vidiq_snapshot_2026-08-28.json",
    "data/sources/seed_sources.jsonl",
    "docs/00_EXECUTIVE_DIRECTIVE.md",
    "docs/01_SYSTEM_ARCHITECTURE.md",
    "docs/02_AUTONOMY_CONTRACT.md",
    "docs/03_CONTENT_SYSTEM.md",
    "docs/04_IP_PLATFORM_POLICY.md",
    "docs/05_MONETIZATION.md",
    "docs/06_82_DAY_LAUNCH.md",
    "docs/07_BOOTSTRAP_AND_RUNBOOK.md",
    "docs/08_THREAT_MODEL_AND_EXPERIMENTS.md",
    "docs/09_RESEARCH_SNAPSHOT.md",
    "docs/10_BRAND_AUTHORITY.md",
    "docs/11_REMEDIALHQ_BRAND_STATUS.md",
    "docs/12_OWNER_DECISION_RECORD.md",
    "docs/13_CONTEXT_WINDOW_DELIVERABLES.md",
    "docs/14_OPPORTUNITY_AND_BUSINESS_THESIS.md",
    "docs/15_OWNER_CREDENTIAL_MATRIX.md",
    "infra/GITHUB_WIF_SETUP.md",
    "infra/sites/README.md",
    "infra/sites/vite-env.d.ts",
    "infra/sites/worker.ts",
    "infra/terraform/.terraform.lock.hcl",
    "infra/terraform/README.md",
    "infra/terraform/main.tf",
    "infra/terraform/outputs.tf",
    "infra/terraform/terraform.tfvars.example",
    "infra/terraform/variables.tf",
    "infra/terraform/versions.tf",
    "ops/ANALYTICS_SETUP.md",
    "ops/BOOKKEEPING_SETUP.md",
    "ops/BRANDED_EMAIL_MAP.md",
    "ops/CREATOR_DESK_ORDER_CONFIRMATION_TEMPLATE.md",
    "ops/EXECUTION_PLAN.csv",
    "ops/EXECUTION_PLAN.md",
    "ops/FIRST_DOLLAR_PLAYBOOK.md",
    "ops/GCP_BOOTSTRAP.md",
    "ops/NEXT_ACTIONS.md",
    "ops/PAYMENT_TEST_RUNBOOK.md",
    "ops/YOUTUBE_CHANNEL_SETUP.md",
    "ops/account_inventory.json",
    "ops/execution_plan.json",
    "scripts/__init__.py",
    "scripts/bootstrap_gcp.sh",
    "scripts/build_launch_short.py",
    "scripts/build_public_bundle.py",
    "scripts/build_public_release.py",
    "scripts/check_container_scan.py",
    "scripts/check_google_artifact_analysis.py",
    "scripts/check_live_site.py",
    "scripts/configure_github_wif.sh",
    "scripts/red_team_generated_draft.py",
    "scripts/render_brand_assets.py",
    "scripts/render_execution_plan.py",
    "scripts/render_dockerignore.py",
    "scripts/revenue_model.py",
    "scripts/stage_sites_deployment.py",
    "scripts/sync_site_data.py",
    "scripts/validate_release.py",
    "scripts/verify_manifest.py",
    "site/404.html",
    "site/_headers",
    "site/_redirects",
    "site/about.html",
    "site/affiliate-disclosure.html",
    "site/ai-disclosure.html",
    "site/app.js",
    "site/contact.html",
    "site/corrections.html",
    "site/coverage.html",
    "site/creator-desk.html",
    "site/data-deletion.html",
    "site/data/claims.json",
    "site/data/manifest.json",
    "site/data/sources.json",
    "site/dmca.html",
    "site/editorial-standards.html",
    "site/favicon.svg",
    "site/gta-vi-official-state.html",
    "site/index.html",
    "site/og-card.png",
    "site/og-card.svg",
    "site/privacy.html",
    "site/robots.txt",
    "site/sample-creator-brief.html",
    "site/sitemap.xml",
    "site/sponsors.html",
    "site/styles.css",
    "site/terms.html",
    "src/remedialhq/__init__.py",
    "src/remedialhq/auth.py",
    "src/remedialhq/briefing.py",
    "src/remedialhq/canonical.py",
    "src/remedialhq/cli.py",
    "src/remedialhq/collector.py",
    "src/remedialhq/delivery_evidence.py",
    "src/remedialhq/execution.py",
    "src/remedialhq/gates.py",
    "src/remedialhq/idempotency.py",
    "src/remedialhq/ledger.py",
    "src/remedialhq/llm.py",
    "src/remedialhq/metrics.py",
    "src/remedialhq/models.py",
    "src/remedialhq/outreach.py",
    "src/remedialhq/payment_evidence.py",
    "src/remedialhq/payment_tests.py",
    "src/remedialhq/phase_artifacts.py",
    "src/remedialhq/phases.py",
    "src/remedialhq/pilots.py",
    "src/remedialhq/pipeline.py",
    "src/remedialhq/provenance.py",
    "src/remedialhq/publishers/__init__.py",
    "src/remedialhq/publishers/base.py",
    "src/remedialhq/publishers/dry_run.py",
    "src/remedialhq/publishers/youtube.py",
    "src/remedialhq/renderer.py",
    "src/remedialhq/scoring.py",
    "src/remedialhq/service.py",
    "src/remedialhq/source_registry.py",
    "src/remedialhq/worker.py",
    "tests/test_auth.py",
    "tests/test_briefing.py",
    "tests/test_creator_brief_cli.py",
    "tests/test_demo.py",
    "tests/test_delivery_evidence.py",
    "tests/test_deployment_security.py",
    "tests/test_execution.py",
    "tests/test_gates.py",
    "tests/test_google_artifact_analysis.py",
    "tests/test_idempotency.py",
    "tests/test_ledger.py",
    "tests/test_live_site.py",
    "tests/test_metrics.py",
    "tests/test_outreach.py",
    "tests/test_outreach_cli.py",
    "tests/test_payment_evidence.py",
    "tests/test_payment_tests.py",
    "tests/test_phase_artifacts.py",
    "tests/test_paid_service_terms.py",
    "tests/test_phases.py",
    "tests/test_pilot_cli.py",
    "tests/test_pilots.py",
    "tests/test_provenance.py",
    "tests/test_public_bundle.py",
    "tests/test_public_release.py",
    "tests/test_release_integrity.py",
    "tests/test_container_scan.py",
    "tests/test_scoring.py",
    "tests/test_service.py",
    "tests/test_sites_staging.py",
    "tests/test_source_registry.py",
    "tests/test_youtube_adapter.py",
})

# This mode exists only for a package command that immediately follows validation.
# It never changes what is packaged: all archive data still comes from committed HEAD.
GENERATED_EVIDENCE_PATHS = {
    "BUILD_REPORT.md",
    "MANIFEST.sha256",
    "RELEASE_NOTES.md",
    "SBOM.cdx.json",
    "artifacts/demo/.remedialhq-demo-output",
    "artifacts/demo/ledger.jsonl",
    "artifacts/demo/publish/PKG-LAUNCH-0001-NEWSLETTER-newsletter.publish.json",
    "artifacts/demo/publish/PKG-LAUNCH-0001-SITE-site.publish.json",
    "artifacts/demo/publish/PKG-LAUNCH-0001-X-x.publish.json",
    "artifacts/demo/publish/PKG-LAUNCH-0001-YOUTUBE-youtube.publish.json",
    "artifacts/demo/render/PKG-LAUNCH-0001-NEWSLETTER.manifest.json",
    "artifacts/demo/render/PKG-LAUNCH-0001-SITE.manifest.json",
    "artifacts/demo/render/PKG-LAUNCH-0001-X.manifest.json",
    "artifacts/demo/render/PKG-LAUNCH-0001-YOUTUBE.manifest.json",
    "artifacts/demo/render/launch-claim-cards.svg",
    "artifacts/demo/run-report.json",
    "artifacts/red-team/generated-draft-adjudication.json",
    "artifacts/validation/build-launch-short.txt",
    "artifacts/validation/compileall.txt",
    "artifacts/validation/docker-build.txt",
    "artifacts/validation/docker-image-identity-format.txt",
    "artifacts/validation/docker-image-identity.txt",
    "artifacts/validation/dry-run-demo.txt",
    "artifacts/validation/ffprobe-launch-short.json",
    "artifacts/validation/javascript-syntax.txt",
    "artifacts/validation/image-python-distributions.txt",
    "artifacts/validation/ledger-verification.txt",
    "artifacts/validation/live-site-report.json",
    "artifacts/validation/mypy.txt",
    "artifacts/validation/red-team-generated-draft.txt",
    "artifacts/validation/render-brand-assets.txt",
    "artifacts/validation/render-execution-plan.txt",
    "artifacts/validation/revenue-model.txt",
    "artifacts/validation/ruff.txt",
    "artifacts/validation/sbom-completeness.txt",
    "artifacts/validation/syft-image-sbom.txt",
    "artifacts/validation/syft-production-image.raw.cdx.json",
    "artifacts/validation/production-image-sbom.txt",
    "artifacts/validation/grype-production-image.json",
    "artifacts/validation/grype-production-image.summary.json",
    "artifacts/validation/grype-production-image.txt",
    "artifacts/validation/trivy-production-image.json",
    "artifacts/validation/trivy-production-image.summary.json",
    "artifacts/validation/trivy-production-image.txt",
    "artifacts/validation/container-vulnerability-gate.txt",
    "artifacts/validation/sync-site-data.txt",
    "artifacts/validation/terraform-format.txt",
    "artifacts/validation/terraform-init.txt",
    "artifacts/validation/terraform-validate.txt",
    "artifacts/validation/unit-tests.txt",
    "artifacts/validation/validation-report.json",
}

CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("Cloudflare API token", re.compile(rb"cfut_[A-Za-z0-9_-]{20,}")),
    ("Cloudflare Global API key", re.compile(rb"cfk_[A-Za-z0-9_-]{20,}")),
    (
        "GitHub access token",
        re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    ),
    (
        "OpenAI API key",
        re.compile(rb"sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}"),
    ),
    ("AWS access key", re.compile(rb"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}")),
    ("Stripe live or restricted key", re.compile(rb"(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z_-]{30,}")),
    (
        "JWT",
        re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    ("private key block", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "quoted secret assignment",
        re.compile(
            rb"(?i)[\"']?[A-Za-z0-9_.-]*(?:api[_-]?(?:key|token)|access[_-]?token|"
            rb"auth[_-]?token|client[_-]?secret|password|passwd|secret)[\"']?"
            rb"\s*[:=]\s*[\"'][^\"'\r\n]{12,}[\"']"
        ),
    ),
    (
        "environment secret assignment",
        re.compile(
            rb"(?m)^[A-Z][A-Z0-9_]*(?:API_KEY|API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|"
            rb"CLIENT_SECRET|PASSWORD|SECRET)[A-Z0-9_]*[ \t]*=[ \t]*"
            rb"[^\s#]{12,}[ \t]*$"
        ),
    ),
)

LOCAL_PATH_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "Windows user profile path",
        re.compile(rb"(?i)(?:[A-Z]:[\\/]+Users[\\/]+[^\\/\x00\r\n]+[\\/])"),
    ),
    (
        "WSL-mounted Windows user profile path",
        re.compile(rb"(?i)/mnt/[a-z]/" + rb"Users/[^/\x00\r\n]+/"),
    ),
    ("Linux home path", re.compile(b"/" + rb"home/[^/\x00\r\n]+/")),
    ("macOS home path", re.compile(b"/" + rb"Users/[^/\x00\r\n]+/")),
    (
        "common local workspace path",
        re.compile(
            rb"(?i)(?:[A-Z]:[\\/]+(?:workspace|workspaces|projects)[\\/]+|"
            rb"/(?:workspace|workspaces)/)"
        ),
    ),
)

def _nested_string(data: dict[str, Any], *keys: str) -> str | None:
    value: Any = data
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _owner_identity_patterns(
    revision: str = "HEAD",
) -> tuple[tuple[str, re.Pattern[bytes]], ...]:
    """Load private identity values without embedding them in public source.

    The administrative inventory is deliberately excluded from the public package.
    A package rebuilt from the public source therefore has no private identity values
    to disclose or scan for, while an administrative build uses the private inventory
    as an additional release-boundary control.
    """

    try:
        inventory_data = _git_bytes(
            "show",
            f"{revision}:ops/account_inventory.json",
        )
    except subprocess.CalledProcessError:
        return ()
    try:
        inventory = json.loads(inventory_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("committed private account inventory is invalid") from error
    if not isinstance(inventory, dict):
        raise TypeError("private account inventory must be a JSON object")

    display_name = _nested_string(inventory, "owner", "display_name")
    exact_values: list[tuple[str, str]] = []
    token_values: list[tuple[str, str]] = []
    if display_name:
        exact_values.append(("owner display name", display_name))
        name_tokens = re.findall(r"[A-Za-z]{3,}", display_name)
        if name_tokens:
            token_values.append(("owner given-name token", name_tokens[0]))

    for label, keys, scan_local_part in (
        ("owner root mailbox", ("google", "root_email"), True),
        ("owner bootstrap mailbox", ("google", "bootstrap_email"), False),
        (
            "workspace administrator mailbox",
            ("google", "workspace_admin_email"),
            False,
        ),
        (
            "workspace administrator mailbox",
            ("brand", "workspace_admin_email"),
            False,
        ),
    ):
        mailbox = _nested_string(inventory, *keys)
        if not mailbox:
            continue
        exact_values.append((label, mailbox))
        local_part, separator, _ = mailbox.partition("@")
        if (
            scan_local_part
            and separator
            and len(local_part) >= 3
            and local_part.lower() not in {"admin", "administrator", "owner"}
        ):
            token_values.append(("owner mailbox identity token", local_part))

    for label, keys in (
        ("private cloud project identifier", ("google", "gcp_project_id")),
        ("private cloud billing identifier", ("google", "gcp_billing_account_id")),
    ):
        private_identifier = _nested_string(inventory, *keys)
        if private_identifier:
            exact_values.append((label, private_identifier))

    patterns: list[tuple[str, re.Pattern[bytes]]] = []
    seen: set[bytes] = set()
    for label, value in exact_values:
        encoded = value.encode("utf-8")
        folded = encoded.lower()
        if folded in seen:
            continue
        seen.add(folded)
        patterns.append((label, re.compile(re.escape(encoded), re.IGNORECASE)))
    for label, value in token_values:
        encoded = value.encode("utf-8")
        folded = encoded.lower()
        if folded in seen:
            continue
        seen.add(folded)
        patterns.append(
            (
                label,
                re.compile(
                    rb"(?<![A-Za-z])" + re.escape(encoded) + rb"(?![A-Za-z])",
                    re.IGNORECASE,
                ),
            )
        )
    return tuple(patterns)


@dataclass(frozen=True)
class GitEntry:
    mode: str
    object_type: str
    oid: str
    path: PurePosixPath


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_bytes(*args: str) -> bytes:
    git_environment = {
        **{
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        },
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        env=git_environment,
        check=True,
        capture_output=True,
    )
    return completed.stdout


def _git_text(*args: str) -> str:
    return _git_bytes(*args).decode("utf-8").strip()


def _validated_relative_path(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        not value
        or relative.is_absolute()
        or ".." in relative.parts
        or "\\" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"unsafe repository path: {value!r}")
    return relative


def _dirty_scope_path(relative: PurePosixPath) -> bool:
    if any(part in FORBIDDEN_PARTS for part in relative.parts):
        return False
    if len(relative.parts) == 1:
        return relative.suffix.casefold() not in {".bundle", ".zip"}
    return relative.parts[0] in SAFE_DIRECTORIES


def _public_package_path(relative: PurePosixPath) -> bool:
    if relative.as_posix() not in PUBLIC_FILE_PATHS:
        return False
    if relative.as_posix() in PRIVATE_ADMIN_PATHS:
        return False
    if not _dirty_scope_path(relative):
        return False
    name = relative.name.casefold()
    if any(fragment in name for fragment in FORBIDDEN_NAME_FRAGMENTS):
        return False
    return relative.suffix.casefold() not in FORBIDDEN_SUFFIXES


def _decode_git_paths(value: bytes) -> list[str]:
    paths: list[str] = []
    for raw_path in value.split(b"\0"):
        if not raw_path:
            continue
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("repository paths must be UTF-8") from error
        _validated_relative_path(path)
        paths.append(path)
    return paths


def changed_safe_paths(revision: str = "HEAD") -> list[str]:
    tracked = _git_bytes(
        "diff",
        "--name-only",
        "--no-renames",
        "--ignore-submodules=none",
        "-z",
        revision,
        "--",
    )
    untracked = _git_bytes("ls-files", "-z", "--others", "--exclude-standard")
    values = set(_decode_git_paths(tracked))
    values.update(_decode_git_paths(untracked))
    return sorted(
        value
        for value in values
        if _dirty_scope_path(_validated_relative_path(value))
    )


def _is_generated_evidence_path(value: str) -> bool:
    return value in GENERATED_EVIDENCE_PATHS


def assert_release_workspace(
    *,
    allow_generated_evidence_diffs: bool = False,
    revision: str = "HEAD",
) -> list[str]:
    changes = changed_safe_paths(revision)
    unexpected = [
        value
        for value in changes
        if not allow_generated_evidence_diffs or not _is_generated_evidence_path(value)
    ]
    if unexpected:
        raise ValueError(f"release-safe workspace files are not committed: {unexpected}")
    return changes


def head_entries(revision: str = "HEAD") -> list[GitEntry]:
    entries: list[GitEntry] = []
    raw_entries = _git_bytes("ls-tree", "-r", "-z", "--full-tree", revision)
    seen_casefolded: dict[str, str] = {}
    for raw_entry in raw_entries.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, oid = metadata.decode("ascii").split(" ")
            path_text = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("could not parse the committed Git tree") from error
        path = _validated_relative_path(path_text)
        if not _public_package_path(path):
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(
                f"public release entry must be a regular file: {path.as_posix()} "
                f"({mode} {object_type})"
            )
        casefolded = path.as_posix().casefold()
        previous = seen_casefolded.get(casefolded)
        if previous is not None:
            raise ValueError(
                f"public release paths collide on case-insensitive systems: "
                f"{previous!r}, {path.as_posix()!r}"
            )
        seen_casefolded[casefolded] = path.as_posix()
        entries.append(GitEntry(mode, object_type, oid, path))
    return sorted(entries, key=lambda entry: entry.path.as_posix())


def head_blob(entry: GitEntry) -> bytes:
    return _git_bytes("cat-file", "blob", entry.oid)


def package_blobs(entries: list[GitEntry]) -> dict[str, bytes]:
    return {entry.path.as_posix(): head_blob(entry) for entry in entries}


def _scan_patterns(
    blobs: dict[str, bytes],
    patterns: tuple[tuple[str, re.Pattern[bytes]], ...],
) -> list[str]:
    findings: list[str] = []
    for path, data in blobs.items():
        for label, pattern in patterns:
            if pattern.search(data):
                findings.append(f"{path}: {label}")
    return findings


def _local_path_patterns() -> tuple[tuple[str, re.Pattern[bytes]], ...]:
    patterns = list(LOCAL_PATH_PATTERNS)
    for label, path in (
        ("current user home path", Path.home()),
        ("current release workspace path", ROOT),
    ):
        normalized = path.resolve().as_posix().rstrip("/")
        if not normalized:
            continue
        patterns.append(
            (
                label,
                re.compile(re.escape(normalized.encode("utf-8")) + rb"(?:[\\/]|$)"),
            )
        )
    return tuple(patterns)


def scan_release_blobs(
    blobs: dict[str, bytes],
    *,
    owner_identity_patterns: tuple[tuple[str, re.Pattern[bytes]], ...] | None = None,
) -> None:
    credential_findings = _scan_patterns(blobs, CREDENTIAL_PATTERNS)
    if credential_findings:
        raise ValueError(
            f"release credential-pattern scan failed: {credential_findings}"
        )
    path_findings = _scan_patterns(blobs, _local_path_patterns())
    if path_findings:
        raise ValueError(f"release local-path scan failed: {path_findings}")
    if owner_identity_patterns is None:
        owner_identity_patterns = _owner_identity_patterns()
    identity_findings = _scan_patterns(blobs, owner_identity_patterns)
    if identity_findings:
        raise ValueError(f"release owner-identity scan failed: {identity_findings}")


def _zip_timestamp(revision: str = "HEAD") -> tuple[int, int, int, int, int, int]:
    source_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_epoch is None:
        source_epoch = _git_text("show", "-s", "--format=%ct", revision)
    value = datetime.fromtimestamp(max(int(source_epoch), 315532800), tz=UTC)
    return (value.year, value.month, value.day, value.hour, value.minute, value.second)


def _zip_info(
    name: str,
    timestamp: tuple[int, int, int, int, int, int],
    mode: str = "100644",
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=timestamp)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    permissions = 0o100755 if mode == "100755" else 0o100644
    info.external_attr = permissions << 16
    return info


def build_release(
    output: Path,
    *,
    allow_generated_evidence_diffs: bool = False,
) -> dict[str, Any]:
    commit = _git_text("rev-parse", "--verify", "HEAD^{commit}")
    allowed_changes = assert_release_workspace(
        allow_generated_evidence_diffs=allow_generated_evidence_diffs,
        revision=commit,
    )
    entries = head_entries(commit)
    if not entries:
        raise ValueError("release has no eligible files")
    file_data = package_blobs(entries)
    owner_identity_patterns = _owner_identity_patterns(commit)
    scan_release_blobs(
        file_data,
        owner_identity_patterns=owner_identity_patterns,
    )

    version_data = file_data.get("VERSION")
    if version_data is None:
        raise ValueError("committed HEAD does not contain a public VERSION file")
    try:
        version = version_data.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ValueError("committed VERSION must be UTF-8") from error
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError(f"invalid committed VERSION: {version!r}")

    prefix = f"remedialhq-engine-v{version}"
    entry_modes = {entry.path.as_posix(): entry.mode for entry in entries}
    file_rows: list[dict[str, Any]] = []
    for path, data in file_data.items():
        file_rows.append(
            {
                "path": path,
                "mode": entry_modes[path],
                "bytes": len(data),
                "sha256": sha256_bytes(data),
            }
        )
    source_snapshot_sha256 = sha256_bytes(
        json.dumps(file_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )

    contents = {
        "schema_version": 2,
        "release": f"v{version}",
        "source_snapshot_sha256": source_snapshot_sha256,
        "source_policy": "exact blobs from committed HEAD",
        "privacy_boundary": {
            "owner_private_path_entries_included": False,
            "artifact_selection": "closed public file allowlist",
            "private_administrative_paths_excluded": sorted(PRIVATE_ADMIN_PATHS),
            "owner_identity_pattern_scan": {
                "status": (
                    "BEST_EFFORT_PASS"
                    if owner_identity_patterns
                    else "NOT_CONFIGURED"
                ),
                "assurance": (
                    "BEST_EFFORT_PATTERN_MATCHING"
                    if owner_identity_patterns
                    else "NO_PRIVATE_IDENTITY_INPUT"
                ),
                "scope": "every included blob",
                "meaning": (
                    (
                        "Best effort scanning found no configured owner identity "
                        "pattern. This is not comprehensive proof that the archive "
                        "contains no personal identifier of any possible format."
                    )
                    if owner_identity_patterns
                    else (
                        "No private owner-identity inventory exists in this source "
                        "revision, so identity-specific pattern scanning was not "
                        "configured."
                    )
                ),
            },
            "credential_pattern_scan": {
                "status": "BEST_EFFORT_PASS",
                "assurance": "BEST_EFFORT_PATTERN_MATCHING",
                "scope": "every included blob",
                "meaning": (
                    "Best effort scanning found no configured representative credential "
                    "pattern. This is not comprehensive proof that the archive contains "
                    "no credential of any possible format."
                ),
            },
            "local_workstation_path_pattern_scan": {
                "status": "PASS",
                "scope": "every included blob",
            },
            "excluded_path_parts": sorted(FORBIDDEN_PARTS),
            "excluded_artifact_trees": [
                "artifacts/demo",
                "artifacts/red-team",
                "artifacts/validation",
            ],
        },
        "files": file_rows,
    }
    contents_data = (json.dumps(contents, indent=2, sort_keys=True) + "\n").encode()
    sums = [f"{row['sha256']}  {row['path']}" for row in file_rows]
    sums.append(f"{sha256_bytes(contents_data)}  PACKAGE_CONTENTS.json")
    sums_data = ("\n".join(sums) + "\n").encode()
    timestamp = _zip_timestamp(commit)

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for relative, data in file_data.items():
                archive.writestr(
                    _zip_info(
                        f"{prefix}/{relative}",
                        timestamp,
                        entry_modes[relative],
                    ),
                    data,
                )
            archive.writestr(
                _zip_info(f"{prefix}/PACKAGE_CONTENTS.json", timestamp), contents_data
            )
            archive.writestr(
                _zip_info(f"{prefix}/PACKAGE_SHA256SUMS.txt", timestamp), sums_data
            )
        expected_members = {
            **{f"{prefix}/{relative}": data for relative, data in file_data.items()},
            f"{prefix}/PACKAGE_CONTENTS.json": contents_data,
            f"{prefix}/PACKAGE_SHA256SUMS.txt": sums_data,
        }
        with zipfile.ZipFile(temporary) as archive:
            corrupt = archive.testzip()
            if corrupt:
                raise ValueError(f"release archive failed CRC verification: {corrupt}")
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("release archive contains duplicate member names")
            if set(names) != set(expected_members):
                raise ValueError(
                    "release archive members do not match the approved file set"
                )
            for name in names:
                member_path = PurePosixPath(name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise ValueError(f"unsafe archive member: {name}")
                if archive.read(name) != expected_members[name]:
                    raise ValueError(f"release archive content mismatch: {name}")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)

    return {
        "status": "PASS",
        "release": f"v{version}",
        "git_commit": commit,
        "source_policy": "exact blobs from committed HEAD",
        "output": str(output.resolve()),
        "files": len(file_rows) + 2,
        "bytes": output.stat().st_size,
        "sha256": sha256_file(output),
        "allowed_generated_evidence_diffs": allowed_changes,
        "credential_pattern_scan": "BEST_EFFORT_PASS",
        "local_path_pattern_scan": "PASS",
        "crc_check": "PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="build a bounded ReMediaLHQ public release ZIP from committed HEAD"
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--allow-generated-evidence-diffs",
        action="store_true",
        help=(
            "permit only the closed post-validation evidence diff set; archive "
            "content still comes from committed HEAD"
        ),
    )
    args = parser.parse_args()
    print(
        json.dumps(
            build_release(
                Path(args.output).resolve(),
                allow_generated_evidence_diffs=args.allow_generated_evidence_diffs,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
