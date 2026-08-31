from __future__ import annotations

import re
import subprocess
import unittest
from collections import Counter
from pathlib import Path

from scripts import render_dockerignore

ROOT = Path(__file__).resolve().parents[1]


def bash_array(source: str, name: str) -> tuple[str, ...]:
    match = re.search(rf"^{re.escape(name)}=\(\n(?P<body>.*?)^\)$", source, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"missing Bash array: {name}")
    return tuple(
        line.strip()
        for line in match.group("body").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


class DeploymentSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bootstrap_path = ROOT / "scripts/bootstrap_gcp.sh"
        cls.wif_path = ROOT / "scripts/configure_github_wif.sh"
        cls.ci_path = ROOT / ".github/workflows/ci.yml"
        cls.workflow_path = ROOT / ".github/workflows/deploy.yml"
        cls.artifact_analysis_path = ROOT / "scripts/check_google_artifact_analysis.py"
        cls.guide_path = ROOT / "infra/GITHUB_WIF_SETUP.md"
        cls.terraform_path = ROOT / "infra/terraform/main.tf"
        cls.dockerfile_path = ROOT / "Dockerfile"
        cls.dockerignore_path = ROOT / ".dockerignore"
        cls.gitignore_path = ROOT / ".gitignore"
        cls.bootstrap = cls.bootstrap_path.read_text(encoding="utf-8")
        cls.wif = cls.wif_path.read_text(encoding="utf-8")
        cls.ci = cls.ci_path.read_text(encoding="utf-8")
        cls.workflow = cls.workflow_path.read_text(encoding="utf-8")
        cls.artifact_analysis = cls.artifact_analysis_path.read_text(encoding="utf-8")
        cls.guide = cls.guide_path.read_text(encoding="utf-8")
        cls.terraform = cls.terraform_path.read_text(encoding="utf-8")
        cls.dockerfile = cls.dockerfile_path.read_text(encoding="utf-8")
        cls.dockerignore = cls.dockerignore_path.read_text(encoding="utf-8")
        cls.gitignore = cls.gitignore_path.read_text(encoding="utf-8")

    def test_shell_scripts_have_valid_bash_syntax(self) -> None:
        for path in (self.bootstrap_path, self.wif_path):
            with self.subTest(path=path.name):
                result = subprocess.run(
                    ["bash", "-n", str(path)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_ci_project_roles_are_update_only_and_read_only_analysis(self) -> None:
        self.assertEqual(
            bash_array(self.bootstrap, "ci_project_roles"),
            (
                '"$CI_RUN_ROLE"',
                '"$CONTAINER_ANALYSIS_VIEWER_ROLE"',
                '"$ARTIFACT_ANALYSIS_SBOM_READER_ROLE"',
            ),
        )
        self.assertIn(
            'CI_RUN_PERMISSIONS="run.operations.get,run.services.get,run.services.update"',
            self.bootstrap,
        )
        self.assertEqual(
            bash_array(self.bootstrap, "ci_run_service_names"),
            (
                "remedialhq-prod-collect",
                "remedialhq-prod-reconcile",
                "remedialhq-prod-compile",
                "remedialhq-prod-gate",
                "remedialhq-prod-publish",
                "remedialhq-prod-measure",
                "remedialhq-prod-site",
            ),
        )
        self.assertIn("resource.name.startsWith", self.bootstrap)
        self.assertIn("resource.name ==", self.bootstrap)
        self.assertIn('--condition="expression=${CI_RUN_CONDITION}', self.bootstrap)
        self.assertIn("not restricted to the seven runtime services", self.bootstrap)
        for prohibited_permission in (
            "run.services.create",
            "run.services.delete",
            "run.services.setIamPolicy",
            "run.operations.delete",
        ):
            with self.subTest(prohibited_permission=prohibited_permission):
                self.assertNotIn(prohibited_permission, self.bootstrap)
        self.assertIn(
            "gcloud artifacts repositories add-iam-policy-binding remedialhq",
            self.bootstrap,
        )
        self.assertIn('--role="roles/artifactregistry.writer"', self.bootstrap)
        self.assertIn(
            'CONTAINER_ANALYSIS_VIEWER_ROLE="roles/containeranalysis.occurrences.viewer"',
            self.bootstrap,
        )
        self.assertIn('--role="$CONTAINER_ANALYSIS_VIEWER_ROLE"', self.bootstrap)
        self.assertIn(
            'EXPECTED_CONTAINER_ANALYSIS_ROLE="roles/containeranalysis.occurrences.viewer"',
            self.wif,
        )
        self.assertIn(
            'ARTIFACT_ANALYSIS_SBOM_READER_ROLE="roles/storage.objectViewer"',
            self.bootstrap,
        )
        self.assertIn(
            'EXPECTED_ARTIFACT_ANALYSIS_SBOM_READER_ROLE="roles/storage.objectViewer"',
            self.wif,
        )
        self.assertIn(
            'ARTIFACT_ANALYSIS_SBOM_BUCKET="artifactanalysis-${REGION}-${PROJECT_NUMBER}"',
            self.bootstrap,
        )
        self.assertIn(
            "projects/_/buckets/${ARTIFACT_ANALYSIS_SBOM_BUCKET}/objects/",
            self.bootstrap,
        )
        self.assertIn(
            'EXPECTED_ARTIFACT_ANALYSIS_SBOM_BUCKET="artifactanalysis-${REGION}-${PROJECT_NUMBER}"',
            self.wif,
        )
        self.assertIn(
            "projects/_/buckets/${EXPECTED_ARTIFACT_ANALYSIS_SBOM_BUCKET}/objects/",
            self.wif,
        )
        condition_title = "read-artifact-analysis-sboms"
        condition_description = (
            "Read only Artifact Analysis generated SBOM objects in this region."
        )
        self.assertIn(
            f'ARTIFACT_ANALYSIS_SBOM_CONDITION_TITLE="{condition_title}"',
            self.bootstrap,
        )
        self.assertIn(
            f'EXPECTED_ARTIFACT_ANALYSIS_SBOM_CONDITION_TITLE="{condition_title}"',
            self.wif,
        )
        self.assertIn(
            f'ARTIFACT_ANALYSIS_SBOM_CONDITION_DESCRIPTION="{condition_description}"',
            self.bootstrap,
        )
        self.assertIn(
            f'EXPECTED_ARTIFACT_ANALYSIS_SBOM_CONDITION_DESCRIPTION="{condition_description}"',
            self.wif,
        )
        self.assertIn(f'title       = "{condition_title}"', self.terraform)
        self.assertIn(f'description = "{condition_description}"', self.terraform)
        self.assertIn("actual_sbom_reader_title", self.bootstrap)
        self.assertIn("actual_sbom_reader_description", self.bootstrap)
        self.assertIn("actual_sbom_reader_title", self.wif)
        self.assertIn("actual_sbom_reader_description", self.wif)
        self.assertIn("analysis_viewer_role_found", self.bootstrap)
        self.assertIn("analysis_viewer_role_found", self.wif)
        self.assertIn("sbom_reader_role_found", self.bootstrap)
        self.assertIn("sbom_reader_role_found", self.wif)

        prohibited = {
            "roles/bigquery.admin",
            "roles/cloudscheduler.admin",
            "roles/dns.admin",
            "roles/iam.serviceAccountAdmin",
            "roles/iam.serviceAccountUser",
            "roles/pubsub.admin",
            "roles/resourcemanager.projectIamAdmin",
            "roles/run.admin",
            "roles/run.developer",
            "roles/secretmanager.admin",
            "roles/serviceusage.serviceUsageAdmin",
            "roles/storage.admin",
        }
        legacy = set(bash_array(self.bootstrap, "legacy_project_roles"))
        self.assertTrue(prohibited.issubset(legacy))
        self.assertTrue(prohibited.isdisjoint(bash_array(self.bootstrap, "ci_project_roles")))
        self.assertIn("gcloud projects remove-iam-policy-binding", self.bootstrap)
        self.assertIn("Unexpected project role remains on the GitHub deployer", self.bootstrap)

    def test_bootstrap_handles_current_gcloud_command_and_batch_limits(self) -> None:
        self.assertIn("gcloud projects update --help", self.bootstrap)
        self.assertIn("gcloud alpha projects update --help", self.bootstrap)
        self.assertIn("service_batch_size=20", self.bootstrap)
        self.assertIn('${services[@]:offset:service_batch_size}', self.bootstrap)

    def test_artifact_analysis_apis_are_enabled_by_both_control_paths(self) -> None:
        required_apis = {
            "containeranalysis.googleapis.com",
            "containerscanning.googleapis.com",
        }
        self.assertTrue(required_apis.issubset(set(bash_array(self.bootstrap, "services"))))
        for api in required_apis:
            with self.subTest(api=api):
                self.assertIn(f'"{api}"', self.terraform)
        self.assertIn(
            'resource "google_project_iam_member" "deploy_artifact_analysis_viewer"',
            self.terraform,
        )
        self.assertIn('role    = "roles/containeranalysis.occurrences.viewer"', self.terraform)
        self.assertIn(
            'member  = "serviceAccount:remedialhq-deploy@${var.project_id}.iam.gserviceaccount.com"',
            self.terraform,
        )
        self.assertIn(
            'resource "google_project_iam_member" "deploy_artifact_analysis_sbom_reader"',
            self.terraform,
        )
        self.assertIn('role    = "roles/storage.objectViewer"', self.terraform)
        self.assertIn(
            "artifactanalysis-${var.region}-${data.google_project.current.number}/objects/",
            self.terraform,
        )

    def test_terraform_is_idempotent_and_fail_closed_at_rest(self) -> None:
        self.assertIn('paused      = !var.network_collection_enabled', self.terraform)
        self.assertIn(
            'length("${var.project_id}-${local.prefix}-${each.value}") <= 54',
            self.terraform,
        )
        self.assertIn(
            '"${var.project_id}-rmh-${local.bucket_codes[each.key]}-${random_id.suffix.hex}"',
            self.terraform,
        )
        self.assertEqual(self.terraform.count("manual_instance_count = 0"), 2)
        self.assertEqual(self.terraform.count('scaling_mode          = "MANUAL"'), 2)
        self.assertEqual(
            self.terraform.count(
                "ignore_changes = [template[0].containers[0].image]"
            ),
            2,
        )

    def test_collection_scheduler_uses_the_exact_versioned_trigger_contract(self) -> None:
        scheduler_start = self.terraform.index(
            'resource "google_cloud_scheduler_job" "collection_tick"'
        )
        scheduler_end = self.terraform.index(
            'resource "google_dns_managed_zone" "primary"',
            scheduler_start,
        )
        scheduler = self.terraform[scheduler_start:scheduler_end]
        for field in (
            "schema_version = 1",
            'trigger        = "scheduler"',
            'mode           = "bounded"',
            'phase          = "collect"',
        ):
            with self.subTest(field=field):
                self.assertIn(field, scheduler)

    def test_collect_artifacts_have_create_only_prefix_scoped_iam(self) -> None:
        self.assertIn(
            'resource "google_storage_bucket_iam_member" "collect_artifact_creator"',
            self.terraform,
        )
        self.assertIn('role   = "roles/storage.objectCreator"', self.terraform)
        self.assertIn(
            'resource "google_storage_bucket_iam_member" "collect_artifact_viewer"',
            self.terraform,
        )
        self.assertIn('for_each = toset(["collect", "reconcile"])', self.terraform)
        self.assertGreaterEqual(
            self.terraform.count("objects/phase-artifacts/v1/collect/"),
            2,
        )
        self.assertIn('name  = "PHASE_ARTIFACT_BUCKET"', self.terraform)
        creator_start = self.terraform.index(
            'resource "google_storage_bucket_iam_member" "collect_artifact_creator"'
        )
        topics_start = self.terraform.index(
            'resource "google_pubsub_topic" "phase"',
            creator_start,
        )
        artifact_iam = self.terraform[creator_start:topics_start]
        self.assertNotIn("roles/storage.objectAdmin", artifact_iam)
        self.assertNotIn("roles/storage.objectUser", artifact_iam)

    def test_runtime_image_is_minimal_pinned_and_unprivileged(self) -> None:
        from_lines = [
            line for line in self.dockerfile.splitlines() if line.startswith("FROM ")
        ]
        self.assertEqual(len(from_lines), 2)
        self.assertRegex(
            from_lines[0],
            (
                r"^FROM cgr\.dev/chainguard/python:latest-dev@sha256:"
                r"[0-9a-f]{64} AS build$"
            ),
        )
        self.assertRegex(
            from_lines[1],
            r"^FROM cgr\.dev/chainguard/python:latest@sha256:[0-9a-f]{64}$",
        )
        lowered = self.dockerfile.casefold()
        for prohibited in ("ffmpeg", "cairosvg", "pillow", "apk add", "apt-get"):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, lowered)
        self.assertIn("requirements-runtime.lock", self.dockerfile)
        self.assertNotIn("requirements-production.lock", self.dockerfile)
        self.assertIn("--no-build-isolation", self.dockerfile)
        self.assertIn("pip uninstall --yes pip setuptools wheel", self.dockerfile)
        self.assertIn("USER 65532:65532", self.dockerfile.splitlines())
        self.assertIn(
            'ENTRYPOINT ["/opt/venv/bin/python", "-m", "remedialhq.cli"]',
            self.dockerfile,
        )

    def test_workflow_cannot_plan_or_apply_production_terraform(self) -> None:
        lowered = self.workflow.casefold()
        for prohibited in (
            "terraform plan",
            "terraform apply",
            "backend-config",
            "inputs.apply",
            "gcloud run deploy",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, lowered)
        self.assertIn("terraform init -backend=false -input=false", self.workflow)
        self.assertIn("terraform validate", self.workflow)

    def test_workflow_updates_only_the_expected_existing_services(self) -> None:
        service_block = re.search(
            r"^  DEPLOY_SERVICES: >-\n(?P<body>(?:    .+\n)+)",
            self.workflow,
            re.MULTILINE,
        )
        self.assertIsNotNone(service_block)
        assert service_block is not None
        services = tuple(service_block.group("body").split())
        self.assertEqual(
            services,
            (
                "remedialhq-prod-measure",
                "remedialhq-prod-publish",
                "remedialhq-prod-gate",
                "remedialhq-prod-compile",
                "remedialhq-prod-reconcile",
                "remedialhq-prod-collect",
                "remedialhq-prod-site",
            ),
        )
        self.assertLess(
            self.workflow.index('gcloud run services describe "$service"'),
            self.workflow.index('gcloud run services update "$service"'),
        )
        self.assertIn('--image="$IMAGE_URI"', self.workflow)
        self.assertIn('[[ "${#services[@]}" -eq 7 ]]', self.workflow)
        self.assertIn("PUBLISHING_ENABLED=false", self.workflow)
        self.assertIn("ENABLE_NETWORK_COLLECTION=false", self.workflow)
        self.assertIn("YOUTUBE_LIVE_ADAPTER_ENABLED=false", self.workflow)
        self.assertIn("YOUTUBE_VISIBLE_PUBLICATION_AUTHORIZED=false", self.workflow)
        self.assertEqual(self.workflow.count('for service in "${services[@]}"; do'), 3)
        self.assertLess(
            self.workflow.index('--format=export > "${prior_dir}/${service}.yaml"'),
            self.workflow.index("trap rollback_deployment ERR"),
        )
        attempted = self.workflow.index('attempted_services+=("$service")')
        update = self.workflow.index('gcloud run services update "$service"', attempted)
        self.assertLess(attempted, update)
        self.assertIn('gcloud run services replace "${prior_dir}/${service}.yaml"', self.workflow)
        self.assertIn('for ((index=${#attempted_services[@]} - 1;', self.workflow)
        self.assertIn("is not fail-closed before rollout", self.workflow)
        self.assertNotIn("--quiet || true", self.workflow)
        self.assertIn("rollback_failed=1", self.workflow)
        self.assertIn("Manual recovery is required", self.workflow)

    def test_release_gates_are_mirrored_before_cloud_authentication(self) -> None:
        required_checks = (
            "ruff check src scripts tests",
            "mypy src/remedialhq scripts",
            "python -W error::ResourceWarning -m unittest discover -s tests -v",
            "remedialhq demo --root . --output /tmp/remedialhq-demo",
            "remedialhq verify-ledger /tmp/remedialhq-demo/ledger.jsonl",
            "node --check site/app.js",
            "python scripts/check_release_evidence.py",
            "python scripts/build_public_release.py",
            "--output /tmp/remedialhq-public-release.zip",
            "terraform init -backend=false -input=false",
            "terraform fmt -check",
            "terraform validate",
        )
        auth_position = self.workflow.index("google-github-actions/auth@")
        for required in required_checks:
            with self.subTest(required=required):
                self.assertIn(required, self.workflow)
                self.assertLess(self.workflow.index(required), auth_position)

    def test_release_evidence_gate_has_only_verified_paths(self) -> None:
        for label, workflow in (("ci", self.ci), ("deploy", self.workflow)):
            with self.subTest(label=label):
                self.assertIn("if [[ -f scripts/check_release_evidence.py ]]", workflow)
                self.assertIn(
                    "elif [[ -f PACKAGE_CONTENTS.json && -f PACKAGE_SHA256SUMS.txt ]]",
                    workflow,
                )
                self.assertIn("python scripts/verify_manifest.py", workflow)
                self.assertIn("git archive --format=tar HEAD", workflow)
                self.assertIn('(cd "$package_dir" && python scripts/verify_manifest.py)', workflow)
                self.assertIn(
                    "Release evidence checker or verified public-package markers are required.",
                    workflow,
                )

    def test_third_party_actions_are_pinned_to_full_commits(self) -> None:
        uses = re.findall(
            r"^[ \t]+(?:-[ \t]+)?uses:[ \t]*([^\s#]+)", self.workflow, re.MULTILINE
        )
        expected = Counter(
            {
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262": 2,
                "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065": 1,
                "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": 3,
                "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25": 1,
                "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a": 1,
                "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e": 1,
                "hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd": 1,
                "google-github-actions/auth@c200f3691d83b41bf9bbd8638997a462592937ed": 1,
                "google-github-actions/setup-gcloud@e427ad8a34f8676edf47cf7d7925499adf3eb74f": 1,
                "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6": 1,
            }
        )
        self.assertEqual(Counter(uses), expected)
        for use in uses:
            with self.subTest(use=use):
                self.assertRegex(use, r"^[^@\s]+@[0-9a-f]{40}$")

        ci_uses = re.findall(
            r"^[ \t]+(?:-[ \t]+)?uses:[ \t]*([^\s#]+)", self.ci, re.MULTILINE
        )
        self.assertEqual(
            Counter(ci_uses),
            Counter(
                {
                    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262": 1,
                    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065": 1,
                    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": 1,
                    "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25": 1,
                    "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a": 1,
                    "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e": 1,
                }
            ),
        )
        self.assertIn("persist-credentials: false", self.ci)

    def test_workflows_validate_with_the_runtime_python_version(self) -> None:
        expected = "python-version: '3.14'"
        self.assertEqual(self.ci.count(expected), 1)
        self.assertEqual(self.workflow.count(expected), 1)
        self.assertEqual(self.workflow.count("version: '569.0.0'"), 1)

    def test_container_scans_are_machine_readable_and_fail_closed(self) -> None:
        for label, workflow, suffix, image_reference in (
            ("ci", self.ci, "ci", "$CI_IMAGE"),
            ("deploy", self.workflow, "deploy", "$IMAGE_URI"),
        ):
            with self.subTest(label=label):
                self.assertIn("severity: CRITICAL,HIGH", workflow)
                self.assertIn("vuln-type: os,library", workflow)
                self.assertIn("ignore-unfixed: false", workflow)
                self.assertIn("scanners: vuln", workflow)
                self.assertIn("format: json", workflow)
                self.assertIn(f"output: trivy-{suffix}-report.json", workflow)
                self.assertIn(f"--file grype-{suffix}-report.json", workflow)
                self.assertIn("if-no-files-found: error", workflow)
                self.assertIn("scripts/check_container_scan.py", workflow)
                self.assertIn("--scanner trivy", workflow)
                self.assertIn("--scanner grype", workflow)
                self.assertIn(f'--expected-image "{image_reference}"', workflow)
                self.assertIn("TRIVY_SCAN_OUTCOME", workflow)
                self.assertIn("GRYPE_SCAN_OUTCOME", workflow)
                self.assertIn("trivy_gate != 0 || grype_gate != 0", workflow)
                self.assertIn("grype_${GRYPE_VERSION}_linux_amd64.tar.gz", workflow)
                self.assertIn("sha256sum --check --status", workflow)
                self.assertIn(
                    "edda0968d8827daab01d32b3cd7de192ae0915005e7bbfcfef9e68e79bc43343",
                    workflow,
                )

        self.assertIn("image-ref: ${{ env.CI_IMAGE }}", self.ci)
        self.assertIn("image-ref: ${{ steps.image.outputs.image_uri }}", self.workflow)
        self.assertLess(
            self.workflow.index("Enforce the dual-scanner Critical and High gate"),
            self.workflow.index("Update existing Cloud Run services only"),
        )

    def test_google_artifact_analysis_is_a_fail_closed_deployment_gate(self) -> None:
        workflow_required = (
            "python scripts/check_google_artifact_analysis.py",
            '"$IMAGE_URI"',
            "--timeout-seconds 1200",
            "--poll-interval-seconds 15",
            "artifact-analysis-discovery.json",
            "artifact-analysis-sbom-export.json",
            "artifact-analysis-sbom.spdx.json",
            "artifact-analysis-vulnerabilities.json",
            "artifact-analysis-summary.json",
            "artifact-analysis-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        for value in workflow_required:
            with self.subTest(value=value):
                self.assertIn(value, self.workflow)
        checker_required = (
            "--show-package-vulnerability",
            "--show-sbom-references",
            '"sbom",\n                "export"',
            'f"--uri={image_uri}"',
            "Artifact Analysis vulnerabilities could not be listed",
            'status == "FINISHED_SUCCESS"',
            'sbom_state != "COMPLETE"',
            "REQUIRED_ANALYSIS_TYPES <= set(analysis_types)",
            "list(raw) == [None]",
            "occurrence.get(\"resourceUri\") != expected_resource_uri",
            "subject.get(\"name\") != expected_resource_uri",
            "application/spdx+json",
            "projects/goog-analysis/",
            '"gcloud", "storage", "cat"',
            "signed_reference_hash_matches_download",
            "BLOCKING_SEVERITIES",
            "shared polling deadline",
        )
        for value in checker_required:
            with self.subTest(checker_value=value):
                self.assertIn(value, self.artifact_analysis)
        self.assertNotIn('"--location"', self.artifact_analysis)
        google_gate = self.workflow.index(
            "Require completed Google Artifact Analysis with no blocking findings"
        )
        sign = self.workflow.index("Keyless sign and verify the immutable image")
        deploy = self.workflow.index("Update existing Cloud Run services only")
        self.assertLess(google_gate, sign)
        self.assertLess(google_gate, deploy)

    def test_deployment_timeout_covers_scan_poll_and_ordered_rollout(self) -> None:
        build_job = self.workflow.split("  build-and-deploy:", 1)[1]
        self.assertIn("timeout-minutes: 60", build_job.split("    steps:", 1)[0])

    def test_pushed_image_has_attestations_and_keyless_signature(self) -> None:
        required = (
            "provenance: mode=max",
            (
                "sbom: generator=docker.io/docker/buildkit-syft-scanner@sha256:"
                "ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9"
            ),
            "push: true",
            'docker buildx imagetools inspect "$IMAGE_URI" --raw',
            'metadata.get("containerimage.digest") != expected_digest',
            'metadata.get("buildx.build.provenance")',
            'context: "{{defaultContext}}"',
            'expected_commit, expected_repository, server_url',
            'source_uri == expected_source',
            "BuildKit provenance is not bound to the expected GitHub repository and commit",
            '"attestation-manifest"',
            '"vnd.docker.reference.digest"',
            "attestation_reference != application_digest",
            '"https://spdx.dev/Document"',
            '"https://slsa.dev/provenance/v0.2"',
            "buildkit-attestation-manifest.json",
            'CERTIFICATE_IDENTITY="${GITHUB_SERVER_URL}/${GITHUB_WORKFLOW_REF}"',
            'cosign sign --yes "$IMAGE_URI"',
            "cosign verify",
            '--certificate-identity="$CERTIFICATE_IDENTITY"',
            '--certificate-oidc-issuer="https://token.actions.githubusercontent.com"',
            "cosign-verification.json",
            "signed-supply-chain-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, self.workflow)
        sign_position = self.workflow.index('cosign sign --yes "$IMAGE_URI"')
        verify_position = self.workflow.index("cosign verify", sign_position)
        deploy_position = self.workflow.index("Update existing Cloud Run services only")
        self.assertLess(sign_position, verify_position)
        self.assertLess(verify_position, deploy_position)
        self.assertNotIn("COSIGN_PRIVATE_KEY", self.workflow)
        self.assertNotIn("service-account-key", self.workflow)

    def test_rollout_checks_service_readiness_and_candidate_public_content(self) -> None:
        for required in (
            'conditions.get("Ready") != "True"',
            'status.get("latestReadyRevisionName") != status.get("latestCreatedRevisionName")',
            'actual_image != expected_image',
            "http://127.0.0.1:18080/data/claims.json",
            "http://127.0.0.1:18080/data/sources.json",
            'b"ReMediaLHQ"',
            "candidate claims reference missing sources",
            'pathlib.Path("site/data", name)',
            'docker pull "$IMAGE_URI"',
            'runtime_identity" == "65532:65532"',
            "http://127.0.0.1:18081/healthz",
            "unexpected phase-service health response",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.workflow)
        self.assertNotIn("status.url", self.workflow)
        self.assertLess(
            self.workflow.index("Build and push the attested immutable candidate"),
            self.workflow.index("Probe the exact pushed digest as the non-root runtime"),
        )
        self.assertLess(
            self.workflow.index("Probe the exact pushed digest as the non-root runtime"),
            self.workflow.index("Scan the immutable pushed image with Trivy"),
        )

    def test_ci_smokes_the_real_non_root_cli_and_service(self) -> None:
        for required in (
            "Smoke-test the non-root CLI and phase service",
            'runtime_identity" == "65532:65532"',
            '"$CI_IMAGE" --help',
            "-m remedialhq.service",
            "http://127.0.0.1:18081/healthz",
            "unexpected phase-service health response",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.ci)
        self.assertLess(
            self.ci.index("Smoke-test the non-root CLI and phase service"),
            self.ci.index("Scan the container candidate with Trivy"),
        )

    def test_production_build_uses_commit_pinned_git_context_and_allowlist(self) -> None:
        push_section = self.workflow.split("- id: push", 1)[1].split("- id: image", 1)[0]
        self.assertIn('context: "{{defaultContext}}"', push_section)
        self.assertNotIn("context: .", push_section)
        self.assertIn('"$GITHUB_SHA" "$GITHUB_REPOSITORY" "$GITHUB_SERVER_URL"', self.workflow)
        self.assertEqual(self.dockerignore, render_dockerignore.render_dockerignore())
        dockerignore_lines = self.dockerignore.splitlines()
        self.assertEqual(dockerignore_lines[1], "**")
        for allowed in (
            "!pyproject.toml",
            "!LICENSE.txt",
            "!README.md",
            "!requirements-build.lock",
            "!requirements-runtime.lock",
            "!artifacts/launch/remedialhq-launch-short-visual-prototype.mp4",
            "!artifacts/launch/short-001-storyboard.json",
        ):
            with self.subTest(allowed=allowed):
                self.assertIn(allowed, dockerignore_lines)
        for unsafe_glob in (
            "!src/**",
            "!config/**",
            "!data/**",
            "!content/**",
            "!brand/**",
            "!site/**",
        ):
            with self.subTest(unsafe_glob=unsafe_glob):
                self.assertNotIn(unsafe_glob, dockerignore_lines)
        self.assertIn("gha-creds-*.json", self.gitignore.splitlines())

    def test_workflow_identity_is_branch_and_environment_bounded(self) -> None:
        self.assertIn("contents: read", self.workflow)
        self.assertIn("id-token: write", self.workflow)
        self.assertNotIn("contents: write", self.workflow)
        self.assertEqual(self.workflow.count("persist-credentials: false"), 2)
        self.assertIn("if: ${{ github.ref == 'refs/heads/main' }}", self.workflow)
        self.assertIn("environment: production", self.workflow)
        global_permissions = self.workflow.split("concurrency:", 1)[0]
        self.assertNotIn("id-token", global_permissions)
        build_job = self.workflow.split("  build-and-deploy:", 1)[1]
        self.assertIn("permissions:\n      contents: read\n      id-token: write", build_job)

    def test_wif_preserves_all_immutable_and_exact_claim_bindings(self) -> None:
        for claim in (
            "assertion.repository",
            "assertion.repository_id",
            "assertion.repository_owner_id",
            "assertion.ref",
            "assertion.environment",
            "assertion.workflow_ref",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, self.wif)
        self.assertIn("attribute.repository_id/${GITHUB_REPOSITORY_ID}", self.wif)
        self.assertIn("GITHUB_REF=\"${GITHUB_REF:-refs/heads/main}\"", self.wif)
        self.assertIn("GITHUB_ENVIRONMENT=\"${GITHUB_ENVIRONMENT:-production}\"", self.wif)
        self.assertIn(".github/workflows/deploy.yml@${GITHUB_REF}", self.wif)

    def test_ci_can_act_as_only_the_runtime_service_accounts(self) -> None:
        self.assertEqual(
            bash_array(self.wif, "runtime_service_account_ids"),
            (
                "remedialhq-prod-collect",
                "remedialhq-prod-reconcile",
                "remedialhq-prod-compile",
                "remedialhq-prod-gate",
                "remedialhq-prod-publish",
                "remedialhq-prod-measure",
                "remedialhq-prod-site",
            ),
        )
        self.assertIn('--role="roles/iam.serviceAccountUser"', self.wif)
        self.assertIn('--member="serviceAccount:${DEPLOY_SA}"', self.wif)
        self.assertIn("Apply the fail-closed Terraform configuration", self.wif)
        self.assertIn("Refusing WIF activation with unexpected deployer project role", self.wif)
        self.assertIn("EXPECTED_CI_RUN_CONDITION", self.wif)
        self.assertIn("not resource-restricted", self.wif)

    def test_guide_separates_owner_and_ci_authority(self) -> None:
        for required in (
            "owner identity performs the one-time Google Cloud bootstrap",
            "no Terraform state-bucket access",
            "validates Terraform with `-backend=false`",
            "cannot create infrastructure or apply Terraform",
            "Do not create a JSON service-account key",
            "maximum-mode provenance and an SBOM",
            "fails closed for every Critical or High",
            "exact `deploy.yml` workflow identity",
            "introduces no static signing or service-account key",
            "exact GitHub commit",
            "zero findings whose effective severity is Critical or High",
            "Missing or null effective severity fails closed",
            "authenticated read-only Artifact Analysis API response",
            "CLI schema rather than a separately versioned API contract",
            "restores the exported configuration, image, and traffic state",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.guide)


if __name__ == "__main__":
    unittest.main()
