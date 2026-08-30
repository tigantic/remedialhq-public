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
        cls.guide_path = ROOT / "infra/GITHUB_WIF_SETUP.md"
        cls.terraform_path = ROOT / "infra/terraform/main.tf"
        cls.dockerignore_path = ROOT / ".dockerignore"
        cls.gitignore_path = ROOT / ".gitignore"
        cls.bootstrap = cls.bootstrap_path.read_text(encoding="utf-8")
        cls.wif = cls.wif_path.read_text(encoding="utf-8")
        cls.ci = cls.ci_path.read_text(encoding="utf-8")
        cls.workflow = cls.workflow_path.read_text(encoding="utf-8")
        cls.guide = cls.guide_path.read_text(encoding="utf-8")
        cls.terraform = cls.terraform_path.read_text(encoding="utf-8")
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

    def test_ci_project_role_is_cloud_run_update_only_and_resource_restricted(self) -> None:
        self.assertEqual(bash_array(self.bootstrap, "ci_project_roles"), ('"$CI_RUN_ROLE"',))
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
        services = (
            "remedialhq-prod-collect",
            "remedialhq-prod-reconcile",
            "remedialhq-prod-compile",
            "remedialhq-prod-gate",
            "remedialhq-prod-publish",
            "remedialhq-prod-measure",
            "remedialhq-prod-site",
        )
        for service in services:
            with self.subTest(service=service):
                expected_count = 2 if service == "remedialhq-prod-site" else 1
                self.assertEqual(self.workflow.count(service), expected_count)
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
            self.workflow.index('prior_images["$service"]="$prior_image"'),
            self.workflow.index("trap rollback_deployment ERR"),
        )
        self.assertIn('updated_services+=("$service")', self.workflow)
        self.assertIn('--image="${prior_images[$service]}"', self.workflow)
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
                "hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd": 1,
                "google-github-actions/auth@c200f3691d83b41bf9bbd8638997a462592937ed": 1,
                "google-github-actions/setup-gcloud@e427ad8a34f8676edf47cf7d7925499adf3eb74f": 1,
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
                }
            ),
        )
        self.assertIn("persist-credentials: false", self.ci)

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
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.workflow)
        self.assertNotIn("status.url", self.workflow)
        self.assertLess(
            self.workflow.index("docker run --detach"),
            self.workflow.index("google-github-actions/auth@"),
        )

    def test_image_build_precedes_cloud_credentials_and_context_is_allowlisted(self) -> None:
        self.assertLess(
            self.workflow.index("Build candidate before cloud authentication"),
            self.workflow.index("google-github-actions/auth@"),
        )
        self.assertEqual(self.dockerignore, render_dockerignore.render_dockerignore())
        dockerignore_lines = self.dockerignore.splitlines()
        self.assertEqual(dockerignore_lines[1], "**")
        for allowed in (
            "!pyproject.toml",
            "!README.md",
            "!requirements-build.lock",
            "!requirements-production.lock",
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
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.guide)


if __name__ == "__main__":
    unittest.main()
