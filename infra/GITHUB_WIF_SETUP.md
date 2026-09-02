# GitHub Workload Identity Federation Setup

Use separate authority for infrastructure bootstrap and routine application deployment.

## Authority boundary

The owner identity performs the one-time Google Cloud bootstrap and every production Terraform plan and apply. Do not authenticate that identity in GitHub Actions.

The GitHub deploy service account receives only:

- `roles/artifactregistry.writer` on the `remedialhq` Artifact Registry repository;
- `roles/containeranalysis.occurrences.viewer` at project scope, which grants only read access to Artifact Analysis occurrences and project metadata needed to bind scan results to the pushed digest;
- `roles/storage.objectViewer` with an IAM condition restricted to objects under the regional Google-managed Artifact Analysis SBOM bucket;
- the project custom role `remedialhqCloudRunImageDeployer`, containing only `run.services.get`, `run.services.update`, and `run.operations.get`, with an IAM condition that limits service access to the seven named ReMediaLHQ services in the configured region; and
- `roles/iam.serviceAccountUser` on the seven runtime service accounts used by those services.

It receives no Terraform state-bucket access and no project IAM, Secret Manager admin, Storage admin, DNS admin, Scheduler admin, Pub/Sub admin, BigQuery admin, Service Usage admin, service-account admin, Cloud Run admin, or Cloud Run developer role. Its object-read permission cannot read the Terraform state bucket or application data buckets. `scripts/bootstrap_gcp.sh` removes legacy broad project bindings from the deploy service account when they are present. The condition permits read-only operation polling in the configured region so an allowed service update can finish, but no update permission applies to any other Cloud Run service.

The routine workflow validates Terraform with `-backend=false`, builds and pushes one digest-pinned image from the exact GitHub commit, and updates only existing Cloud Run services. It cannot create infrastructure or apply Terraform.

After initial creation, the routine workflow is the sole authority for each Cloud Run container image. Terraform intentionally ignores only the nested image field so a later owner-controlled infrastructure apply cannot roll a service back to the bootstrap image. Terraform continues to own every other service setting, including manual zero-instance scaling and all publication controls.

## Required repository variables

```text
GCP_PROJECT_ID
GCP_REGION=us-east1
GCP_WIF_PROVIDER
GCP_DEPLOY_SERVICE_ACCOUNT
```

Create a protected GitHub environment named `production`. Limit deployment to `refs/heads/main` and require the owner-approved reviewers appropriate for the repository. The identity-provider condition independently requires the immutable numeric repository ID, immutable numeric owner ID, exact branch ref, exact environment, and exact workflow ref.

## 1. Owner bootstrap

Run this locally with the owner or administrator Google Cloud identity:

```bash
export PROJECT_ID="<project-id>"
export BILLING_ACCOUNT_ID="<billing-account-id>"
export REGION="us-east1"

scripts/bootstrap_gcp.sh
```

The script enables services, creates the Artifact Registry repository, creates the remote-state bucket, creates the deploy service account, removes legacy broad CI grants, and installs the minimal CI grants described above.

## 2. Owner initial image and Terraform apply

The first Terraform apply needs an existing image. Build and push that bootstrap image with the owner identity, resolve its digest, and use the immutable digest URI as `TF_VAR_image_uri`.

```bash
BOOTSTRAP_TAG="${REGION}-docker.pkg.dev/${PROJECT_ID}/remedialhq/engine:owner-bootstrap"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
docker build --pull --tag "$BOOTSTRAP_TAG" .
docker push "$BOOTSTRAP_TAG"
BOOTSTRAP_DIGEST="$(gcloud artifacts docker images describe "$BOOTSTRAP_TAG" --format='value(image_summary.digest)')"
export TF_VAR_image_uri="${REGION}-docker.pkg.dev/${PROJECT_ID}/remedialhq/engine@${BOOTSTRAP_DIGEST}"
export TF_VAR_project_id="$PROJECT_ID"
export TF_VAR_region="$REGION"
export TF_VAR_publishing_enabled="false"
export TF_VAR_network_collection_enabled="false"
export TF_VAR_create_dns_zone="false"
export TF_VAR_site_public_enabled="false"
export TF_VAR_youtube_live_adapter_enabled="false"
export TF_VAR_youtube_credentials_ready="false"
export TF_VAR_youtube_visible_publication_authorized="false"

terraform -chdir=infra/terraform init \
  -input=false \
  -backend-config="bucket=${PROJECT_ID}-remedialhq-tfstate"
terraform -chdir=infra/terraform fmt -check
terraform -chdir=infra/terraform validate
terraform -chdir=infra/terraform plan -input=false -out=tfplan
terraform -chdir=infra/terraform apply -input=false tfplan
```

Review the plan before applying it. Keep every publication, credential, public-site, DNS, and network-collection switch false during the initial apply.

## 3. Bind the exact GitHub workflow

After Terraform creates the runtime service accounts, run the WIF configuration with the owner identity:

```bash
export GITHUB_ORG="tigantic"
export GITHUB_REPO="remedialhq"
export GITHUB_REPOSITORY_ID="<immutable-numeric-repository-id>"
export GITHUB_REPOSITORY_OWNER_ID="<immutable-numeric-owner-id>"
export GITHUB_REF="refs/heads/main"
export GITHUB_ENVIRONMENT="production"
export GITHUB_WORKFLOW_REF="${GITHUB_ORG}/${GITHUB_REPO}/.github/workflows/deploy.yml@${GITHUB_REF}"
export DEPLOY_SA="remedialhq-deploy@${PROJECT_ID}.iam.gserviceaccount.com"

scripts/configure_github_wif.sh
```

The script verifies the deploy and runtime service accounts before changing bindings. It refuses activation if the deploy service account has any project role other than the update-only custom role, the read-only Artifact Analysis occurrence-viewer role, and the bucket-restricted SBOM object-reader role, or if either IAM condition is broader than its exact resource boundary. It then creates or updates the attribute-restricted provider, grants the exact numeric repository principal permission to impersonate the deploy service account, and grants that deploy service account `iam.serviceAccounts.actAs` only on these runtime identities:

```text
remedialhq-prod-collect
remedialhq-prod-reconcile
remedialhq-prod-compile
remedialhq-prod-gate
remedialhq-prod-publish
remedialhq-prod-measure
remedialhq-prod-site
```

Copy the four printed values into the repository variables. Do not create a JSON service-account key.

## Routine deployment

Run `.github/workflows/deploy.yml` from `refs/heads/main` through the protected `production` environment. It performs tests, validates Terraform without loading production state, pushes an immutable image, confirms every target Cloud Run service already exists, forces the application publication switches closed, and updates only the existing service image and those fail-closed settings.

The workflow uses BuildKit to attach maximum-mode provenance and an SBOM to the pushed image. The provenance must bind the configured GitHub repository and exact commit, and the attestation manifest must reference the sole Linux AMD64 application manifest. The workflow pulls and probes that exact pushed digest as the non-root CLI, phase service, and static site. It scans the immutable digest independently with Trivy and a checksum-pinned Grype release, binds both reports to the exact image identity, retains the raw and normalized JSON as GitHub Actions artifacts, and fails closed for every Critical or High operating-system or library finding, including findings without a published fix. A missing, malformed, incomplete, or identity-mismatched report from either scanner also blocks deployment.

After both local scanners pass, the workflow waits for Google Artifact Analysis to report `FINISHED_SUCCESS` with completed operating-system and Python analysis. It requests SBOM export exactly once without a location override, then requires a complete Google-managed signed SPDX reference bound to the exact image. The workflow downloads the referenced object through a bucket-restricted read grant, matches its bytes to the reference hash, and validates the SPDX 2.3 document identity and inventory. The gate requires zero findings whose effective severity is Critical or High. Missing or null effective severity fails closed. The occurrence-viewer role cannot create or modify notes, occurrences, images, services, or IAM policy. The authenticated read-only Artifact Analysis API response is the signature trust boundary because Google's signing public key is not exposed to this principal for independent cryptographic verification. Any CLI error, permission failure, malformed response, scan timeout, incomplete SBOM, unreadable or mismatched SBOM object, or blocking finding stops the deployment.

The Artifact Analysis JSON rendered by `gcloud` is a CLI schema rather than a separately versioned API contract. The workflow pins Google Cloud CLI `569.0.0`, whose live output was used for the parser contract. Revalidate the discovery and vulnerability field paths before changing that version. An unexpected schema fails closed.

Only after all three vulnerability gates pass does the workflow use the GitHub OIDC identity to create a keyless Cosign signature. It verifies that signature against the exact `deploy.yml` workflow identity and GitHub's token issuer before any Cloud Run update. Build metadata, the OCI index, Artifact Analysis output, downloaded SPDX object, and Cosign verification output are retained as machine-readable run evidence. Services are updated from downstream consumer to upstream producer, with the site last. Before mutation, the workflow exports every service configuration and confirms that all publication authority switches are closed. If any attempted update or readiness check fails, it restores the exported configuration, image, and traffic state in reverse order. The signing path uses the same short-lived GitHub OIDC authority as Google Workload Identity Federation and introduces no static signing or service-account key.

Infrastructure, IAM, secrets, DNS, scheduling, messaging, datasets, buckets, service identities, and production authority switches remain owner-controlled Terraform work outside GitHub Actions.
