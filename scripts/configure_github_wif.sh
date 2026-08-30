#!/usr/bin/env bash
set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID}"
: "${GITHUB_ORG:?Set GITHUB_ORG}"
: "${GITHUB_REPO:?Set GITHUB_REPO}"
: "${GITHUB_REPOSITORY_ID:?Set the immutable numeric GitHub repository ID}"
: "${GITHUB_REPOSITORY_OWNER_ID:?Set the immutable numeric GitHub owner ID}"

REGION="${REGION:-us-east1}"
GITHUB_REF="${GITHUB_REF:-refs/heads/main}"
GITHUB_ENVIRONMENT="${GITHUB_ENVIRONMENT:-production}"
GITHUB_WORKFLOW_REF="${GITHUB_WORKFLOW_REF:-${GITHUB_ORG}/${GITHUB_REPO}/.github/workflows/deploy.yml@${GITHUB_REF}}"

[[ "$GITHUB_ORG" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "GITHUB_ORG is invalid." >&2; exit 2; }
[[ "$GITHUB_REPO" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "GITHUB_REPO is invalid." >&2; exit 2; }
[[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || { echo "PROJECT_ID is invalid." >&2; exit 2; }
[[ "$REGION" =~ ^[a-z][a-z0-9-]*[a-z0-9]$ ]] || { echo "REGION is invalid." >&2; exit 2; }
[[ "$GITHUB_REPOSITORY_ID" =~ ^[0-9]+$ ]] || { echo "GITHUB_REPOSITORY_ID must be numeric." >&2; exit 2; }
[[ "$GITHUB_REPOSITORY_OWNER_ID" =~ ^[0-9]+$ ]] || { echo "GITHUB_REPOSITORY_OWNER_ID must be numeric." >&2; exit 2; }
[[ "$GITHUB_REF" =~ ^refs/heads/[A-Za-z0-9._/-]+$ && "$GITHUB_REF" != *".."* ]] || { echo "GITHUB_REF must identify one branch." >&2; exit 2; }
[[ "$GITHUB_ENVIRONMENT" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "GITHUB_ENVIRONMENT is invalid." >&2; exit 2; }
[[ "$GITHUB_WORKFLOW_REF" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@refs/heads/[A-Za-z0-9._/-]+$ && "$GITHUB_WORKFLOW_REF" != *".."* ]] || { echo "GITHUB_WORKFLOW_REF is invalid." >&2; exit 2; }

command -v gcloud >/dev/null 2>&1 || { echo "gcloud CLI is required." >&2; exit 3; }

PROJECT_NUMBER="${PROJECT_NUMBER:-$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')}"
DEPLOY_SA="${DEPLOY_SA:-remedialhq-deploy@${PROJECT_ID}.iam.gserviceaccount.com}"
[[ "$DEPLOY_SA" == *"@${PROJECT_ID}.iam.gserviceaccount.com" ]] || {
  echo "DEPLOY_SA must belong to PROJECT_ID." >&2
  exit 2
}

POOL_ID="${POOL_ID:-github-remedialhq}"
PROVIDER_ID="${PROVIDER_ID:-github}"
LOCATION="global"

gcloud config set project "$PROJECT_ID" >/dev/null

if ! gcloud iam service-accounts describe "$DEPLOY_SA" \
  --project="$PROJECT_ID" >/dev/null 2>&1; then
  echo "Deploy service account is missing: ${DEPLOY_SA}" >&2
  echo "Run scripts/bootstrap_gcp.sh with the owner identity first." >&2
  exit 4
fi

CI_RUN_ROLE_ID="${CI_RUN_ROLE_ID:-remedialhqCloudRunImageDeployer}"
[[ "$CI_RUN_ROLE_ID" =~ ^[A-Za-z0-9_.]{3,64}$ ]] || {
  echo "CI_RUN_ROLE_ID is invalid." >&2
  exit 2
}
EXPECTED_CI_PROJECT_ROLE="projects/${PROJECT_ID}/roles/${CI_RUN_ROLE_ID}"
ci_run_service_names=(
  remedialhq-prod-collect
  remedialhq-prod-reconcile
  remedialhq-prod-compile
  remedialhq-prod-gate
  remedialhq-prod-publish
  remedialhq-prod-measure
  remedialhq-prod-site
)
EXPECTED_CI_RUN_CONDITION="resource.name.startsWith('projects/${PROJECT_ID}/locations/${REGION}/operations/')"
for service_name in "${ci_run_service_names[@]}"; do
  resource_name="projects/${PROJECT_ID}/locations/${REGION}/services/${service_name}"
  EXPECTED_CI_RUN_CONDITION+=" || resource.name == '${resource_name}'"
done
deploy_project_roles="$(gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members=serviceAccount:${DEPLOY_SA}" \
  --format="value(bindings.role)")"
expected_role_found=false
while IFS= read -r role; do
  if [[ "$role" == "$EXPECTED_CI_PROJECT_ROLE" ]]; then
    expected_role_found=true
  elif [[ -n "$role" ]]; then
    echo "Refusing WIF activation with unexpected deployer project role: ${role}" >&2
    exit 5
  fi
done <<< "$deploy_project_roles"
if [[ "$expected_role_found" != true ]]; then
  echo "The update-only Cloud Run role is not bound to the deploy service account." >&2
  echo "Run scripts/bootstrap_gcp.sh with the owner identity first." >&2
  exit 5
fi
actual_ci_run_condition="$(gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.role=${EXPECTED_CI_PROJECT_ROLE} AND bindings.members=serviceAccount:${DEPLOY_SA}" \
  --format="value(bindings.condition.expression)")"
if [[ "$actual_ci_run_condition" != "$EXPECTED_CI_RUN_CONDITION" ]]; then
  echo "Refusing WIF activation because the deployer role is not resource-restricted." >&2
  echo "Run scripts/bootstrap_gcp.sh with the owner identity first." >&2
  exit 5
fi

runtime_service_account_ids=(
  remedialhq-prod-collect
  remedialhq-prod-reconcile
  remedialhq-prod-compile
  remedialhq-prod-gate
  remedialhq-prod-publish
  remedialhq-prod-measure
  remedialhq-prod-site
)
runtime_service_accounts=()
for runtime_id in "${runtime_service_account_ids[@]}"; do
  runtime_service_account="${runtime_id}@${PROJECT_ID}.iam.gserviceaccount.com"
  if ! gcloud iam service-accounts describe "$runtime_service_account" \
    --project="$PROJECT_ID" >/dev/null 2>&1; then
    echo "Runtime service account is missing: ${runtime_service_account}" >&2
    echo "Apply the fail-closed Terraform configuration with the owner identity first." >&2
    exit 4
  fi
  runtime_service_accounts+=("$runtime_service_account")
done

if ! gcloud iam workload-identity-pools describe "$POOL_ID" --location="$LOCATION" >/dev/null 2>&1; then
  gcloud iam workload-identity-pools create "$POOL_ID" \
    --location="$LOCATION" \
    --display-name="ReMediaLHQ GitHub"
fi

ATTRIBUTE_MAPPING="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_id=assertion.repository_id,attribute.repository_owner_id=assertion.repository_owner_id,attribute.ref=assertion.ref,attribute.environment=assertion.environment,attribute.workflow_ref=assertion.workflow_ref"
ATTRIBUTE_CONDITION="assertion.repository == '${GITHUB_ORG}/${GITHUB_REPO}' && assertion.repository_id == '${GITHUB_REPOSITORY_ID}' && assertion.repository_owner_id == '${GITHUB_REPOSITORY_OWNER_ID}' && assertion.ref == '${GITHUB_REF}' && assertion.environment == '${GITHUB_ENVIRONMENT}' && assertion.workflow_ref == '${GITHUB_WORKFLOW_REF}'"

if ! gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" --workload-identity-pool="$POOL_ID" --location="$LOCATION" >/dev/null 2>&1; then
  gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
    --location="$LOCATION" \
    --workload-identity-pool="$POOL_ID" \
    --display-name="ReMediaLHQ GitHub provider" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="$ATTRIBUTE_MAPPING" \
    --attribute-condition="$ATTRIBUTE_CONDITION"
else
  gcloud iam workload-identity-pools providers update-oidc "$PROVIDER_ID" \
    --location="$LOCATION" \
    --workload-identity-pool="$POOL_ID" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="$ATTRIBUTE_MAPPING" \
    --attribute-condition="$ATTRIBUTE_CONDITION"
fi

PRINCIPAL="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.repository_id/${GITHUB_REPOSITORY_ID}"

gcloud iam service-accounts add-iam-policy-binding "$DEPLOY_SA" \
  --role="roles/iam.workloadIdentityUser" \
  --member="$PRINCIPAL"

for runtime_service_account in "${runtime_service_accounts[@]}"; do
  gcloud iam service-accounts add-iam-policy-binding "$runtime_service_account" \
    --project="$PROJECT_ID" \
    --role="roles/iam.serviceAccountUser" \
    --member="serviceAccount:${DEPLOY_SA}" \
    --condition=None >/dev/null
done

PROVIDER_NAME="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"
cat <<VALUES
Set these GitHub repository variables:
GCP_PROJECT_ID=${PROJECT_ID}
GCP_REGION=${REGION}
GCP_WIF_PROVIDER=${PROVIDER_NAME}
GCP_DEPLOY_SERVICE_ACCOUNT=${DEPLOY_SA}
VALUES
