#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-${1:-}}"
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:-${2:-}}"
REGION="${REGION:-us-east1}"
PROJECT_NAME="${PROJECT_NAME:-ReMediaLHQ Production}"

if [[ -z "$PROJECT_ID" || -z "$BILLING_ACCOUNT_ID" ]]; then
  cat >&2 <<'USAGE'
Usage:
  PROJECT_ID=<globally-unique-id> BILLING_ACCOUNT_ID=<billing-id> scripts/bootstrap_gcp.sh
  scripts/bootstrap_gcp.sh <project-id> <billing-account-id>
USAGE
  exit 2
fi
[[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || { echo "PROJECT_ID is invalid." >&2; exit 2; }
[[ "$REGION" =~ ^[a-z][a-z0-9-]*[a-z0-9]$ ]] || { echo "REGION is invalid." >&2; exit 2; }

command -v gcloud >/dev/null 2>&1 || { echo "gcloud CLI is required." >&2; exit 3; }

if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud projects create "$PROJECT_ID" --name="$PROJECT_NAME" --set-as-default
else
  gcloud config set project "$PROJECT_ID" >/dev/null
fi

gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT_ID"
project_labels="brand=remedialhq,environment=production,owner=owner-private,workload=autonomous-media,vertical=gta6"
if gcloud projects update --help 2>/dev/null | grep -q -- "--update-labels"; then
  gcloud projects update "$PROJECT_ID" --update-labels="$project_labels"
elif gcloud alpha projects update --help 2>/dev/null | grep -q -- "--update-labels"; then
  # Recent gcloud releases expose project-label mutation only on the alpha
  # surface while the stable Resource Manager command is being migrated.
  gcloud alpha projects update "$PROJECT_ID" --update-labels="$project_labels"
else
  echo "This gcloud release cannot update project labels." >&2
  exit 4
fi

services=(
  aiplatform.googleapis.com
  artifactregistry.googleapis.com
  bigquery.googleapis.com
  certificatemanager.googleapis.com
  cloudbuild.googleapis.com
  cloudscheduler.googleapis.com
  containeranalysis.googleapis.com
  containerscanning.googleapis.com
  dns.googleapis.com
  iam.googleapis.com
  iamcredentials.googleapis.com
  logging.googleapis.com
  monitoring.googleapis.com
  pubsub.googleapis.com
  run.googleapis.com
  secretmanager.googleapis.com
  serviceusage.googleapis.com
  speech.googleapis.com
  storage.googleapis.com
  sts.googleapis.com
  texttospeech.googleapis.com
  transcoder.googleapis.com
  youtube.googleapis.com
  youtubeanalytics.googleapis.com
  youtubereporting.googleapis.com
)

# Service Usage currently accepts no more than 20 services in one activation
# request. Chunk the list so the bootstrap remains deterministic as it grows.
service_batch_size=20
for ((offset = 0; offset < ${#services[@]}; offset += service_batch_size)); do
  gcloud services enable \
    "${services[@]:offset:service_batch_size}" \
    --project="$PROJECT_ID"
done

STATE_BUCKET="${PROJECT_ID}-remedialhq-tfstate"
DEPLOY_SA_ID="${DEPLOY_SA_ID:-remedialhq-deploy}"
DEPLOY_SA="${DEPLOY_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

if ! gcloud artifacts repositories describe remedialhq \
  --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud artifacts repositories create remedialhq \
    --repository-format=docker \
    --location="$REGION" \
    --description="ReMediaLHQ production container images" \
    --project="$PROJECT_ID"
fi

if ! gcloud storage buckets describe "gs://${STATE_BUCKET}" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${STATE_BUCKET}" \
    --project="$PROJECT_ID" \
    --location="$REGION" \
    --uniform-bucket-level-access \
    --public-access-prevention
fi
gcloud storage buckets update "gs://${STATE_BUCKET}" --versioning

if ! gcloud iam service-accounts describe "$DEPLOY_SA" \
  --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$DEPLOY_SA_ID" \
    --display-name="ReMediaLHQ GitHub image deployer" \
    --project="$PROJECT_ID"
fi

# Remove grants from the earlier Terraform-in-CI design. The owner identity running this
# bootstrap retains infrastructure authority. The GitHub identity receives only image-push
# and existing-service update permissions.
legacy_project_roles=(
  roles/artifactregistry.writer
  roles/bigquery.admin
  roles/cloudscheduler.admin
  roles/dns.admin
  roles/iam.serviceAccountAdmin
  roles/iam.serviceAccountUser
  roles/pubsub.admin
  roles/resourcemanager.projectIamAdmin
  roles/run.admin
  roles/run.developer
  roles/secretmanager.admin
  roles/serviceusage.serviceUsageAdmin
  roles/storage.admin
)
for role in "${legacy_project_roles[@]}"; do
  binding="$(gcloud projects get-iam-policy "$PROJECT_ID" \
    --flatten="bindings[].members" \
    --filter="bindings.role=${role} AND bindings.members=serviceAccount:${DEPLOY_SA}" \
    --format="value(bindings.role)")"
  while IFS= read -r bound_role; do
    if [[ "$bound_role" == "$role" ]]; then
      gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${DEPLOY_SA}" \
        --role="$role" \
        --condition=None \
        --quiet >/dev/null
      break
    fi
  done <<< "$binding"
done

gcloud artifacts repositories add-iam-policy-binding remedialhq \
  --location="$REGION" \
  --project="$PROJECT_ID" \
  --member="serviceAccount:${DEPLOY_SA}" \
  --role="roles/artifactregistry.writer" \
  --condition=None >/dev/null

CONTAINER_ANALYSIS_VIEWER_ROLE="roles/containeranalysis.occurrences.viewer"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${DEPLOY_SA}" \
  --role="$CONTAINER_ANALYSIS_VIEWER_ROLE" \
  --condition=None \
  --quiet >/dev/null

CI_RUN_ROLE_ID="${CI_RUN_ROLE_ID:-remedialhqCloudRunImageDeployer}"
[[ "$CI_RUN_ROLE_ID" =~ ^[A-Za-z0-9_.]{3,64}$ ]] || {
  echo "CI_RUN_ROLE_ID is invalid." >&2
  exit 2
}
CI_RUN_ROLE="projects/${PROJECT_ID}/roles/${CI_RUN_ROLE_ID}"
CI_RUN_PERMISSIONS="run.operations.get,run.services.get,run.services.update"
ci_run_service_names=(
  remedialhq-prod-collect
  remedialhq-prod-reconcile
  remedialhq-prod-compile
  remedialhq-prod-gate
  remedialhq-prod-publish
  remedialhq-prod-measure
  remedialhq-prod-site
)
CI_RUN_CONDITION="resource.name.startsWith('projects/${PROJECT_ID}/locations/${REGION}/operations/')"
for service_name in "${ci_run_service_names[@]}"; do
  resource_name="projects/${PROJECT_ID}/locations/${REGION}/services/${service_name}"
  CI_RUN_CONDITION+=" || resource.name == '${resource_name}'"
done
CI_RUN_CONDITION_TITLE="remedialhq-seven-services"
if ! gcloud iam roles describe "$CI_RUN_ROLE_ID" \
  --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam roles create "$CI_RUN_ROLE_ID" \
    --project="$PROJECT_ID" \
    --title="ReMediaLHQ Cloud Run image deployer" \
    --description="Update the image and fail-closed settings on existing ReMediaLHQ services." \
    --permissions="$CI_RUN_PERMISSIONS" \
    --stage=GA
else
  gcloud iam roles update "$CI_RUN_ROLE_ID" \
    --project="$PROJECT_ID" \
    --title="ReMediaLHQ Cloud Run image deployer" \
    --description="Update the image and fail-closed settings on existing ReMediaLHQ services." \
    --permissions="$CI_RUN_PERMISSIONS" \
    --stage=GA
fi

ci_project_roles=(
  "$CI_RUN_ROLE"
  "$CONTAINER_ANALYSIS_VIEWER_ROLE"
)
gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${DEPLOY_SA}" \
  --role="$CI_RUN_ROLE" \
  --condition=None \
  --quiet >/dev/null 2>&1 || true
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${DEPLOY_SA}" \
  --role="$CI_RUN_ROLE" \
  --condition="expression=${CI_RUN_CONDITION},title=${CI_RUN_CONDITION_TITLE},description=Only the seven ReMediaLHQ runtime services" \
  --quiet >/dev/null

deploy_project_roles="$(gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members=serviceAccount:${DEPLOY_SA}" \
  --format="value(bindings.role)")"
expected_role_found=false
analysis_viewer_role_found=false
while IFS= read -r role; do
  if [[ "$role" == "$CI_RUN_ROLE" ]]; then
    expected_role_found=true
  elif [[ "$role" == "$CONTAINER_ANALYSIS_VIEWER_ROLE" ]]; then
    analysis_viewer_role_found=true
  elif [[ -n "$role" ]]; then
    echo "Unexpected project role remains on the GitHub deployer: ${role}" >&2
    exit 5
  fi
done <<< "$deploy_project_roles"
if [[ "$expected_role_found" != true ]]; then
  echo "The update-only Cloud Run role was not bound to the GitHub deployer." >&2
  exit 5
fi
if [[ "$analysis_viewer_role_found" != true ]]; then
  echo "The read-only Artifact Analysis occurrence role was not bound to the GitHub deployer." >&2
  exit 5
fi
actual_ci_run_condition="$(gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.role=${CI_RUN_ROLE} AND bindings.members=serviceAccount:${DEPLOY_SA}" \
  --format="value(bindings.condition.expression)")"
if [[ "$actual_ci_run_condition" != "$CI_RUN_CONDITION" ]]; then
  echo "The GitHub deployer binding is not restricted to the seven runtime services." >&2
  exit 5
fi

echo "ReMediaLHQ Google Cloud bootstrap complete."
echo "PROJECT_ID=$PROJECT_ID"
echo "REGION=$REGION"
echo "TERRAFORM_STATE_BUCKET=$STATE_BUCKET"
echo "DEPLOY_SA=$DEPLOY_SA"
echo "Next: apply Terraform once with the owner identity and fail-closed switches."
echo "Then configure GitHub WIF and runtime service-account impersonation."
