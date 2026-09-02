data "google_project" "current" {}

locals {
  prefix = "remedialhq-${var.environment}"
  services = toset([
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "bigquery.googleapis.com",
    "certificatemanager.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudscheduler.googleapis.com",
    "containeranalysis.googleapis.com",
    "containerscanning.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "speech.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com",
    "texttospeech.googleapis.com",
    "transcoder.googleapis.com",
    "youtube.googleapis.com",
    "youtubeanalytics.googleapis.com",
    "youtubereporting.googleapis.com",
  ])
  phases = ["collect", "reconcile", "compile", "gate", "publish", "measure"]
  next_phase = {
    collect   = "reconcile"
    reconcile = "compile"
    compile   = "gate"
    gate      = "publish"
    publish   = "measure"
    measure   = null
  }
  buckets = {
    source_quarantine = "source-quarantine"
    source_approved   = "source-approved"
    media_workspace   = "media-workspace"
    media_published   = "media-published"
    site_static       = "site-static"
    evidence_ledger   = "evidence-ledger"
    backup            = "backup"
    state             = "state"
  }
  bucket_codes = {
    source_quarantine = "srcq"
    source_approved   = "srca"
    media_workspace   = "medw"
    media_published   = "medp"
    site_static       = "site"
    evidence_ledger   = "ledg"
    backup            = "back"
    state             = "stat"
  }
  datasets = toset([
    "sources", "claims", "editorial", "publishing", "audience",
    "experiments", "revenue", "costs", "operations"
  ])
  secret_names = toset([
    "youtube-oauth-client",
    "youtube-owner-token",
    "x-oauth-client",
    "x-owner-token",
    "meta-app-secret",
    "meta-owner-token",
    "tiktok-app-secret",
    "tiktok-owner-token",
    "newsletter-api-key",
    "newsletter-webhook-secret",
    "affiliate-config",
    "site-session-secret",
    "ledger-signing-key",
  ])
  edge_services = {
    app = {
      hostname    = "app.remedialhq.com"
      iap_enabled = true
    }
    api = {
      hostname    = "api.remedialhq.com"
      iap_enabled = true
    }
    verify = {
      hostname    = "verify.remedialhq.com"
      iap_enabled = false
    }
  }
  edge_services_enabled = var.edge_subdomains_enabled ? local.edge_services : {}
  edge_private_services_enabled = {
    for name, service in local.edge_services_enabled : name => service
    if service.iap_enabled
  }
}

resource "google_project_service" "required" {
  for_each           = local.services
  service            = each.value
  disable_on_destroy = false
}

resource "google_project_service" "edge" {
  provider = google-beta
  for_each = var.edge_subdomains_enabled ? toset([
    "compute.googleapis.com",
    "iap.googleapis.com",
  ]) : toset([])

  service            = each.value
  disable_on_destroy = false
}

resource "google_project_service_identity" "iap" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  project = var.project_id
  service = "iap.googleapis.com"

  depends_on = [google_project_service.edge]
}

resource "terraform_data" "edge_preflight" {
  count = var.edge_subdomains_enabled ? 1 : 0

  input = {
    hostnames           = sort([for service in values(local.edge_services) : service.hostname])
    image_uris          = var.edge_image_uris
    iap_owner_principal = var.edge_iap_owner_principal
  }

  lifecycle {
    precondition {
      condition     = var.environment == "prod"
      error_message = "The remedialhq.com edge subdomains may be enabled only for the prod environment."
    }
    precondition {
      condition     = !var.create_dns_zone
      error_message = "Cloudflare remains authoritative for remedialhq.com; create_dns_zone must remain false."
    }
    precondition {
      condition = alltrue([
        for image_uri in values(var.edge_image_uris) : can(regex(
          "^${var.region}-docker\\.pkg\\.dev/${var.project_id}/[^/@[:space:]]+/[^@[:space:]]+@sha256:[0-9a-f]{64}$",
          image_uri,
        ))
      ])
      error_message = "All three edge images must be nonempty, digest-pinned Artifact Registry images in this project and region."
    }
    precondition {
      condition     = var.edge_iap_owner_principal != ""
      error_message = "edge_iap_owner_principal is required before app and API can be created."
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

data "google_artifact_registry_repository" "engine" {
  location      = var.region
  repository_id = "remedialhq"
}

resource "google_project_iam_member" "deploy_artifact_analysis_viewer" {
  project = var.project_id
  role    = "roles/containeranalysis.occurrences.viewer"
  member  = "serviceAccount:remedialhq-deploy@${var.project_id}.iam.gserviceaccount.com"

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "deploy_artifact_analysis_sbom_reader" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:remedialhq-deploy@${var.project_id}.iam.gserviceaccount.com"

  condition {
    title       = "read-artifact-analysis-sboms"
    description = "Read only Artifact Analysis generated SBOM objects in this region."
    expression  = "resource.name.startsWith('projects/_/buckets/artifactanalysis-${var.region}-${data.google_project.current.number}/objects/')"
  }

  depends_on = [google_project_service.required]
}

resource "google_service_account" "phase" {
  for_each     = toset(local.phases)
  account_id   = substr("${local.prefix}-${each.key}", 0, 30)
  display_name = "ReMediaLHQ ${each.key} phase"
  depends_on   = [google_project_service.required]
}

resource "google_service_account" "push" {
  account_id   = substr("${local.prefix}-push", 0, 30)
  display_name = "ReMediaLHQ Pub/Sub push identity"
  depends_on   = [google_project_service.required]
}

resource "google_service_account" "site_runtime" {
  account_id   = substr("${local.prefix}-site", 0, 30)
  display_name = "ReMediaLHQ unprivileged static site runtime"
  depends_on   = [google_project_service.required]
}

resource "google_service_account_iam_member" "pubsub_token_creator" {
  service_account_id = google_service_account.push.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_storage_bucket" "data" {
  for_each = local.buckets
  name = length("${var.project_id}-${local.prefix}-${each.value}") <= 54 ? (
    "${var.project_id}-${local.prefix}-${each.value}-${random_id.suffix.hex}"
  ) : "${var.project_id}-rmh-${local.bucket_codes[each.key]}-${random_id.suffix.hex}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  versioning {
    enabled = true
  }
  dynamic "lifecycle_rule" {
    for_each = each.key == "source_quarantine" || each.key == "backup" ? [1] : []
    content {
      condition {
        age = 365
      }
      action {
        type          = "SetStorageClass"
        storage_class = "COLDLINE"
      }
    }
  }
  dynamic "lifecycle_rule" {
    for_each = each.key == "state" ? [1] : []
    content {
      condition {
        num_newer_versions = 20
      }
      action {
        type = "Delete"
      }
    }
  }
}

resource "google_storage_bucket_iam_member" "phase_state" {
  for_each = google_service_account.phase
  bucket   = google_storage_bucket.data["state"].name
  role     = "roles/storage.objectAdmin"
  member   = "serviceAccount:${each.value.email}"
}

resource "google_storage_bucket_iam_member" "collect_artifact_creator" {
  bucket = google_storage_bucket.data["source_quarantine"].name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.phase["collect"].email}"

  condition {
    title       = "create-immutable-collect-artifacts"
    description = "Create only collect snapshot artifacts under the dedicated prefix."
    expression  = "resource.name.startsWith('projects/_/buckets/${google_storage_bucket.data["source_quarantine"].name}/objects/phase-artifacts/v1/collect/')"
  }
}

resource "google_storage_bucket_iam_member" "collect_artifact_viewer" {
  for_each = toset(["collect", "reconcile"])
  bucket   = google_storage_bucket.data["source_quarantine"].name
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${google_service_account.phase[each.key].email}"

  condition {
    title       = "read-immutable-collect-artifacts-${each.key}"
    description = "Read only collect snapshot artifacts under the dedicated prefix."
    expression  = "resource.name.startsWith('projects/_/buckets/${google_storage_bucket.data["source_quarantine"].name}/objects/phase-artifacts/v1/collect/')"
  }
}

resource "google_pubsub_topic" "phase" {
  for_each                   = toset(local.phases)
  name                       = "${local.prefix}-${each.key}"
  message_retention_duration = "604800s"
}

resource "google_pubsub_topic_iam_member" "phase_publisher" {
  for_each = { for phase, next in local.next_phase : phase => next if next != null }
  project  = var.project_id
  topic    = google_pubsub_topic.phase[each.value].name
  role     = "roles/pubsub.publisher"
  member   = "serviceAccount:${google_service_account.phase[each.key].email}"
}

resource "google_project_iam_member" "compile_aiplatform" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.phase["compile"].email}"
}

resource "google_pubsub_topic_iam_member" "scheduler_collect" {
  project = var.project_id
  topic   = google_pubsub_topic.phase["collect"].name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
}

resource "google_bigquery_dataset" "domain" {
  for_each                    = local.datasets
  dataset_id                  = replace("${local.prefix}_${each.key}", "-", "_")
  location                    = var.region
  delete_contents_on_destroy  = false
  default_table_expiration_ms = null
  labels                      = { environment = var.environment, system = "remedialhq", domain = each.key }
}

resource "google_bigquery_table" "events" {
  dataset_id          = google_bigquery_dataset.domain["operations"].dataset_id
  table_id            = "events"
  deletion_protection = true
  time_partitioning {
    type  = "DAY"
    field = "occurred_at"
  }
  clustering = ["event_type", "platform", "package_id"]
  schema = jsonencode([
    { name = "occurred_at", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "event_type", type = "STRING", mode = "REQUIRED" },
    { name = "platform", type = "STRING", mode = "NULLABLE" },
    { name = "package_id", type = "STRING", mode = "NULLABLE" },
    { name = "payload", type = "JSON", mode = "NULLABLE" },
    { name = "ledger_hash", type = "STRING", mode = "REQUIRED" }
  ])
}

resource "google_bigquery_dataset_iam_member" "measure_operations" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.domain["operations"].dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.phase["measure"].email}"
}

resource "google_secret_manager_secret" "platform" {
  for_each  = local.secret_names
  secret_id = "${local.prefix}-${each.key}"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "youtube_publisher" {
  secret_id = google_secret_manager_secret.platform["youtube-owner-token"].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.phase["publish"].email}"
}

resource "google_cloud_run_v2_service" "phase" {
  for_each            = toset(local.phases)
  name                = "${local.prefix}-${each.key}"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = true

  scaling {
    scaling_mode          = "MANUAL"
    manual_instance_count = 0
  }

  template {
    service_account                  = google_service_account.phase[each.key].email
    timeout                          = each.key == "collect" ? "1800s" : "900s"
    max_instance_request_concurrency = 1
    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }
    containers {
      image   = var.image_uri
      command = ["python", "-m", "remedialhq.service"]
      ports { container_port = 8080 }
      env {
        name  = "PHASE"
        value = each.key
      }
      env {
        name  = "APP_ROOT"
        value = "/app"
      }
      env {
        name  = "WORKSPACE"
        value = "/tmp/remedialhq"
      }
      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "SOURCE_BUCKET"
        value = google_storage_bucket.data["source_approved"].name
      }
      dynamic "env" {
        for_each = contains(["collect", "reconcile"], each.key) ? [1] : []
        content {
          name  = "PHASE_ARTIFACT_BUCKET"
          value = google_storage_bucket.data["source_quarantine"].name
        }
      }
      env {
        name  = "ASSET_BUCKET"
        value = google_storage_bucket.data["media_workspace"].name
      }
      env {
        name  = "STATE_BUCKET"
        value = google_storage_bucket.data["state"].name
      }
      env {
        name  = "TELEMETRY_DATASET"
        value = google_bigquery_dataset.domain["operations"].dataset_id
      }
      env {
        name  = "PUBLISHING_ENABLED"
        value = tostring(var.publishing_enabled)
      }
      env {
        name  = "YOUTUBE_EXPECTED_CHANNEL_ID"
        value = var.youtube_expected_channel_id
      }
      env {
        name  = "YOUTUBE_CREDENTIALS_READY"
        value = tostring(var.youtube_credentials_ready)
      }
      env {
        name  = "YOUTUBE_LIVE_ADAPTER_ENABLED"
        value = tostring(var.youtube_live_adapter_enabled)
      }
      env {
        name  = "YOUTUBE_MEDIA_PATH"
        value = var.youtube_media_path
      }
      env {
        name  = "YOUTUBE_THUMBNAIL_PATH"
        value = var.youtube_thumbnail_path
      }
      env {
        name  = "YOUTUBE_PRIVACY_STATUS"
        value = var.youtube_privacy_status
      }
      env {
        name  = "YOUTUBE_VISIBLE_PUBLICATION_AUTHORIZED"
        value = tostring(var.youtube_visible_publication_authorized)
      }
      env {
        name  = "PUBLISH_TARGETS"
        value = "youtube"
      }
      env {
        name  = "ENABLE_NETWORK_COLLECTION"
        value = tostring(var.network_collection_enabled)
      }
      env {
        name  = "DAILY_SPEND_LIMIT_USD"
        value = tostring(var.daily_spend_limit_usd)
      }
      dynamic "env" {
        for_each = each.key == "publish" ? {
          YOUTUBE_TOKEN_FILE = "/secrets/youtube/token.json"
        } : {}
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "volume_mounts" {
        for_each = each.key == "publish" && var.youtube_credentials_ready ? [1] : []
        content {
          name       = "youtube-token"
          mount_path = "/secrets/youtube"
        }
      }
      dynamic "env" {
        for_each = local.next_phase[each.key] == null ? [] : [local.next_phase[each.key]]
        content {
          name  = "NEXT_TOPIC"
          value = google_pubsub_topic.phase[env.value].id
        }
      }
      resources { limits = { cpu = "2", memory = each.key == "compile" ? "4Gi" : "2Gi" } }
    }
    dynamic "volumes" {
      for_each = each.key == "publish" && var.youtube_credentials_ready ? [1] : []
      content {
        name = "youtube-token"
        secret {
          secret = google_secret_manager_secret.platform["youtube-owner-token"].secret_id
          items {
            version = "latest"
            path    = "token.json"
          }
        }
      }
    }
  }
  depends_on = [google_project_service.required]

  lifecycle {
    ignore_changes = [template[0].containers[0].image]

    precondition {
      condition = !var.youtube_live_adapter_enabled || (
        var.youtube_credentials_ready && length(trimspace(var.youtube_expected_channel_id)) > 0
      )
      error_message = "YouTube live publishing requires credentials_ready and an expected channel ID."
    }
  }
}

resource "google_cloud_run_v2_service" "site" {
  name                = "${local.prefix}-site"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = true

  scaling {
    scaling_mode          = "MANUAL"
    manual_instance_count = 0
  }

  template {
    service_account                  = google_service_account.site_runtime.email
    timeout                          = "300s"
    max_instance_request_concurrency = 80
    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }
    containers {
      image   = var.image_uri
      command = ["python", "-m", "http.server"]
      args    = ["8080", "--bind", "0.0.0.0", "--directory", "/app/site"]
      ports { container_port = 8080 }
      resources { limits = { cpu = "1", memory = "512Mi" } }
    }
  }
  depends_on = [google_project_service.required]

  lifecycle {
    ignore_changes = [template[0].containers[0].image]
  }
}

resource "google_cloud_run_v2_service_iam_member" "site_public" {
  count    = var.site_public_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.site.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "push_invoker" {
  for_each = google_cloud_run_v2_service.phase
  project  = var.project_id
  location = var.region
  name     = each.value.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.push.email}"
}

resource "google_pubsub_subscription" "phase" {
  for_each                   = toset(local.phases)
  name                       = "${local.prefix}-${each.key}-push"
  topic                      = google_pubsub_topic.phase[each.key].id
  ack_deadline_seconds       = 600
  message_retention_duration = "604800s"
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
  push_config {
    push_endpoint = google_cloud_run_v2_service.phase[each.key].uri
    oidc_token {
      service_account_email = google_service_account.push.email
      audience              = google_cloud_run_v2_service.phase[each.key].uri
    }
  }
  depends_on = [google_cloud_run_v2_service_iam_member.push_invoker, google_service_account_iam_member.pubsub_token_creator]
}

resource "google_cloud_scheduler_job" "collection_tick" {
  name        = "${local.prefix}-collection-tick"
  description = "Starts the approved-source collection phase."
  schedule    = "*/15 * * * *"
  time_zone   = var.scheduler_timezone
  paused      = !var.network_collection_enabled
  pubsub_target {
    topic_name = google_pubsub_topic.phase["collect"].id
    data = base64encode(jsonencode({
      schema_version = 1
      trigger        = "scheduler"
      mode           = "bounded"
      phase          = "collect"
    }))
  }
  depends_on = [google_pubsub_topic_iam_member.scheduler_collect]
}

resource "google_dns_managed_zone" "primary" {
  count       = var.create_dns_zone ? 1 : 0
  name        = "remedialhq-com"
  dns_name    = "remedialhq.com."
  description = "ReMediaLHQ production DNS"
  labels      = { environment = var.environment, system = "remedialhq" }
}

resource "google_service_account" "edge" {
  provider = google-beta
  for_each = local.edge_services_enabled

  account_id   = substr("${local.prefix}-${each.key}", 0, 30)
  display_name = "ReMediaLHQ ${each.key} edge runtime"

  depends_on = [terraform_data.edge_preflight]
}

resource "google_cloud_run_v2_service" "edge" {
  provider = google-beta
  for_each = local.edge_services_enabled

  name                 = "${local.prefix}-${each.key}"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection  = true
  default_uri_disabled = true
  iap_enabled          = each.value.iap_enabled
  invoker_iam_disabled = !each.value.iap_enabled

  template {
    service_account                  = google_service_account.edge[each.key].email
    timeout                          = "60s"
    max_instance_request_concurrency = 40

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image   = var.edge_image_uris[each.key]
      command = ["/opt/venv/bin/python"]
      args    = ["-m", "remedialhq.edge"]

      ports {
        container_port = 8080
      }

      env {
        name  = "EDGE_ROLE"
        value = each.key
      }
      env {
        name  = "PUBLIC_ORIGIN"
        value = "https://${each.value.hostname}"
      }
      env {
        name  = "APP_ROOT"
        value = "/app"
      }
      dynamic "env" {
        for_each = each.value.iap_enabled ? {
          EDGE_EXPECTED_OWNER_EMAIL_SHA256 = sha256(lower(trimprefix(var.edge_iap_owner_principal, "user:")))
          EDGE_IAP_AUDIENCE                = "/projects/${data.google_project.current.number}/locations/${var.region}/services/${local.prefix}-${each.key}"
        } : {}
        content {
          name  = env.key
          value = env.value
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  depends_on = [
    google_project_service.edge,
    google_project_service_identity.iap,
    terraform_data.edge_preflight,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "edge_iap_invoker" {
  provider = google-beta
  for_each = local.edge_private_services_enabled

  project  = var.project_id
  location = google_cloud_run_v2_service.edge[each.key].location
  name     = google_cloud_run_v2_service.edge[each.key].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_project_service_identity.iap[0].email}"
}

resource "google_iap_web_cloud_run_service_iam_member" "edge_owner" {
  provider = google-beta
  for_each = local.edge_private_services_enabled

  project                = var.project_id
  location               = google_cloud_run_v2_service.edge[each.key].location
  cloud_run_service_name = google_cloud_run_v2_service.edge[each.key].name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = var.edge_iap_owner_principal

  depends_on = [google_cloud_run_v2_service_iam_member.edge_iap_invoker]
}

resource "google_compute_region_network_endpoint_group" "edge" {
  provider = google-beta
  for_each = local.edge_services_enabled

  name                  = "${local.prefix}-${each.key}-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.edge[each.key].name
  }

  depends_on = [google_project_service.edge]
}

resource "google_compute_backend_service" "edge" {
  provider = google-beta
  for_each = local.edge_services_enabled

  name                  = "${local.prefix}-${each.key}-backend"
  protocol              = "HTTP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false

  backend {
    group = google_compute_region_network_endpoint_group.edge[each.key].id
  }

  log_config {
    enable      = true
    sample_rate = 1
  }
}

resource "google_compute_global_address" "edge" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  name         = "${local.prefix}-edge-ipv4"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"

  depends_on = [google_project_service.edge]
}

resource "google_compute_managed_ssl_certificate" "edge" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  # A new name forces validation against the propagated DNS. Future certificate
  # replacements must increment this suffix so create_before_destroy can work.
  name = "${local.prefix}-edge-certificate-v2"

  managed {
    domains = sort([for service in values(local.edge_services) : service.hostname])
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [google_project_service.edge]
}

resource "google_compute_ssl_policy" "edge" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  name            = "${local.prefix}-edge-tls"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"

  depends_on = [google_project_service.edge]
}

resource "google_compute_url_map" "edge_https" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  name = "${local.prefix}-edge-https"

  default_url_redirect {
    host_redirect          = "remedialhq.com"
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = true
  }

  dynamic "host_rule" {
    for_each = local.edge_services_enabled
    content {
      hosts        = [host_rule.value.hostname]
      path_matcher = "${host_rule.key}-paths"
    }
  }

  dynamic "path_matcher" {
    for_each = local.edge_services_enabled
    content {
      name            = "${path_matcher.key}-paths"
      default_service = google_compute_backend_service.edge[path_matcher.key].id
    }
  }
}

resource "google_compute_target_https_proxy" "edge" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  name             = "${local.prefix}-edge-https"
  url_map          = google_compute_url_map.edge_https[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.edge[0].id]
  ssl_policy       = google_compute_ssl_policy.edge[0].id
  quic_override    = "ENABLE"
}

resource "google_compute_global_forwarding_rule" "edge_https" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  name                  = "${local.prefix}-edge-https"
  target                = google_compute_target_https_proxy.edge[0].id
  ip_address            = google_compute_global_address.edge[0].address
  ip_protocol           = "TCP"
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

resource "google_compute_url_map" "edge_http_redirect" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  name = "${local.prefix}-edge-http-redirect"

  default_url_redirect {
    https_redirect         = true
    host_redirect          = "remedialhq.com"
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = true
  }

  dynamic "host_rule" {
    for_each = local.edge_services_enabled
    content {
      hosts        = [host_rule.value.hostname]
      path_matcher = "${host_rule.key}-http-redirect"
    }
  }

  dynamic "path_matcher" {
    for_each = local.edge_services_enabled
    content {
      name = "${path_matcher.key}-http-redirect"

      default_url_redirect {
        https_redirect         = true
        host_redirect          = path_matcher.value.hostname
        redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
        strip_query            = false
      }
    }
  }
}

resource "google_compute_target_http_proxy" "edge" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  name    = "${local.prefix}-edge-http"
  url_map = google_compute_url_map.edge_http_redirect[0].id
}

resource "google_compute_global_forwarding_rule" "edge_http" {
  provider = google-beta
  count    = var.edge_subdomains_enabled ? 1 : 0

  name                  = "${local.prefix}-edge-http"
  target                = google_compute_target_http_proxy.edge[0].id
  ip_address            = google_compute_global_address.edge[0].address
  ip_protocol           = "TCP"
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
