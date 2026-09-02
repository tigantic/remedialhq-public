output "phase_service_accounts" { value = { for key, account in google_service_account.phase : key => account.email } }
output "push_service_account" { value = google_service_account.push.email }
output "site_runtime_service_account" { value = google_service_account.site_runtime.email }
output "artifact_registry_repository" { value = data.google_artifact_registry_repository.engine.id }
output "buckets" { value = { for key, bucket in google_storage_bucket.data : key => bucket.name } }
output "datasets" { value = { for key, dataset in google_bigquery_dataset.domain : key => dataset.dataset_id } }
output "phase_topics" { value = { for key, topic in google_pubsub_topic.phase : key => topic.id } }
output "phase_services" { value = { for key, service in google_cloud_run_v2_service.phase : key => service.uri } }
output "publishing_enabled" { value = var.publishing_enabled }
output "dns_nameservers" { value = var.create_dns_zone ? google_dns_managed_zone.primary[0].name_servers : [] }
output "site_service_uri" { value = google_cloud_run_v2_service.site.uri }
output "site_public_enabled" { value = var.site_public_enabled }
output "youtube_live_adapter_enabled" { value = var.youtube_live_adapter_enabled }
output "edge_subdomains_enabled" { value = var.edge_subdomains_enabled }
output "edge_hostnames" { value = sort([for service in values(local.edge_services) : service.hostname]) }
output "edge_service_names" {
  value = {
    for name, service in google_cloud_run_v2_service.edge : name => service.name
  }
}
output "edge_ipv4_address" {
  value = var.edge_subdomains_enabled ? google_compute_global_address.edge[0].address : null
}
output "edge_cloudflare_dns_records" {
  description = "DNS-only Cloudflare records required for initial certificate provisioning."
  value = var.edge_subdomains_enabled ? {
    for name, service in local.edge_services : name => {
      type    = "A"
      name    = service.hostname
      value   = google_compute_global_address.edge[0].address
      proxied = false
    }
  } : {}
}
output "edge_certificate_name" {
  value = var.edge_subdomains_enabled ? google_compute_managed_ssl_certificate.edge[0].name : null
}
