variable "project_id" {
  description = "Google Cloud project ID."
  type        = string
}

variable "region" {
  description = "Primary deployment region."
  type        = string
  default     = "us-east1"
}

variable "environment" {
  description = "Environment label."
  type        = string
  default     = "prod"
}

variable "image_uri" {
  description = "Immutable container image URI. Pin a digest in production."
  type        = string
}

variable "publishing_enabled" {
  description = "Global fail-closed publication switch."
  type        = bool
  default     = false
}

variable "daily_spend_limit_usd" {
  description = "Application-enforced daily generation spend limit."
  type        = number
  default     = 250
}


variable "network_collection_enabled" {
  description = "Allow the collector to make network requests to registry-approved sources."
  type        = bool
  default     = false
}

variable "scheduler_timezone" {
  type    = string
  default = "America/New_York"
}

variable "create_dns_zone" {
  description = "Create the remedialhq.com Cloud DNS managed zone. Enable only after deciding to delegate DNS to Google Cloud."
  type        = bool
  default     = false
}

variable "site_public_enabled" {
  description = "Grant allUsers permission to invoke the static site service."
  type        = bool
  default     = false
}

variable "youtube_live_adapter_enabled" {
  description = "Enable the YouTube live adapter inside the publish phase."
  type        = bool
  default     = false
}

variable "youtube_credentials_ready" {
  description = "Mount the latest YouTube owner-token secret version into the publish service."
  type        = bool
  default     = false
}

variable "youtube_expected_channel_id" {
  description = "Exact owner-verified YouTube channel ID; required before enabling the live adapter."
  type        = string
  default     = ""
}

variable "youtube_media_path" {
  description = "Container path to the media asset used by the first private upload."
  type        = string
  default     = "/app/artifacts/launch/remedialhq-launch-short-visual-prototype.mp4"
}

variable "youtube_thumbnail_path" {
  description = "Container path to the YouTube thumbnail."
  type        = string
  default     = "/app/brand/thumbnail-episode-001.png"
}

variable "youtube_privacy_status" {
  description = "YouTube upload privacy status."
  type        = string
  default     = "private"
  validation {
    condition     = contains(["private", "unlisted", "public"], var.youtube_privacy_status)
    error_message = "youtube_privacy_status must be private, unlisted, or public."
  }
}

variable "youtube_visible_publication_authorized" {
  description = "Separate owner authority for unlisted or public YouTube uploads."
  type        = bool
  default     = false
}

variable "edge_subdomains_enabled" {
  description = "Create the app, API, and public-ledger Cloud Run services and their global HTTPS load balancer."
  type        = bool
  default     = false
}

variable "edge_image_uris" {
  description = "Digest-pinned Artifact Registry images for the app, API, and public-ledger runtimes. Required when edge_subdomains_enabled is true."
  type = object({
    app    = string
    api    = string
    verify = string
  })
  default = {
    app    = ""
    api    = ""
    verify = ""
  }

  validation {
    condition = alltrue([
      for image_uri in values(var.edge_image_uris) :
      image_uri == "" || can(regex("@sha256:[0-9a-f]{64}$", image_uri))
    ])
    error_message = "Every nonempty edge image URI must end in a lowercase sha256 digest pin."
  }
}

variable "edge_iap_owner_principal" {
  description = "Single owner user principal granted IAP access to app and API, in user:name@example.com form. Required when edge_subdomains_enabled is true."
  type        = string
  default     = ""

  validation {
    condition = (
      var.edge_iap_owner_principal == "" ||
      can(regex("^user:[^@[:space:]]+@[^@[:space:]]+$", var.edge_iap_owner_principal))
    )
    error_message = "edge_iap_owner_principal must be empty or one explicit user:email principal."
  }
}
