# Security Policy

## Supported release

`0.7.x` is the active ReMediaLHQ release line.

## Reporting

Report security concerns to `security@remedialhq.com` after Google Workspace activation. Until then, use the owner-controlled root Google account through a private channel. Include the affected component, impact, reproduction details, and any evidence needed to validate the issue.

## Credential handling

Production OAuth clients, refresh tokens, API keys, webhook secrets, signing keys, recovery codes, identity documents, banking data, and tax data are excluded from Git history. Delegated runtime credentials are installed through Google Secret Manager. Owner identity values and operating records required for provider forms remain local under `local-private/` or in an approved encrypted system. The current public-source ZIP excludes owner identity and private administrative records. The full Git bundle contains historical administrative source and must remain private.

## Publication security

ReMediaLHQ publication is fail-closed. A live platform action requires passing content gates, an enabled platform capability, a scoped owner credential, and a recorded owner authority. Public or unlisted YouTube publication additionally requires the explicit visible-publication switch.

## Supply chain

Pin production images and builder bases by digest, use GitHub Workload Identity Federation for Google Cloud deployment, protect `main`, review dependency updates, and verify the release manifest before deployment. A release image is ineligible for deployment unless its final digest has verified build provenance, an SBOM, and an acceptable vulnerability scan under the committed release policy.

Artifact Analysis scanning is active. The first provenance-bearing v0.7.0 audit candidate was rejected with 7 Critical and 44 High findings and was never deployed. The v0.7.1 replacement image passed local Trivy and Grype gates, and its separate Cloud Build audit produced signed provenance, a signed SPDX reference, and zero Google finding objects without deployment. The v0.7.2 workflow explicitly requests SBOM export, verifies the exact signed subject and location through the authenticated read-only Google API, downloads the object through a bucket-restricted grant, verifies its referenced hash and SPDX 2.3 identity, and accepts only the exact clean `[null]` response shape. Version 0.7.3 retains that gate and adds create-only, generation-pinned source snapshot manifests with configured-bucket and event-lineage validation. It does not claim independent verification against Google's unavailable KMS public key. Production services remain private, manually held at zero instances, and pinned to the earlier v0.6.1 digest until the remote workflow executes every gate successfully.
