# Release Notes: v0.7.0

Release date: August 30, 2026

## Production cloud foundation

- Verified the production Google Cloud project, organization, billing attachment, and owner authority through authenticated APIs.
- Created a project-scoped $250 monthly budget with current-spend alerts at $25, $50, $100, $175, and $250.
- Bootstrapped the private Artifact Registry repository, versioned Terraform state bucket, and least-privilege deploy identity.
- Applied the fail-closed production control plane with seven Ready Cloud Run services, nine BigQuery datasets, eight protected data buckets, six event topics and subscriptions, and thirteen empty Secret Manager containers.
- Kept public invocation, DNS creation, source collection, credentials, live adapters, and visible publication disabled. The collection scheduler is paused and all services are explicitly held at manual zero instances.
- Verified a zero-change post-apply Terraform plan.

## Keyless deployment

- Built and locally probed the verified bootstrap container before pushing its immutable digest to the private registry.
- Bound Google Workload Identity Federation to the exact numeric GitHub repository and owner IDs, main branch, production environment, and deployment workflow.
- Granted GitHub image-write permission and condition-restricted update access only to the seven existing runtime services. No service-account JSON key was created and GitHub has no Terraform state access.
- Configured all four non-secret GitHub deployment variables.
- Assigned routine image-digest updates solely to the deployment workflow while Terraform retains authority over every other service setting, preventing an infrastructure apply from rolling services back to the bootstrap image.

## First-dollar operating controls

- Added a strict private qualification-plan contract for exactly 50 personalized prospects scheduled ten per day on days three through seven.
- Added privacy-minimized queueing, fresh suppression checks, irreversible evidenced opt-outs, one-row qualified replacement, campaign outcomes, and a single authoritative ledger-lineage rollover.
- Versioned the outreach extensions as pilot-ledger schema 4 while retaining strict read-only schema 3 replay and reconciliation.
- Added CLI workflows, operating guidance, release allowlisting, and adversarial tests. No prospect was invented or contacted, so the external 14-day revenue test remains open.

## Reliability corrections

- Made the cloud bootstrap compatible with current gcloud project-label commands and the 20-service activation batch limit.
- Added deterministic compact bucket names when the descriptive form would exceed Google Cloud's 63-character limit.
- Pinned service-level manual zero-instance state to eliminate provider-default drift.
- Paused the collection schedule automatically whenever network collection is disabled.
- Moved generated version and test-count coherence checks into the post-validation evidence gate so a version bump closes without stale-evidence cycles.

## Deliberately pending

The qualified 14-day outreach run, paid-pilot fulfillment, GitHub Actions account-level startup resolution, container scanning, signed build provenance, root-account hardening, registrar renewal and MFA checks, YouTube feature verification, application and ledger subdomains, analytics, newsletter automation, OAuth grants, live source collection, and automated channel publication remain open. This release does not claim first revenue or autonomous public operation.
