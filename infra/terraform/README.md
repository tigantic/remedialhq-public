# Google Cloud deployment skeleton

This module establishes an authenticated, event-driven control plane for ReMediaLHQ. It does not create public media accounts, OAuth clients, payout identities, secret versions, or a production container image.

## Topology

1. Cloud Scheduler publishes a bounded collection tick.
2. Six Pub/Sub topics isolate collect, reconcile, compile, gate, publish, and measure authority.
3. Each topic pushes to one IAM-authenticated Cloud Run service with request concurrency set to `1`.
4. Every phase uses a distinct service account. A phase may publish only to its next topic, every phase is limited to the dedicated idempotency-state bucket, only compile can call Vertex AI, only measure can edit the operations dataset, and only publish can read the YouTube owner-token secret.
5. A phase publishes the next event only after a `PASS`; `HOLD` or `REJECT` stops the chain.
6. A private, versioned state bucket holds generation-matched version 2 event records, request digests, and leases. Duplicate push deliveries return the committed result or resume an interrupted dispatch. Conflicting or permanently invalid request material is acknowledged as rejected, transient storage failures release their current lease token, and an ambiguous publication attempt retains a one-hour reconciliation lease.
7. Child event IDs are deterministic. Pub/Sub remains an at-least-once transport, while every downstream phase resolves duplicate event IDs through the state machine.
8. Live collection commits snapshot files create-only under a dedicated prefix in the source-quarantine bucket, then commits a canonical manifest last. Reconcile reads only the generation-pinned manifest and file objects, verifies every digest, source-registry revision, summary-to-file relationship, and event-lineage field, and stops at `HOLD` until live claim extraction is implemented. Pub/Sub carries only the immutable artifact reference.
9. The collect identity has conditional create and read access only to the collect-artifact prefix. Reconcile has conditional read-only access to that prefix; neither identity can overwrite or delete those objects.
10. Separate versioned Cloud Storage buckets preserve quarantined and approved sources, working and published media, static site assets, the evidence ledger, state, and backups.
11. Domain-separated BigQuery datasets store sources, claims, editorial output, publishing, audience, experiments, revenue, costs, and operations telemetry.
12. Secret Manager creates the complete empty ReMediaLHQ credential inventory until the owner provisions credential versions.
13. The bootstrap step creates Artifact Registry and the versioned remote-state bucket before the first image push or Terraform plan.
14. Optional Cloud DNS provisioning is controlled by `create_dns_zone`.
15. `publishing_enabled` and `network_collection_enabled` both default to `false`.
16. A separately gated edge plane can create `app.remedialhq.com`, `api.remedialhq.com`, and `verify.remedialhq.com` behind one global external Application Load Balancer. It is disabled by default.

The six phase Cloud Run endpoints require IAM authentication. Their only invoker is the dedicated Pub/Sub push identity. Data-bucket, additional secret, and analytics permissions are intentionally absent until the corresponding persistent data flow is implemented and tested.

## Edge subdomains

`edge_subdomains_enabled = false` creates no edge services, Compute Engine resources, IAP service identity, or IAP policy. Enabling it requires all of the following:

- `environment = "prod"`;
- `create_dns_zone = false`, because Cloudflare remains authoritative;
- three nonempty Artifact Registry image URIs in this project and region, each pinned by digest;
- one explicit `user:` principal in `edge_iap_owner_principal`.

The app, API, and verification runtimes use distinct zero-privilege service accounts. The module grants none of them bucket, database, secret, phase, or publication permissions. The verification image must contain only the reviewed public projection. It must never mount or read the private pilot ledger, Stripe evidence, customer data, or the private evidence bucket.

App and API enable IAP directly on their Cloud Run services. Direct IAP protects every ingress path, while the load-balancer backend IAP setting remains unused. Terraform pre-provisions the IAP service agent, grants that agent `roles/run.invoker` on only app and API, and grants the configured owner `roles/iap.httpsResourceAccessor` on only those two services. The runtime receives a service-specific direct-IAP audience and a SHA-256 digest derived from the owner principal so it can validate the signed IAP assertion and bind the verified email claim to the configured owner. Verify receives neither private value. Verify is the sole unauthenticated service. Its Cloud Run invoker check is disabled, but its ingress accepts only internal and load-balancer traffic.

All three services disable their default `run.app` URI and accept traffic only through the load balancer. Exact host rules select the three backends. An unknown HTTPS host redirects to `https://remedialhq.com`; it never routes to app or API. Port 80 performs a permanent HTTPS redirect. The HTTPS frontend uses a Google-managed certificate and a modern TLS policy with TLS 1.2 as the minimum.

The existing control plane remains pinned to Google provider 6.x. Edge resources alone use Google Beta provider 7.21 or newer because the earlier installed provider does not expose direct Cloud Run IAP and default-URI disabling. This isolates the production state from a broad major-provider migration. No custom OAuth secret is accepted or stored in Terraform state.

### Activation sequence

1. Build and independently validate the three runtime images. Keep the verification runtime limited to its public allowlist projection.
2. Set the three digest-pinned image URIs, exact owner principal, and IAP readiness confirmation. Enable the edge feature in the owner-only production variable file.
3. Review a saved Terraform plan and apply it with the owner/admin identity. Do not delegate this initial creation to the update-only GitHub deployer.
4. Read `edge_cloudflare_dns_records` from the Terraform output. Add those three `A` records in Cloudflare with proxying disabled while Google provisions the certificate. Keep Cloudflare's interception and forced-redirect features off until certificate issuance succeeds.
5. Wait until the managed certificate is active, then verify HTTP-to-HTTPS redirects, TLS 1.2 or newer, exact host routing, IAP denial for app and API without the owner session, owner access with IAP, public read-only verify access, and failure of the default `run.app` endpoints.
6. If Cloudflare proxying is later enabled, repeat the full origin, authentication, header, and certificate-renewal checks. Do not treat an edge certificate alone as proof that the Google origin remains protected.

## Apply

```bash
PROJECT_ID=<project> BILLING_ACCOUNT_ID=<billing-id> ../../scripts/bootstrap_gcp.sh
cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config="bucket=<project>-remedialhq-tfstate"
terraform validate
terraform plan
terraform apply
```

Run the bootstrap once with an owner/admin identity, then configure GitHub Workload Identity Federation with `scripts/configure_github_wif.sh`. Pin `image_uri` to an immutable digest. Before activating a version 0.8.2 phase image, verify that the event-state prefix is empty or deliberately drain legacy records because schema version 1 state is rejected. The static site service, live YouTube adapter, owner-token mount, network collection, and global publication each have separate fail-closed switches. Create the YouTube owner-token secret version and set the verified `youtube_expected_channel_id` before enabling the live adapter. Run private soak tests before changing any visible-publication authority. Create-only workload IAM is not a substitute for a retention-locked audit store against bucket administrators.
