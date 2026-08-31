# Google Cloud deployment skeleton

This module establishes an authenticated, event-driven control plane for ReMediaLHQ. It does not create public media accounts, OAuth grants, payout identities, secret versions, or a production container image.

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

Cloud Run endpoints require IAM authentication. The only invoker granted by this module is the dedicated Pub/Sub push identity. Data-bucket, additional secret, and analytics permissions are intentionally absent until the corresponding persistent data flow is implemented and tested.

## Apply

```bash
PROJECT_ID=<project> BILLING_ACCOUNT_ID=<billing-id> ../../scripts/bootstrap_gcp.sh
cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config="bucket=<project>-remedialhq-tfstate"
terraform validate
terraform plan
terraform apply
```

Run the bootstrap once with an owner/admin identity, then configure GitHub Workload Identity Federation with `scripts/configure_github_wif.sh`. Pin `image_uri` to an immutable digest. Before activating a version 0.7.3 phase image, verify that the event-state prefix is empty or deliberately drain legacy records because schema version 1 state is rejected. The static site service, live YouTube adapter, owner-token mount, network collection, and global publication each have separate fail-closed switches. Create the YouTube owner-token secret version and set the verified `youtube_expected_channel_id` before enabling the live adapter. Run private soak tests before changing any visible-publication authority. Create-only workload IAM is not a substitute for a retention-locked audit store against bucket administrators.
