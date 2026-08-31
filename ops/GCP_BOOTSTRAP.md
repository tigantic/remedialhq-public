# ReMediaLHQ Google Cloud Bootstrap

The private administrative inventory records the production project, numeric project identifier, billing configuration, region, budget, and deployment evidence. RMH-030 through RMH-035 were completed and independently verified on 2026-08-30.

The primary region is `us-east1`. The project-scoped monthly budget is `$250` with current-spend notifications at `$25`, `$50`, `$100`, `$175`, and `$250`.

The bootstrap remains idempotent. For recovery or a new environment, run it only with an owner or administrator identity:

```bash
export PROJECT_ID="<owner-private-project-id>"
export BILLING_ACCOUNT_ID="<owner-private-billing-account-id>"
export REGION="us-east1"
bash scripts/bootstrap_gcp.sh
```

Build and probe the bootstrap image, publish it to the private Artifact Registry repository, resolve its immutable digest, and use that digest for `TF_VAR_image_uri`. Apply Terraform with publication, network collection, public site invocation, DNS creation, credentials, live adapters, and visible publication disabled. A successful initial apply must end with a zero-change follow-up plan. Artifact Analysis automatic scanning is active and every release candidate must be evaluated at its final immutable digest before deployment.

All seven Cloud Run services are explicitly set to `MANUAL` scaling with zero instances. They remain Ready, private, and pinned to the previously deployed v0.6.1 image. After service creation, the GitHub deployment workflow owns the image digest while Terraform ignores only that nested image field. This prevents a later infrastructure apply from rolling services back to the bootstrap image while retaining Terraform authority over scaling, access, and publication controls.

The collection scheduler must remain paused whenever network collection is disabled. Secret containers are intentionally created without secret versions. Do not add production credentials until the corresponding execution gate is complete.

The production project now has Artifact Analysis scanning enabled. A dedicated release-build service account is limited to log writing, image writing in the single ReMediaLHQ Artifact Registry repository, and object reading in the Cloud Build staging bucket. Cloud Build `3c2d7973-ffe3-42ef-a3c5-9479b9937d20` built the verified sanitized v0.7.0 public source with verified execution, Google-signed SLSA level 3 provenance, and a signed Artifact Analysis SBOM reference. The resulting digest was rejected after the Google scan reported 7 Critical and 44 High findings. It was not deployed.

RMH-043 remains open until a remediated final release digest passes the committed vulnerability policy, its provenance and SBOM are verified, and the keyless GitHub workflow completes end to end. GitHub Actions run `33295512821` received no runner and executed zero steps. GitHub reported the account-level block as a billing entitlement issue; that message does not prove an unpaid balance.
