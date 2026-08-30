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

Build and probe the bootstrap image, publish it to the private Artifact Registry repository, resolve its immutable digest, and use that digest for `TF_VAR_image_uri`. Apply Terraform with publication, network collection, public site invocation, DNS creation, credentials, live adapters, and visible publication disabled. A successful initial apply must end with a zero-change follow-up plan.

All seven Cloud Run services are explicitly set to `MANUAL` scaling with zero instances. After service creation, the GitHub deployment workflow owns the image digest while Terraform ignores only that nested image field. This prevents a later infrastructure apply from rolling services back to the bootstrap image while retaining Terraform authority over scaling, access, and publication controls.

The collection scheduler must remain paused whenever network collection is disabled. Secret containers are intentionally created without secret versions. Do not add production credentials until the corresponding execution gate is complete.

Container vulnerability scanning and signed build provenance remain open hardening work. The keyless GitHub identity is configured and least-privilege verified, but its first end-to-end workflow authentication remains blocked by the recorded GitHub Actions startup failure.
