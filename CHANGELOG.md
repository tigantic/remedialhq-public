# Changelog

## 0.8.2 - 2026-09-02

- Added strict campaign preflight version 3 across 37 owner-private files, including exact plan, cohort, draft, sender, sales-angle, postal-footer, suppression, ledger, route, and evidence bindings.
- Preserved reproducible unauthenticated transport excerpts for 22 unique creator-published business routes, retained 19 email-compatible routes, quarantined three channel mismatches, and left 28 unresolved without guessing contact details.
- Upgraded the 50-draft campaign packet to customer-facing schema 2 copy with exact owner-profile scanning and the approved commercial postal footer in every email-style message.
- Added a create-only YouTube upload preview and exact-digest express confirmation that binds the channel, privacy state, package, media, thumbnail, metadata, declarations, marker, and canonical consumption directory.
- Made YouTube confirmations single-use across copied and hard-linked aliases, pinned verified media bytes through upload, and prohibited unpreviewed existing-video mutations.
- Converted expected YouTube authorization failures into explicit phase holds and added adversarial tests for confirmation reuse, post-confirmation mutation, marker collisions, and phase handling.
- Reclassified the execution queue without fictional agent-action availability and kept every live platform action behind its real owner or prerequisite gate.
- Rehearsed successful fulfillment, pre-fulfillment cancellation, seller rejection, full refunds, delivery evidence, feedback, and slot accounting in an isolated synthetic environment with zero provider calls.

## 0.8.1 - 2026-09-01

- Generated a private, owner-only packet of 50 grounded Creator Signal Desk outreach drafts with exact campaign routing, send-day rechecks, suppression controls, and opt-out language. No outreach was sent by the release process.
- Added a reusable draft generator with strict cohort matching, private-file permissions, channel-specific copy, and tests that prevent owner identity or em dashes from entering campaign output.
- Filtered `PENDING` and `REJECTED` records from the public claim projection while retaining the complete private source corpus.
- Replaced premature public claims about active video, newsletter, social, affiliate, and sponsor operations with accurate current capabilities.
- Simplified the Creator Desk conversion copy, kept the required no-public-payment-link boundary, and improved the independence notice legibility.
- Upgraded the Sites runtime and build dependencies to a zero-finding dependency audit, rebuilt the deployment, and published version 17.
- Verified all 17 clean document routes, legacy redirects, branded 404 behavior, method controls, HTTPS security headers, public identity boundaries, assets, and canonical source hashes on `remedialhq.com`.

## 0.8.0 - 2026-08-31

- Replaced arbitrary founding-slot reconciliation files with a closed, versioned JSON contract and a bounded, symlink-safe loader.
- Versioned the writable pilot ledger as schema 5 while retaining schemas 1 through 4 as verified, read-only migration evidence.
- Made a redacted Stripe LIVE history the lifetime-slot authority, cross-checked stable provider-purchase identities against the actual prior ledger, retained the full inherited identity set, kept local artifact hashes in a separate integrity domain, and bound exact-file and canonical-record digests into initialization.
- Added tax-aware live-payment evidence v2 and order-manifest schema 5, preserving the USD 99.00 booked-revenue base while recording exact tax, gross charge, and full gross refund movement.
- Rejected legacy v1 payment evidence for new schema-5 events and rejected nonzero schema 1 through 4 migration ledgers that cannot prove an owner-private provider-purchase binding.
- Added read-only `pilot reconciliation-facts` output plus adversarial reconciliation and migration tests.
- Added a cutoff-bound, fully paginated, privacy-minimized Stripe live-history collector and a strict history-to-reconciliation adapter that writes owner-only evidence without exposing raw provider identifiers or customer data.
- Enforced exact 0600 modes for the authoritative pilot ledger and lock on every operation, with an explicit synthetic-test-only override that fails closed for real records.
- Initialized and independently rechecked the single authoritative schema-5 ledger at zero consumed founding slots and five remaining.
- Published Sites version 14 with the exact registered source-video citation and restored canonical redirects for every alternate host.

## 0.7.3 - 2026-08-30

- Added a durable, immutable `collect` to `reconcile` source-snapshot handoff instead of forwarding instance-local paths through Pub/Sub.
- Committed content-addressed snapshot files create-only and made the canonical generation-bound manifest the final commit marker.
- Required strict artifact schemas, duplicate-field rejection, safe relative paths, bounded file sets, exact hashes, exact byte counts, pinned generations, configured-bucket binding, and exact event lineage before materialization.
- Reused an already committed event manifest after a reclaimed processing lease, preventing a network refetch after a crash between artifact commit and event-state commit.
- Bound event IDs to canonical request digests, preserved content-derived publication idempotency across lineage-only duplicates, and rejected conflicting or legacy state records without creating a permanent Pub/Sub poison retry.
- Gave phase leases a margin beyond their Cloud Run request timeout, released caught retryable failures with token- and generation-safe state transitions, distinguished permanent integrity rejection from transient artifact unavailability, and isolated every processing attempt in a removable request-scoped workspace.
- Verified publish event IDs against current package and authority material, preflighted downstream configuration before platform work, and preserved a one-hour reconciliation lease after any ambiguous remote side effect.
- Removed temporary filesystem paths from portable collection results and rejected missing, legacy, foreign, malformed, or tampered live handoffs.
- Bound every network snapshot manifest to its source-registry revision and required exact agreement between source summaries, metadata, body hashes, sizes, and manifest file entries.
- Stopped verified live snapshots at an explicit `HOLD` until live claim extraction is implemented, preventing silent fallback to baked seed claims.
- Rejected Pub/Sub envelopes without a real event identity, required the exact versioned scheduler trigger, derived collect roots only from authenticated event identity, and refused to commit a nonterminal `PASS` when its next topic is absent.
- Granted collect conditional create and read access only to its artifact prefix and reconcile conditional read-only access, with no overwrite or delete authority.
- Added adversarial artifact, phase, service-ordering, strict-metadata, and Terraform IAM tests while keeping network collection, publication, and Cloud Run scaling disabled.

## 0.7.2 - 2026-08-30

- Preserved the published v0.7.1 tag and artifacts while starting a separate patch release for the remote deployment-gate correction.
- Replaced the untestable inline Google scan block with a source-controlled Artifact Analysis checker and behavioral tests.
- Required exact image digest and HTTPS resource binding for discovery, vulnerability, signed SBOM subject, and SBOM reference evidence.
- Added one explicit `gcloud artifacts sbom export` request without a location override, followed by signed-reference polling under one 20-minute deadline.
- Required a complete OS and Python scan, signed Google reference metadata, matching in-toto envelope payload, SPDX MIME type, GCS location, and document hash.
- Added a bucket-restricted object-read grant so the workflow downloads the referenced SPDX file, verifies its exact signed hash, and validates its image-bound SPDX 2.3 inventory.
- Recorded the authenticated read-only Google API as the signature trust boundary without claiming unavailable independent KMS signature verification.
- Preserved Google's raw vulnerability response and normalized only the exact singleton `[null]` clean response to an empty finding list.
- Kept every Critical and High finding blocking, rejected missing or null effective severity, and accepted only explicit valid Medium, Low, Minimal, and Unknown severities under the existing policy.
- Added the checker and its adversarial tests to the closed public release allowlist.
- Recorded a checksum-locked private v0.7.1 Cloud Build audit with signed provenance, an explicitly exported signed SPDX document, zero Google finding objects, and no Cloud Run change.

## 0.7.1 - 2026-08-30

- Activated Artifact Analysis automatic vulnerability scanning and its required analysis APIs in the production project.
- Created a dedicated release-build service account with project log-writing, repository-scoped image-writing, and staging-bucket object-read access only.
- Built the verified sanitized v0.7.0 public source through Cloud Build with verified execution, Google-signed SLSA level 3 provenance, and a signed Artifact Analysis SBOM reference.
- Rejected that v0.7.0 audit image after the Google scan reported 7 Critical and 44 High findings; no Cloud Run service was updated.
- Confirmed that all seven Cloud Run services remain private, Ready, manually held at zero instances, and pinned to the previously deployed v0.6.1 image.
- Enabled branch protection, secret scanning, push protection, dependency alerts, and automated security updates on the sanitized public repository.
- Reproduced GitHub Actions run `33295512821` with no runner, zero executed steps, and an account-level message reported as a billing entitlement block; this does not establish an unpaid balance.
- Replaced the vulnerable runtime with a digest-pinned, non-root Chainguard Python 3.14 image using a runtime-only dependency lock and no shell or package manager in the final stage.
- Added exact-image Syft inventory, independent Trivy and Grype gates, BuildKit provenance and SBOM attestations, keyless Cosign signing, attachment verification, Google Artifact Analysis gating, immutable pushed-image smoke tests, and fail-closed release evidence checks. Cloud deployment remains blocked until every remote gate executes successfully.

## 0.7.0 - 2026-08-30

- Provisioned the owner-verified Google Cloud project, linked billing, and created a project-scoped $250 monthly budget with staged current-spend alerts.
- Deployed the private fail-closed control plane across seven Cloud Run services, eight protected versioned data buckets, nine BigQuery datasets, six Pub/Sub lanes, and 13 empty secret containers.
- Explicitly held every Cloud Run service at manual zero instances, paused collection, and verified the final Terraform state with a zero-change plan.
- Created the private Artifact Registry release image and pinned every service to its immutable digest while assigning later image updates solely to the keyless deployment workflow.
- Configured least-privilege GitHub Workload Identity Federation for the exact repository, owner, branch, environment, and deployment workflow without a service-account key.
- Added a strict private outreach qualification plan, exact 50-person cadence, daily cap, suppression controls, irreversible opt-outs, qualified replacements, and outcome tracking without storing prospect identity data.
- Versioned the expanded outreach ledger as schema 4, retained strict read-only schema 3 replay and reconciliation, and hardened outreach-plan imports against file replacement or mutation races.
- Hardened Google Cloud bootstrap compatibility for current project-label commands and Service Usage batch limits, plus compacted overlong generated bucket names.
- Separated source preflight assertions from generated release-evidence coherence so version and test-count checks close cleanly after source-bound validation.
- Added an automated sanitized public Git-bundle builder with trusted package verification, bounded streaming extraction, hostile Git-environment isolation, hook rejection, exact byte and mode matching, strict fsck, and atomic no-overwrite publication.

## 0.6.1 - 2026-08-29

- Recorded owner completion of Google Workspace, branded email delivery, a private commercial postal-address control, Stripe seller configuration, and the Stripe test-mode payment lifecycle.
- Independently verified public SPF, DKIM, DMARC, Google MX, the `ReMediaL HQ` YouTube display name, and the live `/privacy` and `/terms` HTTPS routes.
- Reconciled owner-reported Google Cloud, GitHub, vidIQ, X, Instagram, and Facebook identifiers while leaving unknown platform IDs and verification states unresolved.
- Kept the owner, Workspace administrator, seller, payout, postal, and tax details out of the public site and public source package.
- Corrected the public contact page to identify `support@remedialhq.com` as the active branded route and expanded legal-route and private-email regression checks.
- Moved owner-identity scan inputs behind the private administrative boundary and removed the administrator mailbox from public release guidance.
- Made package verification work directly in a public Git-bundle clone while preserving exact checks for all non-Git files.
- Replaced live cloud and administrative commit identifiers in public package content with private placeholders and a deterministic source-snapshot digest.
- Added Git-index mode verification so public bundle clones preserve and verify every declared executable bit.

## 0.6.0 - 2026-08-29

- Introduced an explicit schema 3 pilot-ledger initialization and lifetime founding-slot reconciliation boundary for legacy ledgers.
- Added active-scope amendments that invalidate stale customer and seller acceptances until the amended scope is accepted again.
- Required strict, redacted, order-bound live payment and refund evidence with source-artifact hashes and observation-time chronology.
- Split local artifact completion from externally evidenced delivery, with exact order, artifact, source-proof, and dispatch-time correlation.
- Hardened ledger and manifest writes against concurrent processes, symbolic-link ancestors, unsafe file replacement, and stale projections.
- Changed publication HOLD responses to fail with a service-unavailable status and hardened claim, source, and renderer input boundaries.
- Reduced cloud deployment privilege, isolated phase identities, narrowed the container context, added staged rollout rollback, and strengthened Workload Identity Federation controls.
- Bound validation evidence to the exact source fingerprint and commit, restricted release manifests to tracked regular files, and hardened extracted-package verification against inventory downgrade and cross-platform path escapes.
- Added a closed public-file allowlist with credential, owner-identity, local-path, and dependency-boundary checks.
- Updated the first-dollar operating playbook and CLI examples for the evidence-backed schema 3 workflow.

## 0.5.1 - 2026-08-29

- Removed the owner's personal name and personal-name mailbox from every public site document, metadata record, byline, footer, and inquiry route.
- Standardized public site contact on `support@remedialhq.com` and added validation that prevents the retired personal identity from returning.
- Restored readable dark text and arrow styling on the lime article offer buttons and hardened the mobile header against horizontal clipping.
- Redirected the provider hostname to the canonical domain and recorded the verified Sites version 11 deployment.
- Recorded the public YouTube channel ID and surfaced the remaining display-name alignment action.
- Initialized the owner-only bookkeeping workspace and chart of accounts required before live revenue.
- Reconciled the 90-action execution authority, public deployment authority, release evidence, and private-data packaging boundary.
- Excluded untracked Python build metadata from release manifests so clean Git bundle checkouts reproduce the committed manifest exactly.

## 0.5.0 - 2026-08-29

- Added standard Creator Signal Desk paid-service, cancellation, and full-refund terms for the $99, 14-day, five-slot founding pilot.
- Added a private Stripe Payments checkout capped at five completed sessions without publishing the checkout URL in the repository or public site.
- Switched every public contact route to a branded domain address and recorded the independently verified mail DNS posture.
- Kept Managed Payments disabled because the offer is a service, with Stripe documented only as the checkout and payment processor.
- Bound creator briefs to the exact current pilot-ledger head and rejected stale manifests after a refund.
- Hardened customer deliverable writes against symbolic-link replacement, partial commits, and permissive file modes.
- Made Sites staging mirror only exact committed source files and safely remove stale deployment content.
- Repaired local and CI packaging so generated validation evidence cannot invalidate the exact-commit public release build.

## 0.4.0 - 2026-08-29

- Reconciled the canonical repository with the live `remedialhq.com` HTTPS deployment and published policy pages.
- Added a privacy-minimized, hash-chained operating ledger for the five-slot Creator Signal Desk sales and fulfillment workflow.
- Added deterministic pilot-order handling and output provenance for customer-specific creator briefs.
- Added a fail-closed public release builder that excludes owner-private data, credentials, archives, caches, and prior release bundles.
- Hardened JSON boolean parsing so string values cannot silently enable a source or bypass a prohibited-source flag.
- Added release validation for authored public em dashes and expanded CI quality gates.

## 0.3.0 - 2026-08-29

- Added the five-slot, 14-day, $99 Creator Signal Desk founding pilot and manual first-dollar playbook.
- Added a public offer page, sample creator brief, source-linked GTA VI article, working inquiry flow, and social share card.
- Added a zero-to-one sales funnel model with payment, refund, fulfillment-time, and owner-labor assumptions.
- Tightened factual gates to exact reviewed public wording and bound titles, bodies, media bytes, and storyboards to review records.
- Added expected-channel verification, repository publication authority, retryable publication HOLDs, upload reconciliation, and secure token handling.
- Fixed Terraform syntax; added provider locking, remote state, bootstrap resources, deploy IAM, and an unprivileged site runtime identity.
- Expanded release validation to Ruff, mypy, Terraform, Docker when available, public-site link crawling, and media hash checks.
- Removed unsupported public growth claims, false confidence precision, and autonomous-production language from the launch funnel.

## 0.2.0 - 2026-08-29

- Adopted `ReMediaLHQ` as the active brand and `remedialhq.com` as the canonical domain.
- Recorded personal operating authority in the owner-private administrative record.
- Recorded owner-completed Gmail, domain, and YouTube channel actions.
- Added an 86-task execution authority in Markdown, CSV, and JSON.
- Added account inventory, critical-path runbook, branded email map, YouTube setup, GCP bootstrap, and analytics setup.
- Rebranded the Python package, CLI, site, channel assets, media prototype, infrastructure, and release metadata.
- Added YouTube OAuth owner-bootstrap support and live adapter binding controls.
- Added website policy, disclosure, corrections, contact, sponsor, and data-deletion pages.
- Added Google Cloud bootstrap automation and expanded Terraform resources.
- Preserved the complete v0.1.0 chat-window release byte-for-byte under `archive/`.
- Added local-private owner data segregation outside Git history.

## 0.1.0 - 2026-08-29

- Established the original evidence-led GTA VI intelligence vertical.
- Added the 82-day pre-launch opportunity calendar and launch-day answer command center.
- Added source and claim corpora, launch packages, deterministic gates, ledger, cloud design, brand assets, site, revenue model, tests, and release evidence.
