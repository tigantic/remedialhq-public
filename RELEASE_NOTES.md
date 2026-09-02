# Release Notes: v0.8.2

Release date: September 2, 2026

## Campaign route and upload authorization controls

- Validates 50 Creator Signal Desk prospects and drafts across 37 exact owner-private inputs without sending outreach or granting send authority.
- Reproduces 22 unique creator-published business routes from preserved unauthenticated transport excerpts, retains 19 email-compatible routes, quarantines three channel mismatches, and leaves 28 unresolved without guessing contact details.
- Binds customer-facing draft schema 2 copy to the approved sales-angle packet, owner-identity exclusion scan, exact commercial postal footer, planned date, suppression gate, and opt-out language.
- Adds a create-only YouTube upload preview and exact-digest confirmation across the target channel, privacy state, package, video, thumbnail, metadata, declarations, deterministic marker, and canonical consumption directory.
- Consumes each preview once across copied or hard-linked confirmation aliases, pins the reviewed media bytes through upload, and rejects exact or unverifiable marker collisions without mutating an existing video.
- Converts expected upload-control failures into explicit phase holds while keeping every YouTube publication switch disabled by default.
- Excludes `PENDING` and `REJECTED` records from public claim data while preserving the complete private evidence corpus.
- Retains the verified Sites version 19 public deployment with accurate current-channel language, concise Creator Desk conversion copy, readable independence text, and the required private-checkout boundary.

## Authoritative founding-slot controls

- Captures all available Stripe LIVE founding-offer history through a fixed cutoff with complete pagination and no raw provider identifiers, customer data, URLs, or secrets in retained evidence.
- Separates stable provider purchase identity from exact local evidence-file hashes, so later refunds or disputes cannot change slot ownership or weaken artifact provenance.
- Requires tax-aware live-payment evidence v2 and records the USD 99.00 base, tax, gross charge, and full gross refund as distinct values.
- Converts the retained Stripe snapshot into strict reconciliation evidence mechanically, then binds the exact history-file digest, canonical reconciliation digest, and full lifetime provider identity set into schema-5 ledger initialization.
- Enforces exact 0600 modes for the owner-private ledger and lock on every operation; insecure storage fails closed unless the explicit synthetic-test-only override is used.
- Records the authoritative ledger at zero consumed founding slots and five remaining, with a second post-initialization Stripe capture confirming no purchase crossed the cutoff.
- Records Sites version 19 with canonical alternate-host redirects, the exact registered source-video citation, and plain creator-facing sample copy without internal claim IDs.

## Immutable collection handoff

- Commits network source snapshots as content-addressed, create-only objects and commits the canonical manifest last.
- Pins manifest and file reads to exact Cloud Storage generations, hashes, byte counts, configured bucket, phase, and root-event lineage.
- Rejects duplicate JSON fields, unsafe paths, oversized sets, missing files, tampering, foreign references, and legacy live handoffs before reconciliation.
- Reuses an already committed collect manifest after lease recovery instead of repeating the network request.
- Stops verified live inputs at an explicit `HOLD` until claim extraction exists, preventing silent fallback to baked seed claims.
- Grants collect conditional creator and viewer access only to its artifact prefix and grants reconcile conditional read-only access.

## Hardened production runtime

- Replaced the vulnerable general-purpose runtime with digest-pinned Chainguard Python 3.14 builder and runtime images.
- Split media and development dependencies away from the deployed service. The runtime lock contains only the application and required cloud adapters.
- Runs as UID and GID 65532 with no package manager, shell, pip, setuptools, or wheel in the final image.
- Generated a complete Syft CycloneDX inventory from the exact immutable validation image.

## Fail-closed vulnerability policy

- Trivy result: PASS with 0 Critical and 0 High findings.
- Grype result: PASS with 0 Critical and 0 High findings.
- Both reports must identify the same immutable image ID. Missing tools, malformed reports, identity mismatches, unfixed findings, and any Critical or High finding fail the release.
- Source-controlled CI and deployment workflows define the same independent dual-scanner policy before an image can advance. Remote CI is intentionally deferred and is not represented as executed evidence.

## Supply-chain controls

- The source-controlled workflow produces BuildKit provenance and SBOM attestations, verifies their attachment to the application manifest, signs the immutable image digest with keyless Cosign, and verifies the signature before deployment.
- Google Artifact Analysis APIs are enabled. The workflow waits for complete OS and Python analysis, explicitly requests SBOM export once, and then requires an exact-image signed SPDX reference before evaluating findings.
- A bucket-restricted read grant lets the workflow download only Artifact Analysis SBOM objects, match the referenced bytes to the signed hash, and validate the image-bound SPDX 2.3 inventory.
- The authenticated read-only Google API response is the signature trust boundary. The workflow does not claim independent cryptographic verification against Google's unavailable KMS public key.
- Google's exact singleton `[null]` clean response is preserved as raw evidence and narrowly normalized to zero finding objects. Every other malformed null shape fails closed.
- A prior v0.7.0 cloud build produced Google-signed SLSA provenance but failed the vulnerability threshold and was not deployed.
- A separate v0.7.1 audit produced signed SLSA level 3 provenance, a signed SPDX reference, and zero Google finding objects. It was not deployed because the GitHub-hosted workflow did not execute.
- The GitHub-hosted keyless path remains unexecuted. CI is intentionally deferred, and source-controlled controls are not represented as executed evidence.

## Deliberately pending

The seven phase-processing Cloud Run services remain private, manually held at zero instances, and on the accepted v0.6.1 digest until every v0.8.2 cloud gate passes. The IAP-gated owner application and API plus the public read-only verifier are deployed separately and live over managed HTTPS. The qualified 14-day outreach run, paid-pilot fulfillment, deferred CI, root-account hardening, registrar MFA, YouTube feature verification, analytics, newsletter automation, OAuth grants, live source collection, and automated channel publication remain open. This release does not claim first revenue or autonomous public operation.
