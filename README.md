# ReMediaLHQ Engine

**Evidence-led creator research and entertainment media engine**
Version `0.8.2` · release line, September 2, 2026

ReMediaLHQ turns fast-moving entertainment hype into source-linked intelligence, original analysis, launch tracking, practical guides, and measurable distribution. GTA VI is the first commercial vertical.

## Current owner authority

```text
Owner: private administrative record
Root Google account: private administrative record
Domain: remedialhq.com
YouTube: @ReMediaLHQ
```

The domain and YouTube channel are recorded as owner-completed. The public display name is `ReMediaL HQ`, and the channel ID is `UCm6r0Dl4So4COH00U1qCE2w`. The public site and policy pages are live over HTTPS at [remedialhq.com](https://remedialhq.com), and the active public contact route is `support@remedialhq.com`. The owner-gated app and API plus the public read-only verifier are also live over managed HTTPS. Public DNS verifies mail authentication. The owner reports end-to-end branded delivery and the private payment-provider controls complete. Authenticated Stripe history and the owner-private schema-5 ledger verify zero consumed founding slots and five remaining. Analytics, root-account hardening, and remaining channel settings are still open. Version 0.8.2 is a source candidate until its commit-bound validation, release evidence, tag, package, and public publication all pass.

## First-dollar path

The fastest commercial lane is the manually fulfilled **Creator Signal Desk**: five founding slots, 14 calendar days, $99 one-time. The site includes the offer, an inquiry path, standard paid-service and refund terms, a public sample brief, and a source-linked GTA VI proof article. The price is a willingness-to-pay test, not proven unit economics, a forecast, or a performance guarantee. The owner-controlled checkout stays private and may be sent only after fit, scope, written acceptance, founding-slot reconciliation, and transaction-specific checks. Use the [first-dollar playbook](ops/FIRST_DOLLAR_PLAYBOOK.md) to qualify and close each order.

## Prime directive

Produce useful, original, attributable entertainment media while preserving evidence state, source lineage, rights boundaries, commercial disclosure, and fail-closed publication control.

## Editorial state model

Every material claim is assigned one of six states:

- `CONFIRMED`
- `OBSERVED`
- `REPORTED`
- `INFERRED`
- `PENDING`
- `REJECTED`

The public wording, title strength, publication route, and correction behavior are constrained by that state.

## Repository map

```text
artifacts/              Reviewed public launch and revenue-validation assets
brand/                  ReMediaLHQ identity, channel, social, watermark, and thumbnail assets
config/                 Identity, source, policy, platform, and revenue contracts
content/                Launch package, 82-day calendar, and opportunity queue
data/                   Seed sources, claims, and research snapshots
docs/                   Public architecture, autonomy, policy, launch, and revenue records
infra/terraform/         Google Cloud deployment configuration
ops/                    Public-safe operating and setup runbooks
scripts/                Bootstrap, rendering, package verification, and release utilities
site/                   ReMediaLHQ static site and required policy pages
src/remedialhq/          Executable deterministic core
tests/                  Unit, adversarial, and integration tests
```

The public source package uses a closed file allowlist. Private execution authority, account inventory, owner records, detailed validation logs, and historical archives are intentionally omitted.

## Run locally

For a public Git bundle, clone it first:

```bash
git clone ../remedialhq-engine-v0.8.2-public.bundle remedialhq-engine
cd remedialhq-engine
```

From either that clone or the extracted public ZIP root, verify the declared package files before installing anything. Git control metadata created by cloning is ignored, while every non-Git file remains subject to the exact package inventory.

```bash
python scripts/verify_manifest.py
python -m venv ../remedialhq-venv
source ../remedialhq-venv/bin/activate
pip install --require-hashes --requirement requirements-build.lock
pip install --require-hashes --requirement requirements-production.lock
pip install --require-hashes --requirement requirements-dev.lock
pip install --no-build-isolation --no-deps --editable .

remedialhq demo --root . --output artifacts/demo
remedialhq verify-ledger artifacts/demo/ledger.jsonl
python scripts/render_brand_assets.py
python scripts/build_launch_short.py
python scripts/revenue_model.py
python -m unittest discover -s tests -v
```

Run package verification before installing or generating anything in the extracted directory. The virtual environment stays outside the package so verification starts from the exact shipped inventory.

## Paid-pilot operations

The `remedialhq pilot` commands maintain a private, hash-chained schema 5 record of the five-slot founding test. Initialization requires a retained reconciliation record that conforms to [`config/pilot-slot-reconciliation.schema.json`](config/pilot-slot-reconciliation.schema.json). Capture sanitized live history with `python -m remedialhq.stripe_live_history`, then convert those exact retained bytes with `python -m remedialhq.stripe_reconciliation`; the adapter verifies canonicality, privacy boundaries, complete pagination, offer identity, every purchase digest, and owner-only storage before it creates reconciliation evidence. Its redacted Stripe LIVE account-history record is the lifetime-slot authority, including successful purchases that are not present in a ledger and purchases later refunded. A schema-5 predecessor can be supplied with `--prior-ledger`; the command verifies its chain, inherited provider identities, every direct `PURCHASED` event hash, and every direct payment-evidence artifact. Stable provider-purchase digests are cross-checked against provider history, while local evidence-artifact hashes remain a separate integrity domain and are independently bound. The new initialization event retains the full inherited provider-digest set and binds both the exact reconciliation-file digest and its canonical record digest. Schemas 1 through 4 are readable, migration-only evidence, but a nonzero legacy ledger fails closed because it cannot prove the provider-purchase binding required by schema 5. Designate exactly one successor as authoritative and archive every predecessor read-only. The cap is mechanically enforced within that lineage, but local files can be copied or forked, so the retained reconciliation record and operator access controls must prevent branching.

Real pilot records must live on an owner-only filesystem that enforces POSIX permissions. Under WSL, use an ext4 path under `/home`, not a Windows-mounted path under `/mnt/c`. Set the private directory to `0700`; the ledger, its hidden lock file, prior ledgers, and retained evidence files must each be `0600`. Every ledger operation rechecks the ledger and lock modes and fails closed if either differs. The `--allow-insecure-test-storage` flag is an explicit escape hatch only for synthetic, non-sensitive tests. It prints a warning and must never be used with real prospects, customers, payments, or evidence.

The workflow confirms an exact scope reference and written customer acceptance before checkout, admits only a strict redacted `LIVE` payment evidence file into revenue, requires post-payment order acceptance against the same active scope before fulfillment, and binds each brief to approved claim IDs. A scope amendment names the scope it supersedes and invalidates prior customer and seller acceptance. The amended scope needs fresh written customer acceptance, plus fresh seller acceptance if payment has already been captured. Fulfillment stops after an opaque cancellation request.

The owner-only bookkeeping workspace is described in [`ops/BOOKKEEPING_SETUP.md`](ops/BOOKKEEPING_SETUP.md). Its live journal and reconciliations remain under ignored `local-private/bookkeeping/` and never enter Git or distributable releases.

```text
pilot init -> outreach-validate -> outreach-import -> suppression-check
           -> contact -> reply -> sample -> scope -> customer-acceptance
           -> checkout -> purchase -> accept-order -> start
           -> complete-artifact -> deliver -> feedback
scope, before start -> amend-scope -> fresh customer acceptance
                                  -> fresh seller acceptance when already paid
purchase -> reject-order -> refund
purchase or accepted order -> cancel -> refund when eligible
```

The outreach validator and importer accept only opaque IDs, enumerated facts, dates, and evidence digests. They do not find prospects, verify evidence bodies, or send messages. The imported campaign enforces the 50-prospect plan, 10-contact daily cap, planned channel and date, a fresh suppression check, and irreversible opt-outs. A pre-contact opted-out candidate can be replaced through one validated `outreach-amend` event without changing campaign controls, expanding the active cohort, or erasing the opt-out history. Fifty contacts recorded through the legacy manual path cannot cross the decision gate; the summary returns `QUALIFICATION_PLAN_REQUIRED` unless the complete outreach plan was imported first.

`purchase` requires an explicit opaque order ID, a strict redacted v2 JSON file supplied with `--payment-evidence`, and the verified fee in cents. The file binds a stable provider-purchase digest, a USD 99.00 one-time base price, nonnegative tax, and the exact gross live charge to that order. `TEST` and legacy v1 evidence are deliberately rejected for new schema-5 events. `refund` requires v2 full-refund evidence with the same provider-purchase digest and a refunded amount equal to the original gross charge. Booked-revenue and fee metrics continue to use the USD 99.00 service base, while schema-5 events and order-manifest schema 5 expose base, tax, gross, and refunded-gross movement separately.

Artifact completion and delivery are separate events. `complete-artifact --artifact` hashes the exact local deliverable without storing its path. `deliver --order-id ... --delivery-evidence ...` accepts only redacted external delivery proof that matches both the order and completed artifact digest. A local file alone is not delivery evidence.

Run `remedialhq pilot --help` for all operator commands and use the [first-dollar playbook](ops/FIRST_DOLLAR_PLAYBOOK.md) for the secure storage setup, evidence schemas, and exact sequence. The command-line default `local-private/pilot-events.jsonl` is convenient for synthetic repository tests but is not safe for real records when the repository is under `/mnt/c`. Pass an explicit owner-only `/home` path for live operations. The ledger stores opaque references and normalized evidence digests, not evidence bodies, names, email addresses, messages, card data, raw provider IDs, or private file paths.

## Guarded Google analytics setup

`remedialhq google-setup` prints an offline plan by default. An explicit
`--live-readback` enables owner-authorized inspection, while `--apply-live` is required
before the command can verify the Search Console domain, add its sitemap, or create the
exact GA4 property, web stream, and GTM web container. It never creates provider
accounts or accepts terms. See the [Google setup runbook](ops/GOOGLE_SETUP_RUNBOOK.md)
for required scopes, fixed target identities, and private evidence handling.

## YouTube owner authorization

The hashed runtime installation above includes the optional YouTube dependencies. The
authorization command will not open Google consent until an owner-private record proves
explicit acceptance of the exact current ReMediaLHQ Privacy Policy and Terms. Create that
record outside the repository in an owner-only `0700` directory:

```bash
remedialhq auth youtube-policy-acceptance \
  --repository-root . \
  --output /secure/path/youtube-policy-acceptance.json \
  --accept-privacy-policy \
  --accept-terms
```

Then run the local owner bootstrap after creating the Google OAuth desktop client:

```bash
remedialhq auth youtube \
  --client-secrets /secure/path/client_secret.json \
  --token-output /secure/path/remedialhq-youtube-token.json \
  --policy-acceptance /secure/path/youtube-policy-acceptance.json \
  --repository-root .
```

The acceptance record is create-only, uses mode `0600`, binds the accepted policy source
digests to the exact requested OAuth scopes, and contains no owner identity. The authorization
command revalidates it before loading the Google OAuth library, opens Google consent, resolves
the authorized channel, and writes a restricted local token file for installation into Google
Secret Manager.

To withdraw a local grant, use a fresh create-only evidence path in the same owner-only
directory. The command revokes the Google credential first, deletes the exact supplied local
token only after Google accepts the revocation, and writes a redacted mode-`0600` record that
contains no token or owner identity:

```bash
remedialhq auth youtube-revoke \
  --repository-root . \
  --token-file /secure/path/remedialhq-youtube-token.json \
  --evidence-output /secure/path/youtube-revocation-evidence.json \
  --confirm-revoke-and-delete
```

This command does not delete a separate Secret Manager version or YouTube-hosted content.
Those resources require their own explicit cleanup steps.

## Fixed YouTube channel setup

Plan the reviewed channel setup offline. Live execution requires an owner-only token
file outside the repository with the `youtube.force-ssl` scope. Planning validates the
exact channel, current-orange watermark, and seven private playlists without loading
or requiring the token and without contacting YouTube:

```bash
remedialhq auth youtube-policy-acceptance \
  --repository-root . \
  --output /secure/path/youtube-channel-policy-acceptance.json \
  --accept-privacy-policy \
  --accept-terms \
  --channel-setup

remedialhq auth youtube \
  --channel-setup \
  --client-secrets /secure/path/client_secret.json \
  --token-output /secure/path/remedialhq-youtube-setup-token.json \
  --policy-acceptance /secure/path/youtube-channel-policy-acceptance.json \
  --repository-root .
```

```bash
remedialhq setup-youtube-channel \
  --root . \
  --expected-channel-id UCm6r0Dl4So4COH00U1qCE2w \
  --watermark brand/youtube-video-watermark-current.png \
  --watermark-sha256 8ad2b256526c26101a98f5caeedce8434da6da3ecbf1311a642c544e464ff118
```

Add `--live --token-file /secure/path/remedialhq-youtube-setup-token.json` only
after reviewing that plan. Live mode creates only missing exact
playlists as Private and sets the reviewed watermark at offset zero using YouTube's
provider-default duration. The Watermarks API has no readback method and does not
document an exact Entire video sentinel, so the command does not claim that Studio's
Entire video setting is verified. Confirm that setting in Studio before closing
RMH-024. The command cannot change the avatar, banner, public description, upload
defaults, business contact, or publication authority.

## Deployment blueprint

The deployed private Google Cloud control plane provides a fail-closed, dormant topology:

- scheduled approved-source collection;
- isolated Pub/Sub topics and Cloud Run services for collection, reconciliation, compilation, gating, publication, and measurement;
- versioned Cloud Storage for sources, media, state, and evidence;
- BigQuery telemetry datasets;
- Secret Manager placeholders for delegated platform authority;
- private-by-default publication;
- deterministic event identities and duplicate-delivery recovery;
- create-only, generation-pinned source snapshot artifacts between collect and reconcile;
- Artifact Registry and immutable deployment images.

### Edge runtime

The production image includes one bounded HTTP runtime with three explicit roles. Run it with `python -m remedialhq.edge` and set `EDGE_ROLE` to `app`, `api`, or `verify`.

The `app` and `api` roles are private. They require direct Cloud Run IAP, a valid signed `X-Goog-IAP-JWT-Assertion`, the exact audience in `EDGE_IAP_AUDIENCE`, the current Cloud Run service name in `K_SERVICE`, and `EDGE_EXPECTED_OWNER_EMAIL_SHA256`. The configured audience must match `/projects/PROJECT_NUMBER/locations/us-east1/services/${K_SERVICE}` with a numeric Google Cloud project number. The runtime validates the IAP signature against Google's IAP public keys, requires the IAP issuer, subject, and email claims, and compares the normalized email digest without returning or logging the identity. If the compatibility email header is present, it must use the exact `accounts.google.com:` namespace and match the signed email claim. Any validation, key-fetch, configuration, or identity mismatch denies access.

The `verify` role is public, read-only, and identity-free. It exposes `/`, `/healthz`, `/status.json`, and `/claims.json` from the reviewed files under `site/data/`. It publishes bounded claim fields and release digests only. Every role accepts only `GET` and `HEAD`, rejects request bodies and ambiguous paths, and emits a strict security-header baseline.

## Supply-chain audit state

Artifact Analysis automatic vulnerability scanning is active. A Cloud Build audit of the verified, sanitized v0.7.0 public source produced Google-signed SLSA level 3 provenance and a signed SBOM reference under a dedicated least-privilege release-build service account. Its resulting image was rejected after the Google scan reported 7 Critical and 44 High findings. It was not deployed.

The sanitized public repository has branch protection, secret scanning, push protection, dependency alerts, and automated security updates enabled. A separate Cloud Build audit of the verified sanitized v0.7.1 source produced Google-signed SLSA level 3 provenance. Explicit SBOM export produced a signed SPDX reference whose hash and exact image subject were verified, and Google's clean vulnerability response contained no finding objects. The v0.7.2 source line corrected the remote gate sequence, and v0.7.3 added the immutable collection handoff. Version 0.8.0 added strict founding-slot reconciliation, tax-aware payment evidence, and permission-enforcing owner-private storage. Version 0.8.1 added the private outreach-draft generator and public claim projection. Version 0.8.2 adds reproducible creator-published route evidence, identity-safe commercial copy binding, campaign preflight version 3, and immutable single-use YouTube upload confirmation. Remote CI is intentionally deferred, so no current source candidate is represented as deployed.

## Included launch package

- ReMediaLHQ visual identity and channel assets;
- 82-day GTA VI pre-launch calendar;
- 82-item opportunity queue;
- 13-source default-deny registry;
- 22-claim seed corpus;
- first long-form episode, short, article, social thread, and newsletter;
- static public claim ledger;
- original short-form motion prototype;
- revenue scenarios;
- first-dollar validation model and manual sales playbook;
- Creator Signal Desk offer and public sample deliverable;
- red-team adjudication;
- automated tests, SBOM, manifests, and release validation.

## Historical deliverables

Prior release artifacts are retained only in the private administrative repository. They are historical evidence, not active brand authority and not part of the public source package.

## Independence notice

ReMediaLHQ is independent editorial coverage operated by its rights holder. It is not affiliated with, authorized by, or endorsed by Rockstar Games, Take-Two Interactive, Sony, Microsoft, or their subsidiaries. Third-party names and marks are used for editorial identification.

## Production boundary

The static site and required policy pages are live over HTTPS at `remedialhq.com`. The seven phase-processing Cloud Run services remain Ready, private, manually held at zero instances, and pinned to the previously deployed v0.6.1 image. The v0.7.0 through v0.8.2 candidates have not replaced that dormant processing runtime. Separate edge services provide the IAP-gated owner app and API plus the public read-only verifier over Google-managed HTTPS. They use zero-privilege identities, restricted ingress, disabled default origins, exact host routing, and a digest-pinned reviewed image. Live collection and publication remain disabled. Version 0.8.2 retains the durable collection handoff and adds owner-confirmation-gated YouTube upload controls, while live claim extraction remains intentionally unimplemented and stops at `HOLD`; compile, gate, and measurement still use seed data in offline mode. The deployed processing system is a dormant control plane and controlled test harness, not a claim of autonomous production operation. Paid-service terms version `creator-desk-v1` states the standard pilot scope, Stripe Payments processor role, cancellation, and full-refund-only policy. Stripe Managed Payments is disabled for this service. No public Payment Link is included. The owner-private ledger is initialized with zero consumed slots and five remaining. The link remains private and may be sent only after fit, scope, written acceptance, slot reconciliation, and any transaction-specific legal or tax checks are complete.
