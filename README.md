# ReMediaLHQ Engine

**Evidence-led creator research and entertainment media engine**
Version `0.7.3` · release line, August 30, 2026

ReMediaLHQ turns fast-moving entertainment hype into source-linked intelligence, original analysis, launch tracking, practical guides, and measurable distribution. GTA VI is the first commercial vertical.

## Current owner authority

```text
Owner: private administrative record
Root Google account: private administrative record
Domain: remedialhq.com
YouTube: @ReMediaLHQ
```

The domain and YouTube channel are recorded as owner-completed. The public display name is `ReMediaL HQ`, and the channel ID is `UCm6r0Dl4So4COH00U1qCE2w`. The public site and policy pages are live over HTTPS at [remedialhq.com](https://remedialhq.com), and the active public contact route is `support@remedialhq.com`. Public DNS verifies mail authentication. The owner reports end-to-end branded delivery and the private payment-provider controls complete. Analytics, root-account hardening, and remaining channel settings are still open. Version 0.7.3 is a source candidate until its commit-bound validation, release evidence, tag, package, and public publication all pass.

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
git clone ../remedialhq-engine-v0.7.3-public.bundle remedialhq-engine
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

The `remedialhq pilot` commands maintain a private, hash-chained schema 4 record of the five-slot founding test. Initialize the ledger explicitly with a retained lifetime-slot reconciliation artifact. If a schema 1, 2, 3, or 4 ledger exists, pass it with `--prior-ledger`; initialization verifies its chain, counts its purchases and inherited slots as consumed lifetime slots, and anchors its head hash in the new ledger. Schema 1 through 3 ledgers remain readable only as migration evidence and cannot accept new events. Designate exactly one successor as authoritative and archive every prior ledger read-only. The cap is mechanically enforced within that lineage, but local files can be copied or forked, so the tool cannot prevent multiple successors or later writes to a copied predecessor. The retained reconciliation artifact and operator access controls must prevent branching.

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

`purchase` requires an explicit opaque order ID, a strict redacted JSON file supplied with `--payment-evidence`, and the verified fee in cents. The file must describe a successful USD 99.00 one-time live payment and correlate to that order. `TEST` is deliberately rejected. `refund` similarly requires a strict full-refund evidence file supplied with `--refund-evidence` and correlated to the original order and payment.

Artifact completion and delivery are separate events. `complete-artifact --artifact` hashes the exact local deliverable without storing its path. `deliver --order-id ... --delivery-evidence ...` accepts only redacted external delivery proof that matches both the order and completed artifact digest. A local file alone is not delivery evidence.

Run `remedialhq pilot --help` for all operator commands and use the [first-dollar playbook](ops/FIRST_DOLLAR_PLAYBOOK.md) for the evidence schemas and exact sequence. The default ledger is `local-private/pilot-events.jsonl`, which is excluded from Git and sanitized public packages. It stores opaque references and normalized evidence digests, not evidence bodies, names, email addresses, messages, card data, raw provider IDs, or private file paths.

## YouTube owner authorization

The hashed runtime installation above includes the optional YouTube dependencies. Run the local owner bootstrap after creating the Google OAuth desktop client:

```bash
remedialhq auth youtube \
  --client-secrets /secure/path/client_secret.json \
  --token-output /secure/path/remedialhq-youtube-token.json
```

The command opens Google consent, resolves the authorized channel, and writes a restricted local token file for installation into Google Secret Manager.

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

## Supply-chain audit state

Artifact Analysis automatic vulnerability scanning is active. A Cloud Build audit of the verified, sanitized v0.7.0 public source produced Google-signed SLSA level 3 provenance and a signed SBOM reference under a dedicated least-privilege release-build service account. Its resulting image was rejected after the Google scan reported 7 Critical and 44 High findings. It was not deployed.

The sanitized public repository has branch protection, secret scanning, push protection, dependency alerts, and automated security updates enabled. GitHub Actions did not allocate jobs for the v0.7.1 release, and its backend message is not evidence of an unpaid balance. A separate Cloud Build audit of the verified sanitized v0.7.1 source produced Google-signed SLSA level 3 provenance. Explicit SBOM export produced a signed SPDX reference whose hash and exact image subject were verified, and Google's clean vulnerability response contained no finding objects. The v0.7.2 source line corrected the remote gate to request that export, verify the signed reference, and narrowly normalize only Google's exact `[null]` clean response. Version 0.7.3 retains those controls and adds the immutable collection handoff. Remote workflow controls remain unexecuted until GitHub allocates a job, so deployment stays blocked.

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

The static site and required policy pages are live over HTTPS at `remedialhq.com`. The seven private Cloud Run services remain Ready, private, manually held at zero instances, and pinned to the previously deployed v0.6.1 image. The v0.7.0 through v0.7.3 candidates have not replaced that runtime. Live collection and publication remain disabled. Version 0.7.3 durably binds collected snapshot bytes to reconciliation, but live claim extraction is intentionally unimplemented and stops at `HOLD`; compile, gate, and measurement still use seed data in offline mode. The deployed system is a dormant control plane and controlled test harness, not a claim of autonomous production operation. Paid-service terms version `creator-desk-v1` states the standard pilot scope, Stripe Payments processor role, cancellation, and full-refund-only policy. Stripe Managed Payments is disabled for this service. No public Payment Link is included. The owner reports the private checkout controls and test-mode payment lifecycle complete. The link remains private and may be sent only after fit, scope, written acceptance, slot reconciliation, and any transaction-specific legal or tax checks are complete.
