# ReMediaLHQ Google setup runbook

This runbook covers the bounded automation for RMH-053, RMH-055, and RMH-056.
It does not create Google Analytics or Google Tag Manager accounts, accept provider
terms, configure the Google Auth Platform application, or grant OAuth consent.

## Fixed targets

The command fixes the public product targets below and requires the owner-private
Cloud project identifier as an explicit input:

```text
Google Cloud project: owner-supplied `--project-id` value kept outside Git
Domain: remedialhq.com
Search Console property: sc-domain:remedialhq.com
Sitemap: https://remedialhq.com/sitemap.xml
Analytics account: ReMediaLHQ
GA4 property: ReMediaLHQ Production
GA4 web stream: ReMediaLHQ Website
GA4 default URI: https://remedialhq.com
Tag Manager account: ReMediaLHQ
Tag Manager container: ReMediaLHQ Website
Tag Manager usage context: web
```

## Safety model

- Running the command without a live flag only prints an offline plan. It does not
  load a credential or use the network.
- `--live-readback` enables authenticated inspection only.
- `--apply-live` is the only flag that enables mutations.
- The command inspects all three product surfaces before the first mutation.
- An absent or ambiguous exact-name Analytics or Tag Manager account blocks every
  mutation. Account creation and terms acceptance remain manual owner actions.
- Existing exact resources are read back and skipped. A second successful run makes
  no mutation.
- A conflicting exact name, URI, resource type, or duplicate match fails closed.
- The credential is loaded from an explicit owner-private file and is never written.
- Evidence contains selected status fields and non-secret resource identifiers only.
  Raw API responses, OAuth material, and the owner email are not retained.
- Live evidence must be outside the repository in a real owner-controlled `0700`
  directory. The evidence file is atomically written at `0600`.

## One-time prerequisites

1. Complete the Google Auth Platform application and its desktop client in the
   owner-private Google Cloud project.
2. Manually accept any required Google Analytics and Tag Manager terms and ensure one
   existing account named exactly `ReMediaLHQ` is visible to the owner credential.
3. Obtain owner consent for exactly these scopes:

```text
https://www.googleapis.com/auth/userinfo.email
https://www.googleapis.com/auth/siteverification
https://www.googleapis.com/auth/webmasters
https://www.googleapis.com/auth/analytics.edit
https://www.googleapis.com/auth/tagmanager.edit.containers
```

4. Store the resulting authorized-user credential outside Git at mode `0600`.
5. Create an evidence directory outside Git at mode `0700`.

Set the owner-private project identifier only in the local shell:

```bash
export OWNER_GCP_PROJECT_ID="<owner-private-project-id>"
```

The owner account is validated by a SHA-256 digest so its address is neither committed
nor retained in evidence. Generate the digest without echoing the address:

```bash
python3 -c 'import getpass,hashlib; value=getpass.getpass("Owner Google email: ").strip().casefold(); print(hashlib.sha256(value.encode()).hexdigest())'
```

## Offline plan

```bash
PYTHONPATH=src python3 -m remedialhq.cli google-setup
```

## Authenticated read-only preflight

```bash
PYTHONPATH=src python3 -m remedialhq.cli google-setup \
  --project-id "$OWNER_GCP_PROJECT_ID" \
  --live-readback \
  --credential /owner-private/google-owner-token.json \
  --owner-account-sha256 OWNER_EMAIL_SHA256 \
  --evidence-output /owner-private/google-setup-readback.json \
  --repository-root .
```

A successful incomplete readback returns `READY`. Missing or ambiguous parent accounts
return `BLOCKED` and make no mutation.

## Explicit bounded apply

Review the readback evidence, then replace `--live-readback` with `--apply-live` and use
a new or existing secure evidence filename:

```bash
PYTHONPATH=src python3 -m remedialhq.cli google-setup \
  --project-id "$OWNER_GCP_PROJECT_ID" \
  --apply-live \
  --credential /owner-private/google-owner-token.json \
  --owner-account-sha256 OWNER_EMAIL_SHA256 \
  --evidence-output /owner-private/google-setup-apply.json \
  --repository-root .
```

The bounded mutation set is limited to:

1. Verify the existing Google DNS token for `remedialhq.com` when the authenticated
   owner is not already verified.
2. Add `sc-domain:remedialhq.com` when absent and require `siteOwner` readback.
3. Submit `https://remedialhq.com/sitemap.xml` when absent.
4. Create `ReMediaLHQ Production` under the one existing exact Analytics account when
   absent.
5. Create the exact `ReMediaLHQ Website` web stream when absent.
6. Create the exact `ReMediaLHQ Website` web container under the one existing exact
   Tag Manager account when absent.

If a provider rejects a call after an earlier mutation succeeded, the command returns
`FAILED_CLOSED`. Rerun the read-only preflight first. The next apply inspects current
state and resumes without recreating confirmed resources.
