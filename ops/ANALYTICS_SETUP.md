# ReMediaLHQ Analytics Setup

Create the GA4 account `ReMediaLHQ`, property `ReMediaLHQ Production`, and web stream `https://remedialhq.com`. Create the Google Tag Manager account `ReMediaLHQ` and web container `ReMediaLHQ Website`.

Create these conversion events:

```text
newsletter_signup
youtube_click
affiliate_click
sponsor_inquiry
article_complete
return_visitor
guide_download
```

Connect GA4 to Search Console and BigQuery. Record the GA4 property ID, measurement ID, stream ID, and GTM container ID in the owner-private account inventory, outside the public package.

## Repository event contract

`site/analytics.js` defines the seven event names above and ships disabled. It records nothing unless all three activation conditions are present: an explicit enable switch, granted consent, and an explicitly configured event sink. It rejects identifying parameter names and unbounded values.

The current signal-brief form opens a draft email and is not a completed signup. It must not emit `newsletter_signup`. That event is accepted only after a future newsletter provider returns a bounded confirmation reference. No GA4 or Tag Manager identifier is embedded, no analytics library is loaded, and no data is transmitted by the current repository state.

Before activation:

1. Create and verify the owner-controlled GA4 property, web stream, and Tag Manager container.
2. Confirm the public consent experience and the applicable policy text.
3. Configure a reviewed sink without allowing raw email addresses, names, account identifiers, tokens, or free-form text.
4. Test every event in a non-production property and verify that the mailto form still cannot count as a signup.
5. Record the owner-private property, stream, measurement, and container identifiers outside the public package.

The guarded repository command for steps 1 and 5 is documented in
[`ops/GOOGLE_SETUP_RUNBOOK.md`](GOOGLE_SETUP_RUNBOOK.md). It is offline by default,
supports an explicitly enabled read-only preflight, and requires `--apply-live` before
any bounded provider mutation.
