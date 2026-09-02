# IP and Platform Policy

## Commercial asset rule

Rockstar’s public support policy, last updated January 10, 2025, says Take-Two generally does not object to non-commercial fan use, defines non-commercial as not making money through posted game footage or using it to promote a product or service, reserves takedown rights, and bars pre-release leaked footage. This business therefore does not interpret public availability as commercial permission.

Default pre-launch output uses:

- original typography and vector graphics;
- original charts, diagrams, timelines, databases, and motion graphics;
- original or commercially licensed music and voice;
- factual descriptions and attributable commentary;
- source links rather than copied galleries;
- no official logo in the brand identity;
- no implication of affiliation or endorsement.

## Asset states

| State | Monetized use |
|---|---|
| `OWNED` | Allowed within owner policy |
| `ORIGINAL_GENERATED` | Allowed after originality and safety checks |
| `LICENSED_COMMERCIAL` | Allowed within recorded scope |
| `PUBLIC_DOMAIN` | Allowed with provenance |
| `EDITORIAL_REVIEW_REQUIRED` | Hold |
| `NONCOMMERCIAL_ONLY` | Block |
| `UNKNOWN` | Hold |
| `PROHIBITED_LEAK` | Reject and quarantine |

Fair use is a fact-specific doctrine, not a pipeline default. The engine never marks an asset commercially usable merely because a draft is educational, critical, or transformative.

## YouTube

- Original commentary and meaningful editorial value are mandatory.
- Repetitive, mass-produced, generic, templated, or minimally differentiated output is a monetization risk.
- Automated tools may assist production, but each final item must preserve a distinct narrative, original analysis, or educational value.
- The publisher records title, description, tags, disclosure state, thumbnail, category, claims, asset lineage, and a deterministic package identity.
- Tests may change packaging, never underlying facts.
- Current full-ad qualification is 1,000 subscribers plus either 4,000 qualified public watch hours in 12 months or 10 million qualified public Shorts views in 90 days.
- YouTube has announced that new applicants will need 8,000 qualified watch hours or 20 million qualified Shorts views beginning February 1, 2027; existing YPP members are not displaced by that threshold change.
- Uploads through an unverified YouTube Data API project are restricted to private viewing. The adapter therefore defaults to private and requires an explicit public-publication authority for `unlisted` or `public` status.

## TikTok

- Creator-reward strategy favors original, high-quality utility rather than cross-posted watermark packages.
- Direct posting requires a registered application, approved `video.publish` scope, and authorization from the target user.
- Unaudited Direct Post clients are restricted to `SELF_ONLY` visibility and a small user cap; public automation therefore remains disabled until audit completion.
- TikTok’s developer guidance says a Direct Post client cannot merely be an internal utility for accounts managed by the developer or its team. It must serve an eligible product use case, display the current creator identity and controls, preview the content, and obtain express user consent for each upload.
- Therefore the default TikTok route is **Upload-to-TikTok draft plus owner review**, or private `SELF_ONLY` integration testing. Unattended public Direct Post is capability-locked unless the deployed product and audit actually satisfy TikTok’s intended-use and consent requirements.
- TikTok’s current sharing guidance prohibits unwanted promotional branding and watermarks in content submitted through an integration. The renderer maintains a TikTok-specific clean export rather than blindly reposting branded files.
- Until those conditions are met, the adapter never simulates public success.

## Search

- No scaled pages whose primary purpose is ranking rather than helping.
- Every page must resolve a discrete question, expose sources, and add original structure or analysis.
- Programmatic pages require sufficient unique data and internal relationships.
- Thin tag/filter pages remain `noindex`.

## Affiliate and sponsorship disclosure

Commercial relationships are represented in content metadata. Required disclosures render conspicuously near the relevant recommendation or endorsement, not only in a footer.

## Advertiser sensitivity

The source game may contain mature content. Thumbnails, hooks, titles, and descriptions avoid gratuitous sexual imagery, gore, slurs, or shock framing. Accurate discussion does not require maximizing advertiser risk.

## Independence notice

> Independent editorial coverage. Not affiliated with or endorsed by Rockstar Games or Take-Two Interactive.

## Primary policy authorities

The release evidence snapshot records the official Rockstar copyright policy, YouTube monetization and Data API policies, and TikTok Content Posting API requirements in `data/sources/seed_sources.jsonl`. Retrieval dates and source identities remain bound to the claim ledger rather than silently overwritten.
