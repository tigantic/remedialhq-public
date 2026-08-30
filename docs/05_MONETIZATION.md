# Monetization System

## First-dollar lane: paid research before audience scale

The near-term commercial test is the **Creator Signal Desk**, a manually delivered 14-day founding pilot for independent gaming and entertainment creators. Five slots are offered at $99 each. A pilot includes a source-linked change brief, three content angles, safe claim wording, an unresolved-claim list, and one custom rumor check.

This is an untested offer and a demand-validation experiment-not recurring revenue, a forecast, or a promise of content performance. The operating sequence is defined in `ops/FIRST_DOLLAR_PLAYBOOK.md`.

### Initial validation assumptions

| Funnel or cost input | Assumption |
|---|---:|
| Personalized prospects | 50 |
| Reply rate | 20% |
| Sample requests from replies | 50% |
| Purchases from sample requests | 40% |
| Founding pilot price | $99 |
| Refund rate | 5% |
| Payment fee | 2.9% + $0.30 per charge |
| Outreach time | 8 minutes per prospect |
| Sample time | 0.5 hour per request |
| Fulfillment time | 3 hours per non-refunded pilot |
| Owner-hour cost | $35 |

The model therefore expects two purchases and $198 booked revenue from 50 prospects. It also counts outreach, samples, fulfillment, refunds, fees, and owner time. At the initial assumptions the test produces positive cash before owner labor but negative economic contribution after owner labor; that is a deliberate learning cost, not a scalable pricing claim. Replace every conversion and time assumption with observed data after the first cohort.

## Later-stage revenue architecture

These lanes require qualified audience, inventory, eligibility, or product demand that does not yet exist. They are strategic options, not current revenue.

### 1. Long-form video advertising
Technical explainers, ledger briefings, myth adjudication, and launch utility produce qualified watch hours and returning viewers.

### 2. Vertical video
Primarily audience acquisition; direct platform revenue is additive. Each vertical maps to a canonical page, long-form video, or newsletter reason.

### 3. Search and display
Post-launch utility pages-settings, mechanics, locations, missions, vehicles, weapons, collectibles, and updates-form the durable layer.

### 4. Affiliate commerce
Relevant consoles, storage, controllers, headsets, displays, game editions, and licensed merchandise. Recommendations remain evidence-independent and clearly disclosed.

### 5. Sponsorship
Sell defined franchises rather than generic mentions:

- Mechanics Lab;
- weekly Ledger;
- Launch Utility;
- newsletter presenting partner;
- searchable tool sponsor.

Sponsors receive placement, not authority over claim state.

### 6. Owned audience
A concise weekly state-change briefing creates portable audience value.

### 7. Data products
Once the graph is dense enough: public claim API, creator research feeds, change alerts, embeddable evidence cards, and cross-release intelligence.

## Later-stage twelve-month sensitivity cases

These cases show how later-stage economics react to large audience inputs. They are **not forecasts or guarantees**, and they are not evidence that ReMediaLHQ currently has the audience, platform eligibility, sponsor demand, affiliate approval, ad inventory, or conversion rates shown.

| Scenario | Long-form | Shorts | Web | Affiliate | Sponsors | Newsletter | Gross |
|---|---:|---:|---:|---:|---:|---:|---:|
| Base | $9,000 | $1,200 | $24,000 | $16,500 | $12,000 | $6,000 | **$68,700** |
| Traction | $60,000 | $8,000 | $180,000 | $128,000 | $120,000 | $48,000 | **$544,000** |
| Breakout | $250,000 | $30,000 | $840,000 | $630,000 | $500,000 | $180,000 | **$2,430,000** |

First-dollar and audience assumptions live in `config/revenue.json`; recalculate with `python scripts/revenue_model.py`. Generated outputs are written to `artifacts/revenue/`.

## Allocation function

```text
expected contribution =
    expected views × effective RPM
  + affiliate sessions × EPC
  + sponsor inventory value
  + owned-audience value
  - generation cost
  - distribution cost
  - expected rights loss
  - expected correction cost
```

The optimizer allocates production slots subject to evidence, originality, risk, and channel-diversity constraints.

## Capital posture

Keep costs variable until paid demand exists. Spend first on a working business identity, a public proof sample, compliant outreach, a tested payment path, source quality, and delivery speed. Defer autonomous cloud publishing and large audience-acquisition spend until the pilot decision gates support further investment. Never buy artificial views.
