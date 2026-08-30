# Threat Model and Experiments

## Primary threats and controls

**Rights contamination:** allowlists, immutable source hashes, leak classifier, asset registry, fail-closed rights gate.

**Hallucinated certainty:** claim IDs, state-constrained wording, sentence alignment, title-strength gate.

**Content-farm collapse:** semantic-similarity limits, utility score, format diversity, contribution margin after correction/risk cost.

**Prompt injection:** source text is data, never instruction; isolated schema extraction; secretless verifier.

**Account compromise:** least privilege, Secret Manager, per-platform identity, rotation, anomaly detection, circuit breakers.

**Metric poisoning:** fraud flags, source-weighted analytics, bounded updates, holdout experiments.

**Sponsor capture:** sponsor metadata is separate from claims; sponsor receives no evidence authority.

**Brand confusion:** original identity, no official logo/trade dress, visible independence notice, trademark clearance.

## Experiment contract

Every experiment contains:

- immutable hypothesis ID;
- exactly one primary variable;
- eligible population;
- control/treatment;
- primary metric and guardrails;
- minimum sample;
- stop-loss;
- result and decision.

Fact state cannot vary across treatments.

## Initial experiments

1. Forensic title vs direct-number title.
2. Claim-ladder thumbnail vs single proof card.
3. 60–75 second vs 90–120 second vertical.
4. Narrated diagram vs kinetic typography.
5. Answer-first article vs narrative lead.
6. Newsletter CTA after first answer vs page end.
7. Weekly consolidated ledger vs rapid individual updates.

Retain a 10% derivative-expansion holdout to estimate incremental value.
