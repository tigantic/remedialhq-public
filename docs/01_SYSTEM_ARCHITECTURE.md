# System Architecture

## Logical pipeline

```mermaid
flowchart LR
    A[Approved public sources] --> B[Collector]
    B --> C[Quarantine + immutable snapshot]
    C --> D[Extractor]
    D --> E[Claim reconciler]
    E --> F[(Hash-chained claim ledger)]
    F --> G[(Knowledge graph)]
    G --> H[Opportunity engine]
    M[Demand + trend telemetry] --> H
    H --> I[Content compiler]
    I --> J[Evidence / rights / originality / disclosure gates]
    J -->|PASS| K[Original renderer]
    J -->|HOLD| Q[Quarantine queue]
    K --> L[Platform adapters]
    L --> N[YouTube / site / social / newsletter]
    N --> O[Performance + revenue telemetry]
    O --> P[Experiment allocator]
    P --> H
    O --> R[Circuit breakers]
    R --> L
```

## Separation of authority

| Worker | Authority | Forbidden action |
|---|---|---|
| Scout | Fetch allowlisted sources and trend telemetry | Publish or infer facts |
| Verifier | Extract, reconcile, and classify claims | Create titles or media |
| Cartographer | Maintain entities, relationships, and timelines | Upgrade claim certainty |
| Planner | Rank opportunities and assign formats | Override policy gates |
| Compiler | Draft only from claim IDs | Introduce unsourced facts |
| Rights controller | Classify assets and license scope | Assume fair use or implied permission |
| Publisher | Upload passed packages with scoped tokens | Edit content or bypass a hold |
| Analyst | Read performance and propose experiments | Delete adverse results |
| Auditor | Verify hashes, lineage, and corrections | Modify records |

## Core records

### Source

Canonical locator; publisher; tier; publication/retrieval timestamps; immutable hash; rights posture; prohibited/leak flag; snapshot location.

### Claim

Immutable ID; normalized proposition; state; supporting and contradicting source IDs; confidence; entities; timestamps; public wording boundary; supersession relationships.

### Content package

Opportunity ID; claim IDs; platform; title/body/script; disclosures; asset manifest; originality telemetry; gate report; publication identity; experiment assignment.

## Reference Google Cloud deployment

```mermaid
flowchart TB
    CS[Cloud Scheduler] --> PS[Phase-isolated Pub/Sub topics]
    PS --> CRS[Authenticated Cloud Run services]
    CRS --> PS
    CRS --> GCS[(Cloud Storage)]
    CRS --> IDX[(Optional derived graph index)]
    CRS --> BQ[(BigQuery)]
    SM[Secret Manager] --> CRS
    AR[Artifact Registry] --> CRS
    CRS --> YT[YouTube Data API]
    CRS --> WEB[Canonical site]
    CRS --> TIK[TikTok after approval]
    CRS --> META[Meta after approval]
    LOG[Logging + Monitoring] --> CB[Circuit breakers]
    CB --> CRS
```

Recommended topics:

- `source.discovered`
- `source.snapshotted`
- `claim.pending`
- `claim.changed`
- `opportunity.ready`
- `content.compiled`
- `content.held`
- `content.passed`
- `publish.requested`
- `publish.completed`
- `metrics.received`
- `correction.required`

## Idempotency and interrupted delivery

Every phase receives an immutable event ID. Child event IDs are derived deterministically from the parent event and next phase. In the Cloud Run deployment, a private, versioned Cloud Storage state bucket stores generation-matched event records with processing and dispatch leases. The authoritative event state does not depend on a separately provisioned database.

The state machine has four operative outcomes:

- `PROCESS`: this worker owns a bounded processing lease;
- `DISPATCH`: a committed result is ready to send to the next phase;
- `RETURN`: the event already completed and its canonical response is returned;
- `BUSY`: another unexpired lease owns the event, so Pub/Sub is told to retry.

A crash before result commit permits lease reclamation. A crash after result commit permits dispatch resumption. Pub/Sub transport remains at-least-once, so the deterministic child event ID is also resolved by the downstream phase. Live platform adapters require an additional platform-publication identity check before external side effects are enabled.

## Scaling posture

The first 82 days do not require Kubernetes. Authenticated Cloud Run services plus phase-isolated Pub/Sub delivery are sufficient until measured event latency or throughput proves otherwise.
