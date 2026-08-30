# Stripe Test Evidence Runbook

## Purpose and authority boundary

This runbook captures a redacted, test-only record of the Creator Signal Desk payment
exercise. The local gate validates document shape, price, flow completeness, redaction, and
internal consistency. It does not connect to Stripe, inspect an account, change payment
settings, write to the pilot ledger, or update the execution plan.

A passing report cannot mark RMH-106 complete. That task also requires owner review of the
captured evidence, resolution of the RMH-094 account-setting dependency, and separate
verification of the private live offer link. Never record a Stripe test payment as revenue.

## Fixed test contract

The gate accepts only this contract:

- Provider: `STRIPE`
- Mode: `TEST`
- Stripe `livemode`: `false`
- Currency: `USD`
- One-time amount: `9900` cents, exactly USD 99.00
- Payment type: `ONE_TIME`
- Evidence classifications: `SYNTHETIC` or `OWNER_CAPTURED`
- Required flows: successful checkout, abandonment, receipt, cancellation interpretation,
  and full refund

Synthetic evidence is useful only for testing the local validator. It is not proof that an
owner performed a Stripe test. Owner-captured evidence identifies a redacted observation,
but the local gate still has no authority to complete RMH-106.

## Private workspace rules

Perform the provider exercise in Stripe test mode. Keep all raw screenshots and provider
exports outside Git and outside the public release. Create a redacted copy of each evidence
artifact before hashing it.

The JSON file must not contain:

- secret, restricted, publishable, webhook, OAuth, or API credentials;
- card numbers, security codes, expiry values, or payment-method details;
- customer or owner names, email addresses, phone numbers, or postal addresses;
- checkout, receipt, dashboard, or artifact URLs;
- raw Stripe object IDs or raw Stripe event payloads;
- live-mode evidence;
- free-text notes, metadata, or unrecognized fields.

Use a new local opaque reference for every evidence item. An opaque reference is a label
minted for this report, not a transformed or copied Stripe object ID. The required forms are:

```text
evidence_ref: evd_ followed by 32 lowercase hexadecimal characters
provider_ref: ref_ followed by 32 lowercase hexadecimal characters
correlation_ref: cor_ followed by 32 lowercase hexadecimal characters
test_run_ref: run_ followed by 32 lowercase hexadecimal characters
artifact_sha256: 64 lowercase hexadecimal characters
```

The `test_run_ref` binds all five records to one test exercise. The `correlation_ref` binds
the successful checkout, receipt, cancellation interpretation, and full refund to one test
payment chain. The abandonment record must use a different correlation reference because it
represents a separate checkout. The `provider_ref` is a unique local label for one provider
observation. Do not retain a lookup table in the repository. The `artifact_sha256` is the
digest of the redacted evidence artifact, not the raw capture.

## Provider test sequence

1. Confirm the Stripe dashboard visibly indicates test mode before creating any object.
2. Configure or select a one-time USD 99.00 test offer. Do not reuse a live Payment Link.
3. Run one successful checkout with Stripe-provided test data. Confirm the completed test
   payment is exactly USD 99.00 and capture a redacted artifact.
4. Start a separate test checkout, leave without submitting payment, and allow the session
   to become abandoned or expired. Confirm no payment was created. Capture a redacted
   artifact.
5. Confirm the successful test payment produced a USD 99.00 receipt in the expected test
   channel. Remove all recipient and payment-method data before saving the evidence copy.
6. Record the cancellation interpretation exactly: a service cancellation request does not
   cancel a completed Stripe payment. A completed payment changes only when the separate
   full-refund action succeeds.
7. Refund the successful test payment in full. Confirm the successful refund is exactly USD
   99.00, not a partial refund, and capture a redacted artifact.
8. Hash each redacted artifact with SHA-256 and build the JSON document below. Use
   timezone-aware RFC 3339 timestamps copied from the observation, with `Z` or a numeric
   timezone offset.
9. Run the local gate and retain only the redacted input plus its normalized report and
   digest in the owner-controlled evidence store.

The successful checkout must occur no later than its receipt, the cancellation
interpretation must follow the receipt, and the full refund must follow the cancellation
interpretation. The abandonment flow is a separate checkout and may be observed at any
point.

## Strict JSON template

The example below is synthetic. Its references, hashes, and timestamps are placeholders,
not completed evidence.

```json
{
  "schema_version": "remedialhq.payment-test-evidence.v1",
  "provider": "STRIPE",
  "mode": "TEST",
  "livemode": false,
  "currency": "USD",
  "unit_amount_cents": 9900,
  "payment_type": "ONE_TIME",
  "test_run_ref": "run_00000000000000000000000000000001",
  "evidence": [
    {
      "flow": "SUCCESSFUL_CHECKOUT",
      "classification": "SYNTHETIC",
      "observed_at": "2026-08-29T14:00:00Z",
      "evidence_ref": "evd_00000000000000000000000000000001",
      "provider_ref": "ref_00000000000000000000000000000011",
      "correlation_ref": "cor_00000000000000000000000000000021",
      "artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000101",
      "outcome": "PAYMENT_SUCCEEDED",
      "charged_amount_cents": 9900,
      "payment_method_redacted": true
    },
    {
      "flow": "ABANDONMENT",
      "classification": "SYNTHETIC",
      "observed_at": "2026-08-29T13:00:00-04:00",
      "evidence_ref": "evd_00000000000000000000000000000002",
      "provider_ref": "ref_00000000000000000000000000000012",
      "correlation_ref": "cor_00000000000000000000000000000022",
      "artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000102",
      "outcome": "CHECKOUT_ABANDONED_NO_PAYMENT",
      "payment_created": false
    },
    {
      "flow": "RECEIPT",
      "classification": "SYNTHETIC",
      "observed_at": "2026-08-29T14:01:00Z",
      "evidence_ref": "evd_00000000000000000000000000000003",
      "provider_ref": "ref_00000000000000000000000000000013",
      "correlation_ref": "cor_00000000000000000000000000000021",
      "artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000103",
      "outcome": "RECEIPT_ISSUED",
      "receipt_amount_cents": 9900,
      "recipient_redacted": true
    },
    {
      "flow": "CANCELLATION_INTERPRETATION",
      "classification": "SYNTHETIC",
      "observed_at": "2026-08-29T14:02:00Z",
      "evidence_ref": "evd_00000000000000000000000000000004",
      "provider_ref": "ref_00000000000000000000000000000014",
      "correlation_ref": "cor_00000000000000000000000000000021",
      "artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000104",
      "outcome": "CANCELLATION_REQUEST_RECORDED",
      "interpretation": "A_CANCELLATION_REQUEST_DOES_NOT_CANCEL_A_COMPLETED_STRIPE_PAYMENT",
      "required_follow_up": "FULL_REFUND"
    },
    {
      "flow": "FULL_REFUND",
      "classification": "SYNTHETIC",
      "observed_at": "2026-08-29T14:03:00Z",
      "evidence_ref": "evd_00000000000000000000000000000005",
      "provider_ref": "ref_00000000000000000000000000000015",
      "correlation_ref": "cor_00000000000000000000000000000021",
      "artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000105",
      "outcome": "REFUND_SUCCEEDED",
      "refunded_amount_cents": 9900
    }
  ]
}
```

Replace `SYNTHETIC` with `OWNER_CAPTURED` only for a flow personally observed in Stripe test
mode and bound to its redacted artifact. Mixed classification is allowed and is counted in
the aggregate report.

## Run the local gate

From the repository root, with the evidence file stored outside the public tree:

```text
PYTHONPATH=src python -m remedialhq.payment_tests /private/path/payment-test-evidence.json --pretty
```

Success exits with status `0` and prints an envelope containing:

- a normalized aggregate report with all five flows in canonical order;
- counts for `SYNTHETIC` and `OWNER_CAPTURED` evidence;
- first and last UTC observation timestamps;
- explicit false values for live-mode and raw-payload acceptance;
- `rmh_106_may_be_marked_complete: false`;
- one lowercase 64-character SHA-256 digest covering the normalized report.

Rejection exits with status `2`. Rejected content is never printed. Correct the source
evidence instead of weakening the gate.

## Owner review checklist

- [ ] The Stripe dashboard was in test mode for every captured action.
- [ ] The checkout charged exactly USD 99.00 once.
- [ ] The abandoned checkout created no payment.
- [ ] The receipt showed exactly USD 99.00 and the stored copy is redacted.
- [ ] The cancellation interpretation is explicit and was followed by a separate refund.
- [ ] The refund succeeded for the full USD 99.00.
- [ ] Every timestamp includes a timezone.
- [ ] One test-run reference binds all five records.
- [ ] One payment correlation reference binds checkout, receipt, interpretation, and refund.
- [ ] The abandonment checkout uses a separate correlation reference.
- [ ] Every evidence artifact hash is unique and was computed after redaction.
- [ ] No secret, card data, personal data, URL, raw object ID, or provider payload is stored.
- [ ] No test payment was written to a revenue or pilot ledger.
- [ ] The passing local report is treated as evidence input, not as RMH-106 completion.
