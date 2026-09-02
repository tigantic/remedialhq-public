# ReMediaLHQ Newsletter Integration Contract

## Current state

The newsletter integration is disabled. No provider is selected, no public signup or webhook endpoint exists, and the website does not store an email address. The homepage form opens a draft email to the ReMediaLHQ desk.

`config/newsletter_contract.json` is the fail-closed authority record. The integration cannot be activated unless a provider, signup endpoint, webhook endpoint, and approved address-storage boundary are all configured together.

## Signup contract

A future signup request is limited to:

- one syntactically valid email address;
- explicit consent set to true;
- the accepted terms version; and
- the accepted privacy version.

The request body is bounded, extra fields are rejected, and the contract performs no logging or persistence. A live route must not be exposed until the newsletter provider, publication, consent language, secret boundary, and owner approval are recorded under RMH-080 through RMH-083.

## Webhook contract

A future provider webhook must use HMAC-SHA256 over the timestamp and exact request body. The timestamp must fall inside the bounded replay window, the secret must meet the minimum length, and the body must match the exact schema. Only confirmed-subscription and unsubscribe events are accepted.

Webhook records use opaque event, subscriber, and consent references. Email addresses, names, phone numbers, account identifiers, tokens, cookies, IP addresses, free-form notes, and raw provider payloads are rejected. The event ID supports later idempotency enforcement without exposing subscriber identity.

## Activation boundary

The repository contract and tests do not expose a POST route, choose a provider, transmit data, store an address, send a newsletter, or authorize publication. Those actions remain blocked until their recorded prerequisites and owner-controlled settings are complete.
