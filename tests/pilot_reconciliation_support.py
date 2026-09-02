from __future__ import annotations

from remedialhq.pilot_reconciliation import (
    PilotSlotReconciliation,
    PriorPilotLedgerSnapshot,
    build_pilot_slot_reconciliation,
)


def reconciliation_document(
    prior: PriorPilotLedgerSnapshot | None = None,
    *,
    provider_purchase_hashes: tuple[str, ...] | None = None,
) -> dict[str, object]:
    if provider_purchase_hashes is None:
        provider_hashes = list(() if prior is None else prior.provider_purchase_sha256s)
        required_count = 0 if prior is None else prior.lifetime_consumed_slots
        candidate = 9000
        while len(provider_hashes) < required_count:
            digest = f"{candidate:064x}"
            if digest not in provider_hashes:
                provider_hashes.append(digest)
            candidate += 1
    else:
        provider_hashes = list(provider_purchase_hashes)
    return {
        "schema_version": "remedialhq.pilot-slot-reconciliation.v1",
        "reconciliation_ref": "rec_00000000000000000000000000000001",
        "reconciled_at": "2026-08-30T12:00:00Z",
        "scope": "ALL_LIFETIME_FOUNDING_PURCHASES",
        "checks": {
            "all_known_ledgers_reviewed": True,
            "payment_provider_history_reviewed": True,
            "single_authoritative_successor_designated": True,
        },
        "payment_provider": {
            "provider": "STRIPE",
            "mode": "LIVE",
            "observed_at": "2026-08-30T11:59:00Z",
            "history_scope": "ALL_AVAILABLE_ACCOUNT_HISTORY",
            "history_evidence_sha256": f"{8000:064x}",
            "provider_purchase_sha256s": provider_hashes,
        },
        "prior_ledger": None if prior is None else prior.to_dict(),
        "lifetime_consumed_slots": len(provider_hashes),
    }


def reconciliation_evidence(
    prior: PriorPilotLedgerSnapshot | None = None,
    *,
    provider_purchase_hashes: tuple[str, ...] | None = None,
) -> PilotSlotReconciliation:
    return build_pilot_slot_reconciliation(
        reconciliation_document(
            prior,
            provider_purchase_hashes=provider_purchase_hashes,
        ),
        expected_prior_ledger=prior,
    )
