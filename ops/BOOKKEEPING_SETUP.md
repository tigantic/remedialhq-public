# ReMediaLHQ Bookkeeping Setup

## Status and boundary

RMH-093 is initialized as an owner-only local workspace under `local-private/bookkeeping/`. That directory is ignored by Git and excluded from every distributable release. This document records the reproducible operating structure without publishing transactions, customer data, provider identifiers, bank data, or tax records.

The setup does not choose cash or accrual accounting, assert a tax registration, determine deductibility, or replace qualified accounting and tax advice.

## Working records

| Record | Purpose | Required control |
| --- | --- | --- |
| Chart of accounts | Stable classification of assets, liabilities, equity, income, contra-income, and expenses | Never reuse an account code for a different purpose |
| Double-entry journal | Line-level record of actual business transactions | Debits and credits must balance for every journal entry |
| Stripe reconciliation | Match charges, refunds, disputes, fees, payouts, and bank deposits | Use provider reports and actual values |
| Source-document register | Bind each entry to a receipt, invoice, payout report, or other evidence | Store only an encrypted reference and SHA-256 |
| Monthly close register | Record reconciliation, review, exceptions, and close status | Do not close with an unresolved variance |

## Initial chart design

The working chart includes:

- operating cash, Stripe clearing, receivables, and prepaid expenses;
- payables, sales tax payable, customer refunds payable, and deferred revenue;
- owner contributions and draws;
- separate revenue accounts for Creator Signal Desk, sponsorship, affiliate, advertising, and newsletter activity;
- sales refunds as contra-income;
- separate payment-processing and dispute-fee accounts; and
- software, cloud, domain, marketing, insurance, professional, equipment, travel, bank, and filing expenses.

## Stripe recording pattern

Use actual provider reports. The following is a structure, not a substitute for the owner-selected accounting method:

1. Record the gross customer charge to Stripe clearing and the correct revenue or deferred-revenue account.
2. Record any collected tax to sales tax payable, never to revenue.
3. Record the actual processing fee against Stripe clearing.
4. Record refunds to sales refunds and allowances, with any retained processor fee recorded separately.
5. Record the payout from Stripe clearing to operating cash.
6. Reconcile the expected payout to the actual bank deposit and investigate any nonzero variance.

## Monthly close

For every active month:

1. Verify every journal entry balances.
2. Reconcile the financial account and Stripe clearing.
3. Match every material entry to a hashed source document.
4. Review revenue, refunds, disputes, fees, and owner transactions.
5. Review tax and filing obligations with the correct jurisdiction and adviser context.
6. Record and resolve exceptions before marking the month closed.

## First-dollar gate

The workspace is ready to receive actual records. The owner reports the base Stripe seller, payout, support, address, tax, receipt, statement, and test-mode lifecycle controls complete. Every live order still requires fit and scope confirmation, written acceptance, founding-slot reconciliation, transaction-specific legal and tax checks, payment evidence, and ledger recording.
