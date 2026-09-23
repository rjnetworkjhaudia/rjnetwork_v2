# RJ NETWORK V2.5

Billing & Payment System built on the V2.4 Customer Portal + V2.3 Admin Dashboard.

## Main files

- `customer.html` — customer login, account, invoices, payment history and payment submission.
- `billing.html` — admin billing/invoice/payment verification.
- `admin.html` — existing admin dashboard with Billing shortcut.
- `worker/src/index.js` — V2.5 API endpoints.
- `worker/V2.5-MIGRATION.sql` — migration for an existing V2.4 D1 database.
- `worker/schema.sql` — fresh-install schema including V2.5 tables.
- `V2.5-BILLING-PAYMENT.md` — deployment and operational notes.

## Payment workflow

Customer submits a payment -> `pending` -> admin verifies -> `approved` or `rejected`.

Approved payments accumulate against the invoice. When the approved total reaches the invoice amount, the invoice becomes `paid`.

Automatic bKash transaction verification is intentionally not included in V2.5.
