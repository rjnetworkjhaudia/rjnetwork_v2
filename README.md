# RJ NETWORK V2.6

Automated Monthly Billing + Payment Reconciliation.

V2.6 is cumulative from V2.5 and includes:
- Customer Portal
- Customer/Ticket database architecture
- Admin Dashboard
- Billing & Payment
- Automated monthly invoice generation
- Automatic overdue status handling
- Internal payment/invoice reconciliation
- Billing run audit history
- Manual billing-cycle trigger

## Frontend
GitHub Pages can host the HTML/CSS/JS files.

## Backend
Cloudflare Worker + D1 are required for real customer, ticket and billing data.

## V2.5 → V2.6 migration
For an existing V2.5 D1 database:

```bash
npx wrangler d1 execute rj-network --remote --file=worker/V2.6-MIGRATION.sql
```

## Worker deployment

```bash
cd worker
npx wrangler deploy
```

The Worker cron is configured for daily 02:15 UTC.

See `V2.6-AUTOMATED-BILLING.md` for the full deployment and behavior notes.
