# RJ NETWORK V2.2 — Customer + Ticket Database API

Cloudflare Worker + D1 implementation for the V2.2 foundation.

## What this adds

- Customer master table with unique customer code.
- Public customer lookup using **customer code + phone**.
- Website ticket creation stored in D1.
- Ticket lookup using **ticket code + phone**.
- Admin-only customer CRUD endpoints.
- Admin-only ticket list/update endpoints.
- Ticket event/audit history.
- CORS allowlist.
- Basic request validation and body-size limits.
- Optional Cloudflare Turnstile verification.
- Optional Telegram notification using Worker secrets.

## Deploy

1. Create a Cloudflare D1 database named `rj-network`.
2. Put its ID in `wrangler.toml`.
3. Run:

```bash
wrangler d1 execute rj-network --remote --file=schema.sql
wrangler secret put ADMIN_API_KEY
wrangler deploy
```

Optional:

```bash
wrangler secret put TURNSTILE_SECRET_KEY
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put TELEGRAM_CHAT_ID
```

## Security model

- Never put `ADMIN_API_KEY` in public website source.
- Admin endpoints require `Authorization: Bearer <ADMIN_API_KEY>`.
- Customer/ticket public lookups require both an identifier and phone number.
- Configure `ALLOWED_ORIGINS` to the exact production website origin.
- Turnstile should be enabled before opening ticket creation to unrestricted public traffic.
- Add Cloudflare WAF/rate limiting rules for `/api/tickets` in production.

## Endpoints

Public:
- `GET /api/health`
- `POST /api/tickets`
- `POST /api/customer/lookup`
- `POST /api/ticket/lookup`

Admin:
- `GET /api/admin/customers`
- `POST /api/admin/customers`
- `PATCH /api/admin/customers/:id`
- `GET /api/admin/tickets`
- `PATCH /api/admin/tickets/:id`
- `GET /api/admin/tickets/:id/events`

Example customer lookup body:

```json
{"customerCode":"RJ1001","phone":"017XXXXXXXX"}
```

Example ticket creation body:

```json
{
  "customerCode":"RJ1001",
  "name":"মোঃ ...",
  "phone":"017XXXXXXXX",
  "address":"ঝাউদিয়া, কুষ্টিয়া",
  "requestType":"service_problem",
  "subject":"ইন্টারনেট ধীর",
  "description":"রাতে স্পিড কমে যাচ্ছে",
  "requestedPackage":null,
  "turnstileToken":"..."
}
```
