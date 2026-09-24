const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};
const MAX_BODY = 18 * 1024;
const PHONE_RE = /^(?:01\d{9}|8801\d{9}|\+8801\d{9})$/;
const REQUEST_TYPES = new Set(["new_connection", "service_problem", "package_change", "billing", "other"]);
const TICKET_STATUSES = new Set(["open", "in_progress", "waiting_customer", "resolved", "closed"]);
const PRIORITIES = new Set(["low", "normal", "high", "urgent"]);

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extra },
  });
}

function normalizePhone(value) {
  const p = String(value || "").replace(/[\s-]/g, "");
  if (/^01\d{9}$/.test(p)) return p;
  if (/^8801\d{9}$/.test(p)) return `0${p.slice(2)}`;
  if (/^\+8801\d{9}$/.test(p)) return `0${p.slice(3)}`;
  return "";
}

function clean(value, max) {
  return String(value ?? "").trim().slice(0, max);
}


const PBKDF2_ITERATIONS = 120000;
const SESSION_DAYS = 7;

function b64(bytes) {
  let s = "";
  const a = new Uint8Array(bytes);
  for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000));
  return btoa(s);
}

function unb64(value) {
  const s = atob(value);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, saltB64) {
  const salt = saltB64 ? unb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2", salt, iterations:PBKDF2_ITERATIONS, hash:"SHA-256"}, key, 256);
  return { salt: b64(salt), hash: b64(bits) };
}

async function verifyPassword(password, saltB64, expectedHash) {
  if (!saltB64 || !expectedHash) return false;
  const result = await hashPassword(password, saltB64);
  return result.hash === expectedHash;
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 8 && password.length <= 128;
}

function sessionExpiry() {
  return new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
}

async function createCustomerSession(env, customerId) {
  const raw = `${crypto.randomUUID()}-${crypto.randomUUID()}-${crypto.randomUUID()}`;
  const tokenHash = await sha256Hex(raw);
  const expiresAt = sessionExpiry();
  await env.DB.prepare("INSERT INTO customer_sessions (customer_id, token_hash, expires_at) VALUES (?, ?, ?)")
    .bind(customerId, tokenHash, expiresAt).run();
  return { token: raw, expiresAt };
}

async function requireCustomer(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) return { error: json({error:"unauthorized"},401) };
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(`SELECT s.id AS session_id, s.customer_id, s.expires_at, c.customer_code, c.full_name, c.phone, c.address, c.package_name, c.monthly_fee, c.status, c.due_day, c.installed_at
    FROM customer_sessions s JOIN customers c ON c.id=s.customer_id
    WHERE s.token_hash=? AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') LIMIT 1`).bind(tokenHash).first();
  if (!row) return { error: json({error:"session_expired"},401) };
  await env.DB.prepare("UPDATE customer_sessions SET last_used_at=CURRENT_TIMESTAMP WHERE id=?").bind(row.session_id).run();
  return { row };
}

async function customerLogin(request, env) {
  const body = await readJson(request);
  const code = clean(body.customerCode, 32);
  const password = String(body.password || "");
  if (!code || !validPassword(password)) return json({error:"invalid_credentials"},400);
  const customer = await env.DB.prepare("SELECT id, customer_code, full_name, phone, address, package_name, monthly_fee, status, due_day, installed_at, password_hash, password_salt FROM customers WHERE customer_code=? LIMIT 1").bind(code).first();
  if (!customer || !customer.password_hash || customer.status === "closed" || !(await verifyPassword(password, customer.password_salt, customer.password_hash))) return json({error:"invalid_credentials"},401);
  const session = await createCustomerSession(env, customer.id);
  const safe = {...customer}; delete safe.password_hash; delete safe.password_salt;
  return json({ok:true, token:session.token, expiresAt:session.expiresAt, customer:safe});
}

async function customerMe(request, env) {
  const auth = await requireCustomer(request, env); if (auth.error) return auth.error;
  const c = auth.row;
  return json({ok:true, customer:{customer_code:c.customer_code,full_name:c.full_name,phone:c.phone,address:c.address,package_name:c.package_name,monthly_fee:c.monthly_fee,status:c.status,due_day:c.due_day,installed_at:c.installed_at}});
}

async function customerLogout(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (token) await env.DB.prepare("DELETE FROM customer_sessions WHERE token_hash=?").bind(await sha256Hex(token)).run();
  return json({ok:true});
}

async function customerTickets(request, env) {
  const auth = await requireCustomer(request, env); if (auth.error) return auth.error;
  const rows = await env.DB.prepare(`SELECT id,ticket_code,request_type,subject,description,requested_package,status,priority,assigned_to,created_at,updated_at,resolved_at
    FROM tickets WHERE customer_id=? OR (customer_id IS NULL AND customer_phone=?) ORDER BY id DESC LIMIT 100`).bind(auth.row.customer_id, auth.row.phone).all();
  return json({ok:true,tickets:rows.results||[]});
}

async function customerTicketEvents(request, env, id) {
  const auth = await requireCustomer(request, env); if (auth.error) return auth.error;
  const ticket = await env.DB.prepare("SELECT id FROM tickets WHERE id=? AND (customer_id=? OR (customer_id IS NULL AND customer_phone=?)) LIMIT 1").bind(id,auth.row.customer_id,auth.row.phone).first();
  if (!ticket) return json({error:"not_found"},404);
  const rows = await env.DB.prepare("SELECT event_type,old_status,new_status,note,created_at FROM ticket_events WHERE ticket_id=? ORDER BY id DESC").bind(id).all();
  return json({ok:true,events:rows.results||[]});
}

async function adminSetCustomerPassword(request, env, id) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  const body = await readJson(request);
  const password = String(body.password || "");
  if (!validPassword(password)) return json({error:"password_min_8_chars"},400);
  const customer = await env.DB.prepare("SELECT id FROM customers WHERE id=?").bind(id).first();
  if (!customer) return json({error:"not_found"},404);
  const hp = await hashPassword(password);
  await env.DB.prepare("UPDATE customers SET password_hash=?, password_salt=?, password_updated_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(hp.hash,hp.salt,id).run();
  await env.DB.prepare("DELETE FROM customer_sessions WHERE customer_id=?").bind(id).run();
  return json({ok:true});
}

function originAllowed(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map(x => x.trim()).filter(Boolean);
  return !origin || allowed.includes(origin);
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map(x => x.trim()).filter(Boolean);
  return {
    "access-control-allow-origin": origin && allowed.includes(origin) ? origin : (allowed[0] || ""),
    "access-control-allow-methods": "GET,POST,PATCH,OPTIONS",
    "access-control-allow-headers": "Content-Type,Authorization",
    "access-control-max-age": "86400",
    "vary": "Origin",
  };
}

async function readJson(request) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > MAX_BODY) throw new Error("request_too_large");
  const text = await request.text();
  if (text.length > MAX_BODY) throw new Error("request_too_large");
  try { return JSON.parse(text || "{}"); } catch { throw new Error("invalid_json"); }
}

async function requireAdmin(request, env) {
  const expected = String(env.ADMIN_API_KEY || "");
  if (!expected) return json({ error: "admin_not_configured" }, 503);
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token || token !== expected) return json({ error: "unauthorized" }, 401);
  return null;
}

function ticketCode() {
  const d = new Date();
  const stamp = d.toISOString().slice(0,10).replaceAll("-", "");
  const rand = crypto.randomUUID().replaceAll("-", "").slice(0,6).toUpperCase();
  return `RJ-${stamp}-${rand}`;
}

function customerCode() {
  const rand = crypto.randomUUID().replaceAll("-", "").slice(0,8).toUpperCase();
  return `RJ${rand}`;
}

async function verifyTurnstile(token, request, env) {
  if (!env.TURNSTILE_SECRET_KEY) return true;
  if (!token) return false;
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET_KEY);
  form.append("response", token);
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) form.append("remoteip", ip);
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
  const data = await r.json();
  return data.success === true;
}

async function notifyTelegram(env, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text, disable_web_page_preview: true }),
  }).catch(() => {});
}

async function createTicket(request, env) {
  const body = await readJson(request);
  const name = clean(body.name, 80);
  const phone = normalizePhone(body.phone);
  const address = clean(body.address, 300);
  const requestType = clean(body.requestType, 40);
  const subject = clean(body.subject, 120);
  const description = clean(body.description || body.note, 1000);
  const requestedPackage = clean(body.requestedPackage || "", 80) || null;
  const customerCodeValue = clean(body.customerCode || "", 32) || null;

  if (!name || name.length < 2) return json({ error: "invalid_name" }, 400);
  if (!phone || !PHONE_RE.test(phone)) return json({ error: "invalid_phone" }, 400);
  if (!address || address.length < 3) return json({ error: "invalid_address" }, 400);
  if (!REQUEST_TYPES.has(requestType)) return json({ error: "invalid_request_type" }, 400);
  if (!subject || description.length < 3) return json({ error: "invalid_ticket_content" }, 400);
  if (!(await verifyTurnstile(body.turnstileToken, request, env))) return json({ error: "turnstile_failed" }, 403);

  let customer = null;
  if (customerCodeValue) {
    customer = await env.DB.prepare("SELECT id, customer_code, full_name, phone, status FROM customers WHERE customer_code = ? LIMIT 1")
      .bind(customerCodeValue).first();
    if (customer && customer.phone !== phone) customer = null;
  }

  const code = ticketCode();
  const result = await env.DB.prepare(`INSERT INTO tickets
    (ticket_code, customer_id, request_type, subject, description, requested_package, customer_name, customer_phone, customer_address)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(code, customer?.id || null, requestType, subject, description, requestedPackage, name, phone, address)
    .run();

  const ticketId = result.meta.last_row_id;
  await env.DB.prepare("INSERT INTO ticket_events (ticket_id, event_type, new_status, note, actor) VALUES (?, 'created', 'open', ?, 'website')")
    .bind(ticketId, "Ticket created from website").run();

  await notifyTelegram(env, `🎫 RJ NETWORK নতুন Ticket\n${code}\nনাম: ${name}\nমোবাইল: ${phone}\nধরন: ${requestType}\nবিষয়: ${subject}`);
  return json({ ok: true, ticketCode: code, status: "open" }, 201);
}

async function customerLookup(request, env) {
  const body = await readJson(request);
  const code = clean(body.customerCode, 32);
  const phone = normalizePhone(body.phone);
  if (!code || !phone) return json({ error: "invalid_lookup" }, 400);
  const customer = await env.DB.prepare(`SELECT customer_code, full_name, phone, address, package_name, monthly_fee, status, due_day, installed_at, created_at, updated_at
    FROM customers WHERE customer_code = ? AND phone = ? LIMIT 1`).bind(code, phone).first();
  if (!customer) return json({ error: "not_found" }, 404);
  return json({ ok: true, customer });
}

async function ticketLookup(request, env) {
  const body = await readJson(request);
  const code = clean(body.ticketCode, 32);
  const phone = normalizePhone(body.phone);
  if (!code || !phone) return json({ error: "invalid_lookup" }, 400);
  const ticket = await env.DB.prepare(`SELECT ticket_code, request_type, subject, requested_package, status, priority, customer_name, created_at, updated_at, resolved_at
    FROM tickets WHERE ticket_code = ? AND customer_phone = ? LIMIT 1`).bind(code, phone).first();
  if (!ticket) return json({ error: "not_found" }, 404);
  const events = await env.DB.prepare(`SELECT event_type, old_status, new_status, note, created_at FROM ticket_events WHERE ticket_id = (SELECT id FROM tickets WHERE ticket_code = ?) ORDER BY id DESC`).bind(code).all();
  return json({ ok: true, ticket, events: events.results || [] });
}

async function adminCustomers(request, env) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  if (request.method === "GET") {
    const url = new URL(request.url); const q = clean(url.searchParams.get("q"), 80);
    const rows = q
      ? await env.DB.prepare(`SELECT id, customer_code, full_name, phone, address, package_name, monthly_fee, status, due_day, installed_at, created_at, updated_at FROM customers WHERE customer_code LIKE ? OR full_name LIKE ? OR phone LIKE ? ORDER BY id DESC LIMIT 100`).bind(`%${q}%`,`%${q}%`,`%${q}%`).all()
      : await env.DB.prepare(`SELECT id, customer_code, full_name, phone, address, package_name, monthly_fee, status, due_day, installed_at, created_at, updated_at FROM customers ORDER BY id DESC LIMIT 100`).all();
    return json({ ok: true, customers: rows.results || [] });
  }
  if (request.method === "POST") {
    const body = await readJson(request);
    const code = clean(body.customerCode || customerCode(), 32);
    const name = clean(body.fullName, 80); const phone = normalizePhone(body.phone); const address = clean(body.address, 300);
    if (!name || !phone || !address || !PHONE_RE.test(phone)) return json({ error: "invalid_customer" }, 400);
    try {
      const r = await env.DB.prepare(`INSERT INTO customers (customer_code, full_name, phone, address, package_name, monthly_fee, status, due_day, installed_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(code, name, phone, address, clean(body.packageName,80)||null, Number.isFinite(Number(body.monthlyFee)) ? Number(body.monthlyFee) : null, ["active","suspended","closed","pending"].includes(body.status) ? body.status : "active", body.dueDay ? Number(body.dueDay) : null, clean(body.installedAt,30)||null, clean(body.notes,500)||null).run();
      return json({ ok:true, id:r.meta.last_row_id, customerCode:code },201);
    } catch (e) { return json({ error: "customer_create_failed" }, 409); }
  }
  return json({ error:"method_not_allowed" },405);
}

async function adminCustomerPatch(request, env, id) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  const body = await readJson(request);
  const current = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(id).first();
  if (!current) return json({ error:"not_found" },404);
  const phone = body.phone !== undefined ? normalizePhone(body.phone) : current.phone;
  if (!PHONE_RE.test(phone)) return json({ error:"invalid_phone" },400);
  const status = body.status !== undefined ? body.status : current.status;
  if (!["active","suspended","closed","pending"].includes(status)) return json({ error:"invalid_status" },400);
  await env.DB.prepare(`UPDATE customers SET full_name=?, phone=?, address=?, package_name=?, monthly_fee=?, status=?, due_day=?, installed_at=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .bind(clean(body.fullName ?? current.full_name,80), phone, clean(body.address ?? current.address,300), clean(body.packageName ?? current.package_name,80)||null, body.monthlyFee !== undefined ? Number(body.monthlyFee) : current.monthly_fee, status, body.dueDay !== undefined ? Number(body.dueDay) : current.due_day, clean(body.installedAt ?? current.installed_at,30)||null, clean(body.notes ?? current.notes,500)||null, id).run();
  return json({ok:true});
}

async function adminStats(request, env) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  const [customers, active, suspended, pending, tickets, open, progress, urgent, revenue] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) AS n FROM customers").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM customers WHERE status='active'").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM customers WHERE status='suspended'").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM customers WHERE status='pending'").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM tickets").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM tickets WHERE status='open'").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM tickets WHERE status='in_progress'").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM tickets WHERE priority='urgent' AND status NOT IN ('resolved','closed')").first(),
    env.DB.prepare("SELECT COALESCE(SUM(monthly_fee),0) AS n FROM customers WHERE status='active'").first(),
  ]);
  const recent = await env.DB.prepare("SELECT ticket_code, customer_name, subject, status, priority, created_at FROM tickets ORDER BY id DESC LIMIT 6").all();
  return json({ok:true,stats:{customers:Number(customers?.n||0),active:Number(active?.n||0),suspended:Number(suspended?.n||0),pending:Number(pending?.n||0),tickets:Number(tickets?.n||0),open:Number(open?.n||0),inProgress:Number(progress?.n||0),urgent:Number(urgent?.n||0),monthlyRevenue:Number(revenue?.n||0)},recentTickets:recent.results||[]});
}

async function adminTickets(request, env) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  if (request.method === "GET") {
    const url = new URL(request.url); const status = clean(url.searchParams.get("status"),30); const q = clean(url.searchParams.get("q"),80);
    let sql = `SELECT id,ticket_code,customer_id,request_type,subject,requested_package,status,priority,customer_name,customer_phone,assigned_to,created_at,updated_at,resolved_at FROM tickets WHERE 1=1`;
    const binds = [];
    if (status && TICKET_STATUSES.has(status)) { sql += " AND status = ?"; binds.push(status); }
    if (q) { sql += " AND (ticket_code LIKE ? OR customer_name LIKE ? OR customer_phone LIKE ? OR subject LIKE ?)"; binds.push(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`); }
    sql += " ORDER BY id DESC LIMIT 200";
    const rows = await env.DB.prepare(sql).bind(...binds).all();
    return json({ok:true,tickets:rows.results||[]});
  }
  return json({error:"method_not_allowed"},405);
}

async function adminTicketPatch(request, env, id) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  const body = await readJson(request);
  const current = await env.DB.prepare("SELECT * FROM tickets WHERE id = ?").bind(id).first();
  if (!current) return json({error:"not_found"},404);
  const status = body.status || current.status; const priority = body.priority || current.priority;
  if (!TICKET_STATUSES.has(status) || !PRIORITIES.has(priority)) return json({error:"invalid_status_or_priority"},400);
  const resolution = clean(body.resolutionNote ?? current.resolution_note,1000)||null;
  const assigned = clean(body.assignedTo ?? current.assigned_to,80)||null;
  await env.DB.prepare(`UPDATE tickets SET status=?, priority=?, assigned_to=?, resolution_note=?, updated_at=CURRENT_TIMESTAMP, resolved_at=? WHERE id=?`)
    .bind(status, priority, assigned, resolution, ["resolved","closed"].includes(status) ? new Date().toISOString() : current.resolved_at, id).run();
  if (status !== current.status || resolution !== current.resolution_note) {
    await env.DB.prepare(`INSERT INTO ticket_events (ticket_id,event_type,old_status,new_status,note,actor) VALUES (?,?,?,?,?,?)`)
      .bind(id,"updated",current.status,status,resolution||null,"admin").run();
  }
  return json({ok:true});
}

async function adminTicketEvents(request, env, id) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  const rows = await env.DB.prepare("SELECT event_type,old_status,new_status,note,actor,created_at FROM ticket_events WHERE ticket_id=? ORDER BY id DESC").bind(id).all();
  return json({ok:true,events:rows.results||[]});
}


const BILLING_METHODS = new Set(["bkash","cash","bank","other"]);
const PAYMENT_STATUSES = new Set(["pending","approved","rejected","refunded"]);

function billingMonthInfo(year, month, dueDay) {
  const last = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const day = Math.min(Math.max(Number(dueDay || 1), 1), last);
  return `${year}-${String(month).padStart(2,"0")}-${String(day).padStart(2,"0")}`;
}

function invoiceCode(year, month) {
  const rand = crypto.randomUUID().replaceAll("-", "").slice(0,8).toUpperCase();
  return `RJINV-${year}${String(month).padStart(2,"0")}-${rand}`;
}
function paymentCode() {
  const d = new Date().toISOString().slice(0,10).replaceAll("-", "");
  const rand = crypto.randomUUID().replaceAll("-", "").slice(0,8).toUpperCase();
  return `RJPAY-${d}-${rand}`;
}
function effectiveInvoiceStatus(row) {
  if (!row) return null;
  if (row.status === "unpaid" && row.due_date && new Date(`${row.due_date}T23:59:59Z`) < new Date()) return "overdue";
  return row.status;
}

async function customerInvoices(request, env) {
  const auth = await requireCustomer(request, env); if (auth.error) return auth.error;
  const rows = await env.DB.prepare(`SELECT id,invoice_code,billing_year,billing_month,amount,due_date,status,paid_at,created_at,updated_at
    FROM invoices WHERE customer_id=? ORDER BY billing_year DESC,billing_month DESC LIMIT 24`).bind(auth.row.customer_id).all();
  const invoices=(rows.results||[]).map(x=>({...x,status:effectiveInvoiceStatus(x)}));
  return json({ok:true,invoices});
}

async function customerPayments(request, env) {
  const auth = await requireCustomer(request, env); if (auth.error) return auth.error;
  const rows = await env.DB.prepare(`SELECT p.payment_code,p.amount,p.method,p.transaction_ref,p.status,p.verified_at,p.created_at,i.invoice_code,i.billing_year,i.billing_month
    FROM payments p JOIN invoices i ON i.id=p.invoice_id WHERE p.customer_id=? ORDER BY p.id DESC LIMIT 50`).bind(auth.row.customer_id).all();
  return json({ok:true,payments:rows.results||[]});
}

async function customerSubmitPayment(request, env) {
  const auth = await requireCustomer(request, env); if (auth.error) return auth.error;
  const body = await readJson(request);
  const invoiceId = Number(body.invoiceId);
  const amount = Number(body.amount);
  const method = clean(body.method,20);
  const transactionRef = clean(body.transactionRef||"",80)||null;
  const payerPhone = normalizePhone(body.payerPhone||"") || null;
  const proofNote = clean(body.proofNote||"",500)||null;
  if (!Number.isInteger(invoiceId) || invoiceId < 1 || !Number.isFinite(amount) || amount <= 0 || amount > 100000000) return json({error:"invalid_payment"},400);
  if (!BILLING_METHODS.has(method)) return json({error:"invalid_payment_method"},400);
  if (payerPhone && !PHONE_RE.test(payerPhone)) return json({error:"invalid_payer_phone"},400);
  const invoice = await env.DB.prepare("SELECT id,invoice_code,customer_id,amount,status FROM invoices WHERE id=? AND customer_id=? LIMIT 1").bind(invoiceId,auth.row.customer_id).first();
  if (!invoice || invoice.status === "void" || invoice.status === "paid") return json({error:"invoice_not_payable"},409);
  const approved = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS n FROM payments WHERE invoice_id=? AND status='approved'").bind(invoiceId).first();
  const remaining = Math.max(Number(invoice.amount)-Number(approved?.n||0),0);
  if (amount > remaining) return json({error:"amount_exceeds_due",remaining},400);
  const code=paymentCode();
  const r=await env.DB.prepare(`INSERT INTO payments (payment_code,invoice_id,customer_id,amount,method,transaction_ref,payer_phone,proof_note,status) VALUES (?,?,?,?,?,?,?,?, 'pending')`)
    .bind(code,invoiceId,auth.row.customer_id,Math.round(amount),method,transactionRef,payerPhone,proofNote).run();
  await env.DB.prepare("UPDATE invoices SET status='pending', updated_at=CURRENT_TIMESTAMP WHERE id=? AND status!='paid'").bind(invoiceId).run();
  await env.DB.prepare("INSERT INTO billing_events (invoice_id,payment_id,event_type,note,actor) VALUES (?,?, 'payment_submitted', ?, 'customer')").bind(invoiceId,r.meta.last_row_id,`Payment ${code} submitted`).run();
  await notifyTelegram(env,`💳 RJ NETWORK Payment Submitted\n${code}\nInvoice: ${invoice.invoice_code}\nAmount: ৳${Math.round(amount)}\nMethod: ${method}`);
  return json({ok:true,paymentCode:code,status:"pending"},201);
}

async function adminInvoices(request, env) {
  const guard=await requireAdmin(request,env); if(guard) return guard;
  const url=new URL(request.url); const q=clean(url.searchParams.get("q"),80); const status=clean(url.searchParams.get("status"),20);
  let sql=`SELECT i.id,i.invoice_code,i.customer_id,c.customer_code,c.full_name,c.phone,i.billing_year,i.billing_month,i.amount,i.due_date,i.status,i.paid_at,i.created_at FROM invoices i JOIN customers c ON c.id=i.customer_id WHERE 1=1`;
  const binds=[];
  if(status && ["unpaid","pending","paid","overdue","void"].includes(status)){
    if(status === "overdue") sql += " AND i.status='unpaid' AND i.due_date IS NOT NULL AND i.due_date < date('now')";
    else if(status === "unpaid") sql += " AND i.status='unpaid' AND (i.due_date IS NULL OR i.due_date >= date('now'))";
    else { sql += " AND i.status=?"; binds.push(status); }
  }
  if(q){sql+=" AND (i.invoice_code LIKE ? OR c.customer_code LIKE ? OR c.full_name LIKE ? OR c.phone LIKE ?)";binds.push(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`)}
  sql+=" ORDER BY i.id DESC LIMIT 300";
  const rows=await env.DB.prepare(sql).bind(...binds).all();
  return json({ok:true,invoices:(rows.results||[]).map(x=>({...x,status:effectiveInvoiceStatus(x)}))});
}

async function adminGenerateInvoice(request, env) {
  const guard=await requireAdmin(request,env); if(guard) return guard;
  const body=await readJson(request);
  const customerId=Number(body.customerId), year=Number(body.year), month=Number(body.month);
  if(!Number.isInteger(customerId)||!Number.isInteger(year)||!Number.isInteger(month)||month<1||month>12||year<2020||year>2100) return json({error:"invalid_billing_period"},400);
  const c=await env.DB.prepare("SELECT id,customer_code,full_name,monthly_fee,due_day,status FROM customers WHERE id=? LIMIT 1").bind(customerId).first();
  if(!c) return json({error:"customer_not_found"},404);
  const amount=body.amount!==undefined?Number(body.amount):Number(c.monthly_fee||0);
  if(!Number.isFinite(amount)||amount<0||amount>100000000) return json({error:"invalid_amount"},400);
  const dueDate=body.dueDate?clean(body.dueDate,20):billingMonthInfo(year,month,c.due_day||1);
  try{
    const code=invoiceCode(year,month);
    const r=await env.DB.prepare(`INSERT INTO invoices (invoice_code,customer_id,billing_year,billing_month,amount,due_date,status,notes) VALUES (?,?,?,?,?,?, 'unpaid', ?)`)
      .bind(code,customerId,year,month,Math.round(amount),dueDate,clean(body.notes||"",500)||null).run();
    await env.DB.prepare("INSERT INTO billing_events (invoice_id,event_type,note,actor) VALUES (?, 'invoice_created', ?, 'admin')").bind(r.meta.last_row_id,`Invoice ${code} created`).run();
    return json({ok:true,id:r.meta.last_row_id,invoiceCode:code},201);
  }catch(e){return json({error:"invoice_exists_or_create_failed"},409)}
}

async function adminPayments(request, env) {
  const guard=await requireAdmin(request,env); if(guard) return guard;
  const url=new URL(request.url); const status=clean(url.searchParams.get("status"),20);
  let sql=`SELECT p.id,p.payment_code,p.invoice_id,p.customer_id,p.amount,p.method,p.transaction_ref,p.payer_phone,p.proof_note,p.status,p.verified_by,p.verified_at,p.created_at,i.invoice_code,i.amount AS invoice_amount,i.billing_year,i.billing_month,c.customer_code,c.full_name,c.phone FROM payments p JOIN invoices i ON i.id=p.invoice_id JOIN customers c ON c.id=p.customer_id WHERE 1=1`;
  const binds=[];
  if(PAYMENT_STATUSES.has(status)){sql+=" AND p.status=?";binds.push(status)}
  sql+=" ORDER BY p.id DESC LIMIT 300";
  const rows=await env.DB.prepare(sql).bind(...binds).all();
  return json({ok:true,payments:rows.results||[]});
}

async function adminPaymentPatch(request, env, id) {
  const guard=await requireAdmin(request,env); if(guard) return guard;
  const body=await readJson(request); const next=clean(body.status,20);
  if(!["approved","rejected","refunded"].includes(next)) return json({error:"invalid_payment_status"},400);
  const payment=await env.DB.prepare("SELECT * FROM payments WHERE id=? LIMIT 1").bind(id).first();
  if(!payment) return json({error:"not_found"},404);
  if(payment.status!=="pending" && next!=="refunded") return json({error:"payment_already_processed"},409);
  const actor=clean(body.verifiedBy||"admin",80);
  if(next==="approved"){
    const other=await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS n FROM payments WHERE invoice_id=? AND status='approved' AND id!=?").bind(payment.invoice_id,id).first();
    const approvedTotal=Number(other?.n||0)+Number(payment.amount||0);
    const inv=await env.DB.prepare("SELECT amount FROM invoices WHERE id=?").bind(payment.invoice_id).first();
    const invoiceStatus=approvedTotal>=Number(inv?.amount||0)?"paid":"pending";
    await env.DB.prepare("UPDATE payments SET status='approved',verified_by=?,verified_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(actor,id).run();
    await env.DB.prepare("UPDATE invoices SET status=?,paid_at=CASE WHEN ?='paid' THEN CURRENT_TIMESTAMP ELSE paid_at END,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(invoiceStatus,invoiceStatus,payment.invoice_id).run();
    await env.DB.prepare("INSERT INTO billing_events (invoice_id,payment_id,event_type,note,actor) VALUES (?,?, 'payment_approved', ?, ?)").bind(payment.invoice_id,id,`Payment ${payment.payment_code} approved`,actor).run();
  } else {
    await env.DB.prepare("UPDATE payments SET status=?,verified_by=?,verified_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(next,actor,id).run();
    if(next==="rejected") await env.DB.prepare("UPDATE invoices SET status=CASE WHEN status='pending' THEN 'unpaid' ELSE status END,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(payment.invoice_id).run();
    await env.DB.prepare("INSERT INTO billing_events (invoice_id,payment_id,event_type,note,actor) VALUES (?,?, ?, ?, ?)").bind(payment.invoice_id,id,`payment_${next}`,`Payment ${payment.payment_code} ${next}`,actor).run();
  }
  return json({ok:true});
}


function isoDateOnly(d = new Date()) {
  return new Date(d).toISOString().slice(0,10);
}

function periodForDate(d = new Date()) {
  const x = new Date(d);
  return { year: x.getUTCFullYear(), month: x.getUTCMonth() + 1 };
}

async function reconcileBilling(env) {
  const rows = await env.DB.prepare(`SELECT i.id,i.amount,i.status,i.due_date
    FROM invoices i WHERE i.status!='void' ORDER BY i.id ASC LIMIT 5000`).all();
  let changed = 0;
  const today = isoDateOnly();
  for (const inv of rows.results || []) {
    const approved = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) n FROM payments WHERE invoice_id=? AND status='approved'").bind(inv.id).first();
    const pending = await env.DB.prepare("SELECT COUNT(*) n FROM payments WHERE invoice_id=? AND status='pending'").bind(inv.id).first();
    const approvedTotal = Number(approved?.n || 0);
    const pendingCount = Number(pending?.n || 0);
    let next = 'unpaid';
    if (approvedTotal >= Number(inv.amount || 0)) next = 'paid';
    else if (pendingCount > 0) next = 'pending';
    else if (inv.due_date && inv.due_date < today) next = 'overdue';
    if (next !== inv.status) {
      await env.DB.prepare("UPDATE invoices SET status=?, paid_at=CASE WHEN ?='paid' THEN COALESCE(paid_at,CURRENT_TIMESTAMP) ELSE NULL END, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(next, next, inv.id).run();
      await env.DB.prepare("INSERT INTO billing_events (invoice_id,event_type,note,actor) VALUES (?, 'invoice_reconciled', ?, 'system')")
        .bind(inv.id, `Invoice status reconciled: ${inv.status} → ${next}; approved=৳${approvedTotal}; pending=${pendingCount}`).run();
      changed++;
    }
  }
  return changed;
}

async function runBillingCycle(env, year, month, trigger='scheduled') {
  const runKey = trigger === 'scheduled' ? `scheduled:${year}-${String(month).padStart(2,'0')}:${isoDateOnly()}` : `manual:${year}-${String(month).padStart(2,'0')}:${crypto.randomUUID()}`;
  const existing = await env.DB.prepare("SELECT id,status,generated_count,skipped_count,overdue_count,reconciled_count FROM billing_runs WHERE run_key=? LIMIT 1").bind(runKey).first();
  if (existing && existing.status === 'completed') return { ...existing, alreadyRun: true };

  let runId;
  if (existing) {
    runId = existing.id;
    await env.DB.prepare("UPDATE billing_runs SET status='running',error_message=NULL,started_at=CURRENT_TIMESTAMP,finished_at=NULL WHERE id=?").bind(runId).run();
  } else {
    const r = await env.DB.prepare(`INSERT INTO billing_runs (run_key,billing_year,billing_month,trigger,status) VALUES (?,?,?,?, 'running')`)
      .bind(runKey,year,month,trigger).run();
    runId = r.meta.last_row_id;
  }

  let generated = 0, skipped = 0, overdue = 0, reconciled = 0;
  try {
    const customers = await env.DB.prepare(`SELECT id,customer_code,monthly_fee,due_day,status FROM customers WHERE status='active' ORDER BY id ASC LIMIT 5000`).all();
    for (const c of customers.results || []) {
      const amount = Number(c.monthly_fee || 0);
      if (!Number.isFinite(amount) || amount <= 0) { skipped++; continue; }
      const existingInvoice = await env.DB.prepare("SELECT id FROM invoices WHERE customer_id=? AND billing_year=? AND billing_month=? LIMIT 1")
        .bind(c.id,year,month).first();
      if (existingInvoice) { skipped++; continue; }
      const dueDate = billingMonthInfo(year, month, c.due_day || 1);
      const code = invoiceCode(year, month);
      try {
        const r = await env.DB.prepare(`INSERT INTO invoices (invoice_code,customer_id,billing_year,billing_month,amount,due_date,status,notes) VALUES (?,?,?,?,?,?, 'unpaid', ?)`)
          .bind(code,c.id,year,month,Math.round(amount),dueDate,'Auto-generated monthly invoice').run();
        await env.DB.prepare("INSERT INTO billing_events (invoice_id,event_type,note,actor) VALUES (?, 'invoice_auto_generated', ?, 'system')")
          .bind(r.meta.last_row_id,`Monthly invoice ${code} generated automatically`).run();
        generated++;
      } catch (_) {
        skipped++;
      }
    }
    reconciled = await reconcileBilling(env);
    const overdueRow = await env.DB.prepare("SELECT COUNT(*) n FROM invoices WHERE status='overdue'").first();
    overdue = Number(overdueRow?.n || 0);
    await env.DB.prepare(`UPDATE billing_runs SET status='completed',generated_count=?,skipped_count=?,overdue_count=?,reconciled_count=?,finished_at=CURRENT_TIMESTAMP WHERE id=?`)
      .bind(generated,skipped,overdue,reconciled,runId).run();
    return { id:runId, runKey, status:'completed', generatedCount:generated, skippedCount:skipped, overdueCount:overdue, reconciledCount:reconciled };
  } catch (e) {
    await env.DB.prepare("UPDATE billing_runs SET status='failed',error_message=?,finished_at=CURRENT_TIMESTAMP WHERE id=?").bind(clean(e.message||'billing_cycle_failed',500),runId).run();
    throw e;
  }
}

async function adminBillingRun(request, env) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  const body = await readJson(request);
  const now = periodForDate();
  const year = Number(body.year || now.year);
  const month = Number(body.month || now.month);
  if (!Number.isInteger(year) || !Number.isInteger(month) || year < 2020 || year > 2100 || month < 1 || month > 12) return json({error:'invalid_billing_period'},400);
  const result = await runBillingCycle(env,year,month,'manual');
  return json({ok:true,result});
}

async function adminBillingAutomation(request, env) {
  const guard = await requireAdmin(request, env); if (guard) return guard;
  const runs = await env.DB.prepare(`SELECT id,run_key,billing_year,billing_month,trigger,status,generated_count,skipped_count,overdue_count,reconciled_count,started_at,finished_at,error_message
    FROM billing_runs ORDER BY id DESC LIMIT 20`).all();
  return json({ok:true,runs:runs.results||[]});
}

async function adminBillingStats(request,env){
  const guard=await requireAdmin(request,env);if(guard)return guard;
  const [unpaid,pending,paid,approved] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) n,COALESCE(SUM(amount),0) total FROM invoices WHERE status IN ('unpaid','overdue')").first(),
    env.DB.prepare("SELECT COUNT(*) n,COALESCE(SUM(amount),0) total FROM payments WHERE status='pending'").first(),
    env.DB.prepare("SELECT COUNT(*) n,COALESCE(SUM(amount),0) total FROM invoices WHERE status='paid'").first(),
    env.DB.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE status='approved' AND date(created_at)=date('now')").first()
  ]);
  return json({ok:true,stats:{unpaidCount:Number(unpaid?.n||0),unpaidAmount:Number(unpaid?.total||0),pendingPayments:Number(pending?.n||0),pendingAmount:Number(pending?.total||0),paidInvoices:Number(paid?.n||0),paidAmount:Number(paid?.total||0),todayCollected:Number(approved?.total||0)}});
}

export default {
  async scheduled(event, env, ctx) {
    const period = periodForDate(new Date());
    ctx.waitUntil(runBillingCycle(env, period.year, period.month, 'scheduled'));
  },
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    if (!originAllowed(request, env)) return json({error:"origin_not_allowed"},403);
    if (request.method === "OPTIONS") return new Response(null,{status:204,headers:cors});
    const url = new URL(request.url);
    try {
      let response;
      if (url.pathname === "/api/health" && request.method === "GET") response = json({ok:true,service:"RJ NETWORK V2.5 API",time:new Date().toISOString()});
      else if (url.pathname === "/api/tickets" && request.method === "POST") response = await createTicket(request,env);
      else if (url.pathname === "/api/customer/lookup" && request.method === "POST") response = await customerLookup(request,env);
      else if (url.pathname === "/api/customer/login" && request.method === "POST") response = await customerLogin(request,env);
      else if (url.pathname === "/api/customer/me" && request.method === "GET") response = await customerMe(request,env);
      else if (url.pathname === "/api/customer/logout" && request.method === "POST") response = await customerLogout(request,env);
      else if (url.pathname === "/api/customer/tickets" && request.method === "GET") response = await customerTickets(request,env);
      else if (url.pathname.match(/^\/api\/customer\/tickets\/\d+\/events$/) && request.method === "GET") response = await customerTicketEvents(request,env,url.pathname.split("/")[4]);
      else if (url.pathname === "/api/ticket/lookup" && request.method === "POST") response = await ticketLookup(request,env);
      else if (url.pathname === "/api/admin/customers" && ["GET","POST"].includes(request.method)) response = await adminCustomers(request,env);
      else if (url.pathname.match(/^\/api\/admin\/customers\/\d+\/password$/) && request.method === "PATCH") response = await adminSetCustomerPassword(request,env,url.pathname.split("/")[4]);
      else if (url.pathname.match(/^\/api\/admin\/customers\/\d+$/) && request.method === "PATCH") response = await adminCustomerPatch(request,env,url.pathname.split("/").pop());
      else if (url.pathname === "/api/admin/stats" && request.method === "GET") response = await adminStats(request,env);
      else if (url.pathname === "/api/admin/tickets" && request.method === "GET") response = await adminTickets(request,env);
      else if (url.pathname.match(/^\/api\/admin\/tickets\/\d+$/) && request.method === "PATCH") response = await adminTicketPatch(request,env,url.pathname.split("/").pop());
      else if (url.pathname === "/api/customer/invoices" && request.method === "GET") response = await customerInvoices(request,env);
      else if (url.pathname === "/api/customer/payments" && request.method === "GET") response = await customerPayments(request,env);
      else if (url.pathname === "/api/customer/payments" && request.method === "POST") response = await customerSubmitPayment(request,env);
      else if (url.pathname === "/api/admin/invoices" && request.method === "GET") response = await adminInvoices(request,env);
      else if (url.pathname === "/api/admin/invoices" && request.method === "POST") response = await adminGenerateInvoice(request,env);
      else if (url.pathname === "/api/admin/payments" && request.method === "GET") response = await adminPayments(request,env);
      else if (url.pathname.match(/^\/api\/admin\/payments\/\d+$/) && request.method === "PATCH") response = await adminPaymentPatch(request,env,url.pathname.split("/").pop());
      else if (url.pathname === "/api/admin/billing-stats" && request.method === "GET") response = await adminBillingStats(request,env);
      else if (url.pathname === "/api/admin/billing/run" && request.method === "POST") response = await adminBillingRun(request,env);
      else if (url.pathname === "/api/admin/billing/automation" && request.method === "GET") response = await adminBillingAutomation(request,env);

      else if (url.pathname.match(/^\/api\/admin\/tickets\/\d+\/events$/) && request.method === "GET") response = await adminTicketEvents(request,env,url.pathname.split("/")[4]);
      else response = json({error:"not_found"},404);
      Object.entries(cors).forEach(([k,v])=>response.headers.set(k,v));
      return response;
    } catch (e) {
      const code = e.message === "request_too_large" ? 413 : e.message === "invalid_json" ? 400 : 500;
      return json({error: code === 500 ? "server_error" : e.message},code,cors);
    }
  }
};
