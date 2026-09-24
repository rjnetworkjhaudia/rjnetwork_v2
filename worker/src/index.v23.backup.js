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

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    if (!originAllowed(request, env)) return json({error:"origin_not_allowed"},403);
    if (request.method === "OPTIONS") return new Response(null,{status:204,headers:cors});
    const url = new URL(request.url);
    try {
      let response;
      if (url.pathname === "/api/health" && request.method === "GET") response = json({ok:true,service:"RJ NETWORK V2.2 API",time:new Date().toISOString()});
      else if (url.pathname === "/api/tickets" && request.method === "POST") response = await createTicket(request,env);
      else if (url.pathname === "/api/customer/lookup" && request.method === "POST") response = await customerLookup(request,env);
      else if (url.pathname === "/api/ticket/lookup" && request.method === "POST") response = await ticketLookup(request,env);
      else if (url.pathname === "/api/admin/customers" && ["GET","POST"].includes(request.method)) response = await adminCustomers(request,env);
      else if (url.pathname.match(/^\/api\/admin\/customers\/\d+$/) && request.method === "PATCH") response = await adminCustomerPatch(request,env,url.pathname.split("/").pop());
      else if (url.pathname === "/api/admin/stats" && request.method === "GET") response = await adminStats(request,env);
      else if (url.pathname === "/api/admin/tickets" && request.method === "GET") response = await adminTickets(request,env);
      else if (url.pathname.match(/^\/api\/admin\/tickets\/\d+$/) && request.method === "PATCH") response = await adminTicketPatch(request,env,url.pathname.split("/").pop());
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
