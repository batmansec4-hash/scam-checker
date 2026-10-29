// Scam Check PK Pro API, Phase A: codes, activation, admin.
// Never log message text or codes. Only counters and hashes are stored.

const PLANS = {
  pro:      { limit: 100, devices: 2 },
  business: { limit: 300, devices: 5 },
};
const PERIOD_DAYS = 31;
const GRACE_DAYS = 3;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 characters, no 0/O/1/I
const CODE_RE = /^SCPK([A-HJ-NP-Z2-9]{12})$/;
const DEVICE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const enc = new TextEncoder();

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
const fail = (status, error, message) => json({ ok: false, error, message }, status);

async function sha256Hex(text) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
const hashCode = (env, canon) => sha256Hex(`${env.HASH_SALT}|code|${canon}`);
const hashDevice = (env, id) => sha256Hex(`${env.HASH_SALT}|dev|${id.toLowerCase()}`);
const hashIp = (env, req) => sha256Hex(`${env.HASH_SALT}|ip|${req.headers.get('CF-Connecting-IP') || 'unknown'}`);

function newCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const c = [...bytes].map((b) => ALPHABET[b & 31]).join(''); // 256 is a multiple of 32, so no bias
  return `SCPK-${c.slice(0, 4)}-${c.slice(4, 8)}-${c.slice(8, 12)}`;
}
function normalizeCode(input) {
  if (typeof input !== 'string' || input.length > 40) return null;
  const m = CODE_RE.exec(input.toUpperCase().replace(/[^A-Z0-9]/g, ''));
  if (!m) return null;
  return `SCPK-${m[1].slice(0, 4)}-${m[1].slice(4, 8)}-${m[1].slice(8, 12)}`;
}

async function readJson(request) {
  if (!(request.headers.get('content-type') || '').includes('application/json')) return null;
  if (Number(request.headers.get('content-length') || 0) > 4096) return null;
  const text = await request.text();
  if (text.length > 4096) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

// ---- rate limiting (stored in D1, keyed by hashed IP) ----
async function rlCount(env, key, windowSec) {
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare('SELECT window_start, count FROM rate_limits WHERE key = ?1').bind(key).first();
  return !row || now - row.window_start >= windowSec ? 0 : row.count;
}
async function rlHit(env, key, windowSec) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO rate_limits (key, window_start, count) VALUES (?1, ?2, 1)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN ?2 - window_start >= ?3 THEN 1 ELSE count + 1 END,
       window_start = CASE WHEN ?2 - window_start >= ?3 THEN ?2 ELSE window_start END`
  ).bind(key, now, windowSec).run();
}

// ---- admin check ----
async function adminCheck(request, env) {
  if (!env.ADMIN_PASSPHRASE || env.ADMIN_PASSPHRASE.length < 16) return 'unconfigured';
  const key = `admin:${await hashIp(env, request)}`;
  if ((await rlCount(env, key, 900)) >= 5) return 'locked';
  const given = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const a = enc.encode(await sha256Hex(`adm|${given}`));
  const b = enc.encode(await sha256Hex(`adm|${env.ADMIN_PASSPHRASE}`));
  if (crypto.subtle.timingSafeEqual(a, b)) return 'ok';
  await rlHit(env, key, 900);
  return 'denied';
}

// ---- code creation ----
async function createCode(env, plan, label, now) {
  const p = PLANS[plan];
  const code = newCode();
  const res = await env.DB.prepare(
    `INSERT INTO codes (code_hash, plan, label, issued_at, expires_at, max_devices, monthly_limit)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`
  ).bind(await hashCode(env, code), plan, label, now, now + (PERIOD_DAYS + GRACE_DAYS) * 86400, p.devices, p.limit).run();
  return { code, id: res.meta.last_row_id, expires_at: now + (PERIOD_DAYS + GRACE_DAYS) * 86400 };
}

// ---- customer endpoints ----
async function lookup(request, env, body) {
  const code = normalizeCode(body.code);
  const device = typeof body.device_id === 'string' && DEVICE_RE.test(body.device_id) ? body.device_id : null;
  if (!code || !device) return { error: fail(400, 'bad_request', 'Check the code and try again.'), hit: true };
  const row = await env.DB.prepare('SELECT * FROM codes WHERE code_hash = ?1').bind(await hashCode(env, code)).first();
  if (!row) return { error: fail(403, 'invalid_code', 'This code is not valid.'), hit: true };
  const now = Math.floor(Date.now() / 1000);
  if (row.status !== 'active' || row.expires_at < now)
    return { error: fail(403, 'expired', 'This code has expired. Ask for a new code.') };
  return { row, deviceHash: await hashDevice(env, device), now };
}
async function state(env, row) {
  const u = await env.DB.prepare('SELECT count FROM usage WHERE code_id = ?1').bind(row.id).first();
  return { ok: true, plan: row.plan, expires_at: row.expires_at, limit: row.monthly_limit, used: u ? u.count : 0 };
}
async function activate(request, env, body, bind) {
  const rlKey = `act:${await hashIp(env, request)}`;
  if ((await rlCount(env, rlKey, 3600)) >= 10) return fail(429, 'too_many', 'Too many attempts. Try again later.');
  const r = await lookup(request, env, body);
  if (r.error) {
    if (r.hit) await rlHit(env, rlKey, 3600);
    return r.error;
  }
  const { row, deviceHash, now } = r;
  const known = await env.DB.prepare('SELECT 1 AS x FROM devices WHERE code_id = ?1 AND device_hash = ?2').bind(row.id, deviceHash).first();
  if (!known) {
    if (!bind) return fail(403, 'device_not_registered', 'Enter your code on this device first.');
    const ins = await env.DB.prepare(
      `INSERT INTO devices (code_id, device_hash, first_seen)
       SELECT ?1, ?2, ?3 WHERE (SELECT COUNT(*) FROM devices WHERE code_id = ?1) < ?4`
    ).bind(row.id, deviceHash, now, row.max_devices).run();
    if (!ins.meta.changes) return fail(403, 'device_limit', 'This code is already used on the maximum number of devices.');
  }
  return json(await state(env, row));
}

// ---- admin endpoints ----
async function admin(path, request, env, body) {
  const now = Math.floor(Date.now() / 1000);
  if (path === '/api/admin/issue') {
    const label = typeof body.label === 'string' ? body.label.replace(/[\u0000-\u001f]/g, '').trim().slice(0, 60) : '';
    if (!PLANS[body.plan] || !label) return fail(400, 'bad_request', 'Choose a plan and enter a label.');
    const c = await createCode(env, body.plan, label, now);
    return json({ ok: true, ...c, plan: body.plan, label });
  }
  if (path === '/api/admin/list') {
    const { results } = await env.DB.prepare(
      `SELECT c.id, c.label, c.plan, c.status, c.issued_at, c.expires_at, c.max_devices, c.monthly_limit, c.replaced_by,
              (SELECT COUNT(*) FROM devices d WHERE d.code_id = c.id) AS devices,
              COALESCE((SELECT count FROM usage u WHERE u.code_id = c.id), 0) AS used
       FROM codes c ORDER BY c.id DESC LIMIT 200`
    ).all();
    return json({ ok: true, now, codes: results });
  }
  const id = Number.isInteger(body.id) ? body.id : null;
  if (id === null) return fail(400, 'bad_request', 'Missing id.');
  if (path === '/api/admin/revoke') {
    const r = await env.DB.prepare(`UPDATE codes SET status = 'revoked' WHERE id = ?1`).bind(id).run();
    return json({ ok: true, changed: r.meta.changes });
  }
  if (path === '/api/admin/renew') {
    const old = await env.DB.prepare('SELECT plan, label FROM codes WHERE id = ?1').bind(id).first();
    if (!old) return fail(404, 'not_found', 'No such code.');
    const c = await createCode(env, old.plan, old.label, now);
    await env.DB.prepare(`UPDATE codes SET status = 'revoked', replaced_by = ?2 WHERE id = ?1`).bind(id, c.id).run();
    return json({ ok: true, ...c, plan: old.plan, label: old.label });
  }
  return fail(404, 'not_found', 'Unknown endpoint.');
}

async function route(request, env) {
  const path = new URL(request.url).pathname;
  if (path === '/api/health') return json({ ok: true });
  if (request.method !== 'POST') return fail(405, 'method', 'Use POST.');
  if (!env.DB || !env.HASH_SALT || env.HASH_SALT.length < 32) return fail(503, 'unconfigured', 'Service is not set up yet.');
  const body = await readJson(request);
  if (!body) return fail(400, 'bad_request', 'Invalid request.');
  if (path.startsWith('/api/admin/')) {
    const a = await adminCheck(request, env);
    if (a === 'unconfigured') return fail(503, 'unconfigured', 'Admin is not set up yet.');
    if (a === 'locked') return fail(429, 'locked', 'Too many failed attempts. Wait 15 minutes.');
    if (a !== 'ok') return fail(401, 'denied', 'Wrong passphrase.');
    return admin(path, request, env, body);
  }
  if (path === '/api/activate') return activate(request, env, body, true);
  if (path === '/api/status') return activate(request, env, body, false);
  return fail(404, 'not_found', 'Unknown endpoint.');
}

export default {
  async fetch(request, env) {
    if (!new URL(request.url).pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
    try {
      return await route(request, env);
    } catch (e) {
      console.error('api error', e && e.message);
      return fail(500, 'server_error', 'Something went wrong. Try again.');
    }
  },
};
