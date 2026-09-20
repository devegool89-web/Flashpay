'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT) || 7860;
const HOST = process.env.HOST || '0.0.0.0';

const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SECURE_COOKIE = process.env.INSECURE_COOKIES !== '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || '').trim();
const REDIS_TOKEN = (process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
const REDIS_KEY = process.env.REDIS_KEY || 'flashpay:db';
const USE_REDIS = Boolean(REDIS_URL && REDIS_TOKEN);

if (ADMIN_PASSWORD.length < 12) {
  console.error('ADMIN_PASSWORD مطلوب ويجب ألا يقل عن 12 حرفاً.');
  process.exit(1);
}

const CURRENCIES = ['USD', 'USDT', 'EUR', 'LBP', 'JOD', 'LYD', 'KWD'];
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILS = 5;
const MAX_BODY = 20 * 1024;
const MAX_CLIENTS = 50000;
const MAX_RATE = 1e7;

const SALT = crypto.randomBytes(16);
const PW_KEY = crypto.scryptSync(ADMIN_PASSWORD, SALT, 32);

function passwordMatches(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 200) return false;
  const key = crypto.scryptSync(input, SALT, 32);
  return crypto.timingSafeEqual(key, PW_KEY);
}

async function redisCmd(args) {
  const res = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
    signal: AbortSignal.timeout(10000)
  });
  let data = null;
  try { data = await res.json(); } catch { }
  if (!res.ok || !data || data.error) throw new Error('Redis Error');
  return data.result;
}

async function saveDb(next) {
  if (USE_REDIS) {
    await redisCmd(['SET', REDIS_KEY, JSON.stringify(next)]);
    return;
  }
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true, mode: 0o700 });
  const tmp = DATA_FILE + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(next, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DATA_FILE);
}

function parseDb(text) {
  const db = JSON.parse(text);
  if (!db || typeof db !== 'object' || !Array.isArray(db.clients)) throw new Error('بنية البيانات غير صحيحة');
  return { rates: db.rates ?? null, ratesUpdatedAt: db.ratesUpdatedAt ?? null, clients: db.clients };
}

async function loadDb() {
  const fresh = { rates: null, ratesUpdatedAt: null, clients: [] };
  if (USE_REDIS) {
    try {
      let text = await redisCmd(['GET', REDIS_KEY]);
      if (text === null) {
        await redisCmd(['SET', REDIS_KEY, JSON.stringify(fresh), 'NX']);
        text = await redisCmd(['GET', REDIS_KEY]);
      }
      return parseDb(text);
    } catch (e) {
      process.exit(1);
    }
  }
  try {
    return parseDb(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') { await saveDb(fresh); return fresh; }
    process.exit(1);
  }
}

let db = null;
let writeChain = Promise.resolve();
function withWriteLock(fn) {
  const run = writeChain.then(fn, fn);
  writeChain = run.catch(() => {});
  return run;
}

function normalizePhone(raw) {
  return String(raw).replace(/[\u0660-\u0669]/g, ch => String(ch.charCodeAt(0) - 0x660)).replace(/[\u06F0-\u06F9]/g, ch => String(ch.charCodeAt(0) - 0x6F0)).replace(/[\s\-()]/g, '');
}
function isValidPhone(p) { return /^\+?\d{8,15}$/.test(p); }
function round6(x) { return Math.round(x * 1e6) / 1e6; }

function validateRates(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { error: 'rates_required', message: 'الأسعار مطلوبة' };
  const out = {};
  for (const c of CURRENCIES) {
    const r = input[c];
    if (!r || typeof r.buy !== 'number' || typeof r.sell !== 'number') return { error: 'invalid_number', message: `سعر ${c} غير صالح` };
    const buy = round6(r.buy), sell = round6(r.sell);
    if (!(buy > 0 && sell > 0 && buy <= MAX_RATE && sell <= MAX_RATE)) return { error: 'out_of_range', message: `سعر ${c} خارج المدى` };
    out[c] = { buy, sell };
  }
  return { rates: out };
}

const sessions = new Map();
const attempts = new Map();
const onlineUsers = new Map(); // التتبع الحي للعملاء

setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (exp < now) sessions.delete(t);
  for (const [ip, a] of attempts) if (a.resetAt < now) attempts.delete(ip);
  // إزالة المستخدمين غير النشطين بعد 60 ثانية
  for (const [phone, lastSeen] of onlineUsers) if (now - lastSeen > 60000) onlineUsers.delete(phone);
}, 30000).unref();

function parseCookies(h) { const o = {}; (h || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }); return o; }
function createSession() { const t = crypto.randomBytes(32).toString('hex'); sessions.set(t, Date.now() + SESSION_TTL_MS); return t; }
function getSessionToken(req) { const t = parseCookies(req.headers.cookie).fp_sid; if (!t || !sessions.has(t)) return null; return t; }
function sessionCookie(v, m) { return `fp_sid=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${m}` + (SECURE_COOKIE ? '; Secure' : ''); }
function clientIp(req) { return TRUST_PROXY ? (req.headers['x-forwarded-for'] || '').split(',').pop().trim() : req.socket.remoteAddress; }
function isLimited(ip) { const a = attempts.get(ip); return a ? (a.resetAt > Date.now() && a.fails >= LOGIN_MAX_FAILS) : false; }
function noteFail(ip) { const now = Date.now(), a = attempts.get(ip); if (!a || a.resetAt < now) attempts.set(ip, { fails: 1, resetAt: now + LOGIN_WINDOW_MS }); else a.fails++; }

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(body);
}
function fail(res, status, error, message) { json(res, status, { error, message }); }

const PUBLIC_DIR = fs.existsSync(path.join(__dirname, 'public', 'index.html')) ? path.join(__dirname, 'public') : __dirname;
const PAGES = { index: fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8'), admin: fs.readFileSync(path.join(PUBLIC_DIR, 'admin.html'), 'utf8') };

function sendPage(res, html, isAdmin) {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(html.replaceAll('__NONCE__', nonce));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', chunk => { size += chunk.length; if (size > MAX_BODY) reject({ status: 413 }); chunks.push(chunk); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject({ status: 400 }); } });
  });
}

async function handleAdmin(req, res, pathname, url) {
  const method = req.method;
  if (pathname === '/api/admin/login') {
    if (method !== 'POST') return fail(res, 405, '', '');
    const ip = clientIp(req);
    if (isLimited(ip)) return fail(res, 429, 'too_many_attempts', 'محاولات كثيرة');
    const body = await readJson(req);
    if (!passwordMatches(body.password)) { noteFail(ip); return fail(res, 401, 'invalid_credentials', 'كلمة المرور خاطئة'); }
    attempts.delete(ip);
    res.setHeader('Set-Cookie', sessionCookie(createSession(), SESSION_TTL_MS / 1000));
    return json(res, 200, { ok: true });
  }

  const token = getSessionToken(req);
  if (!token) return fail(res, 401, 'unauthorized', 'سجل الدخول أولاً');

  if (pathname === '/api/admin/state') return json(res, 200, { currencies: CURRENCIES, rates: db.rates, ratesUpdatedAt: db.ratesUpdatedAt });
  if (pathname === '/api/admin/rates' && method === 'PUT') {
    const result = validateRates((await readJson(req)).rates);
    if (result.error) return fail(res, 400, result.error, result.message);
    return withWriteLock(async () => {
      const next = { ...db, rates: result.rates, ratesUpdatedAt: new Date().toISOString() };
      await saveDb(next); db = next; return json(res, 200, { rates: db.rates, ratesUpdatedAt: db.ratesUpdatedAt });
    });
  }
  if (pathname === '/api/admin/clients' && method === 'GET') {
    const q = (url.searchParams.get('q') || '').trim().toLowerCase();
    const list = q ? db.clients.filter(c => c.phone.includes(normalizePhone(q)) || (c.name && c.name.toLowerCase().includes(q))) : db.clients;
    // إضافة حالة الاتصال الحي للعملاء
    const mappedList = list.slice(0, 1000).map(c => ({ ...c, isOnline: onlineUsers.has(c.phone) }));
    return json(res, 200, { total: db.clients.length, clients: mappedList });
  }
  const m = pathname.match(/^\/api\/admin\/clients\/([0-9a-f-]{36})$/);
  if (m && method === 'DELETE') {
    return withWriteLock(async () => {
      const next = { ...db, clients: db.clients.filter(c => c.id !== m[1]) };
      await saveDb(next); db = next; return json(res, 200, { ok: true });
    });
  }
  return fail(res, 404, '', '');
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost'), pathname = url.pathname, method = req.method;
  
  if (pathname === '/' || pathname === '/admin' || pathname === '/admin/') {
    return sendPage(res, pathname === '/' ? PAGES.index : PAGES.admin, pathname !== '/');
  }

  if (pathname === '/api/rates') return json(res, 200, { rates: db.rates, updatedAt: db.ratesUpdatedAt });

  // استقبال تسجيل الدخول التلقائي مع الاسم
  if (pathname === '/api/register') {
    if (method !== 'POST') return fail(res, 405, '', '');
    const body = await readJson(req);
    const phone = normalizePhone(body.phone ?? '');
    const name = typeof body.name === 'string' && body.name.trim() !== '' ? body.name.trim().slice(0, 50) : 'بدون اسم';
    if (!isValidPhone(phone)) return fail(res, 400, 'invalid', '');

    onlineUsers.set(phone, Date.now()); // جعله متصلاً فوراً

    return withWriteLock(async () => {
      const existing = db.clients.find(c => c.phone === phone);
      if (existing) {
        if (existing.name !== name) { existing.name = name; await saveDb(db); } // تحديث الاسم إذا تغير
      } else {
        if (db.clients.length < MAX_CLIENTS) {
          const client = { id: crypto.randomUUID(), phone, name, createdAt: new Date().toISOString() };
          const next = { ...db, clients: [client, ...db.clients] };
          await saveDb(next); db = next;
        }
      }
      return json(res, 200, { ok: true });
    });
  }

  // استقبال نبضات الاتصال الحي (Ping)
  if (pathname === '/api/ping' && method === 'POST') {
    const body = await readJson(req);
    if (body.phone) onlineUsers.set(normalizePhone(body.phone), Date.now());
    return json(res, 200, { ok: true });
  }

  if (pathname.startsWith('/api/admin/')) return handleAdmin(req, res, pathname, url);
  return fail(res, 404, '', '');
}

const server = http.createServer(async (req, res) => {
  try { await handle(req, res); } catch (err) { fail(res, 500, '', ''); }
});
(async () => {
  db = await loadDb();
  server.listen(PORT, HOST, () => { console.log(`Running on port ${PORT}`); });
})();
