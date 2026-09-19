'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/* ================= الإعدادات (من متغيرات البيئة) ================= */
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SECURE_COOKIE = process.env.INSECURE_COOKIES !== '1'; // اجعلها 1 للتجربة على http محلياً فقط
const TRUST_PROXY = process.env.TRUST_PROXY === '1';        // 1 عند العمل خلف nginx

// تخزين دائم اختياري على Upstash Redis (يعمل عبر HTTPS بلا أي مكتبات). إن لم يُضبط يُستخدم الملف المحلي.
const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || '').trim();
const REDIS_TOKEN = (process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
const REDIS_KEY = process.env.REDIS_KEY || 'flashpay:db';
const USE_REDIS = Boolean(REDIS_URL && REDIS_TOKEN);

if (ADMIN_PASSWORD.length < 12) {
  console.error('ADMIN_PASSWORD مطلوب ويجب ألا يقل عن 12 حرفاً.');
  process.exit(1);
}

if ((REDIS_URL && !REDIS_TOKEN) || (!REDIS_URL && REDIS_TOKEN)) {
  console.error('يجب ضبط UPSTASH_REDIS_REST_URL و UPSTASH_REDIS_REST_TOKEN معاً.');
  process.exit(1);
}
if (USE_REDIS) {
  let u;
  try { u = new URL(REDIS_URL); } catch { u = null; }
  const localTest = u && u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost');
  if (!u || !(u.protocol === 'https:' || localTest)) {
    console.error('UPSTASH_REDIS_REST_URL غير صالح (يجب أن يبدأ بـ https://).');
    process.exit(1);
  }
}

const CURRENCIES = ['USD', 'USDT', 'EUR', 'LBP', 'JOD', 'LYD', 'KWD'];
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILS = 5;
const MAX_BODY = 20 * 1024;
const MAX_CLIENTS = 50000;
const MAX_RATE = 1e7;

/* ================= كلمة مرور الأدمن ================= */
const SALT = crypto.randomBytes(16);
const PW_KEY = crypto.scryptSync(ADMIN_PASSWORD, SALT, 32);

function passwordMatches(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 200) return false;
  const key = crypto.scryptSync(input, SALT, 32);
  return crypto.timingSafeEqual(key, PW_KEY);
}

/* ================= التخزين (Upstash Redis أو ملف JSON بكتابة ذرّية) ================= */
async function redisCmd(args) {
  const res = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
    signal: AbortSignal.timeout(10000)
  });
  let data = null;
  try { data = await res.json(); } catch { /* تجاهل */ }
  if (!res.ok || !data || data.error) {
    throw new Error('Redis ' + res.status + (data && data.error ? ': ' + data.error : ''));
  }
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
        // أول تشغيل: ننشئ السجل فقط إن لم يكن موجوداً (NX) حتى لا نكتب فوق بيانات حقيقية أبداً
        await redisCmd(['SET', REDIS_KEY, JSON.stringify(fresh), 'NX']);
        text = await redisCmd(['GET', REDIS_KEY]);
      }
      if (typeof text !== 'string') throw new Error('قيمة غير متوقعة من Redis');
      return parseDb(text);
    } catch (e) {
      // لا نبدأ بقاعدة فارغة إذا تعذّرت القراءة حتى لا نفقد البيانات
      console.error('تعذّر تحميل البيانات من Redis، أوقفت التشغيل حمايةً للبيانات:', e.message);
      process.exit(1);
    }
  }
  try {
    return parseDb(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') {
      await saveDb(fresh);
      return fresh;
    }
    // لا نستبدل ملفاً تالفاً بملف فارغ حتى لا نفقد البيانات
    console.error('تعذّر قراءة ملف البيانات، أوقفت التشغيل حمايةً للبيانات:', e.message);
    process.exit(1);
  }
}

let db = null; // يُحمَّل عند بدء التشغيل قبل قبول أي طلب

// تنفيذ عمليات التعديل واحدة تلو الأخرى، لأن الحفظ صار غير متزامن ولا نريد تداخل طلبين.
let writeChain = Promise.resolve();
function withWriteLock(fn) {
  const run = writeChain.then(fn, fn);
  writeChain = run.catch(() => {});
  return run;
}

/* ================= التحقق من المدخلات ================= */
function normalizePhone(raw) {
  return String(raw)
    .replace(/[\u0660-\u0669]/g, ch => String(ch.charCodeAt(0) - 0x660))
    .replace(/[\u06F0-\u06F9]/g, ch => String(ch.charCodeAt(0) - 0x6F0))
    .replace(/[\s\-()]/g, '');
}

function isValidPhone(p) {
  return /^\+?\d{8,15}$/.test(p);
}

function isFacebookHost(h) {
  h = h.toLowerCase();
  return h === 'facebook.com' || h.endsWith('.facebook.com') || h === 'fb.com' || h.endsWith('.fb.com') || h === 'fb.me';
}

// يقبل رابط فيسبوك (https) أو اسم صفحة نصياً. يرجع null إذا كانت القيمة غير صالحة.
function validateFacebook(v) {
  if (typeof v !== 'string') return null;
  let s = v.trim();
  if (!s || s.length > 300 || /[\u0000-\u001f\u007f]/.test(s)) return null;
  if (/^(www\.|m\.)?(facebook|fb)\.com\//i.test(s)) s = 'https://' + s;
  if (/^[a-z][a-z0-9+.\-]*:/i.test(s)) {
    let u;
    try { u = new URL(s); } catch { return null; }
    if (u.protocol !== 'https:' || !isFacebookHost(u.hostname)) return null;
    return u.href;
  }
  return s;
}

function round6(x) { return Math.round(x * 1e6) / 1e6; }

function validateRates(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { error: 'rates_required', message: 'الأسعار مطلوبة' };
  }
  const keys = Object.keys(input);
  if (keys.length !== CURRENCIES.length || !CURRENCIES.every(c => keys.includes(c))) {
    return { error: 'all_currencies_required', message: 'يجب إرسال أسعار جميع العملات' };
  }
  const out = {};
  for (const c of CURRENCIES) {
    const r = input[c];
    if (!r || typeof r.buy !== 'number' || typeof r.sell !== 'number' || !Number.isFinite(r.buy) || !Number.isFinite(r.sell)) {
      return { error: 'invalid_number', message: `سعر ${c} غير صالح` };
    }
    const buy = round6(r.buy), sell = round6(r.sell);
    if (!(buy > 0 && sell > 0 && buy <= MAX_RATE && sell <= MAX_RATE)) {
      return { error: 'out_of_range', message: `سعر ${c} خارج المدى المسموح` };
    }
    if (sell < buy) {
      return { error: 'sell_below_buy', message: `في ${c}: سعر بيع المكتب يجب ألا يقل عن سعر شراء المكتب` };
    }
    out[c] = { buy, sell };
  }
  return { rates: out };
}

/* ================= الجلسات وتحديد المحاولات ================= */
const sessions = new Map(); // token -> expiresAt
const attempts = new Map(); // ip -> { fails, resetAt }

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  });
  return out;
}

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

function getSessionToken(req) {
  const token = parseCookies(req.headers.cookie).fp_sid;
  if (!token) return null;
  const exp = sessions.get(token);
  if (!exp) return null;
  if (exp < Date.now()) { sessions.delete(token); return null; }
  return token;
}

function sessionCookie(value, maxAgeSec) {
  return `fp_sid=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}` + (SECURE_COOKIE ? '; Secure' : '');
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff) return xff.split(',').pop().trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function isLimited(ip) {
  const a = attempts.get(ip);
  if (!a) return false;
  if (a.resetAt < Date.now()) { attempts.delete(ip); return false; }
  return a.fails >= LOGIN_MAX_FAILS;
}

function noteFail(ip) {
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a || a.resetAt < now) attempts.set(ip, { fails: 1, resetAt: now + LOGIN_WINDOW_MS });
  else a.fails += 1;
}

setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (exp < now) sessions.delete(t);
  for (const [ip, a] of attempts) if (a.resetAt < now) attempts.delete(ip);
}, 10 * 60 * 1000).unref();

/* ================= الاستجابات ================= */
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (SECURE_COOKIE) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'"
  });
  res.end(body);
}

function fail(res, status, error, message) {
  json(res, status, { error, message });
}

// يعمل سواء كانت الصفحات داخل مجلد public أو بجانب server.js مباشرةً (أسهل للرفع من الهاتف)
const PUBLIC_DIR = fs.existsSync(path.join(__dirname, 'public', 'index.html')) ? path.join(__dirname, 'public') : __dirname;
const PAGES = {
  index: fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8'),
  admin: fs.readFileSync(path.join(PUBLIC_DIR, 'admin.html'), 'utf8')
};

function sendPage(res, html, isAdmin) {
  const nonce = crypto.randomBytes(16).toString('base64');
  const body = html.replaceAll('__NONCE__', nonce);
  const headers = {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'Content-Security-Policy':
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; ` +
      `font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; ` +
      `base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  };
  if (isAdmin) headers['X-Robots-Tag'] = 'noindex, nofollow';
  res.writeHead(200, headers);
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const ct = (req.headers['content-type'] || '').toLowerCase();
    if (!ct.startsWith('application/json')) return reject({ status: 415, error: 'unsupported_media_type', message: 'نوع المحتوى غير مدعوم' });
    let size = 0, tooBig = false;
    const chunks = [];
    req.on('data', chunk => {
      if (tooBig) return;
      size += chunk.length;
      if (size > MAX_BODY) { tooBig = true; return reject({ status: 413, error: 'too_large', message: 'الطلب كبير جداً' }); }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooBig) return;
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('shape');
        resolve(v);
      } catch {
        reject({ status: 400, error: 'invalid_json', message: 'صيغة الطلب غير صحيحة' });
      }
    });
    req.on('error', () => reject({ status: 400, error: 'read_error', message: 'تعذّرت قراءة الطلب' }));
  });
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

/* ================= المسارات ================= */
async function handleAdmin(req, res, pathname, url) {
  const method = req.method;

  if (method !== 'GET' && !sameOrigin(req)) return fail(res, 403, 'bad_origin', 'طلب مرفوض');

  if (pathname === '/api/admin/login') {
    if (method !== 'POST') return fail(res, 405, 'method_not_allowed', 'الطريقة غير مسموحة');
    const ip = clientIp(req);
    if (isLimited(ip)) return fail(res, 429, 'too_many_attempts', 'محاولات كثيرة، حاول بعد 15 دقيقة');
    const body = await readJson(req);
    if (!passwordMatches(body.password)) {
      noteFail(ip);
      return fail(res, 401, 'invalid_credentials', 'كلمة المرور غير صحيحة');
    }
    attempts.delete(ip);
    res.setHeader('Set-Cookie', sessionCookie(createSession(), SESSION_TTL_MS / 1000));
    return json(res, 200, { ok: true });
  }

  const token = getSessionToken(req);
  if (!token) return fail(res, 401, 'unauthorized', 'انتهت الجلسة، سجّل الدخول');

  if (pathname === '/api/admin/logout') {
    if (method !== 'POST') return fail(res, 405, 'method_not_allowed', 'الطريقة غير مسموحة');
    sessions.delete(token);
    res.setHeader('Set-Cookie', sessionCookie('', 0));
    return json(res, 200, { ok: true });
  }

  if (pathname === '/api/admin/state') {
    if (method !== 'GET') return fail(res, 405, 'method_not_allowed', 'الطريقة غير مسموحة');
    return json(res, 200, { currencies: CURRENCIES, rates: db.rates, ratesUpdatedAt: db.ratesUpdatedAt });
  }

  if (pathname === '/api/admin/rates') {
    if (method !== 'PUT') return fail(res, 405, 'method_not_allowed', 'الطريقة غير مسموحة');
    const body = await readJson(req);
    const result = validateRates(body.rates);
    if (result.error) return fail(res, 400, result.error, result.message);
    return withWriteLock(async () => {
      const next = { ...db, rates: result.rates, ratesUpdatedAt: new Date().toISOString() };
      await saveDb(next);
      db = next;
      return json(res, 200, { rates: db.rates, ratesUpdatedAt: db.ratesUpdatedAt });
    });
  }

  if (pathname === '/api/admin/clients') {
    if (method === 'GET') {
      const q = (url.searchParams.get('q') || '').trim().toLowerCase().slice(0, 100);
      const qPhone = normalizePhone(q);
      const list = q
        ? db.clients.filter(c => c.phone.includes(qPhone) || c.facebook.toLowerCase().includes(q))
        : db.clients;
      return json(res, 200, { total: db.clients.length, clients: list.slice(0, 1000) });
    }
    if (method === 'POST') {
      const body = await readJson(req);
      const phone = normalizePhone(body.phone ?? '');
      if (!isValidPhone(phone)) return fail(res, 400, 'invalid_phone', 'رقم الهاتف غير صحيح (من 8 إلى 15 رقماً)');
      const facebook = validateFacebook(body.facebook);
      if (!facebook) return fail(res, 400, 'invalid_facebook', 'أدخل رابط صفحة فيسبوك صحيحاً (https) أو اسم الصفحة');
      return withWriteLock(async () => {
        if (db.clients.some(c => c.phone === phone)) return fail(res, 409, 'duplicate_phone', 'هذا الرقم مسجّل مسبقاً');
        if (db.clients.length >= MAX_CLIENTS) return fail(res, 400, 'limit_reached', 'تم بلوغ الحد الأقصى للعملاء');
        const client = { id: crypto.randomUUID(), phone, facebook, createdAt: new Date().toISOString() };
        const next = { ...db, clients: [client, ...db.clients] };
        await saveDb(next);
        db = next;
        return json(res, 201, { client, total: db.clients.length });
      });
    }
    return fail(res, 405, 'method_not_allowed', 'الطريقة غير مسموحة');
  }

  const m = pathname.match(/^\/api\/admin\/clients\/([0-9a-f-]{36})$/);
  if (m) {
    if (method !== 'DELETE') return fail(res, 405, 'method_not_allowed', 'الطريقة غير مسموحة');
    return withWriteLock(async () => {
      if (!db.clients.some(c => c.id === m[1])) return fail(res, 404, 'not_found', 'العميل غير موجود');
      const next = { ...db, clients: db.clients.filter(c => c.id !== m[1]) };
      await saveDb(next);
      db = next;
      return json(res, 200, { ok: true, total: db.clients.length });
    });
  }

  return fail(res, 404, 'not_found', 'غير موجود');
}

async function handle(req, res) {
  setSecurityHeaders(res);
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch { return fail(res, 400, 'bad_request', 'طلب غير صحيح'); }
  const pathname = url.pathname;
  const method = req.method;

  if (pathname === '/' || pathname === '/admin' || pathname === '/admin/') {
    if (method !== 'GET' && method !== 'HEAD') return fail(res, 405, 'method_not_allowed', 'الطريقة غير مسموحة');
    return sendPage(res, pathname === '/' ? PAGES.index : PAGES.admin, pathname !== '/');
  }

  if (pathname === '/healthz') {
    return json(res, 200, { ok: true });
  }

  if (pathname === '/api/rates') {
    if (method !== 'GET') return fail(res, 405, 'method_not_allowed', 'الطريقة غير مسموحة');
    return json(res, 200, { rates: db.rates, updatedAt: db.ratesUpdatedAt });
  }

  if (pathname.startsWith('/api/admin/')) return handleAdmin(req, res, pathname, url);

  return fail(res, 404, 'not_found', 'غير موجود');
}

const server = http.createServer(async (req, res) => {
  try {
    await handle(req, res);
  } catch (err) {
    if (res.headersSent) return res.end();
    if (err && typeof err.status === 'number') {
      if (err.status === 413) res.once('finish', () => req.destroy());
      return fail(res, err.status, err.error, err.message);
    }
    console.error(err);
    fail(res, 500, 'server_error', 'خطأ داخلي');
  }
});

server.headersTimeout = 15000;
server.requestTimeout = 30000;

(async () => {
  db = await loadDb();
  server.listen(PORT, HOST, () => {
    console.log(`FLASH PAY يعمل على http://${HOST}:${PORT} (التخزين: ${USE_REDIS ? 'Upstash Redis' : 'ملف محلي'})`);
  });
})();

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}
