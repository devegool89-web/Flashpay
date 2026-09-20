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
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || (process.env.RAILWAY_PUBLIC_DOMAIN ? 'https://' + process.env.RAILWAY_PUBLIC_DOMAIN : 'mailto:admin@example.com');
const MAX_SUBS = 20000;

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
  if (!res.ok || !data || data.error) throw new Error('Redis Error (HTTP ' + res.status + ')');
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
  return { rates: db.rates ?? null, ratesUpdatedAt: db.ratesUpdatedAt ?? null, clients: db.clients, subs: (db.subs && typeof db.subs === 'object' && !Array.isArray(db.subs)) ? db.subs : {}, vapid: db.vapid ?? null };
}

async function loadDb() {
  const fresh = { rates: null, ratesUpdatedAt: null, clients: [], subs: {}, vapid: null };
  if (USE_REDIS) {
    try {
      let text = await redisCmd(['GET', REDIS_KEY]);
      if (text === null) {
        await redisCmd(['SET', REDIS_KEY, JSON.stringify(fresh), 'NX']);
        text = await redisCmd(['GET', REDIS_KEY]);
      }
      return parseDb(text);
    } catch (e) {
      console.error('فشل الاتصال بـ Redis أو قراءة البيانات:', e.message);
      process.exit(1);
    }
  }
  try {
    return parseDb(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') { await saveDb(fresh); return fresh; }
    console.error('فشل قراءة ملف البيانات:', e.message);
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

// ===== Web Push (RFC 8030 / 8188 / 8291 / 8292) بدون مكتبات خارجية =====
const PUSH_HOSTS = ['fcm.googleapis.com', 'android.googleapis.com', 'updates.push.services.mozilla.com', 'web.push.apple.com'];
const PUSH_SUFFIXES = ['.push.services.mozilla.com', '.push.apple.com', '.notify.windows.com'];
const b64u = b => Buffer.from(b).toString('base64url');
const fromB64u = t => Buffer.from(t, 'base64url');
const hkdf = (ikm, salt, info, len) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));

function isAllowedPushEndpoint(ep) {
  if (typeof ep !== 'string' || ep.length > 2000) return false;
  let u; try { u = new URL(ep); } catch { return false; }
  if (u.protocol !== 'https:' || (u.port && u.port !== '443') || u.username || u.password) return false;
  const h = u.hostname.toLowerCase();
  return PUSH_HOSTS.includes(h) || PUSH_SUFFIXES.some(x => h.endsWith(x));
}
const normB64 = v => (typeof v === 'string' ? v.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_') : v);
function subscriptionProblem(sub) {
  if (!sub || typeof sub !== 'object' || !sub.keys || typeof sub.keys !== 'object') return ['bad_body', 'بيانات الاشتراك ناقصة'];
  if (typeof sub.endpoint !== 'string' || !sub.endpoint) return ['bad_endpoint', 'رابط الاشتراك مفقود'];
  if (!isAllowedPushEndpoint(sub.endpoint)) {
    let h = '?'; try { h = new URL(sub.endpoint).hostname; } catch { }
    return ['bad_endpoint', 'نطاق غير مسموح: ' + h.slice(0, 60)];
  }
  const { p256dh, auth } = sub.keys;
  if (typeof p256dh !== 'string' || typeof auth !== 'string' || !/^[A-Za-z0-9_-]+$/.test(p256dh) || !/^[A-Za-z0-9_-]+$/.test(auth)) return ['bad_keys', 'صيغة المفاتيح غير صحيحة'];
  const pk = fromB64u(p256dh), au = fromB64u(auth);
  if (!(pk.length === 65 && pk[0] === 4)) return ['bad_keys', 'طول مفتاح p256dh=' + pk.length];
  if (au.length !== 16) return ['bad_keys', 'طول مفتاح auth=' + au.length];
  return null;
}
const validSubscription = sub => !subscriptionProblem(sub);
const subId = endpoint => crypto.createHash('sha256').update(endpoint).digest('hex').slice(0, 32);

function generateVapid() {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const j = privateKey.export({ format: 'jwk' });
  return { x: j.x, y: j.y, d: j.d };
}
const vapidPublicKey = v => b64u(Buffer.concat([Buffer.from([4]), fromB64u(v.x), fromB64u(v.y)]));
const jwtCache = new Map();
function vapidHeader(endpoint, v) {
  const aud = new URL(endpoint).origin;
  const now = Math.floor(Date.now() / 1000);
  const ck = aud + '|' + v.x;
  let c = jwtCache.get(ck);
  if (!c || c.exp - now < 3600) {
    const exp = now + 12 * 3600;
    const head = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
    const claims = b64u(JSON.stringify({ aud, exp, sub: VAPID_SUBJECT }));
    const key = crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', x: v.x, y: v.y, d: v.d }, format: 'jwk' });
    const sig = crypto.sign('sha256', Buffer.from(head + '.' + claims), { key, dsaEncoding: 'ieee-p1363' });
    c = { jwt: head + '.' + claims + '.' + b64u(sig), exp };
    jwtCache.set(ck, c);
  }
  return 'vapid t=' + c.jwt + ', k=' + vapidPublicKey(v);
}

// تشفير aes128gcm حسب RFC 8291 (المعاملان الاختياريان للاختبار فقط)
function encryptPayload(sub, plaintext, testOpts) {
  const uaPublic = fromB64u(sub.keys.p256dh);
  const authSecret = fromB64u(sub.keys.auth);
  const ecdh = (testOpts && testOpts.ecdh) || (() => { const e = crypto.createECDH('prime256v1'); e.generateKeys(); return e; })();
  const asPublic = ecdh.getPublicKey();
  const salt = (testOpts && testOpts.salt) || crypto.randomBytes(16);
  const secret = ecdh.computeSecret(uaPublic);
  const prk = hkdf(secret, authSecret, Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]), 32);
  const cek = hkdf(prk, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdf(prk, salt, Buffer.from('Content-Encoding: nonce\0'), 12);
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const data = Buffer.concat([cipher.update(Buffer.concat([plaintext, Buffer.from([2])])), cipher.final(), cipher.getAuthTag()]);
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([asPublic.length]), asPublic, data]);
}

async function sendPush(sub, message) {
  const payload = Buffer.from(JSON.stringify(message));
  if (payload.length > 3000) throw new Error('payload too large');
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: { Authorization: vapidHeader(sub.endpoint, db.vapid), 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high' },
    body: encryptPayload(sub, payload),
    signal: AbortSignal.timeout(10000)
  });
  await res.arrayBuffer().catch(() => {});
  if (res.status === 404 || res.status === 410) return 'gone';
  return res.ok ? 'ok' : 'fail';
}

let broadcasting = false;
async function broadcast(message) {
  const entries = Object.entries(db.subs || {});
  const gone = []; let sent = 0, failed = 0;
  for (let i = 0; i < entries.length; i += 20) {
    const batch = entries.slice(i, i + 20);
    const results = await Promise.all(batch.map(async ([, sub]) => { try { return await sendPush(sub, message); } catch { return 'fail'; } }));
    results.forEach((r, j) => { if (r === 'ok') sent++; else if (r === 'gone') gone.push(batch[j][0]); else failed++; });
  }
  if (gone.length) {
    await withWriteLock(async () => {
      const subs = { ...db.subs }; gone.forEach(id => delete subs[id]);
      const next = { ...db, subs }; await saveDb(next); db = next;
    });
  }
  return { total: entries.length, sent, failed, removed: gone.length };
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
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
}
function fail(res, status, error, message) { json(res, status, { error, message }); }

const PUBLIC_DIR = fs.existsSync(path.join(__dirname, 'public', 'index.html')) ? path.join(__dirname, 'public') : __dirname;
const DIAG_HTML = "<!DOCTYPE html>\n<html lang=\"ar\" dir=\"rtl\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"robots\" content=\"noindex\">\n<title>فحص الإشعارات | FLASH PAY</title>\n<style nonce=\"__NONCE__\">\n  body { margin: 0; padding: 18px; background: #050507; color: #eee; font-family: system-ui, \"Segoe UI\", Tahoma, sans-serif; line-height: 1.7; }\n  h1 { font-size: 20px; color: #FFD700; margin: 0 0 6px; }\n  p { color: #aaa; font-size: 14px; margin: 6px 0 14px; }\n  button { width: 100%; padding: 15px; margin: 6px 0; border-radius: 14px; border: 0; font-size: 16px; font-weight: 800; cursor: pointer; background: linear-gradient(90deg, #ff9900, #ffd700); color: #000; }\n  button.sec { background: #1b1b20; color: #FFD700; border: 1px solid #444; }\n  button:disabled { opacity: .5; }\n  pre { direction: ltr; text-align: left; white-space: pre-wrap; word-break: break-word; background: #0e0e12; border: 1px solid #2a2a30; border-radius: 12px; padding: 12px; font-size: 12.5px; color: #d8f5d0; min-height: 60px; }\n</style>\n</head>\n<body>\n<h1>🔍 فحص الإشعارات</h1>\n<p>اضغط «ابدأ الفحص»، وإذا ظهر طلب السماح بالإشعارات اضغط «سماح». عند الانتهاء اضغط «نسخ التقرير» وأرسله لي (أو صوّر الشاشة كاملة). لا يُحفظ شيء في موقعك ولا يُرسل أي بيانات شخصية.</p>\n<button id=\"go\">ابدأ الفحص</button>\n<button id=\"copy\" class=\"sec\" hidden>نسخ التقرير</button>\n<pre id=\"out\">لم يبدأ الفحص بعد.</pre>\n<script nonce=\"__NONCE__\">\n(function () {\n  var $ = function (id) { return document.getElementById(id); };\n  var rows = [];\n  function render() { $('out').textContent = rows.map(function (r) { return r.join(': '); }).join('\\n'); }\n  function add(k, v) { rows.push([k, v]); render(); }\n  function now() { return performance.now(); }\n  function withTimeout(p, ms) {\n    return new Promise(function (res, rej) {\n      var t = setTimeout(function () { var e = new Error('انتهت المهلة ' + ms + 'ms'); e.name = 'Timeout'; rej(e); }, ms);\n      p.then(function (v) { clearTimeout(t); res(v); }, function (e) { clearTimeout(t); rej(e); });\n    });\n  }\n  function b64ToBytes(b64) {\n    var s = (b64 + '='.repeat((4 - b64.length % 4) % 4)).replace(/-/g, '+').replace(/_/g, '/');\n    return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); });\n  }\n  document.addEventListener('securitypolicyviolation', function (e) { add('⚠ حجب CSP', e.blockedURI); });\n\n  function probe(name, url, sameOrigin) {\n    var t0 = now(), ctl = new AbortController(), timer = setTimeout(function () { ctl.abort(); }, 8000);\n    return fetch(url, { mode: sameOrigin ? 'same-origin' : 'no-cors', cache: 'no-store', signal: ctl.signal }).then(function (r) {\n      clearTimeout(timer);\n      add('اتصال: ' + name, 'وصل (' + Math.round(now() - t0) + 'ms' + (sameOrigin ? ', HTTP ' + r.status : '') + ')');\n      return { ok: true, resp: r };\n    }).catch(function (e) {\n      clearTimeout(timer);\n      add('اتصال: ' + name, 'فشل بعد ' + Math.round(now() - t0) + 'ms — ' + e.name + (e.message ? ': ' + String(e.message).slice(0, 60) : ''));\n      return { ok: false };\n    });\n  }\n\n  async function run() {\n    $('go').disabled = true; rows = []; render();\n    var nav = navigator, conn = nav.connection || {};\n    add('الوقت على الجهاز (UTC)', new Date().toISOString());\n    add('المتصفح', nav.userAgent);\n    add('صفحة آمنة (HTTPS)', String(window.isSecureContext));\n    add('الشاشة الرئيسية (PWA)', String((window.matchMedia && matchMedia('(display-mode: standalone)').matches) || nav.standalone === true));\n    add('يدعم ServiceWorker / PushManager / Notification', ['serviceWorker' in nav, 'PushManager' in window, 'Notification' in window].join(' / '));\n    add('متصل (navigator.onLine)', String(nav.onLine));\n    add('نوع الشبكة (إن توفر)', (conn.effectiveType || '-') + ' / saveData=' + (conn.saveData === undefined ? '-' : conn.saveData));\n    add('المنطقة الزمنية', (Intl.DateTimeFormat().resolvedOptions().timeZone) || '-');\n\n    if (!('serviceWorker' in nav) || !('PushManager' in window) || !('Notification' in window)) { add('النتيجة', 'المتصفح لا يدعم Web Push أصلاً'); done(); return; }\n\n    // اتصال الموقع + فرق الساعة\n    var own = await probe('موقعك', '/api/rates', true);\n    if (own.ok) {\n      var d = own.resp.headers.get('date');\n      if (d) add('فرق ساعة الجهاز عن السيرفر', Math.round((Date.now() - new Date(d).getTime()) / 1000) + ' ثانية');\n    }\n\n    // الإذن\n    if (Notification.permission === 'default') {\n      try { add('نتيجة طلب الإذن', await withTimeout(Notification.requestPermission(), 60000)); } catch (e) { add('طلب الإذن', 'فشل — ' + e.name + ': ' + e.message); }\n    }\n    add('حالة الإذن (Notification.permission)', Notification.permission);\n\n    // Service Worker\n    var reg = null;\n    try {\n      reg = await withTimeout(nav.serviceWorker.register('/sw.js'), 10000);\n      await withTimeout(nav.serviceWorker.ready, 10000);\n      add('Service Worker', 'مفعّل — scope=' + reg.scope);\n    } catch (e) { add('Service Worker', 'فشل — ' + e.name + ': ' + e.message); }\n\n    // مفتاح السيرفر\n    var keyBytes = null;\n    try {\n      var kr = await fetch('/api/push/key'); var kd = await kr.json();\n      keyBytes = b64ToBytes(kd.key);\n      add('مفتاح الإشعارات من السيرفر', 'HTTP ' + kr.status + '، الطول ' + keyBytes.length + ' بايت (المتوقع 65)');\n    } catch (e) { add('مفتاح الإشعارات من السيرفر', 'فشل — ' + e.name + ': ' + e.message); }\n\n    // الاتصال بخدمات الإشعارات (بالتوازي)\n    await Promise.all([\n      probe('إنترنت عام (google.com)', 'https://www.google.com/generate_204'),\n      probe('خدمة إشعارات Google (fcm.googleapis.com)', 'https://fcm.googleapis.com/'),\n      probe('Firebase Installations (googleapis.com)', 'https://firebaseinstallations.googleapis.com/'),\n      probe('خدمة إشعارات Mozilla (updates.push.services.mozilla.com)', 'https://updates.push.services.mozilla.com/')\n    ]);\n\n    if (reg && keyBytes) {\n      try { add('pushManager.permissionState', await reg.pushManager.permissionState({ userVisibleOnly: true, applicationServerKey: keyBytes })); }\n      catch (e) { add('pushManager.permissionState', 'فشل — ' + e.name + ': ' + e.message); }\n\n      var existing = null;\n      try { existing = await reg.pushManager.getSubscription(); } catch (e) { add('getSubscription', 'فشل — ' + e.name + ': ' + e.message); }\n      if (existing) {\n        var h0 = ''; try { h0 = new URL(existing.endpoint).hostname; } catch (e) {}\n        add('اشتراك قائم مسبقاً', 'نعم — ' + h0 + ' (لن يُمسّ، ولم يُجرَ اختبار subscribe)');\n      } else if (Notification.permission === 'granted') {\n        var t0 = now();\n        try {\n          var sub = await withTimeout(reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes }), 20000);\n          var ms = Math.round(now() - t0);\n          if (!sub) { add('subscribe', 'أعاد قيمة فارغة (null) بعد ' + ms + 'ms'); }\n          else {\n            var host = ''; try { host = new URL(sub.endpoint).hostname; } catch (e) {}\n            add('subscribe', 'نجح بعد ' + ms + 'ms — الخدمة: ' + host + ' — طول الرابط ' + sub.endpoint.length);\n            try { await sub.unsubscribe(); add('تنظيف', 'حُذف الاشتراك التجريبي'); } catch (e) { add('تنظيف', 'فشل — ' + e.name); }\n          }\n        } catch (e) { add('subscribe', 'فشل بعد ' + Math.round(now() - t0) + 'ms — ' + e.name + ': ' + String(e.message).slice(0, 140)); }\n      } else { add('subscribe', 'لم يُجرَ لأن الإذن ليس granted'); }\n    }\n    done();\n  }\n  function done() { add('—', 'انتهى الفحص'); $('go').disabled = false; $('go').textContent = 'إعادة الفحص'; $('copy').hidden = false; }\n  $('go').addEventListener('click', function () { run().catch(function (e) { add('خطأ غير متوقع', e && e.message); done(); }); });\n  $('copy').addEventListener('click', function () {\n    var text = $('out').textContent;\n    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(function () { $('copy').textContent = 'تم النسخ ✔'; }, function () {\n      var r = document.createRange(); r.selectNodeContents($('out')); var s = getSelection(); s.removeAllRanges(); s.addRange(r); $('copy').textContent = 'حدّد النص ثم انسخه يدوياً';\n    });\n  });\n})();\n</script>\n</body>\n</html>\n";

function sendDiag(res) {
  const nonce = crypto.randomBytes(16).toString('base64');
  const csp = ["default-src 'none'", `script-src 'nonce-${nonce}'`, `style-src 'nonce-${nonce}'`, "connect-src 'self' https://www.google.com https://fcm.googleapis.com https://firebaseinstallations.googleapis.com https://updates.push.services.mozilla.com", "worker-src 'self'", "manifest-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"].join('; ');
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': csp, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' });
  res.end(DIAG_HTML.replaceAll('__NONCE__', nonce));
}

const PAGES = { index: fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8'), admin: fs.readFileSync(path.join(PUBLIC_DIR, 'admin.html'), 'utf8') };

function sendPage(res, html, isAdmin) {
  const nonce = crypto.randomBytes(16).toString('base64');
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}' https://fonts.googleapis.com`,
    "style-src-attr 'unsafe-inline'",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "frame-ancestors 'none'"
  ].join('; ');
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': csp,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer'
  });
  res.end(html.replaceAll('__NONCE__', nonce));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', chunk => { size += chunk.length; if (size > MAX_BODY) reject({ status: 413 }); chunks.push(chunk); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject({ status: 400 }); } });
  });
}

// ===== ملفات PWA والإشعارات (مضمّنة حتى لا تحتاج رفع ملفات إضافية) =====
const SW_JS = `'use strict';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', event => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) { d = { body: event.data ? event.data.text() : '' }; }
  event.waitUntil(self.registration.showNotification(d.title || 'FLASH PAY', {
    body: d.body || '',
    icon: '/icon-192.png',
    badge: '/badge-96.png',
    dir: 'rtl',
    lang: 'ar',
    tag: d.tag || 'flashpay-rates',
    renotify: true,
    vibrate: [120, 60, 120],
    data: { url: '/' }
  }));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) { if ('focus' in c) return c.focus(); }
    return self.clients.openWindow('/');
  }));
});
`;
const MANIFEST = JSON.stringify({
  name: 'FLASH PAY', short_name: 'FLASH PAY', lang: 'ar', dir: 'rtl',
  start_url: '/', scope: '/', display: 'standalone',
  background_color: '#050507', theme_color: '#050507',
  icons: [
    { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' }
  ]
});
const ICON_192 = Buffer.from('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', 'base64');
const ICON_512 = Buffer.from('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SHwKQK4G2GjZ2T9jdwEI3UCfvxMQUkDndSDKeHkCbLTo8t+w0wB43gVDBgo14KF/dfCdgN1F33dLAAQMUDpQTQMqMnBj2b8JAAgGHhSqAKkBN5H9WwHAj78hsh+K54GAAgkacCvZvyEAIiHwB4OHcvPA9QT4A+Xhhv5otwRAEHtsD4o04GoVCJaLlxv7g90aAOGGACO7L9sJ+IW/uMG/1U0CEMYE2z4FUjTAL3zn+1b/TjcLQBhf4VK3f7UGRCvkm/4T3TYAcXzzOMgjIEy8s7jcwd/mLgBIpoRk5x8s/R+5K+Dw9PDzeEd/lHsCgInf9cRxhsPhZLZYb/ffv/f4N7hrAEwYAAwA5k9gADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADBhADChLP4PDN+oWQAE4YkAAAAASUVORK5CYII=', 'base64');
const BADGE_96 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAMAAADVRocKAAAAP1BMVEUAAAD///////////////////////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwlEnmAAAAEHRSTlMA/soPSTBxsJAAAAAAAAAAd8NGswAAATFJREFUeNrtmdEOgjAMRdd23fr/X2wMShgSeaCHxLj7ATtew4GtK2VmZmYGi8HrN4d/v8CAkAoXgAEdBriINLgACqjCAkyfgAAdExZgAgOWAtLhAhwgYIC/1hcFHSMBawERBqAwoAoLsM36YpxjGGAoQABiADhcAAD0EaBjeqZjR2mZjh1ELdOxg1zexdhJgVzHPuPJj+g+Pdmx2wtEtmP72I87JrRj1wt4HRLZjp08shV+bQM7PIW/OyXZsRMAvbcgCji9+6qpjn3/9Cgy0wnSsdEz6AyipGODBtAx0NBHdKsBddSvcIFVA2ycE6RjGw24kZ2ig4RVA24sa+ws560BOFeu8EBw0YAc7ccdQ1/0bkLhAoV8Sbw0YC8OnHRs0QC+u2lwgRL09Rn8B83MzPxtHiI0BiGbBJ04AAAAAElFTkSuQmCC', 'base64');
const ASSETS = {
  '/sw.js': { type: 'application/javascript; charset=utf-8', body: SW_JS, cache: 'no-cache' },
  '/manifest.webmanifest': { type: 'application/manifest+json; charset=utf-8', body: MANIFEST, cache: 'no-cache' },
  '/icon-192.png': { type: 'image/png', body: ICON_192, cache: 'public, max-age=86400' },
  '/icon-512.png': { type: 'image/png', body: ICON_512, cache: 'public, max-age=86400' },
  '/badge-96.png': { type: 'image/png', body: BADGE_96, cache: 'public, max-age=86400' }
};

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

  if (pathname === '/api/admin/logout') {
    if (method !== 'POST') return fail(res, 405, '', '');
    sessions.delete(token);
    res.setHeader('Set-Cookie', sessionCookie('', 0));
    return json(res, 200, { ok: true });
  }

  if (pathname === '/api/admin/state') return json(res, 200, { currencies: CURRENCIES, rates: db.rates, ratesUpdatedAt: db.ratesUpdatedAt, pushSubscribers: Object.keys(db.subs || {}).length });
  if (pathname === '/api/admin/push/send') {
    if (method !== 'POST') return fail(res, 405, '', '');
    const b = await readJson(req);
    const title = typeof b.title === 'string' ? b.title.trim().slice(0, 80) : '';
    const body = typeof b.body === 'string' ? b.body.trim().slice(0, 400) : '';
    if (!title || !body) return fail(res, 400, 'invalid', 'العنوان والنص مطلوبان');
    if (broadcasting) return fail(res, 429, 'busy', 'هناك عملية إرسال قيد التنفيذ');
    broadcasting = true;
    try { return json(res, 200, await broadcast({ title, body, tag: 'flashpay-rates' })); }
    finally { broadcasting = false; }
  }
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
  
  if ((pathname === '/diag' || pathname === '/diag/') && method === 'GET') return sendDiag(res);

  if (pathname === '/' || pathname === '/admin' || pathname === '/admin/') {
    return sendPage(res, pathname === '/' ? PAGES.index : PAGES.admin, pathname !== '/');
  }

  const asset = ASSETS[pathname];
  if (asset && method === 'GET') {
    res.writeHead(200, { 'Content-Type': asset.type, 'Cache-Control': asset.cache, 'X-Content-Type-Options': 'nosniff' });
    return res.end(asset.body);
  }

  if (pathname === '/api/rates') return json(res, 200, { rates: db.rates, updatedAt: db.ratesUpdatedAt });

  if (pathname === '/api/push/key') return json(res, 200, { key: vapidPublicKey(db.vapid) });

  if (pathname === '/api/push/subscribe') {
    if (method !== 'POST') return fail(res, 405, '', '');
    const body = await readJson(req);
    const raw = body && body.subscription;
    const sub = raw && raw.keys && typeof raw.keys === 'object' ? { ...raw, keys: { p256dh: normB64(raw.keys.p256dh), auth: normB64(raw.keys.auth) } } : raw;
    const problem = subscriptionProblem(sub);
    if (problem) { console.warn('push subscribe rejected:', problem[0], problem[1]); return fail(res, 400, problem[0], problem[1]); }
    const phone = normalizePhone(body.phone ?? '');
    const id = subId(sub.endpoint);
    return withWriteLock(async () => {
      if (!db.subs[id] && Object.keys(db.subs).length >= MAX_SUBS) return fail(res, 503, 'full', '');
      const rec = { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth }, phone: isValidPhone(phone) ? phone : null, createdAt: (db.subs[id] && db.subs[id].createdAt) || new Date().toISOString() };
      const next = { ...db, subs: { ...db.subs, [id]: rec } };
      await saveDb(next); db = next;
      return json(res, 200, { ok: true });
    });
  }

  if (pathname === '/api/push/unsubscribe') {
    if (method !== 'POST') return fail(res, 405, '', '');
    const body = await readJson(req);
    if (!body || typeof body.endpoint !== 'string') return fail(res, 400, 'invalid', '');
    const id = subId(body.endpoint);
    return withWriteLock(async () => {
      if (db.subs[id]) { const subs = { ...db.subs }; delete subs[id]; const next = { ...db, subs }; await saveDb(next); db = next; }
      return json(res, 200, { ok: true });
    });
  }

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
    const pingPhone = normalizePhone(body && body.phone ? body.phone : '');
    if (isValidPhone(pingPhone)) onlineUsers.set(pingPhone, Date.now());
    return json(res, 200, { ok: true });
  }

  if (pathname.startsWith('/api/admin/')) return handleAdmin(req, res, pathname, url);
  return fail(res, 404, '', '');
}

const server = http.createServer(async (req, res) => {
  try { await handle(req, res); } catch (err) {
    console.error('request error:', req.method, req.url.split('?')[0], err && (err.message || err.status || err));
    if (!res.headersSent) fail(res, (err && err.status) || 500, '', '');
  }
});
if (require.main === module) {
  (async () => {
    db = await loadDb();
    console.log('Storage:', USE_REDIS ? 'Upstash Redis' : 'local file (يُمسح مع كل نشر جديد على Railway!)');
    if (!db.vapid) { db = { ...db, vapid: generateVapid() }; await saveDb(db); console.log('تم إنشاء مفاتيح VAPID للإشعارات'); }
    server.listen(PORT, HOST, () => { console.log(`Running on port ${PORT}`); });
  })();
} else {
  module.exports = { encryptPayload, vapidHeader, vapidPublicKey, generateVapid, validSubscription, isAllowedPushEndpoint };
}
