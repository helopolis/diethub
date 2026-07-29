const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const multer = require('multer');
const { OAuth2Client } = require('google-auth-library');
const { Webhook } = require('svix');
const store = require('./db');
const { buildHealthProfile, coachSummary } = require('./health');
const ai = require('./ai');
const app = express();

// X-Forwarded-For is only honored when the connection comes from a trusted
// proxy — by default the local reverse proxy (nginx on the same host).
// Override with TRUST_PROXY: "false" if the app is exposed directly,
// a hop count like "1", or an address list like "loopback, 10.0.0.0/8".
const TP = process.env.TRUST_PROXY ?? 'loopback';
app.set('trust proxy', TP === 'true' ? true : TP === 'false' ? false : /^\d+$/.test(TP) ? parseInt(TP) : TP);

// verify: stashes the exact raw bytes alongside the parsed body - needed
// because Svix signature verification (watch webhook receiver) must HMAC
// the untouched request bytes, not a re-serialized JSON.stringify(req.body)
// which can differ in key order/whitespace and would break the signature.
app.use(express.json({ limit: '1mb', verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DATA_DIR = process.env.DATA_DIR || '/data/diethub';
const JWT_SECRET = process.env.JWT_SECRET || 'diethub_secret_2026_CHANGE_IN_PROD';
const BASE = '/diet';
const TRIAL_DAYS = 14;
const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_PASS = process.env.GMAIL_APP_PASS || '';
const GMAIL_AUTH = process.env.GMAIL_AUTH || GMAIL_USER;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || '';
// BETA_MODE (2026-07-18): launch flag — bypasses trial expiration and all
// plan-tier gates (VIP/Elite-only features) app-wide, so beta users get full
// access for free while the product is proven out. Flip to 'false' via env
// var when ready to actually enforce plans/payment — no need to touch the
// gating logic itself, it's all routed through this one flag.
const BETA_MODE = process.env.BETA_MODE !== 'false';
// Google Sign-In — needs a real OAuth Client ID from Google Cloud Console
// (see setup notes where this is used below). Empty until then; endpoint
// returns setupRequired so the frontend can hide/disable the button cleanly
// rather than show a broken one.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// Same "hide the button until configured" pattern as Google above.
// SETUP REQUIRED: create an app at https://developers.facebook.com/apps
// (Facebook Login product, Valid OAuth redirect not needed for the JS SDK
// flow used here), then set FACEBOOK_APP_ID and FACEBOOK_APP_SECRET in the
// container's environment.
const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID || '';
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET || '';

// ─── PLANS & KASHIER ──────────────────────────────────────────────────────────
const PLAN_PRICES = { basic:99, standard:179, premium:249, vip:349, elite:449 };
// The Payment API Key (a.k.a. iframe key) signs the HPP hash and the webhook —
// it is SECRET and lives only here on the server, never in the browser.
const KASHIER = {
  mid:     process.env.KASHIER_MERCHANT_ID || '',
  payKey:  process.env.KASHIER_PAYMENT_API_KEY || process.env.KASHIER_SECRET_KEY || '',
  mode:    process.env.KASHIER_MODE === 'live' ? 'live' : 'test',
  baseUrl: process.env.PUBLIC_BASE_URL || 'https://diet.talabatito.com',
};
function kashierConfigured() { return !!(KASHIER.mid && KASHIER.payKey && !/YOUR_|XX-XXXX/.test(KASHIER.mid)); }
// HPP order hash — HMAC-SHA256 of "/?payment=MID.ORDER.AMOUNT.CURRENCY" with the
// Payment API Key. Verified byte-for-byte against Kashier's published test vector.
function kashierHash(orderId, amount, currency='EGP') {
  return crypto.createHmac('sha256', KASHIER.payKey)
    .update(`/?payment=${KASHIER.mid}.${orderId}.${amount}.${currency}`).digest('hex');
}
// Kashier names the fields it signed in `signatureKeys`; we rebuild key=value&…
// in that order and HMAC-SHA256 with the Payment API Key, then timing-safe compare.
const KASHIER_SIG_KEYS = ['amount','channel','currency','kashierOrderId','merchantOrderId','method','orderReference','status','transactionId','transactionResponseCode'];
function kashierVerify(data, signatureKeys, signature) {
  if (!signature || !KASHIER.payKey) return false;
  const keys = (Array.isArray(signatureKeys) && signatureKeys.length) ? signatureKeys : KASHIER_SIG_KEYS;
  const qs = keys.filter(k => data[k] !== undefined).map(k => `${k}=${data[k]}`).join('&');
  const expected = crypto.createHmac('sha256', KASHIER.payKey).update(qs).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(signature))); }
  catch { return false; }
}

// ─── SECURITY CONFIG ──────────────────────────────────────────────────────────
const SEC = {
  PWD_MIN: 8, PWD_MAX: 128,
  PWD_REGEX: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{};:'",.<>?\/\\|`~]).{8,128}$/,
  USR_MIN: 3, USR_MAX: 30,
  USR_REGEX: /^[a-zA-Z0-9_.-]{3,30}$/,
  USR_RESERVED: ['admin','root','administrator','superuser','system','support','diethub','api','null','undefined'],
  LOGIN_MAX: 5, LOGIN_WIN: 15 * 60 * 1000,
  REG_MAX: 7, REG_WIN: 10 * 60 * 1000,
  API_MAX: 60, API_WIN: 60 * 1000,
  VERIFY_EXP: 24 * 60 * 60 * 1000,
  SESSION_H: 8,
  INJECTION: [
    /(<script[\s>]|<\/script>|javascript:|on\w+\s*=)/i,
    /(union[\s+]select|drop[\s+]table|insert[\s+]into|delete[\s+]from|exec[\s+(]|eval[\s+(])/i,
    /(\.\.\/)|(\.\.\\)|(%2e%2e)/i,
    /(0x[0-9a-f]{4,})/i
  ]
};

// ─── RATE LIMITER ─────────────────────────────────────────────────────────────
const rl = new Map();
function rateLimit(ip, action, max, win) {
  const key = `${action}:${ip}`;
  const now = Date.now();
  const r = rl.get(key) || { n: 0, start: now, blocked: 0 };
  if (r.blocked && now < r.blocked) return { ok: false, wait: Math.ceil((r.blocked - now) / 1000) };
  if (now - r.start > win) { r.n = 0; r.start = now; r.blocked = 0; }
  r.n++;
  if (r.n > max) { r.blocked = now + win * 2; rl.set(key, r); return { ok: false, wait: Math.ceil(win * 2 / 1000) }; }
  rl.set(key, r);
  return { ok: true, left: max - r.n };
}
function rlReset(ip, action) { rl.delete(`${action}:${ip}`); }
setInterval(() => { const now = Date.now(); for (const [k, v] of rl) if (now - v.start > SEC.LOGIN_WIN * 4) rl.delete(k); }, 30 * 60 * 1000);

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function getIP(req) {
  // req.ip respects the 'trust proxy' setting: X-Forwarded-For is only used
  // when the request actually came through a trusted proxy, so clients can't
  // spoof their way past the rate limiter by sending fake headers.
  return req.ip || req.socket?.remoteAddress || 'unknown';
}
function sanitize(s) {
  if (typeof s !== 'string') return s;
  for (const p of SEC.INJECTION) if (p.test(s)) return null;
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;').trim();
}
function validatePwd(p) {
  if (!p || p.length < SEC.PWD_MIN) return `كلمة المرور يجب أن تكون ${SEC.PWD_MIN} أحرف على الأقل · Password must be at least ${SEC.PWD_MIN} characters`;
  if (p.length > SEC.PWD_MAX) return 'كلمة المرور طويلة جداً · Password too long';
  if (!SEC.PWD_REGEX.test(p)) return 'كلمة المرور ضعيفة! يجب أن تحتوي على:\n✓ حرف كبير (A-Z) · ✓ حرف صغير (a-z) · ✓ رقم (0-9) · ✓ رمز خاص مثل: !@#$%\nمثال صحيح: MyDiet2026!\nPassword too weak! Must have: uppercase + lowercase + number + special char (!@#$%)';
  return null;
}
function validateUsr(u) {
  if (!u || u.length < SEC.USR_MIN) return `اسم المستخدم ${SEC.USR_MIN} أحرف على الأقل · Username min ${SEC.USR_MIN} chars`;
  if (u.length > SEC.USR_MAX) return 'اسم المستخدم طويل جداً · Username too long';
  if (!SEC.USR_REGEX.test(u)) return 'اسم المستخدم يحتوي على رموز غير مسموحة!\nمسموح فقط: أحرف إنجليزية، أرقام، _ و .\nمثال صحيح: Mohamed_2026\nOnly English letters, numbers, underscore _ and dot . are allowed';
  if (SEC.USR_RESERVED.includes(u.toLowerCase())) return 'اسم المستخدم محجوز · Username reserved';
  return null;
}
function hashPwd(pwd) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(pwd, salt, 100000, 64, 'sha512').toString('hex');
  return `pbkdf2:${salt}:${hash}`;
}
function checkPwd(pwd, stored) {
  if (!stored.startsWith('pbkdf2:')) return pwd === stored; // legacy plain
  const [, salt, hash] = stored.split(':');
  const h2 = crypto.pbkdf2Sync(pwd, salt, 100000, 64, 'sha512').toString('hex');
  try { return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(h2, 'hex')); } catch { return false; }
}
function randToken(n = 32) { return crypto.randomBytes(n).toString('hex'); }
// BMI + BMR (Mifflin-St Jeor). Shared by registration AND profile updates —
// previously BMI was only ever computed once at signup and went stale after
// a user updated their weight/height; BMR didn't exist at all.
function calcBmiBmr(weight, height, age, gender) {
  const w = parseFloat(weight), h = parseFloat(height), a = parseInt(age);
  if (!w || !h) return { bmi: null, bmr: null };
  const bmi = parseFloat((w / Math.pow(h / 100, 2)).toFixed(1));
  let bmr = null;
  if (w && h && a) {
    const base = 10 * w + 6.25 * h - 5 * a;
    bmr = Math.round(gender === 'female' ? base - 161 : base + 5);
  }
  return { bmi, bmr };
}
function b64url(s) { return Buffer.from(s).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'); }
function mkToken(u) {
  const h = b64url(JSON.stringify({ alg:'HS256' }));
  const p = b64url(JSON.stringify({ id:u.id, usr:u.username, role:u.role, plan:u.plan, exp:Date.now()+SEC.SESSION_H*3600*1000 }));
  const s = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64'));
  return `${h}.${p}.${s}`;
}
function checkToken(token) {
  try {
    if (!token || token.split('.').length !== 3) return null;
    const [h, p, s] = token.split('.');
    const exp = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64'));
    if (!crypto.timingSafeEqual(Buffer.from(s), Buffer.from(exp))) return null;
    const d = JSON.parse(Buffer.from(p, 'base64').toString());
    return Date.now() > d.exp ? null : d;
  } catch { return null; }
}
function getCookie(req) { const m = (req.headers.cookie||'').match(/dh_token=([^;]+)/); return m?.[1]; }
function trial(u) {
  if (BETA_MODE || u.role === 'admin' || u.paid) return { active:true, daysLeft:999, expired:false };
  const days = Math.floor((Date.now() - new Date(u.trialStart||u.created)) / 86400000);
  const left = TRIAL_DAYS - days;
  return { active: left > 0, daysLeft: Math.max(0, left), expired: left <= 0 };
}

// ─── DATA ─────────────────────────────────────────────────────────────────────
// Backed by SQLite (see db.js). Same key→JSON interface as the old flat files,
// but atomic and durable. `update()` gives transactional read-modify-write.
const { load, save, update } = store;
function secLog(event, ip, extra={}) {
  const logs = load('security_log.json') || [];
  logs.unshift({ ts:new Date().toISOString(), event, ip, ...extra });
  save('security_log.json', logs.slice(0, 500));
}

// ─── ANALYTICS / EVENT TRACKING ───────────────────────────────────────────────
// One place records every lifecycle event. It powers the admin funnel/CAC
// dashboard AND, if N8N_WEBHOOK_URL is set, forwards each event to n8n so
// automations (welcome emails, abandoned-checkout, retention, Slack/WhatsApp
// alerts) can fire on it. Analytics must never break a request, so it's all
// wrapped and fire-and-forget.
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL || '';
function utmFrom(req) {
  const b = req?.body || {}, q = req?.query || {};
  return {
    utmSource:   b.utm_source   || q.utm_source   || null,
    utmMedium:   b.utm_medium   || q.utm_medium   || null,
    utmCampaign: b.utm_campaign || q.utm_campaign || null,
  };
}
function track(name, { req, userId, anonId, props } = {}) {
  try {
    const uid = userId || req?.user?.id || null;
    store.logEvent({ name, userId: uid, anonId: anonId || req?.body?.anonId || null,
      props: props || {}, ip: req ? getIP(req) : null, ...utmFrom(req) });
    if (N8N_WEBHOOK_URL) {
      fetch(N8N_WEBHOOK_URL, { method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ event:name, userId:uid, ts:new Date().toISOString(), props:props||{} }) })
        .catch(()=>{});
    }
  } catch(e) { /* analytics is best-effort — never surface to the caller */ }
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','SAMEORIGIN');
  res.setHeader('X-XSS-Protection','1; mode=block');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.removeHeader('X-Powered-By');
  next();
});
app.use(`${BASE}/api`, (req, res, next) => {
  const r = rateLimit(getIP(req), 'api', SEC.API_MAX, SEC.API_WIN);
  if (!r.ok) return res.status(429).json({ error:'Too many requests', retryAfter: r.wait });
  next();
});
function auth(req, res, next) {
  const t = getCookie(req) || (req.headers.authorization||'').replace('Bearer ','');
  const d = t ? checkToken(t) : null;
  if (!d) return req.headers.accept?.includes('json') ? res.status(401).json({error:'Unauthorized'}) : res.redirect(`${BASE}/login`);
  const users = load('users.json') || [];
  const u = users.find(u => u.id === d.id && u.active);
  if (!u) return res.redirect(`${BASE}/login`);
  if (!u.emailVerified && u.role !== 'admin') {
    return req.headers.accept?.includes('json')
      ? res.status(403).json({ error:'Email not verified', code:'UNVERIFIED' })
      : res.redirect(`${BASE}/verify-pending`);
  }
  const tr = trial(u);
  // req.path includes the BASE prefix (e.g. /diet/api/payment/...), so match on
  // the full prefix — the old bare '/payment' check never matched and locked
  // expired users out of the very page where they pay.
  const onPaymentRoute = req.path.startsWith(`${BASE}/payment`) || req.path.startsWith(`${BASE}/api/payment`);
  if (tr.expired && !onPaymentRoute) {
    track('paywall_hit', { userId: u.id, props: { path: req.path } });
    return req.headers.accept?.includes('json') ? res.status(402).json({expired:true}) : res.redirect(`${BASE}/payment`);
  }
  req.user = d; req.userObj = u; req.trial = tr;
  next();
}
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({error:'Forbidden'});
  next();
}
// Decodes the session token if present but never blocks — lets public routes
// attribute events/actions to a user when one is logged in.
function optionalAuth(req, res, next) {
  const t = getCookie(req) || (req.headers.authorization||'').replace('Bearer ','');
  const d = t ? checkToken(t) : null;
  if (d) req.user = d;
  next();
}

// ─── INIT DATA ────────────────────────────────────────────────────────────────
function initData() {
  const files = {
    'users.json': [{
      id:'u1', username:'admin', password: hashPwd('DietAdmin2026!@#'),
      email:'admin@diet.talabatito.com', emailVerified:true,
      role:'admin', plan:'elite', created:'2026-04-19', active:true,
      trialStart:'2026-04-19', paid:true, lang:'ar',
      loginAttempts:0, lastLogin:null, profile:{}
    }],
    'subscriptions.json': [],
    'ratings.json': [],
    'pending_verifications.json': [],
    'security_log.json': [],
    'food_prices.json': {
      lastUpdated:'2026-04-20',
      items:[
        {id:'chicken',name:'صدر فراخ طازج',nameEn:'Chicken Breast',unit:'kg',qty:'200g per serving',qtyAr:'200 جم للحصة',carrefour:185,metro:175,royal:165,talabat:195,category:'protein'},
        {id:'eggs',name:'بيض أحمر',nameEn:'Eggs (30 pcs)',unit:'carton',qty:'2-3 eggs per serving',qtyAr:'2-3 بيضات',carrefour:130,metro:125,royal:135,talabat:140,category:'protein'},
        {id:'fish',name:'سمك بلطي',nameEn:'Tilapia Fish',unit:'kg',qty:'150g per serving',qtyAr:'150 جم للحصة',carrefour:85,metro:90,royal:95,talabat:100,category:'protein'},
        {id:'beef',name:'لحمة كندوز',nameEn:'Beef',unit:'kg',qty:'150g per serving',qtyAr:'150 جم للحصة',carrefour:280,metro:265,royal:275,talabat:295,category:'protein'},
        {id:'cheese',name:'جبن قريش',nameEn:'Fresh Cheese',unit:'500g',qty:'3-4 tbsp (60g)',qtyAr:'60 جم',carrefour:45,metro:42,royal:38,talabat:50,category:'dairy'},
        {id:'veggies',name:'خضار مشكلة',nameEn:'Mixed Vegetables',unit:'kg',qty:'200g per serving',qtyAr:'200 جم للحصة',carrefour:35,metro:28,royal:32,talabat:40,category:'vegetables'},
        {id:'avocado',name:'أفوكادو',nameEn:'Avocado',unit:'kg',qty:'half (80g)',qtyAr:'نصف حبة (80 جم)',carrefour:95,metro:88,royal:92,talabat:105,category:'vegetables'},
        {id:'olive_oil',name:'زيت زيتون',nameEn:'Olive Oil',unit:'500ml',qty:'1 tbsp per meal',qtyAr:'ملعقة للوجبة',carrefour:120,metro:135,royal:130,talabat:145,category:'fats'},
        {id:'nuts',name:'مكسرات مشكلة',nameEn:'Mixed Nuts',unit:'250g',qty:'30g handful',qtyAr:'30 جم',carrefour:95,metro:98,royal:89,talabat:108,category:'fats'},
        {id:'cucumber',name:'خيار',nameEn:'Cucumber',unit:'kg',qty:'1 medium (120g)',qtyAr:'حبة متوسطة (120 جم)',carrefour:12,metro:10,royal:11,talabat:15,category:'vegetables'},
        {id:'tomato',name:'طماطم',nameEn:'Tomatoes',unit:'kg',qty:'1 medium (100g)',qtyAr:'حبة متوسطة (100 جم)',carrefour:15,metro:12,royal:14,talabat:18,category:'vegetables'}
      ]
    },
    'meal_plans.json': buildMealPlans(),
    'labs.json': buildLabTests(),
  };
  // Import any legacy flat-file JSON left over from the old storage (one-time,
  // idempotent), then seed defaults for any document still missing.
  const allKeys = Object.keys(files).concat(
    ['password_resets.json','nutrition_logs.json','lab_results.json','watch_data.json','geofence_zones.json']
  );
  store.migrateFromJson(DATA_DIR, allKeys);
  Object.entries(files).forEach(([f, d]) => {
    if (load(f) === null) save(f, d);
  });
}

function buildMealPlans() {
  const mk = (day,dayEn,meals) => ({day,dayEn,meals});
  const meal = (type,typeEn,time,name,nameEn,ings,cal,protein,carbs,fat,price) => ({type,typeEn,time,name,nameEn,ingredients:ings,cal,protein,carbs,fat,price});
  const ing = (item,itemEn,qty,grams) => ({item,itemEn,qty,grams});
  return {
    atkins:{
      nameAr:'آتكينز',nameEn:'Atkins',dailyCalories:1650,dailyCarbs:'20g',dailyProtein:'120g',dailyFat:'130g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مسلوق بالجبن القريش','Boiled eggs with fresh cheese',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('جبن قريش','Fresh Cheese','4 ملاعق / 4 tbsp',80),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],420,'28g','3g','32g',22),
          meal('غداء','Lunch','1:00 PM','صدر فراخ مشوي مع سلطة','Grilled chicken with salad',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('خيار','Cucumber','حبة / 1 piece',120),ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28)],380,'42g','6g','18g',45),
          meal('عشاء','Dinner','7:00 PM','سمك بلطي مشوي مع خضار','Grilled tilapia with vegetables',[ing('سمك بلطي','Tilapia Fish','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],320,'35g','8g','14g',28),
          meal('سناك','Snack','4:00 PM','مكسرات وبيض','Nuts and eggs',[ing('مكسرات مشكلة','Mixed Nuts','30 جم / 30g',30),ing('بيض أحمر','Eggs','بيضتان / 2 eggs',120)],280,'14g','4g','22g',15)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','عجة كوسة وفلفل','Zucchini pepper omelette',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],380,'24g','5g','28g',18),
          meal('غداء','Lunch','1:00 PM','كفتة مشوية مع سلطة','Grilled kofta with salad',[ing('لحمة كندوز','Beef','150 جم / 150g',150),ing('طماطم','Tomatoes','2 حبة / 2 pieces',200),ing('خيار','Cucumber','حبة / 1 piece',120)],520,'38g','8g','35g',58),
          meal('عشاء','Dinner','7:00 PM','شوربة دجاج بالخضار','Chicken vegetable soup',[ing('صدر فراخ طازج','Chicken Breast','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],290,'32g','10g','8g',32),
          meal('سناك','Snack','4:00 PM','أفوكادو بالجبن','Avocado with cheese',[ing('أفوكادو','Avocado','نصف حبة / half',80),ing('جبن قريش','Fresh Cheese','3 ملاعق / 3 tbsp',60)],260,'8g','5g','22g',20)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مقلي بالزبدة','Fried eggs in butter',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('جبن قريش','Fresh Cheese','4 ملاعق / 4 tbsp',80)],450,'26g','2g','36g',22),
          meal('غداء','Lunch','1:00 PM','لحمة مشوية مع سلطة','Grilled beef with salad',[ing('لحمة كندوز','Beef','150 جم / 150g',150),ing('خيار','Cucumber','حبة / 1 piece',120),ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28)],480,'40g','6g','30g',68),
          meal('عشاء','Dinner','7:00 PM','دجاج مسلوق مع خضار','Boiled chicken with vegetables',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],340,'38g','10g','14g',42),
          meal('سناك','Snack','4:00 PM','جبن وبيض مسلوق','Cheese and boiled eggs',[ing('جبن قريش','Fresh Cheese','4 ملاعق / 4 tbsp',80),ing('بيض أحمر','Eggs','بيضتان / 2 eggs',120)],280,'18g','2g','20g',14)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','جبن قريش بالبيض','Fresh cheese with eggs',[ing('جبن قريش','Fresh Cheese','6 ملاعق / 6 tbsp',120),ing('بيض أحمر','Eggs','بيضتان / 2 eggs',120)],340,'28g','3g','22g',18),
          meal('غداء','Lunch','1:00 PM','سمك مشوي مع أفوكادو','Grilled fish with avocado',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('أفوكادو','Avocado','حبة / 1 whole',160),ing('طماطم','Tomatoes','حبة / 1 piece',100)],480,'42g','8g','28g',48),
          meal('عشاء','Dinner','7:00 PM','فراخ مشوية مع خضار','Grilled chicken with vegetables',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','300 جم / 300g',300),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28)],360,'40g','8g','16g',40),
          meal('سناك','Snack','4:00 PM','مكسرات وجبن','Nuts and cheese',[ing('مكسرات مشكلة','Mixed Nuts','30 جم / 30g',30),ing('جبن قريش','Fresh Cheese','3 ملاعق / 3 tbsp',60)],280,'10g','5g','24g',16)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','عجة سبانخ بالجبن','Spinach cheese omelette',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('خضار مشكلة','Mixed Vegetables','60 جم / 60g',60),ing('جبن قريش','Fresh Cheese','3 ملاعق / 3 tbsp',60)],400,'26g','4g','30g',20),
          meal('غداء','Lunch','1:00 PM','دجاج بالخضار','Chicken with vegetables',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],460,'44g','6g','26g',55),
          meal('عشاء','Dinner','7:00 PM','لحمة مفرومة بالخضار','Ground beef with vegetables',[ing('لحمة كندوز','Beef','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28)],420,'32g','10g','28g',52),
          meal('سناك','Snack','4:00 PM','أفوكادو بالليمون','Avocado with lemon',[ing('أفوكادو','Avocado','نصف حبة / half',80)],160,'2g','5g','14g',12)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور عائلي بيض وجبن','Family breakfast eggs and cheese',[ing('بيض أحمر','Eggs','4 بيضات / 4 eggs',240),ing('جبن قريش','Fresh Cheese','5 ملاعق / 5 tbsp',100),ing('طماطم','Tomatoes','2 حبة / 2 pieces',200)],480,'34g','8g','34g',28),
          meal('غداء','Lunch','2:00 PM','فراخ مشوية كاملة','Whole grilled chicken',[ing('صدر فراخ طازج','Chicken Breast','250 جم / 250g',250),ing('خضار مشكلة','Mixed Vegetables','300 جم / 300g',300),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28)],520,'52g','12g','22g',62),
          meal('عشاء','Dinner','8:00 PM','سمك بالليمون','Fish with lemon',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28)],340,'38g','4g','18g',30),
          meal('سناك','Snack','5:00 PM','مكسرات','Mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','30 جم / 30g',30)],180,'5g','4g','16g',10)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالزبدة واللحم','Eggs with butter and meat',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('لحمة كندوز','Beef','50 جم / 50g',50)],380,'30g','2g','28g',32),
          meal('غداء','Lunch','1:00 PM','كباب مشوي مع خضار','Grilled kebab with vegetables',[ing('لحمة كندوز','Beef','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','300 جم / 300g',300),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28)],560,'44g','8g','38g',72),
          meal('عشاء','Dinner','7:00 PM','شوربة خضار بالدجاج','Vegetable chicken soup',[ing('صدر فراخ طازج','Chicken Breast','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','250 جم / 250g',250)],300,'32g','12g','8g',35),
          meal('سناك','Snack','4:00 PM','أفوكادو ومكسرات','Avocado and nuts',[ing('أفوكادو','Avocado','نصف حبة / half',80),ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],240,'4g','6g','20g',18)
        ])
      ]
    },
    keto:{
      nameAr:'كيتو',nameEn:'Keto',dailyCalories:1600,dailyCarbs:'25g',dailyProtein:'90g',dailyFat:'140g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','أومليت بالجبن والزبدة','Cheese butter omelette',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('جبنة رومي','Roumy Cheese','2 شريحة / 2 slices',60),ing('زبدة','Butter','ملعقة / 1 tbsp',14)],460,'24g','2g','40g',24),
          meal('غداء','Lunch','1:00 PM','صدر دجاج بصوص الجبن الكريمي مع بروكلي','Chicken breast in cream cheese sauce with broccoli',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('كريمة طبخ','Cooking Cream','3 ملاعق / 3 tbsp',45),ing('بروكلي','Broccoli','150 جم / 150g',150)],520,'42g','6g','36g',52),
          meal('عشاء','Dinner','7:00 PM','سلمون مشوي بالزبدة والليمون مع سبانخ','Grilled salmon in lemon butter with spinach',[ing('سلمون','Salmon','180 جم / 180g',180),ing('زبدة','Butter','ملعقة / 1 tbsp',14),ing('سبانخ','Spinach','100 جم / 100g',100)],460,'36g','4g','32g',85),
          meal('سناك','Snack','4:00 PM','مكسرات مشكلة وجبنة','Mixed nuts and cheese',[ing('مكسرات مشكلة','Mixed Nuts','30 جم / 30g',30),ing('جبنة رومي','Roumy Cheese','شريحة / 1 slice',30)],260,'10g','3g','22g',18)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مقلي بزيت جوز الهند','Eggs fried in coconut oil',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('زيت جوز الهند','Coconut Oil','ملعقة / 1 tbsp',14)],380,'19g','1g','34g',20),
          meal('غداء','Lunch','1:00 PM','برجر لحم بدون خبز مع أفوكادو','Bunless beef burger with avocado',[ing('لحمة مفرومة','Ground Beef','180 جم / 180g',180),ing('أفوكادو','Avocado','حبة / 1 whole',160),ing('جبنة شيدر','Cheddar Cheese','شريحة / 1 slice',30)],580,'38g','6g','44g',65),
          meal('عشاء','Dinner','7:00 PM','كباب ضاني مع سلطة زيتون','Lamb kebab with olive salad',[ing('لحم ضاني','Lamb','180 جم / 180g',180),ing('زيتون','Olives','30 جم / 30g',30),ing('خيار','Cucumber','حبة / 1 piece',120)],540,'34g','5g','40g',78),
          meal('سناك','Snack','4:00 PM','بيض مسلوق بالمايونيز','Boiled egg with mayo',[ing('بيض أحمر','Eggs','بيضتان / 2 eggs',120),ing('مايونيز','Mayonnaise','ملعقة / 1 tbsp',14)],220,'13g','1g','18g',12)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','زبادي يوناني كامل الدسم بجوز الهند','Full-fat Greek yogurt with coconut',[ing('زبادي يوناني','Greek Yogurt','150 جم / 150g',150),ing('جوز الهند مبشور','Shredded Coconut','20 جم / 20g',20),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],340,'16g','6g','26g',30),
          meal('غداء','Lunch','1:00 PM','سمك مشوي بزبدة الثوم','Grilled fish in garlic butter',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('زبدة','Butter','ملعقة ونصف / 1.5 tbsp',21),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],420,'40g','4g','26g',48),
          meal('عشاء','Dinner','7:00 PM','دجاج بالكاري وكريمة جوز الهند','Chicken curry with coconut cream',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('كريمة جوز الهند','Coconut Cream','50 مل / 50ml',50),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],480,'38g','6g','32g',56),
          meal('سناك','Snack','4:00 PM','مكسرات برازيلية وجبنة شيدر','Brazil nuts and cheddar',[ing('مكسرات برازيلية','Brazil Nuts','20 جم / 20g',20),ing('جبنة شيدر','Cheddar Cheese','شريحة / 1 slice',30)],250,'9g','3g','21g',20)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالافوكادو ولحم مقدد','Eggs with avocado and beef bacon',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('أفوكادو','Avocado','نصف حبة / half',80),ing('لحم مقدد بقري','Beef Bacon','30 جم / 30g',30)],420,'22g','4g','34g',35),
          meal('غداء','Lunch','1:00 PM','كفتة مشوية بصوص جبنة','Grilled kofta with cheese sauce',[ing('لحمة مفرومة','Ground Beef','180 جم / 180g',180),ing('كريمة طبخ','Cooking Cream','3 ملاعق / 3 tbsp',45),ing('جبنة رومي','Roumy Cheese','شريحة / 1 slice',30)],560,'36g','5g','42g',62),
          meal('عشاء','Dinner','7:00 PM','جمبري بالثوم والزبدة','Shrimp in garlic butter',[ing('جمبري','Shrimp','180 جم / 180g',180),ing('زبدة','Butter','ملعقتان / 2 tbsp',28),ing('سبانخ','Spinach','100 جم / 100g',100)],420,'34g','4g','28g',95),
          meal('سناك','Snack','4:00 PM','زيتون وجبنة فيتا','Olives and feta',[ing('زيتون','Olives','30 جم / 30g',30),ing('جبنة فيتا','Feta Cheese','40 جم / 40g',40)],220,'8g','2g','19g',18)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','عجة بالسبانخ والجبن الكريمي','Spinach cream cheese omelette',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('سبانخ','Spinach','60 جم / 60g',60),ing('جبنة كريمي','Cream Cheese','30 جم / 30g',30)],400,'22g','3g','32g',26),
          meal('غداء','Lunch','1:00 PM','صدر دجاج محشو بالجبن','Cheese-stuffed chicken breast',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('جبنة موزاريلا','Mozzarella Cheese','40 جم / 40g',40),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],500,'46g','5g','32g',58),
          meal('عشاء','Dinner','7:00 PM','لحمة مشوية بصوص الفلفل الأخضر','Grilled beef in green pepper sauce',[ing('لحمة كندوز','Beef','180 جم / 180g',180),ing('كريمة طبخ','Cooking Cream','2 ملعقة / 2 tbsp',30),ing('فلفل أخضر','Green Pepper','80 جم / 80g',80)],500,'36g','5g','36g',70),
          meal('سناك','Snack','4:00 PM','أفوكادو كامل بزيت الزيتون','Whole avocado with olive oil',[ing('أفوكادو','Avocado','حبة / 1 whole',160),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],320,'4g','9g','30g',22)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور عائلي كيتو','Family keto breakfast',[ing('بيض أحمر','Eggs','4 بيضات / 4 eggs',240),ing('جبنة رومي','Roumy Cheese','2 شريحة / 2 slices',60),ing('أفوكادو','Avocado','نصف حبة / half',80)],500,'28g','4g','38g',36),
          meal('غداء','Lunch','2:00 PM','فراخ مشوية كاملة بالزبدة','Whole grilled chicken in butter',[ing('فرخة كاملة','Whole Chicken','250 جم / 250g',250),ing('زبدة','Butter','ملعقتان / 2 tbsp',28),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],580,'48g','5g','40g',68),
          meal('عشاء','Dinner','8:00 PM','سمك بالكريمة والليمون','Fish in cream and lemon',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('كريمة طبخ','Cooking Cream','3 ملاعق / 3 tbsp',45)],420,'38g','3g','28g',52),
          meal('سناك','Snack','5:00 PM','مكسرات مشكلة','Mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','30 جم / 30g',30)],200,'6g','5g','18g',15)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالجبنة الرومي','Eggs with roumy cheese',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('جبنة رومي','Roumy Cheese','2 شريحة / 2 slices',60)],400,'26g','2g','32g',24),
          meal('غداء','Lunch','1:00 PM','ريب آي مشوي مع سلطة','Grilled ribeye with salad',[ing('لحم ريب آي','Ribeye Steak','200 جم / 200g',200),ing('سلطة خضراء','Green Salad','100 جم / 100g',100),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28)],620,'42g','4g','48g',95),
          meal('عشاء','Dinner','7:00 PM','شوربة دجاج كريمية','Creamy chicken soup',[ing('صدر فراخ طازج','Chicken Breast','150 جم / 150g',150),ing('كريمة طبخ','Cooking Cream','3 ملاعق / 3 tbsp',45),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],400,'32g','5g','28g',48),
          meal('سناك','Snack','4:00 PM','جبن وزيتون','Cheese and olives',[ing('جبنة فيتا','Feta Cheese','40 جم / 40g',40),ing('زيتون','Olives','20 جم / 20g',20)],200,'8g','2g','17g',16)
        ])
      ]
    },
    mediterranean:{
      nameAr:'متوسطي',nameEn:'Mediterranean',dailyCalories:1750,dailyCarbs:'180g',dailyProtein:'90g',dailyFat:'70g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','فول مدمس بزيت الزيتون والطماطم','Foul medames with olive oil and tomato',[ing('فول مدمس','Foul Medames','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28),ing('طماطم','Tomatoes','حبة / 1 piece',100)],380,'16g','48g','12g',15),
          meal('غداء','Lunch','1:00 PM','سمك مشوي مع أرز وسلطة','Grilled fish with rice and salad',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('أرز أبيض','White Rice','150 جم / 150g',150),ing('سلطة خضراء','Green Salad','100 جم / 100g',100),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],520,'38g','58g','14g',52),
          meal('عشاء','Dinner','7:00 PM','عدس بالخضار وخبز بلدي','Lentil soup with vegetables and baladi bread',[ing('عدس','Lentils','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100),ing('عيش بلدي','Baladi Bread','نصف رغيف / half loaf',60)],380,'18g','56g','8g',18),
          meal('سناك','Snack','4:00 PM','حمص بزيت الزيتون مع خيار','Hummus in olive oil with cucumber',[ing('حمص','Hummus','100 جم / 100g',100),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14),ing('خيار','Cucumber','حبة / 1 piece',120)],260,'8g','20g','16g',18)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','زبادي يوناني بالعسل والمكسرات','Greek yogurt with honey and nuts',[ing('زبادي يوناني','Greek Yogurt','170 جم / 170g',170),ing('عسل نحل','Honey','ملعقة / 1 tbsp',20),ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],320,'14g','32g','14g',28),
          meal('غداء','Lunch','1:00 PM','فراخ مشوية مع أرز وخضار','Grilled chicken with rice and vegetables',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('أرز بني','Brown Rice','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],520,'44g','54g','12g',58),
          meal('عشاء','Dinner','7:00 PM','مكرونة بصوص الطماطم والزيتون','Pasta with tomato and olive sauce',[ing('مكرونة','Pasta','150 جم / 150g',150),ing('طماطم','Tomatoes','2 حبة / 2 pieces',200),ing('زيتون','Olives','30 جم / 30g',30),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],420,'12g','62g','14g',28),
          meal('سناك','Snack','4:00 PM','فاكهة موسمية ومكسرات','Seasonal fruit and nuts',[ing('تفاح','Apple','حبة / 1 piece',150),ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],220,'4g','28g','10g',15)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان بالحليب والفاكهة','Oats with milk and fruit',[ing('شوفان','Oats','50 جم / 50g',50),ing('لبن','Milk','200 مل / 200ml',200),ing('موز','Banana','حبة / 1 piece',120)],360,'14g','58g','8g',20),
          meal('غداء','Lunch','1:00 PM','سمك السلمون بالخضار المشوية','Salmon with grilled vegetables',[ing('سلمون','Salmon','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],460,'40g','16g','26g',88),
          meal('عشاء','Dinner','7:00 PM','طعمية وسلطة بالطحينة','Falafel with tahini salad',[ing('طعمية','Falafel','150 جم / 150g',150),ing('سلطة خضراء','Green Salad','100 جم / 100g',100),ing('طحينة','Tahini','ملعقة / 1 tbsp',15)],420,'16g','38g','22g',22),
          meal('سناك','Snack','4:00 PM','زبادي بالتوت','Yogurt with berries',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('توت مشكل','Mixed Berries','60 جم / 60g',60)],140,'6g','16g','4g',22)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالطماطم والزعتر','Eggs with tomato and thyme',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],280,'14g','8g','20g',16),
          meal('غداء','Lunch','1:00 PM','كسكسي بالخضار والحمص','Couscous with vegetables and chickpeas',[ing('كسكسي','Couscous','150 جم / 150g',150),ing('حمص حب','Chickpeas','80 جم / 80g',80),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],460,'16g','78g','8g',30),
          meal('عشاء','Dinner','7:00 PM','جمبري مشوي مع أرز','Grilled shrimp with rice',[ing('جمبري','Shrimp','150 جم / 150g',150),ing('أرز أبيض','White Rice','120 جم / 120g',120),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],440,'32g','48g','12g',75),
          meal('سناك','Snack','4:00 PM','خبز بلدي بزيت الزيتون والزعتر','Baladi bread with olive oil and zaatar',[ing('عيش بلدي','Baladi Bread','نصف رغيف / half loaf',60),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14),ing('زعتر','Zaatar','ملعقة / 1 tbsp',8)],240,'6g','30g','10g',10)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','جبنة قريش بالطماطم والزيتون','Cottage cheese with tomato and olives',[ing('جبنة قريش','Cottage Cheese','100 جم / 100g',100),ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('زيتون','Olives','20 جم / 20g',20)],220,'14g','10g','12g',18),
          meal('غداء','Lunch','1:00 PM','دجاج بالفرن مع بطاطا وخضار','Baked chicken with potato and vegetables',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('بطاطس مسلوقة','Boiled Potato','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],480,'42g','44g','12g',50),
          meal('عشاء','Dinner','7:00 PM','شوربة عدس بخبز بلدي','Lentil soup with baladi bread',[ing('عدس','Lentils','200 جم / 200g',200),ing('عيش بلدي','Baladi Bread','نصف رغيف / half loaf',60)],340,'16g','54g','6g',15),
          meal('سناك','Snack','4:00 PM','مكسرات وفاكهة مجففة','Nuts and dried fruit',[ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20),ing('تمر','Dates','2 حبة / 2 pieces',30)],220,'5g','24g','12g',18)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور عائلي متوسطي','Family Mediterranean breakfast',[ing('فول مدمس','Foul Medames','150 جم / 150g',150),ing('طماطم','Tomatoes','2 حبة / 2 pieces',200),ing('زيت زيتون','Olive Oil','ملعقتان / 2 tbsp',28),ing('عيش بلدي','Baladi Bread','رغيف / 1 loaf',120)],460,'18g','66g','16g',28),
          meal('غداء','Lunch','2:00 PM','فراخ مشوية كاملة مع أرز وسلطة','Whole grilled chicken with rice and salad',[ing('فرخة كاملة','Whole Chicken','250 جم / 250g',250),ing('أرز أبيض','White Rice','150 جم / 150g',150),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],580,'50g','58g','16g',65),
          meal('عشاء','Dinner','8:00 PM','سمك بالفرن بالليمون والأعشاب','Baked fish with lemon and herbs',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],380,'38g','12g','16g',48),
          meal('سناك','Snack','5:00 PM','فاكهة موسمية','Seasonal fruit',[ing('برتقال','Orange','حبة / 1 piece',150),ing('تفاح','Apple','حبة / 1 piece',150)],140,'2g','36g','1g',12)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالجبنة البيضاء وخبز بلدي','Eggs with white cheese and baladi bread',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('عيش بلدي','Baladi Bread','نصف رغيف / half loaf',60)],380,'22g','36g','16g',20),
          meal('غداء','Lunch','1:00 PM','كفتة مشوية مع أرز وخضار','Grilled kofta with rice and vegetables',[ing('لحمة مفرومة','Ground Beef','150 جم / 150g',150),ing('أرز أبيض','White Rice','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],540,'34g','62g','16g',60),
          meal('عشاء','Dinner','7:00 PM','سلطة تونة بالحمص والخضار','Tuna salad with chickpeas and vegetables',[ing('تونة','Tuna','120 جم / 120g',120),ing('حمص حب','Chickpeas','80 جم / 80g',80),ing('سلطة خضراء','Green Salad','100 جم / 100g',100),ing('زيت زيتون','Olive Oil','ملعقة / 1 tbsp',14)],380,'32g','30g','14g',45),
          meal('سناك','Snack','4:00 PM','حمص وخبز بلدي','Hummus with baladi bread',[ing('حمص','Hummus','80 جم / 80g',80),ing('عيش بلدي','Baladi Bread','ربع رغيف / quarter loaf',30)],220,'8g','28g','8g',15)
        ])
      ]
    },
    diabetic:{
      nameAr:'مرضى السكري',nameEn:'Diabetic',dailyCalories:1500,dailyCarbs:'130g',dailyProtein:'100g',dailyFat:'55g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مسلوق مع خبز أسمر وخيار','Boiled eggs with brown bread and cucumber',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60),ing('خيار','Cucumber','حبة / 1 piece',120)],320,'18g','32g','12g',16),
          meal('غداء','Lunch','1:00 PM','صدر دجاج مشوي مع أرز بني وخضار','Grilled chicken breast with brown rice and vegetables',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('أرز بني','Brown Rice','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],460,'42g','40g','10g',52),
          meal('عشاء','Dinner','7:00 PM','سمك مشوي مع سلطة خضراء','Grilled fish with green salad',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('سلطة خضراء','Green Salad','150 جم / 150g',150),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],300,'36g','8g','12g',48),
          meal('سناك','Snack','4:00 PM','زبادي بدون سكر مع قرفة','Unsweetened yogurt with cinnamon',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('قرفة','Cinnamon','رشة / pinch',2)],90,'6g','7g','3g',14)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان بالقرفة بدون سكر','Oats with cinnamon, no added sugar',[ing('شوفان','Oats','40 جم / 40g',40),ing('لبن','Milk','150 مل / 150ml',150),ing('قرفة','Cinnamon','رشة / pinch',2)],260,'11g','38g','6g',15),
          meal('غداء','Lunch','1:00 PM','كفتة مشوية مع خضار سوتيه','Grilled kofta with sautéed vegetables',[ing('لحمة مفرومة','Ground Beef','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],420,'32g','16g','24g',55),
          meal('عشاء','Dinner','7:00 PM','عدس بخضار بدون خبز','Lentil soup with vegetables, no bread',[ing('عدس','Lentils','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],240,'14g','36g','2g',14),
          meal('سناك','Snack','4:00 PM','حفنة لوز','A handful of almonds',[ing('لوز','Almonds','20 جم / 20g',20)],120,'4g','4g','10g',12)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','جبنة قريش مع خبز أسمر وطماطم','Cottage cheese with brown bread and tomato',[ing('جبنة قريش','Cottage Cheese','100 جم / 100g',100),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60),ing('طماطم','Tomatoes','حبة / 1 piece',100)],280,'18g','34g','6g',18),
          meal('غداء','Lunch','1:00 PM','سمك بالفرن مع بطاطا مسلوقة','Baked fish with boiled potato',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('بطاطس مسلوقة','Boiled Potato','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],380,'38g','36g','6g',48),
          meal('عشاء','Dinner','7:00 PM','صدر دجاج بالخضار المشوية','Chicken breast with grilled vegetables',[ing('صدر فراخ طازج','Chicken Breast','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],320,'36g','14g','8g',42),
          meal('سناك','Snack','4:00 PM','تفاحة صغيرة','A small apple',[ing('تفاح','Apple','حبة صغيرة / 1 small',100)],55,'0g','14g','0g',8)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','بياض بيض بالخضار','Egg whites with vegetables',[ing('بياض بيض','Egg Whites','4 بيضات / 4 whites',140),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],180,'20g','8g','4g',14),
          meal('غداء','Lunch','1:00 PM','فراخ مسلوقة مع أرز بني وسلطة','Boiled chicken with brown rice and salad',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('أرز بني','Brown Rice','100 جم / 100g',100),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],420,'42g','36g','8g',50),
          meal('عشاء','Dinner','7:00 PM','شوربة خضار بالدجاج','Chicken vegetable soup',[ing('صدر فراخ طازج','Chicken Breast','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],240,'28g','12g','6g',35),
          meal('سناك','Snack','4:00 PM','خيار وجزر مقطع','Sliced cucumber and carrot',[ing('خيار','Cucumber','حبة / 1 piece',120),ing('جزر','Carrot','حبة / 1 piece',80)],45,'1g','9g','0g',6)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مسلوق مع أفوكادو','Boiled eggs with avocado',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('أفوكادو','Avocado','نصف حبة / half',80)],260,'14g','8g','20g',20),
          meal('غداء','Lunch','1:00 PM','لحمة مشوية مع خضار وأرز بني','Grilled beef with vegetables and brown rice',[ing('لحمة كندوز','Beef','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],460,'34g','38g','16g',65),
          meal('عشاء','Dinner','7:00 PM','سمك مشوي بالليمون','Grilled fish with lemon',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],260,'36g','6g','8g',46),
          meal('سناك','Snack','4:00 PM','مكسرات مشكلة قليلة','A small handful of mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],90,'3g','3g','8g',10)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور عائلي متوازن','Family balanced breakfast',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('جبنة قريش','Cottage Cheese','60 جم / 60g',60),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60)],340,'24g','30g','14g',22),
          meal('غداء','Lunch','2:00 PM','فراخ مشوية مع أرز بني وخضار','Grilled chicken with brown rice and vegetables',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('أرز بني','Brown Rice','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],480,'46g','42g','10g',58),
          meal('عشاء','Dinner','8:00 PM','سمك بالفرن مع خضار','Baked fish with vegetables',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],300,'36g','14g','8g',48),
          meal('سناك','Snack','5:00 PM','زبادي بدون سكر','Unsweetened yogurt',[ing('زبادي','Plain Yogurt','150 جم / 150g',150)],90,'5g','7g','3g',14)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','7:00 AM','عجة خضار بزيت زيتون قليل','Vegetable omelette with a little olive oil',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],250,'14g','8g','18g',18),
          meal('غداء','Lunch','1:00 PM','كبدة مشوية مع خضار وأرز بني','Grilled liver with vegetables and brown rice',[ing('كبدة بقري','Beef Liver','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],420,'38g','38g','10g',48),
          meal('عشاء','Dinner','7:00 PM','شوربة عدس خفيفة','Light lentil soup',[ing('عدس','Lentils','150 جم / 150g',150)],180,'11g','28g','2g',10),
          meal('سناك','Snack','4:00 PM','حبة خيار وجبنة قريش','Cucumber with cottage cheese',[ing('خيار','Cucumber','حبة / 1 piece',120),ing('جبنة قريش','Cottage Cheese','40 جم / 40g',40)],90,'6g','5g','2g',10)
        ])
      ]
    },
    women:{
      nameAr:'المرأة',nameEn:'Women',dailyCalories:1800,dailyCarbs:'200g',dailyProtein:'80g',dailyFat:'65g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','زبادي بالفواكه والمكسرات','Yogurt with fruit and nuts',[ing('زبادي','Plain Yogurt','170 جم / 170g',170),ing('موز','Banana','حبة / 1 piece',120),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],320,'12g','42g','12g',26),
          meal('غداء','Lunch','1:00 PM','عدس بالأرز البني وسلطة','Lentils with brown rice and salad',[ing('عدس','Lentils','180 جم / 180g',180),ing('أرز بني','Brown Rice','100 جم / 100g',100),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],420,'18g','62g','6g',24),
          meal('عشاء','Dinner','7:00 PM','سمك مشوي مع خضار','Grilled fish with vegetables',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],340,'36g','10g','14g',48),
          meal('سناك','Snack','4:00 PM','تفاح ولوز','Apple and almonds',[ing('تفاح','Apple','حبة / 1 piece',150),ing('لوز','Almonds','15 جم / 15g',15)],180,'4g','24g','9g',18)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مسلوق مع عيش أسمر وأفوكادو','Boiled eggs with brown bread and avocado',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60),ing('أفوكادو','Avocado','نصف حبة / half',80)],380,'18g','36g','18g',28),
          meal('غداء','Lunch','1:00 PM','صدر فراخ مشوي مع أرز بني وسبانخ','Grilled chicken breast with brown rice and spinach',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('أرز بني','Brown Rice','120 جم / 120g',120),ing('سبانخ','Spinach','100 جم / 100g',100)],460,'42g','48g','8g',56),
          meal('عشاء','Dinner','7:00 PM','شوربة عدس بالخضار','Lentil soup with vegetables',[ing('عدس','Lentils','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],280,'15g','44g','3g',16),
          meal('سناك','Snack','4:00 PM','زبادي يوناني بالعسل','Greek yogurt with honey',[ing('زبادي يوناني','Greek Yogurt','150 جم / 150g',150),ing('عسل نحل','Honey','ملعقة / 1 tbsp',20)],180,'11g','20g','4g',26)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان بالحليب والموز','Oats with milk and banana',[ing('شوفان','Oats','50 جم / 50g',50),ing('لبن','Milk','200 مل / 200ml',200),ing('موز','Banana','حبة / 1 piece',120)],380,'15g','62g','8g',20),
          meal('غداء','Lunch','1:00 PM','كبدة مشوية مع أرز بني وسلطة','Grilled liver with brown rice and salad',[ing('كبدة بقري','Beef Liver','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],420,'36g','40g','10g',48),
          meal('عشاء','Dinner','7:00 PM','سمك بالليمون مع خضار','Fish with lemon and vegetables',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],300,'36g','10g','8g',46),
          meal('سناك','Snack','4:00 PM','تمر ومكسرات','Dates and nuts',[ing('تمر','Dates','3 حبات / 3 pieces',45),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],200,'4g','30g','9g',16)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','توست أسمر بالجبنة القريش والطماطم','Brown toast with cottage cheese and tomato',[ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60),ing('جبنة قريش','Cottage Cheese','80 جم / 80g',80),ing('طماطم','Tomatoes','حبة / 1 piece',100)],280,'16g','34g','7g',20),
          meal('غداء','Lunch','1:00 PM','فراخ بالخضار مع أرز بني','Chicken with vegetables and brown rice',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],440,'42g','40g','9g',54),
          meal('عشاء','Dinner','7:00 PM','سلطة تونة بالحمص','Tuna salad with chickpeas',[ing('تونة','Tuna','100 جم / 100g',100),ing('حمص حب','Chickpeas','80 جم / 80g',80),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],340,'30g','28g','10g',42),
          meal('سناك','Snack','4:00 PM','فاكهة موسمية','Seasonal fruit',[ing('برتقال','Orange','حبة / 1 piece',150),ing('تفاح','Apple','حبة / 1 piece',150)],140,'2g','36g','1g',12)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','عجة سبانخ','Spinach omelette',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('سبانخ','Spinach','80 جم / 80g',80),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],260,'16g','8g','18g',18),
          meal('غداء','Lunch','1:00 PM','لحمة مفرومة قليلة الدهن مع خضار وأرز بني','Lean ground beef with vegetables and brown rice',[ing('لحمة مفرومة','Ground Beef','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],460,'34g','44g','14g',60),
          meal('عشاء','Dinner','7:00 PM','شوربة خضار بالدجاج','Chicken vegetable soup',[ing('صدر فراخ طازج','Chicken Breast','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],260,'28g','14g','6g',35),
          meal('سناك','Snack','4:00 PM','زبادي بالتوت','Yogurt with berries',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('توت مشكل','Mixed Berries','60 جم / 60g',60)],140,'6g','16g','4g',22)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور عائلي (بيض وجبنة وعيش أسمر وطماطم)','Family breakfast (eggs, cheese, brown bread, tomato)',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60),ing('طماطم','Tomatoes','حبة / 1 piece',100)],380,'24g','38g','16g',26),
          meal('غداء','Lunch','2:00 PM','فراخ مشوية كاملة مع أرز بني وسلطة','Whole grilled chicken with brown rice and salad',[ing('فرخة كاملة','Whole Chicken','200 جم / 200g',200),ing('أرز بني','Brown Rice','120 جم / 120g',120),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],480,'46g','46g','12g',60),
          meal('عشاء','Dinner','8:00 PM','سمك بالفرن بالأعشاب','Baked fish with herbs',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],300,'36g','12g','8g',46),
          meal('سناك','Snack','5:00 PM','مكسرات مشكلة','Mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],130,'4g','5g','11g',14)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالأفوكادو','Eggs with avocado',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('أفوكادو','Avocado','نصف حبة / half',80)],280,'14g','8g','22g',20),
          meal('غداء','Lunch','1:00 PM','عدس بالخضار وأرز بني','Lentils with vegetables and brown rice',[ing('عدس','Lentils','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100),ing('أرز بني','Brown Rice','100 جم / 100g',100)],400,'17g','62g','5g',22),
          meal('عشاء','Dinner','7:00 PM','جمبري مشوي مع سلطة','Grilled shrimp with salad',[ing('جمبري','Shrimp','150 جم / 150g',150),ing('سلطة خضراء','Green Salad','100 جم / 100g',100),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],260,'28g','8g','12g',82),
          meal('سناك','Snack','4:00 PM','تفاحة ولوز','Apple and almonds',[ing('تفاح','Apple','حبة / 1 piece',150),ing('لوز','Almonds','15 جم / 15g',15)],180,'4g','24g','9g',18)
        ])
      ]
    },
    women_40:{
      nameAr:'المرأة فوق الأربعين',nameEn:'Women Over 40',dailyCalories:1700,dailyCarbs:'170g',dailyProtein:'90g',dailyFat:'60g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','زبادي يوناني بالمكسرات واللوز','Greek yogurt with nuts and almonds',[ing('زبادي يوناني','Greek Yogurt','170 جم / 170g',170),ing('لوز','Almonds','15 جم / 15g',15),ing('مكسرات مشكلة','Mixed Nuts','10 جم / 10g',10)],300,'16g','20g','16g',34),
          meal('غداء','Lunch','1:00 PM','سلمون مشوي مع خضار وأرز بني','Grilled salmon with vegetables and brown rice',[ing('سلمون','Salmon','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],480,'40g','40g','20g',92),
          meal('عشاء','Dinner','7:00 PM','دجاج بالخضار','Chicken with vegetables',[ing('صدر فراخ طازج','Chicken Breast','160 جم / 160g',160),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],320,'36g','12g','10g',48),
          meal('سناك','Snack','4:00 PM','جبنة قريش بالطماطم','Cottage cheese with tomato',[ing('جبنة قريش','Cottage Cheese','80 جم / 80g',80),ing('طماطم','Tomatoes','حبة / 1 piece',100)],140,'12g','8g','5g',18)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مع جبنة بيضاء وخبز أسمر','Eggs with white cheese and brown bread',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60)],340,'22g','32g','14g',24),
          meal('غداء','Lunch','1:00 PM','صدر دجاج مشوي مع بروكلي وأرز بني','Grilled chicken breast with broccoli and brown rice',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('بروكلي','Broccoli','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],440,'44g','38g','9g',56),
          meal('عشاء','Dinner','7:00 PM','شوربة عدس','Lentil soup',[ing('عدس','Lentils','180 جم / 180g',180)],240,'14g','38g','2g',12),
          meal('سناك','Snack','4:00 PM','زبادي بالتوت','Yogurt with berries',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('توت مشكل','Mixed Berries','60 جم / 60g',60)],140,'6g','16g','4g',22)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان باللبن والمكسرات','Oats with milk and nuts',[ing('شوفان','Oats','40 جم / 40g',40),ing('لبن','Milk','180 مل / 180ml',180),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],340,'14g','48g','10g',22),
          meal('غداء','Lunch','1:00 PM','سمك مشوي مع سبانخ وأرز بني','Grilled fish with spinach and brown rice',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('سبانخ','Spinach','100 جم / 100g',100),ing('أرز بني','Brown Rice','100 جم / 100g',100)],420,'40g','40g','8g',56),
          meal('عشاء','Dinner','7:00 PM','كفتة مشوية قليلة الدهن مع خضار','Lean grilled kofta with vegetables',[ing('لحمة مفرومة','Ground Beef','130 جم / 130g',130),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],340,'28g','12g','18g',52),
          meal('سناك','Snack','4:00 PM','لوز وجبنة','Almonds and cheese',[ing('لوز','Almonds','15 جم / 15g',15),ing('جبنة قريش','Cottage Cheese','50 جم / 50g',50)],150,'9g','5g','10g',16)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','عجة بالجبنة والسبانخ','Cheese and spinach omelette',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('جبنة بيضاء','White Cheese','30 جم / 30g',30),ing('سبانخ','Spinach','60 جم / 60g',60)],300,'20g','6g','22g',22),
          meal('غداء','Lunch','1:00 PM','فراخ بالخضار المشوية','Chicken with grilled vegetables',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],380,'42g','16g','12g',52),
          meal('عشاء','Dinner','7:00 PM','سلطة تونة بالحمص والخضار','Tuna salad with chickpeas and vegetables',[ing('تونة','Tuna','100 جم / 100g',100),ing('حمص حب','Chickpeas','80 جم / 80g',80),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],340,'30g','28g','10g',42),
          meal('سناك','Snack','4:00 PM','تفاح ولوز','Apple and almonds',[ing('تفاح','Apple','حبة / 1 piece',150),ing('لوز','Almonds','15 جم / 15g',15)],180,'4g','24g','9g',18)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','زبادي يوناني بالعسل','Greek yogurt with honey',[ing('زبادي يوناني','Greek Yogurt','170 جم / 170g',170),ing('عسل نحل','Honey','ملعقة / 1 tbsp',20)],220,'13g','24g','5g',30),
          meal('غداء','Lunch','1:00 PM','لحمة مشوية قليلة الدهن مع خضار وأرز بني','Lean grilled beef with vegetables and brown rice',[ing('لحمة كندوز','Beef','140 جم / 140g',140),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],440,'32g','40g','15g',62),
          meal('عشاء','Dinner','7:00 PM','سمك بالفرن مع بروكلي','Baked fish with broccoli',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('بروكلي','Broccoli','150 جم / 150g',150)],300,'38g','10g','8g',50),
          meal('سناك','Snack','4:00 PM','جبنة قريش','Cottage cheese',[ing('جبنة قريش','Cottage Cheese','80 جم / 80g',80)],80,'9g','3g','3g',14)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور متكامل (بيض وجبنة وخضار)','Balanced breakfast (eggs, cheese, vegetables)',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('جبنة بيضاء','White Cheese','30 جم / 30g',30),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80)],300,'22g','12g','20g',24),
          meal('غداء','Lunch','2:00 PM','فراخ مشوية كاملة مع خضار وأرز بني','Whole grilled chicken with vegetables and brown rice',[ing('فرخة كاملة','Whole Chicken','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],460,'46g','40g','12g',58),
          meal('عشاء','Dinner','8:00 PM','سمك السلمون بالليمون','Salmon with lemon',[ing('سلمون','Salmon','160 جم / 160g',160),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],380,'34g','8g','20g',82),
          meal('سناك','Snack','5:00 PM','مكسرات مشكلة','Mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],130,'4g','5g','11g',14)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالأفوكادو والجبنة','Eggs with avocado and cheese',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('أفوكادو','Avocado','نصف حبة / half',80),ing('جبنة بيضاء','White Cheese','20 جم / 20g',20)],320,'18g','8g','24g',24),
          meal('غداء','Lunch','1:00 PM','عدس بالخضار','Lentils with vegetables',[ing('عدس','Lentils','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],280,'16g','44g','3g',16),
          meal('عشاء','Dinner','7:00 PM','جمبري بالثوم مع سلطة','Garlic shrimp with salad',[ing('جمبري','Shrimp','150 جم / 150g',150),ing('سلطة خضراء','Green Salad','100 جم / 100g',100),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],260,'28g','8g','12g',82),
          meal('سناك','Snack','4:00 PM','زبادي بالمكسرات','Yogurt with nuts',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('مكسرات مشكلة','Mixed Nuts','10 جم / 10g',10)],140,'7g','9g','8g',20)
        ])
      ]
    },
    men:{
      nameAr:'الرجل',nameEn:'Men',dailyCalories:2400,dailyCarbs:'250g',dailyProtein:'130g',dailyFat:'80g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالجبنة والخبز الأسمر','Eggs with cheese and brown bread',[ing('بيض أحمر','Eggs','4 بيضات / 4 eggs',240),ing('جبنة بيضاء','White Cheese','50 جم / 50g',50),ing('عيش أسمر','Brown Bread','رغيف / 1 loaf',120)],560,'34g','56g','22g',36),
          meal('غداء','Lunch','1:00 PM','صدر فراخ كبير مع أرز وخضار','Large chicken breast with rice and vegetables',[ing('صدر فراخ طازج','Chicken Breast','250 جم / 250g',250),ing('أرز أبيض','White Rice','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],680,'58g','78g','12g',75),
          meal('عشاء','Dinner','7:00 PM','لحمة مشوية مع بطاطا وخضار','Grilled beef with potato and vegetables',[ing('لحمة كندوز','Beef','200 جم / 200g',200),ing('بطاطس مسلوقة','Boiled Potato','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],620,'42g','62g','24g',92),
          meal('سناك','Snack','4:00 PM','زبادي بالمكسرات وموز','Yogurt with nuts and banana',[ing('زبادي','Plain Yogurt','170 جم / 170g',170),ing('مكسرات مشكلة','Mixed Nuts','25 جم / 25g',25),ing('موز','Banana','حبة / 1 piece',120)],340,'12g','44g','13g',28)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان بالحليب كامل الدسم والموز والمكسرات','Oats with whole milk, banana and nuts',[ing('شوفان','Oats','70 جم / 70g',70),ing('لبن','Milk','250 مل / 250ml',250),ing('موز','Banana','حبة / 1 piece',120),ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],560,'22g','82g','16g',32),
          meal('غداء','Lunch','1:00 PM','كفتة مشوية مع أرز وسلطة','Grilled kofta with rice and salad',[ing('لحمة مفرومة','Ground Beef','220 جم / 220g',220),ing('أرز أبيض','White Rice','180 جم / 180g',180),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],640,'46g','66g','24g',88),
          meal('عشاء','Dinner','7:00 PM','سمك مع بطاطا مسلوقة وخضار','Fish with boiled potato and vegetables',[ing('سمك بلطي','Tilapia Fish','220 جم / 220g',220),ing('بطاطس مسلوقة','Boiled Potato','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],480,'46g','44g','12g',68),
          meal('سناك','Snack','4:00 PM','بيض مسلوق ومكسرات','Boiled eggs and nuts',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],280,'16g','6g','22g',20)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','عجة كبيرة بالجبنة واللحم','Large omelette with cheese and beef',[ing('بيض أحمر','Eggs','4 بيضات / 4 eggs',240),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('لحمة مفرومة','Ground Beef','60 جم / 60g',60)],540,'38g','6g','40g',48),
          meal('غداء','Lunch','1:00 PM','ريب آي مع أرز وخضار','Ribeye steak with rice and vegetables',[ing('لحم ريب آي','Ribeye Steak','220 جم / 220g',220),ing('أرز أبيض','White Rice','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],720,'50g','66g','32g',118),
          meal('عشاء','Dinner','7:00 PM','فراخ مشوية مع بطاطا','Grilled chicken with potato',[ing('صدر فراخ طازج','Chicken Breast','220 جم / 220g',220),ing('بطاطس مسلوقة','Boiled Potato','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],560,'50g','56g','12g',68),
          meal('سناك','Snack','4:00 PM','زبادي بروتين وفواكه','Protein yogurt with fruit',[ing('زبادي يوناني','Greek Yogurt','200 جم / 200g',200),ing('موز','Banana','حبة / 1 piece',120)],260,'16g','36g','4g',34)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','توست بالجبنة والبيض','Toast with cheese and eggs',[ing('عيش فينو','White Bread','رغيف / 1 loaf',100),ing('جبنة بيضاء','White Cheese','50 جم / 50g',50),ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180)],560,'32g','52g','24g',36),
          meal('غداء','Lunch','1:00 PM','سمك مع أرز بني وخضار','Fish with brown rice and vegetables',[ing('سمك بلطي','Tilapia Fish','220 جم / 220g',220),ing('أرز بني','Brown Rice','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],540,'50g','60g','10g',70),
          meal('عشاء','Dinner','7:00 PM','لحمة مفرومة مع مكرونة وخضار','Ground beef with pasta and vegetables',[ing('لحمة مفرومة','Ground Beef','200 جم / 200g',200),ing('مكرونة','Pasta','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],660,'40g','78g','22g',80),
          meal('سناك','Snack','4:00 PM','مكسرات وموز','Nuts and banana',[ing('مكسرات مشكلة','Mixed Nuts','25 جم / 25g',25),ing('موز','Banana','حبة / 1 piece',120)],260,'6g','30g','14g',22)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بلحم مقدد وخبز أسمر','Eggs with beef bacon and brown bread',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('لحم مقدد بقري','Beef Bacon','50 جم / 50g',50),ing('عيش أسمر','Brown Bread','رغيف / 1 loaf',120)],580,'34g','56g','24g',42),
          meal('غداء','Lunch','1:00 PM','فراخ مشوية كبيرة مع أرز وسلطة','Large grilled chicken with rice and salad',[ing('صدر فراخ طازج','Chicken Breast','250 جم / 250g',250),ing('أرز أبيض','White Rice','200 جم / 200g',200),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],660,'58g','74g','12g',75),
          meal('عشاء','Dinner','7:00 PM','كباب مشوي مع خضار وأرز','Grilled kebab with vegetables and rice',[ing('لحم ضاني','Lamb','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز أبيض','White Rice','150 جم / 150g',150)],660,'44g','54g','30g',105),
          meal('سناك','Snack','4:00 PM','زبادي بالعسل والمكسرات','Yogurt with honey and nuts',[ing('زبادي','Plain Yogurt','170 جم / 170g',170),ing('عسل نحل','Honey','ملعقة / 1 tbsp',20),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],280,'10g','36g','10g',30)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور عائلي كبير (بيض وجبنة وفول وخبز)','Large family breakfast (eggs, cheese, foul, bread)',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('فول مدمس','Foul Medames','150 جم / 150g',150),ing('عيش بلدي','Baladi Bread','رغيف / 1 loaf',120)],680,'38g','78g','24g',40),
          meal('غداء','Lunch','2:00 PM','فراخ مشوية كاملة مع أرز وخضار','Whole grilled chicken with rice and vegetables',[ing('فرخة كاملة','Whole Chicken','280 جم / 280g',280),ing('أرز أبيض','White Rice','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],700,'60g','74g','16g',82),
          meal('عشاء','Dinner','8:00 PM','سمك بالفرن مع بطاطا','Baked fish with potato',[ing('سمك بلطي','Tilapia Fish','220 جم / 220g',220),ing('بطاطس مسلوقة','Boiled Potato','200 جم / 200g',200)],480,'46g','48g','10g',62),
          meal('سناك','Snack','5:00 PM','مكسرات مشكلة وتمر','Mixed nuts and dates',[ing('مكسرات مشكلة','Mixed Nuts','25 جم / 25g',25),ing('تمر','Dates','3 حبات / 3 pieces',45)],280,'6g','40g','12g',22)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان بالحليب والمكسرات والعسل','Oats with milk, nuts and honey',[ing('شوفان','Oats','70 جم / 70g',70),ing('لبن','Milk','250 مل / 250ml',250),ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20),ing('عسل نحل','Honey','ملعقة / 1 tbsp',20)],560,'20g','84g','16g',36),
          meal('غداء','Lunch','1:00 PM','لحمة مشوية مع أرز وخضار','Grilled beef with rice and vegetables',[ing('لحمة كندوز','Beef','220 جم / 220g',220),ing('أرز أبيض','White Rice','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],660,'46g','66g','26g',98),
          meal('عشاء','Dinner','7:00 PM','شوربة دجاج بالخضار مع خبز','Chicken vegetable soup with bread',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200),ing('عيش بلدي','Baladi Bread','نصف رغيف / half loaf',60)],460,'40g','54g','10g',52),
          meal('سناك','Snack','4:00 PM','بيض مسلوق وجبنة','Boiled eggs and cheese',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('جبنة بيضاء','White Cheese','30 جم / 30g',30)],230,'17g','2g','17g',20)
        ])
      ]
    },
    men_40:{
      nameAr:'الرجل فوق الأربعين',nameEn:'Men Over 40',dailyCalories:2100,dailyCarbs:'200g',dailyProtein:'120g',dailyFat:'70g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالجبنة والخبز الأسمر','Eggs with cheese and brown bread',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60)],420,'28g','36g','20g',30),
          meal('غداء','Lunch','1:00 PM','سمك مشوي مع أرز بني وخضار','Grilled fish with brown rice and vegetables',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('أرز بني','Brown Rice','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],500,'46g','54g','10g',62),
          meal('عشاء','Dinner','7:00 PM','صدر دجاج بالخضار','Chicken breast with vegetables',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],380,'44g','12g','12g',54),
          meal('سناك','Snack','4:00 PM','طماطم وجبنة','Tomato and cheese',[ing('طماطم','Tomatoes','2 حبة / 2 pieces',200),ing('جبنة قريش','Cottage Cheese','60 جم / 60g',60)],140,'10g','10g','5g',16)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان بالحليب قليل الدسم والمكسرات','Oats with low-fat milk and nuts',[ing('شوفان','Oats','50 جم / 50g',50),ing('لبن','Milk','200 مل / 200ml',200),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],380,'16g','58g','10g',22),
          meal('غداء','Lunch','1:00 PM','فراخ مشوية مع بروكلي وأرز بني','Grilled chicken with broccoli and brown rice',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('بروكلي','Broccoli','150 جم / 150g',150),ing('أرز بني','Brown Rice','120 جم / 120g',120)],460,'46g','44g','9g',56),
          meal('عشاء','Dinner','7:00 PM','شوربة عدس بالخضار','Lentil soup with vegetables',[ing('عدس','Lentils','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],280,'15g','44g','3g',16),
          meal('سناك','Snack','4:00 PM','زبادي بالتوت','Yogurt with berries',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('توت مشكل','Mixed Berries','60 جم / 60g',60)],140,'6g','16g','4g',22)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','بياض بيض بالخضار وخبز أسمر','Egg whites with vegetables and brown bread',[ing('بياض بيض','Egg Whites','4 بيضات / 4 whites',140),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60)],320,'26g','36g','4g',22),
          meal('غداء','Lunch','1:00 PM','سلمون مشوي مع خضار وأرز بني','Grilled salmon with vegetables and brown rice',[ing('سلمون','Salmon','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],540,'44g','40g','22g',98),
          meal('عشاء','Dinner','7:00 PM','كفتة مشوية قليلة الدهن مع سلطة','Lean grilled kofta with salad',[ing('لحمة مفرومة','Ground Beef','160 جم / 160g',160),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],360,'32g','8g','22g',60),
          meal('سناك','Snack','4:00 PM','مكسرات مشكلة قليلة','A small handful of mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],130,'4g','5g','11g',14)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','عجة بالطماطم والجبنة القريش','Tomato and cottage cheese omelette',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('جبنة قريش','Cottage Cheese','50 جم / 50g',50)],340,'26g','10g','22g',24),
          meal('غداء','Lunch','1:00 PM','فراخ بالخضار مع أرز بني','Chicken with vegetables and brown rice',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','120 جم / 120g',120)],460,'46g','46g','9g',58),
          meal('عشاء','Dinner','7:00 PM','سمك بالفرن بالليمون والأعشاب','Baked fish with lemon and herbs',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],360,'40g','12g','10g',52),
          meal('سناك','Snack','4:00 PM','تفاح ولوز','Apple and almonds',[ing('تفاح','Apple','حبة / 1 piece',150),ing('لوز','Almonds','15 جم / 15g',15)],180,'4g','24g','9g',18)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','زبادي يوناني بالمكسرات','Greek yogurt with nuts',[ing('زبادي يوناني','Greek Yogurt','170 جم / 170g',170),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],240,'15g','16g','13g',34),
          meal('غداء','Lunch','1:00 PM','لحمة مشوية قليلة الدهن مع خضار وأرز بني','Lean grilled beef with vegetables and brown rice',[ing('لحمة كندوز','Beef','160 جم / 160g',160),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],460,'36g','42g','16g',66),
          meal('عشاء','Dinner','7:00 PM','شوربة خضار بالدجاج','Chicken vegetable soup',[ing('صدر فراخ طازج','Chicken Breast','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],300,'34g','14g','7g',42),
          meal('سناك','Snack','4:00 PM','طماطم وجبنة قريش','Tomato and cottage cheese',[ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('جبنة قريش','Cottage Cheese','60 جم / 60g',60)],110,'9g','5g','4g',14)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور متوازن (بيض وجبنة وخبز أسمر وطماطم)','Balanced breakfast (eggs, cheese, brown bread, tomato)',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60),ing('طماطم','Tomatoes','حبة / 1 piece',100)],440,'30g','40g','20g',32),
          meal('غداء','Lunch','2:00 PM','فراخ مشوية كاملة مع أرز بني وسلطة','Whole grilled chicken with brown rice and salad',[ing('فرخة كاملة','Whole Chicken','230 جم / 230g',230),ing('أرز بني','Brown Rice','150 جم / 150g',150),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],540,'52g','52g','14g',66),
          meal('عشاء','Dinner','8:00 PM','سمك السلمون بالخضار','Salmon with vegetables',[ing('سلمون','Salmon','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],420,'38g','12g','22g',88),
          meal('سناك','Snack','5:00 PM','مكسرات مشكلة','Mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],130,'4g','5g','11g',14)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالأفوكادو','Eggs with avocado',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('أفوكادو','Avocado','نصف حبة / half',80)],280,'14g','8g','22g',20),
          meal('غداء','Lunch','1:00 PM','سمك مشوي مع خضار وأرز بني','Grilled fish with vegetables and brown rice',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','120 جم / 120g',120)],480,'46g','52g','9g',58),
          meal('عشاء','Dinner','7:00 PM','عدس بالخضار','Lentils with vegetables',[ing('عدس','Lentils','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],280,'16g','44g','3g',16),
          meal('سناك','Snack','4:00 PM','زبادي بالعسل','Yogurt with honey',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('عسل نحل','Honey','ملعقة / 1 tbsp',20)],150,'6g','20g','3g',20)
        ])
      ]
    },
    kids:{
      nameAr:'الأطفال',nameEn:'Kids',dailyCalories:1600,dailyCarbs:'210g',dailyProtein:'55g',dailyFat:'55g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:30 AM','بيض مسلوق مع توست وجبنة','Boiled eggs with toast and cheese',[ing('بيض أحمر','Eggs','بيضتان / 2 eggs',120),ing('عيش فينو','White Bread','رغيف صغير / 1 small loaf',60),ing('جبنة بيضاء','White Cheese','30 جم / 30g',30)],340,'18g','36g','12g',22),
          meal('غداء','Lunch','1:00 PM','صدر فراخ مشوي مع أرز وخضار ملونة','Grilled chicken breast with rice and colorful vegetables',[ing('صدر فراخ طازج','Chicken Breast','120 جم / 120g',120),ing('أرز أبيض','White Rice','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],420,'28g','52g','9g',42),
          meal('عشاء','Dinner','7:00 PM','مكرونة بالجبنة والخضار','Cheesy pasta with vegetables',[ing('مكرونة','Pasta','120 جم / 120g',120),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80)],380,'16g','54g','12g',30),
          meal('سناك','Snack','4:00 PM','موزة وحليب','Banana and milk',[ing('موز','Banana','حبة / 1 piece',120),ing('لبن','Milk','200 مل / 200ml',200)],220,'8g','36g','5g',18)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:30 AM','كورن فليكس بالحليب وموز','Corn flakes with milk and banana',[ing('كورن فليكس','Corn Flakes','40 جم / 40g',40),ing('لبن','Milk','200 مل / 200ml',200),ing('موز','Banana','حبة / 1 piece',120)],300,'10g','54g','5g',18),
          meal('غداء','Lunch','1:00 PM','كفتة صغيرة مع أرز وخضار','Small kofta with rice and vegetables',[ing('لحمة مفرومة','Ground Beef','100 جم / 100g',100),ing('أرز أبيض','White Rice','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80)],440,'22g','50g','16g',48),
          meal('عشاء','Dinner','7:00 PM','شوربة دجاج بالخضار مع توست','Chicken vegetable soup with toast',[ing('صدر فراخ طازج','Chicken Breast','80 جم / 80g',80),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100),ing('عيش فينو','White Bread','رغيف صغير / 1 small loaf',60)],320,'18g','40g','8g',26),
          meal('سناك','Snack','4:00 PM','زبادي بالفواكه','Yogurt with fruit',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('موز','Banana','نصف حبة / half',60)],150,'6g','20g','4g',20)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:30 AM','توست بالجبنة والعسل','Toast with cheese and honey',[ing('عيش فينو','White Bread','رغيف صغير / 1 small loaf',60),ing('جبنة بيضاء','White Cheese','30 جم / 30g',30),ing('عسل نحل','Honey','نصف ملعقة / half tbsp',10)],280,'12g','38g','9g',18),
          meal('غداء','Lunch','1:00 PM','سمك بالفرن مع بطاطا وخضار','Oven-baked fish with potato and vegetables',[ing('سمك بلطي','Tilapia Fish','100 جم / 100g',100),ing('بطاطس مسلوقة','Boiled Potato','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80)],340,'22g','44g','7g',32),
          meal('عشاء','Dinner','7:00 PM','بيض بالجبنة مع خبز','Eggs with cheese and bread',[ing('بيض أحمر','Eggs','بيضتان / 2 eggs',120),ing('جبنة بيضاء','White Cheese','30 جم / 30g',30),ing('عيش فينو','White Bread','رغيف صغير / 1 small loaf',60)],340,'18g','36g','14g',24),
          meal('سناك','Snack','4:00 PM','تفاح مقطع بالعسل','Sliced apple with honey',[ing('تفاح','Apple','حبة / 1 piece',150),ing('عسل نحل','Honey','نصف ملعقة / half tbsp',10)],110,'0g','28g','0g',14)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:30 AM','بيض مسلوق مع عصير برتقال طازج','Boiled eggs with fresh orange juice',[ing('بيض أحمر','Eggs','بيضتان / 2 eggs',120),ing('برتقال','Orange','حبتان / 2 pieces',300)],260,'14g','30g','8g',22),
          meal('غداء','Lunch','1:00 PM','فراخ بالخضار مع أرز','Chicken with vegetables and rice',[ing('صدر فراخ طازج','Chicken Breast','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100),ing('أرز أبيض','White Rice','120 جم / 120g',120)],420,'28g','52g','8g',42),
          meal('عشاء','Dinner','7:00 PM','مكرونة بصوص الطماطم والجبنة','Pasta with tomato sauce and cheese',[ing('مكرونة','Pasta','120 جم / 120g',120),ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('جبنة بيضاء','White Cheese','30 جم / 30g',30)],360,'14g','58g','10g',26),
          meal('سناك','Snack','4:00 PM','حليب بالكاكاو الطبيعي ومكسرات قليلة','Natural cocoa milk with a few nuts',[ing('لبن','Milk','200 مل / 200ml',200),ing('مكسرات مشكلة','Mixed Nuts','10 جم / 10g',10)],180,'8g','20g','8g',18)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:30 AM','شوفان بالحليب والعسل والفواكه','Oats with milk, honey and fruit',[ing('شوفان','Oats','40 جم / 40g',40),ing('لبن','Milk','180 مل / 180ml',180),ing('عسل نحل','Honey','نصف ملعقة / half tbsp',10),ing('موز','Banana','نصف حبة / half',60)],320,'12g','56g','6g',20),
          meal('غداء','Lunch','1:00 PM','كفتة مشوية صغيرة مع أرز وخضار','Small grilled kofta with rice and vegetables',[ing('لحمة مفرومة','Ground Beef','100 جم / 100g',100),ing('أرز أبيض','White Rice','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80)],440,'22g','50g','16g',48),
          meal('عشاء','Dinner','7:00 PM','شوربة خضار بالدجاج','Chicken vegetable soup',[ing('صدر فراخ طازج','Chicken Breast','80 جم / 80g',80),ing('خضار مشكلة','Mixed Vegetables','120 جم / 120g',120)],220,'16g','20g','6g',24),
          meal('سناك','Snack','4:00 PM','جبنة وتوست صغير','Cheese and small toast',[ing('جبنة بيضاء','White Cheese','30 جم / 30g',30),ing('عيش فينو','White Bread','نصف رغيف / half loaf',30)],160,'8g','16g','7g',14)
        ]),
        mk('الجمعة','Friday',[
          meal('إفطار','Breakfast','8:00 AM','فطور عائلي للأطفال (بيض وجبنة وعسل وتوست)','Family kids breakfast (eggs, cheese, honey, toast)',[ing('بيض أحمر','Eggs','بيضتان / 2 eggs',120),ing('جبنة بيضاء','White Cheese','30 جم / 30g',30),ing('عسل نحل','Honey','نصف ملعقة / half tbsp',10),ing('عيش فينو','White Bread','رغيف صغير / 1 small loaf',60)],380,'18g','42g','15g',26),
          meal('غداء','Lunch','1:30 PM','فراخ مشوية مع أرز وخضار ملونة','Grilled chicken with rice and colorful vegetables',[ing('صدر فراخ طازج','Chicken Breast','130 جم / 130g',130),ing('أرز أبيض','White Rice','130 جم / 130g',130),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],440,'30g','54g','9g',44),
          meal('عشاء','Dinner','7:00 PM','بيتزا منزلية صحية بالخضار','Homemade healthy veggie pizza',[ing('عيش فينو','White Bread','رغيف / 1 loaf',100),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('خضار مشكلة','Mixed Vegetables','60 جم / 60g',60)],400,'16g','54g','13g',32),
          meal('سناك','Snack','5:00 PM','فاكهة موسمية','Seasonal fruit',[ing('تفاح','Apple','حبة / 1 piece',150)],80,'0g','21g','0g',10)
        ]),
        mk('السبت','Saturday',[
          meal('إفطار','Breakfast','8:00 AM','بان كيك الشوفان بالموز','Oat and banana pancakes',[ing('شوفان','Oats','40 جم / 40g',40),ing('موز','Banana','حبة / 1 piece',120),ing('بيض أحمر','Eggs','بيضة / 1 egg',60),ing('لبن','Milk','100 مل / 100ml',100)],340,'12g','52g','9g',22),
          meal('غداء','Lunch','1:00 PM','سمك بالفرن مع بطاطا وخضار','Baked fish with potato and vegetables',[ing('سمك بلطي','Tilapia Fish','100 جم / 100g',100),ing('بطاطس مسلوقة','Boiled Potato','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80)],340,'22g','44g','7g',32),
          meal('عشاء','Dinner','7:00 PM','مكرونة بالدجاج والخضار','Pasta with chicken and vegetables',[ing('مكرونة','Pasta','120 جم / 120g',120),ing('صدر فراخ طازج','Chicken Breast','80 جم / 80g',80),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80)],400,'22g','54g','10g',36),
          meal('سناك','Snack','4:00 PM','زبادي بالعسل والفواكه','Yogurt with honey and fruit',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('عسل نحل','Honey','نصف ملعقة / half tbsp',10),ing('موز','Banana','نصف حبة / half',60)],180,'6g','30g','4g',24)
        ])
      ]
    }
  };
}

// Resolves a test's why/whyAr field (which may be a flat string for
// diet-agnostic tests, or a {diet: reason, default: reason} map for tests
// whose rationale genuinely differs by diet/demographic) down to the one
// string relevant to the given diet.
function resolveLabWhy(field, diet) {
  if (typeof field === 'string') return field;
  return field[diet] || field.default;
}

// Same 9 diet/demographic keys as buildMealPlans() - each test is tagged
// with which diets it's actually relevant for ('all' = every diet), and
// carries diet-specific reasoning where the medical rationale genuinely
// differs (e.g. lipid profile matters for a different reason in Atkins vs
// Women 40+ vs general use) rather than showing the same Atkins-framed
// "why" text to every user regardless of their selected diet.
function buildLabTests() {
  return {
    lastUpdated:'2026-07-21',
    tests:[
      { id:'lipid', name:'Lipid Profile', nameAr:'دهون الدم الكاملة', urgent:true, frequency:'monthly', frequencyAr:'شهرياً', mokhtabar:150, alpha:200, labmed:180, diets:['all'],
        why:{ default:'Monitors cholesterol and heart health', atkins:'Essential for Atkins — monitors cholesterol changes from a high-fat diet', keto:'Essential for Keto — monitors cholesterol changes from a very high-fat diet', men_40:'Heart disease risk rises after 40 — track cholesterol closely', women_40:'Cholesterol often rises after menopause — important to monitor' },
        whyAr:{ default:'يراقب الكوليسترول وصحة القلب', atkins:'أساسي في Atkins — يراقب تغيرات الكوليسترول من نظام عالي الدهون', keto:'أساسي في Keto — يراقب تغيرات الكوليسترول من نظام عالي الدهون جداً', men_40:'خطر أمراض القلب يزيد بعد الأربعين — تابع الكوليسترول جيداً', women_40:'الكوليسترول غالباً يرتفع بعد سن اليأس — مهم المتابعة' } },
      { id:'kidney', name:'Kidney Function', nameAr:'وظائف الكلى', urgent:true, frequency:'quarterly', frequencyAr:'كل 3 أشهر', mokhtabar:200, alpha:252, labmed:230, diets:['atkins','keto','men','men_40'],
        why:{ default:'High-protein diets stress the kidneys — must monitor' },
        whyAr:{ default:'الأنظمة عالية البروتين تضغط على الكلى — يجب المتابعة' } },
      { id:'sugar', name:'Blood Sugar + HbA1c', nameAr:'سكر الدم + HbA1c', urgent:true, frequency:'quarterly', frequencyAr:'كل 3 أشهر', mokhtabar:80, alpha:110, labmed:90, diets:['all'],
        why:{ default:'Foundation for all diets — determines insulin resistance', diabetic:'Core test for managing diabetes — tracks long-term blood sugar control', kids:'Establishes a healthy baseline early and catches issues while easy to manage' },
        whyAr:{ default:'أساس كل الأنظمة — يحدد مستوى مقاومة الإنسولين', diabetic:'التحليل الأساسي لمتابعة السكري — يتابع التحكم طويل المدى في سكر الدم', kids:'يحدد خط أساس صحي مبكراً ويكشف أي مشكلة وهي لسه سهل التعامل معها' } },
      { id:'cbc', name:'CBC Complete Blood Count', nameAr:'صورة الدم الكاملة', urgent:false, frequency:'quarterly', frequencyAr:'كل 3 أشهر', mokhtabar:60, alpha:165, labmed:100, diets:['all'],
        why:{ default:'Detects anemia and general blood health issues', atkins:'Detects anemia common when cutting carbs', keto:'Detects anemia common when cutting carbs', women:'Iron-deficiency anemia is common in women — this test catches it early', women_40:'Iron-deficiency anemia is common in women — this test catches it early', kids:'Screens for anemia, which affects growth and concentration in children' },
        whyAr:{ default:'يكشف الأنيميا ومشاكل الدم العامة', atkins:'يكشف الأنيميا الشائعة عند تقليل الكربوهيدرات', keto:'يكشف الأنيميا الشائعة عند تقليل الكربوهيدرات', women:'أنيميا نقص الحديد شائعة عند النساء — هذا التحليل يكشفها مبكراً', women_40:'أنيميا نقص الحديد شائعة عند النساء — هذا التحليل يكشفها مبكراً', kids:'يكشف الأنيميا التي تؤثر على النمو والتركيز عند الأطفال' } },
      { id:'liver', name:'Liver Function', nameAr:'وظائف الكبد', urgent:false, frequency:'quarterly', frequencyAr:'كل 3 أشهر', mokhtabar:150, alpha:300, labmed:250, diets:['all'],
        why:{ default:'General liver health check', atkins:'The liver works hard during ketosis and high-fat digestion', keto:'The liver works hard during ketosis and high-fat digestion' },
        whyAr:{ default:'فحص عام لصحة الكبد', atkins:'الكبد يعمل بشكل مكثف أثناء الكيتوسيس وهضم الدهون العالية', keto:'الكبد يعمل بشكل مكثف أثناء الكيتوسيس وهضم الدهون العالية' } },
      { id:'thyroid', name:'Thyroid TSH+T3+T4', nameAr:'هرمونات الغدة الدرقية', urgent:false, frequency:'quarterly', frequencyAr:'كل 3 أشهر', mokhtabar:150, alpha:175, labmed:160, diets:['all'],
        why:{ default:'Thyroid issues prevent weight loss/health goals despite a perfect diet', women_40:'Thyroid problems become more common around menopause and affect weight and energy' },
        whyAr:{ default:'مشاكل الغدة تمنع تحقيق أهدافك الصحية حتى مع أفضل نظام', women_40:'مشاكل الغدة الدرقية تصبح أكثر شيوعاً حول سن اليأس وتؤثر على الوزن والطاقة' } },
      { id:'vitamins', name:'Vit D + B12 + Magnesium', nameAr:'فيتامين د + ب12 + مغنيسيوم', urgent:false, frequency:'yearly', frequencyAr:'سنوياً', mokhtabar:350, alpha:450, labmed:400, diets:['all'],
        why:{ default:'Very common deficiencies in Egypt despite sunshine', women_40:'Vitamin D is essential for bone density, which declines faster after menopause', kids:'Supports healthy growth, bones and energy in growing children', diabetic:'Magnesium deficiency is common in diabetics and affects insulin function' },
        whyAr:{ default:'نقص شائع جداً في مصر رغم الشمس', women_40:'فيتامين د أساسي لكثافة العظام التي تقل بسرعة أكبر بعد سن اليأس', kids:'يدعم النمو الصحي والعظام والطاقة عند الأطفال', diabetic:'نقص الماغنسيوم شائع عند مرضى السكري ويؤثر على وظيفة الإنسولين' } },
      { id:'urine', name:'Complete Urine Analysis', nameAr:'تحليل بول كامل', urgent:true, frequency:'monthly', frequencyAr:'شهرياً', mokhtabar:20, alpha:50, labmed:35, diets:['atkins','keto'],
        why:{ default:'Detects ketones — confirms successful ketosis' },
        whyAr:{ default:'يكشف الكيتونات — يؤكد نجاح الكيتوسيس' } },
      { id:'psa', name:'PSA (Prostate-Specific Antigen)', nameAr:'مستضد البروستاتا النوعي PSA', urgent:true, frequency:'yearly', frequencyAr:'سنوياً', mokhtabar:180, alpha:220, labmed:200, diets:['men_40'],
        why:{ default:'Standard prostate health screening recommended for men over 40' },
        whyAr:{ default:'فحص روتيني لصحة البروستاتا موصى به للرجال فوق الأربعين' } },
      { id:'bone_panel', name:'Bone Health Panel (Calcium + Phosphorus + ALP)', nameAr:'فحص صحة العظام (كالسيوم + فوسفور + ALP)', urgent:false, frequency:'yearly', frequencyAr:'سنوياً', mokhtabar:220, alpha:280, labmed:250, diets:['women_40'],
        why:{ default:'Bone density loss accelerates around and after menopause - this catches early signs' },
        whyAr:{ default:'فقدان كثافة العظام يتسارع حول سن اليأس وبعده — يكشف هذا الفحص العلامات المبكرة' } },
      { id:'growth_screen', name:'Iron & Growth Screening', nameAr:'فحص الحديد والنمو', urgent:false, frequency:'quarterly', frequencyAr:'كل 3 أشهر', mokhtabar:60, alpha:165, labmed:100, diets:['kids'],
        why:{ default:'Iron deficiency is common in children and affects growth, focus and energy' },
        whyAr:{ default:'نقص الحديد شائع عند الأطفال ويؤثر على النمو والتركيز والطاقة' } },
    ]
  };
}

// Same 9 diet/demographic keys as buildMealPlans() - the Activity tab was
// previously one hardcoded weekly schedule (Sun=Walk, Mon=Exercise, etc,
// literally baked into the HTML, never varying by diet) plus one generic
// beginner/intermediate/advanced exercise list shown to everyone. Both are
// now genuinely tailored per diet/demographic, matching the same pattern
// already applied to meal plans, supplements and lab tests.
function buildActivityPlans() {
  // Called as day(icon, englishText, arabicText, cal, duration, isRest) at every
  // call site below - map them into the correctly-named fields here rather
  // than renaming all call sites.
  const day = (icon, activityEn, activity, cal, duration, isRest) => ({ icon, activity, activityEn, cal, duration, isRest: !!isRest });

  return {
    atkins: {
      week: [
        day('🚶','Walk','مشي سريع',180,'30 min'), day('🏋️','Resistance Training','تمارين مقاومة',320,'45 min'), day('🧘','Rest','راحة',0,'-',true),
        day('🚶','Walk','مشي سريع',180,'30 min'), day('🏋️','Resistance Training','تمارين مقاومة',320,'45 min'), day('🧘','Rest','راحة',0,'-',true), day('🔥','HIIT','HIIT',220,'20 min')
      ],
      levels: {
        beginner: [ ['🚶','Brisk Walk','مشي سريع','30 min morning fasted walk — burns 20% more fat','30 دقيقة صباحاً على الريق — يسرع حرق الدهون 20%','180 kcal','30 min'], ['🧘','Stretching','إطالة وتنفس','15 min — flexibility and reducing keto fatigue','15 دقيقة — مرونة وتقليل إرهاق الكيتو','40 kcal','15 min'], ['💧','Daily Hydration','ترطيب يومي','2.5L water + salt and lemon as natural electrolyte','2.5 لتر ماء + ملح وليمون كإلكتروليت طبيعي','Essential','All day'] ],
        intermediate: [ ['🏋️','Resistance Training','تمارين مقاومة','Squats + Push-ups + Pull-ups — 3 sets × 12 reps','سكوات + ضغط + عقلة — 3 جولات × 12 تكرار','320 kcal','45 min'], ['🔥','Light HIIT','HIIT خفيف','20s work / 40s rest × 8 rounds','20 ثانية شغل / 40 راحة × 8 دورات','180 kcal','20 min'], ['🧘','Post-workout Stretch','إطالة بعد التمرين','15 min main muscle groups','15 دقيقة للعضلات الرئيسية','30 kcal','15 min'] ],
        advanced: [ ['🏋️','Full Weight Training','تمارين حديد شاملة','Chest + Back + Shoulders — 4 sets × 10 reps heavy','صدر + ظهر + أكتاف — 4 جولات × 10 تكرار بأوزان ثقيلة','450 kcal','60 min'], ['🔥','Intense HIIT','HIIT مكثف','30s work / 15s rest × 12 rounds','30 ثانية شغل / 15 راحة × 12 دورة','280 kcal','25 min'], ['🧘','Full Cool-down','تبريد وإطالة كاملة','15 min stretching + deep breathing','15 دقيقة إطالة + تنفس عميق','30 kcal','15 min'] ]
      }
    },
    keto: {
      week: [
        day('🚶','Fasted Walk','مشي على الريق',180,'30 min'), day('🏋️','Resistance Training','تمارين مقاومة',320,'45 min'), day('🧘','Rest','راحة',0,'-',true),
        day('🧘‍♀️','Stretch','إطالة',40,'15 min'), day('🏋️','Resistance Training','تمارين مقاومة',320,'45 min'), day('🧘','Rest','راحة',0,'-',true), day('🚶','Walk','مشي',180,'30 min')
      ],
      levels: {
        beginner: [ ['🚶','Fasted Morning Walk','مشي صباحي على الريق','30 min walk before eating — supports fat-burning in ketosis','30 دقيقة مشي قبل الأكل — يدعم حرق الدهون في الكيتوسيس','180 kcal','30 min'], ['🧂','Electrolyte Check-in','متابعة الأملاح','Make sure you had your electrolytes today to avoid keto flu','تأكد إنك اخدت أملاحك النهارده عشان تتجنب أنفلونزا الكيتو','—','—'], ['🧘','Stretching','إطالة وتنفس','15 min — helps with early-ketosis fatigue','15 دقيقة — تساعد في إرهاق بداية الكيتوسيس','40 kcal','15 min'] ],
        intermediate: [ ['🏋️','Resistance Training','تمارين مقاومة','Squats + Push-ups + Pull-ups — 3 sets × 12 reps, fat adapts well to this once keto-adapted','سكوات + ضغط + عقلة — 3 جولات × 12 تكرار، الجسم يتأقلم جيداً بعد الكيتو أدابتيشن','320 kcal','45 min'], ['🚶','Steady Cardio','كارديو ثابت','Low-intensity cardio burns fat efficiently in ketosis','كارديو خفيف الشدة يحرق الدهون بكفاءة في الكيتوسيس','200 kcal','30 min'], ['🧘','Post-workout Stretch','إطالة بعد التمرين','15 min main muscle groups','15 دقيقة للعضلات الرئيسية','30 kcal','15 min'] ],
        advanced: [ ['🏋️','Full Weight Training','تمارين حديد شاملة','Chest + Back + Shoulders — 4 sets × 10 reps heavy','صدر + ظهر + أكتاف — 4 جولات × 10 تكرار بأوزان ثقيلة','450 kcal','60 min'], ['🔥','Moderate HIIT','HIIT متوسط','Keep HIIT moderate on keto — very intense HIIT can be harder without carbs for quick fuel','خلي الـ HIIT متوسط في الكيتو — الشديد جداً بيكون أصعب من غير كربوهيدرات للطاقة السريعة','240 kcal','20 min'], ['🧘','Full Cool-down','تبريد وإطالة كاملة','15 min stretching + deep breathing','15 دقيقة إطالة + تنفس عميق','30 kcal','15 min'] ]
      }
    },
    mediterranean: {
      week: [
        day('🚶','Walk','مشي',180,'30 min'), day('🏊','Cardio / Swim','كارديو / سباحة',250,'30 min'), day('🧘','Rest','راحة',0,'-',true),
        day('🚶','Walk','مشي',180,'30 min'), day('🏋️','Light Resistance','تمارين مقاومة خفيفة',280,'40 min'), day('🧘‍♀️','Stretch / Yoga','إطالة / يوجا',40,'15 min'), day('🚶','Walk','مشي',180,'30 min')
      ],
      levels: {
        beginner: [ ['🚶','Daily Walk','مشي يومي','30 min walk — the backbone of the Mediterranean active lifestyle','30 دقيقة مشي — أساس نمط الحياة النشط المتوسطي','180 kcal','30 min'], ['🏊','Light Swim','سباحة خفيفة','Gentle swimming is easy on joints and great for heart health','السباحة الخفيفة سهلة على المفاصل ورائعة لصحة القلب','220 kcal','30 min'], ['🧘‍♀️','Stretch','إطالة','15 min gentle stretching','15 دقيقة إطالة خفيفة','30 kcal','15 min'] ],
        intermediate: [ ['🏋️','Light Resistance Training','تمارين مقاومة خفيفة','Bodyweight squats + push-ups — 3 sets × 12 reps','سكوات + ضغط بوزن الجسم — 3 جولات × 12 تكرار','280 kcal','40 min'], ['🏊','Cardio Swim','كارديو سباحة','30 min steady swimming or cycling','30 دقيقة سباحة أو دراجة ثابتة','280 kcal','30 min'], ['🧘‍♀️','Yoga','يوجا','20 min flexibility and relaxation','20 دقيقة مرونة واسترخاء','60 kcal','20 min'] ],
        advanced: [ ['🏋️','Full Resistance Circuit','دائرة تمارين شاملة','Full body circuit — 4 sets × 12 reps','دائرة تمارين للجسم كامل — 4 جولات × 12 تكرار','380 kcal','50 min'], ['🚴','Cycling / Hiking','دراجة / تسلق','45 min moderate-intensity cardio','45 دقيقة كارديو متوسط الشدة','400 kcal','45 min'], ['🧘‍♀️','Full Yoga Session','جلسة يوجا كاملة','30 min flexibility and breathing','30 دقيقة مرونة وتنفس','80 kcal','30 min'] ]
      }
    },
    diabetic: {
      week: [
        day('🚶','Walk','مشي',180,'30 min'), day('🚶','Walk','مشي',180,'30 min'), day('🏋️','Light Resistance','تمارين مقاومة خفيفة',250,'30 min'),
        day('🚶','Walk','مشي',180,'30 min'), day('🧘','Rest','راحة',0,'-',true), day('🚶','Walk','مشي',180,'30 min'), day('🏋️','Light Resistance','تمارين مقاومة خفيفة',250,'30 min')
      ],
      levels: {
        beginner: [ ['🚶','Post-meal Walk','مشي بعد الأكل','10-15 min walk after meals significantly helps blood sugar control','10-15 دقيقة مشي بعد الأكل تساعد جداً في التحكم بسكر الدم','80 kcal','15 min'], ['🚶','Daily Walk','مشي يومي','30 min walk — consistency matters more than intensity for blood sugar','30 دقيقة مشي — الانتظام أهم من الشدة للتحكم بالسكر','180 kcal','30 min'], ['🧘','Stretching','إطالة','15 min gentle stretching','15 دقيقة إطالة خفيفة','30 kcal','15 min'] ],
        intermediate: [ ['🏋️','Light Resistance Training','تمارين مقاومة خفيفة','Bodyweight exercises — 3 sets × 10 reps, improves insulin sensitivity','تمارين بوزن الجسم — 3 جولات × 10 تكرار، تحسن حساسية الإنسولين','250 kcal','30 min'], ['🚶','Brisk Walk','مشي سريع','35-40 min at a faster pace','35-40 دقيقة بخطى أسرع','220 kcal','35 min'], ['🧘','Post-workout Stretch','إطالة بعد التمرين','15 min main muscle groups','15 دقيقة للعضلات الرئيسية','30 kcal','15 min'] ],
        advanced: [ ['🏋️','Full Resistance Circuit','دائرة تمارين شاملة','Full body circuit — 3-4 sets × 12 reps','دائرة تمارين للجسم كامل — 3-4 جولات × 12 تكرار','350 kcal','45 min'], ['🚶','Extended Walk / Light Jog','مشي ممتد / هرولة خفيفة','40-45 min at a comfortable but steady pace','40-45 دقيقة بخطى مريحة وثابتة','300 kcal','40 min'], ['🧘','Full Cool-down','تبريد وإطالة كاملة','15 min stretching + deep breathing','15 دقيقة إطالة + تنفس عميق','30 kcal','15 min'] ]
      }
    },
    women: {
      week: [
        day('🚶','Walk','مشي',180,'30 min'), day('🏋️','Resistance Training','تمارين مقاومة',300,'40 min'), day('🧘','Rest','راحة',0,'-',true),
        day('🏊','Cardio','كارديو',220,'30 min'), day('🏋️','Resistance Training','تمارين مقاومة',300,'40 min'), day('🧘','Rest','راحة',0,'-',true), day('🚶','Walk','مشي',180,'30 min')
      ],
      levels: {
        beginner: [ ['🚶','Brisk Walk','مشي سريع','30 min walk — great low-impact start','30 دقيقة مشي — بداية رائعة قليلة التأثير على المفاصل','180 kcal','30 min'], ['🏋️','Bodyweight Basics','تمارين بوزن الجسم','Squats + glute bridges — 3 sets × 12 reps','سكوات + جسر الأرداف — 3 جولات × 12 تكرار','200 kcal','25 min'], ['🧘','Stretching','إطالة','15 min flexibility','15 دقيقة مرونة','30 kcal','15 min'] ],
        intermediate: [ ['🏋️','Resistance Training','تمارين مقاومة','Squats + lunges + rows — 3 sets × 12 reps, builds strength and bone density','سكوات + لانجز + تجديف — 3 جولات × 12 تكرار، يبني القوة وكثافة العظام','300 kcal','40 min'], ['🏊','Cardio','كارديو','30 min swimming, cycling or brisk walking','30 دقيقة سباحة أو دراجة أو مشي سريع','220 kcal','30 min'], ['🧘','Post-workout Stretch','إطالة بعد التمرين','15 min main muscle groups','15 دقيقة للعضلات الرئيسية','30 kcal','15 min'] ],
        advanced: [ ['🏋️','Full Resistance Circuit','دائرة تمارين شاملة','Full body — 4 sets × 12 reps','الجسم كامل — 4 جولات × 12 تكرار','380 kcal','50 min'], ['🔥','HIIT','HIIT','20s work / 40s rest × 8 rounds','20 ثانية شغل / 40 راحة × 8 دورات','200 kcal','20 min'], ['🧘','Full Cool-down','تبريد وإطالة كاملة','15 min stretching + deep breathing','15 دقيقة إطالة + تنفس عميق','30 kcal','15 min'] ]
      }
    },
    women_40: {
      week: [
        day('🚶','Walk','مشي',180,'30 min'), day('🏋️','Bone-Health Resistance','تمارين مقاومة لصحة العظام',280,'40 min'), day('🧘','Rest','راحة',0,'-',true),
        day('🏊','Low-Impact Cardio','كارديو قليل التأثير',200,'30 min'), day('🏋️','Bone-Health Resistance','تمارين مقاومة لصحة العظام',280,'40 min'), day('🧘‍♀️','Stretch','إطالة',40,'15 min'), day('🚶','Walk','مشي',180,'30 min')
      ],
      levels: {
        beginner: [ ['🚶','Brisk Walk','مشي سريع','30 min walk — low-impact and joint-friendly','30 دقيقة مشي — قليل التأثير ولطيف على المفاصل','180 kcal','30 min'], ['🏋️','Weight-Bearing Basics','تمارين تحمل وزن أساسية','Bodyweight squats + wall push-ups — supports bone density','سكوات بوزن الجسم + ضغط على الحائط — يدعم كثافة العظام','180 kcal','25 min'], ['🧘‍♀️','Gentle Stretch','إطالة لطيفة','15 min flexibility, especially hips and back','15 دقيقة مرونة، خاصة الورك والظهر','30 kcal','15 min'] ],
        intermediate: [ ['🏋️','Bone-Health Resistance Training','تمارين مقاومة لصحة العظام','Squats + rows + light dumbbells — 3 sets × 12 reps, weight-bearing exercise slows bone density loss','سكوات + تجديف + أوزان خفيفة — 3 جولات × 12 تكرار، تمارين تحمل الوزن تبطئ فقدان كثافة العظام','280 kcal','40 min'], ['🏊','Low-Impact Cardio','كارديو قليل التأثير','30 min swimming or cycling — easier on joints than running','30 دقيقة سباحة أو دراجة — أسهل على المفاصل من الجري','200 kcal','30 min'], ['🧘‍♀️','Yoga','يوجا','20 min flexibility and balance, both decline with age','20 دقيقة مرونة وتوازن، كلاهما يقل مع العمر','50 kcal','20 min'] ],
        advanced: [ ['🏋️','Full Resistance Circuit','دائرة تمارين شاملة','Full body with moderate weights — 3-4 sets × 12 reps','الجسم كامل بأوزان متوسطة — 3-4 جولات × 12 تكرار','350 kcal','45 min'], ['🚶','Brisk Walk / Light Jog','مشي سريع / هرولة خفيفة','35-40 min steady-state cardio','35-40 دقيقة كارديو ثابت','280 kcal','35 min'], ['🧘‍♀️','Full Stretch & Balance','إطالة وتوازن كاملة','20 min stretching plus balance exercises to reduce fall risk','20 دقيقة إطالة وتمارين توازن لتقليل خطر السقوط','40 kcal','20 min'] ]
      }
    },
    men: {
      week: [
        day('🚶','Walk','مشي',200,'30 min'), day('🏋️','Heavy Resistance','تمارين مقاومة ثقيلة',400,'50 min'), day('🏋️','Heavy Resistance','تمارين مقاومة ثقيلة',400,'50 min'),
        day('🧘','Rest','راحة',0,'-',true), day('🏋️','Heavy Resistance','تمارين مقاومة ثقيلة',400,'50 min'), day('🔥','HIIT','HIIT',280,'25 min'), day('🧘','Rest','راحة',0,'-',true)
      ],
      levels: {
        beginner: [ ['🚶','Brisk Walk','مشي سريع','30 min walk to build a base fitness level','30 دقيقة مشي لبناء لياقة أساسية','200 kcal','30 min'], ['🏋️','Bodyweight Basics','تمارين بوزن الجسم','Push-ups + squats + planks — 3 sets × 12 reps','ضغط + سكوات + بلانك — 3 جولات × 12 تكرار','250 kcal','30 min'], ['🧘','Stretching','إطالة','15 min flexibility','15 دقيقة مرونة','30 kcal','15 min'] ],
        intermediate: [ ['🏋️','Resistance Training','تمارين مقاومة','Bench press + squats + rows — 3-4 sets × 10 reps','بنش برس + سكوات + تجديف — 3-4 جولات × 10 تكرار','380 kcal','45 min'], ['🔥','HIIT','HIIT','20s work / 40s rest × 10 rounds','20 ثانية شغل / 40 راحة × 10 دورات','250 kcal','25 min'], ['🧘','Post-workout Stretch','إطالة بعد التمرين','15 min main muscle groups','15 دقيقة للعضلات الرئيسية','30 kcal','15 min'] ],
        advanced: [ ['🏋️','Heavy Compound Lifts','رفعات مركبة ثقيلة','Squats + deadlifts + bench — 4-5 sets × 6-8 reps heavy','سكوات + ديدليفت + بنش — 4-5 جولات × 6-8 تكرار ثقيلة','500 kcal','60 min'], ['🔥','Intense HIIT','HIIT مكثف','30s work / 15s rest × 12 rounds','30 ثانية شغل / 15 راحة × 12 دورة','300 kcal','25 min'], ['🧘','Full Cool-down','تبريد وإطالة كاملة','15 min stretching + deep breathing','15 دقيقة إطالة + تنفس عميق','30 kcal','15 min'] ]
      }
    },
    men_40: {
      week: [
        day('🚶','Walk','مشي',200,'30 min'), day('🏋️','Moderate Resistance','تمارين مقاومة معتدلة',320,'40 min'), day('🏊','Cardio','كارديو',250,'30 min'),
        day('🧘','Rest','راحة',0,'-',true), day('🏋️','Moderate Resistance','تمارين مقاومة معتدلة',320,'40 min'), day('🏊','Cardio','كارديو',250,'30 min'), day('🧘','Rest','راحة',0,'-',true)
      ],
      levels: {
        beginner: [ ['🚶','Brisk Walk','مشي سريع','30 min walk — heart-healthy and joint-friendly','30 دقيقة مشي — صحي للقلب ولطيف على المفاصل','200 kcal','30 min'], ['🏋️','Bodyweight Basics','تمارين بوزن الجسم','Squats + push-ups — 3 sets × 12 reps, lighter than younger years to protect joints','سكوات + ضغط — 3 جولات × 12 تكرار، أخف من سنين الشباب لحماية المفاصل','220 kcal','30 min'], ['🧘','Stretching','إطالة','15 min flexibility, especially shoulders and hips','15 دقيقة مرونة، خاصة الأكتاف والورك','30 kcal','15 min'] ],
        intermediate: [ ['🏋️','Moderate Resistance Training','تمارين مقاومة معتدلة','Squats + rows + moderate dumbbells — 3 sets × 12 reps, preserves muscle without overloading joints','سكوات + تجديف + أوزان معتدلة — 3 جولات × 12 تكرار، يحافظ على العضلات من غير إجهاد المفاصل','320 kcal','40 min'], ['🏊','Cardio','كارديو','30 min swimming, cycling or brisk walking — protects the heart','30 دقيقة سباحة أو دراجة أو مشي سريع — يحمي القلب','250 kcal','30 min'], ['🧘','Post-workout Stretch','إطالة بعد التمرين','15 min main muscle groups','15 دقيقة للعضلات الرئيسية','30 kcal','15 min'] ],
        advanced: [ ['🏋️','Full Resistance Circuit','دائرة تمارين شاملة','Full body with moderate-heavy weights — 3-4 sets × 10 reps','الجسم كامل بأوزان متوسطة لثقيلة — 3-4 جولات × 10 تكرار','400 kcal','50 min'], ['🏊','Extended Cardio','كارديو ممتد','35-40 min steady-state cardio for heart health','35-40 دقيقة كارديو ثابت لصحة القلب','320 kcal','35 min'], ['🧘','Full Cool-down','تبريد وإطالة كاملة','15 min stretching + deep breathing','15 دقيقة إطالة + تنفس عميق','30 kcal','15 min'] ]
      }
    },
    kids: {
      week: [
        day('⚽','Outdoor Play','لعب في الهواء الطلق',150,'30 min'), day('🚴','Cycling','دراجة',150,'30 min'), day('🤸','Free Play','لعب حر',120,'30 min'),
        day('🏊','Swimming','سباحة',180,'30 min'), day('👨‍👩‍👧','Family Walk','مشي عائلي',120,'30 min'), day('⚽','Sports Practice','تدريب رياضي',180,'40 min'), day('🤸','Free Play','لعب حر',120,'30 min')
      ],
      levels: {
        beginner: [ ['🤸','Light Play','لعب خفيف','Running around, hopscotch, simple games — fun matters more than intensity','جري وحجلة وألعاب بسيطة — المتعة أهم من الشدة','120 kcal','30 min'], ['🚴','Bike Riding','ركوب الدراجة','A relaxed bike ride around the neighborhood','جولة هادئة بالدراجة حول الحي','150 kcal','30 min'], ['🧘','Stretch & Relax','إطالة واسترخاء','5-10 min simple stretches, keep it fun','5-10 دقائق إطالة بسيطة، خليها ممتعة','20 kcal','10 min'] ],
        intermediate: [ ['⚽','Active Play','لعب نشط','Football, tag, or jump rope with friends','كورة أو استغماية أو نط الحبل مع الأصحاب','180 kcal','30 min'], ['🏊','Swimming','سباحة','Great full-body activity, always with supervision','نشاط رائع للجسم كامل، دايماً تحت إشراف','180 kcal','30 min'], ['🚴','Cycling','دراجة','Moderate-pace bike ride','ركوب دراجة بسرعة متوسطة','160 kcal','30 min'] ],
        advanced: [ ['⚽','Sports Team Practice','تدريب فريق رياضي','Structured practice for a sport the child enjoys (football, swimming, gymnastics)','تدريب منظم لرياضة يحبها الطفل (كورة، سباحة، جمباز)','220 kcal','45 min'], ['🤸','Active Games Circuit','دائرة ألعاب نشطة','Mix of running, jumping and climbing games','خليط من الجري والقفز وألعاب التسلق','200 kcal','35 min'], ['🧘','Cool-down Stretch','إطالة تهدئة','10 min gentle stretching to finish','10 دقائق إطالة لطيفة للختام','20 kcal','10 min'] ]
      }
    },
  };
}

// ─── EMAIL ────────────────────────────────────────────────────────────────────
async function sendVerifyEmail(email, username, token) {
  const url = `https://diet.talabatito.com/diet/verify-email?token=${token}`;
  if (!GMAIL_USER || !GMAIL_PASS) {
    console.log(`[DEV] Verify URL for ${email}: ${url}`);
    return { dev: true };
  }
  try {
    const nodemailer = require('nodemailer');
    const t = nodemailer.createTransport({ host:'smtp.gmail.com', port:587, secure:false, auth:{ user:GMAIL_AUTH, pass:GMAIL_PASS } });
    await t.sendMail({
      from: `"DietHub" <${GMAIL_USER}>`,
      to: email,
      subject: 'تفعيل حساب DietHub / Verify your account',
      html: `<div dir="rtl" style="font-family:Cairo,sans-serif;max-width:500px;margin:auto;padding:32px;background:#f9f9f9;border-radius:16px">
        <h2 style="color:#2D6A4F">مرحباً ${username}! 🥗</h2>
        <p style="color:#555;line-height:1.6">اضغط على الزر التالي لتفعيل حسابك في DietHub والبدء في رحلتك الصحية.</p>
        <div style="text-align:center;margin:24px 0">
          <a href="${url}" style="background:linear-gradient(135deg,#C8F560,#A8E063);color:#1A1A2E;padding:14px 28px;border-radius:12px;text-decoration:none;font-weight:700;display:inline-block">تفعيل الحساب ←</a>
        </div>
        <p style="color:#999;font-size:0.78rem;text-align:center">الرابط صالح 24 ساعة · Link expires in 24 hours<br>
        Hello ${username}! Click above to verify your DietHub account.</p>
      </div>`
    });
    return { sent: true };
  } catch(e) { console.error('Email error:', e.message); return { error: e.message }; }
}

async function sendResetEmail(email, username, token) {
  const url = `https://diet.talabatito.com/diet/reset-password?token=${token}`;
  if (!GMAIL_USER || !GMAIL_PASS) {
    console.log(`[DEV] Reset URL for ${email}: ${url}`);
    return { dev: true };
  }
  try {
    const nodemailer = require('nodemailer');
    const t = nodemailer.createTransport({ host:'smtp.gmail.com', port:587, secure:false, auth:{ user:GMAIL_AUTH, pass:GMAIL_PASS } });
    await t.sendMail({
      from: `"DietHub" <${GMAIL_USER}>`,
      to: email,
      subject: 'Reset your DietHub password / إعادة تعيين كلمة المرور',
      html: `<div dir="rtl" style="font-family:Cairo,sans-serif;max-width:500px;margin:auto;padding:32px;background:#f9f9f9;border-radius:16px">
        <h2 style="color:#2D6A4F">إعادة تعيين كلمة المرور</h2>
        <p style="color:#555;line-height:1.6">مرحباً ${username}، اضغط على الزر التالي لإعادة تعيين كلمة مرورك.</p>
        <div style="text-align:center;margin:24px 0">
          <a href="${url}" style="background:linear-gradient(135deg,#C8F560,#A8E063);color:#1A1A2E;padding:14px 28px;border-radius:12px;text-decoration:none;font-weight:700;display:inline-block">إعادة تعيين كلمة المرور ←</a>
        </div>
        <p style="color:#999;font-size:0.78rem;text-align:center">الرابط صالح ساعة واحدة فقط · Link expires in 1 hour<br>
        Hello ${username}! Click above to reset your DietHub password.<br>
        If you did not request this, ignore this email.</p>
      </div>`
    });
    return { sent: true };
  } catch(e) { console.error('Reset email error:', e.message); return { error: e.message }; }
}
// ─── ROUTES ───────────────────────────────────────────────────────────────────
app.get(`${BASE}/login`, (req,res) => res.sendFile(path.join(__dirname,'public','login.html')));
app.get(`${BASE}/demo`, (req,res) => res.sendFile(path.join(__dirname,'public','demo.html')));
app.get(`${BASE}/payment`, (req,res) => res.sendFile(path.join(__dirname,'public','payment.html')));
app.get(`${BASE}/verify-pending`, (req,res) => res.sendFile(path.join(__dirname,'public','verify_pending.html')));
app.get(['/', BASE, `${BASE}/`], (req,res) => res.redirect(`${BASE}/dashboard`));
app.get(`${BASE}/dashboard`, auth, (req,res) => { res.setHeader('Cache-Control','no-store'); res.sendFile(path.join(__dirname,'public', req.user.role==='admin'?'admin.html':'dashboard.html')); });

// Verify email
app.get(`${BASE}/verify-email`, (req,res) => {
  const {token} = req.query;
  if (!token) return res.redirect(`${BASE}/login?error=invalid`);
  const pending = load('pending_verifications.json') || [];
  const rec = pending.find(p => p.token === token);
  if (!rec || Date.now() > rec.expiresAt) return res.redirect(`${BASE}/login?error=expired`);
  const users = load('users.json') || [];
  const idx = users.findIndex(u => u.id === rec.userId);
  if (idx < 0) return res.redirect(`${BASE}/login?error=notfound`);
  users[idx].emailVerified = true;
  save('users.json', users);
  save('pending_verifications.json', pending.filter(p => p.token !== token));
  secLog('EMAIL_VERIFIED', 'system', { userId: rec.userId });
  track('email_verified', { userId: rec.userId });
  const t = mkToken(users[idx]);
  res.setHeader('Set-Cookie', `dh_token=${t};path=/;max-age=28800;HttpOnly;SameSite=Strict`);
  res.redirect(`${BASE}/dashboard?verified=1`);
});

app.post(`${BASE}/resend-verification`, (req,res) => {
  const ip = getIP(req);
  const r = rateLimit(ip, 'resend', 3, 3600000);
  if (!r.ok) return res.status(429).json({error:'Too many resend attempts'});
  const {email} = req.body;
  const users = load('users.json') || [];
  const u = users.find(u => u.email === email && !u.emailVerified);
  if (!u) return res.json({ok:true}); // Don't leak
  const token = randToken();
  const pending = load('pending_verifications.json') || [];
  save('pending_verifications.json', [...pending.filter(p=>p.userId!==u.id), {userId:u.id,token,email,expiresAt:Date.now()+SEC.VERIFY_EXP}]);
  sendVerifyEmail(email, u.username, token);
  res.json({ok:true});
});

// LOGIN
app.post(`${BASE}/auth`, (req,res) => {
  const ip = getIP(req);
  const r = rateLimit(ip, 'login', SEC.LOGIN_MAX, SEC.LOGIN_WIN);
  if (!r.ok) {
    secLog('LOGIN_RATE_LIMITED', ip);
    return res.status(429).json({ error:`تم تجاوز عدد المحاولات. انتظر ${Math.ceil(r.wait/60)} دقيقة · Too many attempts. Wait ${Math.ceil(r.wait/60)} minutes`, retryAfter: r.wait });
  }
  const username = sanitize(req.body.username);
  const {password} = req.body;
  if (!username || !password) return res.status(400).json({error:'Missing fields'});
  const users = load('users.json') || [];
  // Check if user exists but is deactivated due to missing email/phone
  const uAll = users.find(u => u.username === username);
  if (uAll && !uAll.active && uAll.forcedReregistration) {
    return res.status(403).json({error:'حسابك موقوف مؤقتاً لاستكمال بيانات التسجيل (البريد الإلكتروني ورقم الهاتف مطلوبان) · Your account is suspended. Please re-register with your email and phone number to restore access.'});
  }
  const u = users.find(u => u.username === username && u.active);
  const valid = u ? checkPwd(password, u.password) : (crypto.randomBytes(32), false); // constant time
  if (!u || !valid) {
    secLog('LOGIN_FAILED', ip, {username});
    if (u) {
      const idx = users.findIndex(uu => uu.id === u.id);
      users[idx].loginAttempts = (users[idx].loginAttempts||0) + 1;
      if (users[idx].loginAttempts >= 10) { users[idx].active = false; secLog('ACCOUNT_LOCKED', ip, {username}); }
      save('users.json', users);
    }
    return res.status(401).json({error:'اسم المستخدم أو كلمة المرور غير صحيحة · Invalid credentials'});
  }
  const idx = users.findIndex(uu => uu.id === u.id);
  users[idx].loginAttempts = 0;
  users[idx].lastLogin = new Date().toISOString();
  save('users.json', users);
  rlReset(ip, 'login');
  secLog('LOGIN_OK', ip, {username});
  track('login', { userId: u.id, req });
  const tr = trial(u);
  res.json({token:mkToken(u), role:u.role, plan:u.plan, username:u.username, trial:tr, lang:u.lang||'ar', emailVerified:u.emailVerified});
});

// GOOGLE SIGN-IN — uses Google Identity Services (frontend gets an ID token
// via the Google button, sends it here). Verifies the token's signature
// server-side rather than trusting anything the client claims — the only
// thing pulled from it is the payload Google itself signed.
// SETUP REQUIRED: create an OAuth 2.0 Client ID at
// https://console.cloud.google.com/apis/credentials (Application type: Web,
// Authorized JavaScript origin: https://diet.talabatito.com), then set
// GOOGLE_CLIENT_ID in the container's environment. Until then this returns
// setupRequired:true and the frontend hides the button.
app.post(`${BASE}/api/auth/google`, async (req, res) => {
  const ip = getIP(req);
  if (!googleClient) return res.status(503).json({ error: 'Google Sign-In not configured', setupRequired: true });
  const r = rateLimit(ip, 'login', SEC.LOGIN_MAX, SEC.LOGIN_WIN);
  if (!r.ok) return res.status(429).json({ error: 'Too many attempts', retryAfter: r.wait });

  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: 'Missing credential' });

  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    payload = ticket.getPayload();
  } catch (e) {
    secLog('GOOGLE_AUTH_INVALID', ip, { error: e.message });
    return res.status(401).json({ error: 'Invalid Google token' });
  }
  if (!payload?.email || !payload.email_verified) {
    return res.status(403).json({ error: 'Google account email not verified' });
  }

  const email = payload.email.toLowerCase().trim();
  const users = load('users.json') || [];
  let user = users.find(u => u.email === email);

  if (!user) {
    // New signup via Google — email is already verified by Google, so skip
    // our own email-verification step. No phone/weight/height/age available
    // from Google — profile starts empty, same as any user would complete
    // later from the dashboard.
    // Google display names can contain anything (Arabic, emoji, punctuation)
    // — the rest of the app assumes usernames match SEC.USR_REGEX, so strip
    // to that character set rather than trust sanitize() alone (it only
    // blocks injection patterns, doesn't enforce the character class).
    let base = (payload.name || email.split('@')[0]).replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_.-]/g, '');
    if (base.length < SEC.USR_MIN) base = 'user' + randToken(2);
    base = base.slice(0, SEC.USR_MAX - 4); // leave room for a numeric suffix
    let username = base, n = 1;
    while (users.find(u => u.username === username)) username = `${base}${++n}`;

    user = {
      id: 'u' + Date.now() + randToken(4),
      username, password: hashPwd(randToken(24)), // unusable random password — this account only ever signs in via Google
      email, phone: '',
      role: 'user', plan: 'trial',
      created: new Date().toISOString().split('T')[0],
      active: true, emailVerified: true,
      trialStart: new Date().toISOString().split('T')[0],
      paid: false, lang: 'ar', loginAttempts: 0, lastLogin: null,
      googleAuth: true,
      profile: { diet: 'atkins', weight: null, height: null, age: null, gender: 'male', budget: 200, bodyFat: null, muscleMass: null, bmi: null, bmr: null }
    };
    users.push(user);
    save('users.json', users);
    secLog('REGISTERED_GOOGLE', ip, { username, email });

    const subs = load('subscriptions.json') || [];
    subs.push({ userId: user.id, plan: 'trial', startDate: user.created, endDate: new Date(Date.now() + TRIAL_DAYS * 86400000).toISOString().split('T')[0], amount: 0, status: 'trial' });
    save('subscriptions.json', subs);
  } else if (!user.active) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  const idx = users.findIndex(u => u.id === user.id);
  users[idx].lastLogin = new Date().toISOString();
  save('users.json', users);
  rlReset(ip, 'login');
  secLog('LOGIN_OK_GOOGLE', ip, { username: user.username });

  const tr = trial(user);
  res.json({ token: mkToken(user), role: user.role, plan: user.plan, username: user.username, trial: tr, lang: user.lang || 'ar', emailVerified: true });
});

// Facebook Login — frontend gets a short-lived user access token via the
// Facebook JS SDK's login popup, sends it here. Verified two ways server-side
// before it's trusted: debug_token confirms the token is genuinely valid and
// was actually issued for OUR app (not some other app's token), then /me
// fetches the profile the token is actually authorized to see.
app.post(`${BASE}/api/auth/facebook`, async (req, res) => {
  const ip = getIP(req);
  if (!FACEBOOK_APP_ID || !FACEBOOK_APP_SECRET) return res.status(503).json({ error: 'Facebook Login not configured', setupRequired: true });
  const r = rateLimit(ip, 'login', SEC.LOGIN_MAX, SEC.LOGIN_WIN);
  if (!r.ok) return res.status(429).json({ error: 'Too many attempts', retryAfter: r.wait });

  const { accessToken } = req.body;
  if (!accessToken) return res.status(400).json({ error: 'Missing accessToken' });

  let fbUser;
  try {
    const appToken = `${FACEBOOK_APP_ID}|${FACEBOOK_APP_SECRET}`;
    const debugRes = await fetch(`https://graph.facebook.com/debug_token?input_token=${encodeURIComponent(accessToken)}&access_token=${encodeURIComponent(appToken)}`);
    const debugData = await debugRes.json();
    if (!debugData.data?.is_valid || debugData.data.app_id !== FACEBOOK_APP_ID) {
      throw new Error('Token not valid for this app');
    }
    const meRes = await fetch(`https://graph.facebook.com/me?fields=id,name,email&access_token=${encodeURIComponent(accessToken)}`);
    fbUser = await meRes.json();
    if (!fbUser?.id) throw new Error('Could not fetch Facebook profile');
  } catch (e) {
    secLog('FACEBOOK_AUTH_INVALID', ip, { error: e.message });
    return res.status(401).json({ error: 'Invalid Facebook token' });
  }
  if (!fbUser.email) {
    return res.status(403).json({ error: 'يرجى السماح بمشاركة بريدك الإلكتروني من فيسبوك لإتمام التسجيل · Please allow email access from Facebook to complete signup' });
  }

  const email = fbUser.email.toLowerCase().trim();
  const users = load('users.json') || [];
  let user = users.find(u => u.email === email);

  if (!user) {
    // New signup via Facebook — same pattern as Google signup above: email
    // comes pre-verified by Facebook, no phone/weight/height/age available,
    // profile starts empty for the user to fill in later from the dashboard.
    let base = (fbUser.name || email.split('@')[0]).replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_.-]/g, '');
    if (base.length < SEC.USR_MIN) base = 'user' + randToken(2);
    base = base.slice(0, SEC.USR_MAX - 4);
    let username = base, n = 1;
    while (users.find(u => u.username === username)) username = `${base}${++n}`;

    user = {
      id: 'u' + Date.now() + randToken(4),
      username, password: hashPwd(randToken(24)), // unusable random password — this account only ever signs in via Facebook
      email, phone: '',
      role: 'user', plan: 'trial',
      created: new Date().toISOString().split('T')[0],
      active: true, emailVerified: true,
      trialStart: new Date().toISOString().split('T')[0],
      paid: false, lang: 'ar', loginAttempts: 0, lastLogin: null,
      facebookAuth: true,
      profile: { diet: 'atkins', weight: null, height: null, age: null, gender: 'male', budget: 200, bodyFat: null, muscleMass: null, bmi: null, bmr: null }
    };
    users.push(user);
    save('users.json', users);
    secLog('REGISTERED_FACEBOOK', ip, { username, email });

    const subs = load('subscriptions.json') || [];
    subs.push({ userId: user.id, plan: 'trial', startDate: user.created, endDate: new Date(Date.now() + TRIAL_DAYS * 86400000).toISOString().split('T')[0], amount: 0, status: 'trial' });
    save('subscriptions.json', subs);
  } else if (!user.active) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  const idx = users.findIndex(u => u.id === user.id);
  users[idx].lastLogin = new Date().toISOString();
  save('users.json', users);
  rlReset(ip, 'login');
  secLog('LOGIN_OK_FACEBOOK', ip, { username: user.username });

  const tr = trial(user);
  res.json({ token: mkToken(user), role: user.role, plan: user.plan, username: user.username, trial: tr, lang: user.lang || 'ar', emailVerified: true });
});

app.get(`${BASE}/logout`, (req,res) => {
  secLog('LOGOUT', getIP(req));
  res.setHeader('Set-Cookie','dh_token=;path=/;max-age=0;HttpOnly;SameSite=Strict');
  res.redirect(`${BASE}/login`);
});

// REGISTER
app.post(`${BASE}/register`, async (req,res) => {
  const ip = getIP(req);
  const r = rateLimit(ip, 'register', SEC.REG_MAX, SEC.REG_WIN);
  if (!r.ok) { secLog('REG_RATE_LIMITED',ip); return res.status(429).json({error:`لقد حاولت التسجيل أكثر من 7 مرات. انتظر 10 دقائق فقط وحاول مجدداً · You tried registering too many times. Please wait just 10 minutes and try again.`}); }

  const username = sanitize(req.body.username);
  const {password, email, phone, diet, weight, height, age, gender, budget, bodyFat, muscleMass} = req.body;

  if (username === null) return res.status(400).json({error:'Invalid characters in username'});
  const uErr = validateUsr(username); if (uErr) return res.status(400).json({error:uErr});
  const pErr = validatePwd(password); if (pErr) return res.status(400).json({error:pErr});
  if (!email) return res.status(400).json({error:'البريد الإلكتروني مطلوب · Email is required'});
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'صيغة البريد غير صحيحة · Invalid email'});
  const cleanEmail = sanitize(email.toLowerCase().trim());
  if (!cleanEmail) return res.status(400).json({error:'البريد الإلكتروني غير صالح · Invalid email'});
  if (!phone || phone.trim().length < 8) return res.status(400).json({error:'رقم الهاتف مطلوب · Phone number is required'});
  const users = load('users.json') || [];
  if (users.find(u=>u.username===username)) return res.status(400).json({error:'اسم المستخدم مستخدم · Username taken'});
  if (cleanEmail && users.find(u=>u.email===cleanEmail)) return res.status(400).json({error:'البريد الإلكتروني مستخدم · Email already registered'});

  const w = parseFloat(weight)||null, h = parseFloat(height)||null;
  const {bmi, bmr} = calcBmiBmr(w, h, age, gender);
  const newUser = {
    id: 'u'+Date.now()+randToken(4),
    username, password: hashPwd(password),
    email: cleanEmail, phone: sanitize(phone||'')||'',
    role:'user', plan:'trial',
    created: new Date().toISOString().split('T')[0],
    active:true, emailVerified: false,
    trialStart: new Date().toISOString().split('T')[0],
    paid:false, lang:'ar', loginAttempts:0, lastLogin:null,
    profile:{ diet:diet||'atkins', weight:w, height:h, age:parseInt(age)||null, gender:gender||'male', budget:parseInt(budget)||200, bodyFat:parseFloat(bodyFat)||null, muscleMass:parseFloat(muscleMass)||null, bmi, bmr }
  };
  users.push(newUser);
  save('users.json', users);
  secLog('REGISTERED', ip, {username, email:cleanEmail});
  // Captures utm_* from the register body so every signup is attributed to a
  // channel — the raw material for per-channel CAC.
  track('user_registered', { userId: newUser.id, req, props: { diet: newUser.profile.diet } });
  track('trial_started', { userId: newUser.id, req });

  // Email verification
  let emailSent = false;
  if (cleanEmail) {
    const vt = randToken();
    const pv = load('pending_verifications.json') || [];
    pv.push({userId:newUser.id, token:vt, email:cleanEmail, expiresAt:Date.now()+SEC.VERIFY_EXP, createdAt:new Date().toISOString()});
    save('pending_verifications.json', pv);
    const er = await sendVerifyEmail(cleanEmail, username, vt);
    emailSent = !er.error && !er.dev;
  }

  // Trial subscription
  const subs = load('subscriptions.json') || [];
  subs.push({userId:newUser.id, plan:'trial', startDate:newUser.created, endDate:new Date(Date.now()+TRIAL_DAYS*86400000).toISOString().split('T')[0], amount:0, status:'trial'});
  save('subscriptions.json', subs);

  // Always require email verification — never issue token on register
  res.json({ok:true, token:null, username:newUser.username, role:'user', plan:'trial', emailVerified:false, emailSent, requiresVerification:true, message:'تم إنشاء الحساب! تحقق من بريدك الإلكتروني لتفعيل الحساب · Account created! Please check your email to verify your account before logging in.'});
});

// USER API
app.get(`${BASE}/api/me`, auth, (req,res) => { const {password,...safe}=req.userObj; res.json({...safe, trial:req.trial, betaMode:BETA_MODE}); });
app.post(`${BASE}/api/profile`, auth, (req,res) => {
  const users = load('users.json')||[];
  const idx = users.findIndex(u=>u.id===req.user.id);
  if (idx<0) return res.status(404).json({});
  const ok = ['diet','budget','weight','height','age','gender','bodyFat','muscleMass','level'];
  const safe = {};
  for (const k of ok) if (req.body[k]!==undefined) safe[k]=req.body[k];
  users[idx].profile = {...users[idx].profile, ...safe};
  // Recompute BMI/BMR whenever weight/height/age/gender change, using the
  // merged (existing + just-updated) profile — not just whatever subset of
  // fields this particular request happened to include.
  const p = users[idx].profile;
  const {bmi, bmr} = calcBmiBmr(p.weight, p.height, p.age, p.gender);
  users[idx].profile.bmi = bmi;
  users[idx].profile.bmr = bmr;
  if (req.body.lang && ['ar','en'].includes(req.body.lang)) users[idx].lang=req.body.lang;
  save('users.json', users);
  res.json({ok:true, bmi, bmr});
});

// ─── UNIFIED HEALTH PROFILE (the hub) ─────────────────────────────────────────
// One consolidated view of the user's health: demographics, goals, derived
// energy/protein/hydration targets, latest wearable + lab signals, and risk
// flags. Read by the dashboard and (next) the AI coach.
app.get(`${BASE}/api/health-profile`, auth, (req,res) => {
  const profile = buildHealthProfile(store, req.user.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  track('health_profile_viewed', { userId: req.user.id });
  res.json(profile);
});
// Update the durable goal inputs that drive the targets above.
app.post(`${BASE}/api/health-profile/goals`, auth, (req,res) => {
  const { goalType, targetWeight, activityLevel } = req.body;
  const patch = {};
  if (goalType !== undefined) {
    if (!['lose','maintain','gain'].includes(goalType)) return res.status(400).json({ error: 'Invalid goalType' });
    patch.goalType = goalType;
  }
  if (activityLevel !== undefined) {
    if (!['sedentary','light','moderate','active','very_active'].includes(activityLevel)) return res.status(400).json({ error: 'Invalid activityLevel' });
    patch.activityLevel = activityLevel;
  }
  if (targetWeight !== undefined) {
    const tw = parseFloat(targetWeight);
    if (!Number.isFinite(tw) || tw < 30 || tw > 400) return res.status(400).json({ error: 'Invalid targetWeight' });
    patch.targetWeight = tw;
  }
  update('users.json', users => {
    const u = users.find(x => x.id === req.user.id);
    if (u) u.profile = { ...u.profile, ...patch };
    return users;
  }, []);
  res.json({ ok: true, profile: buildHealthProfile(store, req.user.id) });
});

// MEAL PLAN API
// Shared by /api/meal-plan and /api/meal-plan/swap so a static-plan meal and
// an AI-generated one get priced through the exact same logic.
const INGREDIENT_KEYWORD_MAP = {'فراخ':'chicken','دجاج':'chicken','صدر فراخ':'chicken','بيض':'eggs','سمك':'fish','بلطي':'fish','لحم':'beef','كندوز':'beef','مفروم':'beef','جبن':'cheese','قريش':'cheese','خضار':'veggies','كوسة':'veggies','أفوكادو':'avocado','زيتون':'olive_oil','مكسرات':'nuts','خيار':'cucumber','طماطم':'tomato'};

function findFoodItem(name, nameEn, foodPrices) {
  const items = foodPrices?.items || [];
  let item = items.find(i=>i.name===name||i.nameEn===nameEn);
  if (!item) {
    const nl = (name||'').toLowerCase();
    for (const [k,v] of Object.entries(INGREDIENT_KEYWORD_MAP)) {
      if (nl.includes(k)) { item = items.find(i=>i.id===v); if (item) break; }
    }
  }
  return item;
}

function priceMeal(meal, foodPrices) {
  let total = 0;
  const ings = meal.ingredients.map(ing => {
    const item = findFoodItem(ing.item, ing.itemEn, foodPrices);
    let price = 0, store = '';
    if (item) {
      const ps = [{s:'carrefour',p:item.carrefour},{s:'metro',p:item.metro},{s:'royal',p:item.royal},{s:'talabat',p:item.talabat}].filter(x=>x.p).sort((a,b)=>a.p-b.p);
      if (ps.length) { price = Math.round((ps[0].p/1000)*ing.grams); store = ps[0].s; }
      total += price;
    }
    return {...ing, price, bestStore: store};
  });
  const adj = Math.round(total) || meal.price;
  return {...meal, price: adj, ingredients: ings};
}

// budget thresholds tuned against the existing 50-1000 clamp range.
function budgetTierFor(budget) {
  if (budget < 150) return 'low';
  if (budget > 350) return 'high';
  return 'mid';
}

function getMealOverride(userId, date, mealType) {
  const all = load('meal_overrides.json') || {};
  return all[userId]?.[date]?.[mealType] || null;
}

function saveMealOverride(userId, date, mealType, entry) {
  const all = load('meal_overrides.json') || {};
  if (!all[userId]) all[userId] = {};
  if (!all[userId][date]) all[userId][date] = {};
  all[userId][date][mealType] = entry;
  save('meal_overrides.json', all);
}

const MEAL_TYPE_LABELS = {
  breakfast: { ar: 'إفطار', en: 'Breakfast', time: '7:00 AM' },
  lunch:     { ar: 'غداء',  en: 'Lunch',     time: '1:00 PM' },
  dinner:    { ar: 'عشاء',  en: 'Dinner',    time: '7:00 PM' },
  snack:     { ar: 'سناك',  en: 'Snack',     time: '4:00 PM' },
};

// Generates one meal via Claude, constrained to real priced ingredients so the
// result always flows through priceMeal()/findFoodItem() unchanged. Claude
// picks ingredients by "id" (from food_prices.json) rather than free-text
// names specifically so it can't hallucinate an ingredient that has no price
// data - the server looks the id up directly, guaranteeing a valid match.
const DIET_STYLE_LABELS = {
  atkins: 'Atkins (very low-carb)',
  keto: 'Ketogenic (very low-carb, high-fat)',
  mediterranean: 'Mediterranean',
  diabetic: 'diabetic-friendly (low glycemic, controlled-carb)',
  women: "general women's nutrition (balanced, iron and folate focused)",
  women_40: 'women over 40 (bone health, muscle preservation, balanced)',
  men: "general men's nutrition (higher protein and calories, balanced)",
  men_40: 'men over 40 (heart-healthy, prostate-friendly, muscle preservation)',
  kids: 'healthy kids (balanced growth nutrition, kid-friendly, no severe restriction)',
};

async function generateMealAlternative(dietStyle, mealType, budgetTier, preference, foodPrices) {
  const label = MEAL_TYPE_LABELS[mealType] || MEAL_TYPE_LABELS.snack;
  const items = foodPrices?.items || [];
  const ingredientCatalog = items.map(i => `${i.id} (${i.nameEn}/${i.name}, ~${i.carrefour} EGP/${i.unit}, category: ${i.category})`).join('\n');

  const tierInstruction = {
    low: 'Use cheap, budget-friendly ingredients from the list (lower price-per-unit items).',
    high: 'Premium ingredients from the list are fine (higher price-per-unit items welcome).',
    mid: '',
  }[budgetTier] || '';
  const preferenceInstruction = preference ? `The user specifically asked for: "${preference}". Reflect that in the meal choice.` : '';

  const prompt = `Suggest one ${DIET_STYLE_LABELS[dietStyle] || dietStyle} ${mealType} meal for an Egyptian meal-planning app. ${tierInstruction} ${preferenceInstruction}

You MUST only use ingredients from this exact list (reference them by "id"):
${ingredientCatalog}

Return ONLY valid JSON, no other text, in this exact shape:
{"name":"Arabic meal name","nameEn":"English meal name","ingredients":[{"ingredientId":"...", "grams":0}],"cal":0,"protein":"0g","carbs":"0g","fat":"0g"}`;

  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 500, messages: [{role:'user', content: prompt}] }),
  });
  const aiData = await aiRes.json();
  const raw = aiData.content?.[0]?.text || '{}';
  const match = raw.match(/\{[\s\S]*\}/);
  const parsed = match ? JSON.parse(match[0]) : null;
  if (!parsed || !Array.isArray(parsed.ingredients) || !parsed.ingredients.length) return null;

  const ingredients = parsed.ingredients
    .map(ing => {
      const item = items.find(i => i.id === ing.ingredientId);
      if (!item) return null; // drop any id Claude got wrong rather than fail the whole meal
      return { item: item.name, itemEn: item.nameEn, qty: item.qtyAr || item.qty, grams: Number(ing.grams) || 100 };
    })
    .filter(Boolean);
  if (!ingredients.length) return null;

  return {
    type: label.ar, typeEn: label.en, time: label.time,
    name: parsed.name || label.ar, nameEn: parsed.nameEn || label.en,
    ingredients,
    cal: parsed.cal || 0, protein: parsed.protein || '0g', carbs: parsed.carbs || '0g', fat: parsed.fat || '0g',
  };
}

app.get(`${BASE}/api/meal-plan`, auth, async (req,res) => {
  const diet = sanitize(req.query.diet)||req.userObj?.profile?.diet||'atkins';
  const budget = Math.min(Math.max(parseInt(req.query.budget||req.userObj?.profile?.budget||200),50),1000);
  const date = req.query.date || new Date().toISOString().split('T')[0];
  const budgetTier = budgetTierFor(budget);
  track('meal_plan_viewed', { userId: req.user.id, props: { diet } }); // activation signal

  const plans = load('meal_plans.json');
  const plan = plans?.[diet]||plans?.atkins;
  if (!plan) return res.json({error:'Plan not found'});
  const pd = load('food_prices.json');

  const week = [];
  for (let dayIdx = 0; dayIdx < plan.week.length; dayIdx++) {
    const day = plan.week[dayIdx];
    const meals = [];
    for (const meal of day.meals) {
      // Only day 0 (today) carries per-user overrides - the rest of the week
      // is still the static plan preview, matching how the dashboard only
      // ever requests/edits "today" via date.
      let effectiveMeal = meal;
      let swapsUsed = 0;
      let mealTypeKey = null;
      if (dayIdx === 0) {
        mealTypeKey = meal.typeEn ? meal.typeEn.toLowerCase() : meal.type;
        const override = getMealOverride(req.user.id, date, mealTypeKey);
        if (override && override.manualSwap) {
          // The user's explicit "change this meal" choice always wins over
          // the budget slider, regardless of which tier it was generated at.
          effectiveMeal = override.meal;
          swapsUsed = override.swapsUsed;
        } else if (override && override.tier === budgetTier) {
          effectiveMeal = override.meal;
        } else if (budgetTier !== 'mid') {
          // No override yet, or one exists but for a different tier than
          // currently requested (e.g. slider moved from low to high) -
          // regenerate for the tier actually being asked for.
          try {
            const generated = await generateMealAlternative(diet, mealTypeKey, budgetTier, null, pd);
            if (generated) {
              effectiveMeal = priceMeal(generated, pd);
              saveMealOverride(req.user.id, date, mealTypeKey, { meal: effectiveMeal, tier: budgetTier, swapsUsed: 0, manualSwap: false });
            }
          } catch (e) {
            console.error('[meal-plan] tier generation failed, falling back to static plan:', e.message);
          }
        }
      }
      const priced = priceMeal(effectiveMeal, pd);
      meals.push({...priced, withinBudget: priced.price <= (budget/4), mealTypeKey, swapsUsed, swapsRemaining: MEAL_SWAP_LIMIT - swapsUsed});
    }
    week.push({...day, meals});
  }

  const dailyCost=week[0]?.meals.reduce((s,m)=>s+m.price,0)||0;
  // Advisory copy only, not meal filtering - meal_plans.json has no per-meal
  // sodium/cholesterol/sugar tags today, so real meal-level filtering by lab
  // flags would need a separate data-modeling effort.
  const labAdvisory = buildLabAdvisories(getLatestLabFlags(req.user.id));
  res.json({...plan,week,dailyCost,budget,withinBudget:dailyCost<=budget,labAdvisory});
});

const MEAL_SWAP_LIMIT = 3;
const MEAL_SWAP_PREFERENCES = { tastier: 'more delicious / tastier', spicy: 'spicy', faster: 'faster and easier to prepare', cheaper: 'cheaper' };

app.post(`${BASE}/api/meal-plan/swap`, auth, async (req,res) => {
  const { date, mealType, preference } = req.body;
  if (!date || !mealType) return res.status(400).json({ error: 'date and mealType required' });
  if (preference && !MEAL_SWAP_PREFERENCES[preference]) return res.status(400).json({ error: 'Invalid preference' });

  const existing = getMealOverride(req.user.id, date, mealType);
  const swapsUsed = existing?.manualSwap ? existing.swapsUsed : 0;
  if (swapsUsed >= MEAL_SWAP_LIMIT) {
    return res.status(403).json({ error: 'لقد استخدمت كل محاولات التغيير الثلاثة لهذه الوجبة اليوم · You have used all 3 swaps for this meal today' });
  }

  const diet = sanitize(req.query.diet) || req.userObj?.profile?.diet || 'atkins';
  const budget = Math.min(Math.max(parseInt(req.userObj?.profile?.budget || 200), 50), 1000);
  const budgetTier = budgetTierFor(budget);
  const pd = load('food_prices.json');

  const generated = await generateMealAlternative(diet, mealType, budgetTier, MEAL_SWAP_PREFERENCES[preference] || null, pd);
  if (!generated) return res.status(502).json({ error: 'تعذر توليد بديل الآن، حاول تاني · Could not generate an alternative right now, try again' });

  const priced = priceMeal(generated, pd);
  const newSwapsUsed = swapsUsed + 1;
  saveMealOverride(req.user.id, date, mealType, { meal: priced, tier: budgetTier, swapsUsed: newSwapsUsed, manualSwap: true });
  secLog('MEAL_SWAP', getIP(req), { userId: req.user.id, date, mealType, preference, swapsUsed: newSwapsUsed });

  res.json({ ok: true, meal: priced, swapsUsed: newSwapsUsed, swapsRemaining: MEAL_SWAP_LIMIT - newSwapsUsed });
});

app.get(`${BASE}/api/food-prices`, auth, (req,res)=>res.json(load('food_prices.json')));
app.get(`${BASE}/api/labs`, auth, (req,res) => {
  const diet = req.query.diet || 'atkins';
  const data = load('labs.json') || { lastUpdated:null, tests:[] };
  const tests = (data.tests||[])
    .filter(t => (t.diets||[]).includes('all') || (t.diets||[]).includes(diet))
    .map(t => ({ ...t, why: resolveLabWhy(t.why, diet), whyAr: resolveLabWhy(t.whyAr, diet) }));
  res.json({ lastUpdated: data.lastUpdated, tests });
});

const ACTIVITY_PLANS = buildActivityPlans();
app.get(`${BASE}/api/activity-plan`, auth, (req,res) => {
  const diet = req.query.diet;
  const plan = ACTIVITY_PLANS[diet] || ACTIVITY_PLANS.atkins;
  res.json(plan);
});

// Public event ingest — for landing pages, the PWA, demo, and marketing pixels
// to record top-of-funnel events (page_view, demo_viewed, cta_click, …) with an
// anonymous id and UTM tags, before a user account exists. Rate limited.
app.post(`${BASE}/api/track`, (req,res)=>{
  const r = rateLimit(getIP(req),'track',120,60000);
  if(!r.ok) return res.status(429).json({error:'Too many events'});
  const name = sanitize(req.body.name);
  if(!name) return res.status(400).json({error:'name required'});
  track(name, { req, anonId: req.body.anonId, props: (req.body.props && typeof req.body.props==='object') ? req.body.props : {} });
  res.json({ok:true});
});

// DEMO (public, rate limited)
app.get(`${BASE}/api/demo/meal-plan`, (req,res)=>{
  const r=rateLimit(getIP(req),'demo',20,60000);
  if(!r.ok)return res.status(429).json({error:'Too many requests'});
  const plans=load('meal_plans.json');
  const day=plans?.atkins?.week?.[0];
  res.json({diet:'atkins',dailyCalories:1650,dailyCarbs:'20g',dailyProtein:'120g',isDemo:true,week:[day],message:'سجل للحصول على 7 أيام كاملة'});
});

// RATINGS
app.post(`${BASE}/api/rate`, (req,res)=>{
  const ip=getIP(req);
  const r=rateLimit(ip,'rate',2,86400000);
  if(!r.ok)return res.status(429).json({error:'One rating per day'});
  const {rating,comment}=req.body;
  const name=sanitize(req.body.name||'')||'مجهول';
  if(!rating||rating<1||rating>5)return res.status(400).json({error:'Invalid rating'});
  if(comment&&comment.length>500)return res.status(400).json({error:'Comment too long'});
  const ratings=load('ratings.json')||[];
  ratings.push({id:'r'+Date.now(),name,email:sanitize(req.body.email||'')||'',rating:parseInt(rating),comment:sanitize(comment||'')||'',ip,date:new Date().toISOString().split('T')[0],approved:false});
  save('ratings.json',ratings);
  res.json({ok:true});
});
app.get(`${BASE}/api/ratings`,(req,res)=>{
  const ratings=load('ratings.json')||[];
  const approved=ratings.filter(r=>r.approved);
  res.json({ratings:approved.slice(0,10),average:approved.length?parseFloat((approved.reduce((s,r)=>s+r.rating,0)/approved.length).toFixed(1)):0,total:approved.length});
});

// PAYMENT (Kashier) ─────────────────────────────────────────────────────────
// Flow: initiate (server signs the order) → user pays on Kashier's hosted page →
// Kashier calls our webhook server-to-server (signed) → webhook is the ONLY thing
// that grants paid access. The browser never decides who becomes paid, and the
// API key never leaves the server.
app.post(`${BASE}/api/payment/initiate`,optionalAuth,(req,res)=>{
  const ip=getIP(req);
  const r=rateLimit(ip,'pay',10,3600000);
  if(!r.ok)return res.status(429).json({error:'Too many payment requests'});
  const { plan } = req.body;
  if(!PLAN_PRICES[plan])return res.status(400).json({error:'Invalid plan'});
  const amount=PLAN_PRICES[plan];
  const email = sanitize(req.body.email||'')||'';
  track('checkout_started', { req, props:{ plan, amount } });
  if(!kashierConfigured())return res.json({ok:false,setupRequired:true,amount,plan});

  const orderId='DH-'+Date.now()+'-'+randToken(3);
  // Persist the order so the webhook can resolve who paid. Server-side only.
  update('payment_orders.json', o=>{
    o[orderId] = { orderId, userId:req.user?.id||null, email, plan, amount, currency:'EGP', status:'pending', createdAt:new Date().toISOString() };
    return o;
  }, {});

  const hash = kashierHash(orderId, amount, 'EGP');
  const redirect = `${KASHIER.baseUrl}${BASE}/payment?order=${orderId}`;
  const webhook = `${KASHIER.baseUrl}${BASE}/api/payment/webhook`;
  const url = `https://checkout.kashier.io/?merchantId=${encodeURIComponent(KASHIER.mid)}`
    + `&orderId=${encodeURIComponent(orderId)}&amount=${amount}&currency=EGP`
    + `&hash=${hash}&mode=${KASHIER.mode}`
    + `&merchantRedirect=${encodeURIComponent(redirect)}`
    + `&serverWebhook=${encodeURIComponent(webhook)}`
    + `&allowedMethods=card,wallet&display=ar&brandColor=%232D6A4F`;
  res.json({ ok:true, kashierUrl:url, orderId, amount, plan });
});
// Admin-only manual grant (e.g. after a manual bank transfer) — moved off
// /api/payment/confirm, which is now the authoritative-webhook return-page
// status poll below. This sets paid=true directly with no Kashier
// verification, so it must stay admin-gated the same way
// /api/admin/users/:id/markpaid already is, and must never share a route
// with the self-service confirm endpoint.
app.post(`${BASE}/api/admin/payment/manual-grant`,auth,adminOnly,(req,res)=>{
  const {paymentRef,plan}=req.body;
  const pp={basic:99,standard:179,premium:249,vip:349,elite:449};
  if(!pp[plan])return res.status(400).json({error:'Invalid plan'});
  const users=load('users.json')||[];
  const idx=users.findIndex(u=>u.id===req.user.id);
  if(idx<0)return res.status(404).json({});
  users[idx].paid=true;users[idx].plan=plan;
  save('users.json',users);
  const subs=load('subscriptions.json')||[];
  subs.push({userId:req.user.id,plan,startDate:new Date().toISOString().split('T')[0],endDate:new Date(Date.now()+30*86400000).toISOString().split('T')[0],amount:pp[plan],status:'active',paymentRef:paymentRef||'MANUAL_'+Date.now()});
  save('subscriptions.json',subs);
  secLog('PAYMENT_CONFIRMED',getIP(req),{userId:req.user.id,plan});
  res.json({ok:true});
});

// Server-to-server webhook — the authoritative source of truth for payment.
app.post(`${BASE}/api/payment/webhook`,(req,res)=>{
  if(!kashierConfigured())return res.status(503).json({error:'Payments not configured'});
  const data = req.body?.data || req.body || {};
  const signature = data.signature || req.body?.signature;
  if(!kashierVerify(data, data.signatureKeys || req.body?.signatureKeys, signature)){
    secLog('PAYMENT_WEBHOOK_BADSIG', getIP(req), { orderId:data.merchantOrderId });
    return res.status(400).json({error:'invalid signature'});
  }
  const orderId = data.merchantOrderId;
  const success = String(data.status||'').toUpperCase()==='SUCCESS';
  const orders = load('payment_orders.json') || {};
  const order = orders[orderId];
  if(!order){ secLog('PAYMENT_WEBHOOK_NOORDER', getIP(req), { orderId }); return res.json({ok:true}); }
  if(order.status==='paid') return res.json({ok:true}); // idempotent — already granted
  if(Number(data.amount)!==Number(order.amount)){
    secLog('PAYMENT_WEBHOOK_AMOUNT', getIP(req), { orderId, got:data.amount, expected:order.amount });
    return res.status(400).json({error:'amount mismatch'});
  }
  if(!success){
    update('payment_orders.json', o=>{ if(o[orderId]) o[orderId].status='failed'; return o; }, {});
    return res.json({ok:true});
  }
  // Grant access — the single authoritative path.
  update('payment_orders.json', o=>{ if(o[orderId]){ o[orderId].status='paid'; o[orderId].transactionId=data.transactionId; o[orderId].paidAt=new Date().toISOString(); } return o; }, {});
  // Resolve the user by stored id, or fall back to the email on the order.
  let uid = order.userId;
  update('users.json', users=>{
    let u = uid ? users.find(x=>x.id===uid) : null;
    if(!u && order.email) u = users.find(x=>x.email===order.email);
    if(u){ u.paid=true; u.plan=order.plan; uid=u.id; }
    return users;
  }, []);
  update('subscriptions.json', subs=>{
    subs.push({ userId:uid, plan:order.plan, startDate:new Date().toISOString().split('T')[0], endDate:new Date(Date.now()+30*86400000).toISOString().split('T')[0], amount:order.amount, status:'active', paymentRef:data.transactionId||('KASHIER_'+orderId) });
    return subs;
  }, []);
  if(uid) track('subscription_paid', { userId:uid, props:{ plan:order.plan, amount:order.amount } });
  secLog('PAYMENT_CONFIRMED', getIP(req), { orderId, userId:uid, plan:order.plan, transactionId:data.transactionId });
  res.json({ ok:true });
});

// Status poll — used by the return page after redirect. Reports the
// webhook-confirmed state; it does NOT grant access itself.
app.post(`${BASE}/api/payment/confirm`,auth,(req,res)=>{
  const orderId = req.body.order;
  let orderStatus = null;
  if(orderId){ const o=(load('payment_orders.json')||{})[orderId]; if(o && (o.userId===req.user.id || o.email===req.userObj.email)) orderStatus=o.status; }
  res.json({ ok:true, paid: !!req.userObj.paid, plan: req.userObj.plan, orderStatus });
});

// ADMIN
app.get(`${BASE}/api/admin/users`,auth,adminOnly,(req,res)=>{
  const users=load('users.json')||[];
  const subs=load('subscriptions.json')||[];
  res.json(users.map(({password,...u})=>({...u,trial:trial(u),sub:subs.find(s=>s.userId===u.id&&s.status==='active')})));
});
app.post(`${BASE}/api/admin/users`,auth,adminOnly,(req,res)=>{
  const username=sanitize(req.body.username);
  const {password,email,plan,role}=req.body;
  const uErr=validateUsr(username); if(uErr)return res.json({ok:false,error:uErr});
  const pErr=validatePwd(password); if(pErr)return res.json({ok:false,error:pErr});
  const users=load('users.json')||[];
  if(users.find(u=>u.username===username))return res.json({ok:false,error:'User exists'});
  const pp={basic:99,standard:179,premium:249,vip:349,elite:449};
  const nu={id:'u'+Date.now()+randToken(4),username,password:hashPwd(password),email:email||'',role:role||'user',plan:plan||'basic',created:new Date().toISOString().split('T')[0],active:true,emailVerified:true,trialStart:new Date().toISOString().split('T')[0],paid:!!pp[plan],lang:'ar',loginAttempts:0,profile:{}};
  users.push(nu);save('users.json',users);
  if(pp[plan]){const subs=load('subscriptions.json')||[];subs.push({userId:nu.id,plan,startDate:nu.created,endDate:new Date(Date.now()+30*86400000).toISOString().split('T')[0],amount:pp[plan],status:'active',paymentRef:'ADMIN_'+Date.now()});save('subscriptions.json',subs);}
  res.json({ok:true});
});
app.delete(`${BASE}/api/admin/users/:id`,auth,adminOnly,(req,res)=>{save('users.json',(load('users.json')||[]).filter(u=>u.id!==req.params.id));res.json({ok:true});});
app.post(`${BASE}/api/admin/users/:id/toggle`,auth,adminOnly,(req,res)=>{const users=load('users.json')||[];const u=users.find(u=>u.id===req.params.id);if(!u)return res.json({ok:false});u.active=!u.active;save('users.json',users);res.json({ok:true,active:u.active});});
app.post(`${BASE}/api/admin/users/:id/markpaid`,auth,adminOnly,(req,res)=>{const users=load('users.json')||[];const u=users.find(u=>u.id===req.params.id);if(!u)return res.json({ok:false});u.paid=true;u.emailVerified=true;save('users.json',users);res.json({ok:true});});
app.get(`${BASE}/api/admin/stats`,auth,adminOnly,(req,res)=>{
  const users=load('users.json')||[];const subs=load('subscriptions.json')||[];const ratings=load('ratings.json')||[];
  const pp={basic:99,standard:179,premium:249,vip:349,elite:449};
  const mrr=subs.filter(s=>s.status==='active').reduce((s,sub)=>s+(pp[sub.plan]||0),0);
  const apr=ratings.filter(r=>r.approved);
  res.json({totalUsers:users.length,activeUsers:users.filter(u=>u.active).length,verifiedUsers:users.filter(u=>u.emailVerified).length,paidUsers:users.filter(u=>u.paid).length,trialUsers:users.filter(u=>!u.paid&&u.active).length,activeSubs:subs.filter(s=>s.status==='active').length,mrr,avgRating:apr.length?(apr.reduce((s,r)=>s+r.rating,0)/apr.length).toFixed(1):0,totalRatings:ratings.length,pendingRatings:ratings.filter(r=>!r.approved).length,planBreakdown:Object.keys(pp).map(p=>({plan:p,count:subs.filter(s=>s.plan===p&&s.status==='active').length}))});
});
app.get(`${BASE}/api/admin/security-log`,auth,adminOnly,(req,res)=>res.json((load('security_log.json')||[]).slice(0,100)));
app.get(`${BASE}/api/admin/ratings`,auth,adminOnly,(req,res)=>res.json(load('ratings.json')||[]));
app.post(`${BASE}/api/admin/ratings/:id/approve`,auth,adminOnly,(req,res)=>{const ratings=load('ratings.json')||[];const r=ratings.find(r=>r.id===req.params.id);if(!r)return res.json({ok:false});r.approved=true;save('ratings.json',ratings);res.json({ok:true});});
app.post(`${BASE}/api/admin/food-prices`,auth,adminOnly,(req,res)=>{const p=load('food_prices.json');p.items=req.body.items;p.lastUpdated=new Date().toISOString().split('T')[0];save('food_prices.json',p);res.json({ok:true,lastUpdated:p.lastUpdated});});
app.get(`${BASE}/api/admin/subscriptions`,auth,adminOnly,(req,res)=>res.json(load('subscriptions.json')||[]));
// Acquisition funnel, conversion, CAC-by-source inputs and daily series.
app.get(`${BASE}/api/admin/analytics`,auth,adminOnly,(req,res)=>{
  res.json(store.analytics(Math.min(Math.max(parseInt(req.query.days)||30,1),365)));
});
// Raw recent event feed.
app.get(`${BASE}/api/admin/events`,auth,adminOnly,(req,res)=>{
  res.json(store.recentEvents(Math.min(Math.max(parseInt(req.query.limit)||100,1),1000)));
});
// Download a full, consistent snapshot of the database (safe to take live).
app.get(`${BASE}/api/admin/backup`,auth,adminOnly,(req,res)=>{
  const tmp = path.join(os.tmpdir(), `diethub_backup_${Date.now()}.db`);
  try {
    store.backup(tmp);
    secLog('DB_BACKUP', getIP(req), { adminId: req.user.id });
    res.download(tmp, `diethub_backup_${new Date().toISOString().split('T')[0]}.db`, () => fs.unlink(tmp, ()=>{}));
  } catch(e) {
    fs.unlink(tmp, ()=>{});
    res.status(500).json({ error: 'Backup failed: ' + e.message });
  }
});
app.get(`${BASE}/api/admin/export`,auth,adminOnly,(req,res)=>{
  const users=load('users.json')||[];const subs=load('subscriptions.json')||[];
  const rows=[['ID','Username','Email','Phone','Plan','Role','Status','EmailVerified','Paid','Diet','Budget','Weight','Height','Age','BMI','BMR','BodyFat%','MuscleMass','Created','SubEnd']];
  users.forEach(u=>{const sub=subs.find(s=>s.userId===u.id&&s.status==='active');rows.push([u.id,u.username,u.email||'',u.phone||'',u.plan,u.role,u.active?'Active':'Inactive',u.emailVerified?'Yes':'No',u.paid?'Yes':'Trial',u.profile?.diet||'',u.profile?.budget||'',u.profile?.weight||'',u.profile?.height||'',u.profile?.age||'',u.profile?.bmi||'',u.profile?.bmr||'',u.profile?.bodyFat||'',u.profile?.muscleMass||'',u.created,sub?.endDate||'']);});
  const csv=rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type','text/csv;charset=utf-8');
  res.setHeader('Content-Disposition',`attachment;filename="diethub_${new Date().toISOString().split('T')[0]}.csv"`);
  res.send('\uFEFF'+csv);
});
app.get(`${BASE}/health`,(req,res)=>res.json({status:'ok',version:'3.0-secure'}));
// Public (no-auth) — lets login.html know whether to render the Google
// button at all, rather than showing one that's guaranteed to fail.
app.get(`${BASE}/api/config`,(req,res)=>res.json({googleClientId: GOOGLE_CLIENT_ID || null, facebookAppId: FACEBOOK_APP_ID || null}));
app.get(`${BASE}/forgot-password`, (req,res) => res.sendFile(path.join(__dirname,'public','forgot_password.html')));
app.get(`${BASE}/reset-password`, (req,res) => res.sendFile(path.join(__dirname,'public','reset_password.html')));
app.post(`${BASE}/api/forgot-password`, async (req,res) => {
  const ip = getIP(req);
  const r = rateLimit(ip, 'forgot', 3, 15 * 60 * 1000);
  if (!r.ok) return res.status(429).json({ error: 'Too many attempts. Wait 15 minutes.' });
  const email = sanitize((req.body.email||'').toLowerCase().trim());
  if (!email) return res.status(400).json({ error: 'Email required' });
  const users = load('users.json') || [];
  const u = users.find(u => u.email === email && u.active);
  if (!u) return res.json({ ok: true });
  const token = randToken();
  const resets = load('password_resets.json') || [];
  const filtered = resets.filter(r => r.userId !== u.id);
  filtered.push({ userId: u.id, token, email, expiresAt: Date.now() + 60 * 60 * 1000, createdAt: new Date().toISOString() });
  save('password_resets.json', filtered);
  await sendResetEmail(email, u.username, token);
  secLog('PASSWORD_RESET_REQUESTED', ip, { email });
  res.json({ ok: true });
});
app.post(`${BASE}/api/reset-password`, (req,res) => {
  const ip = getIP(req);
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Missing data' });
  const pErr = validatePwd(password);
  if (pErr) return res.status(400).json({ error: pErr });
  const resets = load('password_resets.json') || [];
  const rec = resets.find(r => r.token === token);
  if (!rec || Date.now() > rec.expiresAt) return res.status(400).json({ error: 'Link expired or invalid' });
  const users = load('users.json') || [];
  const idx = users.findIndex(u => u.id === rec.userId);
  if (idx < 0) return res.status(400).json({ error: 'User not found' });
  users[idx].password = hashPwd(password);
  users[idx].loginAttempts = 0;
  users[idx].active = true;
  save('users.json', users);
  save('password_resets.json', resets.filter(r => r.token !== token));
  secLog('PASSWORD_RESET_DONE', ip, { userId: rec.userId });
  res.json({ ok: true });
});

// ─── CHATBOT (VIP + ELITE ONLY) ───────────────────────────────────────────────
app.post(`${BASE}/api/chatbot`, auth, async (req, res) => {
  const u = req.userObj;
  if (!BETA_MODE && !['vip','elite'].includes(u.plan) && u.role !== 'admin') {
    return res.status(403).json({ error: 'هذه الميزة متاحة لأعضاء VIP و Elite فقط' });
  }
  const { messages, generateQuestions } = req.body;
  // Coach now reads the full unified health profile (labs + wearables + targets
  // + risk flags), not just the thin demographic fields — this is what turns it
  // from a generic chatbot into a coach that knows the user's actual state.
  // Also fixes the earlier bug where a standalone dietMap here mapped
  // demographic-plan codes (women_40, men_40, diabetic, kids, ...) inconsistently;
  // diet naming now lives in one place, health.js's DIET_AR (see below).
  const hp = buildHealthProfile(store, u.id);
  const summary = coachSummary(hp);

  const systemPrompt = `أنت "دايت بوت"، مساعد متابعة صحي وغذائي ذكي داخل تطبيق DietHub. تتحدث بالعربية دائماً بأسلوب ودود ومشجع وموجز.

الملف الصحي الكامل للمستخدم (استخدمه لتخصيص كل رد):
${summary}

إرشادات مهمة:
- استخدم أرقام المستخدم الحقيقية (السعرات، البروتين، الماء، الوزن، بيانات الساعة) في نصائحك بدلاً من النصائح العامة.
- إن وُجدت "تنبيهات مهمة" فعالِجها أولاً بلطف ودون تخويف.
- أنت لست بديلاً عن الطبيب. إذا ظهرت مؤشرات خطيرة (تحاليل حرجة مثلاً) انصح المستخدم بمراجعة طبيبه.
- ابقَ ضمن نطاق الغذاء والصحة واللياقة، وأعد المستخدم بلطف للموضوع إن خرج عنه.
${generateQuestions ? 'مهمتك الآن: اطرح 3 أسئلة متابعة قصيرة ومخصصة بناءً على ملفه الصحي وتنبيهاته الحالية ووقت اليوم. أرسل الأسئلة فقط كقائمة مرقمة بدون مقدمة.' : 'أجب على رسالة المستخدم بإيجاز وادعمه في رحلته الصحية.'}`;

  try {
    const { text } = await ai.chat({ system: systemPrompt, messages, maxTokens: 500 });
    res.json({ reply: text || 'عذراً، لم أفهم. حاول مجدداً.' });
  } catch(e) {
    console.error('Chatbot error:', e.message);
    res.status(500).json({ error: 'خطأ في المساعد الذكي: ' + e.message });
  }
});


// ─── NUTRITION TRACKER ────────────────────────────────────────────────────────
app.get(`${BASE}/api/nutrition-log`, auth, (req,res) => {
  const logs = load('nutrition_logs.json') || {};
  const userLogs = logs[req.user.id] || [];
  res.json(userLogs);
});

app.post(`${BASE}/api/nutrition-log`, auth, (req,res) => {
  const { date, meals, custom } = req.body;
  if (!date) return res.status(400).json({error:'Date required'});
  const logs = load('nutrition_logs.json') || {};
  if (!logs[req.user.id]) logs[req.user.id] = [];
  const existing = logs[req.user.id].findIndex(l => l.date === date);
  const entry = { date, meals: meals||[], custom: custom||[], savedAt: new Date().toISOString() };
  if (existing >= 0) logs[req.user.id][existing] = entry;
  else logs[req.user.id].push(entry);
  // Keep last 90 days only
  logs[req.user.id] = logs[req.user.id].sort((a,b)=>b.date.localeCompare(a.date)).slice(0,90);
  save('nutrition_logs.json', logs);
  res.json({ok:true});
});

// Local, zero-cost nutrition database (per 100g) covering common Egyptian/Gulf
// staples plus general basics - no external API calls, no usage cost, works
// offline. Deliberately not exhaustive; anything not found here falls back to
// manual entry client-side rather than silently guessing.
const FOOD_DB = [
  { ar:'صدر فرخة مشوي', en:'grilled chicken breast', aliases:['صدر دجاج','فراخ مشوي','دجاج مشوي','chicken breast'], cal:165, protein:31, carbs:0, fat:3.6 },
  { ar:'فخذ فرخة', en:'chicken thigh', aliases:['فخذ دجاج'], cal:209, protein:26, carbs:0, fat:10.9 },
  { ar:'فرخة كاملة مشوية', en:'whole roasted chicken', aliases:['دجاجة مشوية'], cal:190, protein:27, carbs:0, fat:8 },
  { ar:'لحم بقري', en:'beef, lean', aliases:['لحمة بقري','لحم بتلو'], cal:250, protein:26, carbs:0, fat:15 },
  { ar:'لحمة مفرومة', en:'ground beef, cooked', aliases:['لحم مفروم'], cal:254, protein:25, carbs:0, fat:17 },
  { ar:'لحم ضاني', en:'lamb', aliases:['لحمة ضاني','لحم غنم'], cal:294, protein:25, carbs:0, fat:21 },
  { ar:'سمك بلطي', en:'tilapia fish', aliases:['بلطي','سمك مشوي'], cal:128, protein:26, carbs:0, fat:2.7 },
  { ar:'تونة', en:'tuna, canned in water', aliases:['تونه'], cal:116, protein:26, carbs:0, fat:1 },
  { ar:'جمبري', en:'shrimp', aliases:['روبيان'], cal:99, protein:24, carbs:0.2, fat:0.3 },
  { ar:'بيض مسلوق', en:'boiled egg', aliases:['بيضة مسلوقة'], cal:155, protein:13, carbs:1.1, fat:11 },
  { ar:'بياض بيض', en:'egg white', aliases:[], cal:52, protein:11, carbs:0.7, fat:0.2 },
  { ar:'أرز أبيض', en:'white rice, cooked', aliases:['رز أبيض','ارز ابيض'], cal:130, protein:2.7, carbs:28, fat:0.3 },
  { ar:'أرز بني', en:'brown rice, cooked', aliases:['رز بني'], cal:111, protein:2.6, carbs:23, fat:0.9 },
  { ar:'عيش بلدي', en:'baladi bread', aliases:['عيش شامي','خبز بلدي'], cal:265, protein:9, carbs:53, fat:1.5 },
  { ar:'عيش فينو', en:'white bread', aliases:['خبز أبيض','توست'], cal:289, protein:9, carbs:55, fat:3.2 },
  { ar:'مكرونة', en:'pasta, cooked', aliases:['معكرونة'], cal:131, protein:5, carbs:25, fat:1.1 },
  { ar:'بطاطس مسلوقة', en:'boiled potato', aliases:['بطاطا مسلوقة'], cal:87, protein:1.9, carbs:20, fat:0.1 },
  { ar:'بطاطس محمرة', en:'fried potato', aliases:['بطاطس مقلية'], cal:312, protein:3.4, carbs:41, fat:15 },
  { ar:'بطاطا', en:'sweet potato', aliases:['بطاطا حلوة'], cal:86, protein:1.6, carbs:20, fat:0.1 },
  { ar:'شوفان', en:'oats, dry', aliases:[], cal:389, protein:17, carbs:66, fat:7 },
  { ar:'فول مدمس', en:'foul medames', aliases:['فول'], cal:110, protein:7.6, carbs:18, fat:0.6 },
  { ar:'حمص', en:'hummus', aliases:[], cal:166, protein:8, carbs:14, fat:9.6 },
  { ar:'شوربة عدس', en:'lentil soup', aliases:['عدس'], cal:116, protein:9, carbs:20, fat:0.4 },
  { ar:'طعمية', en:'falafel', aliases:['فلافل'], cal:333, protein:13, carbs:32, fat:18 },
  { ar:'طماطم', en:'tomato', aliases:['طماطة'], cal:18, protein:0.9, carbs:3.9, fat:0.2 },
  { ar:'خيار', en:'cucumber', aliases:[], cal:15, protein:0.7, carbs:3.6, fat:0.1 },
  { ar:'سلطة خضراء', en:'green salad', aliases:['سلطة'], cal:20, protein:1, carbs:4, fat:0.2 },
  { ar:'ملوخية', en:'molokhia', aliases:[], cal:60, protein:4.8, carbs:8, fat:1.5 },
  { ar:'بامية', en:'okra', aliases:[], cal:60, protein:2, carbs:8, fat:2 },
  { ar:'سبانخ', en:'spinach', aliases:[], cal:23, protein:2.9, carbs:3.6, fat:0.4 },
  { ar:'كوسة', en:'zucchini', aliases:['كوسه'], cal:17, protein:1.2, carbs:3.1, fat:0.3 },
  { ar:'موز', en:'banana', aliases:[], cal:89, protein:1.1, carbs:23, fat:0.3 },
  { ar:'تفاح', en:'apple', aliases:[], cal:52, protein:0.3, carbs:14, fat:0.2 },
  { ar:'برتقال', en:'orange', aliases:[], cal:47, protein:0.9, carbs:12, fat:0.1 },
  { ar:'مانجو', en:'mango', aliases:[], cal:60, protein:0.8, carbs:15, fat:0.4 },
  { ar:'بطيخ', en:'watermelon', aliases:[], cal:30, protein:0.6, carbs:8, fat:0.2 },
  { ar:'تمر', en:'dates', aliases:[], cal:277, protein:1.8, carbs:75, fat:0.2 },
  { ar:'زبادي', en:'plain yogurt', aliases:['لبن زبادي'], cal:61, protein:3.5, carbs:4.7, fat:3.3 },
  { ar:'زبادي يوناني', en:'greek yogurt', aliases:[], cal:59, protein:10, carbs:3.6, fat:0.4 },
  { ar:'لبن', en:'whole milk', aliases:['حليب'], cal:61, protein:3.2, carbs:4.8, fat:3.3 },
  { ar:'جبنة فيتا', en:'feta cheese', aliases:[], cal:264, protein:14, carbs:4, fat:21 },
  { ar:'جبنة قريش', en:'cottage cheese', aliases:['جبنه قريش'], cal:98, protein:11, carbs:3.4, fat:4.3 },
  { ar:'جبنة بيضاء', en:'white cheese', aliases:[], cal:300, protein:18, carbs:3, fat:24 },
  { ar:'لوز', en:'almonds', aliases:[], cal:579, protein:21, carbs:22, fat:50 },
  { ar:'فول سوداني', en:'peanuts', aliases:['سوداني'], cal:567, protein:26, carbs:16, fat:49 },
  { ar:'زيت زيتون', en:'olive oil', aliases:[], cal:884, protein:0, carbs:0, fat:100 },
  { ar:'أفوكادو', en:'avocado', aliases:['افوكادو'], cal:160, protein:2, carbs:8.5, fat:14.7 },
  { ar:'كشري', en:'koshari', aliases:[], cal:180, protein:5, carbs:30, fat:4 },
  { ar:'كفتة مشوية', en:'grilled kofta', aliases:['كفتة'], cal:220, protein:18, carbs:2, fat:15 },
  { ar:'شاورما فراخ', en:'chicken shawarma', aliases:['شاورما دجاج'], cal:200, protein:18, carbs:10, fat:10 },
  { ar:'فتة', en:'fattah', aliases:[], cal:200, protein:10, carbs:22, fat:8 },
];

function normalizeFoodQuery(s) {
  return (s||'').trim().toLowerCase()
    .replace(/[أإآ]/g,'ا').replace(/ى/g,'ي').replace(/ة/g,'ه'); // normalize common Arabic letter variants
}

function findFoodMatch(query) {
  const q = normalizeFoodQuery(query);
  if (!q) return null;
  let best = null, bestLen = 0;
  for (const item of FOOD_DB) {
    const candidates = [item.ar, item.en, ...(item.aliases||[])];
    for (const c of candidates) {
      const nc = normalizeFoodQuery(c);
      if (!nc) continue;
      if (q === nc || q.includes(nc) || nc.includes(q)) {
        if (nc.length > bestLen) { best = item; bestLen = nc.length; }
      }
    }
  }
  return best;
}

// Estimates calories/protein/carbs/fat for a named food at a given weight, so
// "Add Custom Food" only needs a name + grams instead of the user having to
// already know the macro breakdown themselves. Looked up from FOOD_DB above -
// a local, free, zero-cost database, not a paid AI call.
app.post(`${BASE}/api/nutrition-lookup`, auth, async (req, res) => {
  const foodName = sanitize(req.body.foodName || '').trim();
  const weightGrams = parseFloat(req.body.weightGrams);
  if (!foodName || isNaN(weightGrams) || weightGrams <= 0 || weightGrams > 5000)
    return res.status(400).json({ error: 'foodName and a valid weightGrams (1-5000) required' });

  const match = findFoodMatch(foodName);
  if (!match) {
    return res.status(404).json({
      error: 'الطعام غير موجود في قاعدة البيانات، من فضلك أدخل القيم يدوياً · Food not found in our database, please enter values manually',
      notFound: true,
    });
  }

  const scale = weightGrams / 100;
  res.json({
    name: foodName,
    weightGrams,
    cal: Math.round(match.cal * scale),
    protein: Math.round(match.protein * scale),
    carbs: Math.round(match.carbs * scale),
    fat: Math.round(match.fat * scale),
  });
});

// ─── LAB RESULTS TRACKER ──────────────────────────────────────────────────────
// Known measurable-value vocabulary, matching dashboard.html's labTests form
// (ids/normal ranges) - shared so manual entry and photo-upload extraction
// both produce the same {testId: numericValue} shape for deriveLabFlags().
const LAB_TEST_IDS = ['glucose','hba1c','cholesterol','ldl','hdl','triglycerides','creatinine','tsh','hemoglobin','vitd'];

app.get(`${BASE}/api/lab-results`, auth, (req,res) => {
  if (!BETA_MODE && !['vip','elite'].includes(req.userObj.plan) && req.userObj.role !== 'admin')
    return res.status(403).json({error:'VIP/Elite only'});
  const results = load('lab_results.json') || {};
  res.json(results[req.user.id] || []);
});

// Per-diet supplement suggestions - mirrors buildMealPlans() in spirit: the
// same 9 diet/demographic keys, each with supplements actually relevant to
// that diet's real physiological concerns, not one generic Atkins-oriented
// list shown to everyone regardless of which diet/demographic is selected.
const DIET_SUPPLEMENTS = {
  atkins: [
    { icon:'🐟', name:'Omega-3 Fish Oil 1000mg', nameAr:'أوميجا 3 زيت السمك', why:'Essential for Atkins — supports heart and joints', whyAr:'أساسي في Atkins — يدعم القلب والمفاصل', price:'135 EGP', priceAr:'135 جنيه', link:'https://www.amazon.eg/s?k=omega+3' },
    { icon:'💪', name:'Whey Protein Isolate 1kg', nameAr:'واي بروتين أيزوليت 1 كجم', why:'Preserves muscle during diet — choose Isolate to avoid lactose', whyAr:'يحافظ على العضلات — اختر Isolate لتجنب اللاكتوز', price:'950 EGP', priceAr:'950 جنيه', link:'https://www.amazon.eg/s?k=whey+protein+isolate' },
    { icon:'🧬', name:'Creatine Monohydrate 300g', nameAr:'كرياتين مونوهيدرات 300 جم', why:'Improves workout performance, safe with Atkins', whyAr:'يحسن أداء التمارين، آمن مع Atkins', price:'320 EGP', priceAr:'320 جنيه', link:'https://www.amazon.eg/s?k=creatine' },
    { icon:'⚡', name:'Multivitamin', nameAr:'مالتيفيتامين', why:'Replaces vitamins lost when cutting carbs', whyAr:'يعوض الفيتامينات التي تنخفض مع تقليل الكربوهيدرات', price:'580 EGP', priceAr:'580 جنيه', link:'https://www.amazon.eg/s?k=opti+men' },
    { icon:'🌿', name:'Fenugreek', nameAr:'حلبة', why:'Improves insulin resistance', whyAr:'تحسين مقاومة الإنسولين', price:'8-15 EGP', priceAr:'8-15 جنيه', link:'https://www.amazon.eg/s?k=fenugreek' },
    { icon:'🟡', name:'Turmeric', nameAr:'كركم', why:'Strong anti-inflammatory, supports joints', whyAr:'مضاد التهابات قوي، يدعم المفاصل', price:'20-35 EGP', priceAr:'20-35 جنيه', link:'https://www.amazon.eg/s?k=turmeric' }
  ],
  keto: [
    { icon:'⚡', name:'Electrolyte Powder (Sodium/Potassium/Magnesium)', nameAr:'أملاح معدنية (صوديوم/بوتاسيوم/ماغنسيوم)', why:'Prevents "keto flu" - headaches and fatigue from mineral loss in early ketosis', whyAr:'يمنع "أنفلونزا الكيتو" — الصداع والإرهاق الناتج عن فقد الأملاح في بداية الكيتوسيس', price:'450 EGP', priceAr:'450 جنيه', link:'https://www.amazon.eg/s?k=electrolyte+powder' },
    { icon:'🥥', name:'MCT Oil', nameAr:'زيت MCT', why:'Fast-absorbing fat source that supports ketosis and energy', whyAr:'مصدر دهون سريع الامتصاص يدعم الكيتوسيس والطاقة', price:'520 EGP', priceAr:'520 جنيه', link:'https://www.amazon.eg/s?k=mct+oil' },
    { icon:'🐟', name:'Omega-3 Fish Oil 1000mg', nameAr:'أوميجا 3 زيت السمك', why:'Balances the high fat intake with anti-inflammatory omega-3s', whyAr:'يوازن الدهون العالية بأوميجا 3 المضادة للالتهابات', price:'135 EGP', priceAr:'135 جنيه', link:'https://www.amazon.eg/s?k=omega+3' },
    { icon:'🍽️', name:'Digestive Enzymes', nameAr:'إنزيمات هضمية', why:'Helps digest the higher fat content typical of keto meals', whyAr:'تساعد في هضم كمية الدهون العالية في وجبات الكيتو', price:'280 EGP', priceAr:'280 جنيه', link:'https://www.amazon.eg/s?k=digestive+enzymes' },
    { icon:'⚡', name:'Multivitamin', nameAr:'مالتيفيتامين', why:'Covers micronutrients lower in a very restricted-carb diet', whyAr:'يعوض العناصر الغذائية التي تقل في نظام قليل الكربوهيدرات جداً', price:'580 EGP', priceAr:'580 جنيه', link:'https://www.amazon.eg/s?k=multivitamin' },
    { icon:'🟡', name:'Turmeric', nameAr:'كركم', why:'Anti-inflammatory support, especially useful alongside high-fat meals', whyAr:'مضاد التهابات، مفيد خاصة مع الوجبات عالية الدهون', price:'20-35 EGP', priceAr:'20-35 جنيه', link:'https://www.amazon.eg/s?k=turmeric' }
  ],
  mediterranean: [
    { icon:'🐟', name:'Omega-3 Fish Oil 1000mg', nameAr:'أوميجا 3 زيت السمك', why:'Complements the fish and olive oil already central to this diet', whyAr:'يكمل السمك وزيت الزيتون الأساسيين في هذا النظام', price:'135 EGP', priceAr:'135 جنيه', link:'https://www.amazon.eg/s?k=omega+3' },
    { icon:'☀️', name:'Vitamin D3', nameAr:'فيتامين د3', why:'Common deficiency in Egypt despite sunshine - supports bones and immunity', whyAr:'نقص شائع في مصر رغم الشمس — يدعم العظام والمناعة', price:'180 EGP', priceAr:'180 جنيه', link:'https://www.amazon.eg/s?k=vitamin+d3' },
    { icon:'🦠', name:'Probiotics', nameAr:'بروبيوتيك', why:'Supports gut health alongside the high fiber from legumes and whole grains', whyAr:'يدعم صحة الأمعاء مع الألياف العالية من البقوليات والحبوب الكاملة', price:'420 EGP', priceAr:'420 جنيه', link:'https://www.amazon.eg/s?k=probiotics' },
    { icon:'⚡', name:'Multivitamin', nameAr:'مالتيفيتامين', why:'General micronutrient coverage for a balanced whole-food diet', whyAr:'تغطية عامة للعناصر الغذائية في نظام متوازن', price:'580 EGP', priceAr:'580 جنيه', link:'https://www.amazon.eg/s?k=multivitamin' },
    { icon:'🌿', name:'Fenugreek', nameAr:'حلبة', why:'Traditional support for blood sugar balance', whyAr:'دعم تقليدي لتوازن سكر الدم', price:'8-15 EGP', priceAr:'8-15 جنيه', link:'https://www.amazon.eg/s?k=fenugreek' },
    { icon:'🟡', name:'Turmeric', nameAr:'كركم', why:'Anti-inflammatory, pairs naturally with this diet\'s herbs and spices', whyAr:'مضاد التهابات، يتناسب مع أعشاب وتوابل هذا النظام', price:'20-35 EGP', priceAr:'20-35 جنيه', link:'https://www.amazon.eg/s?k=turmeric' }
  ],
  diabetic: [
    { icon:'🧂', name:'Chromium Picolinate', nameAr:'كروميوم بيكولينات', why:'Supports insulin sensitivity and blood sugar control', whyAr:'يدعم حساسية الإنسولين والتحكم في سكر الدم', price:'320 EGP', priceAr:'320 جنيه', link:'https://www.amazon.eg/s?k=chromium+picolinate' },
    { icon:'🌿', name:'Alpha-Lipoic Acid', nameAr:'ألفا ليبويك أسيد', why:'Antioxidant shown to support healthy blood sugar and nerve health', whyAr:'مضاد أكسدة يدعم سكر الدم الصحي وصحة الأعصاب', price:'480 EGP', priceAr:'480 جنيه', link:'https://www.amazon.eg/s?k=alpha+lipoic+acid' },
    { icon:'🟤', name:'Cinnamon Extract', nameAr:'مستخلص القرفة', why:'Traditional support for blood sugar balance', whyAr:'دعم تقليدي لتوازن سكر الدم', price:'150 EGP', priceAr:'150 جنيه', link:'https://www.amazon.eg/s?k=cinnamon+extract' },
    { icon:'💧', name:'Psyllium Fiber', nameAr:'ألياف السيليوم', why:'Slows sugar absorption and supports healthy digestion', whyAr:'يبطئ امتصاص السكر ويدعم الهضم الصحي', price:'220 EGP', priceAr:'220 جنيه', link:'https://www.amazon.eg/s?k=psyllium+fiber' },
    { icon:'⚡', name:'Magnesium', nameAr:'ماغنسيوم', why:'Often low in diabetics - supports insulin function', whyAr:'غالباً منخفض عند مرضى السكري — يدعم وظيفة الإنسولين', price:'250 EGP', priceAr:'250 جنيه', link:'https://www.amazon.eg/s?k=magnesium' },
    { icon:'☀️', name:'Vitamin D3', nameAr:'فيتامين د3', why:'Linked to better insulin sensitivity when levels are low', whyAr:'مرتبط بحساسية إنسولين أفضل عند انخفاض مستوياته', price:'180 EGP', priceAr:'180 جنيه', link:'https://www.amazon.eg/s?k=vitamin+d3' }
  ],
  women: [
    { icon:'🩸', name:'Iron + Vitamin C', nameAr:'حديد + فيتامين سي', why:'Iron deficiency is common in women - vitamin C improves absorption', whyAr:'نقص الحديد شائع عند النساء — فيتامين سي يحسن الامتصاص', price:'220 EGP', priceAr:'220 جنيه', link:'https://www.amazon.eg/s?k=iron+supplement+women' },
    { icon:'🌱', name:'Folic Acid', nameAr:'حمض الفوليك', why:'Supports cell health and is especially important for women of childbearing age', whyAr:'يدعم صحة الخلايا ومهم خاصة لسن الإنجاب', price:'60 EGP', priceAr:'60 جنيه', link:'https://www.amazon.eg/s?k=folic+acid' },
    { icon:'🦴', name:'Calcium + Vitamin D', nameAr:'كالسيوم + فيتامين د', why:'Supports bone density, which women lose faster with age', whyAr:'يدعم كثافة العظام التي تفقدها المرأة بمعدل أسرع مع العمر', price:'240 EGP', priceAr:'240 جنيه', link:'https://www.amazon.eg/s?k=calcium+vitamin+d' },
    { icon:'⚡', name:"Women's Multivitamin", nameAr:'مالتيفيتامين للمرأة', why:'General micronutrient coverage tailored to women\'s needs', whyAr:'تغطية عامة للعناصر الغذائية المناسبة لاحتياجات المرأة', price:'580 EGP', priceAr:'580 جنيه', link:'https://www.amazon.eg/s?k=women+multivitamin' },
    { icon:'🌸', name:'Evening Primrose Oil', nameAr:'زيت زهرة الربيع المسائية', why:'Traditionally used to support hormonal balance', whyAr:'يستخدم تقليدياً لدعم التوازن الهرموني', price:'350 EGP', priceAr:'350 جنيه', link:'https://www.amazon.eg/s?k=evening+primrose+oil' },
    { icon:'🐟', name:'Omega-3 Fish Oil 1000mg', nameAr:'أوميجا 3 زيت السمك', why:'Supports heart and skin health', whyAr:'يدعم صحة القلب والبشرة', price:'135 EGP', priceAr:'135 جنيه', link:'https://www.amazon.eg/s?k=omega+3' }
  ],
  women_40: [
    { icon:'🦴', name:'Calcium + Vitamin D3', nameAr:'كالسيوم + فيتامين د3', why:'Bone density loss accelerates around and after menopause', whyAr:'فقدان كثافة العظام يتسارع حول سن اليأس وبعده', price:'240 EGP', priceAr:'240 جنيه', link:'https://www.amazon.eg/s?k=calcium+vitamin+d3' },
    { icon:'💪', name:'Whey Protein Isolate', nameAr:'واي بروتين أيزوليت', why:'Higher protein helps preserve muscle mass, which declines faster after 40', whyAr:'البروتين العالي يحافظ على الكتلة العضلية التي تقل بسرعة أكبر بعد الأربعين', price:'950 EGP', priceAr:'950 جنيه', link:'https://www.amazon.eg/s?k=whey+protein+isolate' },
    { icon:'🐟', name:'Omega-3 Fish Oil 1000mg', nameAr:'أوميجا 3 زيت السمك', why:'Supports heart health, which becomes a bigger priority after 40', whyAr:'يدعم صحة القلب التي تصبح أولوية أكبر بعد الأربعين', price:'135 EGP', priceAr:'135 جنيه', link:'https://www.amazon.eg/s?k=omega+3' },
    { icon:'✨', name:'Collagen Peptides', nameAr:'كولاجين', why:'Supports skin elasticity and joint health as natural collagen production slows', whyAr:'يدعم مرونة البشرة وصحة المفاصل مع تباطؤ إنتاج الكولاجين الطبيعي', price:'620 EGP', priceAr:'620 جنيه', link:'https://www.amazon.eg/s?k=collagen+peptides' },
    { icon:'⚡', name:'Magnesium', nameAr:'ماغنسيوم', why:'Supports sleep quality and reduces menopause-related muscle cramps', whyAr:'يدعم جودة النوم ويقلل تشنجات العضلات المرتبطة بسن اليأس', price:'250 EGP', priceAr:'250 جنيه', link:'https://www.amazon.eg/s?k=magnesium' },
    { icon:'🧠', name:'Vitamin B-Complex', nameAr:'فيتامين ب المركب', why:'Supports energy levels and mood during hormonal changes', whyAr:'يدعم مستويات الطاقة والمزاج أثناء التغيرات الهرمونية', price:'190 EGP', priceAr:'190 جنيه', link:'https://www.amazon.eg/s?k=vitamin+b+complex' }
  ],
  men: [
    { icon:'💪', name:'Whey Protein Isolate 1kg', nameAr:'واي بروتين أيزوليت 1 كجم', why:'Supports muscle building alongside a higher-protein diet', whyAr:'يدعم بناء العضلات مع النظام عالي البروتين', price:'950 EGP', priceAr:'950 جنيه', link:'https://www.amazon.eg/s?k=whey+protein+isolate' },
    { icon:'🧬', name:'Creatine Monohydrate 300g', nameAr:'كرياتين مونوهيدرات 300 جم', why:'Well-researched for improving strength and workout performance', whyAr:'مثبت علمياً في تحسين القوة وأداء التمارين', price:'320 EGP', priceAr:'320 جنيه', link:'https://www.amazon.eg/s?k=creatine' },
    { icon:'🔩', name:'Zinc', nameAr:'زنك', why:'Supports testosterone levels and immune function', whyAr:'يدعم مستويات هرمون التستوستيرون ووظيفة المناعة', price:'160 EGP', priceAr:'160 جنيه', link:'https://www.amazon.eg/s?k=zinc' },
    { icon:'⚡', name:"Men's Multivitamin", nameAr:'مالتيفيتامين للرجل', why:'General micronutrient coverage tailored to men\'s needs', whyAr:'تغطية عامة للعناصر الغذائية المناسبة لاحتياجات الرجل', price:'580 EGP', priceAr:'580 جنيه', link:'https://www.amazon.eg/s?k=men+multivitamin' },
    { icon:'🐟', name:'Omega-3 Fish Oil 1000mg', nameAr:'أوميجا 3 زيت السمك', why:'Supports heart and joint health', whyAr:'يدعم صحة القلب والمفاصل', price:'135 EGP', priceAr:'135 جنيه', link:'https://www.amazon.eg/s?k=omega+3' },
    { icon:'☀️', name:'Vitamin D3', nameAr:'فيتامين د3', why:'Common deficiency in Egypt despite sunshine - supports bones and testosterone', whyAr:'نقص شائع في مصر رغم الشمس — يدعم العظام والتستوستيرون', price:'180 EGP', priceAr:'180 جنيه', link:'https://www.amazon.eg/s?k=vitamin+d3' }
  ],
  men_40: [
    { icon:'🐟', name:'Omega-3 Fish Oil 1000mg', nameAr:'أوميجا 3 زيت السمك', why:'Heart health becomes a bigger priority after 40', whyAr:'صحة القلب تصبح أولوية أكبر بعد الأربعين', price:'135 EGP', priceAr:'135 جنيه', link:'https://www.amazon.eg/s?k=omega+3' },
    { icon:'🌴', name:'Saw Palmetto', nameAr:'سو بالميتو', why:'Commonly used to support prostate health after 40', whyAr:'يستخدم عادة لدعم صحة البروستاتا بعد الأربعين', price:'380 EGP', priceAr:'380 جنيه', link:'https://www.amazon.eg/s?k=saw+palmetto' },
    { icon:'❤️', name:'CoQ10', nameAr:'كوإنزيم كيو 10', why:'Supports heart function and energy production, which naturally decline with age', whyAr:'يدعم وظيفة القلب وإنتاج الطاقة التي تقل طبيعياً مع العمر', price:'520 EGP', priceAr:'520 جنيه', link:'https://www.amazon.eg/s?k=coq10' },
    { icon:'💪', name:'Whey Protein Isolate', nameAr:'واي بروتين أيزوليت', why:'Helps preserve muscle mass, which declines faster after 40', whyAr:'يحافظ على الكتلة العضلية التي تقل بسرعة أكبر بعد الأربعين', price:'950 EGP', priceAr:'950 جنيه', link:'https://www.amazon.eg/s?k=whey+protein+isolate' },
    { icon:'⚡', name:'Magnesium', nameAr:'ماغنسيوم', why:'Supports heart rhythm, sleep, and muscle recovery', whyAr:'يدعم نبض القلب والنوم واستشفاء العضلات', price:'250 EGP', priceAr:'250 جنيه', link:'https://www.amazon.eg/s?k=magnesium' },
    { icon:'☀️', name:'Vitamin D3', nameAr:'فيتامين د3', why:'Common deficiency in Egypt despite sunshine - supports bones and testosterone', whyAr:'نقص شائع في مصر رغم الشمس — يدعم العظام والتستوستيرون', price:'180 EGP', priceAr:'180 جنيه', link:'https://www.amazon.eg/s?k=vitamin+d3' }
  ],
  kids: [
    { icon:'🧒', name:"Kids' Multivitamin (gummies)", nameAr:'مالتيفيتامين أطفال (جامي)', why:'Supports overall growth and covers gaps in a picky eater\'s diet', whyAr:'يدعم النمو العام ويغطي النقص عند الأطفال قليلي التنوع في الأكل', price:'320 EGP', priceAr:'320 جنيه', link:'https://www.amazon.eg/s?k=kids+multivitamin+gummies' },
    { icon:'☀️', name:'Vitamin D3 Drops', nameAr:'نقط فيتامين د3', why:'Essential for growing bones - very common deficiency in children', whyAr:'أساسي لنمو العظام — نقص شائع جداً عند الأطفال', price:'150 EGP', priceAr:'150 جنيه', link:'https://www.amazon.eg/s?k=vitamin+d3+drops+kids' },
    { icon:'🐟', name:'Omega-3 DHA (kids)', nameAr:'أوميجا 3 دي إتش إيه للأطفال', why:'Supports brain and eye development', whyAr:'يدعم نمو المخ والعين', price:'280 EGP', priceAr:'280 جنيه', link:'https://www.amazon.eg/s?k=omega+3+dha+kids' },
    { icon:'🦠', name:'Kids\' Probiotics', nameAr:'بروبيوتيك للأطفال', why:'Supports digestion and immune health', whyAr:'يدعم الهضم وصحة المناعة', price:'260 EGP', priceAr:'260 جنيه', link:'https://www.amazon.eg/s?k=kids+probiotics' },
    { icon:'🦴', name:'Calcium (kids)', nameAr:'كالسيوم للأطفال', why:'Supports bone growth during childhood', whyAr:'يدعم نمو العظام في مرحلة الطفولة', price:'180 EGP', priceAr:'180 جنيه', link:'https://www.amazon.eg/s?k=calcium+kids' }
  ],
};
DIET_SUPPLEMENTS.kids.push({ icon:'⚕️', name:'Always consult a pediatrician first', nameAr:'استشر طبيب الأطفال دائماً أولاً', why:'Children\'s supplement needs vary widely by age - a pediatrician should confirm dosage', whyAr:'احتياجات الأطفال من المكملات تختلف كثيراً حسب العمر — يجب أن يؤكد طبيب الأطفال الجرعة', price:'', priceAr:'', link:'#' });

// Lab-driven supplement/advisory suggestions with no weather/location context
// needed - used by the Supplements tab, which the user can open without ever
// visiting the Weather & Hydration tab. Same underlying flags/logic as
// buildEcoRecommendations() uses, just without the indoor/watch-driven items.
app.get(`${BASE}/api/lab-results/recommendations`, auth, (req,res) => {
  const labFlags = getLatestLabFlags(req.user.id);
  const diet = DIET_SUPPLEMENTS[req.query.diet] ? req.query.diet : 'atkins';
  res.json({
    supplements: buildLabSupplements(labFlags),
    advisories: buildLabAdvisories(labFlags),
    dietSupplements: DIET_SUPPLEMENTS[diet],
  });
});

// Shared by manual entry AND photo-upload extraction — was previously
// inlined only in the manual-entry POST handler.
async function analyzeLabResults(results, diet) {
  const prompt = `You are a medical nutrition AI assistant. Analyze these lab results for a patient on a ${diet} diet:\n${JSON.stringify(results)}\n\nProvide a brief analysis in Arabic and English covering:\n1. Which values are normal/abnormal\n2. What dietary changes could help\n3. Overall health trend\n\nReturn JSON: {"analysis_ar":"...","analysis_en":"...","status":"good|warning|critical","recommendations_ar":["..."],"recommendations_en":["..."]}`;
  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method:'POST',
    headers:{'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
    // 800 was too low — a full bilingual (AR+EN) analysis with recommendation
    // lists routinely hit stop_reason:"max_tokens" and got cut off mid-JSON,
    // which is a genuine truncation no amount of parsing robustness can fix.
    body: JSON.stringify({model:'claude-haiku-4-5-20251001',max_tokens:2000,messages:[{role:'user',content:prompt}]})
  });
  const aiData = await aiRes.json();
  // Claude sometimes wraps JSON in a ```json fence despite the prompt asking
  // for raw JSON — strip it the same robust way the vision-extraction step
  // already does, rather than a naive JSON.parse that breaks on the fence.
  const raw = aiData.content?.[0]?.text || '{}';
  const match = raw.match(/\{[\s\S]*\}/);
  return JSON.parse(match ? match[0] : raw);
}

function saveLabEntry(userId, date, results, numericResults) {
  const all = load('lab_results.json') || {};
  if (!all[userId]) all[userId] = [];
  const existing = all[userId].findIndex(l => l.date === date);
  const entry = { date, results, numericResults: numericResults || {}, savedAt: new Date().toISOString() };
  if (existing >= 0) all[userId][existing] = entry;
  else all[userId].push(entry);
  all[userId] = all[userId].sort((a,b)=>b.date.localeCompare(a.date)).slice(0,24);
  save('lab_results.json', all);
  return { all, entry };
}

function getLatestLabFlags(userId) {
  const all = load('lab_results.json') || {};
  const entries = all[userId] || [];
  const latest = entries[0];
  if (!latest || !latest.numericResults) return {};
  return deriveLabFlags(latest.numericResults);
}

function updateLabEntryAnalysis(userId, date, analysis) {
  const all = load('lab_results.json') || {};
  const idx = (all[userId]||[]).findIndex(l=>l.date===date);
  if (idx >= 0) { all[userId][idx].analysis = analysis; save('lab_results.json', all); }
}

app.post(`${BASE}/api/lab-results`, auth, async (req,res) => {
  if (!BETA_MODE && !['vip','elite'].includes(req.userObj.plan) && req.userObj.role !== 'admin')
    return res.status(403).json({error:'VIP/Elite only'});
  const { date, results } = req.body;
  if (!date || !results) return res.status(400).json({error:'Date and results required'});
  // Manual entry already keys by the known testId vocabulary with numeric
  // values (see dashboard.html's labTests form) - filter defensively rather
  // than trusting the request body wholesale before treating it as flaggable.
  const numericResults = {};
  for (const id of LAB_TEST_IDS) {
    if (typeof results[id] === 'number') numericResults[id] = results[id];
  }
  const uid = req.user.id;
  const entry = { date, results, numericResults, savedAt: new Date().toISOString() };
  // Atomic upsert — safe even if another request touches this user's log.
  update('lab_results.json', all => {
    if (!all[uid]) all[uid] = [];
    const i = all[uid].findIndex(l => l.date === date);
    if (i >= 0) all[uid][i] = entry; else all[uid].push(entry);
    all[uid] = all[uid].sort((a,b)=>b.date.localeCompare(a.date)).slice(0,24);
    return all;
  }, {});

  try {
    const u = req.userObj;
    const diet = u.profile?.diet || 'balanced';
    const prompt = `You are a medical nutrition AI assistant. Analyze these lab results for a patient on a ${diet} diet:\n${JSON.stringify(results)}\n\nProvide a brief analysis in Arabic and English covering:\n1. Which values are normal/abnormal\n2. What dietary changes could help\n3. Overall health trend\n\nReturn ONLY valid JSON (no markdown, no code fences): {"analysis_ar":"...","analysis_en":"...","status":"good|warning|critical","recommendations_ar":["..."],"recommendations_en":["..."]}`;
    // 800 was too low here too (see analyzeLabResults above) - full bilingual
    // analysis with recommendation lists gets cut off mid-JSON at that budget.
    const { text } = await ai.chat({ messages: [{ role:'user', content: prompt }], maxTokens: 2000 });
    // Free models sometimes wrap JSON in ```; strip fences before parsing.
    const analysis = JSON.parse((text || '{}').replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim());
    // Re-read under a transaction so the analysis merges onto the latest state
    // instead of clobbering anything written during the await above.
    update('lab_results.json', all => {
      if (!all[uid]) all[uid] = [];
      const i = all[uid].findIndex(l => l.date === date);
      if (i >= 0) all[uid][i] = { ...all[uid][i], analysis };
      else all[uid].push({ ...entry, analysis });
      return all;
    }, {});
    res.json({ok:true, analysis});
  } catch(e) {
    res.json({ok:true, analysis:null});
  }
});

// ─── LAB RESULTS: PHOTO/PDF UPLOAD WITH AUTO-EXTRACTION ───────────────────────
// User uploads a photo/scan of a real lab report; Claude's vision reads the
// values directly rather than requiring manual typing, then feeds into the
// exact same analysis pipeline as manual entry above.
const labUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg','image/png','image/webp','image/heic','application/pdf'].includes(file.mimetype);
    cb(ok ? null : new Error('Unsupported file type — use JPG, PNG, WEBP, HEIC, or PDF'), ok);
  }
});

app.post(`${BASE}/api/lab-results/upload`, auth, labUpload.single('file'), async (req,res) => {
  if (!BETA_MODE && !['vip','elite'].includes(req.userObj.plan) && req.userObj.role !== 'admin')
    return res.status(403).json({error:'VIP/Elite only'});
  if (!req.file) return res.status(400).json({error:'No file uploaded'});
  if (req.file.mimetype === 'application/pdf')
    return res.status(400).json({error:'PDF غير مدعوم حالياً، من فضلك صور التحليل بالكاميرا أو ارفع صورة · PDF not supported yet — please upload a photo of the report instead'});

  const date = req.body.date || new Date().toISOString().split('T')[0];

  try {
    const b64 = req.file.buffer.toString('base64');
    const extractPrompt = `This image is a medical lab report (blood test results), possibly in Arabic or English. Extract every test name and its value with unit. If a reference/normal range is printed, include it.\n\nAlso classify each test against this known list, if it matches one: glucose (blood glucose/fasting sugar), hba1c, cholesterol (total cholesterol), ldl, hdl, triglycerides, creatinine, tsh, hemoglobin, vitd (vitamin D). Use the matching id as "testId", or null if it doesn't match any of these. Also give the value as a plain number in "numericValue" (e.g. 185, not "185 mg/dL") when it's a single numeric result - use null for non-numeric results.\n\nReturn ONLY valid JSON, no other text, in this exact shape:\n{"tests": [{"name":"...", "value": "...", "unit": "...", "range": "...", "testId": "..." or null, "numericValue": 0 or null}]}\n\nIf the image is not a lab report or no values are readable, return {"tests": []}.`;
    const extractRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1500,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: req.file.mimetype, data: b64 } },
            { type: 'text', text: extractPrompt }
          ]
        }]
      })
    });
    const extractData = await extractRes.json();
    const rawText = extractData.content?.[0]?.text || '{}';
    const match = rawText.match(/\{[\s\S]*\}/);
    const extracted = match ? JSON.parse(match[0]) : { tests: [] };

    if (!extracted.tests || extracted.tests.length === 0) {
      return res.json({ ok:false, error: 'لم نتمكن من قراءة نتائج واضحة من الصورة، جرب صورة أوضح · Could not read clear results from the image, try a clearer photo' });
    }

    // Normalize into the same {testName: value} shape manual entry already uses
    const results = {};
    const numericResults = {};
    for (const t of extracted.tests) {
      if (!t.name) continue;
      results[t.name] = t.range ? `${t.value} ${t.unit||''} (${t.range})`.trim() : `${t.value} ${t.unit||''}`.trim();
      // testId lets this uploaded entry feed the same deterministic flag logic
      // manual entry already produces (see deriveLabFlags) - without it, an
      // uploaded report's values are just display strings, unusable for the
      // automatic food/supplement mapping.
      if (LAB_TEST_IDS.includes(t.testId) && typeof t.numericValue === 'number') {
        numericResults[t.testId] = t.numericValue;
      }
    }

    saveLabEntry(req.user.id, date, results, numericResults);
    secLog('LAB_UPLOAD', getIP(req), { userId: req.user.id, testCount: extracted.tests.length });

    let analysis = null;
    try {
      const diet = req.userObj.profile?.diet || 'balanced';
      analysis = await analyzeLabResults(results, diet);
      updateLabEntryAnalysis(req.user.id, date, analysis);
    } catch (e) { console.error('[lab-upload] analysis step failed (extraction still OK):', e.message); }

    res.json({ ok:true, date, results, analysis });
  } catch (e) {
    console.error('[lab-upload] error:', e.message);
    res.status(500).json({ error: 'حصل خطأ أثناء تحليل الصورة · Error processing the image' });
  }
});


// ─── ADMIN IMPERSONATION ──────────────────────────────────────────────────────


// ─── WATCH SYNC ENGINE ────────────────────────────────────────────────────────
// Unified schema: { userId, date, source, steps, heartRate, caloriesBurned, sleep, spO2, stress, water }

app.post(`${BASE}/api/watch/sync`, auth, (req, res) => {
  const { source, date, steps, heartRate, caloriesBurned, sleep, spO2, stress, water } = req.body;
  if (!source || !date) return res.status(400).json({ error: 'source and date required' });

  const allowed = ['apple_watch','wear_os','galaxy_watch','garmin','fitbit','oura','whoop','polar','strava','suunto','ultrahuman','honor_watch','manual'];
  if (!allowed.includes(source)) return res.status(400).json({ error: 'Invalid source' });

  const all = load('watch_data.json') || {};
  if (!all[req.user.id]) all[req.user.id] = [];

  // Deduplicate by date + source
  const key = `${date}_${source}`;
  const existing = all[req.user.id].findIndex(d => `${d.date}_${d.source}` === key);

  const entry = {
    date,
    source,
    steps:           parseInt(steps)           || null,
    heartRate:       parseInt(heartRate)        || null,
    caloriesBurned:  parseInt(caloriesBurned)   || null,
    sleep:           parseFloat(sleep)          || null,
    spO2:            parseFloat(spO2)           || null,
    stress:          parseInt(stress)           || null,
    water:           parseFloat(water)          || null,
    syncedAt: new Date().toISOString()
  };

  if (existing >= 0) all[req.user.id][existing] = entry;
  else all[req.user.id].push(entry);

  // Keep last 90 days per user
  all[req.user.id] = all[req.user.id]
    .sort((a, b) => b.date.localeCompare(a.date))
    .slice(0, 90);

  save('watch_data.json', all);
  secLog('WATCH_SYNC', getIP(req), { userId: req.user.id, source, date });
  res.json({ ok: true, entry });
});

app.get(`${BASE}/api/watch/data`, auth, (req, res) => {
  const all = load('watch_data.json') || {};
  const userdata = all[req.user.id] || [];
  const days = Math.min(parseInt(req.query.days) || 7, 90);
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  const cutoffStr = cutoff.toISOString().split('T')[0];
  const filtered = userdata.filter(d => d.date >= cutoffStr);
  res.json({ data: filtered, days, count: filtered.length });
});

// ─── OPEN WEARABLES INTEGRATION ───────────────────────────────────────────────
// Self-hosted aggregator (github.com/the-momentum/open-wearables) handling real
// OAuth connections to Garmin/Fitbit/Oura/Whoop/Polar/Strava/Suunto/Ultrahuman -
// genuinely server-side, no companion app needed for these. Apple Health/Android
// Health Connect are NOT covered here - both are on-device-only by OS restriction,
// need a companion app embedding Open Wearables' SDK (separate future phase).
const OW_BASE_URL = process.env.OPEN_WEARABLES_URL || 'https://wearables.talabatito.com';
const OW_API_KEY = process.env.OPEN_WEARABLES_API_KEY || '';
const OW_WEBHOOK_SECRET = process.env.OPEN_WEARABLES_WEBHOOK_SECRET || '';
const OW_PROVIDERS = ['garmin', 'fitbit', 'oura', 'whoop', 'polar', 'strava', 'suunto', 'ultrahuman'];

async function getOrCreateOpenWearablesUserId(user) {
  if (user.openWearablesUserId) return user.openWearablesUserId;

  const r = await fetch(`${OW_BASE_URL}/api/v1/users`, {
    method: 'POST',
    headers: { 'X-Open-Wearables-API-Key': OW_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: user.email || undefined }),
  });
  if (!r.ok) throw new Error(`Open Wearables user create failed: ${r.status}`);
  const created = await r.json();

  const users = load('users.json') || [];
  const idx = users.findIndex(u => u.id === user.id);
  if (idx >= 0) { users[idx].openWearablesUserId = created.id; save('users.json', users); }
  return created.id;
}

// Redirects the browser straight into the provider's OAuth page - the dashboard
// connect button just links here, no client-side API key exposure needed.
app.get(`${BASE}/api/watch/connect/:provider`, auth, async (req, res) => {
  const provider = req.params.provider;
  if (!OW_PROVIDERS.includes(provider)) return res.status(400).json({ error: 'Unsupported provider' });
  if (!OW_API_KEY) return res.status(503).json({ error: 'Wearable integration not configured yet' });

  try {
    const owUserId = await getOrCreateOpenWearablesUserId(req.userObj);
    const authRes = await fetch(
      `${OW_BASE_URL}/api/v1/oauth/${provider}/authorize?user_id=${owUserId}&redirect_uri=${encodeURIComponent(`https://diet.talabatito.com${BASE}/dashboard`)}`
    );
    if (!authRes.ok) throw new Error(`authorize failed: ${authRes.status}`);
    const { authorization_url } = await authRes.json();
    res.redirect(authorization_url);
  } catch (e) {
    console.error('[watch/connect] error:', e.message);
    res.status(502).json({ error: 'تعذر بدء الاتصال بالجهاز الآن، حاول تاني · Could not start the device connection right now, try again' });
  }
});

app.get(`${BASE}/api/watch/connections`, auth, async (req, res) => {
  if (!req.userObj.openWearablesUserId || !OW_API_KEY) return res.json({ connections: [] });
  try {
    const r = await fetch(`${OW_BASE_URL}/api/v1/users/${req.userObj.openWearablesUserId}/connections`, {
      headers: { 'X-Open-Wearables-API-Key': OW_API_KEY },
    });
    if (!r.ok) return res.json({ connections: [] });
    res.json({ connections: await r.json() });
  } catch (e) {
    res.json({ connections: [] });
  }
});

// Maps a batch of timeseries samples (already grouped by local date) into the
// existing watch_data.json entry shape, merging only the field(s) this event
// actually carries - separate events arrive per metric, so a full overwrite
// would wipe out data other events already wrote for the same day.
function upsertWatchMetric(userId, date, source, patch) {
  const all = load('watch_data.json') || {};
  if (!all[userId]) all[userId] = [];
  const key = `${date}_${source}`;
  const idx = all[userId].findIndex(d => `${d.date}_${d.source}` === key);
  if (idx >= 0) {
    all[userId][idx] = { ...all[userId][idx], ...patch, syncedAt: new Date().toISOString() };
  } else {
    all[userId].push({
      date, source, steps: null, heartRate: null, caloriesBurned: null,
      sleep: null, spO2: null, stress: null, water: null,
      ...patch, syncedAt: new Date().toISOString(),
    });
  }
  all[userId] = all[userId].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 90);
  save('watch_data.json', all);
}

// Timestamps arrive already expressed in their own local offset (e.g.
// "2025-12-19T07:30:00+01:00") - the date portion IS the local date already,
// no timezone math needed, just take it as-is.
function localDateFromTimestamp(ts) {
  return (ts || '').slice(0, 10);
}

function findUserByOpenWearablesId(owUserId) {
  const users = load('users.json') || [];
  return users.find(u => u.openWearablesUserId === owUserId);
}

// Groups a timeseries webhook's samples by local date and picks the value each
// DietHub metric field needs: daily-total samples are used directly when present
// (per Open Wearables' own guidance - do not sum on top of a reported total),
// otherwise the latest sample in the day stands in for a single-value field.
function reduceSamplesByDate(samples, wantedType) {
  const byDate = {};
  for (const s of samples) {
    if (s.type !== wantedType) continue;
    const d = localDateFromTimestamp(s.timestamp);
    if (!byDate[d]) byDate[d] = { total: 0, hasTotal: false, latest: null, latestTs: '' };
    if (s.is_daily_total) {
      byDate[d].hasTotal = true;
      byDate[d].total = s.value;
    } else if (!byDate[d].hasTotal) {
      byDate[d].total += s.value;
    }
    if (s.timestamp > byDate[d].latestTs) { byDate[d].latest = s.value; byDate[d].latestTs = s.timestamp; }
  }
  return byDate;
}

app.post(`${BASE}/api/watch/webhook`, async (req, res) => {
  if (!OW_WEBHOOK_SECRET) return res.status(503).json({ error: 'Webhook not configured' });

  let event;
  try {
    const wh = new Webhook(OW_WEBHOOK_SECRET);
    event = wh.verify(req.rawBody, req.headers);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid signature' });
  }

  // Always 2xx quickly per Open Wearables' own delivery guidance - unrecognized
  // event types are acknowledged and ignored, not treated as failures to retry.
  try {
    const { type, data } = event;
    const owUserId = data?.user_id;
    const user = owUserId ? findUserByOpenWearablesId(owUserId) : null;
    if (!user) return res.json({ ok: true, skipped: 'unknown user' });

    const source = OW_PROVIDERS.includes(data.provider) ? data.provider : (data.provider || 'manual');

    if (type === 'sleep.created') {
      const date = localDateFromTimestamp(data.start_time);
      upsertWatchMetric(user.id, date, source, { sleep: Math.round((data.duration_seconds / 3600) * 10) / 10 });
    } else if (type === 'steps.created') {
      const byDate = reduceSamplesByDate(data.samples, 'steps');
      for (const [date, v] of Object.entries(byDate)) upsertWatchMetric(user.id, date, source, { steps: Math.round(v.total) });
    } else if (type === 'calories.created') {
      const byDate = reduceSamplesByDate(data.samples, 'energy');
      for (const [date, v] of Object.entries(byDate)) upsertWatchMetric(user.id, date, source, { caloriesBurned: Math.round(v.total) });
    } else if (type === 'heart_rate.created') {
      const byDate = reduceSamplesByDate(data.samples, 'heart_rate');
      for (const [date, v] of Object.entries(byDate)) if (v.latest != null) upsertWatchMetric(user.id, date, source, { heartRate: Math.round(v.latest) });
    } else if (type === 'spo2.created') {
      const byDate = reduceSamplesByDate(data.samples, 'oxygen_saturation');
      for (const [date, v] of Object.entries(byDate)) if (v.latest != null) upsertWatchMetric(user.id, date, source, { spO2: v.latest });
    } else if (type === 'stress.created') {
      const byDate = reduceSamplesByDate(data.samples, 'garmin_stress_level');
      for (const [date, v] of Object.entries(byDate)) if (v.latest != null) upsertWatchMetric(user.id, date, source, { stress: Math.round(v.latest) });
    }
    // Other event types (workouts, connection status, etc.) are acknowledged but not mapped yet.

    secLog('WATCH_WEBHOOK', getIP(req), { userId: user.id, type });
    res.json({ ok: true });
  } catch (e) {
    console.error('[watch/webhook] processing error:', e.message);
    res.json({ ok: true }); // still 2xx - don't want Svix retrying a payload we can't parse
  }
});

app.get(`${BASE}/api/admin/watch-data`, auth, adminOnly, (req, res) => {
  const all = load('watch_data.json') || {};
  const users = load('users.json') || [];
  const summary = Object.entries(all).map(([userId, data]) => {
    const user = users.find(u => u.id === userId);
    const latest = data[0] || {};
    return {
      username: user?.username || userId,
      plan: user?.plan,
      latestDate: latest.date,
      latestSource: latest.source,
      latestSteps: latest.steps,
      latestHeartRate: latest.heartRate,
      totalEntries: data.length
    };
  });
  res.json(summary);
});


// ─── ADMIN IMPERSONATION ──────────────────────────────────────────────────────
app.post(`${BASE}/api/admin/impersonate/:userId`, auth, adminOnly, (req, res) => {
  const users = load('users.json') || [];
  const u = users.find(u => u.id === req.params.userId);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const token = mkToken({ ...u, _impersonated: true });
  secLog('ADMIN_IMPERSONATE', getIP(req), { adminId: req.user.id, targetUser: u.username });
  res.json({ ok: true, token, username: u.username, plan: u.plan });
});

// ─── WEATHER & HYDRATION ─────────────────────────────────────────────────────
const weatherCache = new Map();

function haversineMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLon/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

// Food pools keyed by [temp tier][humidity band]. Humidity changes which foods
// make sense at the same temperature - humid heat traps body heat (sweat can't
// evaporate well) so it needs even lighter/colder/water-richer food than dry
// heat at the same temperature; humid cold calls for more warming soups than
// dry cold. Each pool has 5 candidates so the daily rotation below actually
// varies which 3 show up, instead of the same fixed set forever.
const FOOD_POOLS = {
  veryHot: {
    high: ['سلطة خيار وبطيخ مثلجة · Chilled cucumber & watermelon salad', 'زبادي بارد · Cold yogurt', 'خس وخضار نيئة · Raw lettuce & greens', 'شمام مثلج · Chilled cantaloupe', 'سلطة جرجير بالليمون · Arugula salad with lemon'],
    mid:  ['سلطة دجاج خفيفة · Light chicken salad', 'خيار وطماطم مبردة · Cold cucumber & tomato', 'جبن قريش · Fresh cheese', 'سلطة تونة خفيفة · Light tuna salad', 'زبادي يوناني بالخيار · Greek yogurt with cucumber'],
    low:  ['بطيخ وشمام · Watermelon & cantaloupe', 'خيار بالنعناع · Cucumber with mint', 'سلطة فواكه مائية · Water-rich fruit salad', 'عصير برتقال طازج · Fresh orange juice side', 'سلطة خيار وزبادي · Cucumber & yogurt salad'],
  },
  hot: {
    high: ['سمك مشوي خفيف · Light grilled fish', 'سلطة خضار طازجة · Fresh vegetable salad', 'زبادي يوناني · Greek yogurt', 'صدر فراخ بالليمون · Lemon chicken breast', 'سلطة كينوا بالخضار · Quinoa vegetable salad'],
    mid:  ['صدر فراخ مشوي · Grilled chicken', 'سمك خفيف · Light fish', 'سلطة خضروات · Vegetable salad', 'جمبري مشوي · Grilled shrimp', 'ديك رومي خفيف · Light turkey'],
    low:  ['صدر فراخ مشوي مع خيار · Grilled chicken with cucumber', 'عصير طماطم · Tomato juice side', 'سلطة خضار · Vegetable salad', 'شوربة خضار باردة · Chilled vegetable soup', 'سلطة فتوش · Fattoush salad'],
  },
  mild: {
    high: ['بروتين متوسط مطبوخ · Moderately cooked protein', 'شوربة خفيفة · Light soup', 'خضار سوتيه · Sautéed vegetables', 'سمك مطهو بالبخار · Steamed fish', 'أرز بالخضار · Rice with vegetables'],
    mid:  ['بروتين متوسط · Moderate protein', 'خضار مطبوخة · Cooked vegetables', 'أرز بني بالخضار · Brown rice with vegetables', 'دجاج بالفرن · Baked chicken', 'سلطة دافئة · Warm salad'],
    low:  ['بروتين متوسط · Moderate protein', 'خضار مطبوخة بصلصة · Cooked vegetables with sauce', 'فواكه طازجة · Fresh fruit', 'شوربة خضار · Vegetable soup', 'سمك بالليمون · Fish with lemon'],
  },
  cold: {
    high: ['شوربة عدس دافئة · Warm lentil soup', 'لحم مطبوخ ببطء · Slow-cooked beef', 'خضار جذرية مشوية · Roasted root vegetables', 'شوربة خضار كريمية · Creamy vegetable soup', 'يخنة دجاج · Chicken stew'],
    mid:  ['شوربة دجاج · Chicken soup', 'لحم دافئ · Warm beef', 'خضار مشوية · Roasted vegetables', 'يخنة لحم · Beef stew', 'حساء عدس · Lentil soup'],
    low:  ['شوربة دجاج بالليمون · Chicken soup with lemon', 'لحم دافئ · Warm beef', 'خضار مشوية مع زيت زيتون · Roasted vegetables with olive oil', 'شوربة خضار دافئة · Warm vegetable soup', 'دجاج محمر بالثوم · Garlic roasted chicken'],
  },
};

function humidityBand(humidity) {
  if (humidity > 65) return 'high';
  if (humidity < 35) return 'low';
  return 'mid';
}

// Picks `count` distinct items from a pool, rotating the starting offset by
// day-of-year so the same temp+humidity combo shows different foods day to
// day instead of the exact same fixed list forever.
function pickRotating(pool, count) {
  const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / 86400000);
  const n = pool.length;
  const picks = [];
  for (let i = 0; i < count; i++) picks.push(pool[(dayOfYear + i) % n]);
  return picks;
}

function buildWeatherRecs(temp, humidity) {
  let hydrationL, alert = null, foods = [], drinks = [];

  if      (temp >= 40) { hydrationL = 4.5; alert = 'خطر جفاف شديد — اشرب ماء الآن! · Severe dehydration risk — drink NOW!'; }
  else if (temp >= 35) { hydrationL = 3.5; alert = 'طقس حار جداً — اشرب كل 20 دقيقة · Very hot — drink every 20 min'; }
  else if (temp >= 28) hydrationL = 2.8;
  else if (temp >= 20) hydrationL = 2.2;
  else                 hydrationL = 1.8;

  if (humidity > 80) { hydrationL += 0.5; drinks.push('مشروبات إلكتروليت · Electrolyte drinks'); }
  if (humidity < 30) { hydrationL += 0.3; drinks.push('ماء مع ليمون · Water with lemon'); }

  const hBand = humidityBand(humidity);
  if (temp >= 35) {
    foods = pickRotating(FOOD_POOLS.veryHot[hBand], 3);
    drinks.push('ماء بارد · Cold water', 'عصير بطيخ · Watermelon juice');
  } else if (temp >= 25) {
    foods = pickRotating(FOOD_POOLS.hot[hBand], 3);
    drinks.push('ماء · Water', 'ماء جوز هند · Coconut water');
  } else if (temp >= 15) {
    foods = pickRotating(FOOD_POOLS.mild[hBand], 3);
    drinks.push('ماء دافئ · Warm water', 'شاي أخضر · Green tea');
  } else {
    foods = pickRotating(FOOD_POOLS.cold[hBand], 3);
    drinks.push('شوربة · Soup', 'شاي أعشاب · Herbal tea');
  }

  return { hydrationL: parseFloat(hydrationL.toFixed(1)), alert, foods, drinks };
}

// Indoor/outdoor: an explicit saved geofence zone always wins when the current
// position falls inside one. Otherwise fall back to GPS accuracy - signal
// attenuation indoors commonly pushes accuracy from single-digit/~30m outdoors
// to 50m+ indoors, so it's a real (if approximate) signal that's already
// available from navigator.geolocation with no new hardware. A future mobile/
// watch client reports the same accuracy field, so this needs no API change
// to keep working there.
function inferIndoorOutdoor(userId, lat, lon, accuracy) {
  const zones = load('geofence_zones.json') || {};
  const userZones = zones[userId] || [];
  const activeZone = userZones.find(z => haversineMeters(lat, lon, z.lat, z.lon) <= z.radius) || null;
  if (activeZone) {
    if (activeZone.type === 'outdoor') return { state: 'outdoor', source: 'zone', zone: activeZone };
    if (['home', 'work', 'gym'].includes(activeZone.type)) return { state: 'indoor', source: 'zone', zone: activeZone };
    return { state: 'unknown', source: 'zone', zone: activeZone };
  }
  if (accuracy != null && !isNaN(accuracy)) {
    return { state: accuracy <= 50 ? 'outdoor' : 'indoor', source: 'accuracy', zone: null };
  }
  return { state: 'unknown', source: 'none', zone: null };
}

function getLatestWatchEntry(userId) {
  const all = load('watch_data.json') || {};
  const entries = all[userId] || [];
  return entries[0] || null; // already stored sorted newest-first (see /api/watch/sync)
}

// Thresholds match dashboard.html's labTests normal ranges exactly. Deterministic
// (not AI-driven) on purpose - automatic supplement/food suggestions need to be
// reliable, unlike the free-text AI narrative in analyzeLabResults() which stays
// presentational-only. creatinine is deliberately excluded: kidney-function values
// are too clinically sensitive for a rule-based consumer suggestion.
const LAB_FLAG_RULES = {
  glucose:       { high: 100 },
  hba1c:         { high: 5.7 },
  cholesterol:   { high: 200 },
  ldl:           { high: 100 },
  hdl:           { low: 40 },
  triglycerides: { high: 150 },
  hemoglobin:    { low: 13.5 },
  vitd:          { low: 30 },
  tsh:           { low: 0.4, high: 4.0 },
};

function deriveLabFlags(numericResults) {
  const flags = {};
  if (!numericResults) return flags;
  for (const [id, rule] of Object.entries(LAB_FLAG_RULES)) {
    const v = numericResults[id];
    if (v == null || isNaN(v)) continue;
    if (rule.high != null && v > rule.high) flags[`high_${id}`] = true;
    if (rule.low != null && v < rule.low) flags[`low_${id}`] = true;
  }
  return flags;
}

// Shared between buildEcoRecommendations() (weather panel) and /api/meal-plan
// (banner) so the same flags produce the same advisory copy everywhere.
function buildLabAdvisories(labFlags) {
  const advisories = [];
  if (labFlags.high_glucose || labFlags.high_hba1c) {
    advisories.push('بناءً على تحليلك الأخير، قلل السكريات البسيطة والكربوهيدرات المكررة اليوم · Based on your latest lab results, reduce simple sugars and refined carbs today');
  }
  if (labFlags.high_tsh || labFlags.low_tsh) {
    advisories.push('نتيجة الغدة الدرقية خارج المعدل الطبيعي — يُنصح باستشارة طبيبك · Your thyroid (TSH) result is outside the normal range — please consult your doctor');
  }
  return advisories;
}

// Adds supplement suggestions on top of buildWeatherRecs()'s hydration/food/
// drinks, informed by location (indoor/outdoor), the user's latest synced
// watch entry, and their latest lab-result flags when available. Framed as
// general-wellness suggestions, not diagnostic claims - consistent with this
// app's existing "consult your doctor" tone elsewhere. Degrades gracefully
// with no watch/lab data.
function buildEcoRecommendations(temp, humidity, indoorOutdoor, watchEntry, labFlags) {
  const base = buildWeatherRecs(temp, humidity);
  const supplements = [];
  labFlags = labFlags || {};

  const highExertion = watchEntry && ((watchEntry.steps || 0) >= 8000 || (watchEntry.caloriesBurned || 0) >= 400);
  if (temp >= 30 && highExertion) {
    supplements.push({
      icon: '⚡', nameAr: 'إلكتروليتات', name: 'Electrolytes',
      whyAr: 'تعويض الأملاح المفقودة مع التعرق في الحر مع نشاط عالي · Replaces salts lost to sweat in heat with high activity',
      link: 'https://www.amazon.eg/s?k=electrolyte+powder',
    });
  }

  const poorRecovery = watchEntry && ((watchEntry.sleep != null && watchEntry.sleep < 6) || (watchEntry.stress != null && watchEntry.stress >= 70));
  if (poorRecovery) {
    supplements.push({
      icon: '🌙', nameAr: 'مغنيسيوم', name: 'Magnesium',
      whyAr: 'يدعم الاسترخاء والنوم مع قلة النوم أو الإجهاد المرتفع · Supports relaxation and sleep quality with low sleep or high stress',
      link: 'https://www.amazon.eg/s?k=magnesium+supplement',
    });
  }

  // Vitamin D can be triggered by either the indoor signal or a low lab
  // reading - only ever show it once, with whichever reason(s) actually apply.
  const vitdReasonsAr = [];
  const vitdReasonsEn = [];
  if (indoorOutdoor.state === 'indoor') {
    vitdReasonsAr.push('التواجد الداخلي لفترات طويلة يقلل التعرض لأشعة الشمس');
    vitdReasonsEn.push('Extended time indoors reduces natural sun exposure');
  }
  if (labFlags.low_vitd) {
    vitdReasonsAr.push('نتيجة تحليل فيتامين د الأخيرة منخفضة');
    vitdReasonsEn.push('Your latest Vitamin D lab result was low');
  }
  if (vitdReasonsAr.length) {
    supplements.push({
      icon: '☀️', nameAr: 'فيتامين د', name: 'Vitamin D',
      whyAr: `${vitdReasonsAr.join(' · ')} · ${vitdReasonsEn.join(' · ')}`,
      link: 'https://www.amazon.eg/s?k=vitamin+d3',
    });
  }

  supplements.push(...buildLabSupplements(labFlags, { includeVitd: !vitdReasonsAr.length }));

  return { ...base, supplements, advisories: buildLabAdvisories(labFlags), indoorOutdoor: indoorOutdoor.state };
}

// Lab-only supplement suggestions (omega-3 / iron / vitamin D), reused by
// buildEcoRecommendations() above and by the standalone /api/lab-results/
// recommendations endpoint (Supplements tab has no weather/location context).
// includeVitd defaults true; buildEcoRecommendations passes false when it has
// already added a merged indoor+lab Vitamin D card itself, to avoid a duplicate.
function buildLabSupplements(labFlags, { includeVitd = true } = {}) {
  const supplements = [];
  labFlags = labFlags || {};

  if (includeVitd && labFlags.low_vitd) {
    supplements.push({
      icon: '☀️', nameAr: 'فيتامين د', name: 'Vitamin D',
      whyAr: 'نتيجة تحليل فيتامين د الأخيرة منخفضة · Your latest Vitamin D lab result was low',
      link: 'https://www.amazon.eg/s?k=vitamin+d3',
    });
  }

  if (labFlags.high_ldl || labFlags.high_cholesterol || labFlags.high_triglycerides || labFlags.low_hdl) {
    supplements.push({
      icon: '🐟', nameAr: 'أوميجا 3', name: 'Omega-3',
      whyAr: 'بناءً على نتائج الدهون في تحليلك الأخير · Based on your latest lipid panel results',
      link: 'https://www.amazon.eg/s?k=omega+3',
    });
  }

  if (labFlags.low_hemoglobin) {
    supplements.push({
      icon: '🥩', nameAr: 'أطعمة غنية بالحديد', name: 'Iron-rich foods',
      whyAr: 'نتيجة الهيموجلوبين الأخيرة منخفضة · Your latest hemoglobin result was low',
      link: 'https://www.amazon.eg/s?k=iron+supplement',
    });
  }

  return supplements;
}

// Weather endpoint — requires OPENWEATHER_KEY in .env
app.get(`${BASE}/api/weather`, auth, async (req, res) => {
  const flat = parseFloat(req.query.lat), flon = parseFloat(req.query.lon);
  const facc = req.query.accuracy != null ? parseFloat(req.query.accuracy) : null;
  if (isNaN(flat) || isNaN(flon) || flat < -90 || flat > 90 || flon < -180 || flon > 180)
    return res.status(400).json({ error: 'Invalid coordinates' });

  const KEY = process.env.OPENWEATHER_KEY || '';
  if (!KEY) return res.status(503).json({ error: 'Weather API not configured', setupRequired: true });

  // Only the raw weather reading is cached by location - recommendations are
  // built fresh per request from live per-user context (geofence zones, latest
  // watch entry), since a shared-by-location cache would otherwise leak one
  // user's personalized supplement/indoor-outdoor data to another user who
  // happens to query the same spot within the cache window.
  const cacheKey = `${(flat*100|0)/100}_${(flon*100|0)/100}`;
  const hit = weatherCache.get(cacheKey);
  let weather;
  if (hit && Date.now() - hit.ts < 10 * 60 * 1000) {
    weather = hit.data;
  } else {
    try {
      const r = await fetch(`https://api.openweathermap.org/data/2.5/weather?lat=${flat}&lon=${flon}&appid=${KEY}&units=metric`);
      if (!r.ok) throw new Error('OWM ' + r.status);
      const w = await r.json();
      weather = {
        temp: w.main.temp, feelsLike: w.main.feels_like, humidity: w.main.humidity,
        description: w.weather?.[0]?.description || '',
        icon: w.weather?.[0]?.icon || '',
        city: w.name,
      };
      weatherCache.set(cacheKey, { data: weather, ts: Date.now() });
    } catch(e) {
      console.error('Weather error:', e.message);
      return res.status(502).json({ error: 'Weather service unavailable' });
    }
  }

  const indoorOutdoor = inferIndoorOutdoor(req.user.id, flat, flon, facc);
  const watchEntry = getLatestWatchEntry(req.user.id);
  const labFlags = getLatestLabFlags(req.user.id);

  res.json({
    ...weather,
    recommendations: buildEcoRecommendations(weather.temp, weather.humidity, indoorOutdoor, watchEntry, labFlags),
    updatedAt: new Date().toISOString(),
  });
});

// Geofence zone management
app.get(`${BASE}/api/geofence`, auth, (req, res) => {
  const zones = load('geofence_zones.json') || {};
  res.json(zones[req.user.id] || []);
});

app.post(`${BASE}/api/geofence`, auth, (req, res) => {
  const { name, lat, lon, radius, type } = req.body;
  if (!name || lat == null || lon == null) return res.status(400).json({ error: 'name, lat, lon required' });
  const validTypes = ['home','gym','work','outdoor','other'];
  const zones = load('geofence_zones.json') || {};
  if (!zones[req.user.id]) zones[req.user.id] = [];
  if (zones[req.user.id].length >= 10) return res.status(400).json({ error: 'Max 10 zones' });
  const sname = sanitize(String(name));
  if (!sname) return res.status(400).json({ error: 'Invalid zone name' });
  zones[req.user.id].push({
    id: 'z' + Date.now() + randToken(2),
    name: sname,
    lat: parseFloat(lat), lon: parseFloat(lon),
    radius: Math.min(Math.max(parseInt(radius) || 200, 50), 5000),
    type: validTypes.includes(type) ? type : 'other',
    createdAt: new Date().toISOString()
  });
  save('geofence_zones.json', zones);
  res.json({ ok: true });
});

app.delete(`${BASE}/api/geofence/:id`, auth, (req, res) => {
  const zones = load('geofence_zones.json') || {};
  zones[req.user.id] = (zones[req.user.id] || []).filter(z => z.id !== req.params.id);
  save('geofence_zones.json', zones);
  res.json({ ok: true });
});

// Location check — returns active geofence zone + zone-based activity note
app.post(`${BASE}/api/location/check`, auth, (req, res) => {
  const flat = parseFloat(req.body.lat), flon = parseFloat(req.body.lon);
  if (isNaN(flat) || isNaN(flon)) return res.status(400).json({ error: 'Invalid coordinates' });
  const zones = load('geofence_zones.json') || {};
  const userZones = zones[req.user.id] || [];
  const activeZone = userZones.find(z => haversineMeters(flat, flon, z.lat, z.lon) <= z.radius) || null;
  const notes = {
    gym:     'أنت في الجيم — زد البروتين بعد التمرين · Gym detected — boost post-workout protein',
    outdoor: 'أنت في الهواء الطلق — اشرب ماءً أكثر · Outdoors — increase water intake',
    work:    'وقت العمل — تجنب السناك العشوائي · Work mode — avoid unplanned snacking',
    home:    'في المنزل — وقت مثالي لتحضير وجبتك · Home — great time to prep your meal',
    other:   null
  };
  res.json({ activeZone, activityNote: activeZone ? (notes[activeZone.type] || null) : null });
});

app.use(`${BASE}/*path`,(req,res)=>res.status(404).json({error:'Not found'}));

initData();
app.listen(3200,()=>console.log('DietHub v3 SECURE on port 3200'));
