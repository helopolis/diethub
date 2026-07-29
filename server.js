const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const store = require('./db');
const app = express();

// X-Forwarded-For is only honored when the connection comes from a trusted
// proxy — by default the local reverse proxy (nginx on the same host).
// Override with TRUST_PROXY: "false" if the app is exposed directly,
// a hop count like "1", or an address list like "loopback, 10.0.0.0/8".
const TP = process.env.TRUST_PROXY ?? 'loopback';
app.set('trust proxy', TP === 'true' ? true : TP === 'false' ? false : /^\d+$/.test(TP) ? parseInt(TP) : TP);

app.use(express.json({ limit: '10kb' }));
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
  if (u.role === 'admin' || u.paid) return { active:true, daysLeft:999, expired:false };
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
    'labs.json': {
      lastUpdated:'2026-04-20',
      tests:[
        {id:'lipid',name:'Lipid Profile',nameAr:'دهون الدم الكاملة',urgent:true,frequency:'monthly',frequencyAr:'شهرياً',mokhtabar:150,alpha:200,labmed:180,why:'Essential for Atkins — monitors cholesterol changes',whyAr:'أساسي في Atkins — يراقب تغيرات الكوليسترول',diets:['atkins','keto']},
        {id:'kidney',name:'Kidney Function',nameAr:'وظائف الكلى',urgent:true,frequency:'quarterly',frequencyAr:'كل 3 أشهر',mokhtabar:200,alpha:252,labmed:230,why:'High protein diets stress kidneys — must monitor',whyAr:'الأنظمة عالية البروتين تضغط على الكلى',diets:['atkins','keto','all']},
        {id:'sugar',name:'Blood Sugar + HbA1c',nameAr:'سكر الدم + HbA1c',urgent:true,frequency:'quarterly',frequencyAr:'كل 3 أشهر',mokhtabar:80,alpha:110,labmed:90,why:'Foundation for all diets — determines insulin resistance',whyAr:'أساس كل الأنظمة — يحدد مستوى مقاومة الإنسولين',diets:['all']},
        {id:'cbc',name:'CBC Complete Blood Count',nameAr:'صورة الدم الكاملة',urgent:false,frequency:'quarterly',frequencyAr:'كل 3 أشهر',mokhtabar:60,alpha:165,labmed:100,why:'Detects anemia common when cutting carbs',whyAr:'يكشف الأنيميا الشائعة عند تقليل الكربوهيدرات',diets:['all']},
        {id:'liver',name:'Liver Function',nameAr:'وظائف الكبد',urgent:false,frequency:'quarterly',frequencyAr:'كل 3 أشهر',mokhtabar:150,alpha:300,labmed:250,why:'Liver works hard during ketosis',whyAr:'الكبد يعمل بشكل مكثف أثناء الكيتوسيس',diets:['keto','atkins']},
        {id:'thyroid',name:'Thyroid TSH+T3+T4',nameAr:'هرمونات الغدة الدرقية',urgent:false,frequency:'quarterly',frequencyAr:'كل 3 أشهر',mokhtabar:150,alpha:175,labmed:160,why:'Thyroid issues prevent weight loss despite perfect diet',whyAr:'مشاكل الغدة تمنع فقدان الوزن حتى مع أفضل نظام',diets:['all']},
        {id:'vitamins',name:'Vit D + B12 + Magnesium',nameAr:'فيتامين د + ب12 + مغنيسيوم',urgent:false,frequency:'yearly',frequencyAr:'سنوياً',mokhtabar:350,alpha:450,labmed:400,why:'Very common deficiencies in Egypt despite sunshine',whyAr:'نقص شائع جداً في مصر رغم الشمس',diets:['all']},
        {id:'urine',name:'Complete Urine Analysis',nameAr:'تحليل بول كامل',urgent:true,frequency:'monthly',frequencyAr:'شهرياً',mokhtabar:20,alpha:50,labmed:35,why:'Detects ketones — confirms successful ketosis',whyAr:'يكشف الكيتونات — يؤكد نجاح الكيتوسيس في Atkins',diets:['atkins','keto']}
      ]
    }
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
    }
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
  const newUser = {
    id: 'u'+Date.now()+randToken(4),
    username, password: hashPwd(password),
    email: cleanEmail, phone: sanitize(phone||'')||'',
    role:'user', plan:'trial',
    created: new Date().toISOString().split('T')[0],
    active:true, emailVerified: false,
    trialStart: new Date().toISOString().split('T')[0],
    paid:false, lang:'ar', loginAttempts:0, lastLogin:null,
    profile:{ diet:diet||'atkins', weight:w, height:h, age:parseInt(age)||null, gender:gender||'male', budget:parseInt(budget)||200, bodyFat:parseFloat(bodyFat)||null, muscleMass:parseFloat(muscleMass)||null, bmi: w&&h ? parseFloat((w/Math.pow(h/100,2)).toFixed(1)) : null }
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
app.get(`${BASE}/api/me`, auth, (req,res) => { const {password,...safe}=req.userObj; res.json({...safe, trial:req.trial}); });
app.post(`${BASE}/api/profile`, auth, (req,res) => {
  const users = load('users.json')||[];
  const idx = users.findIndex(u=>u.id===req.user.id);
  if (idx<0) return res.status(404).json({});
  const ok = ['diet','budget','weight','height','age','gender','bodyFat','muscleMass','level'];
  const safe = {};
  for (const k of ok) if (req.body[k]!==undefined) safe[k]=req.body[k];
  users[idx].profile = {...users[idx].profile, ...safe};
  if (req.body.lang && ['ar','en'].includes(req.body.lang)) users[idx].lang=req.body.lang;
  save('users.json', users);
  res.json({ok:true});
});

// MEAL PLAN API
app.get(`${BASE}/api/meal-plan`, auth, (req,res) => {
  const diet = sanitize(req.query.diet)||req.userObj?.profile?.diet||'atkins';
  const budget = Math.min(Math.max(parseInt(req.query.budget||req.userObj?.profile?.budget||200),50),1000);
  track('meal_plan_viewed', { userId: req.user.id, props: { diet } }); // activation signal

  const plans = load('meal_plans.json');
  const plan = plans?.[diet]||plans?.atkins;
  if (!plan) return res.json({error:'Plan not found'});
  const pd = load('food_prices.json');
  const kw = {'فراخ':'chicken','دجاج':'chicken','صدر فراخ':'chicken','بيض':'eggs','سمك':'fish','بلطي':'fish','لحم':'beef','كندوز':'beef','مفروم':'beef','جبن':'cheese','قريش':'cheese','خضار':'veggies','كوسة':'veggies','أفوكادو':'avocado','زيتون':'olive_oil','مكسرات':'nuts','خيار':'cucumber','طماطم':'tomato'};
  function findItem(name, nameEn) {
    const items = pd?.items||[];
    let item = items.find(i=>i.name===name||i.nameEn===nameEn);
    if (!item) {
      const nl = (name||'').toLowerCase();
      for (const [k,v] of Object.entries(kw)) {
        if (nl.includes(k)) { item=items.find(i=>i.id===v); if(item)break; }
      }
    }
    return item;
  }
  const week = plan.week.map(day=>({...day, meals: day.meals.map(meal=>{
    let total=0;
    const ings = meal.ingredients.map(ing=>{
      const item=findItem(ing.item, ing.itemEn);
      let price=0, store='';
      if(item){
        const ps=[{s:'carrefour',p:item.carrefour},{s:'metro',p:item.metro},{s:'royal',p:item.royal},{s:'talabat',p:item.talabat}].filter(x=>x.p).sort((a,b)=>a.p-b.p);
        if(ps.length){price=Math.round((ps[0].p/1000)*ing.grams);store=ps[0].s;}
        total+=price;
      }
      return {...ing,price,bestStore:store};
    });
    const adj=Math.round(total)||meal.price;
    return {...meal,price:adj,withinBudget:adj<=(budget/4),ingredients:ings};
  })}));
  const dailyCost=week[0]?.meals.reduce((s,m)=>s+m.price,0)||0;
  res.json({...plan,week,dailyCost,budget,withinBudget:dailyCost<=budget});
});

app.get(`${BASE}/api/food-prices`, auth, (req,res)=>res.json(load('food_prices.json')));
app.get(`${BASE}/api/labs`, auth, (req,res)=>res.json(load('labs.json')));

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
  const url = `https://checkout.kashier.io/?merchantId=${encodeURIComponent(KASHIER.mid)}`
    + `&orderId=${encodeURIComponent(orderId)}&amount=${amount}&currency=EGP`
    + `&hash=${hash}&mode=${KASHIER.mode}`
    + `&merchantRedirect=${encodeURIComponent(redirect)}`
    + `&allowedMethods=card,wallet&display=ar&brandColor=%232D6A4F`;
  res.json({ ok:true, kashierUrl:url, orderId, amount, plan });
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
  const rows=[['ID','Username','Email','Phone','Plan','Role','Status','EmailVerified','Paid','Diet','Budget','Weight','Height','Age','BMI','BodyFat%','MuscleMass','Created','SubEnd']];
  users.forEach(u=>{const sub=subs.find(s=>s.userId===u.id&&s.status==='active');rows.push([u.id,u.username,u.email||'',u.phone||'',u.plan,u.role,u.active?'Active':'Inactive',u.emailVerified?'Yes':'No',u.paid?'Yes':'Trial',u.profile?.diet||'',u.profile?.budget||'',u.profile?.weight||'',u.profile?.height||'',u.profile?.age||'',u.profile?.bmi||'',u.profile?.bodyFat||'',u.profile?.muscleMass||'',u.created,sub?.endDate||'']);});
  const csv=rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type','text/csv;charset=utf-8');
  res.setHeader('Content-Disposition',`attachment;filename="diethub_${new Date().toISOString().split('T')[0]}.csv"`);
  res.send('\uFEFF'+csv);
});
app.get(`${BASE}/health`,(req,res)=>res.json({status:'ok',version:'3.0-secure'}));
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
  if (!['vip','elite'].includes(u.plan) && u.role !== 'admin') {
    return res.status(403).json({ error: 'هذه الميزة متاحة لأعضاء VIP و Elite فقط' });
  }
  const { messages, generateQuestions } = req.body;
  const profile = u.profile || {};
  const dietMap = { atkins:'أتكينز', mediterranean:'متوسطي', keto:'كيتو', lowcarb:'قليل الكربوهيدرات', highprotein:'عالي البروتين', balanced:'متوازن' };
  const dietName = dietMap[profile.diet] || profile.diet || 'متوازن';

  const systemPrompt = `أنت مساعد متابعة غذائي ذكي داخل تطبيق DietHub. اسمك "دايت بوت".
تتحدث بالعربية دائماً بأسلوب ودود ومشجع وموجز.
معلومات المستخدم:
- الاسم: ${u.username}
- نظام غذائي: ${dietName}
- الميزانية اليومية: ${profile.budget || 200} جنيه
- الوزن: ${profile.weight || 'غير محدد'} كجم
- الطول: ${profile.height || 'غير محدد'} سم
- العمر: ${profile.age || 'غير محدد'}
- الجنس: ${profile.gender === 'female' ? 'أنثى' : 'ذكر'}
${generateQuestions ? `مهمتك: اطرح 3 أسئلة متابعة ذكية ومخصصة لهذا المستخدم بناءً على نظامه الغذائي ${dietName} ووقت اليوم الحالي. اجعل الأسئلة عملية وتتعلق بالتزامه بالنظام الغذائي وصحته. أرسل الأسئلة فقط كقائمة مرقمة بدون مقدمة.` : `أجب على رسائل المستخدم بإيجاز ودعمه في رحلته الغذائية. إذا سألك عن شيء خارج نطاق الغذاء والصحة، أعده بلطف لموضوع نظامه الغذائي.`}`;

  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 500,
        system: systemPrompt,
        messages: (messages && messages.length) ? messages : [{ role: 'user', content: 'ابدأ' }]
      })
    });
    if (!anthropicRes.ok) throw new Error('Anthropic error: ' + anthropicRes.status);
    const data = await anthropicRes.json();
    res.json({ reply: data.content?.[0]?.text || 'عذراً، لم أفهم. حاول مجدداً.' });
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

// ─── LAB RESULTS TRACKER ──────────────────────────────────────────────────────
app.get(`${BASE}/api/lab-results`, auth, (req,res) => {
  if (!['vip','elite'].includes(req.userObj.plan) && req.userObj.role !== 'admin')
    return res.status(403).json({error:'VIP/Elite only'});
  const results = load('lab_results.json') || {};
  res.json(results[req.user.id] || []);
});

app.post(`${BASE}/api/lab-results`, auth, async (req,res) => {
  if (!['vip','elite'].includes(req.userObj.plan) && req.userObj.role !== 'admin')
    return res.status(403).json({error:'VIP/Elite only'});
  const { date, results } = req.body;
  if (!date || !results) return res.status(400).json({error:'Date and results required'});
  const uid = req.user.id;
  const entry = { date, results, savedAt: new Date().toISOString() };
  // Atomic upsert — safe even if another request touches this user's log.
  update('lab_results.json', all => {
    if (!all[uid]) all[uid] = [];
    const i = all[uid].findIndex(l => l.date === date);
    if (i >= 0) all[uid][i] = entry; else all[uid].push(entry);
    all[uid] = all[uid].sort((a,b)=>b.date.localeCompare(a.date)).slice(0,24);
    return all;
  }, {});

  // AI analysis
  try {
    const u = req.userObj;
    const diet = u.profile?.diet || 'balanced';
    const prompt = `You are a medical nutrition AI assistant. Analyze these lab results for a patient on a ${diet} diet:\n${JSON.stringify(results)}\n\nProvide a brief analysis in Arabic and English covering:\n1. Which values are normal/abnormal\n2. What dietary changes could help\n3. Overall health trend\n\nReturn JSON: {"analysis_ar":"...","analysis_en":"...","status":"good|warning|critical","recommendations_ar":["..."],"recommendations_en":["..."]}`;
    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST',
      headers:{'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
      body: JSON.stringify({model:'claude-haiku-4-5-20251001',max_tokens:800,messages:[{role:'user',content:prompt}]})
    });
    const aiData = await aiRes.json();
    const analysis = JSON.parse(aiData.content?.[0]?.text || '{}');
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


// ─── ADMIN IMPERSONATION ──────────────────────────────────────────────────────


// ─── WATCH SYNC ENGINE ────────────────────────────────────────────────────────
// Unified schema: { userId, date, source, steps, heartRate, caloriesBurned, sleep, spO2, stress, water }

app.post(`${BASE}/api/watch/sync`, auth, (req, res) => {
  const { source, date, steps, heartRate, caloriesBurned, sleep, spO2, stress, water } = req.body;
  if (!source || !date) return res.status(400).json({ error: 'source and date required' });

  const allowed = ['apple_watch','wear_os','galaxy_watch','garmin','manual'];
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

function buildWeatherRecs(temp, humidity) {
  let hydrationL, alert = null, foods = [], drinks = [];

  if      (temp >= 40) { hydrationL = 4.5; alert = 'خطر جفاف شديد — اشرب ماء الآن! · Severe dehydration risk — drink NOW!'; }
  else if (temp >= 35) { hydrationL = 3.5; alert = 'طقس حار جداً — اشرب كل 20 دقيقة · Very hot — drink every 20 min'; }
  else if (temp >= 28) hydrationL = 2.8;
  else if (temp >= 20) hydrationL = 2.2;
  else                 hydrationL = 1.8;

  if (humidity > 80) { hydrationL += 0.5; drinks.push('مشروبات إلكتروليت · Electrolyte drinks'); }
  if (humidity < 30) { hydrationL += 0.3; drinks.push('ماء مع ليمون · Water with lemon'); }

  if (temp >= 35) {
    foods  = ['سلطة دجاج خفيفة · Light chicken salad', 'خيار وطماطم مبردة · Cold cucumber & tomato', 'جبن قريش · Fresh cheese'];
    drinks.push('ماء بارد · Cold water', 'عصير بطيخ · Watermelon juice');
  } else if (temp >= 25) {
    foods  = ['صدر فراخ مشوي · Grilled chicken', 'سمك خفيف · Light fish', 'سلطة خضروات · Vegetable salad'];
    drinks.push('ماء · Water', 'ماء جوز هند · Coconut water');
  } else if (temp >= 15) {
    foods  = ['بروتين متوسط · Moderate protein', 'خضار مطبوخة · Cooked vegetables'];
    drinks.push('ماء دافئ · Warm water', 'شاي أخضر · Green tea');
  } else {
    foods  = ['شوربة دجاج · Chicken soup', 'لحم دافئ · Warm beef', 'خضار مشوية · Roasted vegetables'];
    drinks.push('شوربة · Soup', 'شاي أعشاب · Herbal tea');
  }

  return { hydrationL: parseFloat(hydrationL.toFixed(1)), alert, foods, drinks };
}

// Weather endpoint — requires OPENWEATHER_KEY in .env
app.get(`${BASE}/api/weather`, auth, async (req, res) => {
  const flat = parseFloat(req.query.lat), flon = parseFloat(req.query.lon);
  if (isNaN(flat) || isNaN(flon) || flat < -90 || flat > 90 || flon < -180 || flon > 180)
    return res.status(400).json({ error: 'Invalid coordinates' });

  const KEY = process.env.OPENWEATHER_KEY || '';
  if (!KEY) return res.status(503).json({ error: 'Weather API not configured', setupRequired: true });

  const cacheKey = `${(flat*100|0)/100}_${(flon*100|0)/100}`;
  const hit = weatherCache.get(cacheKey);
  if (hit && Date.now() - hit.ts < 10 * 60 * 1000) return res.json(hit.data);

  try {
    const r = await fetch(`https://api.openweathermap.org/data/2.5/weather?lat=${flat}&lon=${flon}&appid=${KEY}&units=metric`);
    if (!r.ok) throw new Error('OWM ' + r.status);
    const w = await r.json();
    const temp = w.main.temp, humidity = w.main.humidity;
    const data = {
      temp, feelsLike: w.main.feels_like, humidity,
      description: w.weather?.[0]?.description || '',
      icon: w.weather?.[0]?.icon || '',
      city: w.name,
      recommendations: buildWeatherRecs(temp, humidity),
      updatedAt: new Date().toISOString()
    };
    weatherCache.set(cacheKey, { data, ts: Date.now() });
    res.json(data);
  } catch(e) {
    console.error('Weather error:', e.message);
    res.status(502).json({ error: 'Weather service unavailable' });
  }
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
