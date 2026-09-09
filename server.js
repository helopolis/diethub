const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const multer = require('multer');
const sharp = require('sharp');
const { OAuth2Client, GoogleAuth } = require('google-auth-library');
const { Webhook } = require('svix');
// Official Apple/Google server libraries for native mobile IAP subscriptions
// (see IAP plan, memory project_healthpace_market_validation.md) — the web
// checkout below stays on Kashier; App Store/Play policy require native
// billing for a fitness-coaching app's mobile subscriptions. Using Apple's
// own library (not hand-rolled JWS/x5c chain verification) because getting
// that crypto wrong is exactly the kind of thing "nontrivial to hand-roll
// safely" undersells — this is the same trust boundary as payment webhooks.
const { AppStoreServerAPIClient, SignedDataVerifier, Environment: AppleEnv, Status: AppleSubStatus } = require('@apple/app-store-server-library');
const { androidpublisher } = require('@googleapis/androidpublisher');
const store = require('./db');
const { buildHealthProfile, coachSummary } = require('./health');
const aiLanguage = require('./ai_language');
const { runReminderCheck } = require('./reminders');
const { buildDailyBrief, buildWeeklySummary } = require('./daily_brief');
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
// One route needs a much larger body: n8n's daily-recipe image upload sends
// a base64-encoded AI-generated image (routinely 2-4MB as base64, well over
// the 1mb every other route needs). Scoped by exact path rather than
// raising the global limit, so the rest of the app keeps the tighter
// default — a bigger blanket limit would just be more request-body surface
// every other route never needs.
app.use((req, res, next) => {
  const limit = req.path === '/diet/api/admin/daily-recipe/image' ? '20mb' : '1mb';
  express.json({ limit, verify: (req, res, buf) => { req.rawBody = buf; } })(req, res, next);
});
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DATA_DIR = process.env.DATA_DIR || '/data/diethub';
// Profile photos (2026-09-03) — real files on disk, not SQLite documents:
// binary image data doesn't belong in a JSON-blob document store (see the
// database architecture audit this session), and this mirrors how certs/
// already live as real files rather than going through db.js. Served
// publicly (see the express.static mount below) with a random filename per
// upload — anyone with the exact link can view it (same as Slack/WhatsApp/
// Gravatar avatars), but nobody can guess or enumerate one.
const AVATAR_DIR = path.join(DATA_DIR, 'uploads', 'avatars');
fs.mkdirSync(AVATAR_DIR, { recursive: true });
// Long cache lifetime is safe here specifically because every upload gets a
// brand-new random filename (see POST /api/profile/avatar below) — there is
// no "stale cached old photo" case to worry about, a changed photo is
// always a different URL.
app.use('/uploads/avatars', express.static(AVATAR_DIR, { maxAge: '30d', immutable: true }));
// Same random-filename-per-upload reasoning as AVATAR_DIR above — the daily
// recipe image (n8n-generated, see POST /api/admin/daily-recipe/image)
// needs a real hostable URL too, for the same "binary doesn't belong in a
// JSON-blob document" reason.
const RECIPE_IMAGE_DIR = path.join(DATA_DIR, 'uploads', 'recipes');
fs.mkdirSync(RECIPE_IMAGE_DIR, { recursive: true });
app.use('/uploads/recipes', express.static(RECIPE_IMAGE_DIR, { maxAge: '30d', immutable: true }));
const JWT_SECRET = process.env.JWT_SECRET || 'diethub_secret_2026_CHANGE_IN_PROD';
const BASE = '/diet';
const TRIAL_DAYS = 14;
// The 9 structured allergen categories — matches RegisterScreen.js's
// ALLERGEN_OPTIONS exactly. Real per-food tags exist in FOOD_DB for these.
// Anything outside this set is a free-text "Other" allergy instead (see
// customAllergyText / allergyKeywordsMatch()), matched by keyword against
// food names rather than a structured tag.
// 'sesame' added during the ingredient-database audit — it's the FDA's 9th
// recognized major food allergen (FASTER Act 2021, enforced Jan 2023) and
// this database genuinely contains sesame-based foods (tahini, za'atar,
// and hummus's own core recipe) with no way to flag them before this.
const KNOWN_ALLERGENS = ['milk','eggs','fish','crustaceans','nuts','peanuts','gluten','soybeans','sesame'];
// Self-reported conditions used to gate real safety logic (deficit goals,
// diet contraindication warnings) — not a diagnosis, not a full medical
// history. Deliberately small and scoped to what this app actually acts on
// today; adding a condition here means also adding real gating logic for
// it, not just collecting the label.
const KNOWN_MEDICAL_CONDITIONS = ['type1_diabetes', 'type2_diabetes', 'pregnant', 'breastfeeding', 'ckd'];
const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_PASS = process.env.GMAIL_APP_PASS || '';
const GMAIL_AUTH = process.env.GMAIL_AUTH || GMAIL_USER;
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
// Restructured 2026-09-02 from 5 tiers (basic/standard/premium/vip/elite) to 3,
// now differentiated purely by connected-device access rather than feature
// bundling. Manual entry (typed-in numbers) is never gated at all — it's not
// a device integration. Real devices split into three tiers:
//   tier1: no device integration of any kind.
//   tier2: phone-health-app middleware only (Apple Health / Health Connect —
//     the wearable syncs to the user's own phone health app, Health Pace
//     reads from there). No direct vendor connection.
//   tier3: adds direct-to-vendor-cloud OAuth (Garmin/Fitbit/Oura/Whoop/
//     Polar/Strava/Suunto/Ultrahuman via Open Wearables) AND the Bluetooth
//     medical devices (BP/glucose/scale) built in connectedHealth/.
// See /api/watch/sync's own gate comment for the exact per-source split.
// Chatbot and lab-results used to be VIP/Elite-only; all 3 tiers now get
// them (see hasActiveCoverage() gate below). Existing paying users on any
// of the 5 old tiers were grandfathered onto tier3 (see
// migrate_to_3_tiers.js) since none of the old tiers gated device access —
// that's the mapping that doesn't reduce anyone's existing access.
const PLAN_PRICES = { tier1: 100, tier2: 150, tier3: 500 };
// Display names (Essential/Active/Complete) live client-side only — mobile's
// SubscribeScreen.js/MySubscriptionScreen.js and public/payment.html each
// have their own copy, since the backend never renders a plan name into any
// text (email, receipt, etc.) today.
// Bluetooth medical-device provider ids (see connectedHealth/index.js) —
// a /api/watch/sync call whose `source` is one of these needs tier3
// specifically, not just any device-capable tier (tier2 gets wearables only).
const MEDICAL_DEVICE_SOURCES = ['medical_device:blood_pressure_monitor', 'medical_device:blood_glucose_meter', 'medical_device:smart_scale'];
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

// ─── NATIVE IAP (Apple/Google mobile subscriptions) ────────────────────────
// Same 5 tiers as PLAN_PRICES above, mapped to the product ID scheme
// iap.js (mobile) already uses — com.talabatito.diethub.sub.<tier>, one
// product ID shared across both platforms (App Store Connect and Play
// Console each register it under their own console, but the string is the
// same, so this map doesn't need separate iOS/Android lists).
const IAP_PRODUCT_ID_PREFIX = 'com.talabatito.diethub.sub.';
function tierFromIapProductId(productId) {
  const tier = String(productId || '').replace(IAP_PRODUCT_ID_PREFIX, '');
  return PLAN_PRICES[tier] ? tier : null;
}

const APPLE_IAP = {
  keyId:     process.env.APPLE_IAP_KEY_ID || '',
  issuerId:  process.env.APPLE_IAP_ISSUER_ID || '',
  // Raw .p8 contents (PEM, including -----BEGIN/END PRIVATE KEY----- lines),
  // base64-encoded as a single-line env var — same "blob in container env"
  // pattern as FIREBASE_SERVICE_ACCOUNT (see push.js).
  privateKeyB64: process.env.APPLE_IAP_PRIVATE_KEY || '',
  bundleId:  process.env.APPLE_IAP_BUNDLE_ID || 'com.talabatito.diethub',
  environment: process.env.APPLE_IAP_ENV === 'production' ? AppleEnv.PRODUCTION : AppleEnv.SANDBOX,
};
function appleIapConfigured() { return !!(APPLE_IAP.keyId && APPLE_IAP.issuerId && APPLE_IAP.privateKeyB64); }

let _appleClient = null, _appleVerifier = null;
function getAppleClient() {
  if (!appleIapConfigured()) return null;
  if (!_appleClient) {
    const signingKey = Buffer.from(APPLE_IAP.privateKeyB64, 'base64').toString('utf8');
    _appleClient = new AppStoreServerAPIClient(signingKey, APPLE_IAP.keyId, APPLE_IAP.issuerId, APPLE_IAP.bundleId, APPLE_IAP.environment);
  }
  return _appleClient;
}
function getAppleVerifier() {
  if (!appleIapConfigured()) return null;
  if (!_appleVerifier) {
    const rootCA = fs.readFileSync(path.join(__dirname, 'certs', 'AppleRootCA-G3.cer'));
    // enableOnlineChecks (revocation/OCSP) needs outbound network access from
    // this container — fine here, same posture as any other outbound API call.
    _appleVerifier = new SignedDataVerifier([rootCA], true, APPLE_IAP.environment, APPLE_IAP.bundleId);
  }
  return _appleVerifier;
}

const GOOGLE_PLAY_IAP = {
  // Full service-account JSON, single-line env var — same pattern as
  // FIREBASE_SERVICE_ACCOUNT / APPLE_IAP_PRIVATE_KEY above.
  serviceAccountJson: process.env.GOOGLE_PLAY_SERVICE_ACCOUNT || '',
  packageName: process.env.GOOGLE_PLAY_PACKAGE_NAME || 'com.talabatito.diethub',
};
function googlePlayConfigured() { return !!GOOGLE_PLAY_IAP.serviceAccountJson; }

let _androidPublisherAuthClient = null;
async function getAndroidPublisherClient() {
  if (!googlePlayConfigured()) return null;
  if (!_androidPublisherAuthClient) {
    const credentials = JSON.parse(GOOGLE_PLAY_IAP.serviceAccountJson);
    const auth = new GoogleAuth({ credentials, scopes: ['https://www.googleapis.com/auth/androidpublisher'] });
    _androidPublisherAuthClient = await auth.getClient();
  }
  return androidpublisher({ version: 'v3', auth: _androidPublisherAuthClient });
}

// Cross-source truth: a user can be covered by Kashier (web), Apple, or
// Google — paid status is the OR of all of them, not a single flat flag one
// path sets and forgets, since a lapsed Apple sub shouldn't revoke access a
// user separately has via Kashier, and vice versa.
function hasActiveCoverage(userId) {
  const subs = load('subscriptions.json') || [];
  const now = Date.now();
  return subs.some(s => s.userId === userId
    && ['active', 'grace_period', 'on_hold'].includes(s.status)
    && (!s.endDate || new Date(s.endDate).getTime() > now));
}
// Device-tier gating (2026-09-02) — deliberately does NOT check BETA_MODE,
// unlike the chatbot/lab-results gate below: this is new monetization tied
// to real hardware integration work (wearables/BP/glucose/scale), not
// something to give away free during the beta launch window. tier1 has no
// device access at all, tier2 adds wearables, tier3 adds the Bluetooth
// medical devices — see MEDICAL_DEVICE_SOURCES above.
const DEVICE_TIER_RANK = { tier1: 1, tier2: 2, tier3: 3 };
function hasDeviceTier(u, minTier) {
  if (u.role === 'admin') return true;
  if (!hasActiveCoverage(u.id)) return false;
  return (DEVICE_TIER_RANK[u.plan] || 0) >= DEVICE_TIER_RANK[minTier];
}
// Recomputes user.paid from hasActiveCoverage and sets user.plan to whichever
// currently-covering row expires furthest out — deliberately does NOT clear
// plan/paid when coverage lapses with nothing else active (matches Kashier's
// existing behavior today, which never auto-downgrades on its own fixed
// 30-day expiry either — this is an existing product behavior, not something
// introduced here).
function refreshUserPaidStatus(userId) {
  update('users.json', users => {
    const u = users.find(x => x.id === userId);
    if (!u) return users;
    const covered = hasActiveCoverage(userId);
    if (covered) {
      const subs = load('subscriptions.json') || [];
      const active = subs.filter(s => s.userId === userId && ['active', 'grace_period', 'on_hold'].includes(s.status));
      const furthest = active.sort((a, b) => new Date(b.endDate || 0) - new Date(a.endDate || 0))[0];
      u.paid = true;
      if (furthest) u.plan = furthest.plan;
    }
    return users;
  }, []);
}

// Single choke point both /iap/verify and the two /notify webhooks funnel
// into for writing subscription state — mirrors how the Kashier webhook is
// today's single choke point for its own flow. Idempotent per externalRef
// (Apple originalTransactionId / Google purchaseToken), but — unlike
// Kashier's one-time-order idempotency — still applies updates for a
// genuinely new renewal event on an already-paid user, since a subscription
// renews repeatedly rather than existing as a single order.
function reconcileIapSubscription({ platform, userId, productId, plan, expiresDate, status, externalRef, environment, autoRenewing }) {
  if (!userId || !plan || !externalRef) return;
  update('subscriptions.json', subs => {
    const row = subs.find(s => s.externalRef === externalRef && s.source === platform);
    const endDate = expiresDate ? new Date(expiresDate).toISOString().split('T')[0] : null;
    if (row) {
      row.status = status; row.endDate = endDate || row.endDate; row.plan = plan;
      // Only overwrite a previously-known value with a fresh null when the
      // caller genuinely has no signal this time (e.g. a renewal-info decode
      // failure) — never let a transient miss erase a real prior reading.
      if (autoRenewing != null) row.autoRenewing = autoRenewing;
    } else {
      subs.push({
        userId, plan, source: platform, externalRef, environment,
        startDate: new Date().toISOString().split('T')[0], endDate,
        amount: PLAN_PRICES[plan] || 0, status,
        paymentRef: externalRef,
        autoRenewing: autoRenewing ?? null,
      });
    }
    return subs;
  }, []);
  refreshUserPaidStatus(userId);
}

// ─── SECURITY CONFIG ──────────────────────────────────────────────────────────
const SEC = {
  PWD_MIN: 8, PWD_MAX: 128,
  // Live password-policy regex; the flagged \[ \] \/ escapes below are
  // functionally redundant inside this character class but harmless, and
  // this pattern gates every real password in the system. Deliberately
  // left untouched rather than "fixed" for style — touching a
  // security-critical regex to satisfy a cosmetic lint rule is a real risk
  // with zero real benefit. Verified via the real unit tests
  // (tests/unit/security-critical.test.js) that it still accepts/rejects
  // exactly the same passwords either way.
  // eslint-disable-next-line no-useless-escape
  PWD_REGEX: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{};:'",.<>?\/\\|`~]).{8,128}$/,
  USR_MIN: 3, USR_MAX: 30,
  USR_REGEX: /^[a-zA-Z0-9_.-]{3,30}$/,
  USR_RESERVED: ['admin','root','administrator','superuser','system','support','diethub','api','null','undefined'],
  LOGIN_MAX: 5, LOGIN_WIN: 15 * 60 * 1000,
  REG_MAX: 7, REG_WIN: 10 * 60 * 1000,
  API_MAX: 60, API_WIN: 60 * 1000,
  VERIFY_EXP: 24 * 60 * 60 * 1000,
  SESSION_H: 8,
  IMPERSONATION_SESSION_H: 1, // shorter-lived than a real session — reduces exposure window for an already-sensitive capability
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

// Polling cadence for reminders.js — each individual reminder type only
// actually fires within its own real time window and is deduped per day, so
// this interval is just how often we check, not a per-tick send.
setInterval(() => { runReminderCheck(store).catch(e => console.error('[reminders] check failed:', e.message)); }, 5 * 60 * 1000);
runReminderCheck(store).catch(e => console.error('[reminders] initial check failed:', e.message));

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
// Production hardening pass (independent audit, Part 2/6): `impersonatedBy`
// is new and optional — every existing call site is unaffected (it's simply
// undefined for a real login) — but when set, it does two real things: (1)
// it's actually encoded into the token payload, unlike the previous
// `_impersonated: true` flag on the impersonation route below, which was
// silently dropped because mkToken() never read it, making an impersonation
// session byte-for-byte indistinguishable from a real one; (2) auth() below
// uses its presence to apply a shorter session lifetime to impersonation
// tokens specifically, reducing the real exposure window.
function mkToken(u, impersonatedBy) {
  const h = b64url(JSON.stringify({ alg:'HS256' }));
  const sessionMs = impersonatedBy ? SEC.IMPERSONATION_SESSION_H * 3600 * 1000 : SEC.SESSION_H * 3600 * 1000;
  const payload = { id:u.id, usr:u.username, role:u.role, plan:u.plan, exp:Date.now()+sessionMs };
  if (impersonatedBy) payload.imp = impersonatedBy;
  const p = b64url(JSON.stringify(payload));
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
// Secure flag was previously always omitted — harmless in production only
// because nginx's HTTP→HTTPS redirect meant a plain-HTTP request never
// reached this app, but nothing at the app layer actually enforced it.
// req.secure correctly reflects the original scheme here because
// TRUST_PROXY + nginx's `X-Forwarded-Proto` header are both already
// configured (verified live) — false in CI's direct-HTTP E2E run
// (E2E_BASE_URL=http://localhost:3200), true behind the real HTTPS proxy,
// so this can't silently break the existing Playwright login-flow tests.
function setSessionCookie(req, res, token, maxAgeSec) {
  const secure = req.secure ? ';Secure' : '';
  res.setHeader('Set-Cookie', `dh_token=${token};path=/;max-age=${maxAgeSec}${secure};HttpOnly;SameSite=Strict`);
}
function clearSessionCookie(req, res) {
  const secure = req.secure ? ';Secure' : '';
  res.setHeader('Set-Cookie', `dh_token=;path=/;max-age=0${secure};HttpOnly;SameSite=Strict`);
}

// ─── REFRESH TOKENS ───────────────────────────────────────────────────────────
// Access tokens (mkToken) are short-lived (SEC.SESSION_H = 8h) and stateless —
// fine for the website, which just redirects to /login on expiry. A mobile
// app needs to stay signed in far longer without re-prompting for a password,
// so this adds a real, server-tracked refresh token: opaque (a lookup key, not
// a JWT — nothing to decode), revocable, and rotated on every use (the old one
// is deleted the instant a new one is issued), so a leaked refresh token only
// works once before the legitimate client's next refresh invalidates it.
// Purely additive — the existing cookie/access-token flow is untouched.
const REFRESH_TOKEN_DAYS = 30;
function mkRefreshToken(userId) {
  const token = randToken(32);
  const tokens = load('refresh_tokens.json') || {};
  tokens[token] = { userId, createdAt: Date.now(), expiresAt: Date.now() + REFRESH_TOKEN_DAYS * 86400000 };
  save('refresh_tokens.json', tokens);
  return token;
}
function revokeRefreshToken(token) {
  const tokens = load('refresh_tokens.json') || {};
  if (tokens[token]) { delete tokens[token]; save('refresh_tokens.json', tokens); }
}
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
  } catch { /* analytics is best-effort — never surface to the caller */ }
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
      role:'admin', plan:'tier3', created:'2026-04-19', active:true,
      trialStart:'2026-04-19', paid:true, lang:'ar',
      loginAttempts:0, lastLogin:null, avatarUrl:null, profile:{}
    }],
    'subscriptions.json': [],
    'ratings.json': [],
    'pending_verifications.json': [],
    'security_log.json': [],
    'food_prices.json': {
      lastUpdated:'2026-04-20',
      items:[
        {id:'chicken',name:'صدر فراخ طازج',nameEn:'Chicken Breast',unit:'kg',qty:'200g per serving',qtyAr:'200 جم للحصة',metro:175,category:'protein'},
        {id:'eggs',name:'بيض أحمر',nameEn:'Eggs (30 pcs)',unit:'carton',qty:'2-3 eggs per serving',qtyAr:'2-3 بيضات',metro:125,category:'protein'},
        {id:'fish',name:'سمك بلطي',nameEn:'Tilapia Fish',unit:'kg',qty:'150g per serving',qtyAr:'150 جم للحصة',metro:90,category:'protein'},
        {id:'beef',name:'لحمة كندوز',nameEn:'Beef',unit:'kg',qty:'150g per serving',qtyAr:'150 جم للحصة',metro:265,category:'protein'},
        {id:'cheese',name:'جبن قريش',nameEn:'Fresh Cheese',unit:'500g',qty:'3-4 tbsp (60g)',qtyAr:'60 جم',metro:42,category:'dairy'},
        {id:'veggies',name:'خضار مشكلة',nameEn:'Mixed Vegetables',unit:'kg',qty:'200g per serving',qtyAr:'200 جم للحصة',metro:28,category:'vegetables'},
        {id:'avocado',name:'أفوكادو',nameEn:'Avocado',unit:'kg',qty:'half (80g)',qtyAr:'نصف حبة (80 جم)',metro:88,category:'vegetables'},
        {id:'olive_oil',name:'زيت زيتون',nameEn:'Olive Oil',unit:'500ml',qty:'1 tbsp per meal',qtyAr:'ملعقة للوجبة',metro:135,category:'fats'},
        {id:'nuts',name:'مكسرات مشكلة',nameEn:'Mixed Nuts',unit:'250g',qty:'30g handful',qtyAr:'30 جم',metro:98,category:'fats'},
        {id:'cucumber',name:'خيار',nameEn:'Cucumber',unit:'kg',qty:'1 medium (120g)',qtyAr:'حبة متوسطة (120 جم)',metro:10,category:'vegetables'},
        {id:'tomato',name:'طماطم',nameEn:'Tomatoes',unit:'kg',qty:'1 medium (100g)',qtyAr:'حبة متوسطة (100 جم)',metro:12,category:'vegetables'}
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
      nameAr:'آتكينز',nameEn:'Atkins',dailyCalories:1471,dailyCarbs:'25g',dailyProtein:'115g',dailyFat:'93g',
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
      nameAr:'كيتو',nameEn:'Keto',dailyCalories:1653,dailyCarbs:'16g',dailyProtein:'108g',dailyFat:'125g',
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
      nameAr:'متوسطي',nameEn:'Mediterranean',dailyCalories:1451,dailyCarbs:'159g',dailyProtein:'83g',dailyFat:'51g',
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
      nameAr:'مرضى السكري',nameEn:'Diabetic',dailyCalories:1216,dailyCarbs:'88g',dailyProtein:'93g',dailyFat:'48g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مسلوق مع خبز أسمر وخيار','Boiled eggs with brown bread and cucumber',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60),ing('خيار','Cucumber','حبة / 1 piece',120)],320,'18g','32g','12g',16),
          meal('غداء','Lunch','1:00 PM','صدر دجاج مشوي مع أرز بني وخضار','Grilled chicken breast with brown rice and vegetables',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('أرز بني','Brown Rice','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],460,'42g','40g','10g',52),
          meal('عشاء','Dinner','7:00 PM','سمك مشوي مع سلطة خضراء','Grilled fish with green salad',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('سلطة خضراء','Green Salad','150 جم / 150g',150),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],300,'36g','8g','12g',48),
          meal('سناك','Snack','4:00 PM','زبادي بدون سكر مع قرفة','Unsweetened yogurt with cinnamon',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('قرفة','Cinnamon','رشة / pinch',2)],90,'6g','7g','3g',14),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','15 جم / 15g',15)],87,'3g','3g','8g',10)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان بالقرفة بدون سكر','Oats with cinnamon, no added sugar',[ing('شوفان','Oats','40 جم / 40g',40),ing('لبن','Milk','150 مل / 150ml',150),ing('قرفة','Cinnamon','رشة / pinch',2)],260,'11g','38g','6g',15),
          meal('غداء','Lunch','1:00 PM','كفتة مشوية مع خضار سوتيه','Grilled kofta with sautéed vegetables',[ing('لحمة مفرومة','Ground Beef','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200),ing('زيت زيتون','Olive Oil','نصف ملعقة / half tbsp',7)],420,'32g','16g','24g',55),
          meal('عشاء','Dinner','7:00 PM','عدس بخضار بدون خبز','Lentil soup with vegetables, no bread',[ing('عدس','Lentils','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],240,'14g','36g','2g',14),
          meal('سناك','Snack','4:00 PM','حفنة لوز','A handful of almonds',[ing('لوز','Almonds','20 جم / 20g',20)],120,'4g','4g','10g',12),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز إضافي','Extra almonds',[ing('لوز','Almonds','30 جم / 30g',30)],174,'6g','7g','15g',18)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','جبنة قريش مع خبز أسمر وطماطم','Cottage cheese with brown bread and tomato',[ing('جبنة قريش','Cottage Cheese','100 جم / 100g',100),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60),ing('طماطم','Tomatoes','حبة / 1 piece',100)],280,'18g','34g','6g',18),
          meal('غداء','Lunch','1:00 PM','سمك بالفرن مع بطاطا مسلوقة','Baked fish with boiled potato',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('بطاطس مسلوقة','Boiled Potato','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],380,'38g','36g','6g',48),
          meal('عشاء','Dinner','7:00 PM','صدر دجاج بالخضار المشوية','Chicken breast with grilled vegetables',[ing('صدر فراخ طازج','Chicken Breast','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],320,'36g','14g','8g',42),
          meal('سناك','Snack','4:00 PM','تفاحة صغيرة','A small apple',[ing('تفاح','Apple','حبة صغيرة / 1 small',100)],55,'0g','14g','0g',8),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','30 جم / 30g',30)],174,'6g','7g','15g',18)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','بياض بيض بالخضار','Egg whites with vegetables',[ing('بياض بيض','Egg Whites','4 بيضات / 4 whites',140),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],180,'20g','8g','4g',14),
          meal('غداء','Lunch','1:00 PM','فراخ مسلوقة مع أرز بني وسلطة','Boiled chicken with brown rice and salad',[ing('صدر فراخ طازج','Chicken Breast','180 جم / 180g',180),ing('أرز بني','Brown Rice','100 جم / 100g',100),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],420,'42g','36g','8g',50),
          meal('عشاء','Dinner','7:00 PM','شوربة خضار بالدجاج','Chicken vegetable soup',[ing('صدر فراخ طازج','Chicken Breast','120 جم / 120g',120),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],240,'28g','12g','6g',35),
          meal('سناك','Snack','4:00 PM','خيار وجزر مقطع','Sliced cucumber and carrot',[ing('خيار','Cucumber','حبة / 1 piece',120),ing('جزر','Carrot','حبة / 1 piece',80)],45,'1g','9g','0g',6),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','55 جم / 55g',55)],318,'12g','12g','28g',33)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','بيض مسلوق مع أفوكادو','Boiled eggs with avocado',[ing('بيض أحمر','Eggs','2 بيضة / 2 eggs',120),ing('أفوكادو','Avocado','نصف حبة / half',80)],260,'14g','8g','20g',20),
          meal('غداء','Lunch','1:00 PM','لحمة مشوية مع خضار وأرز بني','Grilled beef with vegetables and brown rice',[ing('لحمة كندوز','Beef','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],460,'34g','38g','16g',65),
          meal('عشاء','Dinner','7:00 PM','سمك مشوي بالليمون','Grilled fish with lemon',[ing('سمك بلطي','Tilapia Fish','180 جم / 180g',180),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],260,'36g','6g','8g',46),
          meal('سناك','Snack','4:00 PM','مكسرات مشكلة قليلة','A small handful of mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],90,'3g','3g','8g',10),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','25 جم / 25g',25)],145,'5g','6g','13g',15)
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
          meal('سناك','Snack','4:00 PM','حبة خيار وجبنة قريش','Cucumber with cottage cheese',[ing('خيار','Cucumber','حبة / 1 piece',120),ing('جبنة قريش','Cottage Cheese','40 جم / 40g',40)],90,'6g','5g','2g',10),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','45 جم / 45g',45)],261,'9g','10g','23g',27)
        ])
      ]
    },
    women:{
      nameAr:'المرأة',nameEn:'Women',dailyCalories:1227,dailyCarbs:'122g',dailyProtein:'85g',dailyFat:'39g',
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
      nameAr:'المرأة فوق الأربعين',nameEn:'Women Over 40',dailyCalories:1232,dailyCarbs:'87g',dailyProtein:'94g',dailyFat:'52g',
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
          meal('سناك','Snack','4:00 PM','زبادي بالتوت','Yogurt with berries',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('توت مشكل','Mixed Berries','60 جم / 60g',60)],140,'6g','16g','4g',22),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','15 جم / 15g',15)],87,'3g','3g','8g',10)
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
          meal('سناك','Snack','4:00 PM','جبنة قريش','Cottage cheese',[ing('جبنة قريش','Cottage Cheese','80 جم / 80g',80)],80,'9g','3g','3g',14),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','30 جم / 30g',30)],174,'6g','7g','15g',18)
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
          meal('سناك','Snack','4:00 PM','زبادي بالمكسرات','Yogurt with nuts',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('مكسرات مشكلة','Mixed Nuts','10 جم / 10g',10)],140,'7g','9g','8g',20),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','35 جم / 35g',35)],203,'7g','8g','18g',21)
        ])
      ]
    },
    men:{
      nameAr:'الرجل',nameEn:'Men',dailyCalories:2070,dailyCarbs:'213g',dailyProtein:'140g',dailyFat:'73g',
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
      nameAr:'الرجل فوق الأربعين',nameEn:'Men Over 40',dailyCalories:1520,dailyCarbs:'117g',dailyProtein:'112g',dailyFat:'64g',
      week:[
        mk('الأحد','Sunday',[
          meal('إفطار','Breakfast','7:00 AM','بيض بالجبنة والخبز الأسمر','Eggs with cheese and brown bread',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('جبنة بيضاء','White Cheese','40 جم / 40g',40),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60)],420,'28g','36g','20g',30),
          meal('غداء','Lunch','1:00 PM','سمك مشوي مع أرز بني وخضار','Grilled fish with brown rice and vegetables',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('أرز بني','Brown Rice','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],500,'46g','54g','10g',62),
          meal('عشاء','Dinner','7:00 PM','صدر دجاج بالخضار','Chicken breast with vegetables',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],380,'44g','12g','12g',54),
          meal('سناك','Snack','4:00 PM','طماطم وجبنة','Tomato and cheese',[ing('طماطم','Tomatoes','2 حبة / 2 pieces',200),ing('جبنة قريش','Cottage Cheese','60 جم / 60g',60)],140,'10g','10g','5g',16),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','15 جم / 15g',15)],87,'3g','3g','8g',10)
        ]),
        mk('الاثنين','Monday',[
          meal('إفطار','Breakfast','7:00 AM','شوفان بالحليب قليل الدسم والمكسرات','Oats with low-fat milk and nuts',[ing('شوفان','Oats','50 جم / 50g',50),ing('لبن','Milk','200 مل / 200ml',200),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],380,'16g','58g','10g',22),
          meal('غداء','Lunch','1:00 PM','فراخ مشوية مع بروكلي وأرز بني','Grilled chicken with broccoli and brown rice',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('بروكلي','Broccoli','150 جم / 150g',150),ing('أرز بني','Brown Rice','120 جم / 120g',120)],460,'46g','44g','9g',56),
          meal('عشاء','Dinner','7:00 PM','شوربة عدس بالخضار','Lentil soup with vegetables',[ing('عدس','Lentils','180 جم / 180g',180),ing('خضار مشكلة','Mixed Vegetables','100 جم / 100g',100)],280,'15g','44g','3g',16),
          meal('سناك','Snack','4:00 PM','زبادي بالتوت','Yogurt with berries',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('توت مشكل','Mixed Berries','60 جم / 60g',60)],140,'6g','16g','4g',22),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','45 جم / 45g',45)],261,'9g','10g','23g',27)
        ]),
        mk('الثلاثاء','Tuesday',[
          meal('إفطار','Breakfast','7:00 AM','بياض بيض بالخضار وخبز أسمر','Egg whites with vegetables and brown bread',[ing('بياض بيض','Egg Whites','4 بيضات / 4 whites',140),ing('خضار مشكلة','Mixed Vegetables','80 جم / 80g',80),ing('عيش أسمر','Brown Bread','رغيف صغير / 1 small loaf',60)],320,'26g','36g','4g',22),
          meal('غداء','Lunch','1:00 PM','سلمون مشوي مع خضار وأرز بني','Grilled salmon with vegetables and brown rice',[ing('سلمون','Salmon','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],540,'44g','40g','22g',98),
          meal('عشاء','Dinner','7:00 PM','كفتة مشوية قليلة الدهن مع سلطة','Lean grilled kofta with salad',[ing('لحمة مفرومة','Ground Beef','160 جم / 160g',160),ing('سلطة خضراء','Green Salad','100 جم / 100g',100)],360,'32g','8g','22g',60),
          meal('سناك','Snack','4:00 PM','مكسرات مشكلة قليلة','A small handful of mixed nuts',[ing('مكسرات مشكلة','Mixed Nuts','20 جم / 20g',20)],130,'4g','5g','11g',14),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','30 جم / 30g',30)],174,'6g','7g','15g',18)
        ]),
        mk('الأربعاء','Wednesday',[
          meal('إفطار','Breakfast','7:00 AM','عجة بالطماطم والجبنة القريش','Tomato and cottage cheese omelette',[ing('بيض أحمر','Eggs','3 بيضات / 3 eggs',180),ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('جبنة قريش','Cottage Cheese','50 جم / 50g',50)],340,'26g','10g','22g',24),
          meal('غداء','Lunch','1:00 PM','فراخ بالخضار مع أرز بني','Chicken with vegetables and brown rice',[ing('صدر فراخ طازج','Chicken Breast','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','120 جم / 120g',120)],460,'46g','46g','9g',58),
          meal('عشاء','Dinner','7:00 PM','سمك بالفرن بالليمون والأعشاب','Baked fish with lemon and herbs',[ing('سمك بلطي','Tilapia Fish','200 جم / 200g',200),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150)],360,'40g','12g','10g',52),
          meal('سناك','Snack','4:00 PM','تفاح ولوز','Apple and almonds',[ing('تفاح','Apple','حبة / 1 piece',150),ing('لوز','Almonds','15 جم / 15g',15)],180,'4g','24g','9g',18),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','30 جم / 30g',30)],174,'6g','7g','15g',18)
        ]),
        mk('الخميس','Thursday',[
          meal('إفطار','Breakfast','7:00 AM','زبادي يوناني بالمكسرات','Greek yogurt with nuts',[ing('زبادي يوناني','Greek Yogurt','170 جم / 170g',170),ing('مكسرات مشكلة','Mixed Nuts','15 جم / 15g',15)],240,'15g','16g','13g',34),
          meal('غداء','Lunch','1:00 PM','لحمة مشوية قليلة الدهن مع خضار وأرز بني','Lean grilled beef with vegetables and brown rice',[ing('لحمة كندوز','Beef','160 جم / 160g',160),ing('خضار مشكلة','Mixed Vegetables','150 جم / 150g',150),ing('أرز بني','Brown Rice','100 جم / 100g',100)],460,'36g','42g','16g',66),
          meal('عشاء','Dinner','7:00 PM','شوربة خضار بالدجاج','Chicken vegetable soup',[ing('صدر فراخ طازج','Chicken Breast','150 جم / 150g',150),ing('خضار مشكلة','Mixed Vegetables','200 جم / 200g',200)],300,'34g','14g','7g',42),
          meal('سناك','Snack','4:00 PM','طماطم وجبنة قريش','Tomato and cottage cheese',[ing('طماطم','Tomatoes','حبة / 1 piece',100),ing('جبنة قريش','Cottage Cheese','60 جم / 60g',60)],110,'9g','5g','4g',14),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','70 جم / 70g',70)],405,'15g','15g','35g',42)
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
          meal('سناك','Snack','4:00 PM','زبادي بالعسل','Yogurt with honey',[ing('زبادي','Plain Yogurt','150 جم / 150g',150),ing('عسل نحل','Honey','ملعقة / 1 tbsp',20)],150,'6g','20g','3g',20),
          meal('سناك إضافي','Extra Snack','9:00 PM','لوز','Almonds',[ing('لوز','Almonds','55 جم / 55g',55)],318,'12g','12g','28g',33)
        ])
      ]
    },
    kids:{
      nameAr:'الأطفال',nameEn:'Kids',dailyCalories:1223,dailyCarbs:'163g',dailyProtein:'61g',dailyFat:'34g',
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
// RC1 Web Pilot Promotion (2026-08-14): login-pilot.html promoted to the
// canonical /login route — verified full feature parity with login.html
// (Google/Facebook sign-in, register tab, forgot-password link, hero
// banner) during the Identity & Authentication domain migration. The
// legacy file remains on disk, unreferenced by any route, as the rollback
// artifact — see server.js.backup-before-rc1-pilot-promotion-2026-08-14 for
// the one-line revert if needed.
app.get(`${BASE}/login`, (req,res) => res.sendFile(path.join(__dirname,'public','login-pilot.html')));
app.get(`${BASE}/demo`, (req,res) => res.sendFile(path.join(__dirname,'public','demo.html')));
app.get(`${BASE}/payment`, (req,res) => res.sendFile(path.join(__dirname,'public','payment.html')));
// RC1 Web Pilot Promotion (2026-08-14) — see /login's comment above for the
// pattern/rollback note.
app.get(`${BASE}/verify-pending`, (req,res) => res.sendFile(path.join(__dirname,'public','verify-pending-pilot.html')));
app.get(['/', BASE, `${BASE}/`], (req,res) => res.redirect(`${BASE}/dashboard`));
app.get(`${BASE}/dashboard`, auth, (req,res) => { res.setHeader('Cache-Control','no-store'); res.sendFile(path.join(__dirname,'public', req.user.role==='admin'?'admin.html':'dashboard.html')); });
// Platform Preferences (2026-08-14) — auth-gated like /dashboard, unlike the
// other *-pilot pages which are plain static files under express.static and
// gate client-side via GET /api/me. This one gates server-side because it's
// the one pilot page that can act on the account itself (password/deletion),
// so an unauthenticated visit should never even receive the page shell.
app.get(`${BASE}/settings-pilot`, auth, (req,res) => { res.setHeader('Cache-Control','no-store'); res.sendFile(path.join(__dirname,'public','settings-pilot.html')); });
app.get(`${BASE}/subscription-pilot`, auth, (req,res) => { res.setHeader('Cache-Control','no-store'); res.sendFile(path.join(__dirname,'public','subscription-pilot.html')); });
// RC1 Web Pilot Promotion (2026-08-14): canonical, permanent URLs for the
// three pages that have no legacy predecessor to replace (Settings,
// Subscription, and — new here — a real auth-gated route for the chatbot
// page, upgrading it from the client-side-only gate every other *-pilot
// page uses to the same server-side auth() gate settings/subscription
// already had, since it's now a first-class, permanently-linked surface).
// The old -pilot URLs are left working, not removed — harmless aliases,
// zero risk of breaking anything that still links to them directly.
app.get(`${BASE}/settings`, auth, (req,res) => { res.setHeader('Cache-Control','no-store'); res.sendFile(path.join(__dirname,'public','settings-pilot.html')); });
app.get(`${BASE}/subscription`, auth, (req,res) => { res.setHeader('Cache-Control','no-store'); res.sendFile(path.join(__dirname,'public','subscription-pilot.html')); });
app.get(`${BASE}/chatbot`, auth, (req,res) => { res.setHeader('Cache-Control','no-store'); res.sendFile(path.join(__dirname,'public','chatbot-pilot.html')); });

// Verify email
app.get(`${BASE}/verify-email`, (req,res) => {
  // Previously the only auth-adjacent, token-possession route with zero rate
  // limiting (not even the generic /api limiter, since this path isn't under
  // /api). Tokens are 256-bit random (randToken()) so brute-forcing one isn't
  // practical regardless, but this closes the one real gap in an otherwise
  // fully rate-limited auth surface at negligible cost to real users.
  const r = rateLimit(getIP(req), 'verify-email', 20, 60000);
  if (!r.ok) return res.redirect(`${BASE}/login?error=ratelimited`);
  const {token} = req.query;
  if (!token) return res.redirect(`${BASE}/login?error=invalid`);
  // Real production bug found live: this array can contain a corrupted
  // `null` entry (confirmed one at index 8 in the live data — likely from
  // an old lost-update race on this file's raw load/push/save pattern,
  // not from the real, correctly-formed push at registration). `.find()`
  // over an array containing null throws "Cannot read properties of null"
  // the moment it reaches that entry, 500ing this route for every token
  // whose real match sits after the null — filtering defensively means a
  // stray corrupted entry can never take this route down again.
  const pending = (load('pending_verifications.json') || []).filter(Boolean);
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
  setSessionCookie(req, res, t, 28800);
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
  const pending = (load('pending_verifications.json') || []).filter(Boolean);
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
  const accessToken = mkToken(u);
  // RC1 security review, 2026-08-14: the web login pages (login.html,
  // login-pilot.html) were setting this same cookie themselves via
  // client-side `document.cookie`, which can never carry HttpOnly — the
  // exact real, working HttpOnly pattern already existed elsewhere in this
  // file (the email-verification redirect, line ~1188) but was never
  // applied to the actual username/password login path every real user
  // takes. Setting it server-side here closes that gap; the corresponding
  // client-side document.cookie lines are removed in the same pass so they
  // can't immediately overwrite this with a non-HttpOnly copy. Mobile is
  // unaffected — it never reads cookies, only the `token` field below.
  setSessionCookie(req, res, accessToken, 28800);
  res.json({token:accessToken, refreshToken:mkRefreshToken(u.id), role:u.role, plan:u.plan, username:u.username, trial:tr, lang:u.lang||'ar', emailVerified:u.emailVerified});
});

// Mobile clients exchange a refresh token for a new access token here instead
// of re-prompting for a password every SEC.SESSION_H hours. Rotates the
// refresh token on every use — see mkRefreshToken above for why.
app.post(`${BASE}/api/auth/refresh`, (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Missing refreshToken' });
  const tokens = load('refresh_tokens.json') || {};
  const rec = tokens[refreshToken];
  if (!rec || Date.now() > rec.expiresAt) return res.status(401).json({ error: 'Invalid or expired refresh token' });
  const users = load('users.json') || [];
  const u = users.find(uu => uu.id === rec.userId && uu.active);
  if (!u) return res.status(401).json({ error: 'Invalid or expired refresh token' });
  delete tokens[refreshToken];
  save('refresh_tokens.json', tokens);
  res.json({ token: mkToken(u), refreshToken: mkRefreshToken(u.id), role: u.role, plan: u.plan, username: u.username });
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

  // Find-or-create inside a real transaction (2026-09-02 fix): two
  // simultaneous Google sign-ins for the same brand-new email used to both
  // pass the `!user` check (the await above yields the event loop before
  // either one reads users.json) and each `push()` its own new row — a
  // real duplicate-account race, not hypothetical. update()'s mutator runs
  // inside a single SQLite IMMEDIATE transaction, so the second concurrent
  // call sees the first one's just-committed row instead of racing it.
  let user = null, isNewUser = false;
  update('users.json', (current) => {
    const users = current || [];
    const existing = users.find(u => u.email === email);
    if (existing) { user = existing; return users; }

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

    const newUser = {
      id: 'u' + Date.now() + randToken(4),
      username, password: hashPwd(randToken(24)), // unusable random password — this account only ever signs in via Google
      email, phone: '',
      role: 'user', plan: 'trial',
      created: new Date().toISOString().split('T')[0],
      active: true, emailVerified: true,
      trialStart: new Date().toISOString().split('T')[0],
      paid: false, lang: 'ar', loginAttempts: 0, lastLogin: null, avatarUrl: null,
      googleAuth: true,
      profile: { diet: 'atkins', weight: null, height: null, age: null, gender: 'male', budget: 200, bodyFat: null, muscleMass: null, bmi: null, bmr: null }
    };
    user = newUser;
    isNewUser = true;
    return [...users, newUser];
  }, []);

  if (isNewUser) {
    secLog('REGISTERED_GOOGLE', ip, { username: user.username, email });
    const subs = load('subscriptions.json') || [];
    subs.push({ userId: user.id, plan: 'trial', startDate: user.created, endDate: new Date(Date.now() + TRIAL_DAYS * 86400000).toISOString().split('T')[0], amount: 0, status: 'trial' });
    save('subscriptions.json', subs);
  } else if (!user.active) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  // Bumping lastLogin re-reads current state inside its own transaction
  // rather than reusing the `users` array captured before the block above
  // — that array could be stale (missing the row just created above) and
  // saving it back would silently wipe out the new user.
  update('users.json', (current) => {
    const users = current || [];
    const idx = users.findIndex(u => u.id === user.id);
    if (idx >= 0) users[idx] = { ...users[idx], lastLogin: new Date().toISOString() };
    return users;
  }, []);
  rlReset(ip, 'login');
  secLog('LOGIN_OK_GOOGLE', ip, { username: user.username });

  const tr = trial(user);
  const accessToken = mkToken(user);
  // Same RC1 HttpOnly-cookie fix as /auth above — see that route's comment.
  setSessionCookie(req, res, accessToken, 28800);
  res.json({ token: accessToken, refreshToken: mkRefreshToken(user.id), role: user.role, plan: user.plan, username: user.username, trial: tr, lang: user.lang || 'ar', emailVerified: true });
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

  // Find-or-create inside a real transaction — same duplicate-account race
  // (and same fix) as /api/auth/google above.
  let user = null, isNewUser = false;
  update('users.json', (current) => {
    const users = current || [];
    const existing = users.find(u => u.email === email);
    if (existing) { user = existing; return users; }

    // New signup via Facebook — same pattern as Google signup above: email
    // comes pre-verified by Facebook, no phone/weight/height/age available,
    // profile starts empty for the user to fill in later from the dashboard.
    let base = (fbUser.name || email.split('@')[0]).replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_.-]/g, '');
    if (base.length < SEC.USR_MIN) base = 'user' + randToken(2);
    base = base.slice(0, SEC.USR_MAX - 4);
    let username = base, n = 1;
    while (users.find(u => u.username === username)) username = `${base}${++n}`;

    const newUser = {
      id: 'u' + Date.now() + randToken(4),
      username, password: hashPwd(randToken(24)), // unusable random password — this account only ever signs in via Facebook
      email, phone: '',
      role: 'user', plan: 'trial',
      created: new Date().toISOString().split('T')[0],
      active: true, emailVerified: true,
      trialStart: new Date().toISOString().split('T')[0],
      paid: false, lang: 'ar', loginAttempts: 0, lastLogin: null, avatarUrl: null,
      facebookAuth: true,
      profile: { diet: 'atkins', weight: null, height: null, age: null, gender: 'male', budget: 200, bodyFat: null, muscleMass: null, bmi: null, bmr: null }
    };
    user = newUser;
    isNewUser = true;
    return [...users, newUser];
  }, []);

  if (isNewUser) {
    secLog('REGISTERED_FACEBOOK', ip, { username: user.username, email });
    const subs = load('subscriptions.json') || [];
    subs.push({ userId: user.id, plan: 'trial', startDate: user.created, endDate: new Date(Date.now() + TRIAL_DAYS * 86400000).toISOString().split('T')[0], amount: 0, status: 'trial' });
    save('subscriptions.json', subs);
  } else if (!user.active) {
    return res.status(403).json({ error: 'Account suspended' });
  }

  // Same reasoning as /api/auth/google above — re-read current state rather
  // than saving back a `users` snapshot that predates the block above.
  update('users.json', (current) => {
    const users = current || [];
    const idx = users.findIndex(u => u.id === user.id);
    if (idx >= 0) users[idx] = { ...users[idx], lastLogin: new Date().toISOString() };
    return users;
  }, []);
  rlReset(ip, 'login');
  secLog('LOGIN_OK_FACEBOOK', ip, { username: user.username });

  const tr = trial(user);
  // Named dhSessionToken here, not accessToken — this route already uses
  // `accessToken` for the incoming Facebook OAuth token (req.body), a
  // completely different value; reusing the name would shadow/collide.
  const dhSessionToken = mkToken(user);
  // Same RC1 HttpOnly-cookie fix as /auth above — see that route's comment.
  setSessionCookie(req, res, dhSessionToken, 28800);
  res.json({ token: dhSessionToken, refreshToken: mkRefreshToken(user.id), role: user.role, plan: user.plan, username: user.username, trial: tr, lang: user.lang || 'ar', emailVerified: true });
});

app.get(`${BASE}/logout`, (req,res) => {
  secLog('LOGOUT', getIP(req));
  clearSessionCookie(req, res);
  res.redirect(`${BASE}/login`);
});

// Mobile-friendly logout — no cookie to clear, so this just revokes the
// refresh token (the access token expires on its own within SEC.SESSION_H).
app.post(`${BASE}/api/auth/logout`, (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) revokeRefreshToken(refreshToken);
  res.json({ ok: true });
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
    paid:false, lang:'ar', loginAttempts:0, lastLogin:null, avatarUrl:null,
    profile:{ diet:diet||'atkins', weight:w, height:h, age:parseInt(age)||null, gender:gender||'male', budget:parseInt(budget)||200, bodyFat:parseFloat(bodyFat)||null, muscleMass:parseFloat(muscleMass)||null, bmi, bmr, measurementsUpdatedAt:new Date().toISOString() }
  };
  users.push(newUser);
  save('users.json', users);
  if (w) {
    const wh = load('weight_history.json') || {};
    wh[newUser.id] = [{ date: newUser.created, weight: w }];
    save('weight_history.json', wh);
  }
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
// Production hardening pass (independent audit, Part 3, F3.1): this route
// previously copied weight/height/age/budget/bodyFat/muscleMass/diet/gender
// from req.body onto the stored profile with zero type or bounds checking —
// the allowlist restricted which *fields* could be set, not what *values*
// they could hold. Bounds below reuse the exact same real numbers already
// enforced elsewhere in this file (POST /api/health-profile/goals' own
// targetWeight check; the 50-1000 budget clamp used by /api/meal-plan and
// /api/meal-plan/swap), rather than inventing new ones — same real limits,
// now enforced consistently at the point of write, not just at some points
// of read.
const PROFILE_VALID_DIETS = ['atkins','keto','lowcarb','highprotein','mediterranean','balanced','diabetic','women','women_40','men','men_40','kids'];
const PROFILE_VALID_GENDERS = ['male','female'];
function validateProfileField(key, value) {
  switch (key) {
    case 'weight': case 'bodyFat': case 'muscleMass': {
      const n = Number(value);
      if (!Number.isFinite(n) || n < 0 || n > 400) return null;
      return n;
    }
    case 'height': {
      const n = Number(value);
      if (!Number.isFinite(n) || n < 50 || n > 260) return null;
      return n;
    }
    case 'age': {
      const n = Number(value);
      if (!Number.isFinite(n) || n < 10 || n > 120) return null;
      return n;
    }
    case 'budget': {
      const n = Number(value);
      if (!Number.isFinite(n)) return null;
      return Math.min(Math.max(n, 50), 1000);
    }
    case 'diet':
      return PROFILE_VALID_DIETS.includes(value) ? value : null;
    case 'gender':
      return PROFILE_VALID_GENDERS.includes(value) ? value : null;
    case 'takesCreatine': case 'cycleTrackingEnabled':
      return typeof value === 'boolean' ? value : null;
    case 'lastPeriodStart': {
      if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
      const d = new Date(value + 'T00:00:00Z');
      if (isNaN(d.getTime()) || d.getTime() > Date.now()) return null; // not a real date, or in the future
      return value;
    }
    case 'cycleLength': {
      const n = Number(value);
      // 20-45 days is a permissive input bound (covers real irregular
      // cycles), not a claimed "normal range" shown to the user anywhere —
      // just wide enough to reject garbage input, not narrow enough to
      // reject a real person's real cycle.
      if (!Number.isFinite(n) || n < 20 || n > 45) return null;
      return Math.round(n);
    }
    default:
      return value; // level/calorieMode/customCalorieTarget: accepted as-is — not read by any real calculation server-side, confirmed by grep before this change; not worth inventing enforcement for fields nothing enforces meaning on
  }
}
app.post(`${BASE}/api/profile`, auth, (req,res) => {
  const users = load('users.json')||[];
  const idx = users.findIndex(u=>u.id===req.user.id);
  if (idx<0) return res.status(404).json({});
  const ok = ['diet','budget','weight','height','age','gender','bodyFat','muscleMass','level','calorieMode','customCalorieTarget','takesCreatine','allergies','customAllergyText','medicalConditions','cycleTrackingEnabled','lastPeriodStart','cycleLength'];
  const safe = {};
  for (const k of ok) {
    if (req.body[k] === undefined) continue;
    if (k === 'allergies' || k === 'customAllergyText' || k === 'medicalConditions') { safe[k] = req.body[k]; continue; }
    const validated = validateProfileField(k, req.body[k]);
    if (validated === null) return res.status(400).json({ error: `Invalid value for ${k}` });
    safe[k] = validated;
  }
  if (safe.allergies !== undefined) {
    safe.allergies = Array.isArray(safe.allergies) ? safe.allergies.filter(a => KNOWN_ALLERGENS.includes(a)) : [];
  }
  // Self-reported, not diagnosed by the app — used to gate genuinely unsafe
  // combinations (a calorie deficit during pregnancy, an aggressive deficit
  // for a minor, Keto/Atkins with no T1D warning) rather than to make any
  // clinical claim itself. See KNOWN_MEDICAL_CONDITIONS.
  if (safe.medicalConditions !== undefined) {
    safe.medicalConditions = Array.isArray(safe.medicalConditions) ? safe.medicalConditions.filter(c => KNOWN_MEDICAL_CONDITIONS.includes(c)) : [];
  }
  // Free-text allergy the user typed under "Other" (e.g. "sesame", "kiwi") —
  // not one of the 8 structured KNOWN_ALLERGENS categories, so it can't be
  // tagged on FOOD_DB entries the same way. Matched by keyword against food
  // names instead — see allergyKeywordsMatch() below. Capped at 200 chars,
  // same sanitize() used for every other free-text profile field.
  if (safe.customAllergyText !== undefined) {
    safe.customAllergyText = typeof safe.customAllergyText === 'string' ? sanitize(safe.customAllergyText).slice(0, 200) : '';
  }
  users[idx].profile = {...users[idx].profile, ...safe};
  // Recompute BMI/BMR whenever weight/height/age/gender change, using the
  // merged (existing + just-updated) profile — not just whatever subset of
  // fields this particular request happened to include.
  const p = users[idx].profile;
  const {bmi, bmr} = calcBmiBmr(p.weight, p.height, p.age, p.gender);
  users[idx].profile.bmi = bmi;
  users[idx].profile.bmr = bmr;
  // Tracks the last time the user actually logged fresh measurements — the
  // daily "log your weight" reminder (reminders.js) uses this to skip anyone
  // who already updated today, instead of nagging regardless of real activity.
  if (['weight','height','bodyFat','muscleMass'].some(k => req.body[k]!==undefined)) {
    users[idx].profile.measurementsUpdatedAt = new Date().toISOString();
  }
  if (req.body.lang && ['ar','en'].includes(req.body.lang)) users[idx].lang=req.body.lang;
  save('users.json', users);

  // Real weight history — previously only the current value was kept (each
  // update overwrote the last), so there was no way to show a real trend
  // ("▼0.4kg since last time") on the daily briefing. One entry per calendar
  // day (last write wins if updated twice same day), kept 90 days like the
  // other daily time series in this app (watch_data, nutrition_logs).
  if (req.body.weight !== undefined && p.weight) {
    const today = new Date().toISOString().split('T')[0];
    const wh = load('weight_history.json') || {};
    const list = (wh[req.user.id] || []).filter(e => e.date !== today);
    list.push({ date: today, weight: p.weight });
    wh[req.user.id] = list.sort((a, b) => b.date.localeCompare(a.date)).slice(0, 90);
    save('weight_history.json', wh);
  }

  res.json({ok:true, bmi, bmr});
});

// ─── PROFILE PHOTO (2026-09-03) ─────────────────────────────────────────────
// Same memoryStorage()+fileFilter shape as labUpload/foodPhotoUpload above,
// reused rather than reinvented. Unlike those two, this file IS persisted —
// resized/re-encoded through sharp() first (never trust a client-reported
// crop/size for something about to be served back out over a public URL)
// and written to AVATAR_DIR under a random filename.
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg','image/png','image/webp','image/heic'].includes(file.mimetype);
    cb(ok ? null : new Error('Unsupported file type — use JPG, PNG, WEBP, or HEIC'), ok);
  }
});

// Deletes the user's current avatar file from disk, if any — shared by the
// replace-on-reupload step below and by DELETE /api/profile/avatar. Safe to
// call with no existing file (fs.existsSync guards it) or a malformed URL.
function deleteAvatarFile(avatarUrl) {
  if (!avatarUrl) return;
  const filename = path.basename(avatarUrl);
  const filePath = path.join(AVATAR_DIR, filename);
  if (path.dirname(filePath) === AVATAR_DIR && fs.existsSync(filePath)) {
    try { fs.unlinkSync(filePath); } catch (e) { console.error('[avatar] failed to delete old file:', e.message); }
  }
}

app.post(`${BASE}/api/profile/avatar`, auth, avatarUpload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  let resized;
  try {
    // Fixed 512x512, always re-encoded to JPEG — regardless of what the
    // client sent. fit:'cover' matches the app's own circular-avatar crop
    // convention (center-cropped to a square) rather than letterboxing.
    resized = await sharp(req.file.buffer).rotate().resize(512, 512, { fit: 'cover' }).jpeg({ quality: 85 }).toBuffer();
  } catch (e) {
    console.error('[avatar] sharp processing failed:', e.message);
    return res.status(400).json({ error: 'Could not process this image — try a different photo' });
  }

  const filename = `${req.user.id}-${randToken(8)}.jpg`;
  fs.writeFileSync(path.join(AVATAR_DIR, filename), resized);
  const avatarUrl = `/uploads/avatars/${filename}`;

  let previousAvatarUrl = null;
  update('users.json', (all) => {
    const idx = (all || []).findIndex(u => u.id === req.user.id);
    if (idx >= 0) { previousAvatarUrl = all[idx].avatarUrl || null; all[idx].avatarUrl = avatarUrl; }
    return all;
  }, []);
  deleteAvatarFile(previousAvatarUrl);

  res.json({ ok: true, avatarUrl });
}, handleUploadError);

app.delete(`${BASE}/api/profile/avatar`, auth, (req, res) => {
  let previousAvatarUrl = null;
  update('users.json', (all) => {
    const idx = (all || []).findIndex(u => u.id === req.user.id);
    if (idx >= 0) { previousAvatarUrl = all[idx].avatarUrl || null; all[idx].avatarUrl = null; }
    return all;
  }, []);
  deleteAvatarFile(previousAvatarUrl);
  res.json({ ok: true });
});

// Real, long-documented backend gap closed 2026-08-14 (Goals & Health
// Reports domain migration): weight_history.json has been written correctly
// on every weight update since it was introduced (see the real-weight-
// history comment above), but no route ever read it back as a series —
// only the daily brief's own buildSnapshot() could see it, server-side,
// for the single "trend since last entry" note. This is the smallest
// possible read addition: no change to the storage model, no change to
// what's written, purely additive. Same shape convention as the other real
// time-series read route in this app (GET /api/watch/data): {data, days,
// count}, newest-first (matches how weight_history.json is already sorted
// when written), capped the same way (90 days is already weight_history's
// own real storage cap, so `days` here can only ever narrow that window,
// never widen it — no fabricated data is possible).
app.get(`${BASE}/api/weight-history`, auth, (req, res) => {
  const all = load('weight_history.json') || {};
  const userHistory = all[req.user.id] || [];
  const days = Math.min(Math.max(parseInt(req.query.days) || 90, 1), 90);
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  const cutoffStr = cutoff.toISOString().split('T')[0];
  const filtered = userHistory.filter(e => e.date >= cutoffStr);
  res.json({ data: filtered, days, count: filtered.length });
});

// ─── ACCOUNT MANAGEMENT (Platform Preferences, 2026-08-14) ────────────────────
// Reuses the exact same checkPwd/hashPwd/validatePwd used by login and
// registration — no parallel auth mechanism introduced.
app.post(`${BASE}/api/account/change-password`, auth, (req, res) => {
  const ip = getIP(req);
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
  const users = load('users.json') || [];
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx < 0) return res.status(404).json({ error: 'Not found' });
  if (!checkPwd(currentPassword, users[idx].password)) {
    secLog('PASSWORD_CHANGE_FAILED', ip, { userId: req.user.id });
    return res.status(401).json({ error: 'كلمة المرور الحالية غير صحيحة · Current password is incorrect' });
  }
  const pErr = validatePwd(newPassword);
  if (pErr) return res.status(400).json({ error: pErr });
  users[idx].password = hashPwd(newPassword);
  save('users.json', users);
  // A password change is a real security boundary — every other signed-in
  // session (any device) loses its refresh token, same as a suspected-
  // compromise response. The session making this call still holds a live
  // access token for the rest of its 8h window, but the client logs itself
  // out immediately afterward anyway (see mobile/web implementation) so the
  // new password takes effect everywhere in practice, not just on paper.
  update('refresh_tokens.json', tokens => {
    for (const [token, rec] of Object.entries(tokens)) if (rec.userId === req.user.id) delete tokens[token];
    return tokens;
  }, {});
  secLog('PASSWORD_CHANGED', ip, { userId: req.user.id });
  res.json({ ok: true });
});

// Production-safe account deletion. Verifies the password (same check as
// login), then removes/scrubs everything this app actually owns for that
// user. Deliberately NOT unsafe file deletion — every touched document goes
// through the same load/update/save JSON-store interface every other route
// in this file uses, one document at a time, each write atomic
// (db.js's update() runs inside an IMMEDIATE transaction).
//
// What this route deletes outright (per-user keyed documents, entire key
// removed): nutrition_logs, weight_history, watch_data, lab_results,
// meal_overrides, ai_suggestions, geofence_zones, push_tokens.
// What it filters out (array-based, matching entries removed):
// pending_verifications, refresh_tokens (all of the user's — real session
// invalidation, every device).
// What it does NOT delete, and why: payment_orders.json and
// security_log.json are retained — financial transaction records and the
// security audit trail are standard exceptions to account-data deletion
// (accounting/fraud-review requirements outlive the account itself), not an
// oversight. ratings.json is left untouched because it has no reliable
// userId linkage (submitted with a free-text, unverified email/name) —
// filtering it by best-effort match risks deleting a stranger's review or
// missing the real one; documented here rather than guessed at silently.
// An active subscription is cancelled (status flipped, not deleted) so
// billing stops without destroying the transaction history behind it.
// The user record itself is soft-deleted: `active:false` (which the
// existing `auth()` middleware already checks on every request — this is
// the real, existing session-invalidation mechanism, not a new one),
// password replaced with an unusable random hash, email/phone/profile
// scrubbed, username replaced with a placeholder so it can never be reused
// to log in again while the row still exists for any remaining foreign-
// key-shaped references (e.g. a retained payment_orders entry's `userId`).
app.post(`${BASE}/api/account/delete`, auth, (req, res) => {
  const ip = getIP(req);
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const users = load('users.json') || [];
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx < 0) return res.status(404).json({ error: 'Not found' });
  if (!checkPwd(password, users[idx].password)) {
    secLog('ACCOUNT_DELETE_FAILED', ip, { userId: req.user.id });
    return res.status(401).json({ error: 'كلمة المرور غير صحيحة · Incorrect password' });
  }
  const userId = req.user.id;
  const originalUsername = users[idx].username;

  // Real filesystem side effect (2026-09-03) — the loop below only clears
  // JSON documents, so the avatar file needs its own explicit deletion.
  deleteAvatarFile(users[idx].avatarUrl);

  const PER_USER_KEYED_FILES = [
    'nutrition_logs.json', 'weight_history.json', 'watch_data.json', 'lab_results.json',
    'meal_overrides.json', 'ai_suggestions.json', 'geofence_zones.json', 'push_tokens.json',
    'geofence_dwell.json',
  ];
  for (const file of PER_USER_KEYED_FILES) {
    update(file, all => { delete all[userId]; return all; }, {});
  }
  update('pending_verifications.json', list => (list || []).filter(Boolean).filter(p => p.userId !== userId), []);
  update('refresh_tokens.json', tokens => {
    for (const [token, rec] of Object.entries(tokens)) if (rec.userId === userId) delete tokens[token];
    return tokens;
  }, {});
  update('subscriptions.json', subs => {
    subs.forEach(s => { if (s.userId === userId && s.status === 'active') { s.status = 'cancelled'; s.cancelledAt = new Date().toISOString(); s.cancelReason = 'account_deleted'; } });
    return subs;
  }, []);

  update('users.json', all => {
    const i = all.findIndex(u => u.id === userId);
    if (i >= 0) {
      all[i] = {
        ...all[i],
        username: `deleted_${userId}`,
        password: hashPwd(randToken(24)),
        email: '', phone: '', profile: {},
        active: false,
        avatarUrl: null,
        deletedAt: new Date().toISOString(),
      };
    }
    return all;
  }, []);

  secLog('ACCOUNT_DELETED', ip, { userId, username: originalUsername });
  track('account_deleted', { userId });
  res.json({ ok: true, deletedAt: new Date().toISOString() });
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

// ─── AI DAILY BRIEFING (Phase 1) ───────────────────────────────────────────
// See daily_brief.js for what this deliberately does and doesn't cover.
// Weather is optional (?lat=&lon=) and reuses the same cache/key as
// /api/weather — omitted entirely rather than faked if not provided.
app.get(`${BASE}/api/daily-brief`, auth, async (req, res) => {
  let weather = null;
  const flat = parseFloat(req.query.lat), flon = parseFloat(req.query.lon);
  if (!isNaN(flat) && !isNaN(flon) && process.env.OPENWEATHER_KEY) {
    const cacheKey = `${(flat*100|0)/100}_${(flon*100|0)/100}`;
    const hit = weatherCache.get(cacheKey);
    if (hit && Date.now() - hit.ts < 10 * 60 * 1000) {
      weather = hit.data;
    } else {
      try {
        const r = await fetch(`https://api.openweathermap.org/data/2.5/weather?lat=${flat}&lon=${flon}&appid=${process.env.OPENWEATHER_KEY}&units=metric`);
        if (r.ok) {
          const w = await r.json();
          weather = { temp: w.main.temp, humidity: w.main.humidity, description: w.weather?.[0]?.description || '', city: w.name };
          weatherCache.set(cacheKey, { data: weather, ts: Date.now() });
        }
      } catch { /* weather is optional on this screen — omit on failure, don't fail the request */ }
    }
  }

  try {
    const lang = aiLanguage.resolveLanguage({ userLang: req.userObj.lang, appLang: req.query.lang });
    const result = await buildDailyBrief(store, ai, coachSummary, buildHealthProfile, req.user.id, lang, weather);
    if (!result) return res.status(404).json({ error: 'Profile not found' });
    track('daily_brief_viewed', { userId: req.user.id });
    res.json(result);
  } catch (e) {
    console.error('Daily brief error:', e.message);
    res.status(500).json({ error: 'Failed to build daily brief' });
  }
});

// Real 7-day hit-rate across meals/water/steps/sleep — reads the same
// nutrition_logs.json / watch_data.json already used elsewhere, no new
// tracking. See daily_brief.js's buildWeeklySummary for the exact
// per-metric "day counts as a hit" rule.
app.get(`${BASE}/api/weekly-summary`, auth, (req, res) => {
  try {
    const hp = buildHealthProfile(store, req.user.id);
    if (!hp) return res.status(404).json({ error: 'Profile not found' });
    res.json(buildWeeklySummary(store, req.user.id, hp));
  } catch (e) {
    console.error('Weekly summary error:', e.message);
    res.status(500).json({ error: 'Failed to build weekly summary' });
  }
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

// All stores tracked per ingredient in food_prices.json - kept in one place
// so adding/removing a tracked store is a one-line change, not a hunt
// through every price-comparison call site. carrefour, royal and talabat
// were removed entirely (not just left unsupported): none of the three can
// ever get an automated price update (carrefour and talabat have real
// anti-bot protection; royal has no direct website at all), so their prices
// would sit frozen forever while the page's "Last updated" banner implied
// otherwise - worse than not listing them.
const STORE_KEYS = ['metro', 'seoudi', 'gourmet', 'spinneys', 'hyperone'];

function priceMeal(meal, foodPrices) {
  let total = 0;
  const ings = meal.ingredients.map(ing => {
    const item = findFoodItem(ing.item, ing.itemEn, foodPrices);
    let price = 0, store = '';
    if (item) {
      // Previously hardcoded to only 4 of the 8 stores tracked in
      // food_prices.json (carrefour/metro/royal/talabat) - seoudi, gourmet,
      // spinneys and hyperone were tracked but never actually compared here,
      // so their prices (including the ones kept fresh automatically by
      // price_scraper.js) never reached the "cheapest store" a user sees.
      const ps = STORE_KEYS.map(s => ({s, p:item[s]})).filter(x=>x.p).sort((a,b)=>a.p-b.p);
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
  const cheapestOf = (i) => Math.min(...STORE_KEYS.map(s => i[s]).filter(p => p > 0));
  const ingredientCatalog = items.map(i => `${i.id} (${i.nameEn}/${i.name}, ~${cheapestOf(i)} EGP/${i.unit}, category: ${i.category})`).join('\n');

  const tierInstruction = {
    low: 'Use cheap, budget-friendly ingredients from the list (lower price-per-unit items).',
    high: 'Premium ingredients from the list are fine (higher price-per-unit items welcome).',
    mid: '',
  }[budgetTier] || '';
  const preferenceInstruction = preference ? `The user specifically asked for: "${preference}". Reflect that in the meal choice.` : '';

  const prompt = `Suggest one ${DIET_STYLE_LABELS[dietStyle] || dietStyle} ${mealType} meal for an Egyptian meal-planning app. ${tierInstruction} ${preferenceInstruction}

You MUST only use ingredients from this exact list (reference them by "id"):
${ingredientCatalog}

The dish name must describe the food itself and must NOT contain the word "${mealType}" or any other meal-time word (breakfast/lunch/dinner/snack, in either language) — this meal's slot is already fixed as ${mealType}, the name should never repeat or contradict it.

Return ONLY valid JSON, no other text, in this exact shape:
{"name":"Arabic meal name","nameEn":"English meal name","ingredients":[{"ingredientId":"...", "grams":0}],"cal":0,"protein":"0g","carbs":"0g","fat":"0g"}`;

  // Previously a hardcoded single-provider Anthropic fetch — the exact
  // outage class ai.js's own header comment warns about ("Anthropic
  // credits ran out, silently broke... until it was noticed") applied here
  // too: meal-swap would 502 for every user the moment Anthropic alone was
  // unavailable, even while the chatbot (already on ai.chat()) kept working
  // via Gemini/Groq. Confirmed live during the Mobile Feature Parity
  // Program: this route really did 502 in production for exactly this
  // reason. Now goes through the same fallback chain as everywhere else.
  // JSON.parse is also now wrapped — previously an unparseable AI reply
  // would throw uncaught up into the route handler instead of being
  // treated the same as "no valid alternative" (the caller already
  // gracefully handles a null return here).
  let parsed;
  try {
    const { text } = await ai.chat({ messages: [{ role: 'user', content: prompt }], maxTokens: 500 });
    const raw = text || '{}';
    const match = raw.match(/\{[\s\S]*\}/);
    parsed = match ? JSON.parse(match[0]) : null;
  } catch (e) {
    console.error('[generateMealAlternative] error:', e.message);
    return null;
  }
  if (!parsed || !Array.isArray(parsed.ingredients) || !parsed.ingredients.length) return null;

  const ingredients = parsed.ingredients
    .map(ing => {
      const item = items.find(i => i.id === ing.ingredientId);
      if (!item) return null; // drop any id Claude got wrong rather than fail the whole meal
      // Keep qty/qtyAr as the two separate single-language strings the price
      // catalog already provides — collapsing to one Arabic-preferring field
      // (the previous `qty: item.qtyAr || item.qty`) meant the English UI
      // showed Arabic text, and mixed-script text inside an LTR Text node
      // rendered visibly reordered/garbled on the client.
      return { item: item.name, itemEn: item.nameEn, qty: item.qty, qtyAr: item.qtyAr, grams: Number(ing.grams) || 100 };
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

// `freshness` is additive - existing consumers (dashboard.html's price
// table, the mobile app's cheapest-store math) only ever read the flat
// {storeName: number} shape on each item and never look at this field, so
// adding it here can't break anything already reading this endpoint. It's
// keyed the same way price_scraper_freshness.json already is:
// {[itemId]: {[storeName]: {lastCrawl, lastSuccess, status, confidence}}}.
app.get(`${BASE}/api/food-prices`, auth, (req,res)=>res.json({ ...load('food_prices.json'), freshness: load('price_scraper_freshness.json') || {} }));
app.get(`${BASE}/api/labs`, auth, (req,res) => {
  const diet = req.query.diet || 'atkins';
  const data = load('labs.json') || { lastUpdated:null, tests:[] };
  const tests = (data.tests||[])
    .filter(t => (t.diets||[]).includes('all') || (t.diets||[]).includes(diet))
    .map(t => ({ ...t, why: resolveLabWhy(t.why, diet), whyAr: resolveLabWhy(t.whyAr, diet) }));
  res.json({ lastUpdated: data.lastUpdated, tests });
});

// Read-only: the lab_tests/lab_reference_ranges tables (db.js), the same
// single source of truth deriveLabFlags() now reads from — a distinct
// concept from /api/labs above (which tier of tests to consider getting),
// this is normal-value reference data for interpreting a result. Standard
// field names throughout (test_id/test_name/unit/population/verified/
// source_url/notes/legacy) per the founder's naming convention; a fresh
// endpoint, not a rename of any existing one, so nothing else changes
// shape. `legacy` here just means "unverified" (no separate resolution
// chain to run for a flat listing) — the richer legacy/population_used
// semantics live in resolveReferenceRange(), used by deriveLabFlagsMeta.
app.get(`${BASE}/api/lab-reference`, auth, (req,res) => {
  try {
    const tests = store.listLabTests().map(t => ({
      test_id: t.test_id,
      test_name: t.name,
      test_name_ar: t.name_ar,
      category: t.category,
      specimen: t.specimen,
      unit: t.units,
      si_unit: t.si_units,
      fasting_required: !!t.fasting_required,
      loinc_code: t.loinc_code,
      // false for creatinine only — real reference data exists for display,
      // but resolveReferenceRange() will never resolve it for automatic
      // flagging (kidney-function values are deliberately excluded from
      // rule-based suggestions). Exposed so a client can show "for your
      // reference" rather than implying this test drives a recommendation.
      flaggable: !!t.flaggable,
      reference_ranges: store.getReferenceRanges(t.test_id).map(r => ({
        population: r.population,
        range_low: r.range_low,
        range_high: r.range_high,
        critical_low: r.critical_low,
        critical_high: r.critical_high,
        unit: r.unit,
        verified: !!r.verified,
        legacy: !r.verified,
        source_name: r.source_name,
        source_url: r.source_url,
        version_date: r.version_date,
        notes: r.notes,
      })),
    }));
    res.json({ tests });
  } catch (e) {
    console.error('Lab reference data error:', e.message);
    res.status(500).json({ error: 'Failed to load lab reference data' });
  }
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
  const {userId,paymentRef,plan}=req.body;
  if(!PLAN_PRICES[plan])return res.status(400).json({error:'Invalid plan'});
  if(!userId)return res.status(400).json({error:'userId required'});
  // Real bug fixed here: this previously read req.user.id (the calling
  // admin's own id from their JWT) instead of a target user, so every call
  // granted the admin themselves a paid plan rather than the intended
  // customer. Confirmed zero real callers anywhere in admin.html or
  // elsewhere in the codebase before this fix, so there was no existing
  // integration to preserve. Also switched to the transactional update()
  // helper, matching the adjacent webhook handler below (server.js:2229)
  // which grants the exact same fields and was already correctly atomic —
  // this route was the one inconsistent sibling.
  const target = update('users.json', users => {
    const u = (users||[]).find(u=>u.id===userId);
    if (u) { u.paid=true; u.plan=plan; }
    return users;
  }, []).find(u=>u.id===userId);
  if(!target)return res.status(404).json({error:'User not found'});
  update('subscriptions.json', subs => {
    (subs||[]).push({userId,plan,startDate:new Date().toISOString().split('T')[0],endDate:new Date(Date.now()+30*86400000).toISOString().split('T')[0],amount:PLAN_PRICES[plan],status:'active',paymentRef:paymentRef||'MANUAL_'+Date.now(),autoRenewing:false});
    return subs;
  }, []);
  secLog('PAYMENT_CONFIRMED',getIP(req),{userId,grantedBy:req.user.id,plan});
  res.json({ok:true});
});

// Server-to-server webhook — the authoritative source of truth for payment.
// Kashier's own signal for a refund/void event, as distinct from a fresh
// SUCCESS/FAIL on a new charge. UNCONFIRMED against a real payload as of
// this writing — Kashier's own docs site blocks automated fetches (403)
// and this session's web-search budget was exhausted trying to verify it
// the honest way. This checks every plausible field Kashier's dashboard
// event names ("Transaction - Refund", "Transaction - Void") suggest,
// case-insensitively, rather than betting on one guessed exact string —
// but it has NOT been exercised against a real webhook delivery. Confirm
// via the dashboard's own "Test Webhook" button (Developers > Integrations
// > Webhooks) and check `docker logs diethub` for the real payload before
// trusting this in production; tighten/correct this condition once confirmed.
function isKashierReversal(data) {
  const status = String(data.status || '').toUpperCase();
  const eventType = String(data.event || data.type || '').toUpperCase();
  return /REFUND|VOID|REVERS|CHARGEBACK/.test(status) || /REFUND|VOID|REVERS|CHARGEBACK/.test(eventType);
}

// Explicit, deliberate revocation — distinct from refreshUserPaidStatus()
// (line ~179), which by design never auto-downgrades (that function backs
// passive expiry across all sources, a separate, already-considered
// product decision, untouched here). A refund/chargeback is an active
// reversal, not passive expiry, and only ever fires for the specific user
// on the specific order being reversed — so it downgrades immediately,
// but only if the user has no OTHER active coverage (e.g. a still-valid
// Apple IAP subscription shouldn't be revoked because an unrelated past
// Kashier order got refunded).
function revokeAccessIfNoOtherCoverage(userId) {
  if (!userId) return;
  update('users.json', users => {
    const u = users.find(x => x.id === userId);
    if (u && !hasActiveCoverage(userId)) { u.paid = false; }
    return users;
  }, []);
}

app.post(`${BASE}/api/payment/webhook`,(req,res)=>{
  if(!kashierConfigured())return res.status(503).json({error:'Payments not configured'});
  const data = req.body?.data || req.body || {};
  const signature = data.signature || req.body?.signature;
  if(!kashierVerify(data, data.signatureKeys || req.body?.signatureKeys, signature)){
    secLog('PAYMENT_WEBHOOK_BADSIG', getIP(req), { orderId:data.merchantOrderId });
    return res.status(400).json({error:'invalid signature'});
  }
  const orderId = data.merchantOrderId;
  const orders = load('payment_orders.json') || {};
  const order = orders[orderId];
  if(!order){ secLog('PAYMENT_WEBHOOK_NOORDER', getIP(req), { orderId }); return res.json({ok:true}); }
  // Stable across this order's whole lifecycle (initial charge, later
  // refund/void) — unlike data.transactionId, which Kashier may assign a
  // *different* id to for the reversal event itself, this is always
  // reconstructable from the one thing every event on this order shares:
  // our own merchantOrderId.
  const externalRef = 'KASHIER_' + orderId;

  // Reversal (refund/void/chargeback) on an order we'd already granted —
  // the fix this whole change exists for. See isKashierReversal()'s own
  // comment on why this branch is unverified against a real payload.
  if (order.status === 'paid' && isKashierReversal(data)) {
    reconcileIapSubscription({
      platform: 'kashier', userId: order.userId, productId: order.plan, plan: order.plan,
      expiresDate: null, status: 'revoked', externalRef, environment: KASHIER.mode, autoRenewing: false,
    });
    revokeAccessIfNoOtherCoverage(order.userId);
    update('payment_orders.json', o => { if (o[orderId]) o[orderId].status = 'refunded'; return o; }, {});
    secLog('PAYMENT_REVOKED', getIP(req), { orderId, userId: order.userId, plan: order.plan });
    return res.json({ ok:true });
  }
  if(order.status==='paid') return res.json({ok:true}); // idempotent — already granted, not a reversal

  const success = String(data.status||'').toUpperCase()==='SUCCESS';
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
  if (!uid && order.email) {
    const users = load('users.json') || [];
    uid = users.find(x => x.email === order.email)?.id;
  }
  // Same reconcileIapSubscription() choke point Apple/Google IAP already use
  // (source:'kashier' fills the real, previously-documented gap of Kashier
  // rows having no `source` field at all) — one shared function for every
  // payment source, not three separate implementations.
  reconcileIapSubscription({
    platform: 'kashier', userId: uid, productId: order.plan, plan: order.plan,
    expiresDate: new Date(Date.now() + 30*86400000).toISOString(), status: 'active',
    externalRef, environment: KASHIER.mode, autoRenewing: false,
  });
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

// ─── SUBSCRIPTION OVERVIEW (read-only, Subscription & Billing domain, 2026-08-14) ──
// The smallest possible read addition over data that already exists and is
// already correctly written by the three payment paths above — no new
// business logic, no new write path. Maps each real subscriptions.json row
// (already real per-provider data: source/status/endDate/autoRenewing) into
// one honest, provider-transparent shape, and reuses hasActiveCoverage()'s
// own cross-provider selection rule to pick which row is "current" rather
// than inventing a second rule that could disagree with it.
function providerFromSource(source) {
  if (source === 'ios') return 'apple';
  if (source === 'android') return 'google';
  return 'kashier'; // Kashier rows have no `source` field — the only real gap value
}
function toSubscriptionView(row, now) {
  const provider = providerFromSource(row.source);
  const remainingDays = row.endDate ? Math.max(0, Math.ceil((new Date(row.endDate).getTime() - now) / 86400000)) : null;
  return {
    plan: row.plan,
    provider,
    // Real, verified architecture asymmetry (readiness review §"Provider
    // Transparency"): Apple/Google subscriptions are platform-managed
    // auto-renewals; Kashier is a fixed-duration window with no re-charge
    // mechanism anywhere in this codebase. Never implied as equivalent.
    renewalType: provider === 'kashier' ? 'fixed_duration' : 'auto',
    autoRenewing: row.autoRenewing ?? null, // null = unknown (older row predating this field, or a decode miss) — never guessed
    status: row.status,
    startDate: row.startDate,
    endDate: row.endDate || null,
    remainingDays,
    amount: row.amount ?? null,
    environment: row.environment || null, // sandbox/production — surfaced for staff/debug use, not hidden
  };
}
app.get(`${BASE}/api/subscription`, auth, (req, res) => {
  const allSubs = (load('subscriptions.json') || []).filter(s => s.userId === req.user.id);
  const now = Date.now();
  const coveringNow = allSubs.filter(s => ['active', 'grace_period', 'on_hold'].includes(s.status) && (!s.endDate || new Date(s.endDate).getTime() > now));
  const currentRow = coveringNow.sort((a, b) => new Date(b.endDate || 0) - new Date(a.endDate || 0))[0] || null;
  // Every new account gets one real, automatic status:'trial' row at
  // registration (see /register and the Google/Facebook sign-in paths) — a
  // genuine record, but not a billing event, so it's excluded from billing
  // history here rather than presented as something the user was charged
  // for. Trial state itself is already fully represented via req.trial.
  const history = allSubs
    .filter(s => s.status !== 'trial')
    .sort((a, b) => new Date(b.startDate || 0) - new Date(a.startDate || 0))
    .map(row => ({ ...toSubscriptionView(row, now), isCurrent: row === currentRow }));
  res.json({
    active: hasActiveCoverage(req.user.id),
    current: currentRow ? toSubscriptionView(currentRow, now) : null,
    history,
    trial: req.trial,
  });
});

// ─── PAYMENT (Native IAP — Apple/Google mobile subscriptions) ──────────────
// Mobile-only path (see iap.js/SubscribeScreen.js in diethub-mobile). The
// client is already authenticated, but its claimed productId/transactionId
// is NOT trusted — the plan/tier actually granted always comes from Apple's
// or Google's own verified response below, never from what the client sent,
// so a tampered client can't claim a cheaper purchase unlocked a pricier tier.
function appleStatusToInternal(status) {
  // Apple Status enum: ACTIVE=1, EXPIRED=2, BILLING_RETRY=3, BILLING_GRACE_PERIOD=4, REVOKED=5
  if (status === AppleSubStatus.ACTIVE) return 'active';
  if (status === AppleSubStatus.BILLING_GRACE_PERIOD) return 'grace_period';
  if (status === AppleSubStatus.BILLING_RETRY) return 'on_hold';
  if (status === AppleSubStatus.REVOKED) return 'revoked';
  return 'expired';
}
function googleStateToInternal(state) {
  switch (state) {
    case 'SUBSCRIPTION_STATE_ACTIVE': return 'active';
    case 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD': return 'grace_period';
    case 'SUBSCRIPTION_STATE_ON_HOLD': return 'on_hold';
    case 'SUBSCRIPTION_STATE_CANCELED': return 'active'; // canceled ≠ expired — stays covered until lineItem.expiryTime
    default: return 'expired'; // EXPIRED, PAUSED, PENDING, etc.
  }
}

async function verifyAppleTransaction(transactionId) {
  const client = getAppleClient(), verifier = getAppleVerifier();
  const statusResponse = await client.getAllSubscriptionStatuses(transactionId);
  for (const group of statusResponse.data || []) {
    for (const item of group.lastTransactions || []) {
      const decoded = await verifier.verifyAndDecodeTransaction(item.signedTransactionInfo);
      if (decoded.transactionId === transactionId || decoded.originalTransactionId === transactionId) {
        // Real, previously-discarded signal (Subscription & Billing domain,
        // 2026-08-14): Apple's own subscription-status response carries a
        // SEPARATE signed renewal-info payload alongside the transaction
        // info, and it's the only place autoRenewStatus actually lives — the
        // transaction payload itself has no such field. Decoded via the same
        // already-integrated verifier, not a new capability, just reading a
        // field this app already receives and previously ignored.
        let autoRenewing = null;
        if (item.signedRenewalInfo) {
          try {
            const renewal = await verifier.verifyAndDecodeRenewalInfo(item.signedRenewalInfo);
            if (renewal.autoRenewStatus != null) autoRenewing = renewal.autoRenewStatus === 1;
          } catch { /* renewal info is a nice-to-have; a decode failure here shouldn't fail the whole verification */ }
        }
        return {
          productId: decoded.productId,
          expiresDate: decoded.expiresDate,
          externalRef: decoded.originalTransactionId,
          status: appleStatusToInternal(item.status),
          autoRenewing,
        };
      }
    }
  }
  return null;
}

async function verifyGooglePurchase(purchaseToken) {
  const client = await getAndroidPublisherClient();
  const { data } = await client.purchases.subscriptionsv2.get({ packageName: GOOGLE_PLAY_IAP.packageName, token: purchaseToken });
  const item = (data.lineItems || [])[0];
  if (!item) return null;
  // Real, previously-discarded signal (Subscription & Billing domain,
  // 2026-08-14): Google's own lineItem already carries autoRenewingPlan.
  // autoRenewEnabled — this app fetched it from Google on every verify call
  // and simply never read the field.
  return {
    productId: item.productId,
    expiresDate: item.expiryTime,
    externalRef: purchaseToken,
    status: googleStateToInternal(data.subscriptionState),
    autoRenewing: item.autoRenewingPlan?.autoRenewEnabled ?? null,
  };
}

app.post(`${BASE}/api/payment/iap/verify`,auth,async(req,res)=>{
  const { platform, transactionId, purchaseToken } = req.body || {};
  try {
    let result = null;
    if (platform === 'ios') {
      if (!appleIapConfigured()) return res.status(503).json({ error:'iOS payments not configured' });
      if (!transactionId) return res.status(400).json({ error:'Missing transactionId' });
      result = await verifyAppleTransaction(transactionId);
    } else if (platform === 'android') {
      if (!googlePlayConfigured()) return res.status(503).json({ error:'Android payments not configured' });
      if (!purchaseToken) return res.status(400).json({ error:'Missing purchaseToken' });
      result = await verifyGooglePurchase(purchaseToken);
    } else {
      return res.status(400).json({ error:'Invalid platform' });
    }
    if (!result) { secLog('IAP_VERIFY_NOMATCH', getIP(req), { userId:req.user.id, platform }); return res.status(400).json({ error:'Purchase not found' }); }
    const plan = tierFromIapProductId(result.productId);
    if (!plan) { secLog('IAP_VERIFY_UNKNOWNPRODUCT', getIP(req), { userId:req.user.id, productId:result.productId }); return res.status(400).json({ error:'Unknown product' }); }
    reconcileIapSubscription({
      platform, userId: req.user.id, productId: result.productId, plan,
      expiresDate: result.expiresDate, status: result.status,
      externalRef: result.externalRef, environment: APPLE_IAP.environment === AppleEnv.PRODUCTION ? 'production' : 'sandbox',
      autoRenewing: result.autoRenewing,
    });
    if (result.status === 'active' || result.status === 'grace_period' || result.status === 'on_hold') {
      track('subscription_paid', { userId:req.user.id, props:{ plan, platform } });
    }
    secLog('IAP_VERIFIED', getIP(req), { userId:req.user.id, platform, plan, status:result.status });
    res.json({ ok:true, plan, paid: hasActiveCoverage(req.user.id) });
  } catch (e) {
    secLog('IAP_VERIFY_ERROR', getIP(req), { userId:req.user?.id, platform, error:e.message });
    res.status(502).json({ error:'Could not verify purchase with the store, try again' });
  }
});

// Server-to-server: App Store Server Notifications V2 (renewals/cancellations/
// refunds after the initial purchase). Registered as the Production/Sandbox
// URL in App Store Connect → App Information → App Store Server Notifications.
// Per Apple's own guidance, the notification's own fields are a nudge to
// re-check, not the source of truth — this re-fetches authoritative state via
// the same verified subscription-status call the initial verify uses.
app.post(`${BASE}/api/payment/apple/notify`,async(req,res)=>{
  if (!appleIapConfigured()) return res.status(503).json({});
  try {
    const verifier = getAppleVerifier();
    const decoded = await verifier.verifyAndDecodeNotification(req.body?.signedPayload);
    const signedTransactionInfo = decoded.data?.signedTransactionInfo;
    if (!signedTransactionInfo) return res.json({}); // e.g. TEST notification, nothing to reconcile
    const tx = await verifier.verifyAndDecodeTransaction(signedTransactionInfo);
    const plan = tierFromIapProductId(tx.productId);
    // Resolve which user this originalTransactionId belongs to from our own
    // records — Apple's notification doesn't carry our internal userId.
    const subs = load('subscriptions.json') || [];
    const existing = subs.find(s => s.source === 'ios' && s.externalRef === tx.originalTransactionId);
    if (!plan || !existing) { secLog('APPLE_NOTIFY_NOMATCH', getIP(req), { notificationType:decoded.notificationType, originalTransactionId:tx.originalTransactionId }); return res.json({}); }
    const isRevoked = decoded.notificationType === 'REFUND' || decoded.notificationType === 'REVOKE';
    // Notification payloads for renewal-relevant events carry their own
    // signedRenewalInfo alongside signedTransactionInfo — same real signal
    // verifyAppleTransaction reads on the initial-verify path, just decoded
    // here from the notification's own data instead of a fresh status call.
    let autoRenewing = null;
    if (decoded.data?.signedRenewalInfo) {
      try {
        const renewal = await verifier.verifyAndDecodeRenewalInfo(decoded.data.signedRenewalInfo);
        if (renewal.autoRenewStatus != null) autoRenewing = renewal.autoRenewStatus === 1;
      } catch { /* best-effort */ }
    }
    reconcileIapSubscription({
      platform:'ios', userId: existing.userId, productId: tx.productId, plan,
      expiresDate: tx.expiresDate, status: isRevoked ? 'revoked' : appleStatusToInternal(AppleSubStatus.ACTIVE),
      externalRef: tx.originalTransactionId, environment: existing.environment,
      autoRenewing,
    });
    secLog('APPLE_NOTIFY', getIP(req), { notificationType:decoded.notificationType, userId:existing.userId, plan });
    res.json({});
  } catch (e) {
    secLog('APPLE_NOTIFY_ERROR', getIP(req), { error:e.message });
    res.status(400).json({}); // bad signature/payload — Apple retries on non-2xx, which is what we want for transient failures, but a verification failure should not be retried into a loop; 400 is the documented safe response either way
  }
});

// Server-to-server: Google Play Real-time Developer Notifications, delivered
// as a Cloud Pub/Sub push (base64 JSON body). Same "don't trust the payload,
// re-fetch" posture as the Apple handler above.
app.post(`${BASE}/api/payment/google/notify`,async(req,res)=>{
  if (!googlePlayConfigured()) return res.status(503).json({});
  try {
    const messageData = req.body?.message?.data;
    if (!messageData) return res.json({});
    const payload = JSON.parse(Buffer.from(messageData, 'base64').toString('utf8'));
    const purchaseToken = payload?.subscriptionNotification?.purchaseToken;
    if (!purchaseToken) return res.json({}); // e.g. a test/one-time-product notification, nothing to reconcile
    const result = await verifyGooglePurchase(purchaseToken);
    if (!result) return res.json({});
    const plan = tierFromIapProductId(result.productId);
    const subs = load('subscriptions.json') || [];
    const existing = subs.find(s => s.source === 'android' && s.externalRef === purchaseToken);
    if (!plan || !existing) { secLog('GOOGLE_NOTIFY_NOMATCH', getIP(req), { purchaseToken }); return res.json({}); }
    reconcileIapSubscription({
      platform:'android', userId: existing.userId, productId: result.productId, plan,
      expiresDate: result.expiresDate, status: result.status,
      externalRef: purchaseToken, environment: existing.environment,
      autoRenewing: result.autoRenewing,
    });
    secLog('GOOGLE_NOTIFY', getIP(req), { userId:existing.userId, plan, status:result.status });
    res.json({});
  } catch (e) {
    secLog('GOOGLE_NOTIFY_ERROR', getIP(req), { error:e.message });
    res.status(400).json({});
  }
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
  // Hardening pass (independent audit, Part 3): role/plan previously took
  // any string with no enum check — real fields, both admin-gated already,
  // but a real data-integrity gap (e.g. a typo'd role value would silently
  // fail every later `role === 'admin'` check rather than erroring here).
  if (role !== undefined && !['user','admin'].includes(role)) return res.json({ok:false,error:'Invalid role'});
  const pp=PLAN_PRICES; // was a re-declared literal copy — see server.js:71 for the one real source of truth
  if (plan !== undefined && !pp[plan]) return res.json({ok:false,error:'Invalid plan'});
  const users=load('users.json')||[];
  if(users.find(u=>u.username===username))return res.json({ok:false,error:'User exists'});
  const nu={id:'u'+Date.now()+randToken(4),username,password:hashPwd(password),email:email||'',role:role||'user',plan:plan||'tier1',created:new Date().toISOString().split('T')[0],active:true,emailVerified:true,trialStart:new Date().toISOString().split('T')[0],paid:!!pp[plan],lang:'ar',loginAttempts:0,profile:{}};
  users.push(nu);save('users.json',users);
  if(pp[plan]){const subs=load('subscriptions.json')||[];subs.push({userId:nu.id,plan,startDate:nu.created,endDate:new Date(Date.now()+30*86400000).toISOString().split('T')[0],amount:pp[plan],status:'active',paymentRef:'ADMIN_'+Date.now()});save('subscriptions.json',subs);}
  res.json({ok:true});
});
app.delete(`${BASE}/api/admin/users/:id`,auth,adminOnly,(req,res)=>{save('users.json',(load('users.json')||[]).filter(u=>u.id!==req.params.id));res.json({ok:true});});
app.post(`${BASE}/api/admin/users/:id/toggle`,auth,adminOnly,(req,res)=>{const users=load('users.json')||[];const u=users.find(u=>u.id===req.params.id);if(!u)return res.json({ok:false});u.active=!u.active;save('users.json',users);res.json({ok:true,active:u.active});});
app.post(`${BASE}/api/admin/users/:id/markpaid`,auth,adminOnly,(req,res)=>{const users=load('users.json')||[];const u=users.find(u=>u.id===req.params.id);if(!u)return res.json({ok:false});u.paid=true;u.emailVerified=true;save('users.json',users);res.json({ok:true});});
app.get(`${BASE}/api/admin/stats`,auth,adminOnly,(req,res)=>{
  const users=load('users.json')||[];const subs=load('subscriptions.json')||[];const ratings=load('ratings.json')||[];
  const pp=PLAN_PRICES; // was a re-declared literal copy — see server.js:71 for the one real source of truth
  const mrr=subs.filter(s=>s.status==='active').reduce((s,sub)=>s+(pp[sub.plan]||0),0);
  const apr=ratings.filter(r=>r.approved);
  res.json({totalUsers:users.length,activeUsers:users.filter(u=>u.active).length,verifiedUsers:users.filter(u=>u.emailVerified).length,paidUsers:users.filter(u=>u.paid).length,trialUsers:users.filter(u=>!u.paid&&u.active).length,activeSubs:subs.filter(s=>s.status==='active').length,mrr,avgRating:apr.length?(apr.reduce((s,r)=>s+r.rating,0)/apr.length).toFixed(1):0,totalRatings:ratings.length,pendingRatings:ratings.filter(r=>!r.approved).length,planBreakdown:Object.keys(pp).map(p=>({plan:p,count:subs.filter(s=>s.plan===p&&s.status==='active').length}))});
});
app.get(`${BASE}/api/admin/security-log`,auth,adminOnly,(req,res)=>res.json((load('security_log.json')||[]).slice(0,100)));
app.get(`${BASE}/api/admin/ratings`,auth,adminOnly,(req,res)=>res.json(load('ratings.json')||[]));
app.post(`${BASE}/api/admin/ratings/:id/approve`,auth,adminOnly,(req,res)=>{const ratings=load('ratings.json')||[];const r=ratings.find(r=>r.id===req.params.id);if(!r)return res.json({ok:false});r.approved=true;save('ratings.json',ratings);res.json({ok:true});});
// Hardening pass (independent audit, Part 3): previously assigned
// req.body.items directly with zero shape/type checking, even though
// admin-only. Real risk wasn't authorization (the route is correctly
// gated) but data integrity: a malformed payload here silently corrupts
// food_prices.json for every user viewing the price-comparison table.
// Was a second, identically-valued STORE_KEYS_ADMIN constant — reuses the
// one real STORE_KEYS declared at server.js:1923 instead (still matches
// dashboard.html's own storeNames array, unchanged).
function validateFoodPriceItem(item) {
  if (!item || typeof item !== 'object') return false;
  if (typeof item.id !== 'string' || !item.id) return false;
  if (typeof item.name !== 'string' || typeof item.nameEn !== 'string') return false;
  if (typeof item.unit !== 'string' || typeof item.category !== 'string') return false;
  for (const store of STORE_KEYS) {
    if (item[store] !== undefined && (typeof item[store] !== 'number' || item[store] < 0 || item[store] > 100000)) return false;
  }
  return true;
}
app.post(`${BASE}/api/admin/food-prices`,auth,adminOnly,(req,res)=>{
  if (!Array.isArray(req.body.items) || !req.body.items.every(validateFoodPriceItem)) {
    return res.status(400).json({ ok:false, error:'Invalid items — each requires string id/name/nameEn/unit/category and non-negative numeric store prices' });
  }
  const p=load('food_prices.json');p.items=req.body.items;p.lastUpdated=new Date().toISOString().split('T')[0];save('food_prices.json',p);res.json({ok:true,lastUpdated:p.lastUpdated});
});

// price_scraper.js (scripts/) queues any match it scores 75-89% confidence
// on, rather than either silently rejecting it or auto-publishing an
// uncertain price. These three endpoints are the human side of that: list
// what's pending, and approve/reject each one. Approving both applies the
// price AND pins the exact product (same SKU/URL the scraper found) - so it
// becomes next week's deterministic re-fetch instead of a repeat guess,
// which is the whole point of a review queue: each approval should make the
// system need fewer of them over time, not the same number forever.
app.get(`${BASE}/api/admin/price-review-queue`,auth,adminOnly,(req,res)=>{
  const queue = load('price_scraper_review_queue.json') || {};
  res.json({ items: Object.entries(queue).map(([key, v]) => ({ key, ...v })) });
});
// Approve/reject happen here (server.js, the always-on process) but
// price_scraper.js (a separate weekly cron script) is what later reads back
// pin/coverage stats - both need to land in the same event log for the
// stability-phase metrics ("80% of approvals are fish") to mean anything.
// Purely observational: doesn't change what approve/reject actually do.
const REVIEW_EVENTS_MAX = 500;
function logHumanReviewEvent(action, entry, key) {
  update('human_review_events.json', events => {
    events.push({ ts: new Date().toISOString(), action, key, itemId: entry.itemId, storeName: entry.storeName, price: entry.price, confidence: entry.confidence });
    while (events.length > REVIEW_EVENTS_MAX) events.shift();
    return events;
  }, []);
}
app.post(`${BASE}/api/admin/price-review-queue/:key/approve`,auth,adminOnly,(req,res)=>{
  const key = req.params.key;
  const queue = load('price_scraper_review_queue.json') || {};
  const entry = queue[key];
  if (!entry) return res.status(404).json({error:'Not found in queue'});
  update('food_prices.json', p => {
    const item = (p.items||[]).find(i => i.id === entry.itemId);
    if (item) item[entry.storeName] = entry.price;
    p.lastUpdated = new Date().toISOString().split('T')[0];
    return p;
  }, {items:[]});
  if (entry.pin && entry.size) {
    update('price_scraper_pins.json', pins => {
      pins[key] = { pin: entry.pin, size: entry.size, name: entry.name, confidence: entry.confidence, pinnedAt: new Date().toISOString(), approvedBy: req.user.id };
      return pins;
    }, {});
  }
  logHumanReviewEvent('approved', entry, key);
  delete queue[key];
  save('price_scraper_review_queue.json', queue);
  res.json({ok:true});
});
app.post(`${BASE}/api/admin/price-review-queue/:key/reject`,auth,adminOnly,(req,res)=>{
  const key = req.params.key;
  const queue = load('price_scraper_review_queue.json') || {};
  const entry = queue[key];
  if (!entry) return res.status(404).json({error:'Not found in queue'});
  logHumanReviewEvent('rejected', entry, key);
  delete queue[key];
  save('price_scraper_review_queue.json', queue);
  res.json({ok:true});
});
// Phase 1+2 observability (2026-08-12): store health, per-item breakdown,
// confidence-reason categories, run-quality trend, freshness snapshot - all
// read-only summaries of what price_scraper.js already recorded. Computed
// here (not by requiring scripts/price_scraper.js directly) because that
// script lives in a directory this container doesn't have mounted - the
// live container only bind-mounts individual files, and scripts/price_scraper.js
// runs as its own separate weekly process, not inside this container. Mirrors
// computeStoreHealth()'s logic there field-for-field so the numbers agree;
// if that function's logic changes, update this copy too.
// Deliberately does not change any matching/scraping behavior - see
// feedback_price_scraper_stability_phase memory for why that distinction
// matters right now.
app.get(`${BASE}/api/admin/price-scraper/health`,auth,adminOnly,(req,res)=>{
  const history = load('price_scraper_history.json') || [];
  if (!history.length) return res.json({ available: false });

  const storeStats = {};
  for (const s of STORE_KEYS) storeStats[s] = { total: 0 };
  const itemStats = {};
  let confidenceScores = [];
  const pinTotals = { created: 0, reused: 0, broken: 0, repaired: 0 };
  let goldenPassed = 0, goldenFailed = 0;
  const reasonCategoryTotals = {};
  const runTrend = [];

  for (const run of history) {
    for (const [itemId, stats] of Object.entries(run.items || {})) {
      itemStats[itemId] = itemStats[itemId] || { total: 0 };
      if (stats.category) itemStats[itemId].category = stats.category;
      for (const [storeName, r] of Object.entries(stats)) {
        if (storeName === 'category' || !storeStats[storeName]) continue;
        storeStats[storeName].total++;
        storeStats[storeName][r.status] = (storeStats[storeName][r.status] || 0) + 1;
        itemStats[itemId].total++;
        itemStats[itemId][r.status] = (itemStats[itemId][r.status] || 0) + 1;
        for (const reason of (r.reasons || [])) {
          reasonCategoryTotals[reason.category] = reasonCategoryTotals[reason.category] || { PASS: 0, WARNING: 0 };
          reasonCategoryTotals[reason.category][reason.severity] = (reasonCategoryTotals[reason.category][reason.severity] || 0) + 1;
        }
      }
    }
    confidenceScores = confidenceScores.concat(run.confidenceScores || []);
    for (const k of Object.keys(pinTotals)) pinTotals[k] += (run.pinEvents?.[k] || []).length;
    if (run.golden) { if (run.golden.passed) goldenPassed++; else goldenFailed++; }
    if (run.summary) runTrend.push({ ts: run.ts, coveragePct: run.summary.coveragePct, avgConfidence: run.summary.avgConfidence, qualityScore: run.summary.qualityScore, qualityGrade: run.summary.qualityGrade });
  }

  const avgConfidence = confidenceScores.length
    ? Math.round((confidenceScores.reduce((a, b) => a + b, 0) / confidenceScores.length) * 10) / 10
    : null;

  const freshness = load('price_scraper_freshness.json') || {};
  const now = Date.now();
  let fresh = 0, recent = 0, aging = 0, expired = 0, neverUpdated = 0, totalTracked = 0;
  for (const stores of Object.values(freshness)) {
    for (const f of Object.values(stores)) {
      totalTracked++;
      if (!f.lastSuccess) { neverUpdated++; continue; }
      const ageDays = (now - new Date(f.lastSuccess).getTime()) / 86400000;
      if (ageDays < 1) fresh++;
      else if (ageDays <= 7) recent++;
      else if (ageDays <= 30) aging++;
      else expired++;
    }
  }

  res.json({
    available: true, runsAnalyzed: history.length,
    storeStats, itemStats, avgConfidence, pinTotals,
    golden: { passed: goldenPassed, failed: goldenFailed },
    reasonCategoryTotals, runTrend,
    freshness: { fresh, recent, aging, expired, neverUpdated, totalTracked },
  });
});
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
    console.error('[admin/backup] error:', e.message);
    res.status(500).json({ error: 'Backup failed' });
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

// ─── HERO BANNERS ───────────────────────────────────────────────────────────
// One real content source consumed by both the website and the mobile app —
// "landing" placement is the public pre-signup pages (login/register),
// "app" placement is shown to already-registered users. Every banner here
// describes something actually shipped and live, not a roadmap promise —
// same "no fake claims" discipline as the rest of the app. Admin CRUD below
// means new banners (e.g. for a future paid ad campaign landing variant)
// don't need a code deploy — just an admin API call.
function defaultBanners() {
  // Two designed image sets sharing one feature list: "outside" (landing,
  // pre-signup) is a short general teaser; "inside" (app, post-signup) is a
  // more detailed benefits card. Same /assets/banners/*.png used on web and
  // mobile. Arabic-only artwork for now — English UI falls back to the old
  // text-only rendering (see renderHeroBanner/renderAppBanner).
  return [
    {
      id: 'hero_ai_briefing', placement: ['landing'], active: false, priority: 1, icon: '🌞',
      image: '/assets/banners/out_ai_briefing.png',
      image_en: '/assets/banners/out_ai_briefing_en.png',
      title_ar: 'ابدأ يومك بملخص صحي ذكي', title_en: 'Start your day with a smart health briefing',
      subtitle_ar: 'نظرة واحدة على سعراتك، بروتينك، مائك، ونشاطك — بدون تخمين', subtitle_en: 'One glance at your calories, protein, water, and activity — no guessing',
      cta_ar: 'جرّب الآن مجاناً', cta_en: 'Try it free', ctaAction: 'register',
    },
    {
      id: 'hero_wellness_score', placement: ['landing'], active: false, priority: 2, icon: '🎯',
      image: '/assets/banners/out_wellness_score.png',
      image_en: '/assets/banners/out_wellness_score_en.png',
      title_ar: 'مؤشر صحي واحد، من بياناتك الحقيقية', title_en: 'One wellness score, built from your real data',
      subtitle_ar: 'نوم، نشاط، تغذية، وترطيب — محسوبة برقم واضح كل يوم', subtitle_en: 'Sleep, activity, nutrition, and hydration — one clear number every day',
      cta_ar: 'اكتشف مؤشرك', cta_en: 'See your score', ctaAction: 'register',
    },
    {
      id: 'hero_wearables', placement: ['landing'], active: false, priority: 3, icon: '⌚',
      image: '/assets/banners/out_wearables.png',
      image_en: '/assets/banners/out_wearables_en.png',
      title_ar: 'اربط ساعتك الذكية', title_en: 'Connect your smartwatch',
      subtitle_ar: 'متوافق مع أشهر الساعات الذكية وأجهزة اللياقة — بياناتك الحقيقية تدخل توصياتك', subtitle_en: 'Apple Watch, Garmin, Fitbit, and 10 more — real data feeds your real recommendations',
      cta_ar: 'اربط جهازك', cta_en: 'Connect your device', ctaAction: 'dashboard',
    },
    {
      id: 'hero_savings', placement: ['landing'], active: false, priority: 4, icon: '💰',
      image: '/assets/banners/out_savings.png',
      image_en: '/assets/banners/out_savings_en.png',
      title_ar: 'وفّر فلوسك في التسوق', title_en: 'Save money on your groceries',
      subtitle_ar: 'مقارنة أسعار حقيقية بين 8 متاجر مصرية كل يوم', subtitle_en: 'Real price comparison across 8 Egyptian stores, every day',
      cta_ar: 'شوف التوفير', cta_en: 'See today\'s savings', ctaAction: 'register',
    },
    {
      id: 'hero_ai_coach', placement: ['landing'], active: false, priority: 5, icon: '🤖',
      image: '/assets/banners/out_ai_coach.png',
      image_en: '/assets/banners/out_ai_coach_en.png',
      title_ar: 'مساعدك الغذائي الذكي', title_en: 'Your AI nutrition coach',
      subtitle_ar: 'يعرف أهدافك الحقيقية ويبني لك خطط وجبات ونشاط عند الطلب', subtitle_en: 'Knows your real goals — builds you meal and activity plans on request',
      cta_ar: 'تحدث معه', cta_en: 'Start chatting', ctaAction: 'dashboard',
    },
    {
      id: 'app_ai_briefing', placement: ['app'], active: false, priority: 1, icon: '🌞',
      image: '/assets/banners/in_ai_briefing.png',
      image_en: '/assets/banners/in_ai_briefing_en.png',
      title_ar: 'ملخصك الصحي اليومي', title_en: 'Your daily health briefing',
      subtitle_ar: 'يتحدث تلقائياً كل صباح من بياناتك الفعلية — السعرات، البروتين، الماء، والنشاط في نظرة واحدة', subtitle_en: 'Auto-updates every morning from your real data — calories, protein, water, and activity in one glance',
      cta_ar: 'شوف ملخص اليوم', cta_en: 'See today\'s briefing', ctaAction: null,
    },
    {
      id: 'app_wellness_score', placement: ['app'], active: false, priority: 2, icon: '🎯',
      image: '/assets/banners/in_wellness_score.png',
      image_en: '/assets/banners/in_wellness_score_en.png',
      title_ar: 'مؤشرك الصحي المتكامل', title_en: 'Your all-in-one wellness score',
      subtitle_ar: 'يجمع النوم والنشاط والتغذية والترطيب في رقم واحد، يتحدث يومياً', subtitle_en: 'Sleep, activity, nutrition, and hydration combined into one number, updated daily',
      cta_ar: 'شوف مؤشرك', cta_en: 'See your score', ctaAction: null,
    },
    {
      id: 'app_wearables', placement: ['app'], active: false, priority: 3, icon: '⌚',
      image: '/assets/banners/in_wearables.png',
      image_en: '/assets/banners/in_wearables_en.png',
      title_ar: 'ساعتك الذكية، متصلة بالكامل', title_en: 'Your smartwatch, fully connected',
      subtitle_ar: 'يدعم أشهر الساعات الذكية وأجهزة اللياقة — مزامنة تلقائية للخطوات والنبض والنوم', subtitle_en: 'Supports the top smartwatches and fitness trackers — auto-sync for steps, heart rate, and sleep',
      cta_ar: 'اربط جهازك', cta_en: 'Connect your device', ctaAction: 'dashboard',
    },
    {
      id: 'app_savings', placement: ['app'], active: false, priority: 4, icon: '💰',
      image: '/assets/banners/in_savings.png',
      image_en: '/assets/banners/in_savings_en.png',
      title_ar: 'وفّر في كل خطة وجبات', title_en: 'Save on every meal plan',
      subtitle_ar: 'أسعار حقيقية من 8 متاجر مصرية، محدّثة يومياً — خطة وجباتك مبنية فعلياً على ميزانيتك', subtitle_en: 'Real prices from 8 Egyptian stores, updated daily — your meal plan is actually built around your budget',
      cta_ar: 'شوف الأسعار', cta_en: 'See prices', ctaAction: null,
    },
    {
      id: 'app_ai_coach', placement: ['app'], active: false, priority: 5, icon: '🤖',
      image: '/assets/banners/in_ai_coach.png',
      image_en: '/assets/banners/in_ai_coach_en.png',
      title_ar: 'مدربك الغذائي بالذكاء الاصطناعي', title_en: 'Your AI nutrition coach',
      subtitle_ar: 'يعرف هدفك ونظامك الغذائي فعلياً، ويبني خطة وجبات أو نشاط كاملة عند الطلب', subtitle_en: 'Actually knows your goal and diet type — builds a full meal or activity plan on request',
      cta_ar: 'تحدث معه', cta_en: 'Start chatting', ctaAction: null,
    },
  ];
}
app.get(`${BASE}/api/banners`, (req, res) => {
  const placement = req.query.placement;
  let banners = load('banners.json');
  if (!banners) { banners = defaultBanners(); save('banners.json', banners); }
  let result = banners.filter(b => b.active);
  if (placement) result = result.filter(b => b.placement.includes(placement));
  result.sort((a, b) => a.priority - b.priority);
  res.json(result);
});
app.get(`${BASE}/api/admin/banners`, auth, adminOnly, (req, res) => {
  let banners = load('banners.json');
  if (!banners) { banners = defaultBanners(); save('banners.json', banners); }
  res.json(banners);
});
app.post(`${BASE}/api/admin/banners`, auth, adminOnly, (req, res) => {
  const b = req.body;
  if (!b?.id || !b?.title_ar) return res.status(400).json({ error: 'id and title_ar required' });
  update('banners.json', all => {
    const list = all || defaultBanners();
    const idx = list.findIndex(x => x.id === b.id);
    const record = { placement: ['landing', 'app'], active: true, priority: 99, icon: '✨', ctaAction: null, ...b };
    if (idx >= 0) list[idx] = record; else list.push(record);
    return list;
  }, null);
  res.json({ ok: true });
});
app.post(`${BASE}/api/admin/banners/:id/toggle`, auth, adminOnly, (req, res) => {
  update('banners.json', all => {
    const list = all || defaultBanners();
    const b = list.find(x => x.id === req.params.id);
    if (b) b.active = !b.active;
    return list;
  }, null);
  res.json({ ok: true });
});
app.delete(`${BASE}/api/admin/banners/:id`, auth, adminOnly, (req, res) => {
  update('banners.json', all => (all || defaultBanners()).filter(x => x.id !== req.params.id), null);
  res.json({ ok: true });
});
// RC1 Web Pilot Promotion (2026-08-14) — see /login's comment above.
app.get(`${BASE}/forgot-password`, (req,res) => res.sendFile(path.join(__dirname,'public','forgot-password-pilot.html')));
app.get(`${BASE}/reset-password`, (req,res) => res.sendFile(path.join(__dirname,'public','reset-password-pilot.html')));
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
// ─── AI SUGGESTIONS (chat-generated plans) ─────────────────────────────────
// Real, bounded validation before ANYTHING the AI writes gets saved to the
// database — same non-negotiable principle already applied to supplement
// label text (never AI-authored, always deterministic): an AI reply must
// never silently become something that LOOKS like verified app data. Saved
// suggestions stay in their own store, always tagged source:'ai_suggestion',
// and the UI must show that label — this validator is the one gate that
// decides whether something is even eligible to be offered for saving.
function validatePlanJSON(type, obj) {
  if (!obj || typeof obj !== 'object' || typeof obj.title !== 'string' || !obj.title.trim()) return null;
  if (!Array.isArray(obj.days) || obj.days.length < 1 || obj.days.length > 7) return null;
  const days = [];
  for (const day of obj.days) {
    if (!day || typeof day.day !== 'string' || !day.day.trim()) return null;
    if (type === 'meals') {
      if (!Array.isArray(day.meals) || day.meals.length < 1 || day.meals.length > 6) return null;
      const meals = [];
      for (const m of day.meals) {
        if (!m || typeof m.type !== 'string' || typeof m.name !== 'string') return null;
        const cal = Number(m.cal), protein = Number(m.protein), carbs = Number(m.carbs), fat = Number(m.fat);
        if (![cal, protein, carbs, fat].every(Number.isFinite)) return null;
        if (cal < 0 || cal > 3000 || protein < 0 || protein > 500 || carbs < 0 || carbs > 500 || fat < 0 || fat > 500) return null;
        meals.push({ type: m.type.trim(), name: m.name.trim(), cal, protein, carbs, fat });
      }
      days.push({ day: day.day.trim(), meals });
    } else {
      if (typeof day.activity !== 'string' || !day.activity.trim()) return null;
      const estCalBurn = day.estCalBurn != null ? Number(day.estCalBurn) : null;
      if (estCalBurn != null && (!Number.isFinite(estCalBurn) || estCalBurn < 0 || estCalBurn > 2000)) return null;
      days.push({ day: day.day.trim(), activity: day.activity.trim(), estCalBurn });
    }
  }
  return { title: obj.title.trim(), days };
}

app.post(`${BASE}/api/chatbot`, auth, async (req, res) => {
  const u = req.userObj;
  // Language now resolves per-request instead of being permanently baked
  // into one hardcoded Arabic prompt — see ai_language.js for the fallback
  // chain (stored user preference -> client-sent app language -> English).
  const lang = aiLanguage.resolveLanguage({ userLang: u.lang, appLang: req.body.lang });
  const S = aiLanguage.strings(lang);
  if (!BETA_MODE && !hasActiveCoverage(u.id) && u.role !== 'admin') {
    return res.status(403).json({ error: S.paidGate });
  }
  // The raw client-supplied messages array was previously forwarded
  // verbatim into ai.js's chat() call, which itself splices it directly
  // after the real system prompt (ai.js:93,108,113,132) with no role check
  // — a client could send {role:'system', content:'...'} inside its own
  // "conversation history" and have it land as a second, later system-role
  // turn in the real provider request, which several providers treat as
  // overriding/supplementing earlier instructions. Filtering to only the
  // two roles a real conversation ever legitimately contains closes that
  // without touching ai.js itself (every other caller of chat() sends
  // already-trusted, server-constructed messages, so the fix belongs at
  // this one client-facing entry point, not in the shared module).
  const { generateQuestions, generatePlan } = req.body;
  const messages = Array.isArray(req.body.messages)
    ? req.body.messages
        .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
        .slice(-30) // generous real conversation length; also bounds prompt size
    : [];
  // Coach now reads the full unified health profile (labs + wearables + targets
  // + risk flags), not just the thin demographic fields — this is what turns it
  // from a generic chatbot into a coach that knows the user's actual state.
  // Also fixes the earlier bug where a standalone dietMap here mapped
  // demographic-plan codes (women_40, men_40, diabetic, kids, ...) inconsistently;
  // diet naming now lives in one place, health.js's DIET_AR/DIET_EN (see below).
  const hp = buildHealthProfile(store, u.id);
  const summary = coachSummary(hp, lang);
  const isAr = lang === 'ar';

  // generatePlan mode: JSON-only output (same "strict JSON, no prose" pattern
  // already used for lab-result analysis), validated with validatePlanJSON()
  // above before it's ever allowed to touch the database. Falls through to
  // the normal conversational reply if the AI's output doesn't validate —
  // the user still gets a helpful answer, it just doesn't get saved.
  if (generatePlan === 'meals' || generatePlan === 'activity') {
    const lastUserMsg = [...(messages || [])].reverse().find(m => m.role === 'user')?.content || '';
    // JSON field KEYS (title/days/day/meals/type/name/cal/...) stay fixed —
    // validatePlanJSON() has no language-specific checks. Only the example
    // placeholder/enum VALUES shown to the model change per language, so
    // the generated plan's own content (day names, meal-type labels) comes
    // back in the resolved language, per the localization requirement.
    const schema = generatePlan === 'meals'
      ? (isAr
          ? `{"title":"...", "days":[{"day":"اسم اليوم","meals":[{"type":"إفطار|غداء|عشاء|سناك","name":"...","cal":0,"protein":0,"carbs":0,"fat":0}]}]}`
          : `{"title":"...", "days":[{"day":"day name","meals":[{"type":"breakfast|lunch|dinner|snack","name":"...","cal":0,"protein":0,"carbs":0,"fat":0}]}]}`)
      : (isAr
          ? `{"title":"...", "days":[{"day":"اسم اليوم","activity":"وصف النشاط","estCalBurn":0}]}`
          : `{"title":"...", "days":[{"day":"day name","activity":"activity description","estCalBurn":0}]}`);
    const planPrompt = isAr
      ? `أنت مساعد غذائي في Health Pace. الملف الصحي للمستخدم:\n${summary}\n\nطلب المستخدم: "${lastUserMsg}"\n\nابنِ ${generatePlan === 'meals' ? 'خطة وجبات أسبوعية (حتى 7 أيام)' : 'خطة نشاط أسبوعية (حتى 7 أيام)'} حقيقية تناسب أهدافه وأرقامه الفعلية. أرجع فقط JSON صالح بدون أي نص إضافي أو علامات كود، بالشكل التالي بالضبط:\n${schema}`
      : `You are Health Pace's nutrition assistant. The user's health profile:\n${summary}\n\nUser's request: "${lastUserMsg}"\n\nBuild a real ${generatePlan === 'meals' ? 'weekly meal plan (up to 7 days)' : 'weekly activity plan (up to 7 days)'} suited to their real goals and numbers. Return ONLY valid JSON, no extra text or code fences, in exactly this shape:\n${schema}`;
    try {
      // A full 7-day structured plan is a lot of JSON for a model to get
      // perfectly right every time — verified live that the exact same
      // prompt can produce valid JSON on one call and a malformed one (e.g.
      // one stray extra closing brace) on the next, from the same provider.
      // Retrying is the standard, safe way to handle that kind of
      // probabilistic formatting slip — validation still gates every
      // attempt equally, so a retry can never lower the bar for what's
      // allowed to be saved, it just gives a fair shot at a clean result.
      let validated = null;
      for (let attempt = 0; attempt < 2 && !validated; attempt++) {
        const { text } = await ai.chat({ messages: [{ role: 'user', content: planPrompt }], maxTokens: 1800 });
        try {
          const parsed = JSON.parse((text || '').replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim());
          validated = validatePlanJSON(generatePlan, parsed);
        } catch { /* malformed JSON — fall through to retry or final failure below */ }
      }
      if (!validated) {
        return res.json({ reply: S.planParseFailed, savedSuggestion: null });
      }
      const suggestion = {
        id: 'sg' + Date.now() + randToken(3), type: generatePlan, source: 'ai_suggestion',
        title: validated.title, content: validated, createdAt: new Date().toISOString(),
      };
      update('ai_suggestions.json', all => {
        if (!all[u.id]) all[u.id] = [];
        all[u.id].unshift(suggestion);
        all[u.id] = all[u.id].slice(0, 20);
        return all;
      }, {});
      // Confirmation text is deterministic, not AI-authored — same reasoning
      // as the label itself: what the user is told just happened should
      // never be something the AI could get wrong or embellish.
      const dayCount = validated.days.length;
      res.json({
        reply: S.planSaved(validated.title, dayCount),
        savedSuggestion: { id: suggestion.id, type: suggestion.type, title: suggestion.title },
      });
    } catch (e) {
      console.error('AI plan generation failed:', e.message);
      res.json({ reply: S.planGenError, savedSuggestion: null });
    }
    return;
  }

  // Product Instructions and Safety Instructions kept verbatim in meaning —
  // the English text is a direct translation, not a redesign of what the
  // assistant is told to do. What changed is WHERE language lives: it used
  // to be one clause inside the identity line ("تتحدث بالعربية دائماً" —
  // "always speaks Arabic"), permanently true regardless of the requester.
  // Now it's ai_language.js's own composed layer, resolved per-request.
  const productInstructions = isAr
    ? `أنت مساعد Health Pace، مساعد متابعة صحي وغذائي ذكي داخل تطبيق Health Pace. تتحدث بأسلوب ودود ومشجع وموجز.`
    : `You are the Health Pace Assistant, an intelligent health and nutrition coaching assistant inside the Health Pace app. You speak in a friendly, encouraging, and concise style.`;
  const safetyInstructions = isAr
    ? `إرشادات مهمة:
- استخدم الملف الصحي أدناه لتخصيص كل رد.
- استخدم أرقام المستخدم الحقيقية (السعرات، البروتين، الماء، الوزن، بيانات الساعة) في نصائحك بدلاً من النصائح العامة.
- إن وُجدت "تنبيهات مهمة" فعالِجها أولاً بلطف ودون تخويف.
- أنت لست بديلاً عن الطبيب. إذا ظهرت مؤشرات خطيرة (تحاليل حرجة مثلاً) انصح المستخدم بمراجعة طبيبه.
- ابقَ ضمن نطاق الغذاء والصحة واللياقة، وأعد المستخدم بلطف للموضوع إن خرج عنه.
${generateQuestions ? 'مهمتك الآن: اطرح 3 أسئلة متابعة قصيرة ومخصصة بناءً على ملفه الصحي وتنبيهاته الحالية ووقت اليوم. أرسل الأسئلة فقط كقائمة مرقمة بدون مقدمة.' : 'أجب على رسالة المستخدم بإيجاز وادعمه في رحلته الصحية.'}`
    : `Important guidelines:
- Use the health profile below to personalize every reply.
- Use the user's real numbers (calories, protein, water, weight, wearable data) in your advice instead of generic tips.
- If "important alerts" exist, address them first, gently and without alarming the user.
- You are not a substitute for a doctor. If serious indicators appear (e.g. critical lab results), advise the user to see their doctor.
- Stay within the scope of nutrition, health, and fitness, and gently guide the user back if they go off-topic.
${generateQuestions ? 'Your task now: ask 3 short, personalized follow-up questions based on their health profile, current alerts, and time of day. Send only the questions as a numbered list, with no preamble.' : "Answer the user's message concisely and support them in their health journey."}`;

  const systemPrompt = aiLanguage.buildSystemPrompt({ productInstructions, safetyInstructions, lang, userContext: summary });

  try {
    const { text } = await ai.chat({ system: systemPrompt, messages, maxTokens: 500 });
    res.json({ reply: text || S.emptyReply });
  } catch(e) {
    console.error('Chatbot error:', e.message);
    res.status(500).json({ error: S.chatbotError });
  }
});

app.get(`${BASE}/api/ai-suggestions`, auth, (req, res) => {
  const all = load('ai_suggestions.json') || {};
  res.json(all[req.user.id] || []);
});
app.delete(`${BASE}/api/ai-suggestions/:id`, auth, (req, res) => {
  update('ai_suggestions.json', all => {
    if (all[req.user.id]) all[req.user.id] = all[req.user.id].filter(s => s.id !== req.params.id);
    return all;
  }, {});
  res.json({ ok: true });
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

// Atomic single-item delete — added 2026-08-14, Nutrition domain migration.
// Previously the only way to delete one custom-logged item was client-side:
// GET the day's log, filter out the target index, POST the whole day back
// (diethub-mobile/api.js's deleteNutritionLogCustomItem). Same real race
// shape already found and fixed once this project (the quick-water
// increment bug, Home Dashboard domain): two concurrent edits to the same
// day (e.g. a delete racing a photo-log save) could read the same "before"
// state and one change would silently overwrite the other. This does the
// read-modify-write in one synchronous handler (no `await` between the
// read and the write below), removing the client-side race window entirely
// rather than trying to guard around it.
app.delete(`${BASE}/api/nutrition-log/:date/custom/:index`, auth, (req, res) => {
  const { date } = req.params;
  const index = parseInt(req.params.index, 10);
  if (!date || isNaN(index) || index < 0) return res.status(400).json({ error: 'Valid date and index required' });

  const logs = load('nutrition_logs.json') || {};
  const userLogs = logs[req.user.id] || [];
  const dayIdx = userLogs.findIndex(l => l.date === date);
  if (dayIdx < 0) return res.status(404).json({ error: 'Log entry not found' });

  const day = userLogs[dayIdx];
  if (!Array.isArray(day.custom) || index >= day.custom.length) {
    return res.status(404).json({ error: 'Item not found' });
  }
  day.custom = day.custom.filter((_, i) => i !== index);
  day.savedAt = new Date().toISOString();
  save('nutrition_logs.json', logs);
  res.json({ ok: true, custom: day.custom });
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
  { ar:'سمك بلطي', en:'tilapia fish', aliases:['بلطي','سمك مشوي'], cal:128, protein:26, carbs:0, fat:2.7, allergens:['fish'] },
  { ar:'تونة', en:'tuna, canned in water', aliases:['تونه'], cal:116, protein:26, carbs:0, fat:1, allergens:['fish'] },
  { ar:'جمبري', en:'shrimp', aliases:['روبيان'], cal:99, protein:24, carbs:0.2, fat:0.3, allergens:['crustaceans'] },
  { ar:'بيض مسلوق', en:'boiled egg', aliases:['بيضة مسلوقة'], cal:155, protein:13, carbs:1.1, fat:11, allergens:['eggs'] },
  { ar:'بياض بيض', en:'egg white', aliases:[], cal:52, protein:11, carbs:0.7, fat:0.2, allergens:['eggs'] },
  { ar:'أرز أبيض', en:'white rice, cooked', aliases:['رز أبيض','ارز ابيض'], cal:130, protein:2.7, carbs:28, fat:0.3 },
  { ar:'أرز بني', en:'brown rice, cooked', aliases:['رز بني'], cal:111, protein:2.6, carbs:23, fat:0.9 },
  { ar:'عيش بلدي', en:'baladi bread', aliases:['عيش شامي','خبز بلدي'], cal:265, protein:9, carbs:53, fat:1.5, allergens:['gluten'] },
  { ar:'عيش فينو', en:'white bread', aliases:['خبز أبيض','توست'], cal:289, protein:9, carbs:55, fat:3.2, allergens:['gluten'] },
  { ar:'مكرونة', en:'pasta, cooked', aliases:['معكرونة'], cal:131, protein:5, carbs:25, fat:1.1, allergens:['gluten'] },
  { ar:'بطاطس مسلوقة', en:'boiled potato', aliases:['بطاطا مسلوقة'], cal:87, protein:1.9, carbs:20, fat:0.1 },
  { ar:'بطاطس محمرة', en:'fried potato', aliases:['بطاطس مقلية'], cal:312, protein:3.4, carbs:41, fat:15 },
  { ar:'بطاطا', en:'sweet potato', aliases:['بطاطا حلوة'], cal:86, protein:1.6, carbs:20, fat:0.1 },
  { ar:'شوفان', en:'oats, dry', aliases:[], cal:389, protein:17, carbs:66, fat:7 },
  { ar:'فول مدمس', en:'foul medames', aliases:['فول'], cal:110, protein:7.6, carbs:18, fat:0.6 },
  // Real hummus contains tahini (sesame paste) as a core recipe ingredient —
  // was missing the sesame tag entirely (audit finding).
  { ar:'حمص', en:'hummus', aliases:[], cal:166, protein:8, carbs:14, fat:9.6, allergens:['sesame'] },
  // Was labeled "lentil soup" but its values were actually plain cooked
  // lentils (matches USDA cooked-lentil reference almost exactly) — a real
  // prepared soup (with broth/oil/vegetables) reads differently per 100g.
  // Split into two honest, distinct entries instead of one mislabeled one.
  { ar:'عدس مطبوخ', en:'cooked lentils', aliases:['عدس'], cal:116, protein:9, carbs:20, fat:0.4 },
  { ar:'شوربة عدس', en:'lentil soup (prepared)', aliases:[], cal:70, protein:4.5, carbs:11, fat:1.5 },
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
  { ar:'زبادي', en:'plain yogurt', aliases:['لبن زبادي'], cal:61, protein:3.5, carbs:4.7, fat:3.3, allergens:['milk'] },
  { ar:'زبادي يوناني', en:'greek yogurt', aliases:[], cal:59, protein:10, carbs:3.6, fat:0.4, allergens:['milk'] },
  { ar:'لبن', en:'whole milk', aliases:['حليب'], cal:61, protein:3.2, carbs:4.8, fat:3.3, allergens:['milk'] },
  { ar:'جبنة فيتا', en:'feta cheese', aliases:[], cal:264, protein:14, carbs:4, fat:21, allergens:['milk'] },
  { ar:'جبنة قريش', en:'cottage cheese', aliases:['جبنه قريش','جبن قريش'], cal:98, protein:11, carbs:3.4, fat:4.3, allergens:['milk'] },
  { ar:'جبنة بيضاء', en:'white cheese', aliases:[], cal:300, protein:18, carbs:3, fat:24, allergens:['milk'] },
  { ar:'لوز', en:'almonds', aliases:[], cal:579, protein:21, carbs:22, fat:50, allergens:['nuts'] },
  { ar:'فول سوداني', en:'peanuts', aliases:['سوداني'], cal:567, protein:26, carbs:16, fat:49, allergens:['peanuts'] },
  { ar:'زيت زيتون', en:'olive oil', aliases:[], cal:884, protein:0, carbs:0, fat:100 },
  { ar:'أفوكادو', en:'avocado', aliases:['افوكادو'], cal:160, protein:2, carbs:8.5, fat:14.7 },
  { ar:'كشري', en:'koshari', aliases:[], cal:180, protein:5, carbs:30, fat:4 },
  { ar:'كفتة مشوية', en:'grilled kofta', aliases:['كفتة'], cal:220, protein:18, carbs:2, fat:15 },
  { ar:'شاورما فراخ', en:'chicken shawarma', aliases:['شاورما دجاج'], cal:200, protein:18, carbs:10, fat:10 },
  { ar:'فتة', en:'fattah', aliases:[], cal:200, protein:10, carbs:22, fat:8, allergens:['gluten'] },
  // koshari's pasta and fattah's bread base were both untagged despite both
  // dishes structurally containing wheat — real gluten-safety gap found by
  // cross-referencing meal-plan ingredients against this database.
  { ar:'كشري', en:'koshari', aliases:[], cal:180, protein:5, carbs:30, fat:4, allergens:['gluten'] },

  // ── Added during the ingredient-database audit: real meal-plan
  // ingredients that had ZERO matching entry here at all (found by cross-
  // referencing every ingredient actually used across all 9 diets against
  // this database's own matching logic — 31 of 69 unique ingredients had no
  // match before this pass). Values are standard reference-composition
  // figures (USDA FoodData Central equivalents), not estimates.
  { ar:'بيض أحمر', en:'whole egg', aliases:['بيضة'], cal:143, protein:12.6, carbs:0.7, fat:9.5, allergens:['eggs'] },
  { ar:'صدر فراخ طازج', en:'raw chicken breast', aliases:['صدر دجاج طازج'], cal:120, protein:22.5, carbs:0, fat:2.6 },
  { ar:'خضار مشكلة', en:'mixed vegetables', aliases:[], cal:35, protein:1.8, carbs:6.5, fat:0.3 },
  // "Mixed nuts" is inherently ambiguous about exact composition — tagged
  // with BOTH nuts and peanuts since a generic blend commonly contains
  // both; the safety-conservative choice when the exact mix is unknown.
  { ar:'مكسرات مشكلة', en:'mixed nuts', aliases:[], cal:607, protein:20, carbs:21, fat:54, allergens:['nuts','peanuts'] },
  { ar:'لحمة كندوز', en:'veal/lean beef cut', aliases:['كندوز'], cal:250, protein:26, carbs:0, fat:15 },
  { ar:'عيش أسمر', en:'whole wheat bread', aliases:['خبز أسمر'], cal:247, protein:13, carbs:41, fat:3.4, allergens:['gluten'] },
  { ar:'سلمون', en:'salmon', aliases:[], cal:206, protein:22, carbs:0, fat:12, allergens:['fish'] },
  { ar:'مايونيز', en:'mayonnaise', aliases:[], cal:680, protein:1, carbs:0.6, fat:75, allergens:['eggs'] },
  { ar:'زبدة', en:'butter', aliases:[], cal:717, protein:0.85, carbs:0.1, fat:81, allergens:['milk'] },
  { ar:'كريمة طبخ', en:'cooking/heavy cream', aliases:['كريمة'], cal:340, protein:2.1, carbs:2.8, fat:36, allergens:['milk'] },
  { ar:'جبنة شيدر', en:'cheddar cheese', aliases:[], cal:403, protein:25, carbs:1.3, fat:33, allergens:['milk'] },
  { ar:'جبنة كريمي', en:'cream cheese', aliases:[], cal:342, protein:6, carbs:4, fat:34, allergens:['milk'] },
  { ar:'جبنة رومي', en:'romano-style hard cheese', aliases:[], cal:387, protein:32, carbs:3.6, fat:27, allergens:['milk'] },
  { ar:'مكسرات برازيلية', en:'brazil nuts', aliases:[], cal:656, protein:14.3, carbs:12.3, fat:66.4, allergens:['nuts'] },
  { ar:'زيت جوز الهند', en:'coconut oil', aliases:[], cal:862, protein:0, carbs:0, fat:100 },
  { ar:'جوز الهند مبشور', en:'shredded coconut, unsweetened', aliases:[], cal:660, protein:6.9, carbs:23.7, fat:64.5 },
  { ar:'كريمة جوز الهند', en:'coconut cream', aliases:[], cal:330, protein:3.6, carbs:6.7, fat:34.7 },
  { ar:'لحم مقدد بقري', en:'beef bacon', aliases:[], cal:541, protein:37, carbs:1.4, fat:42 },
  { ar:'لحم ريب آي', en:'ribeye steak', aliases:[], cal:291, protein:24, carbs:0, fat:21.2 },
  { ar:'فلفل أخضر', en:'green bell pepper', aliases:[], cal:20, protein:0.86, carbs:4.6, fat:0.17 },
  { ar:'عسل نحل', en:'honey', aliases:['عسل'], cal:304, protein:0.3, carbs:82.4, fat:0 },
  // Tahini (sesame paste) is the core ingredient making this a sesame
  // allergen — not tree nuts, not peanuts.
  { ar:'طحينة', en:'tahini', aliases:[], cal:595, protein:17, carbs:21, fat:54, allergens:['sesame'] },
  { ar:'توت مشكل', en:'mixed berries', aliases:[], cal:43, protein:0.8, carbs:10, fat:0.3 },
  { ar:'كسكسي', en:'couscous, cooked', aliases:[], cal:112, protein:3.8, carbs:23.2, fat:0.16, allergens:['gluten'] },
  // Za'atar traditionally includes toasted sesame seeds as a core
  // ingredient alongside thyme/sumac — lower confidence than a single-food
  // entry since it's a blended spice mix with real recipe variation, but
  // the sesame content itself is a well-established, near-universal part
  // of the blend, not a guess.
  { ar:'زعتر', en:"za'atar spice blend", aliases:[], cal:380, protein:10, carbs:40, fat:20, allergens:['sesame'] },
  { ar:'قرفة', en:'cinnamon, ground', aliases:[], cal:247, protein:4, carbs:80.6, fat:1.24 },
  { ar:'جزر', en:'carrot', aliases:[], cal:41, protein:0.93, carbs:9.6, fat:0.24 },
  { ar:'كبدة بقري', en:'beef liver, cooked', aliases:[], cal:175, protein:26.5, carbs:3.9, fat:4.9 },
  // Most mainstream commercial corn flakes contain barley malt extract, a
  // real gluten source despite being corn-based — tagged conservatively.
  // Gluten-free corn flake variants exist but aren't the majority product.
  { ar:'كورن فليكس', en:'corn flakes', aliases:[], cal:357, protein:7.5, carbs:84, fat:0.4, allergens:['gluten'] },
  { ar:'بروكلي', en:'broccoli', aliases:[], cal:34, protein:2.8, carbs:6.6, fat:0.37 },
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

// Real, single implementation of allergen matching — previously only
// existed inline in the photo-logging route (POST /api/nutrition-log/photo),
// so the manual/quick-add path (POST /api/nutrition-lookup, the more
// commonly used one) never surfaced a warning even for a food whose
// FOOD_DB entry carries the exact same real allergens data. Extracted here,
// used by both routes, so the logic can never diverge between them again.
// Free-text "Other" allergies (not one of the 8 structured KNOWN_ALLERGENS)
// have no per-food tag to match against, so this checks by keyword against
// the food's own name instead — real but inherently best-effort: it catches
// "shrimp" naming a food called "shrimp," not an untagged ingredient inside
// a dish with an unrelated name. Split on common separators so someone can
// type more than one thing ("sesame, kiwi" / "سمسم، كيوي") in one field.
function allergyKeywordsMatch(nameAr, nameEn, customAllergyText) {
  if (!customAllergyText) return false;
  const keywords = customAllergyText.split(/[,،/\n]+/).map(k => k.trim().toLowerCase()).filter(k => k.length >= 2);
  if (!keywords.length) return false;
  const haystack = `${nameAr || ''} ${nameEn || ''}`.toLowerCase();
  return keywords.some(k => haystack.includes(k));
}

function computeAllergenWarning(itemAllergens, userAllergies, itemNameAr, itemNameEn, customAllergyText) {
  const matches = (userAllergies && userAllergies.length) ? (itemAllergens || []).filter(a => userAllergies.includes(a)) : [];
  if (allergyKeywordsMatch(itemNameAr, itemNameEn, customAllergyText)) matches.push(customAllergyText.trim());
  return matches;
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
  // Real production safety fix, 2026-08-14: this route previously never
  // checked allergens at all, even though FOOD_DB already carries them for
  // real and the photo-logging route already used them — a user with a
  // real allergy got zero warning on the manual/quick-add path, which is
  // the more commonly used one. Same shared helper the photo route now
  // also uses, so the two paths can't silently diverge again.
  const userAllergies = req.userObj.profile?.allergies || [];
  const customAllergyText = req.userObj.profile?.customAllergyText || '';
  res.json({
    name: foodName,
    weightGrams,
    cal: Math.round(match.cal * scale),
    protein: Math.round(match.protein * scale),
    carbs: Math.round(match.carbs * scale),
    fat: Math.round(match.fat * scale),
    allergenWarning: computeAllergenWarning(match.allergens, userAllergies, match.ar, match.en, customAllergyText),
  });
});

// ─── LAB RESULTS TRACKER ──────────────────────────────────────────────────────
// Known measurable-value vocabulary, matching dashboard.html's labTests form
// (ids/normal ranges) - shared so manual entry and photo-upload extraction
// both produce the same {testId: numericValue} shape for deriveLabFlags().
const LAB_TEST_IDS = ['glucose','hba1c','cholesterol','ldl','hdl','triglycerides','creatinine','tsh','hemoglobin','vitd'];

app.get(`${BASE}/api/lab-results`, auth, (req,res) => {
  if (!BETA_MODE && !hasActiveCoverage(req.userObj.id) && req.userObj.role !== 'admin')
    return res.status(403).json({error:'Paid plan required'});
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

// Real gap this closes: 'diet' above is a single mutually-exclusive choice
// that conflates two different things — a diet MECHANISM (atkins/keto/
// mediterranean) and a DEMOGRAPHIC anchor (women/women_40/men/men_40/kids/
// diabetic). Someone who picked a mechanism diet got zero age/sex
// consideration at all: a 22-year-old and 45-year-old both on Atkins saw
// byte-identical lists, even though the user's real age and gender are
// already collected (buildHealthProfile's demographics) and already used
// elsewhere (BMI, calorie targets) — just never consulted here.
//
// Demographic-anchored choices are deliberately NOT layered further: a
// user who already picked "Women 40+" as their diet IS that demographic
// already, so adding it again would just duplicate entries, not add
// information.
const DIET_MECHANISM_KEYS = ['atkins', 'keto', 'mediterranean'];

// >=40 threshold reuses this file's own existing women_40/men_40 naming
// above — not a new cutoff invented here, just applied to a case that was
// missing it.
function demographicDietKey(age, gender) {
  if (gender === 'female') return age != null && age >= 40 ? 'women_40' : 'women';
  if (gender === 'male') return age != null && age >= 40 ? 'men_40' : 'men';
  return null; // gender not set — no demographic list to infer, base list only
}

// Dedupes by `name` — several items (Omega-3 especially) legitimately
// appear in both a mechanism list and a demographic list; shown once, not
// twice. Order preserved: the diet-mechanism items the user's actual
// choice already earned stay first, age/sex additions come after.
function buildDietSupplements(diet, demographics) {
  const base = DIET_SUPPLEMENTS[diet] || DIET_SUPPLEMENTS.atkins;
  if (!DIET_MECHANISM_KEYS.includes(diet)) return base;
  const demoKey = demographicDietKey(demographics?.age, demographics?.gender);
  if (!demoKey) return base;
  const seen = new Set(base.map(item => item.name));
  const extra = (DIET_SUPPLEMENTS[demoKey] || []).filter(item => !seen.has(item.name));
  return extra.length ? [...base, ...extra] : base;
}

// Lab-driven supplement/advisory suggestions with no weather/location context
// needed - used by the Supplements tab, which the user can open without ever
// visiting the Weather & Hydration tab. Same underlying flags/logic as
// buildEcoRecommendations() uses, just without the indoor/watch-driven items.
app.get(`${BASE}/api/lab-results/recommendations`, auth, (req,res) => {
  // referenceMetadata is additive — every existing field below is computed
  // exactly as before (buildLabSupplements/buildLabAdvisories still take
  // the same flat flags object), so existing clients see no change. New
  // clients can use referenceMetadata to show "based on an unverified/
  // legacy rule" instead of presenting a suggestion as clinically confirmed.
  const { flags: labFlags, meta: referenceMetadata } = getLatestLabFlagsMeta(req.user.id);
  const diet = DIET_SUPPLEMENTS[req.query.diet] ? req.query.diet : 'atkins';
  // Real age/gender, already collected — see buildDietSupplements' own
  // comment for why a diet-mechanism choice (atkins/keto/mediterranean)
  // needs this and a demographic-anchored one (women_40, diabetic, etc.)
  // doesn't. Reading req.userObj.profile.gender directly rather than
  // buildHealthProfile's demographics.gender — that field silently
  // defaults unset gender to 'male' (`p.gender === 'female' ? ... : 'male'`,
  // written for BMI-formula purposes where SOME sex has to be assumed to
  // produce a number at all). Reusing that default here would silently
  // show male-specific supplements to a user who simply never set their
  // gender, exactly the kind of unverified assumption this whole pass has
  // been about not making.
  const demographics = {
    age: buildHealthProfile(store, req.user.id)?.demographics?.age,
    gender: req.userObj.profile?.gender === 'male' || req.userObj.profile?.gender === 'female'
      ? req.userObj.profile.gender : null,
  };
  // Third supplement source, alongside labs and diet — real, not invented:
  // reuses the exact same indoor-detection (geofence zone match, else GPS
  // accuracy heuristic) and Vitamin D copy the Weather tab's eco-
  // recommendations already use, just surfaced here too. Optional and
  // additive — a client that doesn't send lat/lon (or a user who denied
  // location) sees byte-identical behavior to before this existed:
  // buildLabSupplements keeps its own default includeVitd:true, and
  // locationSupplements is simply an empty array, never a guess.
  const qlat = parseFloat(req.query.lat), qlon = parseFloat(req.query.lon), qacc = parseFloat(req.query.accuracy);
  let locationSupplements = [];
  let hasLocationVitd = false;
  if (!isNaN(qlat) && !isNaN(qlon)) {
    const indoorOutdoor = inferIndoorOutdoor(req.user.id, qlat, qlon, isNaN(qacc) ? null : qacc);
    // Only when actually indoor — a purely lab-triggered Vitamin D
    // suggestion (low_vitd flag, user currently outdoor/unknown) belongs in
    // the regular labs list below, not mislabeled as "based on your
    // location" just because coordinates happened to be sent.
    if (indoorOutdoor.state === 'indoor') {
      const vitaminD = buildVitaminDSuggestion(indoorOutdoor.state, labFlags);
      if (vitaminD) { locationSupplements = [vitaminD]; hasLocationVitd = true; }
    }
  }
  res.json({
    supplements: buildLabSupplements(labFlags, { includeVitd: !hasLocationVitd }),
    advisories: buildLabAdvisories(labFlags),
    advisoryTriggers: buildAdvisoryTriggers(labFlags),
    dietSupplements: buildDietSupplements(diet, demographics),
    locationSupplements,
    referenceMetadata,
  });
});

// ─── TODAY'S TREAT ──────────────────────────────────────────────────────────
// A small, positive-framing "treat" suggestion for TodayScreen — real,
// standard nutrition facts for a normal serving of each item (same spirit as
// buildMealPlans()'s own healthy-snack list, just indulgent instead of
// "clean"), not a medical/nutrition prescription. Only 2 of these
// (dark_chocolate, almonds) are tagged lowCarb — real macros, not guessed —
// so a keto/Atkins user is never handed a treat that would blow their carb
// budget for the day.
const TREATS = [
  { id: 'dark_chocolate', icon: '🍫', name: 'Dark Chocolate Square', nameAr: 'مربع شوكولاتة داكنة', portion: '2 small squares (85% cocoa, ~10g)', portionAr: 'مربعان صغيران (شوكولاتة 85%، ~10 جم)', cal: 57, protein: 1, carbs: 4, fat: 5, lowCarb: true },
  { id: 'almonds', icon: '🌰', name: 'Roasted Almonds', nameAr: 'لوز محمص', portion: '10 almonds (~12g)', portionAr: '10 حبات لوز (~12 جم)', cal: 70, protein: 3, carbs: 2, fat: 6, lowCarb: true },
  { id: 'medjool_date', icon: '🌴', name: 'Medjool Date', nameAr: 'تمرة مجهول', portion: '1 date (~24g)', portionAr: 'تمرة واحدة (~24 جم)', cal: 66, protein: 0.4, carbs: 18, fat: 0, lowCarb: false },
  { id: 'greek_yogurt_honey', icon: '🍯', name: 'Greek Yogurt with Honey', nameAr: 'زبادي يوناني بالعسل', portion: '100g yogurt + 1 tsp honey', portionAr: '100 جم زبادي + ملعقة صغيرة عسل', cal: 95, protein: 9, carbs: 9, fat: 2, lowCarb: false },
  { id: 'frozen_grapes', icon: '🍇', name: 'Frozen Grapes', nameAr: 'عنب مجمد', portion: '1 cup (~150g)', portionAr: 'كوب واحد (~150 جم)', cal: 104, protein: 1, carbs: 27, fat: 0, lowCarb: false },
  { id: 'popcorn', icon: '🍿', name: 'Air-Popped Popcorn', nameAr: 'فشار منفوخ بالهواء', portion: '1 cup (~8g)', portionAr: 'كوب واحد (~8 جم)', cal: 31, protein: 1, carbs: 6, fat: 0, lowCarb: false },
  { id: 'ice_cream', icon: '🍨', name: 'Vanilla Ice Cream', nameAr: 'آيس كريم فانيليا', portion: '1 small scoop (~65g)', portionAr: 'كرة صغيرة (~65 جم)', cal: 135, protein: 2, carbs: 16, fat: 7, lowCarb: false },
  { id: 'apple_pb', icon: '🍎', name: 'Apple Slices with Peanut Butter', nameAr: 'شرائح تفاح بزبدة الفول السوداني', portion: '1/2 apple + 1 tbsp peanut butter', portionAr: 'نصف تفاحة + ملعقة كبيرة زبدة فول سوداني', cal: 120, protein: 4, carbs: 10, fat: 8, lowCarb: false },
];
const LOW_CARB_DIETS = ['keto', 'atkins'];

// Deterministic per real calendar day (the client's own todayCairo()-computed
// date string, same convention watch-data sync already uses) — stable across
// refreshes/re-opens within the same day, rotates the next day. Never a
// re-roll on every screen open, which would feel random rather than "today's
// pick".
function hashDateString(dateStr) {
  let hash = 0;
  for (let i = 0; i < dateStr.length; i++) hash = (hash * 31 + dateStr.charCodeAt(i)) >>> 0;
  return hash;
}
function pickTodayTreat(dateStr, remainingCal, diet) {
  if (remainingCal == null || remainingCal <= 0) return null;
  const needsLowCarb = LOW_CARB_DIETS.includes(diet);
  const eligible = TREATS.filter(t => t.cal <= remainingCal && (!needsLowCarb || t.lowCarb));
  if (!eligible.length) return null;
  return eligible[hashDateString(dateStr) % eligible.length];
}

// Returns null (not an error) when nothing fits — e.g. today's budget is
// already fully spent, or the diet needs low-carb and none fit — so the
// client can simply not show the card that day. No "you failed" framing;
// this is meant to feel like an earned option, never a nag.
app.get(`${BASE}/api/today-treat`, auth, (req, res) => {
  const dateStr = sanitize(req.query.date) || new Date().toISOString().split('T')[0];
  const calorieTarget = buildHealthProfile(store, req.user.id)?.targets?.calorieTarget;
  if (calorieTarget == null) return res.json({ treat: null });
  const logs = load('nutrition_logs.json') || {};
  const dayLog = (logs[req.user.id] || []).find(l => l.date === dateStr);
  const consumed = [...(dayLog?.meals || []), ...(dayLog?.custom || [])]
    .reduce((sum, it) => sum + (it.cal || 0), 0);
  const remainingCal = calorieTarget - consumed;
  const diet = req.userObj.profile?.diet || 'atkins';
  res.json({ treat: pickTodayTreat(dateStr, remainingCal, diet), remainingCal });
});

// ─── CYCLE-AWARE FOOD TIPS ──────────────────────────────────────────────────
// Optional, female-only, off by default (cycleTrackingEnabled must be
// explicitly turned on — see /api/profile's whitelist above). Phase math
// uses the one real, well-established clinical estimate in this whole
// feature: ovulation ≈ 14 days before the NEXT period, regardless of total
// cycle length (the luteal phase itself is what's relatively fixed at
// ~14 days; cycle-length variation lives almost entirely in the follicular
// phase before it) — this is the same estimate every real ovulation
// calculator uses, not a number invented for this feature. Menstrual phase
// is fixed at ~5 days (typical bleeding duration doesn't scale with total
// cycle length). Food/drink suggestions below are common, widely-published
// nutrition guidance (iron during menstruation, magnesium/calcium during
// the luteal phase, etc.) — not a clinical claim, and never a substitute for
// a real diagnosis; copy is written to be warm and supportive, not clinical.
const CYCLE_PHASES = {
  menstrual: {
    icon: '🩸',
    titleAr: 'الدورة الشهرية', title: 'Menstrual Phase',
    noteAr: 'نعلم أن هذه الأيام قد تكون متعبة 💛 هذه الأطعمة قد تساعد جسمك الآن:',
    note: "We know these few days can be tough 💛 These might help your body right now:",
    tipsAr: ['أطعمة غنية بالحديد (لحوم حمراء، عدس، سبانخ)', 'شاي زنجبيل دافئ لتخفيف التقلصات', 'شوكولاتة داكنة (مغنيسيوم لتقليل التقلصات)'],
    tips: ['Iron-rich foods (red meat, lentils, spinach)', 'Warm ginger tea to ease cramps', 'Dark chocolate (magnesium may help cramps)'],
  },
  follicular: {
    icon: '🌱',
    titleAr: 'المرحلة الجرابية', title: 'Follicular Phase',
    noteAr: 'طاقتك بدأت ترتفع 🌱 وقت رائع للتزود بـ:',
    note: 'Your energy is likely picking up 🌱 A great time to fuel up with:',
    tipsAr: ['بروتينات خفيفة (سمك، دجاج، بيض)', 'أطعمة مخمّرة (زبادي، مخلل طبيعي)', 'فواكه وخضروات طازجة'],
    tips: ['Light proteins (fish, chicken, eggs)', 'Fermented foods (yogurt, natural pickles)', 'Fresh fruits and vegetables'],
  },
  ovulation: {
    icon: '✨',
    titleAr: 'التبويض', title: 'Ovulation',
    noteAr: 'أنتِ في ذروة نشاطك ✨ حافظي عليه بـ:',
    note: "You're likely at your peak energy ✨ Keep feeling great with:",
    tipsAr: ['خضروات ورقية وتوت (مضادة للالتهاب)', 'أطعمة غنية بالألياف', 'خيار وبطيخ للترطيب'],
    tips: ['Leafy greens and berries (anti-inflammatory)', 'Fiber-rich foods', 'Cucumber and watermelon for hydration'],
  },
  luteal: {
    icon: '🌙',
    titleAr: 'المرحلة الأصفرية (ما قبل الدورة)', title: 'Luteal Phase (PMS)',
    noteAr: 'أعراض ما قبل الدورة قد تكون صعبة 💛 القليل من الاهتمام يفرق كثيراً — جرّبي:',
    note: 'PMS can be rough 💛 A little extra care goes a long way — try:',
    tipsAr: ['كربوهيدرات معقدة (شوفان، حبوب كاملة) لتحسين المزاج', 'أطعمة غنية بالمغنيسيوم والكالسيوم', 'شاي بابونج دافئ، وتقليل الكافيين والملح إن أمكن'],
    tips: ['Complex carbs (oats, whole grains) to help mood', 'Magnesium- and calcium-rich foods', 'Warm chamomile tea, and less caffeine/salt if you can'],
  },
};

function getCyclePhase(lastPeriodStart, cycleLength) {
  const start = new Date(lastPeriodStart + 'T00:00:00Z');
  const daysSince = Math.floor((Date.now() - start.getTime()) / 86400000);
  if (daysSince < 0) return null; // future date, shouldn't happen post-validation, but never guess
  const dayOfCycle = (daysSince % cycleLength) + 1; // 1-indexed
  const ovulationDay = Math.max(cycleLength - 14, 10);
  if (dayOfCycle <= 5) return 'menstrual';
  if (dayOfCycle >= ovulationDay - 1 && dayOfCycle <= ovulationDay + 1) return 'ovulation';
  if (dayOfCycle < ovulationDay - 1) return 'follicular';
  return 'luteal';
}

// Returns null (not an error) whenever the feature doesn't apply — not
// female, tracking not explicitly enabled, or no start-date entered yet —
// so the client simply shows nothing rather than an empty/broken card.
app.get(`${BASE}/api/cycle-today`, auth, (req, res) => {
  const p = req.userObj.profile || {};
  if (p.gender !== 'female' || !p.cycleTrackingEnabled || !p.lastPeriodStart) {
    return res.json({ phase: null });
  }
  const cycleLength = p.cycleLength || 28;
  const phaseKey = getCyclePhase(p.lastPeriodStart, cycleLength);
  if (!phaseKey) return res.json({ phase: null });
  res.json({ phase: { key: phaseKey, ...CYCLE_PHASES[phaseKey] } });
});

// Fed by an n8n workflow (n8n.talabatito.com), not user input — same
// "service account logs in, then POSTs" pattern already used by the
// Diethub price updater workflow against /api/admin/food-prices. Macros
// are computed by the workflow from real per-ingredient nutrition data
// (USDA FoodData Central), never asked from the AI step directly, so this
// endpoint just stores whatever real numbers it's given rather than
// re-deriving or trusting an LLM's stated calorie count.
function validateDailyRecipe(b) {
  if (!b || typeof b !== 'object') return false;
  if (typeof b.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(b.date)) return false;
  if (typeof b.name !== 'string' || typeof b.nameAr !== 'string' || !b.name || !b.nameAr) return false;
  if (typeof b.imageUrl !== 'string' || !b.imageUrl) return false;
  if (!Array.isArray(b.ingredients) || !b.ingredients.length || b.ingredients.length > 20) return false;
  if (!b.ingredients.every(i => i && typeof i.emoji === 'string' && typeof i.name === 'string'
    && typeof i.nameAr === 'string' && typeof i.qty === 'string' && typeof i.qtyAr === 'string')) return false;
  if (!Array.isArray(b.steps) || !Array.isArray(b.stepsAr) || !b.steps.length || b.steps.length !== b.stepsAr.length || b.steps.length > 15) return false;
  if (!b.steps.every(s => typeof s === 'string') || !b.stepsAr.every(s => typeof s === 'string')) return false;
  const macros = b.macros;
  if (!macros || typeof macros !== 'object') return false;
  return ['cal', 'protein', 'carbs', 'fat'].every(k => typeof macros[k] === 'number' && macros[k] >= 0);
}
// Image comes from n8n as a base64 JSON body (the AI image-generation step's
// native output shape), not a multipart file — hence the path-scoped 20mb
// body limit above, rather than reusing avatarUpload's multer config, which
// expects multipart. Same sharp() re-encode discipline as POST /api/profile/avatar:
// never trust what's sent as final bytes for something about to be served
// back out over a public URL — always re-decode and re-encode.
app.post(`${BASE}/api/admin/daily-recipe/image`, auth, adminOnly, async (req, res) => {
  const { imageBase64 } = req.body;
  if (typeof imageBase64 !== 'string' || !imageBase64) return res.status(400).json({ error: 'Missing imageBase64' });
  let resized;
  try {
    resized = await sharp(Buffer.from(imageBase64, 'base64')).resize(900, 620, { fit: 'cover' }).jpeg({ quality: 85 }).toBuffer();
  } catch (e) {
    return res.status(400).json({ error: 'Could not process this image' });
  }
  const filename = `recipe-${todayCairoServer()}-${randToken(8)}.jpg`;
  fs.writeFileSync(path.join(RECIPE_IMAGE_DIR, filename), resized);
  res.json({ url: `/uploads/recipes/${filename}` });
});
app.post(`${BASE}/api/admin/daily-recipe`, auth, adminOnly, (req, res) => {
  if (!validateDailyRecipe(req.body)) {
    return res.status(400).json({ ok: false, error: 'Invalid recipe payload' });
  }
  const b = req.body;
  const recipe = {
    date: b.date, name: sanitize(b.name), nameAr: sanitize(b.nameAr), imageUrl: b.imageUrl,
    ingredients: b.ingredients.map(i => ({
      emoji: i.emoji, name: sanitize(i.name), nameAr: sanitize(i.nameAr), qty: sanitize(i.qty), qtyAr: sanitize(i.qtyAr),
    })),
    steps: b.steps.map(sanitize), stepsAr: b.stepsAr.map(sanitize),
    macros: { cal: b.macros.cal, protein: b.macros.protein, carbs: b.macros.carbs, fat: b.macros.fat },
  };
  update('daily_recipes.json', all => { all[recipe.date] = recipe; return all; }, {});
  res.json({ ok: true, date: recipe.date });
});
app.get(`${BASE}/api/daily-recipe`, auth, (req, res) => {
  const all = load('daily_recipes.json') || {};
  res.json({ recipe: all[todayCairoServer()] || null });
});

// Nothing in the app ever shows a past day's recipe — only ever GET
// /api/daily-recipe for today — so records and images older than the
// retention window are pure dead weight, not a feature users would miss.
// Left unpruned, both daily_recipes.json and RECIPE_IMAGE_DIR grow forever.
// Runs once a day; also once at boot so a restart doesn't wait a full day
// to catch up (same pattern as runReminderCheck below).
const DAILY_RECIPE_RETENTION_DAYS = 30;
function cleanupOldDailyRecipes() {
  const cutoff = new Date(Date.now() - DAILY_RECIPE_RETENTION_DAYS * 86400000);
  const cutoffStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo' }).format(cutoff);
  update('daily_recipes.json', all => {
    for (const date of Object.keys(all)) {
      if (date < cutoffStr) delete all[date];
    }
    return all;
  }, {});
  // Image filenames embed their date (recipe-YYYY-MM-DD-<token>.jpg, see
  // POST /api/admin/daily-recipe/image) — pruning by filename means this
  // doesn't need to cross-reference the JSON above, so an image can never
  // be orphaned by the two falling out of sync.
  let files;
  try { files = fs.readdirSync(RECIPE_IMAGE_DIR); } catch { return; }
  for (const file of files) {
    const m = file.match(/^recipe-(\d{4}-\d{2}-\d{2})-/);
    if (m && m[1] < cutoffStr) {
      try { fs.unlinkSync(path.join(RECIPE_IMAGE_DIR, file)); } catch (e) { console.error('[daily-recipe] failed to delete old image:', e.message); }
    }
  }
}
setInterval(cleanupOldDailyRecipes, 24 * 60 * 60 * 1000);
cleanupOldDailyRecipes();

// Shared by manual entry AND photo-upload extraction. This function's own
// comment previously claimed exactly that, but it wasn't actually true —
// the manual-entry route below had its own second, inline copy of this
// same prompt (using ai.chat(), not this function's raw Anthropic fetch),
// so the two entry points silently drifted onto two different reliability
// levels. Consolidated here for real: this is now the one place the prompt
// exists, and it goes through ai.js's multi-provider fallback chain rather
// than a hardcoded single-provider fetch — closing the exact outage class
// ai.js's own header comment documents ("Anthropic credits ran out,
// silently broke the chatbot... until it was noticed") for both callers,
// not just the one that happened to already use ai.chat().
//
// `results` is user-supplied (manual entry) or AI-vision-extracted (photo
// upload) and was previously interpolated into the prompt completely raw —
// a manual-entry user could put arbitrary text in any result value with no
// restriction on shape/keys before this point. String values are now run
// through the same sanitize() used everywhere else in this file (HTML-
// escapes safe content, returns null for a recognized injection pattern);
// numbers pass through unchanged, so real analysis quality is unaffected.
async function analyzeLabResults(results, diet) {
  const safeResults = Object.fromEntries(
    Object.entries(results || {}).map(([k, v]) => [k, typeof v === 'string' ? sanitize(v) : v])
  );
  const prompt = `You are a medical nutrition AI assistant. Analyze these lab results for a patient on a ${diet} diet:\n${JSON.stringify(safeResults)}\n\nProvide a brief analysis in Arabic and English covering:\n1. Which values are normal/abnormal\n2. What dietary changes could help\n3. Overall health trend\n\nReturn ONLY valid JSON (no markdown, no code fences): {"analysis_ar":"...","analysis_en":"...","status":"good|warning|critical","recommendations_ar":["..."],"recommendations_en":["..."]}`;
  // 800 was too low — a full bilingual (AR+EN) analysis with recommendation
  // lists routinely hit stop_reason:"max_tokens" and got cut off mid-JSON,
  // which is a genuine truncation no amount of parsing robustness can fix.
  const { text } = await ai.chat({ messages: [{ role: 'user', content: prompt }], maxTokens: 2000 });
  // Free models sometimes wrap JSON in ```; strip fences before parsing,
  // same robust handling the vision-extraction step already uses.
  const raw = (text || '{}').replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
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

// Same lookup as getLatestLabFlags, but via deriveLabFlagsMeta — used only
// by /api/lab-results/recommendations' additive metadata field, so the
// other 2 getLatestLabFlags call sites are untouched.
function getLatestLabFlagsMeta(userId) {
  const all = load('lab_results.json') || {};
  const entries = all[userId] || [];
  const latest = entries[0];
  if (!latest || !latest.numericResults) return { flags: {}, meta: [] };
  return deriveLabFlagsMeta(latest.numericResults);
}

function updateLabEntryAnalysis(userId, date, analysis) {
  const all = load('lab_results.json') || {};
  const idx = (all[userId]||[]).findIndex(l=>l.date===date);
  if (idx >= 0) { all[userId][idx].analysis = analysis; save('lab_results.json', all); }
}

app.post(`${BASE}/api/lab-results`, auth, async (req,res) => {
  if (!BETA_MODE && !hasActiveCoverage(req.userObj.id) && req.userObj.role !== 'admin')
    return res.status(403).json({error:'Paid plan required'});
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
    const analysis = await analyzeLabResults(results, diet);
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
  } catch {
    res.json({ok:true, analysis:null});
  }
});

// ─── LAB RESULTS: PHOTO/PDF UPLOAD WITH AUTO-EXTRACTION ───────────────────────
// User uploads a photo/scan of a real lab report; AI vision reads the
// values directly rather than requiring manual typing, then feeds into the
// exact same analysis pipeline as manual entry above.
// Accepts up to 6 files (multi-page reports — was single-file-only, a real
// reported bug since most real lab reports span 2+ pages), sent as one
// ai.chatVision() call with one image per page, so the model reads them as
// one document rather than requiring N separate uploads/round-trips.
// Was a direct Anthropic call (paid, no free tier) until 2026-08-30 — moved
// onto ai.js's free-provider vision chain (see ai.js's own comment) after
// that dependency caused a real outage: Anthropic ran out of credit and
// every upload failed with a message blaming the photo, not the API call.
// Real bug fix (2026-09-03): a rejected fileFilter (bad mimetype) or an
// over-limit file previously had no error-handling middleware anywhere in
// this file, so Express's own default handler caught it and returned a raw
// HTML page with a full stack trace (file paths, dependency versions) to
// the client — a real information-disclosure gap, not just a rough UX
// edge. Shared by every multer route as their trailing 4-arg (error)
// handler — Express recognizes the 4-arg signature and routes a
// fileFilter/limits error here instead of into the normal 3-arg handler.
function handleUploadError(err, req, res, _next) {
  res.status(400).json({ error: err.message || 'Upload failed' });
}

const labUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB per file
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg','image/png','image/webp','image/heic','application/pdf'].includes(file.mimetype);
    cb(ok ? null : new Error('Unsupported file type — use JPG, PNG, WEBP, HEIC, or PDF'), ok);
  }
});

app.post(`${BASE}/api/lab-results/upload`, auth, labUpload.array('files', 6), async (req,res) => {
  if (!BETA_MODE && !hasActiveCoverage(req.userObj.id) && req.userObj.role !== 'admin')
    return res.status(403).json({error:'Paid plan required'});
  if (!req.files || req.files.length === 0) return res.status(400).json({error:'No file uploaded'});
  if (req.files.some(f => f.mimetype === 'application/pdf'))
    return res.status(400).json({error:'PDF غير مدعوم حالياً، من فضلك صور التحليل بالكاميرا أو ارفع صورة · PDF not supported yet — please upload a photo of the report instead'});

  const date = req.body.date || new Date().toISOString().split('T')[0];

  try {
    const images = req.files.map(f => ({ mimeType: f.mimetype, base64: f.buffer.toString('base64') }));
    const extractPrompt = `${req.files.length > 1 ? `These images are ${req.files.length} pages of the same medical lab report` : 'This image is a medical lab report'} (blood test results), possibly in Arabic or English. Extract every test name and its value with unit${req.files.length > 1 ? ' across all pages' : ''}. If a reference/normal range is printed, include it.\n\nAlso classify each test against this known list, if it matches one: glucose (blood glucose/fasting sugar), hba1c, cholesterol (total cholesterol), ldl, hdl, triglycerides, creatinine, tsh, hemoglobin, vitd (vitamin D). Use the matching id as "testId", or null if it doesn't match any of these. Also give the value as a plain number in "numericValue" (e.g. 185, not "185 mg/dL") when it's a single numeric result - use null for non-numeric results.\n\nReturn ONLY valid JSON, no other text, in this exact shape:\n{"tests": [{"name":"...", "value": "...", "unit": "...", "range": "...", "testId": "..." or null, "numericValue": 0 or null}]}\n\nIf the image is not a lab report or no values are readable, return {"tests": []}.`;

    // ai.chatVision() already tries every configured free provider in order
    // and only throws once ALL of them fail — that's the "API call itself
    // failed" case (was previously a real reported bug: a failed Anthropic
    // call fell straight through to the "tests.length === 0" branch below
    // and told the user their PHOTO was unclear, with nothing logged to
    // reveal the real cause). Genuinely zero readable tests in a real
    // response is handled separately below, after a successful call.
    let rawText;
    try {
      const result = await ai.chatVision({ prompt: extractPrompt, images, maxTokens: 1500 });
      rawText = result.text;
    } catch (e) {
      console.error('[lab-upload] all vision providers failed:', e.message);
      return res.status(502).json({ ok:false, error: 'خدمة القراءة التلقائية غير متاحة مؤقتاً، برجاء إدخال النتائج يدوياً أو المحاولة مرة أخرى بعد قليل · Automatic reading is temporarily unavailable — please enter your results manually or try again shortly' });
    }

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
}, handleUploadError);

// ─── NUTRITION LOG: PHOTO UPLOAD WITH AI FOOD IDENTIFICATION ──────────────────
// User photographs a plate; Claude's vision identifies each visible food item
// and a rough portion size (not calories — the model is asked for names/
// portions only). Each item is then resolved against FOOD_DB/findFoodMatch
// first (free, deterministic, matches manual "Add Custom Food" exactly); only
// items with no local match fall back to the AI's own calorie estimate, since
// unlike manual entry there's no "type it in yourself" fallback for a photo.
// Was a direct Anthropic call until 2026-08-30 (same reasoning that used to
// justify it — food photos are called far more often per user per day than
// the rare lab photo — turned out backwards: high-frequency traffic on a
// paid-only dependency is exactly the case most likely to hit a credit
// limit, not a reason to prefer one). Now uses ai.chatVision() (the item-ID
// call, which needs the image) and plain ai.chat() (the calorie-estimate
// follow-up, which is text-only and gets Groq back in its fallback chain
// since that rung doesn't need vision support) — see ai.js's own comment
// for exactly which free providers/models back each.
const foodPhotoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg','image/png','image/webp','image/heic'].includes(file.mimetype);
    cb(ok ? null : new Error('Unsupported file type — use JPG, PNG, WEBP, or HEIC'), ok);
  }
});

app.post(`${BASE}/api/nutrition-log/photo`, auth, foodPhotoUpload.single('file'), async (req,res) => {
  if (!req.file) return res.status(400).json({error:'No file uploaded'});
  const date = req.body.date || new Date().toISOString().split('T')[0];

  try {
    const b64 = req.file.buffer.toString('base64');
    const idPrompt = `This image shows a plate or serving of food, possibly Egyptian/Middle Eastern cuisine. Identify every distinct food item visible and estimate its portion weight in grams.\n\nReturn ONLY valid JSON, no other text, in this exact shape:\n{"items": [{"name": "...", "weightGrams": 0}]}\n\nName each item simply (e.g. "grilled chicken breast", "white rice", "green salad") in English. If nothing edible is visible, return {"items": []}.`;

    // See the lab-photo route above for why this checks for a total-failure
    // exception separately from "the model looked and found nothing" below.
    let rawText;
    try {
      const result = await ai.chatVision({ prompt: idPrompt, images: [{ mimeType: req.file.mimetype, base64: b64 }], maxTokens: 800 });
      rawText = result.text;
    } catch (e) {
      console.error('[nutrition-photo] all vision providers failed:', e.message);
      return res.status(502).json({ ok:false, error: 'خدمة التعرف على الطعام غير متاحة مؤقتاً، برجاء إدخال الوجبة يدوياً أو المحاولة مرة أخرى بعد قليل · Food recognition is temporarily unavailable — please add the meal manually or try again shortly' });
    }

    const match = rawText.match(/\{[\s\S]*\}/);
    const identified = match ? JSON.parse(match[0]) : { items: [] };

    if (!identified.items || identified.items.length === 0) {
      return res.json({ ok:false, error: 'لم نتمكن من التعرف على طعام واضح في الصورة، جرب صورة أوضح · Could not identify clear food items in the photo, try a clearer picture' });
    }

    // Items with no FOOD_DB match need their own calorie estimate — ask for
    // all of them in one follow-up call rather than one round-trip per item.
    const unmatched = [];
    const items = identified.items.filter(it => it.name).map(it => {
      const dbMatch = findFoodMatch(it.name);
      const grams = Math.max(1, Math.min(5000, parseFloat(it.weightGrams) || 100));
      if (dbMatch) {
        const scale = grams / 100;
        return { name: it.name, weightGrams: grams, cal: Math.round(dbMatch.cal*scale), protein: Math.round(dbMatch.protein*scale), carbs: Math.round(dbMatch.carbs*scale), fat: Math.round(dbMatch.fat*scale), allergens: dbMatch.allergens || [], source: 'db' };
      }
      unmatched.push({ name: it.name, weightGrams: grams });
      return null;
    });

    if (unmatched.length) {
      const estPrompt = `For each food item below, estimate calories, protein, carbs, and fat in grams, for the given weight. Return ONLY valid JSON: {"items": [{"name": "...", "cal": 0, "protein": 0, "carbs": 0, "fat": 0}]}\n\nItems: ${JSON.stringify(unmatched)}`;
      // Text-only (no image) — the plain free-provider chain above, not
      // chatVision(), which also brings Groq back into play for this
      // specific call since it doesn't need vision support.
      let estText = '{}';
      try {
        const est = await ai.chat({ messages: [{ role: 'user', content: estPrompt }], maxTokens: 800 });
        estText = est.text;
      } catch (e) {
        // Best-effort — if every provider fails here, unmatched items just
        // keep their zeroed-out defaults below rather than failing the
        // whole upload (the items WITH a FOOD_DB match already saved fine).
        console.error('[nutrition-photo] calorie-estimate providers failed:', e.message);
      }
      const estMatch = estText.match(/\{[\s\S]*\}/);
      const estimated = estMatch ? JSON.parse(estMatch[0]) : { items: [] };
      let ui = 0;
      for (let i = 0; i < items.length; i++) {
        if (items[i] !== null) continue;
        const est = estimated.items?.[ui] || {};
        const src = unmatched[ui];
        items[i] = { name: src.name, weightGrams: src.weightGrams, cal: Math.round(est.cal)||0, protein: Math.round(est.protein)||0, carbs: Math.round(est.carbs)||0, fat: Math.round(est.fat)||0, allergens: [], source: 'ai_estimate' };
        ui++;
      }
    }

    // Flag allergens against the logged-in user's saved profile.allergies —
    // via computeAllergenWarning(), the same shared helper the manual/
    // quick-add lookup route now also uses (see /api/nutrition-lookup),
    // so this logic can't silently diverge between the two paths again.
    const userAllergies = req.userObj.profile?.allergies || [];
    const customAllergyText = req.userObj.profile?.customAllergyText || '';
    // it.name is a single identified-food string (no separate ar/en split
    // for AI-vision items) — passed as both args since the keyword matcher
    // just concatenates them into one search string anyway.
    const withWarnings = items.map(it => ({ ...it, allergenWarning: computeAllergenWarning(it.allergens, userAllergies, it.name, it.name, customAllergyText) }));
    const totalCal = withWarnings.reduce((s,it)=>s+it.cal, 0);

    secLog('NUTRITION_PHOTO_UPLOAD', getIP(req), { userId: req.user.id, itemCount: withWarnings.length });
    res.json({ ok:true, date, items: withWarnings, totalCal });
  } catch (e) {
    console.error('[nutrition-photo] error:', e.message);
    res.status(500).json({ error: 'حصل خطأ أثناء تحليل الصورة · Error processing the image' });
  }
}, handleUploadError);

// ─── ADMIN IMPERSONATION ──────────────────────────────────────────────────────


// ─── WATCH SYNC ENGINE ────────────────────────────────────────────────────────
// Unified schema: { userId, date, source, steps, heartRate, caloriesBurned, sleep, spO2, stress, water }

app.post(`${BASE}/api/watch/sync`, auth, (req, res) => {
  const {
    source, date, steps, heartRate, caloriesBurned, sleep, spO2, stress, water,
    // Connected Health Platform Phase 1 additions — fields the Apple Health
    // / Health Connect plugins can supply that no existing source did.
    // Purely additive: all optional, existing callers sending none of these
    // are completely unaffected (boundedNum(undefined,...) -> null, same as
    // it already behaves for the pre-existing fields today).
    weight, bloodPressureSystolic, bloodPressureDiastolic, bloodGlucose,
    temperature, bodyFat, hrv, recovery, workouts,
  } = req.body;
  if (!source || !date) return res.status(400).json({ error: 'source and date required' });

  // apple_health / health_connect added for the Connected Health Platform's
  // on-device provider plugins (see /root/diethub-mobile/connectedHealth/).
  // Kept as a flat array rather than merged into OW_PROVIDERS/
  // MANUAL_WATCH_SOURCES above — those two are Open-Wearables-specific and
  // manual-entry-specific respectively; on-device SDK sources are a third,
  // distinct category and don't belong in either existing list. The 3
  // medical_device:* ids are the Bluetooth medical-device providers
  // (connectedHealth/providers/MedicalDeviceProvider.js) — real, direct BLE
  // connections, distinct from apple_health/health_connect's phone-OS-
  // aggregator passthrough.
  const ON_DEVICE_MIDDLEWARE_SOURCES = ['apple_health', 'health_connect'];
  const allowed = ['apple_watch','wear_os','galaxy_watch','garmin','fitbit','oura','whoop','polar','strava','suunto','ultrahuman','honor_watch','manual', ...ON_DEVICE_MIDDLEWARE_SOURCES, ...MEDICAL_DEVICE_SOURCES];
  if (!allowed.includes(source)) return res.status(400).json({ error: 'Invalid source' });

  // Device-tier gate (2026-09-02, refined 2026-09-02) — three real
  // categories, not one blanket check:
  //   - Manual entry (typed-in numbers, MANUAL_WATCH_SOURCES) is not a
  //     device integration at all and is never gated — tier1 users can
  //     still log their own steps/heart rate by hand.
  //   - Phone-health-app middleware (apple_health/health_connect — the
  //     wearable syncs to the user's OWN phone health app, which Health
  //     Pace then reads) needs tier2+. Samsung Health has no viable
  //     third-party API of its own (its SDK is partner-gated, and the two
  //     community npm wrappers are unmaintained/unverifiable) — Samsung
  //     Health has synced into Health Connect since ~2022 (One UI 5), so
  //     health_connect already covers it on modern devices; no separate
  //     samsung_health source exists here on purpose, not an oversight.
  //   - Direct-to-vendor-cloud OAuth (OW_PROVIDERS: Garmin/Fitbit/Oura/
  //     Whoop/Polar/Strava/Suunto/Ultrahuman) and the Bluetooth medical
  //     devices both need tier3 specifically — tier2 only gets the
  //     middleware path, not a direct integration.
  // All of this ignores BETA_MODE on purpose (see hasDeviceTier()).
  if (ON_DEVICE_MIDDLEWARE_SOURCES.includes(source) && !hasDeviceTier(req.userObj, 'tier2')) {
    return res.status(403).json({ error: 'Connected device sync requires the Active plan or higher' });
  }
  if (OW_PROVIDERS.includes(source) && !hasDeviceTier(req.userObj, 'tier3')) {
    return res.status(403).json({ error: 'Direct wearable-brand syncing requires the Complete plan' });
  }
  if (MEDICAL_DEVICE_SOURCES.includes(source) && !hasDeviceTier(req.userObj, 'tier3')) {
    return res.status(403).json({ error: 'Blood pressure, glucose, and scale monitoring require the Complete plan' });
  }

  const all = load('watch_data.json') || {};
  if (!all[req.user.id]) all[req.user.id] = [];

  // Deduplicate by date + source
  const key = `${date}_${source}`;
  const existing = all[req.user.id].findIndex(d => `${d.date}_${d.source}` === key);

  // Hardening pass (independent audit, Part 3): previously accepted any
  // parseable number with no bounds — a negative or absurd value (a
  // mistyped or malicious client) would silently persist and surface on
  // the dashboard/daily-brief with no server-side sanity check. Bounds are
  // generous, real physiological/device ranges, not tight product limits.
  const boundedNum = (v, parser, min, max) => {
    const n = parser(v);
    return Number.isFinite(n) && n >= min && n <= max ? n : null;
  };
  // Workouts: a small array of already-normalized session objects (see
  // connectedHealth/normalizer.js buildSample's 'workout' shape), not
  // free-form — validated defensively since it's the one non-scalar field
  // here and arrives straight from a third-party SDK payload.
  const safeWorkouts = Array.isArray(workouts)
    ? workouts
        .filter(w => w && typeof w.activityType === 'string' && Number.isFinite(w.durationMin))
        .slice(0, 20)
        .map(w => ({
          activityType: sanitize(w.activityType).slice(0, 40),
          durationMin: Math.min(Math.max(Math.round(w.durationMin), 0), 1440),
          caloriesBurned: Number.isFinite(w.caloriesBurned) ? Math.min(Math.max(Math.round(w.caloriesBurned), 0), 10000) : null,
          distanceKm: Number.isFinite(w.distanceKm) ? Math.min(Math.max(w.distanceKm, 0), 500) : null,
        }))
    : undefined;
  const entry = {
    date,
    source,
    steps:           boundedNum(steps, parseInt, 0, 200000),
    heartRate:       boundedNum(heartRate, parseInt, 20, 250),
    caloriesBurned:  boundedNum(caloriesBurned, parseInt, 0, 20000),
    sleep:           boundedNum(sleep, parseFloat, 0, 24),
    spO2:            boundedNum(spO2, parseFloat, 0, 100),
    stress:          boundedNum(stress, parseInt, 0, 100),
    water:           boundedNum(water, parseFloat, 0, 50),
    weight:                   boundedNum(weight, parseFloat, 20, 400),
    bloodPressureSystolic:    boundedNum(bloodPressureSystolic, parseInt, 60, 250),
    bloodPressureDiastolic:   boundedNum(bloodPressureDiastolic, parseInt, 30, 150),
    bloodGlucose:             boundedNum(bloodGlucose, parseFloat, 20, 600),
    temperature:              boundedNum(temperature, parseFloat, 30, 45),
    bodyFat:                  boundedNum(bodyFat, parseFloat, 2, 70),
    hrv:                      boundedNum(hrv, parseFloat, 0, 300),
    recovery:                 boundedNum(recovery, parseInt, 0, 100),
    syncedAt: new Date().toISOString()
  };
  if (safeWorkouts !== undefined) entry.workouts = safeWorkouts;

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

// Atomic water-quantity increment — added for the Home Dashboard migration
// to close a real, verified race condition: every "quick-add water" client
// (BriefScreen.js, TodayScreen.js, dashboard-pilot.html) previously did a
// separate GET /api/watch/data read, computed newTotal = current + amount
// client-side, then POSTed it via /api/watch/sync — two rapid taps could
// both read the same "before" value and one increment would be lost. This
// endpoint does the read-modify-write in one synchronous handler (Node is
// single-threaded; no `await` between the read and the write below, so two
// concurrent requests can't interleave), removing the client-side gap
// entirely rather than trying to debounce around it.
app.post(`${BASE}/api/watch/sync/water-increment`, auth, (req, res) => {
  const { date, amount, source } = req.body;
  const amt = parseFloat(amount);
  if (!date || !amt || amt <= 0) return res.status(400).json({ error: 'date and a positive amount required' });
  const src = source || 'manual';

  const all = load('watch_data.json') || {};
  if (!all[req.user.id]) all[req.user.id] = [];

  const key = `${date}_${src}`;
  const idx = all[req.user.id].findIndex(d => `${d.date}_${d.source}` === key);
  const current = idx >= 0 ? (all[req.user.id][idx].water || 0) : 0;
  const newTotal = +(current + amt).toFixed(2);

  if (idx >= 0) all[req.user.id][idx].water = newTotal;
  else all[req.user.id].push({ date, source: src, steps: null, heartRate: null, caloriesBurned: null, sleep: null, spO2: null, stress: null, water: newTotal, syncedAt: new Date().toISOString() });

  all[req.user.id] = all[req.user.id].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 90);
  save('watch_data.json', all);
  secLog('WATCH_WATER_INCREMENT', getIP(req), { userId: req.user.id, date, amount: amt });
  res.json({ ok: true, water: newTotal });
});

app.get(`${BASE}/api/watch/data`, auth, (req, res) => {
  const all = load('watch_data.json') || {};
  const userdata = all[req.user.id] || [];
  const days = Math.min(Math.max(parseInt(req.query.days) || 7, 1), 90);
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

// Display metadata for the real OAuth-connectable providers above, plus the
// real manual-entry-only sources (no OAuth, entered by hand via
// POST /api/watch/sync — 'manual' and the specific device names below).
// Single source of truth, added 2026-08-14 (Wearables domain migration) to
// close a real, verified duplication: this exact id/icon/name set was
// already hardcoded independently in dashboard.html's WATCH_PROVIDERS/
// MANUAL_ONLY_PROVIDERS constants — a second, mobile-side hardcoded copy
// would have made a real duplication a third one. OW_PROVIDERS above (the
// bare id list used for connect/validate logic) is unchanged and still the
// source of truth for which ids are valid; this only adds display metadata
// for the same ids, it doesn't change which providers are supported.
const WATCH_PROVIDER_META = {
  garmin: { icon: '🔵', name: 'Garmin' },
  fitbit: { icon: '💚', name: 'Fitbit' },
  oura: { icon: '💍', name: 'Oura' },
  whoop: { icon: '🖤', name: 'Whoop' },
  polar: { icon: '⚪', name: 'Polar' },
  strava: { icon: '🟠', name: 'Strava' },
  suunto: { icon: '🧭', name: 'Suunto' },
  ultrahuman: { icon: '🔷', name: 'Ultrahuman' },
};
const MANUAL_WATCH_SOURCES = {
  apple_watch: { icon: '⌚', name: 'Apple Watch' },
  wear_os: { icon: '⌚', name: 'Wear OS' },
  galaxy_watch: { icon: '⌚', name: 'Galaxy Watch' },
  honor_watch: { icon: '⌚', name: 'Honor Watch' },
  manual: { icon: '✍️', name: 'Manual Entry', nameAr: 'إدخال يدوي' },
};
// Connected Health Platform Phase 1 — on-device SDK sources, distinct from
// both OW_PROVIDERS (server-side OAuth) and MANUAL_WATCH_SOURCES (typed
// entry, no real connection at all). The mobile ConnectedHealthManager
// decides platform availability (Apple Health iOS-only, Health Connect
// Android-only) client-side via Platform.OS — this list is unfiltered by
// platform on purpose, same "server describes what exists, client decides
// what applies" split already used for connectable/manual above.
const ON_DEVICE_SOURCES = {
  apple_health: { icon: '🍎', name: 'Apple Health', platform: 'ios' },
  health_connect: { icon: '🤖', name: 'Health Connect', platform: 'android' },
};

// Real, data-driven provider list — the client no longer needs its own
// hardcoded copy of ids/icons/names to build a connect UI from.
// Read-only descriptive metadata (which providers/manual labels/on-device
// sources exist) — not gated, since it grants no access by itself. The real
// gates live where a connection is actually initiated or data actually
// written: /api/watch/connect/:provider (tier3, OAuth) and /api/watch/sync
// (per-source, see its own gate comment above).
app.get(`${BASE}/api/watch/providers`, auth, (req, res) => {
  res.json({
    connectable: OW_PROVIDERS.map(id => ({ id, ...WATCH_PROVIDER_META[id] })),
    manual: Object.entries(MANUAL_WATCH_SOURCES).map(([id, meta]) => ({ id, ...meta })),
    onDevice: Object.entries(ON_DEVICE_SOURCES).map(([id, meta]) => ({ id, ...meta })),
  });
});

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
  // Direct-to-vendor-cloud OAuth (see /api/watch/sync's gate comment) needs
  // tier3 specifically — tier2 only covers the phone-health-app middleware
  // path (Apple Health/Health Connect), not a direct vendor connection.
  if (!hasDeviceTier(req.userObj, 'tier3')) {
    return res.status(403).json({ error: 'Direct wearable-brand syncing requires the Complete plan' });
  }
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
  // Same tier3 reasoning as /api/watch/connect/:provider above — this is
  // Open Wearables (direct OAuth) connection status specifically.
  if (!hasDeviceTier(req.userObj, 'tier3')) {
    return res.status(403).json({ error: 'Direct wearable-brand syncing requires the Complete plan' });
  }
  if (!req.userObj.openWearablesUserId || !OW_API_KEY) return res.json({ connections: [] });
  try {
    const r = await fetch(`${OW_BASE_URL}/api/v1/users/${req.userObj.openWearablesUserId}/connections`, {
      headers: { 'X-Open-Wearables-API-Key': OW_API_KEY },
    });
    if (!r.ok) return res.json({ connections: [] });
    res.json({ connections: await r.json() });
  } catch {
    res.json({ connections: [] });
  }
});

// ─── PUSH NOTIFICATIONS ───────────────────────────────────────────────────────
// Device tokens are what a mobile client gets from Firebase Cloud Messaging
// (or the browser's push API for web) and gives to us so we know where to
// send a notification. Actual sending lives in push.js / reminders.js — this
// is just the real, per-user store of "which devices should this user's
// notifications go to."
app.post(`${BASE}/api/push/register`, auth, (req, res) => {
  const { token, platform } = req.body;
  if (!token) return res.status(400).json({ error: 'Missing token' });
  const pushTokens = load('push_tokens.json') || {};
  const devices = (pushTokens[req.user.id] || []).filter(d => d.token !== token);
  devices.push({ token, platform: platform || 'unknown', registeredAt: new Date().toISOString() });
  pushTokens[req.user.id] = devices;
  save('push_tokens.json', pushTokens);
  res.json({ ok: true });
});
app.post(`${BASE}/api/push/unregister`, auth, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Missing token' });
  const pushTokens = load('push_tokens.json') || {};
  pushTokens[req.user.id] = (pushTokens[req.user.id] || []).filter(d => d.token !== token);
  save('push_tokens.json', pushTokens);
  res.json({ ok: true });
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
      // Kept in sync with POST /api/watch/sync's field set (Connected
      // Health Platform Phase 1) so a fresh row looks identical regardless
      // of which ingestion path (this webhook, or a client POST) created
      // it first — no OW webhook event maps to these today, but a future
      // one (e.g. a weight-scale integration) shouldn't have to remember
      // to add itself here too.
      weight: null, bloodPressureSystolic: null, bloodPressureDiastolic: null,
      bloodGlucose: null, temperature: null, bodyFat: null, hrv: null, recovery: null,
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
  } catch {
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
  // Vertical-escalation block (independent audit, Part 6/A01): impersonating
  // another admin previously had no restriction, and — because the old
  // token-minting call silently dropped its own "_impersonated" marker —
  // would have produced a real, full-lifetime admin session indistinguishable
  // from a genuine one. Blocked outright; there is no legitimate support
  // workflow that requires one admin to act as another admin's identity.
  if (u.role === 'admin') {
    secLog('ADMIN_IMPERSONATE_BLOCKED', getIP(req), { adminId: req.user.id, targetUser: u.username, reason: 'target is admin' });
    return res.status(403).json({ error: 'Cannot impersonate another admin account' });
  }
  const token = mkToken(u, req.user.id);
  secLog('ADMIN_IMPERSONATE', getIP(req), { adminId: req.user.id, targetUser: u.username });
  res.json({ ok: true, token, username: u.username, plan: u.plan });
});

// ─── WEATHER & HYDRATION ─────────────────────────────────────────────────────
const weatherCache = new Map();
// Both real readers (server.js:1871, 4337) already treat an entry as stale
// past 10 minutes and never read it again — but neither ever deleted it, so
// the map grew by one entry per distinct ~1km grid cell ever queried, for
// the life of the process, unbounded. Same cleanup shape already
// established for the rate-limiter Map (rl, see the setInterval a few
// hundred lines above) — evicting anything already past the same 10-minute
// staleness window the readers use, on the same kind of periodic sweep.
setInterval(() => { const now = Date.now(); for (const [k, v] of weatherCache) if (now - v.ts > 10 * 60 * 1000) weatherCache.delete(k); }, 10 * 60 * 1000);

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
// Each entry is {text, allergens} — allergens tagged from the dish's own
// real ingredients (e.g. yogurt/cheese → milk, shrimp → crustaceans) so
// buildWeatherRecs() can filter a user's allergies out before picking,
// the same real enforcement FOOD_DB already gets for logged food.
const f = (text, allergens = []) => ({ text, allergens });
const FOOD_POOLS = {
  veryHot: {
    high: [f('سلطة خيار وبطيخ مثلجة · Chilled cucumber & watermelon salad'), f('زبادي بارد · Cold yogurt', ['milk']), f('خس وخضار نيئة · Raw lettuce & greens'), f('شمام مثلج · Chilled cantaloupe'), f('سلطة جرجير بالليمون · Arugula salad with lemon')],
    mid:  [f('سلطة دجاج خفيفة · Light chicken salad'), f('خيار وطماطم مبردة · Cold cucumber & tomato'), f('جبن قريش · Fresh cheese', ['milk']), f('سلطة تونة خفيفة · Light tuna salad', ['fish']), f('زبادي يوناني بالخيار · Greek yogurt with cucumber', ['milk'])],
    low:  [f('بطيخ وشمام · Watermelon & cantaloupe'), f('خيار بالنعناع · Cucumber with mint'), f('سلطة فواكه مائية · Water-rich fruit salad'), f('عصير برتقال طازج · Fresh orange juice side'), f('سلطة خيار وزبادي · Cucumber & yogurt salad', ['milk'])],
  },
  hot: {
    high: [f('سمك مشوي خفيف · Light grilled fish', ['fish']), f('سلطة خضار طازجة · Fresh vegetable salad'), f('زبادي يوناني · Greek yogurt', ['milk']), f('صدر فراخ بالليمون · Lemon chicken breast'), f('سلطة كينوا بالخضار · Quinoa vegetable salad')],
    mid:  [f('صدر فراخ مشوي · Grilled chicken'), f('سمك خفيف · Light fish', ['fish']), f('سلطة خضروات · Vegetable salad'), f('جمبري مشوي · Grilled shrimp', ['crustaceans']), f('ديك رومي خفيف · Light turkey')],
    low:  [f('صدر فراخ مشوي مع خيار · Grilled chicken with cucumber'), f('عصير طماطم · Tomato juice side'), f('سلطة خضار · Vegetable salad'), f('شوربة خضار باردة · Chilled vegetable soup'), f('سلطة فتوش · Fattoush salad', ['gluten'])],
  },
  mild: {
    high: [f('بروتين متوسط مطبوخ · Moderately cooked protein'), f('شوربة خفيفة · Light soup'), f('خضار سوتيه · Sautéed vegetables'), f('سمك مطهو بالبخار · Steamed fish', ['fish']), f('أرز بالخضار · Rice with vegetables')],
    mid:  [f('بروتين متوسط · Moderate protein'), f('خضار مطبوخة · Cooked vegetables'), f('أرز بني بالخضار · Brown rice with vegetables'), f('دجاج بالفرن · Baked chicken'), f('سلطة دافئة · Warm salad')],
    low:  [f('بروتين متوسط · Moderate protein'), f('خضار مطبوخة بصلصة · Cooked vegetables with sauce'), f('فواكه طازجة · Fresh fruit'), f('شوربة خضار · Vegetable soup'), f('سمك بالليمون · Fish with lemon', ['fish'])],
  },
  cold: {
    high: [f('شوربة عدس دافئة · Warm lentil soup'), f('لحم مطبوخ ببطء · Slow-cooked beef'), f('خضار جذرية مشوية · Roasted root vegetables'), f('شوربة خضار كريمية · Creamy vegetable soup', ['milk']), f('يخنة دجاج · Chicken stew')],
    mid:  [f('شوربة دجاج · Chicken soup'), f('لحم دافئ · Warm beef'), f('خضار مشوية · Roasted vegetables'), f('يخنة لحم · Beef stew'), f('حساء عدس · Lentil soup')],
    low:  [f('شوربة دجاج بالليمون · Chicken soup with lemon'), f('لحم دافئ · Warm beef'), f('خضار مشوية مع زيت زيتون · Roasted vegetables with olive oil'), f('شوربة خضار دافئة · Warm vegetable soup'), f('دجاج محمر بالثوم · Garlic roasted chicken')],
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
// Filters allergen matches out of the pool BEFORE picking (never rotates one
// back in once removed), then returns plain display strings — same shape
// callers already expect, so nothing downstream needs to change.
function pickRotating(pool, count, userAllergies, customAllergyText) {
  const safe = pool.filter(item => {
    if (userAllergies?.length && item.allergens.some(a => userAllergies.includes(a))) return false;
    const [ar, en] = item.text.split(' · ');
    if (allergyKeywordsMatch(ar, en, customAllergyText)) return false;
    return true;
  });
  if (!safe.length) return [];
  const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / 86400000);
  const n = safe.length;
  const picks = [];
  for (let i = 0; i < Math.min(count, n); i++) picks.push(safe[(dayOfYear + i) % n].text);
  return picks;
}

function buildWeatherRecs(temp, humidity, userAllergies = [], customAllergyText = '') {
  // Lint pass (Phase 5): `foods` was pre-initialized to [] here but the
  // if/else-if/else-if/else chain below is exhaustive over every real
  // temp value, so it's always reassigned before the return — the initial
  // [] was dead weight, never the value actually returned. Removed; zero
  // behavior change (confirmed by re-reading every branch).
  let hydrationL, alert = null, foods, drinks = [];

  if      (temp >= 40) { hydrationL = 4.5; alert = 'خطر جفاف شديد — اشرب ماء الآن! · Severe dehydration risk — drink NOW!'; }
  else if (temp >= 35) { hydrationL = 3.5; alert = 'طقس حار جداً — اشرب كل 20 دقيقة · Very hot — drink every 20 min'; }
  else if (temp >= 28) hydrationL = 2.8;
  else if (temp >= 20) hydrationL = 2.2;
  else                 hydrationL = 1.8;

  if (humidity > 80) { hydrationL += 0.5; drinks.push('مشروبات إلكتروليت · Electrolyte drinks'); }
  if (humidity < 30) { hydrationL += 0.3; drinks.push('ماء مع ليمون · Water with lemon'); }

  const hBand = humidityBand(humidity);
  if (temp >= 35) {
    foods = pickRotating(FOOD_POOLS.veryHot[hBand], 3, userAllergies, customAllergyText);
    drinks.push('ماء بارد · Cold water', 'عصير بطيخ · Watermelon juice');
  } else if (temp >= 25) {
    foods = pickRotating(FOOD_POOLS.hot[hBand], 3, userAllergies, customAllergyText);
    drinks.push('ماء · Water', 'ماء جوز هند · Coconut water');
  } else if (temp >= 15) {
    foods = pickRotating(FOOD_POOLS.mild[hBand], 3, userAllergies, customAllergyText);
    drinks.push('ماء دافئ · Warm water', 'شاي أخضر · Green tea');
  } else {
    foods = pickRotating(FOOD_POOLS.cold[hBand], 3, userAllergies, customAllergyText);
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

// Thresholds now come from the lab_tests/lab_reference_ranges tables (see
// db.js's resolveReferenceRange) — the old hardcoded LAB_FLAG_RULES object
// (a byte-for-byte duplicate of dashboard.html's labTests normal ranges)
// is gone; the database is the single source of truth now, seeded from
// exactly those same numbers so this function's behavior is unchanged.
// Still deterministic (not AI-driven) on purpose - automatic supplement/
// food suggestions need to be reliable, unlike the free-text AI narrative
// in analyzeLabResults() which stays presentational-only. creatinine is
// still deliberately excluded: resolveReferenceRange() returns null for
// it (no row was ever seeded), same effective result as it never having
// had a LAB_FLAG_RULES entry — kidney-function values are too clinically
// sensitive for a rule-based consumer suggestion.
//
// Iterates numericResults' own keys rather than a fixed rule list (the
// old version's approach) — equivalent either way: a key present in one
// but not the other was always a no-op in the old code too, since you
// can't threshold-compare an undefined value.
function deriveLabFlags(numericResults) {
  const flags = {};
  if (!numericResults) return flags;
  for (const [id, v] of Object.entries(numericResults)) {
    if (v == null || isNaN(v)) continue;
    const resolved = store.resolveReferenceRange(id);
    if (!resolved) continue;
    if (resolved.range_high != null && v > resolved.range_high) flags[`high_${id}`] = true;
    if (resolved.range_low != null && v < resolved.range_low) flags[`low_${id}`] = true;
  }
  return flags;
}

// Same evaluation as deriveLabFlags, but also returns where each flag's
// threshold actually came from — verified / legacy / population_used /
// source — so a caller can tell a client "this suggestion is based on an
// unverified legacy rule" instead of silently presenting it as confirmed.
// A separate function rather than changing deriveLabFlags' own return
// shape, so its ~3 existing call sites stay completely untouched.
function deriveLabFlagsMeta(numericResults) {
  const flags = {};
  const meta = [];
  if (!numericResults) return { flags, meta };
  for (const [id, v] of Object.entries(numericResults)) {
    if (v == null || isNaN(v)) continue;
    const resolved = store.resolveReferenceRange(id);
    if (!resolved) continue;
    let flagged = null;
    if (resolved.range_high != null && v > resolved.range_high) flagged = `high_${id}`;
    if (resolved.range_low != null && v < resolved.range_low) flagged = `low_${id}`;
    if (flagged) {
      flags[flagged] = true;
      meta.push({
        test_id: id, flag: flagged,
        verified: !!resolved.verified, legacy: resolved.legacy,
        population_used: resolved.population_used,
        source_url: resolved.source_url || null,
      });
    }
  }
  return { flags, meta };
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

// Parallel to buildLabAdvisories — same conditions, same order, same
// length — so index i here always describes advisories[i]. Kept as a
// separate function rather than changing buildLabAdvisories' own return
// type (still a plain string[], all 3 existing callers untouched); this
// one is only consumed by the new advisoryTriggers field below.
function buildAdvisoryTriggers(labFlags) {
  const triggers = [];
  if (labFlags.high_glucose || labFlags.high_hba1c) {
    triggers.push({ triggeredBy: ['glucose', 'hba1c'].filter(id => labFlags[`high_${id}`] || labFlags[`low_${id}`]) });
  }
  if (labFlags.high_tsh || labFlags.low_tsh) {
    triggers.push({ triggeredBy: ['tsh'] });
  }
  return triggers;
}

// Vitamin D can be triggered by either the indoor signal or a low lab
// reading - only ever shown once, with whichever reason(s) actually apply.
// Extracted so /api/lab-results/recommendations (Supplements tab) can show
// the same real, indoor-aware suggestion buildEcoRecommendations() already
// does for the Weather tab, instead of only ever seeing the lab-only
// trigger — same copy, same logic, one source of truth for both.
function buildVitaminDSuggestion(indoorState, labFlags) {
  const vitdReasonsAr = [];
  const vitdReasonsEn = [];
  if (indoorState === 'indoor') {
    vitdReasonsAr.push('التواجد الداخلي لفترات طويلة يقلل التعرض لأشعة الشمس');
    vitdReasonsEn.push('Extended time indoors reduces natural sun exposure');
  }
  if (labFlags?.low_vitd) {
    vitdReasonsAr.push('نتيجة تحليل فيتامين د الأخيرة منخفضة');
    vitdReasonsEn.push('Your latest Vitamin D lab result was low');
  }
  if (!vitdReasonsAr.length) return null;
  return {
    icon: '☀️', nameAr: 'فيتامين د', name: 'Vitamin D',
    whyAr: `${vitdReasonsAr.join(' · ')} · ${vitdReasonsEn.join(' · ')}`,
    link: 'https://www.amazon.eg/s?k=vitamin+d3',
  };
}

// Adds supplement suggestions on top of buildWeatherRecs()'s hydration/food/
// drinks, informed by location (indoor/outdoor), the user's latest synced
// watch entry, and their latest lab-result flags when available. Framed as
// general-wellness suggestions, not diagnostic claims - consistent with this
// app's existing "consult your doctor" tone elsewhere. Degrades gracefully
// with no watch/lab data.
function buildEcoRecommendations(temp, humidity, indoorOutdoor, watchEntry, labFlags, userAllergies, customAllergyText) {
  const base = buildWeatherRecs(temp, humidity, userAllergies, customAllergyText);
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

  const vitaminD = buildVitaminDSuggestion(indoorOutdoor.state, labFlags);
  if (vitaminD) supplements.push(vitaminD);

  supplements.push(...buildLabSupplements(labFlags, { includeVitd: !vitaminD }));

  return { ...base, supplements, advisories: buildLabAdvisories(labFlags), indoorOutdoor: indoorOutdoor.state };
}

// Lab-only supplement suggestions (omega-3 / iron / vitamin D), reused by
// buildEcoRecommendations() above and by the standalone /api/lab-results/
// recommendations endpoint (Supplements tab has no weather/location context).
// includeVitd defaults true; buildEcoRecommendations passes false when it has
// already added a merged indoor+lab Vitamin D card itself, to avoid a duplicate.
// triggeredBy is additive — lists which real test_id(s) actually flagged
// (not every test that *could* have) for this specific suggestion, so a
// client can cross-reference against referenceMetadata (already returned
// by /api/lab-results/recommendations) and show "based on an unverified
// reference range" instead of presenting a suggestion as confirmed.
// Existing consumers that don't read this field are unaffected — every
// other property on these objects is unchanged.
function buildLabSupplements(labFlags, { includeVitd = true } = {}) {
  const supplements = [];
  labFlags = labFlags || {};

  if (includeVitd && labFlags.low_vitd) {
    supplements.push({
      icon: '☀️', nameAr: 'فيتامين د', name: 'Vitamin D',
      whyAr: 'نتيجة تحليل فيتامين د الأخيرة منخفضة · Your latest Vitamin D lab result was low',
      link: 'https://www.amazon.eg/s?k=vitamin+d3',
      triggeredBy: ['vitd'],
    });
  }

  const lipidFlags = ['ldl', 'cholesterol', 'triglycerides', 'hdl'].filter(id =>
    labFlags[`high_${id}`] || labFlags[`low_${id}`]);
  if (lipidFlags.length) {
    supplements.push({
      icon: '🐟', nameAr: 'أوميجا 3', name: 'Omega-3',
      whyAr: 'بناءً على نتائج الدهون في تحليلك الأخير · Based on your latest lipid panel results',
      link: 'https://www.amazon.eg/s?k=omega+3',
      triggeredBy: lipidFlags,
    });
  }

  if (labFlags.low_hemoglobin) {
    supplements.push({
      icon: '🥩', nameAr: 'أطعمة غنية بالحديد', name: 'Iron-rich foods',
      whyAr: 'نتيجة الهيموجلوبين الأخيرة منخفضة · Your latest hemoglobin result was low',
      link: 'https://www.amazon.eg/s?k=iron+supplement',
      triggeredBy: ['hemoglobin'],
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
    recommendations: buildEcoRecommendations(weather.temp, weather.humidity, indoorOutdoor, watchEntry, labFlags, req.userObj.profile?.allergies, req.userObj.profile?.customAllergyText),
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
// Cairo calendar-day string, server-side — matches the client's own
// todayCairo() convention (api.js) used everywhere else "today" boundaries
// matter, so a dwell counter doesn't reset at a random UTC-midnight offset.
function todayCairoServer() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo' }).format(new Date());
}

// Honest, not invented: this ONLY knows "how long since the app first
// noticed you here today" — it has zero visibility into anything before
// that first check, and zero visibility while the app is closed in
// between checks (no background location tracking exists in this app —
// deliberately not built, see the founder discussion this shipped from).
// Persisted per (user, zone, day) so opening the app again later the same
// day continues the same clock instead of restarting it.
function trackZoneDwell(userId, zoneId) {
  const today = todayCairoServer();
  const all = load('geofence_dwell.json') || {};
  if (!all[userId]) all[userId] = {};
  const rec = all[userId][zoneId];
  const now = Date.now();
  if (!rec || rec.date !== today) {
    all[userId][zoneId] = { date: today, firstSeenAt: new Date(now).toISOString() };
    save('geofence_dwell.json', all);
    return 0;
  }
  return +((now - new Date(rec.firstSeenAt).getTime()) / 3600000).toFixed(1);
}

// hoursAtZone-triggered posture nudge — deliberately NOT a diagnostic claim
// (no "you may have a back problem", no test/scan recommended). Just a
// break-and-stretch suggestion, the same category of advice as the
// hydration/snacking notes below, shown only for indoor zone types where
// "sitting a long time" is the realistic scenario (home/work/gym), not
// outdoor.
const POSTURE_TIP_HOURS = 3;
const POSTURE_TIP = 'يبدو أنك هنا منذ فترة طويلة — قف وتمدد لبضع دقائق كل ساعة، وإن شعرت بألم مستمر في الظهر استشر طبيبك · Looks like you\'ve been here a while — stand and stretch for a couple of minutes every hour, and see a doctor if you have ongoing back pain';

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
  let hoursAtZone = null, postureTip = null;
  if (activeZone) {
    hoursAtZone = trackZoneDwell(req.user.id, activeZone.id);
    if (['home', 'work', 'gym'].includes(activeZone.type) && hoursAtZone >= POSTURE_TIP_HOURS) {
      postureTip = POSTURE_TIP;
    }
  }
  res.json({ activeZone, activityNote: activeZone ? (notes[activeZone.type] || null) : null, hoursAtZone, postureTip });
});

// ─── NEARBY FITNESS FACILITIES ──────────────────────────────────────────────
// Activity Plan's "Nearest Running Track / Swimming Pool / Cycling Track"
// buttons (2026-09-01). Tries OpenStreetMap's free Overpass API first,
// across several independent public mirrors — live-tested before this was
// written: real running-track data exists for Cairo, but the public
// endpoints do genuinely 502/504 under load, so a single mirror with no
// fallback would be a real reliability problem, not a hypothetical one.
// Google Places (Text Search, not Nearby Search — neither "running track"
// nor "swimming pool" is a real Google place `type`, so a keyword text
// search is the only way to match these categories at all) is the explicit
// last resort, and ONLY runs if every Overpass mirror comes back empty —
// same "configured providers" gating as ai.js's chatVision(): if
// GOOGLE_PLACES_API_KEY isn't set, that branch is skipped entirely, no
// crash, chain just ends at "none found nearby."
const OVERPASS_MIRRORS = [
  'https://overpass-api.de/api/interpreter',
  'https://overpass.kumi.systems/api/interpreter',
  'https://overpass.openstreetmap.fr/api/interpreter',
];
const NEARBY_FACILITY_QUERY = {
  running_track: (r, lat, lon) => `[out:json][timeout:10];(way["leisure"="track"]["sport"~"running"](around:${r},${lat},${lon});node["leisure"="track"]["sport"~"running"](around:${r},${lat},${lon}););out center 5;`,
  swimming_pool: (r, lat, lon) => `[out:json][timeout:10];(way["leisure"="swimming_pool"](around:${r},${lat},${lon});node["leisure"="swimming_pool"](around:${r},${lat},${lon}););out center 5;`,
  cycling_track: (r, lat, lon) => `[out:json][timeout:10];(way["leisure"="track"]["sport"~"cycling"](around:${r},${lat},${lon});node["leisure"="track"]["sport"~"cycling"](around:${r},${lat},${lon});way["highway"="cycleway"](around:${r},${lat},${lon}););out center 5;`,
};
const GOOGLE_PLACES_QUERY = {
  running_track: 'running track',
  swimming_pool: 'public swimming pool',
  cycling_track: 'cycling track',
};
const FACILITY_LABEL = {
  running_track: { ar: 'مضمار جري', en: 'Running Track' },
  swimming_pool: { ar: 'حمام سباحة', en: 'Swimming Pool' },
  cycling_track: { ar: 'مضمار دراجات', en: 'Cycling Track' },
};

async function fetchWithTimeout(url, opts, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

// Tries every mirror in order, returns the first successful (even if empty)
// result set — a mirror returning "0 elements" is a real answer (nothing
// tagged nearby), not a failure, so it does NOT fall through to the next
// mirror; only a network error / bad status / bad JSON does.
async function queryOverpassMirrors(type, lat, lon) {
  const buildQuery = NEARBY_FACILITY_QUERY[type];
  for (const radius of [8000, 20000]) {
    const query = buildQuery(radius, lat, lon);
    for (const mirror of OVERPASS_MIRRORS) {
      try {
        // Explicit Content-Type + a real User-Agent are required — live-
        // tested and confirmed: without them, overpass-api.de returns 406
        // and overpass.openstreetmap.fr returns 403 (Node's fetch defaults
        // differ from curl's, which is what the initial live test used).
        const r = await fetchWithTimeout(mirror, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'HealthPaceApp/1.0 (contact: info@talabatito.com)' },
          body: `data=${encodeURIComponent(query)}`,
        }, 12000);
        if (!r.ok) throw new Error(`${mirror} responded ${r.status}`);
        const data = await r.json();
        const elements = data.elements || [];
        if (elements.length > 0) return elements;
      } catch (e) {
        console.error(`[nearby-facility] Overpass mirror failed (${mirror}):`, e.message);
      }
    }
    // Every mirror returned genuinely zero results at this radius — worth
    // one retry at a wider radius before giving up, since a real running
    // track 9km away is a better answer than "none found" at 8km.
  }
  return [];
}

function nearestFromOverpass(elements, lat, lon) {
  let best = null;
  for (const el of elements) {
    const elLat = el.lat ?? el.center?.lat;
    const elLon = el.lon ?? el.center?.lon;
    if (elLat == null || elLon == null) continue;
    const distanceKm = haversineMeters(lat, lon, elLat, elLon) / 1000;
    if (!best || distanceKm < best.distanceKm) {
      best = { name: el.tags?.name || null, lat: elLat, lon: elLon, distanceKm };
    }
  }
  return best;
}

async function queryGooglePlaces(type, lat, lon) {
  if (!process.env.GOOGLE_PLACES_API_KEY) return null;
  try {
    const url = `https://maps.googleapis.com/maps/api/place/textsearch/json?query=${encodeURIComponent(GOOGLE_PLACES_QUERY[type])}&location=${lat},${lon}&radius=20000&key=${process.env.GOOGLE_PLACES_API_KEY}`;
    const r = await fetchWithTimeout(url, {}, 10000);
    if (!r.ok) throw new Error(`Google Places responded ${r.status}`);
    const data = await r.json();
    if (data.status !== 'OK' || !(data.results || []).length) return null;
    let best = null;
    for (const place of data.results) {
      const pLat = place.geometry?.location?.lat, pLon = place.geometry?.location?.lng;
      if (pLat == null || pLon == null) continue;
      const distanceKm = haversineMeters(lat, lon, pLat, pLon) / 1000;
      if (!best || distanceKm < best.distanceKm) {
        best = { name: place.name || null, lat: pLat, lon: pLon, distanceKm };
      }
    }
    return best;
  } catch (e) {
    console.error('[nearby-facility] Google Places fallback failed:', e.message);
    return null;
  }
}

app.get(`${BASE}/api/nearby-facility`, auth, async (req, res) => {
  const type = req.query.type;
  const lat = parseFloat(req.query.lat), lon = parseFloat(req.query.lon);
  if (!NEARBY_FACILITY_QUERY[type]) return res.status(400).json({ error: 'Invalid facility type' });
  if (isNaN(lat) || isNaN(lon)) return res.status(400).json({ error: 'Invalid coordinates' });

  let best = null;
  let source = null;
  try {
    const elements = await queryOverpassMirrors(type, lat, lon);
    best = nearestFromOverpass(elements, lat, lon);
    if (best) source = 'openstreetmap';
  } catch (e) {
    console.error('[nearby-facility] Overpass chain error:', e.message);
  }

  if (!best) {
    best = await queryGooglePlaces(type, lat, lon);
    if (best) source = 'google';
  }

  if (!best) {
    return res.json({ ok: false, error: 'لم نجد أماكن قريبة حالياً، حاول مرة أخرى لاحقاً · No nearby locations found right now, try again later' });
  }

  secLog('NEARBY_FACILITY', getIP(req), { userId: req.user.id, type, source });
  res.json({
    ok: true,
    source,
    // `name` is a real place name when OSM/Google had one tagged, or null —
    // `genericLabel` is always present so the client never has to guess
    // between a string and a bilingual object in the same field.
    name: best.name || null,
    genericLabel: FACILITY_LABEL[type],
    distanceKm: Math.round(best.distanceKm * 10) / 10,
    lat: best.lat,
    lon: best.lon,
    mapsUrl: `https://www.google.com/maps/search/?api=1&query=${best.lat},${best.lon}`,
  });
});

app.use(`${BASE}/*path`,(req,res)=>res.status(404).json({error:'Not found'}));

initData();

// Production hardening pass, Phase 4 (independent audit, DevOps F8.1 — zero
// automated tests existed anywhere): tests need to import the real Express
// `app` and drive it with supertest, without binding a real port (which
// would collide with whatever's already listening on 3200, and doesn't
// scale to parallel test runs). Everything above this point is completely
// unchanged; only the final `.listen()` call is now conditional. Running
// the file directly (`node server.js`, exactly as docker-compose already
// does) still starts the real server exactly as before — this is a no-op
// for every existing deployment path.
if (require.main === module) {
  app.listen(3200, () => console.log('DietHub v3 SECURE on port 3200'));
}
// Curated internal-function exports for real unit testing (Phase 4) — every
// name here is an existing, unmodified function already defined above;
// exporting them is additive and changes no behavior for the real running
// app, which only ever uses `module.exports` as `app` (require.main check
// above). Deliberately NOT exporting everything — only the real
// security/business-logic-critical functions worth testing in true
// isolation, per the hardening prompt's own "prioritize risk, not
// percentage" instruction.
module.exports = Object.assign(app, {
  _testables: {
    hashPwd, checkPwd, mkToken, checkToken,
    sanitize, validateUsr, validatePwd,
    validateProfileField,
    kashierVerify, kashierHash, kashierConfigured,
    hasActiveCoverage, calcBmiBmr,
  },
});
