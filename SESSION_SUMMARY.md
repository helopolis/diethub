# DietHub — Session Summary & Deployment Guide

**What this is:** everything built in this working session, and exactly how to get it
live on `diet.talabatito.com`. All the work is committed to GitHub but **not yet
running on your server**.

- **Repository:** `helopolis/diethub`
- **Branch with all the work:** `claude/diet-talabatito-review-2u47ds`
- **Status:** 9 commits ahead of `master`. None are deployed to production yet.

---

## ⚠️ Read first: the code and the live site have diverged

Two facts that shape the whole deployment:

1. **None of this work is live yet.** It lives in the GitHub branch above. Your server
   at `diet.talabatito.com` has never received it.
2. **Your live server has changes that are NOT in GitHub** — e.g. the dashboard hero
   showing **BMR (1803)** and **BMI (30.4)**, and extra diet options like
   *"المرأة فوق الأربعين"*. Those exist on the server only, in no git commit.

**Therefore: do NOT blindly overwrite the server with this branch — you'd lose the
live-only changes.** Follow the safe reconciliation order in the Deployment section:
**back up → capture the live code into git → merge → deploy once**.

There is also a **live bug** to fix while reconciling: on production, the *diet* field
shows *"المرأة فوق الأربعين"* (a demographic group) instead of a diet name (Atkins,
Keto…). That code isn't in git, so it must be fixed on the server side during the merge.

---

## What was built (9 commits)

### 1. Security — rate limiter hardened (`d186cd6`)
`getIP()` trusted the client `X-Forwarded-For` header, so anyone could spoof it to reset
their own rate-limit bucket (defeating login/brute-force/registration/reset throttles).
Now uses Express `trust proxy` + `req.ip`. Configurable via `TRUST_PROXY`.
- **Files:** `server.js`

### 2. Real database — SQLite replaces flat JSON files (`f2d9d1b`)
The old storage rewrote whole JSON files per request → corruption under concurrent writes,
no backups, single-server only. New `db.js` is a SQLite-backed document store with the
**same interface**, so it was a small, safe change. Adds atomic writes, WAL durability, a
transactional `update()`, one-time **migration of your existing JSON data**, and an admin
**backup** endpoint.
- **Files:** `db.js` (new), `server.js`, `.gitignore`
- **New endpoint:** `GET /diet/api/admin/backup` (downloads a live DB snapshot)
- **Verified:** 1,600 concurrent cross-process writes, zero lost.

### 3. Analytics / event pipeline (`a8f7564`)
An append-only `events` table that powers the metrics investors ask for (funnel,
trial→paid, CAC by source, retention) **and** doubles as your **n8n automation trigger**
source. Lifecycle events instrumented: `user_registered`, `trial_started`,
`email_verified`, `login`, `meal_plan_viewed`, `paywall_hit`, `checkout_started`,
`subscription_paid`. Set `N8N_WEBHOOK_URL` to forward every event to n8n.
- **Files:** `db.js`, `server.js`
- **New endpoints:** `GET /diet/api/admin/analytics`, `GET /diet/api/admin/events`,
  `POST /diet/api/track` (public top-of-funnel ingest with UTM)

### 4. Secure Kashier payments (`cff2260`, `c2e904e`)
The old flow was unsafe on both ends: the browser computed the hash with the **API key
embedded in `payment.html`** (key exposed), and `confirm` marked users paid on a
**client-posted claim** (anyone could unlock a paid plan for free). Rebuilt:
- **initiate (server):** signs the order with the Payment API Key, returns Kashier's
  hosted checkout URL. Key stays server-side. Hash matches Kashier's published test vector.
- **webhook (server-to-server):** the **only** authoritative grant. Verifies the
  HMAC-SHA256 signature, checks the amount, is idempotent, then marks the user paid.
- **confirm:** downgraded to a status poll for the return page.
- **Also fixed:** the expired-trial paywall gate that blocked lapsed users from the very
  page where they pay.
- **Files:** `server.js`, `public/payment.html`
- **New endpoint:** `POST /diet/api/payment/webhook`
- **Verified:** forged signatures & amount tampering rejected; confirm can't self-grant;
  valid webhook grants access; replays idempotent.

### 5. Unified health profile — the ecosystem hub (`0f25562`)
`health.js` assembles demographics + goals + wearables + labs + nutrition into one object
with derived **BMR, TDEE, calorie/protein/hydration targets** and **risk flags**
(obesity, out-of-range labs, low sleep, high heart rate, low-carb lab reminder, no recent
logging). This is the single source of truth the coach and every module reads from.
- **Files:** `health.js` (new), `server.js`
- **New endpoints:** `GET /diet/api/health-profile`,
  `POST /diet/api/health-profile/goals`

### 6. AI coach wired to the hub (`e9b7fcb`)
The coach previously saw only diet/weight/height/age → generic advice. Now it reads the
full health profile (targets, wearables, lab status, risk flags) as an Arabic briefing and
is told to use the user's real numbers, address flags first, and defer to a doctor on
critical findings.
- **Files:** `health.js`, `server.js`

### 7. Free LLM providers — no more paid-only Anthropic (`01ef9f7`)
`ai.js` — one `chat()` interface with three adapters selected by env var, so you can run
**free now** and switch later with **no code change**:
- **Gemini** (default `gemini-2.5-flash`, free tier ~1k req/day, no card) — **recommended**
- **Groq** (default `llama-3.3-70b-versatile`, free tier)
- **Anthropic** (paid; use when you have income)

Auto-detects from whichever key is set, preferring free ones. Coach + lab analysis both
route through it.
- **Files:** `ai.js` (new), `server.js`

### 8. Live dashboard health card (`7c16252`)
Replaced the hardcoded home stats (static "1,650 kcal / 3 urgent labs") with a live card
driven by `/api/health-profile`: real BMI, calorie/protein/hydration targets, TDEE, 7-day
avg steps, and the user's risk flags. Bilingual.
- **Files:** `public/dashboard.html`

---

## Environment variables to set on the server

Set these in your process manager / `.env` (whatever the server uses). **Never** put keys
in code or commit them.

```bash
# --- Core (set these in production) ---
JWT_SECRET=<long random string>          # session signing — MUST be set, don't use the default
DATA_DIR=/data/diethub                   # where the DB + data live (default is fine)
TRUST_PROXY=loopback                     # if behind nginx on the same box; else "false"
PUBLIC_BASE_URL=https://diet.talabatito.com

# --- Free AI provider (pick ONE; Gemini recommended) ---
GEMINI_API_KEY=<from aistudio.google.com — free, no card>
# GEMINI_MODEL=gemini-2.5-flash          # optional override
# or Groq instead:
# GROQ_API_KEY=<from console.groq.com — free>
# Later, when you have income:
# ANTHROPIC_API_KEY=<paid>

# --- Kashier payments (from dashboard → Developers → API Keys) ---
KASHIER_MERCHANT_ID=MID-45130-316
KASHIER_PAYMENT_API_KEY=<your Payment API Key — TEST first>
KASHIER_MODE=test                        # switch to "live" after approval + live key

# --- Existing (keep if already set) ---
GMAIL_USER=...                           # email verification / password reset
GMAIL_APP_PASS=...
OPENWEATHER_KEY=...                      # weather & hydration feature

# --- Optional ---
N8N_WEBHOOK_URL=https://n8n.talabatito.com/webhook/diethub-events  # forward events to n8n
```

---

## Kashier go-live checklist

1. **Dashboard → Developers → API Keys →** copy the **Payment API Key** (Test) →
   `KASHIER_PAYMENT_API_KEY`. (Merchant ID `MID-45130-316` is already known.)
2. **Dashboard → Developers → Webhooks → Add Webhook →**
   `https://diet.talabatito.com/diet/api/payment/webhook`
3. Keep `KASHIER_MODE=test`, run one test payment (Kashier **Testing** docs have test
   cards). The webhook flips the user to paid automatically; it shows on the **Payments**
   page.
4. Get Kashier to **fill in the blank fee percentages** in your contract (needed for
   margins) and add a visible **refund + delivery policy** to the payment page (contract
   clause 6-12 requires it before checkout).
5. When approved: switch dashboard to Live, use the **Live** Payment API Key, set
   `KASHIER_MODE=live`. Consider **rolling (regenerating)** the test key you screenshotted.
6. Note: your Kashier business is registered **Medical / Pharmacy** — confirm that's right
   for a SaaS subscription, or change to health-tech/software (may speed approval).

---

## Deployment — the safe order (nothing gets lost)

Run these **on your Contabo server yourself**. Replace `APP_DIR` with the real path
(find it with `find / -name server.js -path '*diet*' 2>/dev/null`).

```bash
# 0) Find how the app runs and where it lives
ps aux | grep -iE 'node|pm2' | grep -v grep
pm2 list 2>/dev/null
APP_DIR=/path/to/diethub          # <-- set this from the find command

# 1) BACK UP FIRST — non-negotiable (real users/payments live here)
cp -r /data/diethub  /root/backup_data_$(date +%F)
cp -r "$APP_DIR"     /root/backup_code_$(date +%F)

# 2) Capture the CURRENT LIVE code into git so live-only changes aren't lost
cd "$APP_DIR"
git status                         # if this is NOT a git repo, tell me — we init one
git checkout -b live-production-snapshot
git add -A && git commit -m "Snapshot of live production before merge"
git push origin live-production-snapshot    # needs the repo remote; I'll help if missing

# 3) Bring in the session work
git fetch origin
git merge origin/claude/diet-talabatito-review-2u47ds   # resolve any conflicts (I'll guide)

# 4) Install deps, set env vars, restart
npm install                        # pulls better-sqlite3
#   ...set the env vars from the section above...
pm2 restart diethub || pm2 start server.js --name diethub   # or your systemd unit

# 5) Verify
curl -s http://localhost:3200/diet/health     # expect {"status":"ok",...}
#   then log into the site and check: dashboard health card, a test payment
```

**Rollback if anything breaks:** stop the app, restore `/root/backup_code_*` and
`/root/backup_data_*`, restart. That's why step 1 exists.

> The SQLite migration (step 4) **auto-imports your existing JSON data** on first run, so
> users carry over. The backup in step 1 is still mandatory.

---

## Known issues & pending

- **Live diet-field bug:** production shows *"المرأة فوق الأربعين"* as a diet. Fix the
  user's profile data or the diet dropdown during reconciliation (server-side code).
- **Security follow-up:** the root SSH password was shared in chat — **change it**
  (`passwd`) and ideally move to SSH keys + disable password login.
- **Pending build — "1M-people dataset":** an LLM is **not** trained by importing a CSV.
  The valuable version is **population benchmarks** ("your BMI is higher than X% of men
  your age") + an optional risk-score model from a public dataset (CDC BRFSS / NHANES).
  To be built after deployment is sorted.

---

## Testing done this session

- Rate limiter: spoofed `X-Forwarded-For` ignored when not from a trusted proxy.
- Database: 1,600 concurrent cross-process writes → zero lost updates; legacy JSON
  migration + admin backup verified.
- Analytics: full funnel (page_view → register → verify → activate → checkout → paid) with
  UTM attribution.
- Payments: forged signature & amount-tamper rejected; confirm can't self-grant; valid
  webhook grants access; idempotent replays; expired users can reach checkout.
- Health profile: BMR/TDEE/BMI/protein match hand-computed values; risk flags correct;
  targets recompute on goal change.
- Coach: gating holds; enriched prompt builds and reaches the AI call.
- LLM providers: request shape + response parsing verified for Gemini, Groq, Anthropic.
