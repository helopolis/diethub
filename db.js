// ─── DATA LAYER ───────────────────────────────────────────────────────────────
// SQLite-backed document store. Presents the same key→JSON interface the app
// already used with flat files (load('users.json'), save('users.json', data)),
// but every write is now atomic, durable (WAL), and safe under concurrency —
// no more half-written files or lost updates. All access goes through here, so
// swapping the backend to Postgres later is an isolated change, not a rewrite.

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR || '/data/diethub';
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'diethub.db');

// The directory must exist before the DB file can be opened.
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');   // concurrent readers + atomic commits
db.pragma('synchronous = NORMAL'); // durable, good throughput on WAL
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');  // wait, don't fail, on a momentary write lock

db.exec(`CREATE TABLE IF NOT EXISTS documents (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
)`);

const selStmt    = db.prepare('SELECT value FROM documents WHERE key = ?');
const upsertStmt = db.prepare(`INSERT INTO documents (key, value, updated_at)
  VALUES (@key, @value, @updated_at)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`);

// ─── LAB REFERENCE DATA ─────────────────────────────────────────────────────
// Real relational tables, not the key→JSON document store above — reference
// data is lookup-heavy and naturally relational (a test has many reference
// ranges, one per population), the same reasoning that put `events` in a
// real table instead of a JSON blob.
//
// LOINC is the canonical test identifier (lab_tests.loinc_code), per the
// founder's own architecture call: reference ranges live in a *separate*,
// versioned table (lab_reference_ranges) keyed by population (age/sex/
// pregnancy/etc.), not baked into the test row — so adding a pediatric or
// pregnancy range later is a new row, not a schema change. Shaped to map
// cleanly onto a FHIR Observation: loinc_code -> Observation.code.coding,
// each reference_ranges row -> one Observation.referenceRange entry.
//
// IMPORTANT — verification status: seedLabTests() below (see server.js's
// pre-existing LAB_FLAG_RULES) populates this with the app's own long-
// standing threshold numbers, migrated as-is into this better structure —
// it does NOT invent new medical values. Every seeded range has `verified =
// 0` and `source_url = NULL` until someone actually checks it against a
// real cited source (MedlinePlus / Mayo Clinic Labs / LOINC's own registry
// were the plan, blocked this session on the web-search quota — see the
// founder conversation this schema came out of). Treat `verified = 0` rows
// as "inherited from the old hardcoded rule, not yet independently
// confirmed" — not as validated clinical content.
db.exec(`CREATE TABLE IF NOT EXISTS lab_tests (
  test_id      TEXT PRIMARY KEY,
  loinc_code   TEXT UNIQUE,
  name         TEXT NOT NULL,
  name_ar      TEXT NOT NULL,
  category     TEXT NOT NULL,
  specimen     TEXT,
  units        TEXT NOT NULL,
  si_units     TEXT,
  fasting_required INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
)`);
// Added after the initial table: SQLite has no `ADD COLUMN IF NOT EXISTS`,
// so this checks pragma_table_info first — safe to run on every boot.
// flaggable exists because creatinine needs to stay in lab_tests (it's a
// manual-entry field real users already fill in) without ever being
// auto-flagged: kidney-function values were deliberately excluded from
// rule-based flagging (too clinically sensitive), and that safety property
// needs to survive in the new schema, not just be an accident of which
// tests happened to be in the old hardcoded LAB_FLAG_RULES object.
const hasFlaggable = db.prepare("SELECT 1 FROM pragma_table_info('lab_tests') WHERE name='flaggable'").get();
if (!hasFlaggable) db.exec('ALTER TABLE lab_tests ADD COLUMN flaggable INTEGER NOT NULL DEFAULT 1');

db.exec(`CREATE TABLE IF NOT EXISTS lab_reference_ranges (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  test_id       TEXT NOT NULL REFERENCES lab_tests(test_id),
  population    TEXT NOT NULL, -- 'adult_general' | 'adult_male' | 'adult_female' | 'pregnancy' | 'pediatric' | 'elderly'
  range_low     REAL,
  range_high    REAL,
  critical_low  REAL,
  critical_high REAL,
  unit          TEXT NOT NULL,
  verified      INTEGER NOT NULL DEFAULT 0, -- 0 until checked against source_url
  source_name   TEXT,
  source_url    TEXT,
  version_date  TEXT NOT NULL,
  notes         TEXT,
  created_at    TEXT NOT NULL
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_ranges_test_id ON lab_reference_ranges(test_id)`);

const upsertLabTestStmt = db.prepare(`INSERT INTO lab_tests
    (test_id,loinc_code,name,name_ar,category,specimen,units,si_units,fasting_required,flaggable,created_at,updated_at)
  VALUES (@test_id,@loinc_code,@name,@name_ar,@category,@specimen,@units,@si_units,@fasting_required,@flaggable,@now,@now)
  ON CONFLICT(test_id) DO NOTHING`);

const insRangeStmt = db.prepare(`INSERT INTO lab_reference_ranges
    (test_id,population,range_low,range_high,critical_low,critical_high,unit,verified,source_name,source_url,version_date,notes,created_at)
  VALUES (@test_id,@population,@range_low,@range_high,@critical_low,@critical_high,@unit,@verified,@source_name,@source_url,@version_date,@notes,@now)`);

// Every query joins lab_tests and requires flaggable=1 — creatinine has a
// real reference_ranges row (for the manual-entry display hint) but
// flaggable=0, so this always returns null for it regardless, the same as
// if no row existed at all. That's deliberate: kidney-function values were
// excluded from rule-based flagging as too clinically sensitive, and that
// safety property must hold no matter what data exists, not depend on
// every future caller remembering to check it themselves.
const exactVerifiedStmt = db.prepare(`SELECT r.* FROM lab_reference_ranges r
  JOIN lab_tests t ON t.test_id = r.test_id
  WHERE r.test_id=? AND r.population=? AND r.verified=1 AND t.flaggable=1
  ORDER BY r.version_date DESC LIMIT 1`);
const generalVerifiedStmt = db.prepare(`SELECT r.* FROM lab_reference_ranges r
  JOIN lab_tests t ON t.test_id = r.test_id
  WHERE r.test_id=? AND r.population='adult_general' AND r.verified=1 AND t.flaggable=1
  ORDER BY r.version_date DESC LIMIT 1`);
const exactAnyStmt = db.prepare(`SELECT r.* FROM lab_reference_ranges r
  JOIN lab_tests t ON t.test_id = r.test_id
  WHERE r.test_id=? AND r.population=? AND t.flaggable=1
  ORDER BY r.version_date DESC LIMIT 1`);
const generalAnyStmt = db.prepare(`SELECT r.* FROM lab_reference_ranges r
  JOIN lab_tests t ON t.test_id = r.test_id
  WHERE r.test_id=? AND r.population='adult_general' AND t.flaggable=1
  ORDER BY r.version_date DESC LIMIT 1`);

// Fallback search order (never silently substitutes one population's data
// for another without saying so):
//   1. an exact match for the requested population, itself verified
//   2. a verified adult_general default
//   3. legacy compatibility — whatever unverified row exists (requested
//      population first, else adult_general) — flagged legacy:true so a
//      caller can never mistake this for confirmed clinical data
//   4. null — genuinely nothing usable for this test_id: either no row
//      exists at all, or (creatinine's case) flaggable=0
// Logs once per call when legacy data is used — test_id + populations
// only, no user data, so this is safe to leave on in production.
function resolveReferenceRange(testId, population = 'adult_general') {
  let row = exactVerifiedStmt.get(testId, population);
  if (row) return { ...row, legacy: false, population_used: population };

  row = generalVerifiedStmt.get(testId);
  if (row) return { ...row, legacy: false, population_used: 'adult_general' };

  row = exactAnyStmt.get(testId, population) || generalAnyStmt.get(testId);
  if (row) {
    console.log('[lab-reference] legacy fallback used', {
      test_id: testId, population_requested: population,
      population_on_row: row.population, verified: !!row.verified,
      reason: 'no verified reference range exists for this test/population yet',
    });
    return { ...row, legacy: true, population_used: 'legacy' };
  }

  return null;
}

function getLabTest(testId) {
  return db.prepare('SELECT * FROM lab_tests WHERE test_id = ?').get(testId) || null;
}
function listLabTests() {
  return db.prepare('SELECT * FROM lab_tests ORDER BY category, name').all();
}
function getReferenceRanges(testId) {
  return db.prepare('SELECT * FROM lab_reference_ranges WHERE test_id = ? ORDER BY population').all(testId);
}
// Only inserts a test's ranges the first time it's seeded (checked via the
// test_id upsert's own no-op-on-conflict) — safe to call on every boot
// without duplicating rows on restart, same discipline as migrateFromJson.
// Wrapped in a transaction: without this, a crash between the test-row
// insert and its range-row inserts would leave a lab_test with zero
// reference_ranges — a real (if unlikely) data-integrity gap in the
// original version of this function.
const _seedTxn = db.transaction((test, ranges, now) => {
  // flaggable defaults to 1 (most tests can be auto-flagged); only
  // creatinine seeds with flaggable:0 explicitly.
  const result = upsertLabTestStmt.run({ flaggable: 1, ...test, now });
  if (result.changes > 0) {
    for (const r of ranges) insRangeStmt.run({ ...r, test_id: test.test_id, now });
  }
});
function seedLabTest(test, ranges) {
  _seedTxn(test, ranges, new Date().toISOString());
}

// Migrates the app's own pre-existing numbers — server.js's LAB_FLAG_RULES
// thresholds and public/dashboard.html's labTests names/units — into the
// structure above. Deliberately NOT new medical content: every value here
// already lived in this codebase (in two separate places, actually — this
// also consolidates them into one). `verified: 0` and `source_url: null`
// on every row because neither original location ever cited an external
// source; that verification pass is a real follow-up, not done here.
function seedLabReferenceData() {
  const range = (over) => ({
    population: 'adult_general', range_low: null, range_high: null,
    critical_low: null, critical_high: null, verified: 0,
    source_name: 'Health Pace internal (pre-existing app threshold, not yet independently verified)',
    source_url: null, version_date: new Date().toISOString().slice(0, 10), notes: null,
    ...over,
  });
  seedLabTest(
    { test_id: 'glucose', loinc_code: null, name: 'Blood Glucose', name_ar: 'سكر الدم (Glucose)', category: 'Diabetes', specimen: null, units: 'mg/dL', si_units: null, fasting_required: 1 },
    [range({ range_low: 70, range_high: 100, unit: 'mg/dL' })]
  );
  seedLabTest(
    { test_id: 'hba1c', loinc_code: null, name: 'HbA1c', name_ar: 'HbA1c', category: 'Diabetes', specimen: null, units: '%', si_units: null, fasting_required: 0 },
    [range({ range_high: 5.7, unit: '%' })]
  );
  seedLabTest(
    { test_id: 'cholesterol', loinc_code: null, name: 'Total Cholesterol', name_ar: 'الكوليسترول الكلي', category: 'Lipid Profile', specimen: null, units: 'mg/dL', si_units: null, fasting_required: 0 },
    [range({ range_high: 200, unit: 'mg/dL' })]
  );
  seedLabTest(
    { test_id: 'ldl', loinc_code: null, name: 'LDL Cholesterol', name_ar: 'LDL (الكوليسترول الضار)', category: 'Lipid Profile', specimen: null, units: 'mg/dL', si_units: null, fasting_required: 0 },
    [range({ range_high: 100, unit: 'mg/dL' })]
  );
  seedLabTest(
    { test_id: 'hdl', loinc_code: null, name: 'HDL Cholesterol', name_ar: 'HDL (الكوليسترول النافع)', category: 'Lipid Profile', specimen: null, units: 'mg/dL', si_units: null, fasting_required: 0 },
    [range({ range_low: 40, unit: 'mg/dL' })]
  );
  seedLabTest(
    { test_id: 'triglycerides', loinc_code: null, name: 'Triglycerides', name_ar: 'الدهون الثلاثية', category: 'Lipid Profile', specimen: null, units: 'mg/dL', si_units: null, fasting_required: 0 },
    [range({ range_high: 150, unit: 'mg/dL' })]
  );
  seedLabTest(
    { test_id: 'hemoglobin', loinc_code: null, name: 'Hemoglobin', name_ar: 'هيموغلوبين', category: 'Complete Blood Count', specimen: null, units: 'g/dL', si_units: null, fasting_required: 0 },
    // Known real gap, carried over honestly rather than silently fixed:
    // dashboard.html's own display already labeled this "M:13.5-17.5"
    // (male-specific), but LAB_FLAG_RULES applies 13.5 as a single
    // blanket low-threshold regardless of sex — a healthy woman around
    // 13.0-13.5 g/dL would be incorrectly flagged low. Needs a real
    // adult_female row once someone sources the correct range; not
    // invented here.
    [range({ range_low: 13.5, unit: 'g/dL', notes: 'Applied as a sex-blind threshold in current app logic; dashboard.html labels this male-specific (M:13.5-17.5). No adult_female row yet — real gap, not yet sourced.' })]
  );
  seedLabTest(
    { test_id: 'vitd', loinc_code: null, name: 'Vitamin D', name_ar: 'فيتامين D', category: 'Vitamins', specimen: null, units: 'ng/mL', si_units: null, fasting_required: 0 },
    [range({ range_low: 30, unit: 'ng/mL' })]
  );
  seedLabTest(
    { test_id: 'tsh', loinc_code: null, name: 'TSH', name_ar: 'TSH (الغدة الدرقية)', category: 'Thyroid', specimen: null, units: 'mIU/L', si_units: null, fasting_required: 0 },
    [range({ range_low: 0.4, range_high: 4.0, unit: 'mIU/L' })]
  );
  // flaggable:0 — creatinine was in dashboard.html's manual-entry form
  // (same 0.6-1.2 mg/dL hint migrated below) but was NEVER in
  // LAB_FLAG_RULES; that exclusion was deliberate (kidney-function values
  // are too clinically sensitive for a rule-based consumer suggestion) and
  // resolveReferenceRange()'s flaggable=1 join means this row can never
  // drive an automatic flag no matter what — restores the original manual-
  // entry field (a real regression this seed's first version introduced by
  // only migrating the 9 LAB_FLAG_RULES tests) without reintroducing
  // automatic kidney-value flagging.
  seedLabTest(
    { test_id: 'creatinine', loinc_code: null, name: 'Creatinine', name_ar: 'كرياتينين', category: 'Kidney Function', specimen: null, units: 'mg/dL', si_units: null, fasting_required: 0, flaggable: 0 },
    [range({ range_low: 0.6, range_high: 1.2, unit: 'mg/dL', notes: 'Display-only — flaggable=0, deliberately never used for automatic flagging (see LAB_FLAG_RULES history / kidney-function safety note).' })]
  );
}
seedLabReferenceData();

// ─── EVENTS ─────────────────────────────────────────────────────────────────
// Append-only analytics log. This is a real table, not a JSON document, because
// events are high-volume and append-heavy — exactly the access pattern the
// document store is wrong for. Feeds the funnel/CAC/retention metrics and the
// n8n automation triggers.
db.exec(`CREATE TABLE IF NOT EXISTS events (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           TEXT NOT NULL,
  name         TEXT NOT NULL,
  user_id      TEXT,
  anon_id      TEXT,
  props        TEXT,
  ip           TEXT,
  utm_source   TEXT,
  utm_medium   TEXT,
  utm_campaign TEXT
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_events_name_ts ON events(name, ts)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_events_user   ON events(user_id)`);

const insEvent = db.prepare(`INSERT INTO events
  (ts,name,user_id,anon_id,props,ip,utm_source,utm_medium,utm_campaign)
  VALUES (@ts,@name,@user_id,@anon_id,@props,@ip,@utm_source,@utm_medium,@utm_campaign)`);

function logEvent(e) {
  insEvent.run({
    ts: new Date().toISOString(),
    name: String(e.name).slice(0, 64),
    user_id: e.userId || null,
    anon_id: e.anonId || null,
    props: JSON.stringify(e.props || {}),
    ip: e.ip || null,
    utm_source: e.utmSource || null,
    utm_medium: e.utmMedium || null,
    utm_campaign: e.utmCampaign || null,
  });
}

function safeParse(s) { try { return JSON.parse(s); } catch { return {}; } }

// Recent raw events, newest first — for the admin activity feed / debugging.
function recentEvents(limit = 100) {
  return db.prepare(`SELECT id,ts,name,user_id,anon_id,props,ip,utm_source
    FROM events ORDER BY id DESC LIMIT ?`).all(limit).map(r => ({ ...r, props: safeParse(r.props) }));
}

// The numbers investors ask for: acquisition funnel, conversion, CAC-by-source
// inputs, and a daily time series — all over the last `days` window.
function analytics(days = 30) {
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const distinct = (name) => db.prepare(
    `SELECT COUNT(DISTINCT user_id) n FROM events WHERE name=? AND ts>=? AND user_id IS NOT NULL`
  ).get(name, since).n;

  const registered = distinct('user_registered');
  const verified   = distinct('email_verified');
  const activated  = distinct('meal_plan_viewed');
  const checkout   = distinct('checkout_started');
  const paid        = distinct('subscription_paid');
  const pct = (a, b) => (b ? +((a / b) * 100).toFixed(1) : 0);

  const byEvent = db.prepare(
    `SELECT name, COUNT(*) count, COUNT(DISTINCT user_id) users
     FROM events WHERE ts>=? GROUP BY name ORDER BY count DESC`).all(since);

  // Registrations grouped by acquisition source — the denominator for CAC once
  // you divide each channel's spend by the users it brought in.
  const bySource = db.prepare(
    `SELECT COALESCE(utm_source,'direct') source,
            COUNT(DISTINCT COALESCE(user_id,anon_id)) registrations
     FROM events WHERE name='user_registered' AND ts>=?
     GROUP BY source ORDER BY registrations DESC`).all(since);

  const daily = db.prepare(
    `SELECT substr(ts,1,10) day,
            SUM(CASE WHEN name='user_registered'  THEN 1 ELSE 0 END) registered,
            SUM(CASE WHEN name='subscription_paid' THEN 1 ELSE 0 END) paid
     FROM events WHERE ts>=? GROUP BY day ORDER BY day`).all(since);

  return {
    days,
    funnel: [
      { step: 'Registered',              users: registered, pct: 100 },
      { step: 'Email verified',          users: verified,   pct: pct(verified, registered) },
      { step: 'Activated (viewed plan)', users: activated,  pct: pct(activated, registered) },
      { step: 'Checkout started',        users: checkout,   pct: pct(checkout, registered) },
      { step: 'Paid',                    users: paid,       pct: pct(paid, registered) },
    ],
    trialToPaidPct: pct(paid, registered),
    byEvent, bySource, daily,
  };
}

// Read a document. Returns the parsed JSON, or null if the key doesn't exist
// (matching the old load() contract so callers' `|| []` / `|| {}` still work).
function load(key) {
  const row = selStmt.get(key);
  if (!row) return null;
  try { return JSON.parse(row.value); } catch { return null; }
}

// Write a document, replacing it wholesale. Atomic and durable.
function save(key, data) {
  upsertStmt.run({ key, value: JSON.stringify(data), updated_at: new Date().toISOString() });
  return data;
}

// Atomic read-modify-write. Runs the mutator inside an IMMEDIATE transaction so
// two concurrent updates to the same key can't lose each other's changes — the
// second waits for the first to commit, then sees its result. `mutator` receives
// the current value (or `fallback` if absent) and returns the value to store.
const _txn = db.transaction((key, mutator, fallback) => {
  const current = load(key) ?? fallback;
  const next = mutator(current);
  save(key, next);
  return next;
});
function update(key, mutator, fallback = null) {
  return _txn.immediate(key, mutator, fallback);
}

// One-time import of any legacy flat-file JSON into the store. Skips keys that
// already exist in the DB, so it's safe to run on every boot.
function migrateFromJson(dir, keys) {
  const migrated = [];
  for (const key of keys) {
    if (selStmt.get(key)) continue;            // already in DB
    const fp = path.join(dir, key);
    if (!fs.existsSync(fp)) continue;          // no legacy file
    try {
      save(key, JSON.parse(fs.readFileSync(fp, 'utf8')));
      migrated.push(key);
    } catch (e) {
      console.error(`[db] migrate failed for ${key}:`, e.message);
    }
  }
  if (migrated.length) console.log(`[db] migrated ${migrated.length} legacy file(s): ${migrated.join(', ')}`);
  return migrated;
}

// Write a fully-consistent snapshot of the whole database to `dest`.
// VACUUM INTO is transactional, so the copy is safe to take while the app runs.
function backup(dest) {
  db.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);
  return dest;
}

module.exports = { db, load, save, update, migrateFromJson, backup,
  logEvent, recentEvents, analytics, DB_PATH, DATA_DIR,
  seedLabTest, getLabTest, listLabTests, getReferenceRanges, resolveReferenceRange };
