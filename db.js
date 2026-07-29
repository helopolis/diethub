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
  logEvent, recentEvents, analytics, DB_PATH, DATA_DIR };
