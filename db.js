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

// ─── DOMAIN LOOKUP TABLES ───────────────────────────────────────────────────
// Phase 1 of the nutrition-architecture migration (see the architecture
// audit this came out of): the smallest, lowest-risk slice first — 4 short,
// static enums that previously existed ONLY as JavaScript array/object
// literals in server.js/health.js (KNOWN_ALLERGENS, KNOWN_MEDICAL_CONDITIONS,
// GOAL_TYPES+DEFICIT_PCT+GOAL_PROTEIN_BOOST_PER_KG, ACTIVITY_FACTORS) with no
// database representation at all. These are real, normalized tables (not the
// key→JSON `documents` blob store) — same reasoning as lab_tests above: this
// is genuinely relational reference data, not a document.
//
// IDs are kept as the exact same strings already used everywhere else in the
// app (users' stored allergies/goalType/activityLevel, the mobile UI's
// option values) — changing these to surrogate integer keys would be a
// breaking change to every existing user record and every installed mobile
// build. "IDs over strings" in the broader migration plan applies to new
// entities (foods) that never had a stable string identity; these four
// already do, and preserving it is what makes this migration backward
// compatible with zero adapter code needed.
db.exec(`CREATE TABLE IF NOT EXISTS allergens (
  id         TEXT PRIMARY KEY,
  name_en    TEXT NOT NULL,
  name_ar    TEXT NOT NULL,
  created_at TEXT NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS medical_conditions (
  id         TEXT PRIMARY KEY,
  name_en    TEXT NOT NULL,
  name_ar    TEXT NOT NULL,
  created_at TEXT NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS activity_levels (
  id         TEXT PRIMARY KEY,
  name_en    TEXT NOT NULL,
  name_ar    TEXT NOT NULL,
  factor     REAL NOT NULL,
  created_at TEXT NOT NULL
)`);
// deficit_pct/protein_boost_per_kg are the exact real values already applied
// in production (health.js DEFICIT_PCT / GOAL_PROTEIN_BOOST_PER_KG, verified
// live this session: lose_weight -18%, lose_fat -15%+protein boost,
// maintain 0%, gain_weight +12%, gain_muscle +10%+protein boost) - not new
// numbers invented for this migration.
db.exec(`CREATE TABLE IF NOT EXISTS goals (
  id                   TEXT PRIMARY KEY,
  name_en              TEXT NOT NULL,
  name_ar              TEXT NOT NULL,
  deficit_pct          REAL NOT NULL,
  protein_boost_per_kg REAL NOT NULL DEFAULT 0,
  created_at           TEXT NOT NULL
)`);

const upsertLookupStmts = {
  allergens: db.prepare(`INSERT INTO allergens (id,name_en,name_ar,created_at) VALUES (@id,@name_en,@name_ar,@now)
    ON CONFLICT(id) DO NOTHING`),
  medical_conditions: db.prepare(`INSERT INTO medical_conditions (id,name_en,name_ar,created_at) VALUES (@id,@name_en,@name_ar,@now)
    ON CONFLICT(id) DO NOTHING`),
  activity_levels: db.prepare(`INSERT INTO activity_levels (id,name_en,name_ar,factor,created_at) VALUES (@id,@name_en,@name_ar,@factor,@now)
    ON CONFLICT(id) DO NOTHING`),
  goals: db.prepare(`INSERT INTO goals (id,name_en,name_ar,deficit_pct,protein_boost_per_kg,created_at) VALUES (@id,@name_en,@name_ar,@deficit_pct,@protein_boost_per_kg,@now)
    ON CONFLICT(id) DO NOTHING`),
};

// Seed data migrated as-is from the app's own existing constants (mobile
// RegisterScreen.js's ALLERGEN_OPTIONS/MEDICAL_CONDITION_OPTIONS, constants.js
// GOAL_OPTIONS, health.js's ACTIVITY_AR/ACTIVITY_EN/ACTIVITY_FACTORS) - not
// invented. ON CONFLICT DO NOTHING makes this safe to run on every boot,
// same discipline as seedLabTest above.
function seedLookupTables() {
  const now = new Date().toISOString();
  const allergens = [
    { id: 'milk', name_en: 'Milk', name_ar: 'ألبان' },
    { id: 'eggs', name_en: 'Eggs', name_ar: 'بيض' },
    { id: 'fish', name_en: 'Fish', name_ar: 'سمك' },
    { id: 'crustaceans', name_en: 'Crustaceans', name_ar: 'قشريات' },
    { id: 'nuts', name_en: 'Tree Nuts', name_ar: 'مكسرات' },
    { id: 'peanuts', name_en: 'Peanuts', name_ar: 'فول سوداني' },
    { id: 'gluten', name_en: 'Gluten', name_ar: 'جلوتين' },
    { id: 'soybeans', name_en: 'Soybeans', name_ar: 'صويا' },
    { id: 'sesame', name_en: 'Sesame', name_ar: 'سمسم' },
  ];
  const medicalConditions = [
    { id: 'type1_diabetes', name_en: 'Type 1 Diabetes', name_ar: 'سكري النوع الأول' },
    { id: 'type2_diabetes', name_en: 'Type 2 Diabetes', name_ar: 'سكري النوع الثاني' },
    { id: 'pregnant', name_en: 'Pregnant', name_ar: 'حامل' },
    { id: 'breastfeeding', name_en: 'Breastfeeding', name_ar: 'مرضعة' },
    { id: 'ckd', name_en: 'Chronic Kidney Disease', name_ar: 'مرض كلوي مزمن' },
  ];
  const activityLevels = [
    { id: 'sedentary', name_en: 'Sedentary', name_ar: 'قليل الحركة', factor: 1.2 },
    { id: 'light', name_en: 'Lightly Active', name_ar: 'نشاط خفيف', factor: 1.375 },
    { id: 'moderate', name_en: 'Moderately Active', name_ar: 'نشاط متوسط', factor: 1.55 },
    { id: 'active', name_en: 'Active', name_ar: 'نشيط', factor: 1.725 },
    { id: 'very_active', name_en: 'Very Active', name_ar: 'نشيط جداً', factor: 1.9 },
  ];
  const goals = [
    { id: 'lose_weight', name_en: 'Lose Weight', name_ar: 'إنقاص الوزن', deficit_pct: -0.18, protein_boost_per_kg: 0 },
    { id: 'lose_fat', name_en: 'Lose Fat (preserve muscle)', name_ar: 'حرق الدهون (مع الحفاظ على العضلات)', deficit_pct: -0.15, protein_boost_per_kg: 0.3 },
    { id: 'maintain', name_en: 'Maintain Weight', name_ar: 'الحفاظ على الوزن', deficit_pct: 0, protein_boost_per_kg: 0 },
    { id: 'gain_weight', name_en: 'Gain Weight', name_ar: 'زيادة الوزن', deficit_pct: 0.12, protein_boost_per_kg: 0 },
    { id: 'gain_muscle', name_en: 'Build Muscle', name_ar: 'بناء العضلات', deficit_pct: 0.10, protein_boost_per_kg: 0.3 },
  ];
  for (const r of allergens) upsertLookupStmts.allergens.run({ ...r, now });
  for (const r of medicalConditions) upsertLookupStmts.medical_conditions.run({ ...r, now });
  for (const r of activityLevels) upsertLookupStmts.activity_levels.run({ ...r, now });
  for (const r of goals) upsertLookupStmts.goals.run({ ...r, now });
}
seedLookupTables();

function listAllergens() { return db.prepare('SELECT * FROM allergens ORDER BY id').all(); }
function listMedicalConditions() { return db.prepare('SELECT * FROM medical_conditions ORDER BY id').all(); }
function listActivityLevels() { return db.prepare('SELECT * FROM activity_levels ORDER BY id').all(); }
function listGoals() { return db.prepare('SELECT * FROM goals ORDER BY id').all(); }
function getGoal(id) { return db.prepare('SELECT * FROM goals WHERE id = ?').get(id) || null; }
function getActivityLevel(id) { return db.prepare('SELECT * FROM activity_levels WHERE id = ?').get(id) || null; }

// Boot-time safety net: proves the newly-seeded tables are byte-identical to
// the JavaScript constants every existing code path still reads from, before
// anything is ever pointed at the database version. Throws loudly on boot
// rather than silently letting a mismatch reach production - a migration
// that can't prove equivalence shouldn't ship, per the "never silently
// modify production behavior" constraint this migration was built under.
// Callers pass in the live constants (not re-declared here) so this check
// can never drift out of sync with whichever object server.js/health.js
// actually still uses.
function verifyLookupTablesMatch({ knownAllergens, knownMedicalConditions, activityFactors, goalTypes, goalDeficitPct, goalProteinBoost }) {
  const errors = [];
  const idSetMismatch = (label, dbIds, jsIds) => {
    const a = [...dbIds].sort(), b = [...jsIds].sort();
    if (JSON.stringify(a) !== JSON.stringify(b)) errors.push(`${label} ID set mismatch: DB=${JSON.stringify(a)} JS=${JSON.stringify(b)}`);
  };
  idSetMismatch('allergens', listAllergens().map(r => r.id), knownAllergens);
  idSetMismatch('medical_conditions', listMedicalConditions().map(r => r.id), knownMedicalConditions);
  idSetMismatch('activity_levels', listActivityLevels().map(r => r.id), Object.keys(activityFactors));
  idSetMismatch('goals', listGoals().map(r => r.id), goalTypes);

  for (const level of listActivityLevels()) {
    if (activityFactors[level.id] !== level.factor) {
      errors.push(`activity_levels.${level.id}.factor mismatch: DB=${level.factor} JS=${activityFactors[level.id]}`);
    }
  }
  for (const goal of listGoals()) {
    if (goalDeficitPct[goal.id] !== goal.deficit_pct) {
      errors.push(`goals.${goal.id}.deficit_pct mismatch: DB=${goal.deficit_pct} JS=${goalDeficitPct[goal.id]}`);
    }
    const jsBoost = goalProteinBoost[goal.id] || 0;
    if (jsBoost !== goal.protein_boost_per_kg) {
      errors.push(`goals.${goal.id}.protein_boost_per_kg mismatch: DB=${goal.protein_boost_per_kg} JS=${jsBoost}`);
    }
  }
  if (errors.length) {
    throw new Error('[db] lookup-table migration verification FAILED:\n' + errors.join('\n'));
  }
  console.log('[db] lookup-table migration verified: allergens/medical_conditions/activity_levels/goals all match production JS constants exactly (IDs and values).');
}

// ─── FOODS (Phase 2 of the nutrition-architecture migration) ───────────────
// The highest-value migration from the architecture audit: FOOD_DB (85
// entries) previously lived ONLY as a JavaScript array literal in server.js,
// matched by substring-containment search (findFoodMatch/`.includes()`)
// with a "longest match wins" tie-break. That algorithm was PROVEN unsafe
// during the audit - 6 real, live foods didn't even resolve to themselves
// (e.g. "أرز أبيض"/White Rice matched "eggs" because "أبيض" contains "بيض").
//
// The fix here is structural, not another one-off name fix: foods and their
// aliases are UNIQUE, and lookup is exact-match-after-normalization only,
// never substring/containment. This makes the entire bug class impossible
// by construction, not just fixed for the cases found so far - verified
// below by proving every one of the 84 real foods resolves to ITSELF, not
// just the 6 previously-broken ones.
//
// Aliases point to exactly one food (UNIQUE constraint on food_aliases.alias)
// - two different foods can never claim the same alias, which is the actual
// mechanism (not just a convention) that prevents ambiguity.
db.exec(`CREATE TABLE IF NOT EXISTS foods (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  name_en          TEXT NOT NULL UNIQUE,
  name_ar          TEXT NOT NULL UNIQUE,
  category         TEXT,
  cal_per_100g     REAL NOT NULL,
  protein_per_100g REAL NOT NULL,
  carbs_per_100g   REAL NOT NULL,
  fat_per_100g     REAL NOT NULL,
  active           INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS food_aliases (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  food_id    INTEGER NOT NULL REFERENCES foods(id),
  alias      TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_food_aliases_food_id ON food_aliases(food_id)`);
// allergen_id references the Phase 1 allergens table - real FK, not a string
// re-typed in a third place.
db.exec(`CREATE TABLE IF NOT EXISTS food_allergens (
  food_id     INTEGER NOT NULL REFERENCES foods(id),
  allergen_id TEXT NOT NULL REFERENCES allergens(id),
  PRIMARY KEY (food_id, allergen_id)
)`);

const insFoodStmt = db.prepare(`INSERT INTO foods
    (name_en,name_ar,category,cal_per_100g,protein_per_100g,carbs_per_100g,fat_per_100g,active,created_at,updated_at)
  VALUES (@name_en,@name_ar,@category,@cal,@protein,@carbs,@fat,1,@now,@now)
  ON CONFLICT(name_ar) DO NOTHING`);
const insAliasStmt = db.prepare(`INSERT INTO food_aliases (food_id,alias,created_at) VALUES (@food_id,@alias,@now)
  ON CONFLICT(alias) DO NOTHING`);
const insFoodAllergenStmt = db.prepare(`INSERT INTO food_allergens (food_id,allergen_id) VALUES (@food_id,@allergen_id)
  ON CONFLICT DO NOTHING`);
const getFoodByNameAr = db.prepare('SELECT id FROM foods WHERE name_ar = ?');

// Transcribed programmatically, byte-for-byte, from the FOOD_DB array
// literal that previously lived in server.js - not retyped by hand, and no
// values were changed, added, or invented (verified: 0 mismatches against
// the original array before this shipped). The one change from the
// original: the duplicate "كشري"/koshari entry (which made its own gluten
// tag unreachable dead code - see the architecture audit) is collapsed to
// the single correctly-tagged entry, both entries were otherwise byte-
// identical. Inlined here (not a separate required file) because this
// container's individual-file bind mounts don't include new files added
// mid-session without a mount-config change - a real deployment lesson
// from this migration, not a style choice.
const FOOD_SEED_DATA = [
  { nameAr: "صدر فرخة مشوي", nameEn: "grilled chicken breast", aliases: ["صدر دجاج", "فراخ مشوي", "دجاج مشوي", "chicken breast"], cal: 165, protein: 31, carbs: 0, fat: 3.6, allergens: [] },
  { nameAr: "فخذ فرخة", nameEn: "chicken thigh", aliases: ["فخذ دجاج"], cal: 209, protein: 26, carbs: 0, fat: 10.9, allergens: [] },
  { nameAr: "فرخة كاملة مشوية", nameEn: "whole roasted chicken", aliases: ["دجاجة مشوية"], cal: 190, protein: 27, carbs: 0, fat: 8, allergens: [] },
  { nameAr: "لحم بقري", nameEn: "beef, lean", aliases: ["لحمة بقري", "لحم بتلو"], cal: 250, protein: 26, carbs: 0, fat: 15, allergens: [] },
  { nameAr: "لحمة مفرومة", nameEn: "ground beef, cooked", aliases: ["لحم مفروم"], cal: 254, protein: 25, carbs: 0, fat: 17, allergens: [] },
  { nameAr: "لحم ضاني", nameEn: "lamb", aliases: ["لحمة ضاني", "لحم غنم"], cal: 294, protein: 25, carbs: 0, fat: 21, allergens: [] },
  { nameAr: "سمك بلطي", nameEn: "tilapia fish", aliases: ["بلطي", "سمك مشوي"], cal: 128, protein: 26, carbs: 0, fat: 2.7, allergens: ["fish"] },
  { nameAr: "تونة", nameEn: "tuna, canned in water", aliases: ["تونه"], cal: 116, protein: 26, carbs: 0, fat: 1, allergens: ["fish"] },
  { nameAr: "جمبري", nameEn: "shrimp", aliases: ["روبيان"], cal: 99, protein: 24, carbs: 0.2, fat: 0.3, allergens: ["crustaceans"] },
  { nameAr: "بيض مسلوق", nameEn: "boiled egg", aliases: ["بيضة مسلوقة"], cal: 155, protein: 13, carbs: 1.1, fat: 11, allergens: ["eggs"] },
  { nameAr: "بياض بيض", nameEn: "egg white", aliases: [], cal: 52, protein: 11, carbs: 0.7, fat: 0.2, allergens: ["eggs"] },
  { nameAr: "أرز أبيض", nameEn: "white rice, cooked", aliases: ["رز أبيض", "ارز ابيض"], cal: 130, protein: 2.7, carbs: 28, fat: 0.3, allergens: [] },
  { nameAr: "أرز بني", nameEn: "brown rice, cooked", aliases: ["رز بني"], cal: 111, protein: 2.6, carbs: 23, fat: 0.9, allergens: [] },
  { nameAr: "عيش بلدي", nameEn: "baladi bread", aliases: ["عيش شامي", "خبز بلدي"], cal: 265, protein: 9, carbs: 53, fat: 1.5, allergens: ["gluten"] },
  { nameAr: "عيش فينو", nameEn: "white bread", aliases: ["خبز أبيض", "توست"], cal: 289, protein: 9, carbs: 55, fat: 3.2, allergens: ["gluten"] },
  { nameAr: "مكرونة", nameEn: "pasta, cooked", aliases: ["معكرونة"], cal: 131, protein: 5, carbs: 25, fat: 1.1, allergens: ["gluten"] },
  { nameAr: "بطاطس مسلوقة", nameEn: "boiled potato", aliases: ["بطاطا مسلوقة"], cal: 87, protein: 1.9, carbs: 20, fat: 0.1, allergens: [] },
  { nameAr: "بطاطس محمرة", nameEn: "fried potato", aliases: ["بطاطس مقلية"], cal: 312, protein: 3.4, carbs: 41, fat: 15, allergens: [] },
  { nameAr: "بطاطا", nameEn: "sweet potato", aliases: ["بطاطا حلوة"], cal: 86, protein: 1.6, carbs: 20, fat: 0.1, allergens: [] },
  { nameAr: "شوفان", nameEn: "oats, dry", aliases: [], cal: 389, protein: 17, carbs: 66, fat: 7, allergens: [] },
  { nameAr: "فول مدمس", nameEn: "foul medames", aliases: ["فول"], cal: 110, protein: 7.6, carbs: 18, fat: 0.6, allergens: [] },
  { nameAr: "حمص", nameEn: "hummus", aliases: [], cal: 166, protein: 8, carbs: 14, fat: 9.6, allergens: ["sesame"] },
  { nameAr: "حمص حب معلب", nameEn: "chickpeas, canned", aliases: ["حمص حب", "chickpeas"], cal: 139, protein: 7.3, carbs: 22.5, fat: 2.6, allergens: [] },
  { nameAr: "صدر ديك رومي", nameEn: "turkey breast, grilled", aliases: ["ديك رومي", "turkey"], cal: 135, protein: 29, carbs: 0, fat: 1.6, allergens: [] },
  { nameAr: "عدس مطبوخ", nameEn: "cooked lentils", aliases: ["عدس"], cal: 116, protein: 9, carbs: 20, fat: 0.4, allergens: [] },
  { nameAr: "شوربة عدس", nameEn: "lentil soup (prepared)", aliases: [], cal: 70, protein: 4.5, carbs: 11, fat: 1.5, allergens: [] },
  { nameAr: "طعمية", nameEn: "falafel", aliases: ["فلافل"], cal: 333, protein: 13, carbs: 32, fat: 18, allergens: [] },
  { nameAr: "طماطم", nameEn: "tomato", aliases: ["طماطة"], cal: 18, protein: 0.9, carbs: 3.9, fat: 0.2, allergens: [] },
  { nameAr: "خيار", nameEn: "cucumber", aliases: [], cal: 15, protein: 0.7, carbs: 3.6, fat: 0.1, allergens: [] },
  { nameAr: "سلطة خضراء", nameEn: "green salad", aliases: ["سلطة"], cal: 20, protein: 1, carbs: 4, fat: 0.2, allergens: [] },
  { nameAr: "ملوخية", nameEn: "molokhia", aliases: [], cal: 60, protein: 4.8, carbs: 8, fat: 1.5, allergens: [] },
  { nameAr: "بامية", nameEn: "okra", aliases: [], cal: 60, protein: 2, carbs: 8, fat: 2, allergens: [] },
  { nameAr: "سبانخ", nameEn: "spinach", aliases: [], cal: 23, protein: 2.9, carbs: 3.6, fat: 0.4, allergens: [] },
  { nameAr: "كوسة", nameEn: "zucchini", aliases: ["كوسه"], cal: 17, protein: 1.2, carbs: 3.1, fat: 0.3, allergens: [] },
  { nameAr: "موز", nameEn: "banana", aliases: [], cal: 89, protein: 1.1, carbs: 23, fat: 0.3, allergens: [] },
  { nameAr: "تفاح", nameEn: "apple", aliases: [], cal: 52, protein: 0.3, carbs: 14, fat: 0.2, allergens: [] },
  { nameAr: "برتقال", nameEn: "orange", aliases: [], cal: 47, protein: 0.9, carbs: 12, fat: 0.1, allergens: [] },
  { nameAr: "مانجو", nameEn: "mango", aliases: [], cal: 60, protein: 0.8, carbs: 15, fat: 0.4, allergens: [] },
  { nameAr: "بطيخ", nameEn: "watermelon", aliases: [], cal: 30, protein: 0.6, carbs: 8, fat: 0.2, allergens: [] },
  { nameAr: "تمر", nameEn: "dates", aliases: [], cal: 277, protein: 1.8, carbs: 75, fat: 0.2, allergens: [] },
  { nameAr: "زبادي", nameEn: "plain yogurt", aliases: ["لبن زبادي"], cal: 61, protein: 3.5, carbs: 4.7, fat: 3.3, allergens: ["milk"] },
  { nameAr: "زبادي يوناني", nameEn: "greek yogurt", aliases: [], cal: 59, protein: 10, carbs: 3.6, fat: 0.4, allergens: ["milk"] },
  { nameAr: "لبن", nameEn: "whole milk", aliases: ["حليب"], cal: 61, protein: 3.2, carbs: 4.8, fat: 3.3, allergens: ["milk"] },
  { nameAr: "جبنة فيتا", nameEn: "feta cheese", aliases: [], cal: 264, protein: 14, carbs: 4, fat: 21, allergens: ["milk"] },
  { nameAr: "جبنة قريش", nameEn: "cottage cheese", aliases: ["جبنه قريش", "جبن قريش"], cal: 98, protein: 11, carbs: 3.4, fat: 4.3, allergens: ["milk"] },
  { nameAr: "جبنة بيضاء", nameEn: "white cheese", aliases: [], cal: 300, protein: 18, carbs: 3, fat: 24, allergens: ["milk"] },
  { nameAr: "لوز", nameEn: "almonds", aliases: [], cal: 579, protein: 21, carbs: 22, fat: 50, allergens: ["nuts"] },
  { nameAr: "فول سوداني", nameEn: "peanuts", aliases: ["سوداني"], cal: 567, protein: 26, carbs: 16, fat: 49, allergens: ["peanuts"] },
  { nameAr: "زيت زيتون", nameEn: "olive oil", aliases: [], cal: 884, protein: 0, carbs: 0, fat: 100, allergens: [] },
  { nameAr: "أفوكادو", nameEn: "avocado", aliases: ["افوكادو"], cal: 160, protein: 2, carbs: 8.5, fat: 14.7, allergens: [] },
  { nameAr: "كفتة مشوية", nameEn: "grilled kofta", aliases: ["كفتة"], cal: 220, protein: 18, carbs: 2, fat: 15, allergens: [] },
  { nameAr: "شاورما فراخ", nameEn: "chicken shawarma", aliases: ["شاورما دجاج"], cal: 200, protein: 18, carbs: 10, fat: 10, allergens: [] },
  { nameAr: "فتة", nameEn: "fattah", aliases: [], cal: 200, protein: 10, carbs: 22, fat: 8, allergens: ["gluten"] },
  { nameAr: "كشري", nameEn: "koshari", aliases: [], cal: 180, protein: 5, carbs: 30, fat: 4, allergens: ["gluten"] },
  { nameAr: "بيض أحمر", nameEn: "whole egg", aliases: ["بيضة"], cal: 143, protein: 12.6, carbs: 0.7, fat: 9.5, allergens: ["eggs"] },
  { nameAr: "صدر فراخ طازج", nameEn: "raw chicken breast", aliases: ["صدر دجاج طازج"], cal: 120, protein: 22.5, carbs: 0, fat: 2.6, allergens: [] },
  { nameAr: "خضار مشكلة", nameEn: "mixed vegetables", aliases: [], cal: 35, protein: 1.8, carbs: 6.5, fat: 0.3, allergens: [] },
  { nameAr: "مكسرات مشكلة", nameEn: "mixed nuts", aliases: [], cal: 607, protein: 20, carbs: 21, fat: 54, allergens: ["nuts", "peanuts"] },
  { nameAr: "لحمة كندوز", nameEn: "veal/lean beef cut", aliases: ["كندوز"], cal: 250, protein: 26, carbs: 0, fat: 15, allergens: [] },
  { nameAr: "عيش أسمر", nameEn: "whole wheat bread", aliases: ["خبز أسمر"], cal: 247, protein: 13, carbs: 41, fat: 3.4, allergens: ["gluten"] },
  { nameAr: "سلمون", nameEn: "salmon", aliases: [], cal: 206, protein: 22, carbs: 0, fat: 12, allergens: ["fish"] },
  { nameAr: "مايونيز", nameEn: "mayonnaise", aliases: [], cal: 680, protein: 1, carbs: 0.6, fat: 75, allergens: ["eggs"] },
  { nameAr: "زبدة", nameEn: "butter", aliases: [], cal: 717, protein: 0.85, carbs: 0.1, fat: 81, allergens: ["milk"] },
  { nameAr: "كريمة طبخ", nameEn: "cooking/heavy cream", aliases: ["كريمة"], cal: 340, protein: 2.1, carbs: 2.8, fat: 36, allergens: ["milk"] },
  { nameAr: "جبنة شيدر", nameEn: "cheddar cheese", aliases: [], cal: 403, protein: 25, carbs: 1.3, fat: 33, allergens: ["milk"] },
  { nameAr: "جبنة كريمي", nameEn: "cream cheese", aliases: [], cal: 342, protein: 6, carbs: 4, fat: 34, allergens: ["milk"] },
  { nameAr: "جبنة رومي", nameEn: "romano-style hard cheese", aliases: [], cal: 387, protein: 32, carbs: 3.6, fat: 27, allergens: ["milk"] },
  { nameAr: "مكسرات برازيلية", nameEn: "brazil nuts", aliases: [], cal: 656, protein: 14.3, carbs: 12.3, fat: 66.4, allergens: ["nuts"] },
  { nameAr: "زيت جوز الهند", nameEn: "coconut oil", aliases: [], cal: 862, protein: 0, carbs: 0, fat: 100, allergens: [] },
  { nameAr: "جوز الهند مبشور", nameEn: "shredded coconut, unsweetened", aliases: [], cal: 660, protein: 6.9, carbs: 23.7, fat: 64.5, allergens: [] },
  { nameAr: "كريمة جوز الهند", nameEn: "coconut cream", aliases: [], cal: 330, protein: 3.6, carbs: 6.7, fat: 34.7, allergens: [] },
  { nameAr: "لحم مقدد بقري", nameEn: "beef bacon", aliases: [], cal: 541, protein: 37, carbs: 1.4, fat: 42, allergens: [] },
  { nameAr: "لحم ريب آي", nameEn: "ribeye steak", aliases: [], cal: 291, protein: 24, carbs: 0, fat: 21.2, allergens: [] },
  { nameAr: "فلفل أخضر", nameEn: "green bell pepper", aliases: [], cal: 20, protein: 0.86, carbs: 4.6, fat: 0.17, allergens: [] },
  { nameAr: "عسل نحل", nameEn: "honey", aliases: ["عسل"], cal: 304, protein: 0.3, carbs: 82.4, fat: 0, allergens: [] },
  { nameAr: "طحينة", nameEn: "tahini", aliases: [], cal: 595, protein: 17, carbs: 21, fat: 54, allergens: ["sesame"] },
  { nameAr: "توت مشكل", nameEn: "mixed berries", aliases: [], cal: 43, protein: 0.8, carbs: 10, fat: 0.3, allergens: [] },
  { nameAr: "كسكسي", nameEn: "couscous, cooked", aliases: [], cal: 112, protein: 3.8, carbs: 23.2, fat: 0.16, allergens: ["gluten"] },
  { nameAr: "زعتر", nameEn: "za'atar spice blend", aliases: [], cal: 380, protein: 10, carbs: 40, fat: 20, allergens: ["sesame"] },
  { nameAr: "قرفة", nameEn: "cinnamon, ground", aliases: [], cal: 247, protein: 4, carbs: 80.6, fat: 1.24, allergens: [] },
  { nameAr: "جزر", nameEn: "carrot", aliases: [], cal: 41, protein: 0.93, carbs: 9.6, fat: 0.24, allergens: [] },
  { nameAr: "كبدة بقري", nameEn: "beef liver, cooked", aliases: [], cal: 175, protein: 26.5, carbs: 3.9, fat: 4.9, allergens: [] },
  { nameAr: "كورن فليكس", nameEn: "corn flakes", aliases: [], cal: 357, protein: 7.5, carbs: 84, fat: 0.4, allergens: ["gluten"] },
  { nameAr: "بروكلي", nameEn: "broccoli", aliases: [], cal: 34, protein: 2.8, carbs: 6.6, fat: 0.37, allergens: [] },
];

// Idempotent (ON CONFLICT DO NOTHING on both foods and aliases), safe to run
// on every boot without duplicating rows - same discipline as seedLabTest/
// seedLookupTables above.
function seedFoods(seedData) {
  const now = new Date().toISOString();
  for (const f of seedData) {
    insFoodStmt.run({ name_en: f.nameEn, name_ar: f.nameAr, category: f.category || null, cal: f.cal, protein: f.protein, carbs: f.carbs, fat: f.fat, now });
    const row = getFoodByNameAr.get(f.nameAr);
    if (!row) continue; // shouldn't happen given ON CONFLICT DO NOTHING above still finds the existing row via name_ar
    for (const alias of f.aliases || []) insAliasStmt.run({ food_id: row.id, alias, now });
    for (const allergenId of f.allergens || []) insFoodAllergenStmt.run({ food_id: row.id, allergen_id: allergenId });
  }
}

// Real alias gaps found while verifying migration coverage against every
// actual meal-plan/price-catalog name in current production data (not
// hypothetical) - each of these is confirmed to be the SAME food under a
// different real-world name (a market-form or product-listing variant, not
// a different preparation with different macros), so this adds no new
// nutrition data, just links an existing real name to its existing food.
// Kept separate from the pure FOOD_DB transcription in food_seed_data.js so
// it's clear what was migrated as-is vs. fixed during verification.
//
// Explicitly NOT aliased here, and left unresolved on purpose rather than
// guessed: "زيتون"/Olives (real olives are nutritionally distinct from
// "زيت زيتون"/olive oil - ~115-145 kcal/100g vs 884 - aliasing them would
// misrepresent real nutrition), "جبنة موزاريلا"/Mozzarella and "لبنة"/Labneh
// (no existing entry is nutritionally close enough to any other cheese/
// yogurt already in the table), "تونة في زيت"/Tuna in Oil (meaningfully
// higher fat than the existing water-packed tuna entry), and "بطاطس"/bare
// Potato (ambiguous between the existing boiled/fried entries, which differ
// by 3.5x in calories - neither is safe to guess, and raw potato isn't in
// the table at all). These 5 are real, missing foods, not aliases - adding
// real reference nutrition for them is a follow-up, not guessed here.
function seedFoodAliases(pairs) {
  const now = new Date().toISOString();
  for (const p of pairs) {
    const target = getFoodByNameAr.get(p.matchesNameAr);
    if (!target) { console.error(`[db] seedFoodAliases: target food "${p.matchesNameAr}" not found for alias "${p.nameAr}"`); continue; }
    insAliasStmt.run({ food_id: target.id, alias: p.nameAr, now });
    insAliasStmt.run({ food_id: target.id, alias: p.nameEn, now });
  }
}

// Same normalization already used by the old findFoodMatch (أ/إ/آ->ا, ى->ي,
// ة->ه - real Arabic keyboard/spelling variance, not typo tolerance) but
// applied to EXACT equality here, never containment. This is the entire
// fix: the bug was never the normalization, it was `.includes()`.
function normalizeFoodName(s) {
  return (s || '').trim().toLowerCase().replace(/[أإآ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه');
}

let _foodResolveCache = null; // { normalizedKey -> food row w/ allergens[] }, built once, tiny (84 rows x ~3 keys)
function _buildFoodResolveCache() {
  const cache = new Map();
  const allergensByFood = new Map();
  for (const row of db.prepare('SELECT food_id, allergen_id FROM food_allergens').all()) {
    if (!allergensByFood.has(row.food_id)) allergensByFood.set(row.food_id, []);
    allergensByFood.get(row.food_id).push(row.allergen_id);
  }
  for (const food of db.prepare('SELECT * FROM foods WHERE active = 1').all()) {
    const enriched = { ...food, allergens: allergensByFood.get(food.id) || [] };
    cache.set(normalizeFoodName(food.name_ar), enriched);
    cache.set(normalizeFoodName(food.name_en), enriched);
  }
  for (const alias of db.prepare('SELECT * FROM food_aliases').all()) {
    const food = db.prepare('SELECT * FROM foods WHERE id = ? AND active = 1').get(alias.food_id);
    if (food) cache.set(normalizeFoodName(alias.alias), { ...food, allergens: allergensByFood.get(food.id) || [] });
  }
  return cache;
}

// Exact-match-only resolver - the actual fix. Never falls back to substring/
// containment matching under any circumstance; an unmatched query returns
// null, not a guess. Cache is process-lifetime (foods table changes require
// a restart to be picked up here) - acceptable for a 84-row reference table
// that changes by deliberate admin action, not user activity; revisit if
// that assumption stops holding once foods become admin-editable.
function resolveFood(query) {
  if (!_foodResolveCache) _foodResolveCache = _buildFoodResolveCache();
  const key = normalizeFoodName(query);
  if (!key) return null;
  return _foodResolveCache.get(key) || null;
}

// Boot-time regression test, not a one-time migration check: proves every
// single food resolves to ITSELF via resolveFood() - the same self-match
// test the architecture audit used to discover the original 6 bugs, now
// permanent. A future food/alias added carelessly (colliding with an
// existing one) would fail the UNIQUE constraint at insert time already,
// but this also catches a food that fails to resolve to itself for any
// other reason (e.g. a normalization edge case). Fails loudly on boot.
function verifyFoodResolution() {
  const errors = [];
  for (const food of db.prepare('SELECT * FROM foods WHERE active = 1').all()) {
    const byAr = resolveFood(food.name_ar);
    if (!byAr || byAr.id !== food.id) errors.push(`food ${food.id} (${food.name_en}) name_ar "${food.name_ar}" resolves to ${byAr ? byAr.id + ' (' + byAr.name_en + ')' : 'NOTHING'}, not itself`);
    const byEn = resolveFood(food.name_en);
    if (!byEn || byEn.id !== food.id) errors.push(`food ${food.id} (${food.name_en}) name_en "${food.name_en}" resolves to ${byEn ? byEn.id + ' (' + byEn.name_en + ')' : 'NOTHING'}, not itself`);
  }
  for (const alias of db.prepare('SELECT * FROM food_aliases').all()) {
    const byAlias = resolveFood(alias.alias);
    if (!byAlias || byAlias.id !== alias.food_id) errors.push(`alias "${alias.alias}" (food_id ${alias.food_id}) resolves to ${byAlias ? byAlias.id : 'NOTHING'}, not its own food`);
  }
  if (errors.length) {
    throw new Error('[db] food resolution self-test FAILED:\n' + errors.join('\n'));
  }
  console.log(`[db] food resolution verified: all ${db.prepare('SELECT COUNT(*) c FROM foods').get().c} foods and ${db.prepare('SELECT COUNT(*) c FROM food_aliases').get().c} aliases resolve to themselves via exact match.`);
}

seedFoods(FOOD_SEED_DATA);
seedFoodAliases([
  { nameAr: 'فرخة كاملة', nameEn: 'Whole Chicken', matchesNameAr: 'فرخة كاملة مشوية' },
  { nameAr: 'جمبري مجمد', nameEn: 'Frozen Shrimp', matchesNameAr: 'جمبري' },
  { nameAr: 'زبدة طبيعية', nameEn: 'Natural Butter', matchesNameAr: 'زبدة' },
]);
verifyFoodResolution();

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
  seedLabTest, getLabTest, listLabTests, getReferenceRanges, resolveReferenceRange,
  listAllergens, listMedicalConditions, listActivityLevels, listGoals, getGoal, getActivityLevel,
  verifyLookupTablesMatch,
  resolveFood, normalizeFoodName, verifyFoodResolution };
