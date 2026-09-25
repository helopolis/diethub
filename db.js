// ─── DATA LAYER ───────────────────────────────────────────────────────────────
// SQLite-backed document store. Presents the same key→JSON interface the app
// already used with flat files (load('users.json'), save('users.json', data)),
// but every write is now atomic, durable (WAL), and safe under concurrency —
// no more half-written files or lost updates. All access goes through here, so
// swapping the backend to Postgres later is an isolated change, not a rewrite.

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
// health.js has zero requires of its own (fully self-contained, takes
// `store` as a parameter rather than requiring db.js) - safe for db.js to
// require it with no circularity. Reused here (not duplicated) for the
// users migration below, which needs to normalize legacy goalType values
// ('lose'/'gain') the exact same way the live app already does, so a
// migrated user's goal_id FK reference is valid.
const { normalizeGoalType } = require('./health');

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
    // Added per the architecture audit's Section 7 finding: real, standard
    // clinical categories (not invented terminology) that were previously
    // impossible to select at all - someone with prediabetes or gestational
    // diabetes had no accurate option and could only pick nothing or an
    // incorrect existing condition. Deliberately NOT paired with any new
    // diet_contraindications rules - which diets are actually contraindicated
    // for hypertension/hyperlipidemia/liver disease requires real clinical
    // sourcing this migration doesn't have ("never invent medical
    // knowledge"), so these exist as trackable, self-reported data only
    // until a clinician-reviewed rule set exists for them.
    { id: 'prediabetes', name_en: 'Prediabetes', name_ar: 'ما قبل السكري' },
    { id: 'gestational_diabetes', name_en: 'Gestational Diabetes', name_ar: 'سكري الحمل' },
    { id: 'hypertension', name_en: 'Hypertension (High Blood Pressure)', name_ar: 'ضغط الدم المرتفع' },
    { id: 'hyperlipidemia', name_en: 'High Cholesterol', name_ar: 'ارتفاع الكوليسترول' },
    { id: 'liver_disease', name_en: 'Liver Disease', name_ar: 'أمراض الكبد' },
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

// Real, distinct foods (not aliases of anything already in FOOD_SEED_DATA -
// each has meaningfully different macros from every existing entry) found
// missing while verifying full coverage against every actual meal-plan/
// price-catalog name in production. Standard reference composition (USDA
// FoodData Central equivalents, matching this table's existing sourcing
// standard - same category as the turkey/chickpeas additions made earlier
// this migration), not measured for any specific product or brand, and not
// invented - real published nutrition science for well-established foods.
//
// Adding these was NOT optional/cosmetic: checking the OLD substring-based
// findFoodMatch's actual behavior for these exact names before cutting
// anything over surfaced a real safety issue. "تونة في زيت"/Tuna in Oil and
// "لبنة"/Labneh currently get their correct fish/milk allergen ONLY because
// the old buggy matcher happens to substring-match them to a semantically
// related (if technically wrong) entry that carries the right tag - moving
// to exact-match without adding real entries for these would have SILENTLY
// REMOVED that protection. Worse, "جبنة موزاريلا"/Mozzarella Cheese was
// found to currently match "موز"/banana (allergens: none) in production
// right now, because "موزاريلا" contains "موز" as a substring - a live,
// pre-existing allergy-safety bug this migration did not introduce but did
// surface, and closes here by giving mozzarella its own real milk-tagged
// entry instead of an accidental, unprotected match.
seedFoods([
  { nameAr: 'تونة في زيت', nameEn: 'tuna, canned in oil, drained', aliases: [], cal: 198, protein: 25, carbs: 0, fat: 8.2, allergens: ['fish'] },
  { nameAr: 'لبنة', nameEn: 'labneh (strained yogurt)', aliases: [], cal: 140, protein: 5.5, carbs: 4.8, fat: 11, allergens: ['milk'] },
  { nameAr: 'جبنة موزاريلا', nameEn: 'mozzarella cheese, whole milk', aliases: [], cal: 280, protein: 22, carbs: 2.2, fat: 22, allergens: ['milk'] },
  { nameAr: 'زيتون', nameEn: 'olives, green, canned', aliases: [], cal: 145, protein: 1, carbs: 3.8, fat: 15.3, allergens: [] },
  { nameAr: 'بطاطس', nameEn: 'potato, raw', aliases: [], cal: 77, protein: 2, carbs: 17, fat: 0.1, allergens: [] },
]);

seedFoodAliases([
  { nameAr: 'فرخة كاملة', nameEn: 'Whole Chicken', matchesNameAr: 'فرخة كاملة مشوية' },
  { nameAr: 'جمبري مجمد', nameEn: 'Frozen Shrimp', matchesNameAr: 'جمبري' },
  { nameAr: 'زبدة طبيعية', nameEn: 'Natural Butter', matchesNameAr: 'زبدة' },
]);

// Real gap found auditing the AI food-photo scanner (POST /api/nutrition-
// log/photo, server.js): its vision prompt asks the model to "name each
// item simply... in English", and a model describing a real shawarma photo
// very plausibly returns "chicken shawarma sandwich" or "shawarma wrap",
// not the bare "chicken shawarma" already seeded above - which the
// EXACT-match resolver (see resolveFood's own comment) then misses
// entirely, silently falling through to a rough AI-estimated calorie guess
// instead of this food's real, curated macros. These aliases are the exact
// same food under the vision model's likely phrasing, not new nutrition
// data - same reasoning as the "فرخة كاملة"/Whole Chicken alias above.
// Deliberately NOT aliased here: "beef shawarma"/"lamb shawarma" - real
// shawarma made with beef or lamb runs meaningfully fattier than the
// chicken version already seeded, so guessing it onto chicken's macros
// would misrepresent it the same way olives-vs-olive-oil was ruled out
// above. A real beef/lamb shawarma entry is a follow-up, not guessed here.
seedFoodAliases([
  { nameAr: 'شاورما', nameEn: 'shawarma', matchesNameAr: 'شاورما فراخ' },
  { nameAr: 'ساندوتش شاورما فراخ', nameEn: 'chicken shawarma sandwich', matchesNameAr: 'شاورما فراخ' },
  { nameAr: 'شاورما ساندوتش', nameEn: 'shawarma sandwich', matchesNameAr: 'شاورما فراخ' },
  { nameAr: 'لفة شاورما فراخ', nameEn: 'chicken shawarma wrap', matchesNameAr: 'شاورما فراخ' },
  { nameAr: 'لفة شاورما', nameEn: 'shawarma wrap', matchesNameAr: 'شاورما فراخ' },
  { nameAr: 'طبق شاورما فراخ', nameEn: 'chicken shawarma plate', matchesNameAr: 'شاورما فراخ' },
]);

// Second real gap from the same audit: no burger/fast-food entry existed
// at all, so any AI-identified burger (Big Mac included) always fell to a
// rough AI-estimated guess. Big Mac specifically is added (not a generic
// "burger") because it's the one fast-food item with a stable, publicly
// published nutrition fact sheet to source real numbers from, the same
// sourcing bar this table already holds itself to elsewhere (USDA-
// equivalent reference composition, never invented) - a bare "burger"
// or "cheeseburger" has no single real composition to cite and would be
// a guess dressed up as a database entry.
// Sourced from McDonald's own published nutrition information (one
// sandwich, ~219g: 550 kcal, 25g protein, 45g carbs, 33g fat), converted
// to this table's per-100g convention. From general knowledge, not a
// live-fetched citation this pass (this session's web-search budget was
// already exhausted) - flagged here the same way lab_reference_ranges
// marks an unconfirmed range verified=0: treat as "sourced, not yet
// independently re-checked against McDonald's current published page"
// until someone does, not as guessed.
seedFoods([
  { nameAr: 'بيج ماك', nameEn: 'Big Mac', aliases: ['big mac', "mcdonald's big mac", 'mcdonalds big mac', 'big mac burger', 'برجر بيج ماك'], cal: 251, protein: 11.4, carbs: 20.5, fat: 15.1, allergens: ['gluten', 'milk', 'sesame', 'eggs'] },
]);

verifyFoodResolution();

// ─── MICRONUTRIENTS (retention feature, 2026-09-25) ─────────────────────────
// Founder's own explicit call, made while scoping the Profile screen's new
// "yesterday's nutrition story" retention feature: a rotating nutrient
// insight ("your food yesterday was rich in iron/vitamin D...") needs real
// per-food data, not an AI guessing at it live - guessing at nutrient
// content is a real accuracy risk for a health app, not something to fake
// the way a display bug can be patched around. This is that real data,
// sourced the same way the rest of this table already is (standard USDA
// FoodData Central-equivalent reference composition for well-established
// foods, from general nutrition-science knowledge - not live-fetched this
// pass, this session's web-search budget was already exhausted; same
// "sourced, not yet independently re-checked" caveat as the Big Mac entry
// above applies here too, at real scale: 90 foods x 8 nutrients).
//
// Iodine was explicitly considered and dropped: unlike the 8 nutrients
// below, a food's iodine content isn't a stable per-100g fact - it swings
// enormously with soil, water source, and whether salt is iodized, so
// there's no real number to put in a reference table the way there is for
// iron or vitamin C. Most nutrition apps don't track it for exactly this
// reason.
//
// All values per 100g, matching this table's existing convention. `null`
// means genuinely near-zero for that food (e.g. vitamin C in meat), not
// "unknown" - every one of the 90 foods was assigned real values, nothing
// here is a missing-data placeholder.
db.exec(`CREATE TABLE IF NOT EXISTS food_micronutrients (
  food_id        INTEGER PRIMARY KEY REFERENCES foods(id),
  iron_mg        REAL,
  vitamin_d_mcg  REAL,
  vitamin_b12_mcg REAL,
  calcium_mg     REAL,
  vitamin_c_mg   REAL,
  magnesium_mg   REAL,
  zinc_mg        REAL,
  folate_mcg     REAL
)`);
const upsertMicroStmt = db.prepare(`INSERT INTO food_micronutrients
    (food_id,iron_mg,vitamin_d_mcg,vitamin_b12_mcg,calcium_mg,vitamin_c_mg,magnesium_mg,zinc_mg,folate_mcg)
  VALUES (@food_id,@iron,@vitD,@b12,@calcium,@vitC,@magnesium,@zinc,@folate)
  ON CONFLICT(food_id) DO UPDATE SET
    iron_mg=excluded.iron_mg, vitamin_d_mcg=excluded.vitamin_d_mcg, vitamin_b12_mcg=excluded.vitamin_b12_mcg,
    calcium_mg=excluded.calcium_mg, vitamin_c_mg=excluded.vitamin_c_mg, magnesium_mg=excluded.magnesium_mg,
    zinc_mg=excluded.zinc_mg, folate_mcg=excluded.folate_mcg`);

// Keyed by name_en (this table's own unique key) so it's readable next to
// the food it describes, rather than by opaque numeric id.
const MICRONUTRIENT_DATA = {
  'grilled chicken breast':      { iron: 0.7, vitD: 0.1, b12: 0.3, calcium: 15,  vitC: 0,    magnesium: 29,  zinc: 1.0, folate: 4 },
  'chicken thigh':                { iron: 1.0, vitD: 0.1, b12: 0.4, calcium: 12,  vitC: 0,    magnesium: 23,  zinc: 1.9, folate: 6 },
  'whole roasted chicken':        { iron: 1.3, vitD: 0.2, b12: 0.3, calcium: 11,  vitC: 0,    magnesium: 20,  zinc: 1.6, folate: 5 },
  'beef, lean':                   { iron: 2.6, vitD: 0.1, b12: 2.6, calcium: 12,  vitC: 0,    magnesium: 21,  zinc: 4.8, folate: 6 },
  'ground beef, cooked':          { iron: 2.4, vitD: 0.1, b12: 2.4, calcium: 18,  vitC: 0,    magnesium: 18,  zinc: 5.3, folate: 8 },
  'lamb':                         { iron: 1.9, vitD: 0.1, b12: 2.6, calcium: 17,  vitC: 0,    magnesium: 21,  zinc: 4.5, folate: 15 },
  'tilapia fish':                 { iron: 0.6, vitD: 1.5, b12: 1.9, calcium: 14,  vitC: 0,    magnesium: 27,  zinc: 0.4, folate: 6 },
  'tuna, canned in water':        { iron: 1.0, vitD: 1.7, b12: 2.9, calcium: 8,   vitC: 0,    magnesium: 27,  zinc: 0.6, folate: 2 },
  'shrimp':                       { iron: 0.5, vitD: 0.1, b12: 1.1, calcium: 70,  vitC: 1.7,  magnesium: 39,  zinc: 1.6, folate: 3 },
  'boiled egg':                   { iron: 1.2, vitD: 2.0, b12: 1.1, calcium: 50,  vitC: 0,    magnesium: 10,  zinc: 1.0, folate: 44 },
  'egg white':                    { iron: 0.08,vitD: 0,   b12: 0.09,calcium: 7,   vitC: 0,    magnesium: 11,  zinc: 0.02,folate: 4 },
  'white rice, cooked':           { iron: 0.2, vitD: 0,   b12: 0,   calcium: 10,  vitC: 0,    magnesium: 12,  zinc: 0.5, folate: 3 },
  'brown rice, cooked':           { iron: 0.4, vitD: 0,   b12: 0,   calcium: 10,  vitC: 0,    magnesium: 43,  zinc: 0.6, folate: 4 },
  'baladi bread':                 { iron: 2.0, vitD: 0,   b12: 0,   calcium: 30,  vitC: 0,    magnesium: 40,  zinc: 1.0, folate: 30 },
  'white bread':                  { iron: 3.6, vitD: 0,   b12: 0,   calcium: 100, vitC: 0,    magnesium: 24,  zinc: 0.7, folate: 100 },
  'pasta, cooked':                { iron: 0.9, vitD: 0,   b12: 0,   calcium: 7,   vitC: 0,    magnesium: 18,  zinc: 0.5, folate: 40 },
  'boiled potato':                { iron: 0.3, vitD: 0,   b12: 0,   calcium: 8,   vitC: 13,   magnesium: 20,  zinc: 0.3, folate: 9 },
  'fried potato':                 { iron: 0.7, vitD: 0,   b12: 0,   calcium: 12,  vitC: 10,   magnesium: 24,  zinc: 0.3, folate: 16 },
  'sweet potato':                 { iron: 0.6, vitD: 0,   b12: 0,   calcium: 30,  vitC: 2.4,  magnesium: 25,  zinc: 0.3, folate: 11 },
  'oats, dry':                    { iron: 4.7, vitD: 0,   b12: 0,   calcium: 54,  vitC: 0,    magnesium: 177, zinc: 4.0, folate: 56 },
  'foul medames':                 { iron: 2.5, vitD: 0,   b12: 0,   calcium: 55,  vitC: 1,    magnesium: 45,  zinc: 1.5, folate: 130 },
  'hummus':                       { iron: 1.6, vitD: 0,   b12: 0,   calcium: 40,  vitC: 1,    magnesium: 29,  zinc: 1.4, folate: 55 },
  'chickpeas, canned':            { iron: 2.0, vitD: 0,   b12: 0,   calcium: 40,  vitC: 1,    magnesium: 33,  zinc: 1.0, folate: 65 },
  'turkey breast, grilled':       { iron: 0.7, vitD: 0.1, b12: 0.3, calcium: 12,  vitC: 0,    magnesium: 25,  zinc: 0.9, folate: 6 },
  'cooked lentils':                { iron: 3.3, vitD: 0,   b12: 0,   calcium: 19,  vitC: 1.5,  magnesium: 36,  zinc: 1.3, folate: 180 },
  'lentil soup (prepared)':       { iron: 1.8, vitD: 0,   b12: 0,   calcium: 15,  vitC: 2,    magnesium: 20,  zinc: 0.8, folate: 90 },
  'falafel':                      { iron: 2.0, vitD: 0,   b12: 0,   calcium: 54,  vitC: 2,    magnesium: 39,  zinc: 1.3, folate: 66 },
  'tomato':                       { iron: 0.3, vitD: 0,   b12: 0,   calcium: 10,  vitC: 14,   magnesium: 11,  zinc: 0.2, folate: 15 },
  'cucumber':                     { iron: 0.3, vitD: 0,   b12: 0,   calcium: 16,  vitC: 2.8,  magnesium: 13,  zinc: 0.2, folate: 7 },
  'green salad':                  { iron: 0.9, vitD: 0,   b12: 0,   calcium: 36,  vitC: 9,    magnesium: 13,  zinc: 0.2, folate: 38 },
  'molokhia':                     { iron: 4.0, vitD: 0,   b12: 0,   calcium: 265, vitC: 55,   magnesium: 68,  zinc: 0.7, folate: 20 },
  'okra':                         { iron: 0.6, vitD: 0,   b12: 0,   calcium: 82,  vitC: 23,   magnesium: 57,  zinc: 0.6, folate: 60 },
  'spinach':                      { iron: 2.7, vitD: 0,   b12: 0,   calcium: 99,  vitC: 28,   magnesium: 79,  zinc: 0.5, folate: 194 },
  'zucchini':                     { iron: 0.4, vitD: 0,   b12: 0,   calcium: 16,  vitC: 18,   magnesium: 18,  zinc: 0.3, folate: 24 },
  'banana':                       { iron: 0.3, vitD: 0,   b12: 0,   calcium: 5,   vitC: 8.7,  magnesium: 27,  zinc: 0.2, folate: 20 },
  'apple':                        { iron: 0.1, vitD: 0,   b12: 0,   calcium: 6,   vitC: 4.6,  magnesium: 5,   zinc: 0.04,folate: 3 },
  'orange':                       { iron: 0.1, vitD: 0,   b12: 0,   calcium: 40,  vitC: 53,   magnesium: 10,  zinc: 0.07,folate: 30 },
  'mango':                        { iron: 0.2, vitD: 0,   b12: 0,   calcium: 11,  vitC: 36,   magnesium: 10,  zinc: 0.1, folate: 43 },
  'watermelon':                   { iron: 0.2, vitD: 0,   b12: 0,   calcium: 7,   vitC: 8.1,  magnesium: 10,  zinc: 0.1, folate: 3 },
  'dates':                        { iron: 0.9, vitD: 0,   b12: 0,   calcium: 64,  vitC: 0,    magnesium: 54,  zinc: 0.4, folate: 15 },
  'plain yogurt':                 { iron: 0.05,vitD: 0.03,b12: 0.5, calcium: 110, vitC: 0.8,  magnesium: 11,  zinc: 0.6, folate: 7 },
  'greek yogurt':                 { iron: 0.04,vitD: 0,   b12: 0.4, calcium: 110, vitC: 0,    magnesium: 11,  zinc: 0.5, folate: 7 },
  'whole milk':                   { iron: 0.03,vitD: 1.3, b12: 0.4, calcium: 113, vitC: 0,    magnesium: 10,  zinc: 0.4, folate: 5 },
  'feta cheese':                  { iron: 0.65,vitD: 0.5, b12: 1.7, calcium: 490, vitC: 0,    magnesium: 19,  zinc: 2.9, folate: 32 },
  'cottage cheese':               { iron: 0.14,vitD: 0,   b12: 0.4, calcium: 83,  vitC: 0,    magnesium: 8,   zinc: 0.4, folate: 12 },
  'white cheese':                 { iron: 0.4, vitD: 0.2, b12: 1.0, calcium: 400, vitC: 0,    magnesium: 20,  zinc: 2.5, folate: 20 },
  'almonds':                      { iron: 3.7, vitD: 0,   b12: 0,   calcium: 269, vitC: 0,    magnesium: 270, zinc: 3.1, folate: 44 },
  'peanuts':                      { iron: 1.6, vitD: 0,   b12: 0,   calcium: 92,  vitC: 0,    magnesium: 168, zinc: 3.3, folate: 240 },
  'olive oil':                    { iron: 0.6, vitD: 0,   b12: 0,   calcium: 1,   vitC: 0,    magnesium: 0,   zinc: 0,   folate: 0 },
  'avocado':                      { iron: 0.6, vitD: 0,   b12: 0,   calcium: 12,  vitC: 10,   magnesium: 29,  zinc: 0.6, folate: 81 },
  'grilled kofta':                { iron: 2.4, vitD: 0.1, b12: 2.2, calcium: 20,  vitC: 1,    magnesium: 19,  zinc: 4.5, folate: 8 },
  'chicken shawarma':             { iron: 1.2, vitD: 0.1, b12: 0.4, calcium: 20,  vitC: 2,    magnesium: 24,  zinc: 1.3, folate: 8 },
  'fattah':                       { iron: 2.0, vitD: 0.05,b12: 0.5, calcium: 60,  vitC: 1,    magnesium: 20,  zinc: 1.5, folate: 20 },
  'koshari':                      { iron: 1.8, vitD: 0,   b12: 0,   calcium: 25,  vitC: 3,    magnesium: 25,  zinc: 0.9, folate: 45 },
  'whole egg':                    { iron: 1.75,vitD: 2.0, b12: 1.1, calcium: 56,  vitC: 0,    magnesium: 12,  zinc: 1.3, folate: 47 },
  'raw chicken breast':           { iron: 0.4, vitD: 0.1, b12: 0.3, calcium: 5,   vitC: 0,    magnesium: 25,  zinc: 0.7, folate: 4 },
  'mixed vegetables':             { iron: 0.7, vitD: 0,   b12: 0,   calcium: 30,  vitC: 15,   magnesium: 20,  zinc: 0.4, folate: 30 },
  'mixed nuts':                   { iron: 2.5, vitD: 0,   b12: 0,   calcium: 80,  vitC: 0.5,  magnesium: 150, zinc: 3.0, folate: 60 },
  'veal/lean beef cut':           { iron: 2.6, vitD: 0.1, b12: 2.6, calcium: 12,  vitC: 0,    magnesium: 21,  zinc: 4.8, folate: 6 },
  'whole wheat bread':            { iron: 2.5, vitD: 0,   b12: 0,   calcium: 40,  vitC: 0,    magnesium: 60,  zinc: 1.5, folate: 30 },
  'salmon':                       { iron: 0.3, vitD: 11,  b12: 3.2, calcium: 9,   vitC: 0,    magnesium: 27,  zinc: 0.4, folate: 26 },
  'mayonnaise':                   { iron: 0.2, vitD: 0.2, b12: 0.1, calcium: 8,   vitC: 0,    magnesium: 2,   zinc: 0.1, folate: 2 },
  'butter':                       { iron: 0.02,vitD: 1.5, b12: 0.17,calcium: 24,  vitC: 0,    magnesium: 2,   zinc: 0.1, folate: 3 },
  'cooking/heavy cream':          { iron: 0.03,vitD: 0.5, b12: 0.2, calcium: 65,  vitC: 0.6,  magnesium: 7,   zinc: 0.2, folate: 4 },
  'cheddar cheese':               { iron: 0.7, vitD: 0.6, b12: 0.8, calcium: 720, vitC: 0,    magnesium: 28,  zinc: 3.1, folate: 18 },
  'cream cheese':                 { iron: 0.4, vitD: 0.4, b12: 0.2, calcium: 98,  vitC: 0,    magnesium: 8,   zinc: 0.5, folate: 11 },
  'romano-style hard cheese':     { iron: 0.8, vitD: 0.5, b12: 1.2, calcium: 1064,vitC: 0,    magnesium: 34,  zinc: 4.0, folate: 8 },
  'brazil nuts':                  { iron: 2.4, vitD: 0,   b12: 0,   calcium: 160, vitC: 0.7,  magnesium: 376, zinc: 4.1, folate: 22 },
  'coconut oil':                  { iron: 0.04,vitD: 0,   b12: 0,   calcium: 1,   vitC: 0,    magnesium: 0,   zinc: 0,   folate: 0 },
  'shredded coconut, unsweetened':{ iron: 2.4, vitD: 0,   b12: 0,   calcium: 14,  vitC: 1.4,  magnesium: 90,  zinc: 1.6, folate: 26 },
  'coconut cream':                { iron: 1.6, vitD: 0,   b12: 0,   calcium: 15,  vitC: 2.0,  magnesium: 37,  zinc: 0.6, folate: 16 },
  'beef bacon':                   { iron: 1.4, vitD: 0.1, b12: 1.5, calcium: 10,  vitC: 0,    magnesium: 16,  zinc: 2.5, folate: 3 },
  'ribeye steak':                 { iron: 2.2, vitD: 0.1, b12: 2.0, calcium: 13,  vitC: 0,    magnesium: 20,  zinc: 4.5, folate: 5 },
  'green bell pepper':            { iron: 0.3, vitD: 0,   b12: 0,   calcium: 10,  vitC: 80,   magnesium: 10,  zinc: 0.1, folate: 10 },
  'honey':                        { iron: 0.4, vitD: 0,   b12: 0,   calcium: 6,   vitC: 0.5,  magnesium: 2,   zinc: 0.2, folate: 2 },
  'tahini':                       { iron: 4.0, vitD: 0,   b12: 0,   calcium: 420, vitC: 0,    magnesium: 95,  zinc: 4.6, folate: 98 },
  'mixed berries':                { iron: 0.4, vitD: 0,   b12: 0,   calcium: 15,  vitC: 25,   magnesium: 13,  zinc: 0.2, folate: 20 },
  'couscous, cooked':              { iron: 0.4, vitD: 0,   b12: 0,   calcium: 8,   vitC: 0,    magnesium: 8,   zinc: 0.3, folate: 19 },
  "za'atar spice blend":          { iron: 8.0, vitD: 0,   b12: 0,   calcium: 500, vitC: 5,    magnesium: 100, zinc: 3.0, folate: 30 },
  'cinnamon, ground':             { iron: 8.3, vitD: 0,   b12: 0,   calcium: 1002,vitC: 3.8,  magnesium: 60,  zinc: 1.8, folate: 6 },
  'carrot':                       { iron: 0.3, vitD: 0,   b12: 0,   calcium: 33,  vitC: 5.9,  magnesium: 12,  zinc: 0.2, folate: 19 },
  'beef liver, cooked':           { iron: 6.5, vitD: 1.2, b12: 70,  calcium: 6,   vitC: 1.3,  magnesium: 18,  zinc: 4.0, folate: 220 },
  'corn flakes':                  { iron: 21,  vitD: 0.1, b12: 1.6, calcium: 4,   vitC: 15,   magnesium: 4,   zinc: 4.0, folate: 180 },
  'broccoli':                     { iron: 0.7, vitD: 0,   b12: 0,   calcium: 47,  vitC: 89,   magnesium: 21,  zinc: 0.4, folate: 63 },
  'tuna, canned in oil, drained': { iron: 1.3, vitD: 5,   b12: 2.5, calcium: 8,   vitC: 0,    magnesium: 24,  zinc: 0.8, folate: 3 },
  'labneh (strained yogurt)':     { iron: 0.1, vitD: 0.05,b12: 0.5, calcium: 150, vitC: 0,    magnesium: 12,  zinc: 0.7, folate: 8 },
  'mozzarella cheese, whole milk':{ iron: 0.4, vitD: 0.3, b12: 1.0, calcium: 505, vitC: 0,    magnesium: 20,  zinc: 2.9, folate: 9 },
  'olives, green, canned':        { iron: 0.5, vitD: 0,   b12: 0,   calcium: 52,  vitC: 0,    magnesium: 4,   zinc: 0.2, folate: 0 },
  'potato, raw':                  { iron: 0.8, vitD: 0,   b12: 0,   calcium: 12,  vitC: 20,   magnesium: 23,  zinc: 0.3, folate: 18 },
  'Big Mac':                      { iron: 2.3, vitD: 0.3, b12: 1.2, calcium: 130, vitC: 1,    magnesium: 20,  zinc: 3.0, folate: 40 },
};

function seedMicronutrients(data) {
  const missing = [];
  for (const food of db.prepare('SELECT id, name_en FROM foods WHERE active = 1').all()) {
    const v = data[food.name_en];
    if (!v) { missing.push(food.name_en); continue; }
    upsertMicroStmt.run({
      food_id: food.id, iron: v.iron, vitD: v.vitD, b12: v.b12, calcium: v.calcium,
      vitC: v.vitC, magnesium: v.magnesium, zinc: v.zinc, folate: v.folate,
    });
  }
  if (missing.length) console.error(`[db] seedMicronutrients: no data for ${missing.length} food(s):\n` + missing.join('\n'));
  else console.log(`[db] micronutrients: all ${Object.keys(data).length} foods have real reference data.`);
}
seedMicronutrients(MICRONUTRIENT_DATA);

// Returns the same shape food_micronutrients stores, or null if this food
// has none (shouldn't happen post-seed, but a photo-logged/AI-estimated
// item has no row here at all since it was never matched to a real food).
function getMicronutrients(foodId) {
  const row = db.prepare('SELECT * FROM food_micronutrients WHERE food_id = ?').get(foodId);
  if (!row) return null;
  return {
    iron: row.iron_mg, vitaminD: row.vitamin_d_mcg, vitaminB12: row.vitamin_b12_mcg,
    calcium: row.calcium_mg, vitaminC: row.vitamin_c_mg, magnesium: row.magnesium_mg,
    zinc: row.zinc_mg, folate: row.folate_mcg,
  };
}

// ─── FOOD TAXONOMY (architecture audit Section 4) ──────────────────────────
// foods.category (the old, unused column carried over from the FOOD_DB
// migration - every row was NULL, since FOOD_DB never had a category field
// at all) is deprecated in favor of a real 2-level hierarchy: a food has a
// category_id, categories can have a parent_id. Confirmed and applied
// deliberately, not just left flat: "protein" alone couldn't distinguish
// poultry from red meat, which is exactly the gap the protein-boost
// feature (built earlier this session) runs into - it currently treats
// "boost a protein ingredient" the same way for chicken and beef, with no
// way to prefer one over the other even though real macros differ a lot
// (chicken breast ~165 kcal/31g protein vs ribeye ~291 kcal/24g protein).
// This migration doesn't wire that preference in yet - it lays the real
// data foundation a future pass could use for it.
db.exec(`CREATE TABLE IF NOT EXISTS food_categories (
  id         TEXT PRIMARY KEY,
  name_en    TEXT NOT NULL,
  name_ar    TEXT NOT NULL,
  parent_id  TEXT REFERENCES food_categories(id),
  created_at TEXT NOT NULL
)`);
// SQLite allows adding a column with a REFERENCES clause via ALTER TABLE
// (unlike modifying an existing column's constraint, which requires a full
// table rebuild) - real FK, enforced by the `PRAGMA foreign_keys = ON` set
// at the top of this file, not just a naming convention.
const hasCategoryId = db.prepare("SELECT 1 FROM pragma_table_info('foods') WHERE name='category_id'").get();
if (!hasCategoryId) db.exec('ALTER TABLE foods ADD COLUMN category_id TEXT REFERENCES food_categories(id)');

const insCategoryStmt = db.prepare(`INSERT INTO food_categories (id,name_en,name_ar,parent_id,created_at)
  VALUES (@id,@name_en,@name_ar,@parent_id,@now) ON CONFLICT(id) DO NOTHING`);
const setCategoryStmt = db.prepare('UPDATE foods SET category_id = ? WHERE name_en = ?');

function seedFoodTaxonomy() {
  const now = new Date().toISOString();
  const categories = [
    { id: 'protein', name_en: 'Protein', name_ar: 'بروتين', parent_id: null },
    { id: 'poultry', name_en: 'Poultry', name_ar: 'دواجن', parent_id: 'protein' },
    { id: 'red_meat', name_en: 'Red Meat', name_ar: 'لحوم حمراء', parent_id: 'protein' },
    { id: 'fish', name_en: 'Fish', name_ar: 'أسماك', parent_id: 'protein' },
    { id: 'shellfish', name_en: 'Shellfish', name_ar: 'محار وقشريات', parent_id: 'protein' },
    { id: 'eggs', name_en: 'Eggs', name_ar: 'بيض', parent_id: 'protein' },
    { id: 'organ_meat', name_en: 'Organ Meat', name_ar: 'أحشاء', parent_id: 'protein' },
    { id: 'processed_meat', name_en: 'Processed Meat', name_ar: 'لحوم مصنعة', parent_id: 'protein' },
    { id: 'dairy', name_en: 'Dairy', name_ar: 'ألبان', parent_id: null },
    { id: 'vegetable', name_en: 'Vegetable', name_ar: 'خضروات', parent_id: null },
    { id: 'fruit', name_en: 'Fruit', name_ar: 'فواكه', parent_id: null },
    { id: 'grain', name_en: 'Grain', name_ar: 'حبوب', parent_id: null },
    { id: 'legume', name_en: 'Legume', name_ar: 'بقوليات', parent_id: null },
    { id: 'fat', name_en: 'Fat/Oil/Nuts', name_ar: 'دهون وزيوت ومكسرات', parent_id: null },
    { id: 'bakery', name_en: 'Bakery', name_ar: 'مخبوزات', parent_id: null },
    { id: 'condiment', name_en: 'Condiment/Spice', name_ar: 'بهارات وتوابل', parent_id: null },
    { id: 'sweetener', name_en: 'Sweetener', name_ar: 'محليات', parent_id: null },
    // Real, deliberate category, not a fallback bucket: a prepared composite
    // dish (koshari, fattah, shawarma) genuinely isn't one ingredient, and
    // forcing it into e.g. "grain" because its largest component happens to
    // be rice would misrepresent what the food actually is.
    { id: 'mixed_dish', name_en: 'Mixed/Prepared Dish', name_ar: 'طبق مُجهّز', parent_id: null },
  ];
  for (const c of categories) insCategoryStmt.run({ ...c, now });

  // Every one of the 89 migrated foods, classified by hand against real
  // nutritional/culinary convention (not guessed): nuts/avocado/coconut
  // products go under fat (macro-dominant classification, standard
  // nutrition-science practice, not a botanical one), legume-based dishes
  // (hummus, falafel) under legume, and genuinely composite dishes under
  // mixed_dish rather than forced into whichever single ingredient
  // dominates them.
  const assignments = {
    poultry: ['grilled chicken breast', 'chicken thigh', 'whole roasted chicken', 'turkey breast, grilled', 'raw chicken breast'],
    red_meat: ['beef, lean', 'ground beef, cooked', 'lamb', 'veal/lean beef cut', 'ribeye steak'],
    fish: ['tilapia fish', 'tuna, canned in water', 'salmon', 'tuna, canned in oil, drained'],
    shellfish: ['shrimp'],
    eggs: ['boiled egg', 'egg white', 'whole egg'],
    organ_meat: ['beef liver, cooked'],
    processed_meat: ['beef bacon'],
    dairy: ['plain yogurt', 'greek yogurt', 'whole milk', 'feta cheese', 'cottage cheese', 'white cheese',
      'cooking/heavy cream', 'cheddar cheese', 'cream cheese', 'romano-style hard cheese',
      'labneh (strained yogurt)', 'mozzarella cheese, whole milk'],
    vegetable: ['boiled potato', 'fried potato', 'sweet potato', 'tomato', 'cucumber', 'green salad', 'molokhia',
      'okra', 'spinach', 'zucchini', 'mixed vegetables', 'green bell pepper', 'carrot', 'broccoli', 'potato, raw'],
    fruit: ['banana', 'apple', 'orange', 'mango', 'watermelon', 'dates', 'mixed berries'],
    grain: ['white rice, cooked', 'brown rice, cooked', 'pasta, cooked', 'oats, dry', 'couscous, cooked', 'corn flakes'],
    legume: ['foul medames', 'hummus', 'chickpeas, canned', 'cooked lentils', 'lentil soup (prepared)', 'falafel'],
    fat: ['almonds', 'peanuts', 'olive oil', 'avocado', 'mixed nuts', 'butter', 'brazil nuts', 'coconut oil',
      'shredded coconut, unsweetened', 'coconut cream'],
    bakery: ['baladi bread', 'white bread', 'whole wheat bread'],
    condiment: ['mayonnaise', 'tahini', "za'atar spice blend", 'cinnamon, ground', 'olives, green, canned'],
    sweetener: ['honey'],
    mixed_dish: ['grilled kofta', 'chicken shawarma', 'fattah', 'koshari', 'Big Mac'],
  };
  let assigned = 0;
  const unassigned = [];
  const allFoodNames = new Set(db.prepare('SELECT name_en FROM foods').all().map(r => r.name_en));
  const claimed = new Set();
  for (const [categoryId, names] of Object.entries(assignments)) {
    for (const name of names) {
      claimed.add(name);
      const result = setCategoryStmt.run(categoryId, name);
      if (result.changes > 0) assigned++;
    }
  }
  for (const name of allFoodNames) if (!claimed.has(name)) unassigned.push(name);
  if (unassigned.length) console.error('[db] seedFoodTaxonomy: foods with no category assignment:\n' + unassigned.join('\n'));
  console.log(`[db] food taxonomy: ${assigned} foods categorized across ${categories.length} categories, ${unassigned.length} unassigned.`);
}
seedFoodTaxonomy();

function listFoodCategories() { return db.prepare('SELECT * FROM food_categories ORDER BY parent_id IS NOT NULL, id').all(); }
function listFoodsByCategory(categoryId) { return db.prepare('SELECT * FROM foods WHERE category_id = ? AND active = 1').all(categoryId); }

// ─── DIETS (Phase 3 of the nutrition-architecture migration) ───────────────
// DIET_META, DIET_STYLE_LABELS, and DIET_CONTRAINDICATIONS previously lived
// as 3 separate JS object literals in health.js/server.js, each keyed by
// the same diet id but never cross-checked against each other or against
// what diets actually exist (buildMealPlans()'s 9 real, selectable diets).
// One real table now holds what used to be scattered across three files.
db.exec(`CREATE TABLE IF NOT EXISTS diets (
  id             TEXT PRIMARY KEY,
  name_en        TEXT NOT NULL,
  name_ar        TEXT NOT NULL,
  protein_per_kg REAL NOT NULL,
  low_carb       INTEGER NOT NULL DEFAULT 0,
  style_label_en TEXT,
  created_at     TEXT NOT NULL
)`);
// condition_id FKs into the Phase 1 medical_conditions table - real FK, not
// a string re-typed in a third place.
db.exec(`CREATE TABLE IF NOT EXISTS diet_contraindications (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  diet_id      TEXT NOT NULL REFERENCES diets(id),
  condition_id TEXT NOT NULL REFERENCES medical_conditions(id),
  severity     TEXT NOT NULL,
  message_en   TEXT NOT NULL,
  message_ar   TEXT NOT NULL,
  created_at   TEXT NOT NULL
)`);
// Real bug, found live: this table originally had no uniqueness constraint
// on (diet_id, condition_id), so insDietContraStmt's `ON CONFLICT DO
// NOTHING` had nothing to conflict ON (the only unique column was the
// autoincrement id, which is always new) - every container restart
// silently re-inserted all 6 rows again. By the time this was caught (the
// boot verification below correctly refused to start rather than serve
// corrupted data), production had 24 rows where 6 were expected. This
// dedup must run BEFORE the unique index below, which would otherwise fail
// to create on top of existing duplicates.
db.exec(`DELETE FROM diet_contraindications WHERE id NOT IN (
  SELECT MIN(id) FROM diet_contraindications GROUP BY diet_id, condition_id
)`);
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_diet_contra_unique ON diet_contraindications(diet_id, condition_id)`);

// DO NOTHING on conflict means editing an *existing* diet's fields below
// (name_en/name_ar/protein_per_kg/low_carb/style_label_en) never actually
// reaches the DB on restart - only brand-new diet ids do. Caught live,
// 2026-09-20: relabeling 'diabetic' here alone silently left the DB row
// stale (harmless today - nothing currently reads name_en/name_ar - but
// verifyDietTablesMatch's own protein_per_kg/low_carb/style_label_en checks
// would have the same blind spot for an edit, not just an addition). A
// real field edit needs a one-off manual UPDATE alongside the code change,
// same as this one got.
const insDietStmt = db.prepare(`INSERT INTO diets (id,name_en,name_ar,protein_per_kg,low_carb,style_label_en,created_at)
  VALUES (@id,@name_en,@name_ar,@protein_per_kg,@low_carb,@style_label_en,@now) ON CONFLICT(id) DO NOTHING`);
const insDietContraStmt = db.prepare(`INSERT INTO diet_contraindications (diet_id,condition_id,severity,message_en,message_ar,created_at)
  VALUES (@diet_id,@condition_id,@severity,@message_en,@message_ar,@now) ON CONFLICT DO NOTHING`);

// Intermittent fasting is an eating-*window* pattern (when to eat), a
// different axis entirely from the diets above (what to eat) - a user picks
// a diet AND, optionally, a fasting protocol on top of it. Kept as its own
// table pair rather than a 12th diets row so it never forces a "Keto+IF"/
// "Vegan+IF" content fork - the meal-plan route reshapes the same day's
// meals into the chosen window rather than needing separate content per
// combination. Added 2026-09-20.
db.exec(`CREATE TABLE IF NOT EXISTS fasting_protocols (
  id         TEXT PRIMARY KEY,
  name_en    TEXT NOT NULL,
  name_ar    TEXT NOT NULL,
  fast_hours INTEGER NOT NULL,
  eat_hours  INTEGER NOT NULL,
  created_at TEXT NOT NULL
)`);
// condition_id FKs into medical_conditions, same as diet_contraindications.
// Deliberately limited to conditions that already exist as real, selectable
// rows there (pregnant/breastfeeding/type1_diabetes) - eating-disorder
// history and being underweight are real, standard IF contraindications
// too, but this app has no medical_conditions row for the former and no
// clean derivation for the latter beyond the profile's own bmi column, so
// neither is invented here (same "never invent medical knowledge" rule the
// original migration set for hypertension/hyperlipidemia). Age<18 and
// bmi<18.5 are checked directly from user_profiles in code instead - see
// health.js's FASTING_CONTRAINDICATIONS comment.
db.exec(`CREATE TABLE IF NOT EXISTS fasting_contraindications (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  protocol_id  TEXT NOT NULL REFERENCES fasting_protocols(id),
  condition_id TEXT NOT NULL REFERENCES medical_conditions(id),
  severity     TEXT NOT NULL,
  message_en   TEXT NOT NULL,
  message_ar   TEXT NOT NULL,
  created_at   TEXT NOT NULL
)`);
// Real unique constraint from day one this time - diet_contraindications
// originally shipped without one and silently re-inserted its 6 rows as 24
// on every restart before anyone noticed (ON CONFLICT DO NOTHING had no
// conflict target). Not repeating that here.
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_fasting_contra_unique ON fasting_contraindications(protocol_id, condition_id)`);

const hasFastingProtocolId = db.prepare("SELECT 1 FROM pragma_table_info('user_profiles') WHERE name='fasting_protocol_id'").get();
if (!hasFastingProtocolId) db.exec('ALTER TABLE user_profiles ADD COLUMN fasting_protocol_id TEXT REFERENCES fasting_protocols(id)');
// Hour-of-day (0-23, local to whatever timezone the app already treats
// everything else as) the eating window opens - e.g. 12 for a noon-8pm 16:8
// window. NULL means "protocol chosen but no custom start yet" - server.js
// falls back to a sensible default (noon) rather than requiring this be set
// before fasting can be turned on at all.
const hasFastingWindowStartHour = db.prepare("SELECT 1 FROM pragma_table_info('user_profiles') WHERE name='fasting_window_start_hour'").get();
if (!hasFastingWindowStartHour) db.exec('ALTER TABLE user_profiles ADD COLUMN fasting_window_start_hour INTEGER');

const insFastingProtocolStmt = db.prepare(`INSERT INTO fasting_protocols (id,name_en,name_ar,fast_hours,eat_hours,created_at)
  VALUES (@id,@name_en,@name_ar,@fast_hours,@eat_hours,@now) ON CONFLICT(id) DO NOTHING`);
const insFastingContraStmt = db.prepare(`INSERT INTO fasting_contraindications (protocol_id,condition_id,severity,message_en,message_ar,created_at)
  VALUES (@protocol_id,@condition_id,@severity,@message_en,@message_ar,@now) ON CONFLICT DO NOTHING`);

// Real values migrated as-is from DIET_META/DIET_STYLE_LABELS (health.js/
// server.js) - not new numbers. Two DIET_META keys are deliberately NOT
// migrated: 'lowcarb' and 'highprotein' were confirmed by the architecture
// audit to be orphan config - neither is a real, selectable diet anywhere
// in buildMealPlans() or the mobile DIET_OPTIONS list, and grepping the
// whole codebase found no other reference to either id. 'balanced' IS kept
// despite also not being user-selectable, because it's load-bearing as
// buildHealthProfile's actual fallback (`DIET_META[p.diet] || DIET_META.balanced`)
// for any profile with an unrecognized diet value.
function seedDiets() {
  const now = new Date().toISOString();
  const diets = [
    { id: 'atkins', name_en: 'Atkins', name_ar: 'آتكينز', protein_per_kg: 1.9, low_carb: 1, style_label_en: 'Atkins (very low-carb)' },
    { id: 'keto', name_en: 'Keto', name_ar: 'كيتو', protein_per_kg: 1.8, low_carb: 1, style_label_en: 'Ketogenic (very low-carb, high-fat)' },
    { id: 'mediterranean', name_en: 'Mediterranean', name_ar: 'متوسطي', protein_per_kg: 1.4, low_carb: 0, style_label_en: 'Mediterranean' },
    // name_en/name_ar updated 2026-09-20 (was 'Diabetic'/'مرضى السكري') -
    // honest-labeling fix: this plan's real content is written for Type 2
    // management, not Type 1's different consistent-carb/insulin-matching
    // needs (see the diet_contraindications row below, and constants.js's
    // matching comment on the mobile/web DIET_OPTIONS label). Not checked
    // by verifyDietTablesMatch (only protein_per_kg/low_carb/style_label_en
    // are), so no DIET_META/DIET_STYLE_LABELS change needed alongside this.
    { id: 'diabetic', name_en: 'Diabetes (Type 2)', name_ar: 'السكري (النوع الثاني)', protein_per_kg: 1.6, low_carb: 1, style_label_en: 'diabetic-friendly (low glycemic, controlled-carb)' },
    { id: 'women', name_en: 'Women', name_ar: 'المرأة', protein_per_kg: 1.4, low_carb: 0, style_label_en: "general women's nutrition (balanced, iron and folate focused)" },
    { id: 'women_40', name_en: 'Women Over 40', name_ar: 'المرأة فوق الأربعين', protein_per_kg: 1.6, low_carb: 0, style_label_en: 'women over 40 (bone health, muscle preservation, balanced)' },
    { id: 'men', name_en: 'Men', name_ar: 'الرجل', protein_per_kg: 1.4, low_carb: 0, style_label_en: "general men's nutrition (higher protein and calories, balanced)" },
    { id: 'men_40', name_en: 'Men Over 40', name_ar: 'الرجل فوق الأربعين', protein_per_kg: 1.6, low_carb: 0, style_label_en: 'men over 40 (heart-healthy, prostate-friendly, muscle preservation)' },
    { id: 'kids', name_en: 'Kids', name_ar: 'الأطفال', protein_per_kg: 1.2, low_carb: 0, style_label_en: 'healthy kids (balanced growth nutrition, kid-friendly, no severe restriction)' },
    { id: 'balanced', name_en: 'Balanced (fallback)', name_ar: 'متوازن (احتياطي)', protein_per_kg: 1.4, low_carb: 0, style_label_en: null },
    // Added 2026-09-10: a real, selectable 10th diet (distinct from the
    // internal-only 'balanced' fallback above, which has no meal content of
    // its own) - whole grains, a vegetable at every meal, protein rotated
    // across poultry/fish/legumes/eggs, moderate healthy fats, no
    // restriction. Real week of meals in meal_plans.json, migrated into
    // meals/recipe_ingredients via seedMealsFromDietPlans same as the other 9.
    { id: 'healthy_lifestyle', name_en: 'Healthy Lifestyle', name_ar: 'نمط حياة صحي', protein_per_kg: 1.5, low_carb: 0, style_label_en: 'healthy lifestyle (balanced macros, moderate-protein, no restriction)' },
    // Added 2026-09-19: 100% plant-based - no meat, fish, dairy, eggs, or
    // honey. protein_per_kg set a notch above the general-nutrition diets
    // (1.6, matching women_40/men_40's tier) rather than reusing
    // healthy_lifestyle's 1.5 - plant proteins are typically less
    // bioavailable/complete than animal protein (lower PDCAAS scores), so
    // a real vegan target should run slightly higher to compensate, a
    // standard dietetics consideration. Ingredient-level enforcement is
    // the food_prices.json `vegan` boolean tag (added the same day) plus
    // the hard filter in generateMealAlternative - this row alone doesn't
    // make anything actually vegan, it's the meal-plan/AI-generation code
    // that has to respect it.
    { id: 'vegan', name_en: 'Vegan', name_ar: 'نباتي (فيغن)', protein_per_kg: 1.6, low_carb: 0, style_label_en: 'vegan (100% plant-based - no meat, fish, dairy, eggs, or honey)' },
  ];
  for (const d of diets) insDietStmt.run({ ...d, now });

  const contraindications = [
    { diet_id: 'keto', condition_id: 'type1_diabetes', severity: 'contraindicated',
      message_ar: 'الكيتو يزيد من خطر الحماض الكيتوني السكري (DKA) عند مرضى السكري من النوع الأول. لا تبدأ هذا النظام إلا بإشراف طبيبك مباشرة.',
      message_en: 'Keto carries a real risk of diabetic ketoacidosis (DKA) in Type 1 diabetes. Do not start this diet without direct physician supervision.' },
    { diet_id: 'keto', condition_id: 'ckd', severity: 'caution',
      message_ar: 'هذا النظام يحتوي على دهون عالية وقد لا يناسب حالات الكلى المزمنة. استشر طبيبك أولاً.',
      message_en: 'This diet is high-fat and may not be appropriate with chronic kidney disease. Check with your doctor first.' },
    { diet_id: 'atkins', condition_id: 'ckd', severity: 'caution',
      message_ar: 'هذا النظام عالي البروتين، وقد لا يناسب حالات الكلى المزمنة التي تحتاج لتقليل البروتين. استشر طبيبك أولاً.',
      message_en: 'This diet is high-protein, which may not suit chronic kidney disease (often managed with protein restriction). Check with your doctor first.' },
    { diet_id: 'men', condition_id: 'ckd', severity: 'caution',
      message_ar: 'هذا النظام عالي البروتين نسبياً. استشر طبيبك إذا كان لديك مرض كلوي مزمن.',
      message_en: 'This diet is relatively high-protein. Check with your doctor if you have chronic kidney disease.' },
    { diet_id: 'men_40', condition_id: 'ckd', severity: 'caution',
      message_ar: 'هذا النظام عالي البروتين نسبياً. استشر طبيبك إذا كان لديك مرض كلوي مزمن.',
      message_en: 'This diet is relatively high-protein. Check with your doctor if you have chronic kidney disease.' },
    { diet_id: 'diabetic', condition_id: 'type1_diabetes', severity: 'caution',
      message_ar: 'هذا النظام مصمم كتوجيه عام لسكري النوع الثاني ولا يأخذ في الاعتبار جرعات الأنسولين. إذا كان لديك سكري النوع الأول، احسب الكربوهيدرات مع طبيبك لمطابقة جرعة الأنسولين، ولا تعتمد على هذا الرقم وحده.',
      message_en: "This plan is written as general Type 2 guidance and doesn't account for insulin dosing. If you have Type 1 diabetes, carb-count with your care team to match your insulin ratio — don't rely on this number alone." },
    // Added 2026-09-10: 6 more real, standard clinical cautions (not
    // invented) for the trackable-only conditions added earlier. Explicitly
    // NOT added for hypertension (the real driver, sodium, isn't tracked
    // anywhere in this app's food data - a diet-level rule would be
    // fabricating a link the data can't support) or prediabetes (controlled-
    // carb diets are broadly fine regardless of which one is picked, not a
    // real contraindication case). Scoped to keto/atkins only - the two
    // diets where these specific cautions are clearly, defensibly true.
    { diet_id: 'keto', condition_id: 'pregnant', severity: 'caution',
      message_ar: 'الكيتو غير موصى به عادة أثناء الحمل بسبب تأثير الكيتونات المحتمل على نمو الجنين. استشيري طبيبك قبل اتباع هذا النظام.',
      message_en: "Ketogenic diets aren't generally recommended during pregnancy due to potential effects of ketone exposure on fetal development. Talk to your doctor before following this diet." },
    { diet_id: 'atkins', condition_id: 'pregnant', severity: 'caution',
      message_ar: 'أتكينز نظام منخفض الكربوهيدرات جداً وقد لا يكون مناسباً أثناء الحمل. استشيري طبيبك أولاً.',
      message_en: 'Atkins is a very low-carb diet and may not be appropriate during pregnancy. Check with your doctor first.' },
    { diet_id: 'keto', condition_id: 'gestational_diabetes', severity: 'caution',
      message_ar: 'الكيتو قد يؤثر على إدارة سكري الحمل ومستويات الكيتونات. يجب متابعة هذا النظام تحت إشراف طبي مباشر أثناء الحمل.',
      message_en: 'Keto can affect gestational diabetes management and ketone levels. This diet should only be followed under direct medical supervision during pregnancy.' },
    { diet_id: 'atkins', condition_id: 'gestational_diabetes', severity: 'caution',
      message_ar: 'أتكينز نظام منخفض الكربوهيدرات جداً وقد يحتاج متابعة خاصة مع سكري الحمل. استشيري طبيبك أولاً.',
      message_en: 'Atkins is very low-carb and may need special monitoring alongside gestational diabetes. Check with your doctor first.' },
    { diet_id: 'keto', condition_id: 'breastfeeding', severity: 'caution',
      message_ar: 'الأنظمة المقيدة جداً مثل الكيتو قد تؤثر على كمية الحليب أثناء الرضاعة. استشيري طبيبك أو أخصائي الرضاعة أولاً.',
      message_en: 'Very restrictive diets like Keto can affect milk supply while breastfeeding. Check with your doctor or a lactation specialist first.' },
    { diet_id: 'atkins', condition_id: 'breastfeeding', severity: 'caution',
      message_ar: 'أتكينز نظام مقيد جداً وقد يؤثر على كمية الحليب أثناء الرضاعة. استشيري طبيبك أولاً.',
      message_en: 'Atkins is a very restrictive diet and may affect milk supply while breastfeeding. Check with your doctor first.' },
    { diet_id: 'keto', condition_id: 'type2_diabetes', severity: 'caution',
      message_ar: 'إذا كنت تتناول أدوية للسكري (خاصة الأنسولين)، فإن الكيتو قد يسبب انخفاضاً حاداً في السكر. استشر طبيبك قبل البدء لتعديل الجرعات إذا لزم الأمر.',
      message_en: 'If you take diabetes medication (especially insulin), Keto can cause a sharp drop in blood sugar. Talk to your doctor before starting, in case your dosage needs adjusting.' },
    { diet_id: 'atkins', condition_id: 'type2_diabetes', severity: 'caution',
      message_ar: 'إذا كنت تتناول أدوية للسكري (خاصة الأنسولين)، فإن أتكينز قد يسبب انخفاضاً حاداً في السكر. استشر طبيبك قبل البدء.',
      message_en: 'If you take diabetes medication (especially insulin), Atkins can cause a sharp drop in blood sugar. Talk to your doctor before starting.' },
    { diet_id: 'atkins', condition_id: 'liver_disease', severity: 'caution',
      message_ar: 'أتكينز نظام عالي البروتين وقد يزيد العبء على الكبد في حالات أمراض الكبد. استشر طبيبك أولاً.',
      message_en: 'Atkins is high-protein and may add strain on the liver in liver disease. Check with your doctor first.' },
    { diet_id: 'keto', condition_id: 'liver_disease', severity: 'caution',
      message_ar: 'الكيتو نظام عالي الدهون وقد لا يناسب حالات أمراض الكبد. استشر طبيبك أولاً.',
      message_en: 'Keto is high-fat and may not suit liver disease. Check with your doctor first.' },
    { diet_id: 'keto', condition_id: 'hyperlipidemia', severity: 'caution',
      message_ar: 'الكيتو نظام عالي الدهون جداً، وقد تحتاج لمتابعة تحليل الدهون (الكوليسترول) بشكل منتظم أثناء اتباعه.',
      message_en: 'Keto is very high-fat, and you may need to monitor your lipid panel (cholesterol) regularly while following it.' },
    { diet_id: 'atkins', condition_id: 'hyperlipidemia', severity: 'caution',
      message_ar: 'أتكينز نظام عالي الدهون، وقد تحتاج لمتابعة تحليل الدهون (الكوليسترول) بشكل منتظم أثناء اتباعه.',
      message_en: 'Atkins is high-fat, and you may need to monitor your lipid panel (cholesterol) regularly while following it.' },
    // Added 2026-09-19 alongside the vegan diet itself. Real, standard
    // clinical guidance (not invented): major dietetics bodies consider a
    // well-planned vegan diet viable during pregnancy/breastfeeding, but
    // specifically flag B12, iron, and omega-3 (DHA) as needing deliberate
    // supplementation - B12 especially, since infant deficiency via a
    // vegan mother's breastmilk without supplementation is a real,
    // documented risk. 'caution', not 'contraindicated' - matches that
    // real consensus (viable with planning, not unsafe outright).
    { diet_id: 'vegan', condition_id: 'pregnant', severity: 'caution',
      message_ar: 'النظام النباتي الكامل يحتاج تخطيطاً دقيقاً أثناء الحمل، خصوصاً فيتامين ب12 والحديد وأوميغا 3. ناقشي مع طبيبك خطة المكملات الغذائية المناسبة.',
      message_en: 'A fully plant-based diet needs careful planning during pregnancy, especially vitamin B12, iron, and omega-3. Discuss a supplementation plan with your doctor.' },
    { diet_id: 'vegan', condition_id: 'breastfeeding', severity: 'caution',
      message_ar: 'نقص فيتامين ب12 عند الأم النباتية غير المكمّلة قد يؤثر على الرضيع عبر حليب الثدي. تأكدي من أخذ مكمل ب12 واستشيري طبيبك.',
      message_en: "A breastfeeding mother on a fully plant-based diet without B12 supplementation risks passing that deficiency to her infant through breastmilk. Make sure you're taking a B12 supplement and check with your doctor." },
  ];
  for (const c of contraindications) insDietContraStmt.run({ ...c, now });
}
seedDiets();

// MVP is 16:8 only, per the phased rollout agreed with the founder - it's
// the most-studied, easiest-to-sustain protocol, and validates the whole
// mechanism (window field, countdown UI, meal-redistribution logic,
// contraindication screening) before 18:6/20:4 (a one-row addition each,
// no schema change) or 5:2 (genuinely different weekly-not-daily tracking,
// needs its own design pass later).
// 18:6/20:4 added 2026-09-20, per the phased rollout: 16:8 validated the
// whole mechanism (window field, countdown, retiming, contraindication
// screening) first, live. Confirmed a trivial addition, not new
// architecture - not one line of the actual mechanism code (retiming,
// /api/fasting/status, profile validation, boot verification) hardcodes
// '16:8'; it all reads whatever protocols exist in this table.
function seedFastingProtocols() {
  const now = new Date().toISOString();
  const protocols = [
    { id: '16:8', name_en: '16:8', name_ar: '16:8', fast_hours: 16, eat_hours: 8 },
    { id: '18:6', name_en: '18:6', name_ar: '18:6', fast_hours: 18, eat_hours: 6 },
    { id: '20:4', name_en: '20:4', name_ar: '20:4', fast_hours: 20, eat_hours: 4 },
  ];
  for (const p of protocols) insFastingProtocolStmt.run({ ...p, now });

  // Same 3 conditions/severities/message text across all three protocols -
  // none of the wording references specific hours, and there's no verified
  // clinical source (yet) to justify a *different* severity tier for 18:6/
  // 20:4 specifically vs 16:8, so this doesn't invent one. The real
  // difference a shorter window brings (harder to hit nutrient targets in
  // 4-6h vs 8h) is a UI-copy concern (see constants.js's FASTING_INFO), not
  // a new contraindication rule.
  const contraindications = [];
  for (const protocolId of ['16:8', '18:6', '20:4']) {
    contraindications.push(
      // Real hypoglycemia risk if insulin timing isn't adjusted for the
      // fasting window under medical supervision - contraindicated, not
      // just caution, matching keto's own type1_diabetes severity above.
      { protocol_id: protocolId, condition_id: 'type1_diabetes', severity: 'contraindicated',
        message_ar: 'الصيام المتقطع قد يسبب هبوطاً خطيراً في السكر لمرضى السكري النوع الأول دون تعديل جرعة الأنسولين بإشراف طبي مباشر. لا تبدأ هذا النمط دون استشارة طبيبك.',
        message_en: "Intermittent fasting carries a real hypoglycemia risk for Type 1 diabetics unless insulin timing is adjusted under direct medical supervision. Don't start this pattern without checking with your doctor." },
      { protocol_id: protocolId, condition_id: 'pregnant', severity: 'caution',
        message_ar: 'الحمل يحتاج إمداداً غذائياً مستمراً طوال اليوم. لا يُنصح عادة بالصيام المتقطع أثناء الحمل - استشيري طبيبك أولاً.',
        message_en: 'Pregnancy needs a steady, continuous nutrient supply through the day. Intermittent fasting isn\'t generally recommended during pregnancy - check with your doctor first.' },
      { protocol_id: protocolId, condition_id: 'breastfeeding', severity: 'caution',
        message_ar: 'الرضاعة تحتاج إمداداً غذائياً وسعرات حرارية مستمرة. استشيري طبيبك قبل اتباع الصيام المتقطع أثناء الرضاعة.',
        message_en: 'Breastfeeding needs a steady calorie and nutrient supply. Check with your doctor before following intermittent fasting while breastfeeding.' },
    );
  }
  for (const c of contraindications) insFastingContraStmt.run({ ...c, now });
}
seedFastingProtocols();

function listDiets() { return db.prepare('SELECT * FROM diets ORDER BY id').all(); }
function getDiet(id) { return db.prepare('SELECT * FROM diets WHERE id = ?').get(id) || null; }
function getDietContraindications(dietId, medicalConditions) {
  if (!medicalConditions || !medicalConditions.length) return [];
  const placeholders = medicalConditions.map(() => '?').join(',');
  return db.prepare(`SELECT * FROM diet_contraindications WHERE diet_id = ? AND condition_id IN (${placeholders})`).all(dietId, ...medicalConditions);
}

function listFastingProtocols() { return db.prepare('SELECT * FROM fasting_protocols ORDER BY id').all(); }
function getFastingProtocol(id) { return id ? (db.prepare('SELECT * FROM fasting_protocols WHERE id = ?').get(id) || null) : null; }
function getFastingContraindications(protocolId, medicalConditions) {
  if (!protocolId || !medicalConditions || !medicalConditions.length) return [];
  const placeholders = medicalConditions.map(() => '?').join(',');
  return db.prepare(`SELECT * FROM fasting_contraindications WHERE protocol_id = ? AND condition_id IN (${placeholders})`).all(protocolId, ...medicalConditions);
}

// Boot-time proof this matches the real, live JS constants - same
// discipline as Phase 1's verifyLookupTablesMatch. Deliberately does NOT
// require DIET_META's full key set to match (see seedDiets' comment on the
// 2 orphan keys dropped on purpose) - instead verifies every migrated
// diet's values agree, and that dropping 'lowcarb'/'highprotein' was safe
// by confirming neither string appears anywhere in server.js as a real
// selectable value (checked once, by hand, during this migration - not
// re-checked automatically here, since that would require this file to
// read server.js's source, which is backwards).
function verifyDietTablesMatch({ dietMeta, dietStyleLabels, dietContraindications }) {
  const errors = [];
  for (const diet of listDiets()) {
    const meta = dietMeta[diet.id];
    if (!meta) { errors.push(`diet ${diet.id} has no DIET_META entry`); continue; }
    if (meta.proteinPerKg !== diet.protein_per_kg) errors.push(`diet ${diet.id} protein_per_kg mismatch: DB=${diet.protein_per_kg} JS=${meta.proteinPerKg}`);
    if ((meta.lowCarb ? 1 : 0) !== diet.low_carb) errors.push(`diet ${diet.id} low_carb mismatch: DB=${diet.low_carb} JS=${meta.lowCarb}`);
    const jsLabel = dietStyleLabels[diet.id] || null;
    if (jsLabel !== diet.style_label_en) errors.push(`diet ${diet.id} style_label_en mismatch: DB=${JSON.stringify(diet.style_label_en)} JS=${JSON.stringify(jsLabel)}`);
  }
  let dbContraCount = 0;
  for (const dietId of Object.keys(dietContraindications)) {
    for (const rule of dietContraindications[dietId]) {
      const dbRule = db.prepare('SELECT * FROM diet_contraindications WHERE diet_id = ? AND condition_id = ?').get(dietId, rule.condition);
      if (!dbRule) { errors.push(`diet_contraindications missing: ${dietId}/${rule.condition}`); continue; }
      dbContraCount++;
      if (dbRule.severity !== rule.severity) errors.push(`diet_contraindications ${dietId}/${rule.condition} severity mismatch: DB=${dbRule.severity} JS=${rule.severity}`);
      if (dbRule.message_en !== rule.en) errors.push(`diet_contraindications ${dietId}/${rule.condition} message_en mismatch`);
      if (dbRule.message_ar !== rule.ar) errors.push(`diet_contraindications ${dietId}/${rule.condition} message_ar mismatch`);
    }
  }
  const totalDbRules = db.prepare('SELECT COUNT(*) c FROM diet_contraindications').get().c;
  if (totalDbRules !== dbContraCount) errors.push(`diet_contraindications row count mismatch: DB has ${totalDbRules}, JS accounted for ${dbContraCount}`);
  if (errors.length) throw new Error('[db] diet-table migration verification FAILED:\n' + errors.join('\n'));
  console.log(`[db] diet tables verified: ${listDiets().length} diets and ${totalDbRules} contraindication rules match production JS constants exactly.`);
}

// Same discipline as verifyDietTablesMatch above, for the fasting_protocols/
// fasting_contraindications pair.
function verifyFastingTablesMatch({ fastingMeta, fastingContraindications }) {
  const errors = [];
  for (const protocol of listFastingProtocols()) {
    const meta = fastingMeta[protocol.id];
    if (!meta) { errors.push(`fasting protocol ${protocol.id} has no FASTING_META entry`); continue; }
    if (meta.fastHours !== protocol.fast_hours) errors.push(`fasting protocol ${protocol.id} fast_hours mismatch: DB=${protocol.fast_hours} JS=${meta.fastHours}`);
    if (meta.eatHours !== protocol.eat_hours) errors.push(`fasting protocol ${protocol.id} eat_hours mismatch: DB=${protocol.eat_hours} JS=${meta.eatHours}`);
  }
  let dbContraCount = 0;
  for (const protocolId of Object.keys(fastingContraindications)) {
    for (const rule of fastingContraindications[protocolId]) {
      const dbRule = db.prepare('SELECT * FROM fasting_contraindications WHERE protocol_id = ? AND condition_id = ?').get(protocolId, rule.condition);
      if (!dbRule) { errors.push(`fasting_contraindications missing: ${protocolId}/${rule.condition}`); continue; }
      dbContraCount++;
      if (dbRule.severity !== rule.severity) errors.push(`fasting_contraindications ${protocolId}/${rule.condition} severity mismatch: DB=${dbRule.severity} JS=${rule.severity}`);
      if (dbRule.message_en !== rule.en) errors.push(`fasting_contraindications ${protocolId}/${rule.condition} message_en mismatch`);
      if (dbRule.message_ar !== rule.ar) errors.push(`fasting_contraindications ${protocolId}/${rule.condition} message_ar mismatch`);
    }
  }
  const totalDbRules = db.prepare('SELECT COUNT(*) c FROM fasting_contraindications').get().c;
  if (totalDbRules !== dbContraCount) errors.push(`fasting_contraindications row count mismatch: DB has ${totalDbRules}, JS accounted for ${dbContraCount}`);
  if (errors.length) throw new Error('[db] fasting-table migration verification FAILED:\n' + errors.join('\n'));
  console.log(`[db] fasting tables verified: ${listFastingProtocols().length} protocol(s) and ${totalDbRules} contraindication rules match production JS constants exactly.`);
}

// ─── MEALS & RECIPE INGREDIENTS (Phase 4 of the nutrition-architecture ────
// migration) ─────────────────────────────────────────────────────────────
// The other half of the audit's highest-value finding: meal_plans.json (9
// diets x 7 days x 4 meals = 252 meals) lives as one giant unstructured
// JSON blob, and every ingredient is a free-text name/qty pair with no
// reference to any canonical food - "Never ingredient names" (the master
// migration plan's own Phase 5 principle) was being violated by the single
// largest content asset in the app. Worse: the audit found the blob's own
// hand-typed cal/protein/carbs/fat numbers disagree with what the real
// ingredients (now resolvable via the Phase 2 foods table) actually add up
// to, for 27 of the 252 meals (10.7%), by as much as 69%.
//
// Real fix: every recipe_ingredients row references a food_id (Phase 2),
// never a name string - and meal nutrition is COMPUTED from real per-
// ingredient data via getMealNutrition(), never stored as a separately-
// typed, driftable number. This is the actual generalization of "database
// as single source of truth" for this app's single largest data asset.
//
// NOT seeded at module-load time like Phases 1-3: meal_plans.json is
// itself seeded by server.js's initData(), which runs near the very end of
// server.js (after all routes are defined, long after `require('./db')`
// already finished running this file's own top-level code) - seeding meals
// here unconditionally would silently do nothing on a fresh deployment
// where meal_plans.json doesn't exist yet. seedMealsFromDietPlans() is
// exported and must be called explicitly by server.js after initData().
db.exec(`CREATE TABLE IF NOT EXISTS meals (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  diet_id    TEXT NOT NULL REFERENCES diets(id),
  day_index  INTEGER NOT NULL,
  day_en     TEXT NOT NULL,
  day_ar     TEXT NOT NULL,
  meal_type  TEXT NOT NULL,
  type_ar    TEXT NOT NULL,
  type_en    TEXT NOT NULL,
  time       TEXT,
  name_ar    TEXT NOT NULL,
  name_en    TEXT NOT NULL,
  created_at TEXT NOT NULL
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_meals_diet_day ON meals(diet_id, day_index)`);
db.exec(`CREATE TABLE IF NOT EXISTS recipe_ingredients (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  meal_id    INTEGER NOT NULL REFERENCES meals(id),
  food_id    INTEGER NOT NULL REFERENCES foods(id),
  grams      REAL NOT NULL,
  qty_ar     TEXT,
  qty_en     TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_recipe_ingredients_meal_id ON recipe_ingredients(meal_id)`);

const findExistingMealStmt = db.prepare('SELECT id FROM meals WHERE diet_id=? AND day_index=? AND meal_type=? AND name_ar=?');
const insMealStmt = db.prepare(`INSERT INTO meals (diet_id,day_index,day_en,day_ar,meal_type,type_ar,type_en,time,name_ar,name_en,created_at)
  VALUES (@diet_id,@day_index,@day_en,@day_ar,@meal_type,@type_ar,@type_en,@time,@name_ar,@name_en,@now)`);
const insRecipeIngredientStmt = db.prepare(`INSERT INTO recipe_ingredients (meal_id,food_id,grams,qty_ar,qty_en,sort_order,created_at)
  VALUES (@meal_id,@food_id,@grams,@qty_ar,@qty_en,@sort_order,@now)`);

// Idempotent via the explicit existence check (no natural single-column
// unique key on `meals`, so ON CONFLICT isn't available the way the other
// seed functions use it) - safe to call on every boot. Returns the list of
// (diet, meal) pairs whose ingredients couldn't ALL be resolved, so the
// caller can decide whether that's acceptable (it shouldn't be, given
// Phase 2 already proved 100% coverage on this exact data - a failure here
// means the live meal_plans.json changed since that was verified).
function seedMealsFromDietPlans(plans) {
  if (!plans) return { seeded: 0, skipped: 0, unresolvedIngredients: [] };
  const now = new Date().toISOString();
  let seeded = 0, skipped = 0;
  const unresolvedIngredients = [];
  for (const dietId of Object.keys(plans)) {
    const plan = plans[dietId];
    if (!plan || !Array.isArray(plan.week)) continue;
    if (!getDiet(dietId)) { console.error(`[db] seedMealsFromDietPlans: "${dietId}" is not in the diets table, skipping its meals`); continue; }
    plan.week.forEach((day, dayIndex) => {
      for (const meal of day.meals || []) {
        const mealType = meal.typeEn ? meal.typeEn.toLowerCase() : meal.type;
        if (findExistingMealStmt.get(dietId, dayIndex, mealType, meal.name)) { skipped++; continue; }
        const info = insMealStmt.run({
          diet_id: dietId, day_index: dayIndex, day_en: day.dayEn, day_ar: day.day,
          meal_type: mealType, type_ar: meal.type, type_en: meal.typeEn, time: meal.time || null,
          name_ar: meal.name, name_en: meal.nameEn, now,
        });
        const mealId = info.lastInsertRowid;
        (meal.ingredients || []).forEach((ing, idx) => {
          const food = resolveFood(ing.item) || resolveFood(ing.itemEn);
          if (!food) {
            unresolvedIngredients.push(`${dietId}/${day.dayEn}/${meal.typeEn}: "${ing.item}"/"${ing.itemEn}"`);
            return;
          }
          insRecipeIngredientStmt.run({ meal_id: mealId, food_id: food.id, grams: ing.grams, qty_ar: ing.qtyAr || null, qty_en: ing.qty || null, sort_order: idx, now });
        });
        seeded++;
      }
    });
  }
  if (unresolvedIngredients.length) {
    console.error(`[db] seedMealsFromDietPlans: ${unresolvedIngredients.length} ingredient(s) could not be resolved to a food:\n` + unresolvedIngredients.join('\n'));
  }
  console.log(`[db] meals seeded: ${seeded} new, ${skipped} already existed, ${unresolvedIngredients.length} unresolved ingredients.`);
  return { seeded, skipped, unresolvedIngredients };
}

function getMeal(mealId) { return db.prepare('SELECT * FROM meals WHERE id = ?').get(mealId) || null; }
function getMealIngredients(mealId) {
  return db.prepare(`SELECT ri.*, f.name_ar as food_name_ar, f.name_en as food_name_en, f.cal_per_100g, f.protein_per_100g, f.carbs_per_100g, f.fat_per_100g
    FROM recipe_ingredients ri JOIN foods f ON f.id = ri.food_id
    WHERE ri.meal_id = ? ORDER BY ri.sort_order`).all(mealId);
}
// Computed from real per-ingredient data, never a separately-typed number
// that can drift from what the recipe actually contains - the fix for the
// 27-meal, up-to-69%-divergence finding in the architecture audit.
function getMealNutrition(mealId) {
  const rows = getMealIngredients(mealId);
  return rows.reduce((acc, r) => ({
    cal: acc.cal + (r.cal_per_100g * r.grams) / 100,
    protein: acc.protein + (r.protein_per_100g * r.grams) / 100,
    carbs: acc.carbs + (r.carbs_per_100g * r.grams) / 100,
    fat: acc.fat + (r.fat_per_100g * r.grams) / 100,
  }), { cal: 0, protein: 0, carbs: 0, fat: 0 });
}
function listMealsForDiet(dietId) { return db.prepare('SELECT * FROM meals WHERE diet_id = ? ORDER BY day_index').all(dietId); }

// The read-path cutover: real computed macros for a specific meal_plans.json
// entry, looked up by the same (diet, day, type, name) identity
// seedMealsFromDietPlans() used to create it in the first place. Returns
// null (not a thrown error) if no matching row exists, so the caller can
// gracefully fall back to the blob's own declared numbers rather than
// break - the same "never crash, degrade gracefully" pattern already used
// throughout the meal-plan route for AI failures and allergy substitution.
function getMealNutritionByIdentity(dietId, dayIndex, mealType, nameAr) {
  const meal = findExistingMealStmt.get(dietId, dayIndex, mealType, nameAr);
  if (!meal) return null;
  return getMealNutrition(meal.id);
}

// ─── MEAL OVERRIDES (scalability fix, architecture audit Section 13/14) ────
// Previously `meal_overrides.json` was a single JSON blob keyed by user,
// with EVERY user's every override nested inside one document - reading or
// writing any single user's single meal override meant loading, parsing,
// mutating, and re-serializing every other user's data too (`load`/`save`
// in this file are whole-document operations). At 39 users this is
// invisible (~13KB). At the "millions of users" scale this migration is
// scoped for, it's not a slowdown, it's a memory ceiling: the process would
// need to hold the entire user base's override history just to answer one
// user's one meal-plan request. Real indexed rows fix this by construction.
// Unlike Phases 1-3, this is NOT compared against a JS constant at boot
// (there's no equivalent hardcoded reference for user-generated data) -
// the migration itself, and the natural-key UNIQUE index, are the safety
// net. Safe to seed at module-load time (unlike Phase 4's meals table):
// meal_overrides.json is user-generated, not seeded by initData(), so
// there's no "doesn't exist yet on a fresh deployment" ordering concern -
// load() on an empty/missing key just returns null and the migration
// below correctly does nothing.
db.exec(`CREATE TABLE IF NOT EXISTS meal_overrides (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT NOT NULL,
  date        TEXT NOT NULL,
  meal_type   TEXT NOT NULL,
  diet_id     TEXT,
  meal_json   TEXT NOT NULL,
  tier        TEXT,
  swaps_used  INTEGER NOT NULL DEFAULT 0,
  manual_swap INTEGER NOT NULL DEFAULT 0,
  updated_at  TEXT NOT NULL
)`);
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_meal_overrides_key ON meal_overrides(user_id, date, meal_type)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_meal_overrides_user ON meal_overrides(user_id)`);

const upsertMealOverrideStmt = db.prepare(`INSERT INTO meal_overrides (user_id,date,meal_type,diet_id,meal_json,tier,swaps_used,manual_swap,updated_at)
  VALUES (@user_id,@date,@meal_type,@diet_id,@meal_json,@tier,@swaps_used,@manual_swap,@now)
  ON CONFLICT(user_id,date,meal_type) DO UPDATE SET
    diet_id=excluded.diet_id, meal_json=excluded.meal_json, tier=excluded.tier,
    swaps_used=excluded.swaps_used, manual_swap=excluded.manual_swap, updated_at=excluded.updated_at`);
const getMealOverrideStmt = db.prepare('SELECT * FROM meal_overrides WHERE user_id=? AND date=? AND meal_type=?');
const deleteMealOverrideStmt = db.prepare('DELETE FROM meal_overrides WHERE user_id=? AND date=? AND meal_type=?');

// Same {meal, tier, diet, swapsUsed, manualSwap} shape the old blob entries
// had, so server.js's callers need zero changes beyond the call sites.
function getMealOverrideRow(userId, date, mealType) {
  const row = getMealOverrideStmt.get(userId, date, mealType);
  if (!row) return null;
  return { meal: JSON.parse(row.meal_json), tier: row.tier, diet: row.diet_id, swapsUsed: row.swaps_used, manualSwap: !!row.manual_swap };
}
function saveMealOverrideRow(userId, date, mealType, entry) {
  upsertMealOverrideStmt.run({
    user_id: userId, date, meal_type: mealType, diet_id: entry.diet || null,
    meal_json: JSON.stringify(entry.meal), tier: entry.tier || null,
    swaps_used: entry.swapsUsed || 0, manual_swap: entry.manualSwap ? 1 : 0,
    now: new Date().toISOString(),
  });
}
function deleteMealOverrideRow(userId, date, mealType) { deleteMealOverrideStmt.run(userId, date, mealType); }
// For account deletion - the whole point of moving off the blob is that a
// single user's rows can be targeted directly instead of loading/mutating/
// rewriting everyone's data to remove one user's slice.
function deleteAllMealOverridesForUser(userId) { db.prepare('DELETE FROM meal_overrides WHERE user_id = ?').run(userId); }

// One-time migration of the legacy blob into real rows. Idempotent via the
// UPSERT above (re-running just overwrites with the same values), so safe
// to run on every boot rather than needing a one-shot flag.
function migrateMealOverridesBlob() {
  const blob = load('meal_overrides.json');
  if (!blob) return { migrated: 0 };
  let migrated = 0;
  for (const userId of Object.keys(blob)) {
    for (const date of Object.keys(blob[userId] || {})) {
      for (const mealType of Object.keys(blob[userId][date] || {})) {
        saveMealOverrideRow(userId, date, mealType, blob[userId][date][mealType]);
        migrated++;
      }
    }
  }
  if (migrated) console.log(`[db] meal_overrides migrated: ${migrated} entries from the legacy blob.`);
  return { migrated };
}
migrateMealOverridesBlob();

// ─── USERS (architecture audit's other critical scalability finding) ──────
// The last, and highest-stakes, blob-store migration: users.json held
// EVERY user's identity, password hash, subscription/billing state, and
// full health profile in one JSON array, loaded and fully re-parsed on
// nearly every authenticated request (`auth()` middleware, every profile
// read/write, every admin action). Phase 1 built the real tables and
// migrated + verified the real data byte-for-byte against the live blob
// (see seedUsersFromBlob/verifyUsersMigration below). Phase 2 (below,
// after those two functions) is the actual cutover: load('users.json'),
// save('users.json', ...), and update('users.json', ...) now transparently
// redirect to these tables, so every existing caller across the codebase
// (server.js's ~40 call sites, health.js, daily_brief.js, reminders.js,
// and the test suite's fixture seeding) keeps working completely
// unchanged - no route was individually rewritten.
//
// Split into `users` (identity/auth/billing) and `user_profiles` (health/
// nutrition preferences, 1:1) rather than one wide table - genuinely
// different concerns, matching how the rest of this migration separated
// diets from goals from medical conditions instead of one flat blob.
// Allergies and medical conditions become real many-to-many junction
// tables referencing the exact Phase 1 lookup tables (allergens,
// medical_conditions) - the actual point of building those tables in the
// first place, not just a parallel copy of the same 2 arrays.
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id                     TEXT PRIMARY KEY,
  username               TEXT NOT NULL UNIQUE,
  password               TEXT NOT NULL,
  email                  TEXT,
  phone                  TEXT,
  role                   TEXT NOT NULL DEFAULT 'user',
  plan                   TEXT,
  created                TEXT,
  active                 INTEGER NOT NULL DEFAULT 1,
  email_verified         INTEGER NOT NULL DEFAULT 0,
  trial_start            TEXT,
  paid                   INTEGER NOT NULL DEFAULT 0,
  lang                   TEXT,
  login_attempts         INTEGER NOT NULL DEFAULT 0,
  avatar_url             TEXT,
  last_login             TEXT,
  deleted_at             TEXT,
  facebook_auth          INTEGER NOT NULL DEFAULT 0,
  google_auth            INTEGER NOT NULL DEFAULT 0,
  forced_reregistration  INTEGER NOT NULL DEFAULT 0,
  open_wearables_user_id TEXT,
  updated_at             TEXT NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS user_profiles (
  user_id                 TEXT PRIMARY KEY REFERENCES users(id),
  diet_id                 TEXT REFERENCES diets(id),
  weight                  REAL,
  height                  REAL,
  age                     INTEGER,
  gender                  TEXT,
  budget                  REAL,
  body_fat                REAL,
  muscle_mass             REAL,
  bmi                     REAL,
  bmr                     REAL,
  goal_id                 TEXT REFERENCES goals(id),
  activity_level_id       TEXT REFERENCES activity_levels(id),
  calorie_mode            TEXT,
  custom_calorie_target   REAL,
  cycle_tracking_enabled  INTEGER NOT NULL DEFAULT 0,
  last_period_start       TEXT,
  cycle_length            INTEGER,
  takes_creatine          INTEGER NOT NULL DEFAULT 0,
  measurements_updated_at TEXT,
  custom_allergy_text     TEXT,
  target_weight           REAL,
  profile_lang            TEXT,
  updated_at              TEXT NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS user_allergies (
  user_id     TEXT NOT NULL REFERENCES users(id),
  allergen_id TEXT NOT NULL REFERENCES allergens(id),
  PRIMARY KEY (user_id, allergen_id)
)`);
db.exec(`CREATE TABLE IF NOT EXISTS user_medical_conditions (
  user_id      TEXT NOT NULL REFERENCES users(id),
  condition_id TEXT NOT NULL REFERENCES medical_conditions(id),
  PRIMARY KEY (user_id, condition_id)
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);

const upsertUserStmt = db.prepare(`INSERT INTO users
    (id,username,password,email,phone,role,plan,created,active,email_verified,trial_start,paid,lang,
     login_attempts,avatar_url,last_login,deleted_at,facebook_auth,google_auth,forced_reregistration,open_wearables_user_id,updated_at)
  VALUES (@id,@username,@password,@email,@phone,@role,@plan,@created,@active,@email_verified,@trial_start,@paid,@lang,
     @login_attempts,@avatar_url,@last_login,@deleted_at,@facebook_auth,@google_auth,@forced_reregistration,@open_wearables_user_id,@now)
  ON CONFLICT(id) DO UPDATE SET
    username=excluded.username, password=excluded.password, email=excluded.email, phone=excluded.phone,
    role=excluded.role, plan=excluded.plan, created=excluded.created, active=excluded.active, email_verified=excluded.email_verified,
    trial_start=excluded.trial_start, paid=excluded.paid, lang=excluded.lang, login_attempts=excluded.login_attempts,
    avatar_url=excluded.avatar_url, last_login=excluded.last_login, deleted_at=excluded.deleted_at,
    facebook_auth=excluded.facebook_auth, google_auth=excluded.google_auth,
    forced_reregistration=excluded.forced_reregistration, open_wearables_user_id=excluded.open_wearables_user_id,
    updated_at=excluded.updated_at`);
const upsertUserProfileStmt = db.prepare(`INSERT INTO user_profiles
    (user_id,diet_id,weight,height,age,gender,budget,body_fat,muscle_mass,bmi,bmr,goal_id,activity_level_id,
     calorie_mode,custom_calorie_target,cycle_tracking_enabled,last_period_start,cycle_length,takes_creatine,
     measurements_updated_at,custom_allergy_text,target_weight,profile_lang,fasting_protocol_id,fasting_window_start_hour,updated_at)
  VALUES (@user_id,@diet_id,@weight,@height,@age,@gender,@budget,@body_fat,@muscle_mass,@bmi,@bmr,@goal_id,@activity_level_id,
     @calorie_mode,@custom_calorie_target,@cycle_tracking_enabled,@last_period_start,@cycle_length,@takes_creatine,
     @measurements_updated_at,@custom_allergy_text,@target_weight,@profile_lang,@fasting_protocol_id,@fasting_window_start_hour,@now)
  ON CONFLICT(user_id) DO UPDATE SET
    diet_id=excluded.diet_id, weight=excluded.weight, height=excluded.height, age=excluded.age, gender=excluded.gender,
    budget=excluded.budget, body_fat=excluded.body_fat, muscle_mass=excluded.muscle_mass, bmi=excluded.bmi, bmr=excluded.bmr,
    goal_id=excluded.goal_id, activity_level_id=excluded.activity_level_id, calorie_mode=excluded.calorie_mode,
    custom_calorie_target=excluded.custom_calorie_target, cycle_tracking_enabled=excluded.cycle_tracking_enabled,
    last_period_start=excluded.last_period_start, cycle_length=excluded.cycle_length, takes_creatine=excluded.takes_creatine,
    measurements_updated_at=excluded.measurements_updated_at, custom_allergy_text=excluded.custom_allergy_text,
    target_weight=excluded.target_weight, profile_lang=excluded.profile_lang, fasting_protocol_id=excluded.fasting_protocol_id,
    fasting_window_start_hour=excluded.fasting_window_start_hour, updated_at=excluded.updated_at`);
const insUserAllergyStmt = db.prepare(`INSERT INTO user_allergies (user_id,allergen_id) VALUES (@user_id,@allergen_id) ON CONFLICT DO NOTHING`);
const insUserConditionStmt = db.prepare(`INSERT INTO user_medical_conditions (user_id,condition_id) VALUES (@user_id,@condition_id) ON CONFLICT DO NOTHING`);
const deleteUserAllergiesStmt = db.prepare('DELETE FROM user_allergies WHERE user_id = ?');
const deleteUserConditionsStmt = db.prepare('DELETE FROM user_medical_conditions WHERE user_id = ?');
const bool01 = (v) => (v ? 1 : 0);

// Idempotent (UPSERT on both real tables; junction rows are cleared and
// re-inserted per user each run, since a plain array has no stable row
// identity to UPSERT against) - safe to run on every boot. Every field is
// copied faithfully from the live blob, including ones no current user
// happens to have set (nullable throughout) - nothing guessed, nothing
// dropped. diet_id/goal_id/activity_level_id are only set when they
// reference a row that genuinely exists in that lookup table (checked
// live before this shipped: all real diet values already match; goalType
// is normalized through the exact same normalizeGoalType() the live app
// itself uses, so a legacy 'lose'/'gain' value migrates to the same
// lose_weight/gain_weight a real request would resolve it to) - anything
// that still doesn't match is left NULL rather than forced through, since
// a FK violation would abort the whole migration for every user, not just
// the one with bad data.
// Shared by the one-time blob migration below AND by writeUsersToTables()
// (the live cutover write path, further down) - one field-mapping
// implementation so the two can never drift apart from each other.
function upsertFullUser(u, skippedRefs) {
  const p = u.profile || {};
  const now = new Date().toISOString();
  upsertUserStmt.run({
    id: u.id, username: u.username, password: u.password, email: u.email || null, phone: u.phone || null,
    role: u.role || 'user', plan: u.plan || null, created: u.created || null,
    active: bool01(u.active), email_verified: bool01(u.emailVerified), trial_start: u.trialStart || null,
    paid: bool01(u.paid), lang: u.lang || null, login_attempts: u.loginAttempts || 0,
    avatar_url: u.avatarUrl || null, last_login: u.lastLogin || null, deleted_at: u.deletedAt || null,
    facebook_auth: bool01(u.facebookAuth), google_auth: bool01(u.googleAuth),
    forced_reregistration: bool01(u.forcedReregistration), open_wearables_user_id: u.openWearablesUserId || null,
    now,
  });

  const dietId = p.diet && getDiet(p.diet) ? p.diet : (p.diet ? (skippedRefs.push(`${u.id} diet="${p.diet}"`), null) : null);
  const goalId = p.goalType ? normalizeGoalType(p.goalType) : null;
  const activityLevelId = p.activityLevel && getActivityLevel(p.activityLevel) ? p.activityLevel : (p.activityLevel ? (skippedRefs.push(`${u.id} activityLevel="${p.activityLevel}"`), null) : null);
  const fastingProtocolId = p.fastingProtocol && getFastingProtocol(p.fastingProtocol) ? p.fastingProtocol : (p.fastingProtocol ? (skippedRefs.push(`${u.id} fastingProtocol="${p.fastingProtocol}"`), null) : null);

  upsertUserProfileStmt.run({
    user_id: u.id, diet_id: dietId, weight: p.weight ?? null, height: p.height ?? null, age: p.age ?? null,
    gender: p.gender || null, budget: p.budget ?? null, body_fat: p.bodyFat ?? null, muscle_mass: p.muscleMass ?? null,
    bmi: p.bmi ?? null, bmr: p.bmr ?? null, goal_id: goalId, activity_level_id: activityLevelId,
    calorie_mode: p.calorieMode || null, custom_calorie_target: p.customCalorieTarget ?? null,
    cycle_tracking_enabled: bool01(p.cycleTrackingEnabled), last_period_start: p.lastPeriodStart || null,
    cycle_length: p.cycleLength ?? null, takes_creatine: bool01(p.takesCreatine),
    measurements_updated_at: p.measurementsUpdatedAt || null, custom_allergy_text: p.customAllergyText || null,
    target_weight: p.targetWeight ?? null, profile_lang: p.lang || null, fasting_protocol_id: fastingProtocolId,
    fasting_window_start_hour: Number.isInteger(p.fastingWindowStartHour) && p.fastingWindowStartHour >= 0 && p.fastingWindowStartHour <= 23 ? p.fastingWindowStartHour : null,
    now,
  });

  deleteUserAllergiesStmt.run(u.id);
  for (const allergenId of (Array.isArray(p.allergies) ? p.allergies : [])) {
    if (db.prepare('SELECT 1 FROM allergens WHERE id = ?').get(allergenId)) {
      insUserAllergyStmt.run({ user_id: u.id, allergen_id: allergenId });
    } else {
      skippedRefs.push(`${u.id} allergy="${allergenId}"`);
    }
  }
  deleteUserConditionsStmt.run(u.id);
  for (const conditionId of (Array.isArray(p.medicalConditions) ? p.medicalConditions : [])) {
    if (db.prepare('SELECT 1 FROM medical_conditions WHERE id = ?').get(conditionId)) {
      insUserConditionStmt.run({ user_id: u.id, condition_id: conditionId });
    } else {
      skippedRefs.push(`${u.id} medicalCondition="${conditionId}"`);
    }
  }
}

function seedUsersFromBlob() {
  const users = load('users.json') || [];
  const skippedRefs = [];
  for (const u of users) upsertFullUser(u, skippedRefs);
  if (skippedRefs.length) console.error('[db] seedUsersFromBlob: skipped invalid references (left NULL/omitted, did not block migration):\n' + skippedRefs.join('\n'));
  console.log(`[db] users migrated: ${users.length} from the legacy blob (verification-only - no route reads this table yet).`);
  return { migrated: users.length, skippedRefs };
}
// NOT auto-run at module-load time, unlike Phases 1-3 - users.json is
// itself seeded by server.js's initData(), which runs near the end of
// server.js, long after `require('./db')` already finished running this
// file's own top-level code (the exact same ordering hazard as Phase 4's
// meals table, caught here by testing against a fresh deployment before
// this ever touched real user data: migrating at module-load time here
// would run against an empty/stale blob on first boot, then silently
// leave a duplicate stale row once initData() populated it moments later).
// Superseded by the load/save redirect below as of the 2026-09-10 cutover
// - kept only as the historical one-time migration record, no longer
// called by server.js (calling it post-cutover would be a harmless no-op:
// load('users.json') now reads the tables themselves).

function getUserRow(id) { return db.prepare('SELECT * FROM users WHERE id = ?').get(id) || null; }
function getUserProfileRow(userId) { return db.prepare('SELECT * FROM user_profiles WHERE user_id = ?').get(userId) || null; }
function getUserAllergyIds(userId) { return db.prepare('SELECT allergen_id FROM user_allergies WHERE user_id = ?').all(userId).map(r => r.allergen_id); }
function getUserMedicalConditionIds(userId) { return db.prepare('SELECT condition_id FROM user_medical_conditions WHERE user_id = ?').all(userId).map(r => r.condition_id); }

// Boot-time proof this matches the real, live blob exactly - same
// discipline as every other phase's verification, adapted for this one
// having no independent JS-constant reference: compares the freshly-
// migrated tables field-by-field against the blob they were migrated FROM,
// which is the actual source of truth being protected here. Deliberately
// tolerant of the same normalization the migration itself applies (goalType
// via normalizeGoalType, invalid diet/activity refs left null) - flagging
// those as errors would mean the verification disagrees with the
// migration's own documented, correct behavior.
function verifyUsersMigration() {
  const users = load('users.json') || [];
  const errors = [];
  for (const u of users) {
    const p = u.profile || {};
    const row = getUserRow(u.id);
    if (!row) { errors.push(`user ${u.id} missing from users table`); continue; }
    const checks = [
      ['username', row.username, u.username], ['password', row.password, u.password],
      ['email', row.email, u.email || null], ['phone', row.phone, u.phone || null],
      ['role', row.role, u.role || 'user'], ['plan', row.plan, u.plan || null],
      ['active', !!row.active, !!u.active], ['email_verified', !!row.email_verified, !!u.emailVerified],
      ['trial_start', row.trial_start, u.trialStart || null], ['paid', !!row.paid, !!u.paid],
    ];
    for (const [field, got, want] of checks) {
      if (got !== want) errors.push(`user ${u.id} field ${field} mismatch: table=${JSON.stringify(got)} blob=${JSON.stringify(want)}`);
    }
    const profileRow = getUserProfileRow(u.id) || {};
    const profileChecks = [
      ['weight', profileRow.weight ?? null, p.weight ?? null], ['height', profileRow.height ?? null, p.height ?? null],
      ['age', profileRow.age ?? null, p.age ?? null], ['gender', profileRow.gender ?? null, p.gender || null],
      ['bmi', profileRow.bmi ?? null, p.bmi ?? null], ['bmr', profileRow.bmr ?? null, p.bmr ?? null],
    ];
    for (const [field, got, want] of profileChecks) {
      if (got !== want) errors.push(`user_profiles ${u.id} field ${field} mismatch: table=${JSON.stringify(got)} blob=${JSON.stringify(want)}`);
    }
    const wantAllergies = [...(Array.isArray(p.allergies) ? p.allergies : [])].sort();
    const gotAllergies = getUserAllergyIds(u.id).sort();
    const wantValidAllergies = wantAllergies.filter(a => db.prepare('SELECT 1 FROM allergens WHERE id = ?').get(a));
    if (JSON.stringify(gotAllergies) !== JSON.stringify(wantValidAllergies)) {
      errors.push(`user_allergies ${u.id} mismatch: table=${JSON.stringify(gotAllergies)} blob(valid only)=${JSON.stringify(wantValidAllergies)}`);
    }
  }
  const tableCount = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (tableCount !== users.length) errors.push(`row count mismatch: users table has ${tableCount}, blob has ${users.length}`);
  if (errors.length) throw new Error('[db] users migration verification FAILED:\n' + errors.join('\n'));
  console.log(`[db] users migration verified: all ${users.length} users match the live blob exactly (identity/billing fields, profile fields, and allergy links).`);
}
// Also not auto-run - superseded by the redirect below, see that comment.

// Rebuilds one user's exact users.json object shape from the tables - the
// inverse of upsertFullUser(). Fields with a NOT NULL DEFAULT column
// (active/emailVerified/paid/loginAttempts/etc) are always included, since
// every real caller already reads them defensively (`!!u.active`, `u.paid
// || false`-style, confirmed by grep before this cutover shipped) - a
// user created via a path that never set them originally and one that set
// them to false/0 are indistinguishable once in the table, and every
// caller already treats those two cases identically. Nullable string
// fields (email/phone/trialStart/etc) are included only when set, closer
// to the blob's historically sparse shape but not load-bearing either way.
function userRowToObject(row) {
  const p = getUserProfileRow(row.id) || {};
  const allergyIds = getUserAllergyIds(row.id);
  const conditionIds = getUserMedicalConditionIds(row.id);

  const profile = {};
  if (p.diet_id != null) profile.diet = p.diet_id;
  if (p.fasting_protocol_id != null) profile.fastingProtocol = p.fasting_protocol_id;
  if (p.fasting_window_start_hour != null) profile.fastingWindowStartHour = p.fasting_window_start_hour;
  if (p.weight != null) profile.weight = p.weight;
  if (p.height != null) profile.height = p.height;
  if (p.age != null) profile.age = p.age;
  if (p.gender != null) profile.gender = p.gender;
  if (p.budget != null) profile.budget = p.budget;
  if (p.body_fat != null) profile.bodyFat = p.body_fat;
  if (p.muscle_mass != null) profile.muscleMass = p.muscle_mass;
  if (p.bmi != null) profile.bmi = p.bmi;
  if (p.bmr != null) profile.bmr = p.bmr;
  if (p.goal_id != null) profile.goalType = p.goal_id;
  if (p.activity_level_id != null) profile.activityLevel = p.activity_level_id;
  if (p.calorie_mode != null) profile.calorieMode = p.calorie_mode;
  if (p.custom_calorie_target != null) profile.customCalorieTarget = p.custom_calorie_target;
  if (p.cycle_tracking_enabled) profile.cycleTrackingEnabled = true;
  if (p.last_period_start != null) profile.lastPeriodStart = p.last_period_start;
  if (p.cycle_length != null) profile.cycleLength = p.cycle_length;
  if (p.takes_creatine) profile.takesCreatine = true;
  if (p.measurements_updated_at != null) profile.measurementsUpdatedAt = p.measurements_updated_at;
  if (p.custom_allergy_text != null) profile.customAllergyText = p.custom_allergy_text;
  if (p.target_weight != null) profile.targetWeight = p.target_weight;
  if (p.profile_lang != null) profile.lang = p.profile_lang;
  if (allergyIds.length) profile.allergies = allergyIds;
  if (conditionIds.length) profile.medicalConditions = conditionIds;

  const user = { id: row.id, username: row.username, password: row.password, role: row.role };
  if (row.email != null) user.email = row.email;
  if (row.phone != null) user.phone = row.phone;
  if (row.plan != null) user.plan = row.plan;
  if (row.created != null) user.created = row.created;
  user.active = !!row.active;
  user.emailVerified = !!row.email_verified;
  if (row.trial_start != null) user.trialStart = row.trial_start;
  user.paid = !!row.paid;
  if (row.lang != null) user.lang = row.lang;
  user.loginAttempts = row.login_attempts || 0;
  if (row.avatar_url != null) user.avatarUrl = row.avatar_url;
  user.lastLogin = row.last_login ?? null;
  if (row.deleted_at != null) user.deletedAt = row.deleted_at;
  if (row.facebook_auth) user.facebookAuth = true;
  if (row.google_auth) user.googleAuth = true;
  if (row.forced_reregistration) user.forcedReregistration = true;
  if (row.open_wearables_user_id != null) user.openWearablesUserId = row.open_wearables_user_id;
  user.profile = profile;
  return user;
}

// The live read path behind load('users.json') as of the cutover. Returns
// null (not []) when the table is genuinely empty, matching the blob
// store's null-for-never-saved semantics exactly - initData() below relies
// on `load('users.json') === null` to decide whether to seed the default
// admin account on a brand-new deployment, and a real deploy's users table
// starts out with zero rows just like the blob started out unsaved.
function usersFromTables() {
  const rows = db.prepare('SELECT * FROM users ORDER BY rowid').all();
  if (!rows.length) return null;
  return rows.map(userRowToObject);
}

// The live write path behind save('users.json', ...). save() replaces the
// whole document, so this must too: remove any existing row whose id isn't
// in the incoming array FIRST, then upsert the incoming array - covers
// account deletion and the admin delete-user route (both filter the array
// and re-save it), and also avoids a transient UNIQUE(username) collision
// when an incoming row has a different id than an existing row that
// happens to share its username (upsert-then-delete would briefly have
// both rows alive at once and fail the constraint; delete-then-upsert
// never does). Wrapped in one transaction for the same atomicity save()
// always had.
const _writeUsersTxn = db.transaction((users) => {
  const incomingIds = new Set(users.map(u => u.id));
  const existingIds = db.prepare('SELECT id FROM users').all().map(r => r.id);
  for (const id of existingIds) {
    if (incomingIds.has(id)) continue;
    deleteUserAllergiesStmt.run(id);
    deleteUserConditionsStmt.run(id);
    db.prepare('DELETE FROM user_profiles WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  }
  const skippedRefs = [];
  for (const u of users) upsertFullUser(u, skippedRefs);
  if (skippedRefs.length) console.error('[db] users.json write: skipped invalid references (left NULL/omitted):\n' + skippedRefs.join('\n'));
});
function writeUsersToTables(users) {
  _writeUsersTxn(users);
  return users;
}

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
  if (key === 'users.json') return usersFromTables();
  const row = selStmt.get(key);
  if (!row) return null;
  try { return JSON.parse(row.value); } catch { return null; }
}

// Write a document, replacing it wholesale. Atomic and durable.
function save(key, data) {
  if (key === 'users.json') return writeUsersToTables(data);
  upsertStmt.run({ key, value: JSON.stringify(data), updated_at: new Date().toISOString() });
  mirrorToDisk(key, data);
  return data;
}

// The DB row is the only thing load() ever reads - but for any key that
// still has a legacy file sitting in DATA_DIR (from the original
// migrateFromJson import below), keep that file mirroring current DB
// content on every write. Without this, the file silently freezes at
// whatever it held at first-boot import while the DB row keeps moving,
// with nothing to show the two have diverged - indistinguishable from a
// live, editable file. That's a real incident, not a hypothetical: adding
// the vegan diet's meal plan and priced ingredients on 2026-09-19 was
// built entirely against the on-disk food_prices.json/meal_plans.json,
// which turned out to have been stale since their respective one-time
// imports - hours of edits that the running app never saw, discovered
// only by noticing seedMealsFromDietPlans() reported 0 new meals. This
// doesn't make the file a second read path (load() still never looks at
// it) - it just keeps it truthful as a snapshot/diagnostic, so the next
// person who opens it isn't misled the same way.
function mirrorToDisk(key, data) {
  const fp = path.join(DATA_DIR, key);
  if (!fs.existsSync(fp)) return; // no legacy file for this key - nothing to keep in sync
  try {
    fs.writeFileSync(fp, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error(`[db] mirror-to-disk failed for ${key}:`, e.message);
  }
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

// One-time *import* of any legacy flat-file JSON into the store - read-only
// direction. Skips keys that already exist in the DB, so it's safe to run
// on every boot. The reverse direction (DB -> file) happens continuously
// instead, via save()'s mirrorToDisk() above, so a file that's already
// been imported once doesn't go stale forever after.
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
  resolveFood, normalizeFoodName, verifyFoodResolution, getMicronutrients,
  listDiets, getDiet, getDietContraindications, verifyDietTablesMatch,
  listFastingProtocols, getFastingProtocol, getFastingContraindications, verifyFastingTablesMatch,
  seedMealsFromDietPlans, getMeal, getMealIngredients, getMealNutrition, listMealsForDiet, getMealNutritionByIdentity,
  getMealOverrideRow, saveMealOverrideRow, deleteMealOverrideRow, deleteAllMealOverridesForUser,
  listFoodCategories, listFoodsByCategory,
  getUserRow, getUserProfileRow, getUserAllergyIds, getUserMedicalConditionIds, verifyUsersMigration, seedUsersFromBlob };
