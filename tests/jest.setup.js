// Runs before any test file's imports. Isolates every test run from real
// production data — both DATA_DIR (so initData()'s legacy-JSON migration
// never reads the real, stale flat files still on disk at /data/diethub,
// confirmed during this hardening pass to contain real user records) and
// DB_PATH (so nothing is ever written to the real diethub.db). A fresh,
// empty scratch directory per test run, never the same path twice.
const path = require('path');
const fs = require('fs');
const os = require('os');

const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-test-'));
process.env.DATA_DIR = scratchDir;
process.env.DB_PATH = path.join(scratchDir, 'test.db');
process.env.JWT_SECRET = 'test_only_jwt_secret_never_used_in_production';
process.env.KASHIER_MERCHANT_ID = 'TEST_MERCHANT';
process.env.KASHIER_SECRET_KEY = 'test_kashier_secret_for_signature_tests_only';
process.env.BETA_MODE = 'false'; // exercise real trial/paywall logic in tests, not the production beta bypass
// Deliberately NOT setting any AI provider key (GEMINI/GROQ/OPENROUTER/
// ANTHROPIC_API_KEY) or Apple/Google IAP credentials — tests must never make
// a real call to a paid external API. Anything that would require one is
// either not covered by this test pass (disclosed in TESTING-REPORT.md) or
// tested only up to the boundary of the outbound call.

global.__HP_TEST_SCRATCH_DIR__ = scratchDir;

// `setupFiles` (this file) runs before Jest's test-framework globals
// (afterAll/describe/test) are installed, so `afterAll` isn't callable
// here — process.on('exit') works regardless of that timing and needs no
// framework dependency.
process.on('exit', () => {
  try { fs.rmSync(scratchDir, { recursive: true, force: true }); } catch {}
});
