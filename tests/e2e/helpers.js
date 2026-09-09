// Real E2E test helpers — registers/verifies/cleans up REAL, disposable
// throwaway accounts against the app-under-test, reading its DB file
// directly to pull the email-verification token. The app-under-test and
// this test process always share the same DATA_DIR/DB_PATH (CI starts both
// bare on the same runner filesystem — see .github/workflows/ci.yml), so a
// plain local `node -e` against ./db.js is enough; no Docker involved. Every
// account created here MUST be cleaned up, and only ever via its own real
// API paths or direct removal of the exact record created, never a broad
// delete.
const { execSync } = require('child_process');
const path = require('path');

function runNode(script) {
  return execSync(`node -e "${script.replace(/"/g, '\\"')}"`, {
    encoding: 'utf8',
    cwd: path.join(__dirname, '..', '..'),
    env: process.env,
  }).trim();
}

async function registerAndVerify(request, baseURL, { username, password, email }) {
  await request.post(`${baseURL}/diet/register`, {
    data: { username, password, email, phone: '01012345678', diet: 'balanced', weight: 75, height: 175, age: 30, gender: 'male', budget: 300 },
  });
  const token = runNode(`
    const store = require('./db.js');
    const pv = store.load('pending_verifications.json') || [];
    const rec = pv.find(p => p.email && p.email.includes('${email.split('@')[0]}'));
    console.log(rec ? rec.token : '');
  `);
  if (!token) throw new Error('E2E helper: verification token not found — registration may have failed');
  await request.get(`${baseURL}/diet/verify-email?token=${token}`);
}

function cleanupUser(username) {
  runNode(`
    const store = require('./db.js');
    const users = store.load('users.json') || [];
    const u = users.find(x => x.username === '${username}');
    if (u) {
      store.save('users.json', users.filter(x => x.id !== u.id));
      store.save('pending_verifications.json', (store.load('pending_verifications.json')||[]).filter(p => p.userId !== u.id));
      const rt = store.load('refresh_tokens.json')||{};
      for (const [t,v] of Object.entries(rt)) if (v.userId===u.id) delete rt[t];
      store.save('refresh_tokens.json', rt);
      const nl = store.load('nutrition_logs.json')||{}; delete nl[u.id]; store.save('nutrition_logs.json', nl);
    }
  `);
}

module.exports = { registerAndVerify, cleanupUser, runNode };
