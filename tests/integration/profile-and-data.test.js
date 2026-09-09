// Integration tests — profile input validation (Phase 3 regression, real
// HTTP) and per-user data ownership (health/nutrition data must never be
// readable/writable across accounts).
const request = require('supertest');
const app = require('../../server.js');
const store = require('../../db.js');

function realUser(overrides = {}) {
  const { hashPwd } = app._testables;
  // created/trialStart default to "today" - a hardcoded past date silently
  // starts failing once the real clock outlives TRIAL_DAYS (14) past it
  // (found live during the nutrition-architecture migration, unrelated to
  // that work but real test-suite staleness worth fixing while found).
  const today = new Date().toISOString().split('T')[0];
  return {
    id: 'u_' + Math.random().toString(36).slice(2),
    username: 'u' + Math.random().toString(36).slice(2, 8),
    password: hashPwd('TestPass2026!'),
    email: 'test@example.com', role: 'user', plan: 'trial',
    created: today, active: true, emailVerified: true,
    trialStart: today, paid: false, lang: 'ar', loginAttempts: 0, profile: {},
    ...overrides,
  };
}

async function loginAs(username) {
  const res = await request(app).post('/diet/auth').send({ username, password: 'TestPass2026!' });
  return res.body.token;
}

describe('POST /api/profile — Phase 3 input validation regression (real HTTP)', () => {
  let token;
  beforeEach(async () => {
    const user = realUser({ username: 'profileuser' });
    store.save('users.json', [user]);
    token = await loginAs('profileuser');
  });

  test('a legitimate profile update succeeds', async () => {
    const res = await request(app).post('/diet/api/profile').set('Authorization', `Bearer ${token}`)
      .send({ weight: 78.5, height: 178, age: 31, budget: 350, diet: 'keto', gender: 'male' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.bmi).toBeGreaterThan(0);
  });

  test('an absurd weight value is rejected with 400', async () => {
    const res = await request(app).post('/diet/api/profile').set('Authorization', `Bearer ${token}`).send({ weight: 99999 });
    expect(res.status).toBe(400);
  });

  test('an XSS payload as a diet value is rejected with 400', async () => {
    const res = await request(app).post('/diet/api/profile').set('Authorization', `Bearer ${token}`).send({ diet: '<script>alert(1)</script>' });
    expect(res.status).toBe(400);
  });

  test('an invalid gender value is rejected with 400', async () => {
    const res = await request(app).post('/diet/api/profile').set('Authorization', `Bearer ${token}`).send({ gender: 'not-a-real-value' });
    expect(res.status).toBe(400);
  });
});

describe('POST /api/watch/sync — Phase 3 bounds regression (real HTTP)', () => {
  test('an absurd steps value is safely nulled, not rejected, matching the existing || null convention', async () => {
    const user = realUser({ username: 'watchuser' });
    store.save('users.json', [user]);
    const token = await loginAs('watchuser');
    const res = await request(app).post('/diet/api/watch/sync').set('Authorization', `Bearer ${token}`)
      .send({ source: 'manual', date: '2026-08-14', steps: 99999999, heartRate: 72 });
    expect(res.status).toBe(200);
    expect(res.body.entry.steps).toBeNull();
    expect(res.body.entry.heartRate).toBe(72);
  });
});

describe('Per-user data ownership — horizontal escalation regression', () => {
  test('user A cannot delete user B\'s nutrition log entry by guessing the date', async () => {
    const userA = realUser({ id: 'userA', username: 'usera' });
    const userB = realUser({ id: 'userB', username: 'userb' });
    store.save('users.json', [userA, userB]);
    // Seed a real nutrition log entry for userB only.
    store.save('nutrition_logs.json', { userB: [{ date: '2026-08-14', meals: [], custom: [{ name: 'Secret meal' }] }] });
    const tokenA = await loginAs('usera');
    const res = await request(app).delete('/diet/api/nutrition-log/2026-08-14/custom/0').set('Authorization', `Bearer ${tokenA}`).set('Accept', 'application/json');
    // userA has no log entry for this date in THEIR OWN bucket — correctly 404, not a cross-user delete.
    expect(res.status).toBe(404);
    const logsAfter = store.load('nutrition_logs.json');
    expect(logsAfter.userB[0].custom.length).toBe(1); // userB's real data untouched
  });

  test('GET /api/nutrition-log only ever returns the caller\'s own data', async () => {
    const userA = realUser({ id: 'userA2', username: 'usera2' });
    const userB = realUser({ id: 'userB2', username: 'userb2' });
    store.save('users.json', [userA, userB]);
    store.save('nutrition_logs.json', {
      userA2: [{ date: '2026-08-14', meals: [], custom: [{ name: 'A\'s food' }] }],
      userB2: [{ date: '2026-08-14', meals: [], custom: [{ name: 'B\'s food' }] }],
    });
    const tokenA = await loginAs('usera2');
    const res = await request(app).get('/diet/api/nutrition-log').set('Authorization', `Bearer ${tokenA}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].custom[0].name).toBe("A's food");
  });
});
