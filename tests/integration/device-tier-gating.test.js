// Integration tests — real HTTP via supertest, isolated scratch DB (see
// tests/jest.setup.js). Covers the 2026-09-02 3-tier restructure's real
// behavior, refined the same day after clarifying the intended device
// model: manual entry is never gated (not a device integration); tier2
// only unlocks the phone-health-app middleware path (Apple Health/Health
// Connect); tier3 adds direct-to-vendor-cloud OAuth (Garmin/Fitbit/etc via
// Open Wearables) AND the Bluetooth medical devices. Also covers the
// paired decision that chatbot/lab-results moved from "VIP/Elite only" to
// "any paid tier" — trial users must still be excluded from those, not
// waved through.
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
    id: 'u_test_' + Math.random().toString(36).slice(2),
    username: 'testuser_' + Math.random().toString(36).slice(2, 8),
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

// A real, active, non-expired subscription row — required for
// hasActiveCoverage()/hasDeviceTier() to return true regardless of the
// `paid` flag on the user record itself (those are two independently
// checked things in the real code).
function activeSub(userId, plan) {
  return { userId, plan, startDate: '2026-08-01', endDate: '2027-01-01', amount: 100, status: 'active', paymentRef: 'TEST_' + Date.now() };
}

function seedTierUser(tier) {
  const user = realUser({ username: `tieruser_${tier}_${Math.random().toString(36).slice(2, 6)}`, plan: tier, paid: true });
  store.save('users.json', [user]);
  store.save('subscriptions.json', [activeSub(user.id, tier)]);
  return user;
}

function syncAs(token, body) {
  return request(app).post('/diet/api/watch/sync').set('Authorization', `Bearer ${token}`).send({ date: '2026-09-02', ...body });
}

describe('GET /api/watch/providers — read-only metadata, never gated', () => {
  test('a tier1 user can still read the provider/manual/on-device listing', async () => {
    const user = seedTierUser('tier1');
    const token = await loginAs(user.username);
    const res = await request(app).get('/diet/api/watch/providers').set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(res.status).toBe(200);
  });
});

describe('Manual entry — never a gated "device integration" (real HTTP)', () => {
  test('tier1 can still log a manual watch-data entry by hand', async () => {
    const user = seedTierUser('tier1');
    const token = await loginAs(user.username);
    const res = await syncAs(token, { source: 'manual', steps: 5000 });
    expect(res.status).toBe(200);
  });

  test('tier1 can also log a device-labeled-but-manual entry (e.g. "apple_watch")', async () => {
    const user = seedTierUser('tier1');
    const token = await loginAs(user.username);
    const res = await syncAs(token, { source: 'apple_watch', steps: 5000 });
    expect(res.status).toBe(200);
  });
});

describe('Tier2 — phone-health-app middleware only (Apple Health / Health Connect)', () => {
  test('tier2 can sync via Apple Health / Health Connect', async () => {
    const user = seedTierUser('tier2');
    const token = await loginAs(user.username);
    const res = await syncAs(token, { source: 'apple_health', steps: 1000 });
    expect(res.status).toBe(200);
  });

  test('tier2 is blocked from a direct-to-vendor-cloud OAuth source (Garmin)', async () => {
    const user = seedTierUser('tier2');
    const token = await loginAs(user.username);
    const res = await syncAs(token, { source: 'garmin', steps: 1000 });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Complete plan/);
  });

  test('tier2 is blocked from medical-device sources', async () => {
    const user = seedTierUser('tier2');
    const token = await loginAs(user.username);
    const res = await syncAs(token, { source: 'medical_device:blood_pressure_monitor', bloodPressureSystolic: 120, bloodPressureDiastolic: 80 });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Complete plan/);
  });

  test('tier2 is blocked from initiating direct OAuth connect and reading connection status', async () => {
    const user = seedTierUser('tier2');
    const token = await loginAs(user.username);
    const connect = await request(app).get('/diet/api/watch/connect/garmin').set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(connect.status).toBe(403);
    const connections = await request(app).get('/diet/api/watch/connections').set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(connections.status).toBe(403);
  });
});

describe('Tier1 — no device integration of any kind', () => {
  test('tier1 is blocked from the middleware path', async () => {
    const user = seedTierUser('tier1');
    const token = await loginAs(user.username);
    const res = await syncAs(token, { source: 'apple_health', steps: 1000 });
    expect(res.status).toBe(403);
  });

  test('tier1 is blocked from direct OAuth and medical devices too', async () => {
    const user = seedTierUser('tier1');
    const token = await loginAs(user.username);
    expect((await syncAs(token, { source: 'garmin', steps: 1000 })).status).toBe(403);
    expect((await syncAs(token, { source: 'medical_device:blood_pressure_monitor', bloodPressureSystolic: 120, bloodPressureDiastolic: 80 })).status).toBe(403);
  });
});

describe('Tier3 — middleware + direct OAuth + medical devices, all unlocked', () => {
  test('tier3 can sync via middleware, direct OAuth, and medical devices', async () => {
    const user = seedTierUser('tier3');
    const token = await loginAs(user.username);

    expect((await syncAs(token, { source: 'apple_health', steps: 1000 })).status).toBe(200);
    expect((await syncAs(token, { source: 'garmin', steps: 1000 })).status).toBe(200);

    const medicalSync = await syncAs(token, { source: 'medical_device:blood_pressure_monitor', bloodPressureSystolic: 120, bloodPressureDiastolic: 80 });
    expect(medicalSync.status).toBe(200);
    expect(medicalSync.body.entry.bloodPressureSystolic).toBe(120);
  });
});

describe('Chatbot + lab-results — all 3 paid tiers, trial still excluded (real HTTP)', () => {
  test.each(['tier1', 'tier2', 'tier3'])('%s can reach the chatbot and lab-results routes', async (tier) => {
    const user = seedTierUser(tier);
    const token = await loginAs(user.username);

    const chatbot = await request(app).post('/diet/api/chatbot').set('Authorization', `Bearer ${token}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(chatbot.status).not.toBe(403);

    const labs = await request(app).get('/diet/api/lab-results').set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(labs.status).toBe(200);
  });

  test('a trial user (no active paid coverage) is still excluded from lab-results', async () => {
    // Explicitly mid-trial (a few days in, not brand new) rather than a
    // fixed date - see realUser()'s own comment on why a hardcoded date
    // here would silently start failing once TRIAL_DAYS (14) elapses.
    const midTrialStart = new Date(Date.now() - 3 * 86400000).toISOString().split('T')[0];
    const user = realUser({ username: 'trialuser_' + Math.random().toString(36).slice(2, 6), trialStart: midTrialStart });
    store.save('users.json', [user]);
    store.save('subscriptions.json', []);
    const token = await loginAs(user.username);

    const labs = await request(app).get('/diet/api/lab-results').set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(labs.status).toBe(403);
  });
});
