// Integration tests — real HTTP requests via supertest against the real
// exported Express app, backed by a fully isolated scratch database
// (tests/jest.setup.js). Because this environment is isolated, we can do
// something that wasn't possible against the real production system during
// the earlier hardening passes: seed a real admin account directly and
// exercise the impersonation route end-to-end over real HTTP, closing the
// "remaining risk" explicitly disclosed for HP-006 (Phase 2).
const request = require('supertest');
const app = require('../../server.js');
const store = require('../../db.js');

function realUser(overrides = {}) {
  const { hashPwd } = app._testables;
  // created/trialStart default to "today" (matching how real registration
  // always sets trialStart, server.js line ~1784) rather than a fixed past
  // date - a hardcoded date silently starts failing once the real clock
  // outlives TRIAL_DAYS (14) past it, which is exactly what happened here
  // (found live during the nutrition-architecture migration, unrelated to
  // that work but real test-suite staleness worth fixing while found).
  const today = new Date().toISOString().split('T')[0];
  return {
    id: 'u_test_' + Math.random().toString(36).slice(2),
    username: 'testuser_' + Math.random().toString(36).slice(2, 8),
    password: hashPwd('TestPass2026!'),
    email: 'test@example.com',
    role: 'user',
    plan: 'trial',
    created: today,
    active: true,
    emailVerified: true,
    trialStart: today,
    paid: false,
    lang: 'ar',
    loginAttempts: 0,
    profile: {},
    ...overrides,
  };
}

function seedUsers(users) {
  store.save('users.json', users);
}

describe('Authentication — real HTTP', () => {
  test('login with correct credentials succeeds and sets an HttpOnly, SameSite=Strict cookie', async () => {
    const user = realUser({ username: 'loginok' });
    seedUsers([user]);
    const res = await request(app).post('/diet/auth').send({ username: 'loginok', password: 'TestPass2026!' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    const setCookie = res.headers['set-cookie']?.join(';') || '';
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Strict');
  });

  test('login with wrong password is rejected with 401 and no user-enumeration difference', async () => {
    const user = realUser({ username: 'loginfail' });
    seedUsers([user]);
    const res = await request(app).post('/diet/auth').send({ username: 'loginfail', password: 'WrongPassword!' });
    expect(res.status).toBe(401);
  });

  test('a route requiring auth rejects a request with no token', async () => {
    const res = await request(app).get('/diet/api/me').set('Accept', 'application/json');
    expect(res.status).toBe(401);
  });

  test('a route requiring auth rejects a garbage/tampered token', async () => {
    const res = await request(app).get('/diet/api/me').set('Authorization', 'Bearer not-a-real-token').set('Accept', 'application/json');
    expect(res.status).toBe(401);
  });
});

describe('Admin authorization — real HTTP', () => {
  test('a non-admin user is rejected from an admin route (403)', async () => {
    const user = realUser({ username: 'regularuser' });
    seedUsers([user]);
    const loginRes = await request(app).post('/diet/auth').send({ username: 'regularuser', password: 'TestPass2026!' });
    const token = loginRes.body.token;
    const res = await request(app).get('/diet/api/admin/users').set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(res.status).toBe(403);
  });

  test('an admin user can reach an admin route', async () => {
    const admin = realUser({ username: 'realadmin', role: 'admin' });
    seedUsers([admin]);
    const loginRes = await request(app).post('/diet/auth').send({ username: 'realadmin', password: 'TestPass2026!' });
    const token = loginRes.body.token;
    const res = await request(app).get('/diet/api/admin/users').set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(res.status).toBe(200);
  });
});

describe('Admin impersonation — HP-006 real end-to-end regression (previously untestable against production)', () => {
  test('an admin CANNOT impersonate another admin account (real HTTP, real 403)', async () => {
    const admin1 = realUser({ id: 'admin1', username: 'admin1acct', role: 'admin' });
    const admin2 = realUser({ id: 'admin2', username: 'admin2acct', role: 'admin' });
    seedUsers([admin1, admin2]);
    const loginRes = await request(app).post('/diet/auth').send({ username: 'admin1acct', password: 'TestPass2026!' });
    const token = loginRes.body.token;
    const res = await request(app).post(`/diet/api/admin/impersonate/${admin2.id}`).set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(res.status).toBe(403);
  });

  test('an admin CAN impersonate a regular user, and the resulting token carries the imp marker + shorter expiry', async () => {
    const admin = realUser({ id: 'adminX', username: 'adminXacct', role: 'admin' });
    const target = realUser({ id: 'targetuser', username: 'targetacct', role: 'user' });
    seedUsers([admin, target]);
    const loginRes = await request(app).post('/diet/auth').send({ username: 'adminXacct', password: 'TestPass2026!' });
    const adminToken = loginRes.body.token;
    const res = await request(app).post(`/diet/api/admin/impersonate/${target.id}`).set('Authorization', `Bearer ${adminToken}`).set('Accept', 'application/json');
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    const { checkToken } = app._testables;
    const decoded = checkToken(res.body.token);
    expect(decoded.imp).toBe('adminX');
    const hoursRemaining = (decoded.exp - Date.now()) / 3600000;
    expect(hoursRemaining).toBeLessThanOrEqual(1);
  });

  test('impersonating a non-existent user returns 404, not a crash', async () => {
    const admin = realUser({ id: 'adminY', username: 'adminYacct', role: 'admin' });
    seedUsers([admin]);
    const loginRes = await request(app).post('/diet/auth').send({ username: 'adminYacct', password: 'TestPass2026!' });
    const token = loginRes.body.token;
    const res = await request(app).post('/diet/api/admin/impersonate/does-not-exist').set('Authorization', `Bearer ${token}`).set('Accept', 'application/json');
    expect(res.status).toBe(404);
  });
});
