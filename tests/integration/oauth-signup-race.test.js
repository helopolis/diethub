// Integration test — real HTTP via supertest, isolated scratch DB (see
// tests/jest.setup.js). Regression test for a real bug fixed 2026-09-02:
// /api/auth/google and /api/auth/facebook used to `load('users.json')`,
// check for an existing row by email, and `push()`+`save()` a new one —
// all AFTER an `await` (verifying the token with Google/Facebook), so two
// simultaneous sign-ins for the same brand-new email could both pass the
// "does this user exist" check and each create their own row. The fix
// moves the find-or-create into db.js's update(), which runs inside a real
// SQLite transaction, so concurrent calls serialize instead of racing.
//
// GOOGLE_CLIENT_ID must be set BEFORE server.js is required (it decides at
// module-load time whether `googleClient` is constructed at all), and
// google-auth-library is mocked so this never makes a real network call —
// consistent with jest.setup.js's "no real external API calls in tests"
// policy.
process.env.GOOGLE_CLIENT_ID = 'test_google_client_id';

jest.mock('google-auth-library', () => ({
  OAuth2Client: jest.fn().mockImplementation(() => ({
    verifyIdToken: jest.fn().mockResolvedValue({
      getPayload: () => ({ email: 'racer@example.com', email_verified: true, name: 'Race Condition Tester' }),
    }),
  })),
  GoogleAuth: jest.fn(),
}));

const request = require('supertest');
const app = require('../../server.js');
const store = require('../../db.js');

describe('POST /api/auth/google — duplicate-account race (real HTTP)', () => {
  test('simultaneous sign-ins for the same brand-new email create exactly one user row', async () => {
    // 4, not more — login rate limiting caps at 5 attempts per IP per
    // window (SEC.LOGIN_MAX), and this is about proving atomicity, not
    // stress-testing the rate limiter.
    const results = await Promise.all(
      Array.from({ length: 4 }, () => request(app).post('/diet/api/auth/google').send({ credential: 'fake-token' }))
    );

    for (const r of results) expect(r.status).toBe(200);

    const users = store.load('users.json') || [];
    const matches = users.filter(u => u.email === 'racer@example.com');
    expect(matches).toHaveLength(1);

    // All 4 responses should carry the SAME user id/username — proof they
    // all resolved to the one real row, not 4 independent ones that a
    // final "last write wins" save() happened to collapse down to one by
    // accident.
    const usernames = new Set(results.map(r => r.body.username));
    expect(usernames.size).toBe(1);
  });
});
