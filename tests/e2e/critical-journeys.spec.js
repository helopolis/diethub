// Real, critical-user-journey E2E tests against the live container — same
// verification method used manually throughout this entire hardening
// engagement, now automated and repeatable. Every test creates and cleans
// up its own real, disposable account.
const { test, expect } = require('@playwright/test');
const { registerAndVerify, cleanupUser } = require('./helpers');

function uniqueUser(prefix) {
  const ts = Date.now() + Math.floor(Math.random() * 1000);
  return { username: `${prefix}_${ts}`, password: 'E2ETestPass2026!@#', email: `${prefix}_${ts}@example.com` };
}

test.describe('Critical journey: Registration -> Login -> Dashboard', () => {
  let user;
  test.beforeAll(async ({ request, baseURL }) => {
    user = uniqueUser('e2ereg');
    await registerAndVerify(request, baseURL, user);
  });
  test.afterAll(() => cleanupUser(user.username));

  test('a real user can log in through the promoted /diet/login page and reach the dashboard', async ({ page }) => {
    await page.goto('/diet/login');
    await page.fill('#lUsr', user.username);
    await page.fill('#lPwd', user.password);
    await page.click('#loginBtn');
    await page.waitForURL('**/diet/dashboard', { timeout: 10000 });
    await expect(page).toHaveURL(/\/diet\/dashboard/);
  });

  test('the session cookie is HttpOnly — invisible to page JavaScript (regression: RC1 cookie fix)', async ({ page, context }) => {
    await page.goto('/diet/login');
    await page.fill('#lUsr', user.username);
    await page.fill('#lPwd', user.password);
    await page.click('#loginBtn');
    await page.waitForURL('**/diet/dashboard', { timeout: 10000 });

    const jsVisibleCookie = await page.evaluate(() => document.cookie);
    expect(jsVisibleCookie).not.toContain('dh_token');

    const cookies = await context.cookies();
    const dhCookie = cookies.find(c => c.name === 'dh_token');
    expect(dhCookie).toBeTruthy();
    expect(dhCookie.httpOnly).toBe(true);
    expect(dhCookie.sameSite).toBe('Strict');
  });
});

test.describe('Critical journey: Settings and Subscription navigation', () => {
  let user;
  test.beforeAll(async ({ request, baseURL }) => {
    user = uniqueUser('e2enav');
    await registerAndVerify(request, baseURL, user);
  });
  test.afterAll(() => cleanupUser(user.username));

  async function login(page, u) {
    await page.goto('/diet/login');
    await page.fill('#lUsr', u.username);
    await page.fill('#lPwd', u.password);
    await page.click('#loginBtn');
    await page.waitForURL('**/diet/dashboard', { timeout: 10000 });
  }

  test('a logged-in user can reach the canonical Settings page (Phase 7 promotion)', async ({ page }) => {
    await login(page, user);
    await page.goto('/diet/settings');
    await expect(page.locator('body')).toContainText(/الإعدادات|Settings/);
  });

  test('a logged-in user can reach the canonical Subscription page (Phase 7 promotion)', async ({ page }) => {
    await login(page, user);
    await page.goto('/diet/subscription');
    await expect(page.locator('body')).toContainText(/الاشتراك|Subscription/);
  });

  test('an unauthenticated visitor cannot reach Settings — redirected to login', async ({ page, context }) => {
    await context.clearCookies();
    const res = await page.goto('/diet/settings');
    expect(page.url()).toContain('/diet/login');
  });
});
