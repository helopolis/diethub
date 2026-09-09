// Real, automated accessibility scanning (axe-core) against the live,
// promoted web pages — the "Run automated accessibility scans" requirement.
// This complements (does not replace) manual verification and the
// mobile-side component accessibility tests; automated scanning catches a
// real, meaningful subset of WCAG issues (contrast, missing labels, ARIA
// misuse) but not everything (e.g. logical reading order needs a human).
const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const { registerAndVerify, cleanupUser } = require('./helpers');

function uniqueUser(prefix) {
  const ts = Date.now() + Math.floor(Math.random() * 1000);
  return { username: `${prefix}_${ts}`, password: 'E2ETestPass2026!@#', email: `${prefix}_${ts}@example.com` };
}

test.describe('Automated accessibility scan — real, promoted pages', () => {
  test('the login page has no critical/serious automated a11y violations', async ({ page }) => {
    await page.goto('/diet/login');
    const results = await new AxeBuilder({ page }).include('body').analyze();
    const seriousOrWorse = results.violations.filter(v => v.impact === 'critical' || v.impact === 'serious');
    if (seriousOrWorse.length) {
      console.log('Serious/critical a11y violations found:', JSON.stringify(seriousOrWorse.map(v => ({ id: v.id, help: v.help, nodes: v.nodes.length })), null, 2));
    }
    expect(seriousOrWorse).toEqual([]);
  });

  test('the settings page (authenticated) has no critical/serious automated a11y violations', async ({ page, request, baseURL }) => {
    const user = uniqueUser('e2ea11y');
    await registerAndVerify(request, baseURL, user);
    try {
      await page.goto('/diet/login');
      await page.fill('#lUsr', user.username);
      await page.fill('#lPwd', user.password);
      await page.click('#loginBtn');
      await page.waitForURL('**/diet/dashboard', { timeout: 10000 });
      await page.goto('/diet/settings');
      const results = await new AxeBuilder({ page }).include('body').analyze();
      const seriousOrWorse = results.violations.filter(v => v.impact === 'critical' || v.impact === 'serious');
      if (seriousOrWorse.length) {
        console.log('Serious/critical a11y violations found:', JSON.stringify(seriousOrWorse.map(v => ({ id: v.id, help: v.help, nodes: v.nodes.length })), null, 2));
      }
      expect(seriousOrWorse).toEqual([]);
    } finally {
      cleanupUser(user.username);
    }
  });
});
