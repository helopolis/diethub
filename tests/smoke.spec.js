const { test, expect } = require('@playwright/test');

test.describe('DietHub smoke', () => {
  test('login page loads', async ({ page }) => {
    await page.goto('/login.html');
    await expect(page).toHaveTitle(/DietHub/);
    await expect(page.locator('h1').first()).toContainText('DietHub');
  });

  test('demo page loads', async ({ page }) => {
    await page.goto('/demo.html');
    await expect(page).toHaveTitle(/DietHub/);
  });

  test('static assets are served', async ({ request }) => {
    const res = await request.get('/favicon.ico');
    expect(res.ok()).toBeTruthy();
  });
});
