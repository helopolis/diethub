const { defineConfig } = require('@playwright/test');

// Point tests at a deployed instance with BASE_URL, e.g.:
//   BASE_URL=https://your-domain.com npx playwright test
// Without BASE_URL, the local server.js is started automatically on :3200.
const BASE_URL = process.env.BASE_URL || 'http://localhost:3200';

module.exports = defineConfig({
  testDir: './tests',
  timeout: 30_000,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: BASE_URL,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    // In sandboxed environments (e.g. Claude Code on the web) the browser is
    // pre-installed at a fixed path instead of the Playwright cache.
    launchOptions: process.env.PW_CHROMIUM_PATH
      ? { executablePath: process.env.PW_CHROMIUM_PATH }
      : {},
  },
  webServer: process.env.BASE_URL
    ? undefined
    : {
        command: 'node server.js',
        url: 'http://localhost:3200/login.html',
        reuseExistingServer: true,
        timeout: 15_000,
      },
});
