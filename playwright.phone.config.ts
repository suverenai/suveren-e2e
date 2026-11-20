import { defineConfig, devices } from '@playwright/test';

/**
 * The phone approval app against the real Authority Server (device-keys plan step 11). Its own config and global setup: the
 * default config's setup starts a gateway this suite does not need, and builds the whole gateway monorepo.
 *
 *   npx playwright test -c playwright.phone.config.ts
 *
 * Chromium runs every case (it has a virtual authenticator). WebKit has none, so its cases that need a passkey are skipped
 * with that reason and one case checks that the app starts and names what the browser lacks.
 */
export default defineConfig({
  testDir: './e2e/phone',
  timeout: 120_000,
  retries: 0,
  workers: 1, // one Authority Server, one database, cases that share a registered phone
  globalSetup: './e2e/phone/global-setup.ts',
  // ignoreHTTPSErrors: the app is served over https with a certificate made in global setup (see there why https).
  use: { headless: true, ignoreHTTPSErrors: true, screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
