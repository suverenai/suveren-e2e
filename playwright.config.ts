import { defineConfig } from '@playwright/test';
import { SIMULATION_SPECS } from './e2e/simulation-specs';

export default defineConfig({
  testDir: './e2e',
  // Production gateway: the specs that use the practice CRM/ERP/mailbox run in
  // playwright.simulation.config.ts (a gateway is simulation OR production).
  testIgnore: SIMULATION_SPECS,
  timeout: 60_000,
  retries: 0,
  workers: 1, // Sequential — shared server state
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    headless: true,
    screenshot: 'only-on-failure',
    // A person's browser: Playwright's default announces automation
    // (navigator.webdriver), which the gateway refuses at sign-in and
    // approval since 0.19.5 (defense in depth, by design).
    launchOptions: { args: ['--disable-blink-features=AutomationControlled'] },
  },
});
