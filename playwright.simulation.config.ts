import { defineConfig } from '@playwright/test';
import base from './playwright.config';
import { SIMULATION_SPECS } from './e2e/simulation-specs';

// The same shared stack as the default config, but a SIMULATION gateway
// (fixtures.ts reads HAP_E2E_PW_SIMULATION) and only the specs that use the
// practice CRM / ERP / mailbox. See e2e/simulation-specs.ts.
process.env.HAP_E2E_PW_SIMULATION = '1';

export default defineConfig({
  ...base,
  testMatch: SIMULATION_SPECS,
  testIgnore: [],
  // Its own output folder: Playwright empties its outputDir at the start of a run, and this run follows the default
  // browser run in CI — with the shared `test-results` it deleted that run's screenshots before the logs were uploaded.
  outputDir: 'test-results/simulation',
});
